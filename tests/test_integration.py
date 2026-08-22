"""Integration tests against the running services.

These skip automatically when the stack is not up, so `pytest tests/` always
works. Start the stack first to run them:

    bash scripts/run_all.sh
    python3 -m pytest tests/ -v
"""

import os
import sys
import time

import pytest
import requests

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

BROKER = "http://127.0.0.1:8081"
PROXY = "http://127.0.0.1:8080"
NO_PROXY_ENV = {"http": "", "https": ""}


def stack_is_up():
    try:
        requests.get(PROXY + "/health", timeout=2, proxies=NO_PROXY_ENV)
        requests.get(BROKER + "/agents", timeout=2, proxies=NO_PROXY_ENV)
        return True
    except requests.RequestException:
        return False


pytestmark = pytest.mark.skipif(
    not stack_is_up(),
    reason="services not running, start them with bash scripts/run_all.sh",
)


@pytest.fixture
def token():
    requests.post(BROKER + "/reinstate", json={"agent_id": "ci-debug-agent"},
                  timeout=10, proxies=NO_PROXY_ENV)
    response = requests.post(
        BROKER + "/token",
        json={
            "agent_id": "ci-debug-agent",
            "bootstrap_secret": "bootstrap-ci-debug",
            "task_id": "PYTEST",
            "requested_scopes": ["runs:read", "logs:read", "runs:rerun"],
        },
        timeout=10,
        proxies=NO_PROXY_ENV,
    )
    response.raise_for_status()
    return response.json()


def call(token_value, method, path, body=None):
    headers = {"content-type": "application/json"}
    if token_value:
        headers["authorization"] = "Bearer " + token_value
    return requests.request(
        method, PROXY + "/gw" + path, headers=headers, json=body,
        timeout=15, proxies=NO_PROXY_ENV,
    )


class TestBroker:
    def test_wrong_bootstrap_secret_rejected(self):
        response = requests.post(
            BROKER + "/token",
            json={"agent_id": "ci-debug-agent", "bootstrap_secret": "wrong",
                  "task_id": "T", "requested_scopes": ["runs:read"]},
            timeout=10, proxies=NO_PROXY_ENV,
        )
        assert response.status_code == 401

    def test_cannot_request_more_than_registered_scopes(self, token):
        response = requests.post(
            BROKER + "/token",
            json={"agent_id": "ci-debug-agent",
                  "bootstrap_secret": "bootstrap-ci-debug",
                  "task_id": "T", "requested_scopes": ["deploy:write"]},
            timeout=10, proxies=NO_PROXY_ENV,
        )
        assert response.status_code == 403

    def test_token_is_short_lived(self, token):
        assert token["expires_in"] <= 300

    def test_token_carries_attribution_claims(self, token):
        import jwt

        claims = jwt.decode(token["token"], options={"verify_signature": False})
        for field in ["sub", "jti", "task_id", "scopes", "owner",
                      "principal", "agent_version", "exp"]:
            assert field in claims


class TestProxyEnforcement:
    def test_permitted_call_succeeds(self, token):
        assert call(token["token"], "GET", "/runs").status_code == 200

    def test_out_of_scope_call_refused(self, token):
        assert call(token["token"], "DELETE", "/branches/main").status_code == 403

    def test_missing_token_refused(self):
        assert call(None, "GET", "/runs").status_code == 401

    def test_forged_token_refused(self):
        import base64
        import json

        def segment(obj):
            return base64.urlsafe_b64encode(
                json.dumps(obj).encode()).rstrip(b"=").decode()

        forged = "{}.{}.{}".format(
            segment({"alg": "ES256", "typ": "JWT"}),
            segment({"iss": "non-repudiation-broker", "sub": "ci-debug-agent",
                     "jti": "forged", "exp": 9999999999,
                     "scopes": ["deploy:write"]}),
            "invalid",
        )
        assert call(forged, "POST", "/deploy").status_code == 401

    def test_agent_cannot_reach_target_directly(self):
        """The agent has no credential, so bypassing the proxy gets nothing."""
        response = requests.get("http://127.0.0.1:8082/runs", timeout=10,
                                proxies=NO_PROXY_ENV)
        assert response.status_code == 401


class TestRevocation:
    def test_revocation_beats_a_still_valid_token(self, token):
        assert call(token["token"], "GET", "/runs").status_code == 200

        start = time.time()
        requests.post(BROKER + "/revoke",
                      json={"agent_id": "ci-debug-agent", "reason": "pytest"},
                      timeout=10, proxies=NO_PROXY_ENV)
        response = call(token["token"], "GET", "/runs")
        elapsed = time.time() - start

        assert response.status_code == 403
        assert elapsed < 2.0

        requests.post(BROKER + "/reinstate",
                      json={"agent_id": "ci-debug-agent", "reason": "pytest"},
                      timeout=10, proxies=NO_PROXY_ENV)


class TestAutomaticContainment:
    def test_concealment_triggers_revocation_without_a_human(self):
        """The closed loop: the agent under reports and the system stops it."""
        import sys as _sys

        _sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        from agent.sdk import FlightRecorder

        requests.post(BROKER + "/reinstate", json={"agent_id": "ci-debug-agent"},
                      timeout=10, proxies=NO_PROXY_ENV)
        response = requests.post(
            BROKER + "/token",
            json={"agent_id": "ci-debug-agent",
                  "bootstrap_secret": "bootstrap-ci-debug",
                  "task_id": "PYTEST-CONTAIN",
                  "requested_scopes": ["runs:read", "logs:read", "runs:rerun"]},
            timeout=10, proxies=NO_PROXY_ENV,
        ).json()
        token_value, jti = response["token"], response["jti"]

        honest = FlightRecorder(jti, "PYTEST-CONTAIN", "ci-debug-agent")
        honest.tool_call("GET", "/runs")
        assert call(token_value, "GET", "/runs").status_code == 200

        # Two actions performed and deliberately not reported.
        call(token_value, "GET", "/runs/4471/logs")
        call(token_value, "POST", "/runs/4471/rerun")

        time.sleep(0.3)
        assert call(token_value, "GET", "/runs").status_code == 403

        events = requests.get(PROXY + "/v1/containment", timeout=10,
                              proxies=NO_PROXY_ENV).json()["events"]
        assert any(e["jti"] == jti for e in events)

        requests.post(BROKER + "/reinstate", json={"agent_id": "ci-debug-agent"},
                      timeout=10, proxies=NO_PROXY_ENV)

    def test_a_fresh_token_is_judged_on_its_own_behaviour(self):
        """Containment is per token, so a reinstated agent is not pre-judged."""
        requests.post(BROKER + "/reinstate", json={"agent_id": "ci-debug-agent"},
                      timeout=10, proxies=NO_PROXY_ENV)
        fresh = requests.post(
            BROKER + "/token",
            json={"agent_id": "ci-debug-agent",
                  "bootstrap_secret": "bootstrap-ci-debug",
                  "task_id": "PYTEST-FRESH",
                  "requested_scopes": ["runs:read"]},
            timeout=10, proxies=NO_PROXY_ENV,
        ).json()
        assert call(fresh["token"], "GET", "/runs").status_code == 200


class TestIndependentAudit:
    def test_export_bundle_is_self_contained(self):
        bundle = requests.get(PROXY + "/v1/export", timeout=20,
                              proxies=NO_PROXY_ENV).json()
        for field in ["format", "public_key_pem", "chain_head", "entries"]:
            assert field in bundle
        assert bundle["entries"]

    def test_standalone_auditor_verifies_a_clean_bundle(self):
        """Build an isolated chain rather than trusting the shared database.

        The demo deliberately tampers with data/ledger.db at the end, so a
        test that audits whatever happens to be on disk is testing the last
        thing that ran, not the auditor.
        """
        import json
        import subprocess
        import sys as _sys
        import tempfile

        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        _sys.path.insert(0, root)
        from ledger.store import Ledger

        directory = tempfile.mkdtemp()
        ledger = Ledger(db_path=os.path.join(directory, "l.db"),
                        key_path=os.path.join(directory, "k.pem"))
        for i in range(4):
            ledger.append({
                "agent_id": "test-agent", "agent_version": "1.0.0",
                "owner": "o@example.com", "principal": "o@example.com",
                "task_id": "T", "jti": "j", "method": "GET",
                "path": "/runs/{}".format(i),
                "decision": "DENY" if i == 2 else "ALLOW",
                "reason": "test", "required_scope": "runs:read",
                "status_code": 200, "request_digest": "a",
                "response_digest": "b", "redactions": None,
            })
        entries = ledger.read_all()
        bundle = {
            "format": "non-repudiation-evidence-bundle/1",
            "exported_at": "test",
            "public_key_pem": ledger.public_key_pem(),
            "chain_head": entries[-1]["entry_hash"],
            "entry_count": len(entries),
            "entries": entries,
        }
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as handle:
            json.dump(bundle, handle)
            path = handle.name

        result = subprocess.run(
            [sys.executable, os.path.join(root, "audit.py"), path],
            capture_output=True, text=True, timeout=60,
        )
        assert result.returncode == 0
        assert "VERIFIED" in result.stdout

    def test_standalone_auditor_catches_an_edited_bundle(self):
        import json
        import subprocess
        import sys as _sys
        import tempfile

        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        _sys.path.insert(0, root)
        from ledger.store import Ledger

        directory = tempfile.mkdtemp()
        ledger = Ledger(db_path=os.path.join(directory, "l.db"),
                        key_path=os.path.join(directory, "k.pem"))
        for i in range(3):
            ledger.append({
                "agent_id": "test-agent", "agent_version": "1.0.0",
                "owner": "o@example.com", "principal": "o@example.com",
                "task_id": "T", "jti": "j", "method": "GET",
                "path": "/runs/{}".format(i),
                "decision": "DENY" if i == 1 else "ALLOW",
                "reason": "test", "required_scope": "runs:read",
                "status_code": 200, "request_digest": "a",
                "response_digest": "b", "redactions": None,
            })
        entries = ledger.read_all()
        bundle = {
            "format": "non-repudiation-evidence-bundle/1",
            "public_key_pem": ledger.public_key_pem(),
            "chain_head": entries[-1]["entry_hash"],
            "entries": entries,
        }
        for entry in bundle["entries"]:
            if entry["decision"] == "DENY":
                entry["decision"] = "ALLOW"
                break
        else:
            import pytest as _pytest
            _pytest.skip("no denied entry in the ledger to edit")

        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as handle:
            json.dump(bundle, handle)
            path = handle.name

        result = subprocess.run(
            [sys.executable, os.path.join(root, "audit.py"), path],
            capture_output=True, text=True, timeout=60,
        )
        assert result.returncode == 1
        assert "ALTERED" in result.stdout


class TestEvidence:
    def test_every_call_lands_in_the_ledger(self, token):
        before = len(requests.get(PROXY + "/v1/ledger?limit=500", timeout=10,
                                  proxies=NO_PROXY_ENV).json()["entries"])
        call(token["token"], "GET", "/runs")
        call(token["token"], "DELETE", "/branches/main")
        after = len(requests.get(PROXY + "/v1/ledger?limit=500", timeout=10,
                                 proxies=NO_PROXY_ENV).json()["entries"])
        assert after == before + 2

    def test_secrets_in_a_response_are_redacted(self, token):
        """The build log contains an email and an internal IP."""
        call(token["token"], "GET", "/runs/4471/logs")
        entries = requests.get(PROXY + "/v1/ledger?limit=20", timeout=10,
                               proxies=NO_PROXY_ENV).json()["entries"]
        logs_entry = next(e for e in entries if e["path"] == "/runs/4471/logs")
        assert logs_entry["redactions"]
        assert "EMAIL" in logs_entry["redactions"]

    def test_reconciliation_reports_on_a_token(self, token):
        call(token["token"], "GET", "/runs")
        result = requests.get(
            PROXY + "/v1/reconcile/" + token["jti"], timeout=10,
            proxies=NO_PROXY_ENV,
        ).json()
        assert result["observed_by_proxy"] >= 1
        assert result["verdict"] in (
            "CONSISTENT", "CONCEALMENT DETECTED", "PHANTOM REPORTING DETECTED"
        )
