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
