"""Unit tests. These do not need any service running.

They cover the four pieces where a silent regression would break the demo
without anyone noticing: the policy decision, redaction, the hash chain, and
the reconciliation logic.

Run with:
    python3 -m pytest tests/ -v
"""

import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ledger.store import Ledger  # noqa: E402
from ledger.telemetry import reconcile  # noqa: E402
from proxy import policy, redact  # noqa: E402


class TestPolicy:
    def test_read_allowed_with_scope(self):
        allowed, scope, _, _ = policy.decide("GET", "/runs", ["runs:read"])
        assert allowed is True
        assert scope == "runs:read"

    def test_read_denied_without_scope(self):
        allowed, scope, _, reason = policy.decide("GET", "/runs", ["logs:read"])
        assert allowed is False
        assert scope == "runs:read"
        assert "does not carry" in reason

    def test_destructive_action_needs_its_own_scope(self):
        allowed, _, risk, _ = policy.decide(
            "DELETE", "/branches/main", ["runs:read", "logs:read", "runs:rerun"]
        )
        assert allowed is False
        assert risk == "high"

    def test_unmatched_path_denied_by_default(self):
        """A new endpoint must not become reachable just because it exists."""
        allowed, scope, _, reason = policy.decide(
            "GET", "/admin/users", ["runs:read", "logs:read", "deploy:write"]
        )
        assert allowed is False
        assert scope is None
        assert "denied by default" in reason

    def test_method_swap_on_permitted_path_denied(self):
        allowed, _, _, _ = policy.decide("DELETE", "/runs/4471", ["runs:read"])
        assert allowed is False

    def test_empty_scope_list_allows_nothing(self):
        for method, path in [("GET", "/runs"), ("GET", "/runs/1/logs"),
                             ("POST", "/deploy")]:
            allowed, _, _, _ = policy.decide(method, path, [])
            assert allowed is False

    def test_policy_file_loads(self):
        assert policy.meta()["rule_count"] > 0
        assert len(policy.describe()) == policy.meta()["rule_count"]


class TestRedaction:
    def test_email_removed(self):
        result, marks = redact.redact("contact ops@example.com for the token")
        assert "ops@example.com" not in result
        assert any(m.startswith("EMAIL") for m in marks)

    def test_private_ip_removed(self):
        result, marks = redact.redact("cannot reach vault at 10.114.210.45:8200")
        assert "10.114.210.45" not in result
        assert any(m.startswith("IPV4") for m in marks)

    def test_bearer_token_removed(self):
        secret = "Bearer abcdefghijklmnopqrstuvwxyz0123456789"
        result, marks = redact.redact("authorization: " + secret)
        assert "abcdefghijklmnopqrstuvwxyz" not in result
        assert marks

    def test_private_key_header_removed(self):
        result, _ = redact.redact("-----BEGIN RSA PRIVATE KEY-----")
        assert "BEGIN RSA PRIVATE KEY" not in result

    def test_clean_text_untouched(self):
        text = "213 of 214 tests passed"
        result, marks = redact.redact(text)
        assert result == text
        assert marks == []

    def test_empty_input_is_safe(self):
        assert redact.redact("") == ("", [])
        assert redact.redact(None) == (None, [])


class TestLedger:
    def _fresh(self):
        directory = tempfile.mkdtemp()
        return Ledger(
            db_path=os.path.join(directory, "ledger.db"),
            key_path=os.path.join(directory, "key.pem"),
        )

    def _record(self, decision="ALLOW", path="/runs"):
        return {
            "agent_id": "test-agent", "agent_version": "1.0.0",
            "owner": "owner@example.com", "principal": "owner@example.com",
            "task_id": "T-1", "jti": "jti-1", "method": "GET", "path": path,
            "decision": decision, "reason": "test", "required_scope": "runs:read",
            "status_code": 200, "request_digest": "a", "response_digest": "b",
            "redactions": None,
        }

    def test_first_entry_links_to_genesis(self):
        ledger = self._fresh()
        entry = ledger.append(self._record())
        assert entry["seq"] == 1
        assert entry["prev_hash"] == "0" * 64

    def test_entries_chain_together(self):
        ledger = self._fresh()
        first = ledger.append(self._record())
        second = ledger.append(self._record(path="/runs/1"))
        assert second["prev_hash"] == first["entry_hash"]

    def test_signature_verifies(self):
        from cryptography.hazmat.primitives import serialization

        ledger = self._fresh()
        entry = ledger.append(self._record())
        with open(ledger.key_path, "rb") as handle:
            public = serialization.load_pem_private_key(
                handle.read(), password=None
            ).public_key()
        # Raises InvalidSignature if the entry was not signed by this key.
        public.verify(bytes.fromhex(entry["signature"]),
                      entry["entry_hash"].encode())

    def test_editing_content_breaks_the_hash(self):
        """This is the property the whole audit story depends on."""
        import sqlite3

        from common import canonical_json, sha256_hex
        from ledger.store import SIGNED_FIELDS

        ledger = self._fresh()
        ledger.append(self._record(decision="DENY"))

        conn = sqlite3.connect(ledger.db_path)
        conn.execute("UPDATE entries SET decision='ALLOW' WHERE seq=1")
        conn.commit()
        conn.row_factory = sqlite3.Row
        row = dict(conn.execute("SELECT * FROM entries WHERE seq=1").fetchone())
        conn.close()

        payload = {field: row.get(field) for field in SIGNED_FIELDS}
        assert sha256_hex(canonical_json(payload)) != row["entry_hash"]

    def test_denied_actions_are_recorded_too(self):
        ledger = self._fresh()
        ledger.append(self._record(decision="DENY", path="/deploy"))
        entries = ledger.read_all()
        assert len(entries) == 1
        assert entries[0]["decision"] == "DENY"

    def test_by_token_returns_only_that_token(self):
        """Reconciliation runs on every call, so it must not read the whole
        ledger to find the handful of entries belonging to one token."""
        ledger = self._fresh()
        for jti in ("jti-a", "jti-b", "jti-a"):
            record = self._record()
            record["jti"] = jti
            ledger.append(record)
        assert [e["seq"] for e in ledger.by_token("jti-a")] == [1, 3]
        assert len(ledger.by_token("jti-b")) == 1
        assert ledger.by_token("jti-missing") == []

    def test_by_token_returns_entries_in_order(self):
        ledger = self._fresh()
        for _ in range(3):
            ledger.append(self._record())
        assert [e["seq"] for e in ledger.by_token("jti-1")] == [1, 2, 3]

    def test_token_ids_are_distinct_and_most_recent_first(self):
        ledger = self._fresh()
        for jti in ("jti-a", "jti-b", "jti-a", "jti-c"):
            record = self._record()
            record["jti"] = jti
            ledger.append(record)
        # jti-a appears twice but is listed once, ordered by its latest entry.
        assert ledger.token_ids() == ["jti-c", "jti-a", "jti-b"]

    def test_token_ids_respects_a_limit(self):
        ledger = self._fresh()
        for jti in ("jti-a", "jti-b", "jti-c"):
            record = self._record()
            record["jti"] = jti
            ledger.append(record)
        assert ledger.token_ids(limit=2) == ["jti-c", "jti-b"]

    def test_token_ids_skips_entries_with_no_token(self):
        """A call refused before the token was read has no jti to report."""
        ledger = self._fresh()
        record = self._record()
        record["jti"] = None
        ledger.append(record)
        assert ledger.token_ids() == []

    def test_token_ids_on_an_empty_ledger(self):
        assert self._fresh().token_ids() == []


class TestReconciliation:
    def _ledger_entry(self, method, path, jti="j1"):
        return {"jti": jti, "method": method, "path": path}

    def _reported(self, method, path):
        return {"event_type": "tool_call", "method": method, "path": path}

    def test_matching_streams_are_consistent(self):
        observed = [self._ledger_entry("GET", "/runs"),
                    self._ledger_entry("GET", "/runs/1")]
        reported = [self._reported("GET", "/runs"),
                    self._reported("GET", "/runs/1")]
        result = reconcile(observed, reported, "j1")
        assert result["verdict"] == "CONSISTENT"
        assert result["concealed"] == []

    def test_missing_report_is_concealment(self):
        observed = [self._ledger_entry("GET", "/runs"),
                    self._ledger_entry("POST", "/runs/1/rerun")]
        reported = [self._reported("GET", "/runs")]
        result = reconcile(observed, reported, "j1")
        assert result["verdict"] == "CONCEALMENT DETECTED"
        assert "POST /runs/1/rerun" in result["concealed"]

    def test_claiming_work_never_done_is_phantom(self):
        observed = [self._ledger_entry("GET", "/runs")]
        reported = [self._reported("GET", "/runs"),
                    self._reported("GET", "/runs/999/logs")]
        result = reconcile(observed, reported, "j1")
        assert result["verdict"] == "PHANTOM REPORTING DETECTED"
        assert "GET /runs/999/logs" in result["phantom"]

    def test_other_tokens_are_ignored(self):
        observed = [self._ledger_entry("GET", "/runs", jti="other")]
        result = reconcile(observed, [], "j1")
        assert result["observed_by_proxy"] == 0
        assert result["verdict"] == "CONSISTENT"

    def test_system_containment_entries_are_not_counted_as_concealment(self):
        """The system's own action against an agent is not the agent's action."""
        observed = [
            self._ledger_entry("GET", "/runs"),
            {"jti": "j1", "method": "SYSTEM", "path": "/containment",
             "decision": "CONTAIN"},
        ]
        reported = [self._reported("GET", "/runs")]
        result = reconcile(observed, reported, "j1")
        assert result["verdict"] == "CONSISTENT"
        assert result["observed_by_proxy"] == 1

    def test_internal_events_counted_separately(self):
        reported = [
            {"event_type": "model_call", "model": "m"},
            {"event_type": "hypothesis", "summary": "s"},
            self._reported("GET", "/runs"),
        ]
        result = reconcile([self._ledger_entry("GET", "/runs")], reported, "j1")
        assert result["internal_events"] == 2
        assert result["reported_by_agent"] == 1
