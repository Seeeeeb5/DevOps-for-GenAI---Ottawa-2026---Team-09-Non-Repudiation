"""Store for self reported agent telemetry.

This is deliberately a separate table from the signed ledger, and it is
deliberately not hash chained or signed. The distinction is the point:

  entries          what the proxy observed. Trusted. Signed. Unforgeable.
  self_reported    what the agent says it did. Untrusted. Kept as narrative.

Mixing them into one table would imply they carry the same weight, and they do
not. Reconciliation compares the two and reports where they disagree.
"""

import sqlite3

SCHEMA = """
CREATE TABLE IF NOT EXISTS self_reported (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    received_ts TEXT NOT NULL,
    jti TEXT,
    task_id TEXT,
    agent_id TEXT,
    agent_version TEXT,
    sequence INTEGER,
    event_type TEXT,
    model TEXT,
    tokens_in INTEGER,
    tokens_out INTEGER,
    cost REAL,
    method TEXT,
    path TEXT,
    confidence REAL,
    summary TEXT,
    reason TEXT,
    evidence TEXT,
    attempt INTEGER
);
"""

FIELDS = [
    "received_ts", "jti", "task_id", "agent_id", "agent_version", "sequence",
    "event_type", "model", "tokens_in", "tokens_out", "cost", "method", "path",
    "confidence", "summary", "reason", "evidence", "attempt",
]


class TelemetryStore:
    def __init__(self, db_path):
        self.db_path = db_path
        conn = self._connect()
        conn.executescript(SCHEMA)
        conn.commit()
        conn.close()

    def _connect(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def record(self, event):
        """Store one self reported event exactly as the agent sent it."""
        from common import now_iso

        row = {field: event.get(field) for field in FIELDS}
        row["received_ts"] = now_iso()
        placeholders = ",".join("?" for _ in FIELDS)
        conn = self._connect()
        conn.execute(
            "INSERT INTO self_reported ({}) VALUES ({})".format(
                ",".join(FIELDS), placeholders
            ),
            [row[f] for f in FIELDS],
        )
        conn.commit()
        conn.close()
        return row

    def by_token(self, jti):
        conn = self._connect()
        rows = [dict(r) for r in conn.execute(
            "SELECT * FROM self_reported WHERE jti = ? ORDER BY sequence ASC", (jti,)
        )]
        conn.close()
        return rows

    def all_events(self, limit=200):
        conn = self._connect()
        rows = [dict(r) for r in conn.execute(
            "SELECT * FROM self_reported ORDER BY id DESC LIMIT ?", (int(limit),)
        )]
        conn.close()
        return list(reversed(rows))


def reconcile(ledger_entries, reported_events, jti):
    """Compare what the proxy observed against what the agent admitted to.

    Returns a report naming three categories:

      matched     the agent reported an action the proxy also observed
      concealed   the proxy observed an action the agent never reported
      phantom     the agent claimed an action the proxy never observed

    Concealed entries are the security relevant ones. They mean the agent's own
    telemetry is incomplete, which is exactly the failure mode that makes self
    reported observability untrustworthy on its own.
    """
    observed = [
        (e["method"], e["path"])
        for e in ledger_entries
        if e.get("jti") == jti and e.get("method")
    ]
    claimed = [
        (e["method"], e["path"])
        for e in reported_events
        if e.get("event_type") == "tool_call" and e.get("method")
    ]

    remaining = list(claimed)
    matched = []
    concealed = []
    for call in observed:
        if call in remaining:
            remaining.remove(call)
            matched.append(call)
        else:
            concealed.append(call)
    phantom = remaining

    if concealed:
        verdict = "CONCEALMENT DETECTED"
    elif phantom:
        verdict = "PHANTOM REPORTING DETECTED"
    else:
        verdict = "CONSISTENT"

    return {
        "jti": jti,
        "verdict": verdict,
        "observed_by_proxy": len(observed),
        "reported_by_agent": len(claimed),
        "matched": ["{} {}".format(m, p) for m, p in matched],
        "concealed": ["{} {}".format(m, p) for m, p in concealed],
        "phantom": ["{} {}".format(m, p) for m, p in phantom],
        "internal_events": len([
            e for e in reported_events if e.get("event_type") != "tool_call"
        ]),
    }
