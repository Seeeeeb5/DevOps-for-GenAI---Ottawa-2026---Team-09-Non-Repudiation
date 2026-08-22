"""Tamper evident evidence ledger.

Every proxied call produces one record. Each record carries the hash of the
previous record, so any edit to an earlier record breaks the chain from that
point onward. Each record is also signed with an Ed25519 key that the agent
never holds, which is what makes the record non repudiable: the agent cannot
forge a record and cannot deny one.
"""

import os
import sqlite3
import sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from common import canonical_json, now_iso, sha256_hex  # noqa: E402

GENESIS_HASH = "0" * 64

SCHEMA = """
CREATE TABLE IF NOT EXISTS entries (
    seq INTEGER PRIMARY KEY,
    ts TEXT NOT NULL,
    agent_id TEXT NOT NULL,
    agent_version TEXT,
    owner TEXT,
    principal TEXT,
    task_id TEXT,
    jti TEXT,
    method TEXT,
    path TEXT,
    decision TEXT NOT NULL,
    reason TEXT,
    required_scope TEXT,
    status_code INTEGER,
    request_digest TEXT,
    response_digest TEXT,
    redactions TEXT,
    prev_hash TEXT NOT NULL,
    entry_hash TEXT NOT NULL,
    signature TEXT NOT NULL
);
"""

# Fields that are covered by the hash and the signature. Order is fixed.
SIGNED_FIELDS = [
    "seq",
    "ts",
    "agent_id",
    "agent_version",
    "owner",
    "principal",
    "task_id",
    "jti",
    "method",
    "path",
    "decision",
    "reason",
    "required_scope",
    "status_code",
    "request_digest",
    "response_digest",
    "redactions",
    "prev_hash",
]


class Ledger:
    def __init__(self, db_path, key_path):
        self.db_path = db_path
        self.key_path = key_path
        self._signing_key = self._load_or_create_key()
        conn = self._connect()
        conn.executescript(SCHEMA)
        conn.commit()
        conn.close()

    def _connect(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _load_or_create_key(self):
        """Load the ledger signing key, or create it on first run."""
        if os.path.exists(self.key_path):
            with open(self.key_path, "rb") as handle:
                return serialization.load_pem_private_key(handle.read(), password=None)
        key = ed25519.Ed25519PrivateKey.generate()
        pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        with open(self.key_path, "wb") as handle:
            handle.write(pem)
        os.chmod(self.key_path, 0o600)
        return key

    def public_key_pem(self):
        """Return the verification key so anyone can audit the ledger."""
        return (
            self._signing_key.public_key()
            .public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            .decode()
        )

    def head(self):
        """Return the sequence number and hash of the most recent entry."""
        conn = self._connect()
        row = conn.execute(
            "SELECT seq, entry_hash FROM entries ORDER BY seq DESC LIMIT 1"
        ).fetchone()
        conn.close()
        if row is None:
            return 0, GENESIS_HASH
        return row["seq"], row["entry_hash"]

    def append(self, record):
        """Append one record, chaining it to the current head and signing it."""
        last_seq, prev_hash = self.head()
        entry = dict(record)
        entry["seq"] = last_seq + 1
        entry["ts"] = now_iso()
        entry["prev_hash"] = prev_hash

        payload = {field: entry.get(field) for field in SIGNED_FIELDS}
        entry_hash = sha256_hex(canonical_json(payload))
        signature = self._signing_key.sign(entry_hash.encode()).hex()
        entry["entry_hash"] = entry_hash
        entry["signature"] = signature

        columns = SIGNED_FIELDS + ["entry_hash", "signature"]
        placeholders = ",".join("?" for _ in columns)
        conn = self._connect()
        conn.execute(
            "INSERT INTO entries ({}) VALUES ({})".format(",".join(columns), placeholders),
            [entry.get(c) for c in columns],
        )
        conn.commit()
        conn.close()
        return entry

    def read_all(self, limit=None):
        """Return ledger entries in order, newest last."""
        conn = self._connect()
        query = "SELECT * FROM entries ORDER BY seq ASC"
        if limit:
            query = "SELECT * FROM (SELECT * FROM entries ORDER BY seq DESC LIMIT {}) ORDER BY seq ASC".format(
                int(limit)
            )
        rows = [dict(r) for r in conn.execute(query).fetchall()]
        conn.close()
        return rows
