"""Shared helpers used by the broker, the proxy and the ledger."""

import hashlib
import json
from datetime import datetime, timezone


def now_iso():
    """Return the current UTC time as an ISO 8601 string."""
    return datetime.now(timezone.utc).isoformat()


def canonical_json(obj):
    """Serialize an object deterministically so hashes are reproducible."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_hex(data):
    """Return the hex SHA-256 digest of a string or bytes value."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def digest_of(obj):
    """Return the SHA-256 digest of an arbitrary JSON serializable object."""
    return sha256_hex(canonical_json(obj))
