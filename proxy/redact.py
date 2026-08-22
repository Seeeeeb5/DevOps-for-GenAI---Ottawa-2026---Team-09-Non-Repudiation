"""Redaction applied before any payload is recorded.

The proxy records behaviour, not secrets. Payloads are redacted first and then
only their digest is stored, so the ledger proves what happened without
becoming a new place where credentials and personal data accumulate.
"""

import re

PATTERNS = [
    ("EMAIL", re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")),
    ("AWS_KEY", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("BEARER", re.compile(r"(?i)bearer\s+[A-Za-z0-9._\-]{20,}")),
    ("PRIVATE_KEY", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("API_KEY", re.compile(r"(?i)(api[_-]?key|secret|password|token)\"?\s*[:=]\s*\"?[A-Za-z0-9._\-]{8,}")),
    ("IPV4", re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")),
]


def redact(text):
    """Return (redacted_text, list_of_redaction_labels)."""
    if not text:
        return text, []
    found = []
    result = text
    for label, pattern in PATTERNS:
        result, count = pattern.subn("[{}_REDACTED]".format(label), result)
        if count:
            found.append("{}x{}".format(label, count))
    return result, found
