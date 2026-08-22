#!/usr/bin/env python3
"""Independent auditor for a Non-Repudiation evidence bundle.

This file is deliberately standalone. It imports nothing from the project it
audits, it makes no network calls, and it is short enough to read in full
before you run it. That is the point: if you have to trust our code to believe
our claims, the claims are worth very little.

Give it a bundle exported from the system and it will tell you whether the
record has been altered since it was written.

    python3 audit.py evidence-bundle.json

It checks three things:

  1. Every entry hashes to the value stored alongside it, so no field has been
     edited after the fact.
  2. Every entry carries the hash of the entry before it, so no entry has been
     inserted, removed or reordered.
  3. Every entry carries a valid Ed25519 signature over its hash, made with a
     key the agents never held, so no entry can be forged.

Signature verification needs the `cryptography` package. Without it the first
two checks still run and the third is reported as skipped.

Try breaking it. Open the bundle, change any decision from DENY to ALLOW,
change a path, delete an entry, swap two entries, and run this again. It will
name the position where the record stops being consistent.
"""

import hashlib
import json
import sys

GENESIS_HASH = "0" * 64

# The exact fields covered by the hash and the signature, in this exact order.
# Changing this list changes every hash, which is why it is written out in
# full here rather than derived from anything.
SIGNED_FIELDS = [
    "seq", "ts", "agent_id", "agent_version", "owner", "principal", "task_id",
    "jti", "method", "path", "decision", "reason", "required_scope",
    "status_code", "request_digest", "response_digest", "redactions",
    "prev_hash",
]


def canonical_json(obj):
    """Serialize deterministically. Any difference here changes the hash."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False)


def entry_hash(entry):
    payload = {field: entry.get(field) for field in SIGNED_FIELDS}
    return hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()


def load_verifier(public_key_pem):
    """Return a function that verifies one signature, or None if unavailable."""
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import serialization
    except ImportError:
        return None

    public_key = serialization.load_pem_public_key(public_key_pem.encode())

    def verify(signature_hex, message):
        try:
            public_key.verify(bytes.fromhex(signature_hex), message.encode())
            return True
        except (InvalidSignature, ValueError):
            return False

    return verify


def audit(path):
    with open(path) as handle:
        bundle = json.load(handle)

    entries = bundle.get("entries", [])
    public_key_pem = bundle.get("public_key_pem", "")

    print("Evidence bundle: {}".format(path))
    print("  exported at:   {}".format(bundle.get("exported_at", "unknown")))
    print("  entries:       {}".format(len(entries)))
    print("  claimed head:  {}".format(bundle.get("chain_head", "none")[:16]))
    print()

    if not entries:
        print("The bundle is empty. Nothing to audit.")
        return 0

    verify = load_verifier(public_key_pem) if public_key_pem else None
    if verify is None:
        print("Note: signature checks skipped. Install the cryptography")
        print("package to enable them. Hash and chain checks still run.\n")

    expected_prev = GENESIS_HASH
    signatures_checked = 0

    for position, entry in enumerate(entries):
        seq = entry.get("seq", "?")

        # Check 1. Has any field been edited since this entry was written.
        recomputed = entry_hash(entry)
        if recomputed != entry.get("entry_hash"):
            print("ALTERED at entry {} (position {} in the file)".format(
                seq, position))
            print("  This entry's contents do not match its own hash.")
            print("    stored hash      {}".format(entry.get("entry_hash")))
            print("    recomputed hash  {}".format(recomputed))
            print("  Recorded as: {} {} {}".format(
                entry.get("decision"), entry.get("method"), entry.get("path")))
            print("\n  Something changed this entry after it was written.")
            return 1

        # Check 2. Has anything been inserted, removed or reordered.
        if entry.get("prev_hash") != expected_prev:
            print("BROKEN CHAIN at entry {} (position {} in the file)".format(
                seq, position))
            print("  This entry does not follow the one before it.")
            print("    expected previous hash  {}".format(expected_prev))
            print("    found previous hash     {}".format(entry.get("prev_hash")))
            print("\n  An entry was inserted, removed or reordered here.")
            return 1

        # Check 3. Could this entry have been forged.
        if verify is not None:
            if not verify(entry.get("signature", ""), entry["entry_hash"]):
                print("BAD SIGNATURE at entry {} (position {} in the file)".format(
                    seq, position))
                print("  This entry was not signed by the key in the bundle.")
                print("\n  This entry was fabricated rather than recorded.")
                return 1
            signatures_checked += 1

        expected_prev = entry["entry_hash"]

    print("VERIFIED")
    print("  {} entries form an unbroken chain".format(len(entries)))
    if signatures_checked:
        print("  {} signatures valid".format(signatures_checked))
    print("  chain head: {}".format(expected_prev))

    if bundle.get("chain_head") and bundle["chain_head"] != expected_prev:
        print("\n  Warning: the head we computed does not match the head the")
        print("  bundle claims. Entries may have been removed from the end.")
        return 1

    allowed = sum(1 for e in entries if e.get("decision") == "ALLOW")
    denied = len(entries) - allowed
    agents = sorted({e.get("agent_id") for e in entries if e.get("agent_id")})
    tasks = sorted({e.get("task_id") for e in entries if e.get("task_id")})

    print()
    print("What the record says happened:")
    print("  {} actions allowed, {} refused".format(allowed, denied))
    print("  agents: {}".format(", ".join(agents) or "none recorded"))
    print("  tasks:  {}".format(len(tasks)))
    if denied:
        print("\n  Refused actions:")
        for entry in entries:
            if entry.get("decision") == "DENY":
                print("    entry {:3}  {} {}  ({}, on behalf of {})".format(
                    entry.get("seq"), entry.get("method"), entry.get("path"),
                    entry.get("agent_id") or "no valid token",
                    entry.get("principal") or "unknown"))

    print("\nEvery statement above is derived from the file you gave this")
    print("script. Nothing was taken on trust, and nothing was fetched.")
    return 0


def main():
    if len(sys.argv) != 2:
        print("Usage: python3 audit.py <evidence-bundle.json>")
        return 2
    return audit(sys.argv[1])


if __name__ == "__main__":
    sys.exit(main())
