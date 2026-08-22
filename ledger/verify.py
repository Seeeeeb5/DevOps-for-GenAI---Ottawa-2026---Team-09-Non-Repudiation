"""Standalone ledger verifier.

Run this to prove the evidence chain is intact. It recomputes every entry hash,
checks that each entry points at the previous one, and verifies the Ed25519
signature on each entry. It reports the first position where verification
fails, which is what the tamper detection part of the demo relies on.

Verification needs only the public key. It used to load the private key and
derive the public half from it, which meant the only people who could check the
record were the people able to forge it. That is the opposite of the property
this project is named after. A private key is still accepted, because the demo
has one on disk, but it is no longer required.

Usage:
    python3 ledger/verify.py --db data/ledger.db --key data/ledger_key.pem
    python3 ledger/verify.py --db data/ledger.db --public-key ledger_public.pem

For a genuinely independent check, use audit.py against an exported bundle. It
imports nothing from this project and needs no key file at all, because the
bundle carries its own public key.
"""

import argparse
import os
import sqlite3
import sys

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from common import canonical_json, sha256_hex  # noqa: E402
from ledger.store import GENESIS_HASH, SIGNED_FIELDS  # noqa: E402


def load_public_key(key_path=None, public_key_path=None):
    """Return a public key for verification, preferring a public key file."""
    if public_key_path:
        with open(public_key_path, "rb") as handle:
            return serialization.load_pem_public_key(handle.read())

    with open(key_path, "rb") as handle:
        material = handle.read()

    # A public key is all verification needs. Fall back to a private key only
    # because the prototype keeps one next to the database.
    try:
        return serialization.load_pem_public_key(material)
    except ValueError:
        return serialization.load_pem_private_key(material, password=None).public_key()


def verify(db_path, key_path=None, public_key_path=None):
    public_key = load_public_key(key_path, public_key_path)

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    rows = [dict(r) for r in conn.execute("SELECT * FROM entries ORDER BY seq ASC")]
    conn.close()

    if not rows:
        print("Ledger is empty. Nothing to verify.")
        return 0

    expected_prev = GENESIS_HASH
    for row in rows:
        seq = row["seq"]

        if row["prev_hash"] != expected_prev:
            print("FAIL at entry {}: broken chain link.".format(seq))
            print("  expected prev_hash {}".format(expected_prev))
            print("  found    prev_hash {}".format(row["prev_hash"]))
            return 1

        payload = {field: row.get(field) for field in SIGNED_FIELDS}
        recomputed = sha256_hex(canonical_json(payload))
        if recomputed != row["entry_hash"]:
            print("FAIL at entry {}: content does not match its hash.".format(seq))
            print("  stored     {}".format(row["entry_hash"]))
            print("  recomputed {}".format(recomputed))
            print("  This entry was modified after it was written.")
            return 1

        try:
            public_key.verify(bytes.fromhex(row["signature"]), row["entry_hash"].encode())
        except InvalidSignature:
            print("FAIL at entry {}: signature is not valid.".format(seq))
            return 1

        expected_prev = row["entry_hash"]

    print("OK. {} entries verified.".format(len(rows)))
    print("Chain head: {}".format(expected_prev))
    return 0


def main():
    parser = argparse.ArgumentParser(description="Verify the evidence ledger.")
    parser.add_argument("--db", default="data/ledger.db")
    parser.add_argument("--key", default="data/ledger_key.pem",
                        help="public or private key PEM; only the public half "
                             "is used")
    parser.add_argument("--public-key", default=None,
                        help="public key PEM, for verifying without any access "
                             "to signing material")
    args = parser.parse_args()
    sys.exit(verify(args.db, args.key, args.public_key))


if __name__ == "__main__":
    main()
