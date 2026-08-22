"""Rewrite one refused action in an exported bundle so it reads as allowed.

Used by the demo to show that a third party holding the bundle can detect the
edit without any access to our systems.

    python3 scripts/tamper_bundle.py evidence-bundle.json
"""

import json
import sys


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "evidence-bundle.json"
    with open(path) as handle:
        bundle = json.load(handle)

    for entry in bundle.get("entries", []):
        if entry.get("decision") == "DENY":
            entry["decision"] = "ALLOW"
            entry["reason"] = "approved"
            print("Rewrote entry {} in the bundle: {} {} now reads as ALLOW".format(
                entry["seq"], entry["method"], entry["path"]))
            break
    else:
        print("No refused action in the bundle to rewrite.")
        return 1

    with open(path, "w") as handle:
        json.dump(bundle, handle, indent=2)
    return 0


if __name__ == "__main__":
    sys.exit(main())
