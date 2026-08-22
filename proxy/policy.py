"""Policy engine.

Rules live in policies/policy.json rather than in this file, so that changing
what an agent may do is a reviewable diff to a data file instead of a code
change. Every request is mapped to exactly one required scope. Anything that
matches no rule is denied, so adding an endpoint to the target system does not
silently widen what agents can reach.
"""

import json
import os
import re

POLICY_PATH = os.environ.get(
    "POLICY_PATH",
    os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "policies",
        "policy.json",
    ),
)

_cache = {"mtime": None, "rules": [], "meta": {}}


def load(force=False):
    """Load the policy file, reloading automatically when it changes on disk."""
    try:
        mtime = os.path.getmtime(POLICY_PATH)
    except OSError:
        return _cache["rules"]

    if force or _cache["mtime"] != mtime:
        with open(POLICY_PATH) as handle:
            document = json.load(handle)
        compiled = []
        for rule in document.get("rules", []):
            compiled.append({
                "id": rule["id"],
                "method": rule["method"].upper(),
                "pattern": re.compile(rule["path"]),
                "scope": rule["scope"],
                "risk": rule.get("risk", "unknown"),
                "note": rule.get("note", ""),
            })
        _cache["rules"] = compiled
        _cache["mtime"] = mtime
        _cache["meta"] = {
            "version": document.get("version"),
            "rule_count": len(compiled),
        }
    return _cache["rules"]


def meta():
    load()
    return _cache["meta"]


def describe():
    """Return the rule set in a form the dashboard can display."""
    return [
        {
            "id": r["id"],
            "method": r["method"],
            "path": r["pattern"].pattern,
            "scope": r["scope"],
            "risk": r["risk"],
            "note": r["note"],
        }
        for r in load()
    ]


def resolve(method, path):
    """Return (rule_id, required_scope, risk) for a request, or Nones."""
    normalized = path if path.startswith("/") else "/" + path
    for rule in load():
        if rule["method"] == method.upper() and rule["pattern"].match(normalized):
            return rule["id"], rule["scope"], rule["risk"]
    return None, None, None


def decide(method, path, token_scopes):
    """Return (allowed, required_scope, risk, reason)."""
    rule_id, required, risk = resolve(method, path)
    if required is None:
        return False, None, None, "no policy rule matches this request, denied by default"
    if required not in token_scopes:
        return (
            False,
            required,
            risk,
            "token does not carry the required scope {}".format(required),
        )
    return True, required, risk, "rule {} allows this, scope {} present".format(rule_id, required)
