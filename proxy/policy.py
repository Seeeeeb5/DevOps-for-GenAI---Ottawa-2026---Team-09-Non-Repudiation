"""Request to scope mapping.

Every request that reaches the proxy is mapped to exactly one required scope.
If the agent token does not carry that scope, the call is denied before it ever
reaches the target system. Anything that does not match a rule is denied by
default, so adding a new endpoint to the target does not silently widen what
agents can do.
"""

import re

# Each rule is (method, compiled path pattern, required scope, risk label).
RULES = [
    ("GET", re.compile(r"^/runs/?$"), "runs:read", "low"),
    ("GET", re.compile(r"^/runs/[^/]+/?$"), "runs:read", "low"),
    ("GET", re.compile(r"^/runs/[^/]+/logs/?$"), "logs:read", "low"),
    ("POST", re.compile(r"^/runs/[^/]+/rerun/?$"), "runs:rerun", "medium"),
    ("POST", re.compile(r"^/deploy/?$"), "deploy:write", "high"),
    ("DELETE", re.compile(r"^/branches/[^/]+/?$"), "branches:delete", "high"),
]


def resolve(method, path):
    """Return (required_scope, risk) for a request, or (None, None) if unknown."""
    normalized = path if path.startswith("/") else "/" + path
    for rule_method, pattern, scope, risk in RULES:
        if rule_method == method.upper() and pattern.match(normalized):
            return scope, risk
    return None, None


def decide(method, path, token_scopes):
    """Return (allowed, required_scope, risk, reason)."""
    required, risk = resolve(method, path)
    if required is None:
        return False, None, None, "no policy rule matches this request, denied by default"
    if required not in token_scopes:
        return (
            False,
            required,
            risk,
            "token does not carry the required scope {}".format(required),
        )
    return True, required, risk, "scope {} present in token".format(required)
