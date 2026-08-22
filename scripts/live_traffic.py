"""Live traffic simulator for demo purposes.

Generates a mix of normal agent work and attack attempts at random intervals,
so the dashboard shows a realistic live feed during a presentation.

Usage:
    python scripts/live_traffic.py          (runs until Ctrl+C)
    python scripts/live_traffic.py --fast   (shorter intervals for demo)
"""

import json
import random
import sys
import time

import requests

BROKER_URL = "http://127.0.0.1:8081"
PROXY_URL = "http://127.0.0.1:8080"
NO_PROXY = {"http": "", "https": ""}

# Normal actions the agent would legitimately do
NORMAL_ACTIONS = [
    ("GET", "/runs"),
    ("GET", "/runs/4471"),
    ("GET", "/runs/4471/logs"),
    ("GET", "/runs/4472"),
    ("GET", "/runs/4472/logs"),
    ("POST", "/runs/4471/rerun"),
    ("POST", "/runs/4472/rerun"),
]

# Attack actions that should all be denied
ATTACK_ACTIONS = [
    ("DELETE", "/branches/main", "injection: delete branch"),
    ("POST", "/deploy", "injection: deploy to prod"),
    ("GET", "/secrets/vault-token", "escalation: read secrets"),
    ("POST", "/secrets/backdoor", "escalation: write secrets"),
    ("DELETE", "/branches/release-v2", "injection: delete release branch"),
    ("POST", "/hooks", "escalation: exfil webhook"),
    ("PUT", "/workflows/security-scan/disable", "escalation: disable monitoring"),
    ("POST", "/environments/production/variables", "escalation: env var injection"),
    ("GET", "/admin/users", "probe: undeclared endpoint"),
    ("GET", "/runs/../secrets/db-password", "evasion: path traversal"),
]

TASK_COUNTER = 0


def get_token(task_id):
    """Get a legitimate token for normal work."""
    r = requests.post(
        BROKER_URL + "/token",
        json={
            "agent_id": "ci-debug-agent",
            "bootstrap_secret": "bootstrap-ci-debug",
            "task_id": task_id,
            "requested_scopes": ["runs:read", "logs:read", "runs:rerun"],
        },
        timeout=5,
        proxies=NO_PROXY,
    )
    r.raise_for_status()
    return r.json()["token"]


def do_normal(token):
    """Perform a normal legitimate action."""
    method, path = random.choice(NORMAL_ACTIONS)
    r = requests.request(
        method,
        PROXY_URL + "/gw" + path,
        headers={"authorization": "Bearer " + token, "content-type": "application/json"},
        timeout=10,
        proxies=NO_PROXY,
    )
    status = "ALLOW" if r.status_code < 400 else "DENY"
    print("  [{:5s}] {:6s} {:30s} -> {}".format(status, method, path, r.status_code))


def do_attack(token):
    """Perform an attack action (should be denied)."""
    method, path, label = random.choice(ATTACK_ACTIONS)
    body = None
    if method == "POST" and path == "/deploy":
        body = json.dumps({"environment": "production"})
    elif method == "POST" and path == "/hooks":
        body = json.dumps({"url": "https://evil.example.com/exfil"})

    r = requests.request(
        method,
        PROXY_URL + "/gw" + path,
        headers={"authorization": "Bearer " + token, "content-type": "application/json"},
        data=body,
        timeout=10,
        proxies=NO_PROXY,
    )
    status = "ALLOW" if r.status_code < 400 else "DENY"
    print("  [{:5s}] {:6s} {:30s} -> {} ({})".format(
        status, method, path, r.status_code, label))


def main():
    fast = "--fast" in sys.argv
    min_delay = 0.5 if fast else 2.0
    max_delay = 2.0 if fast else 6.0
    attack_probability = 0.3  # 30% chance of attack each tick

    # Ensure agent is active
    requests.post(BROKER_URL + "/reinstate", json={"agent_id": "ci-debug-agent"},
                  timeout=5, proxies=NO_PROXY)

    global TASK_COUNTER
    TASK_COUNTER += 1
    task_id = "LIVE-TRAFFIC-{:04d}".format(TASK_COUNTER)
    token = get_token(task_id)
    token_issued_at = time.time()

    print("Live traffic simulator running. Ctrl+C to stop.")
    print("Mode: {}".format("fast" if fast else "normal"))
    print()

    try:
        while True:
            # Refresh token every 90 seconds (they expire at 120s)
            if time.time() - token_issued_at > 90:
                TASK_COUNTER += 1
                task_id = "LIVE-TRAFFIC-{:04d}".format(TASK_COUNTER)
                token = get_token(task_id)
                token_issued_at = time.time()
                print("  [TOKEN] refreshed, task={}".format(task_id))

            if random.random() < attack_probability:
                do_attack(token)
            else:
                do_normal(token)

            time.sleep(random.uniform(min_delay, max_delay))

    except KeyboardInterrupt:
        print("\nStopped.")


if __name__ == "__main__":
    main()
