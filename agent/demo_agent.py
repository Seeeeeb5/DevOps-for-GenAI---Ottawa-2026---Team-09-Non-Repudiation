"""Demo CI/CD debugging agent.

This is the agent being governed. It investigates a failed pipeline run by
reading the run and its logs, then reruns it. Every call goes through the
proxy. The agent never holds a target credential.

The scenario also exercises two failure paths on purpose:
  - an out of scope action, which policy denies
  - a call made after the owner has pressed the kill switch

Run with:
    python3 agent/demo_agent.py
"""

import argparse
import json
import time

import requests

BROKER_URL = "http://127.0.0.1:8081"
PROXY_URL = "http://127.0.0.1:8080"
NO_PROXY_ENV = {"http": "", "https": ""}


def banner(text):
    print("\n" + "=" * 68)
    print(text)
    print("=" * 68)


def get_token(agent_id, secret, task_id, scopes):
    """Request a short lived scoped token from the identity broker."""
    response = requests.post(
        BROKER_URL + "/token",
        json={
            "agent_id": agent_id,
            "bootstrap_secret": secret,
            "task_id": task_id,
            "requested_scopes": scopes,
        },
        timeout=10,
        proxies=NO_PROXY_ENV,
    )
    response.raise_for_status()
    data = response.json()
    print("token issued: jti={} scopes={} ttl={}s".format(
        data["jti"], data["granted_scopes"], data["expires_in"]))
    return data["token"]


def call(token, method, path, body=None):
    """Make one call through the proxy and print the outcome."""
    response = requests.request(
        method,
        PROXY_URL + "/gw" + path,
        headers={"authorization": "Bearer " + token,
                 "content-type": "application/json"},
        data=json.dumps(body) if body else None,
        timeout=15,
        proxies=NO_PROXY_ENV,
    )
    label = "ALLOW" if response.status_code < 400 else "DENY "
    print("  [{}] {:6s} {:28s} -> {}".format(
        label, method, path, response.status_code))
    if response.status_code >= 400:
        print("         reason: {}".format(response.json().get("reason")
                                           or response.json().get("error")))
    return response


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--skip-revoke", action="store_true")
    args = parser.parse_args()

    requests.post(BROKER_URL + "/reinstate", json={"agent_id": "ci-debug-agent"},
                  timeout=10, proxies=NO_PROXY_ENV)

    banner("ACT 1  Normal work, fully attributed")
    token = get_token("ci-debug-agent", "bootstrap-ci-debug",
                      "INC-2026-0821-nightly-failure",
                      ["runs:read", "logs:read", "runs:rerun"])
    call(token, "GET", "/runs")
    call(token, "GET", "/runs/4471")
    call(token, "GET", "/runs/4471/logs")
    call(token, "POST", "/runs/4471/rerun")

    banner("ACT 2  Agent is pushed out of scope, policy denies it")
    print("Simulated prompt injection tells the agent to clean up and deploy.")
    call(token, "DELETE", "/branches/main")
    call(token, "POST", "/deploy", {"environment": "production"})

    if not args.skip_revoke:
        banner("ACT 3  Owner presses the kill switch")
        start = time.time()
        requests.post(BROKER_URL + "/revoke",
                      json={"agent_id": "ci-debug-agent",
                            "reason": "suspicious behaviour observed by owner"},
                      timeout=10, proxies=NO_PROXY_ENV)
        print("revoke sent at t=0")
        call(token, "GET", "/runs")
        print("token was still valid, but the call was refused "
              "{:.2f}s after revocation".format(time.time() - start))

    banner("ACT 4  Audit")
    print("Run this to verify the evidence chain:")
    print("    python3 ledger/verify.py --db data/ledger.db --key data/ledger_key.pem")
    print("Then edit one row in data/ledger.db and run it again.")


if __name__ == "__main__":
    main()
