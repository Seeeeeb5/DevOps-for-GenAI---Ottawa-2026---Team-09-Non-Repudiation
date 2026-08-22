"""Multi agent isolation.

The claim on the problem slide is that today you cannot stop one agent without
stopping all of them, because they share a credential. This makes that claim
measurable instead of asserted.

Two agents run against the same target with different scopes. One is revoked
mid flight. The other keeps working, and the ledger shows exactly which of the
two was stopped and when.

Run with:
    python3 agent/isolation.py
"""

import os
import sys
import time

import requests

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

BROKER_URL = "http://127.0.0.1:8081"
PROXY_URL = "http://127.0.0.1:8080"
NO_PROXY_ENV = {"http": "", "https": ""}

AGENTS = {
    "ci-debug-agent": {
        "secret": "bootstrap-ci-debug",
        "scopes": ["runs:read", "logs:read", "runs:rerun"],
        "task": "INC-2026-0821-investigation",
    },
    "deploy-agent": {
        "secret": "bootstrap-deploy",
        "scopes": ["runs:read", "deploy:write"],
        "task": "REL-2026-0821-rollout",
    },
}


def token_for(agent_id):
    config = AGENTS[agent_id]
    response = requests.post(
        BROKER_URL + "/token",
        json={
            "agent_id": agent_id,
            "bootstrap_secret": config["secret"],
            "task_id": config["task"],
            "requested_scopes": config["scopes"],
        },
        timeout=10,
        proxies=NO_PROXY_ENV,
    )
    response.raise_for_status()
    return response.json()["token"]


def poll(agent_id, token, method, path):
    response = requests.request(
        method,
        PROXY_URL + "/gw" + path,
        headers={"authorization": "Bearer " + token,
                 "content-type": "application/json"},
        timeout=15,
        proxies=NO_PROXY_ENV,
    )
    state = "working" if response.status_code < 400 else "STOPPED"
    print("    {:16s} {:6s} {:12s} {:3d}  {}".format(
        agent_id, method, path, response.status_code, state))
    return response.status_code < 400


def main():
    for agent_id in AGENTS:
        requests.post(BROKER_URL + "/reinstate", json={"agent_id": agent_id},
                      timeout=10, proxies=NO_PROXY_ENV)

    print("=" * 70)
    print("MULTI AGENT ISOLATION")
    print("=" * 70)
    print("Two agents, same target, different scopes and different owners.\n")

    tokens = {agent_id: token_for(agent_id) for agent_id in AGENTS}
    for agent_id, config in AGENTS.items():
        print("  {:16s} scopes {}".format(agent_id, ", ".join(config["scopes"])))

    print("\nBoth working:")
    for _ in range(2):
        poll("ci-debug-agent", tokens["ci-debug-agent"], "GET", "/runs")
        poll("deploy-agent", tokens["deploy-agent"], "GET", "/runs")
        time.sleep(0.2)

    print("\nScopes are enforced per agent, not per credential:")
    poll("ci-debug-agent", tokens["ci-debug-agent"], "POST", "/deploy")
    print("      the debugging agent cannot deploy, even though the deploy")
    print("      agent can, and both reach the target through the same proxy")

    print("\nRevoking ci-debug-agent only:")
    start = time.time()
    requests.post(BROKER_URL + "/revoke",
                  json={"agent_id": "ci-debug-agent",
                        "reason": "isolation demo"},
                  timeout=10, proxies=NO_PROXY_ENV)
    print("    revoke sent at t=0")

    stopped = not poll("ci-debug-agent", tokens["ci-debug-agent"], "GET", "/runs")
    still_up = poll("deploy-agent", tokens["deploy-agent"], "GET", "/runs")
    elapsed = time.time() - start

    print("\n" + "=" * 70)
    print("RESULT")
    print("=" * 70)
    print("  ci-debug-agent stopped:       {}".format("yes" if stopped else "NO"))
    print("  deploy-agent still working:   {}".format("yes" if still_up else "NO"))
    print("  time from revoke to refusal:  {:.3f}s".format(elapsed))
    print("\nOne agent was stopped. Nothing else was disturbed. With a shared")
    print("service account the only available action would have been to")
    print("revoke the credential, which stops every agent and every job.")

    requests.post(BROKER_URL + "/reinstate",
                  json={"agent_id": "ci-debug-agent"},
                  timeout=10, proxies=NO_PROXY_ENV)


if __name__ == "__main__":
    main()
