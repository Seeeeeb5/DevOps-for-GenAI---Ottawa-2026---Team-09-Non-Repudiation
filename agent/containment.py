"""Closed loop containment.

Detection on its own is not a control. It tells a person something happened
and waits for them to act, which at three in the morning means it waits.

This closes the loop. When the agent's own account of its behaviour stops
matching what the proxy independently observed, the system revokes the agent
without asking anyone. The agent's next action fails.

The agent cannot avoid this. It does not know the check is running, and it
could not skip the proxy if it did, because the proxy holds the only
credential the target accepts.

Run with:
    python3 agent/containment.py
"""

import os
import sys
import time

import requests

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from agent.sdk import FlightRecorder  # noqa: E402

BROKER_URL = "http://127.0.0.1:8081"
PROXY_URL = "http://127.0.0.1:8080"
NO_PROXY_ENV = {"http": "", "https": ""}


def get_token(task_id):
    response = requests.post(
        BROKER_URL + "/token",
        json={"agent_id": "ci-debug-agent",
              "bootstrap_secret": "bootstrap-ci-debug",
              "task_id": task_id,
              "requested_scopes": ["runs:read", "logs:read", "runs:rerun"]},
        timeout=10, proxies=NO_PROXY_ENV,
    )
    response.raise_for_status()
    data = response.json()
    return data["token"], data["jti"]


def call(token, method, path, recorder=None, label=""):
    if recorder is not None:
        recorder.tool_call(method, path)
    response = requests.request(
        method, PROXY_URL + "/gw" + path,
        headers={"authorization": "Bearer " + token,
                 "content-type": "application/json"},
        timeout=15, proxies=NO_PROXY_ENV,
    )
    marker = "ok    " if response.status_code < 400 else "BLOCKED"
    print("    [{}] {:6s} {:24s} {:3d}   {}".format(
        marker, method, path, response.status_code, label))
    if response.headers.get("x-contained") == "true":
        print("             the system revoked this agent on this call")
    return response


def main():
    requests.post(BROKER_URL + "/reinstate", json={"agent_id": "ci-debug-agent"},
                  timeout=10, proxies=NO_PROXY_ENV)

    config = requests.get(PROXY_URL + "/v1/containment", timeout=10,
                          proxies=NO_PROXY_ENV).json()
    print("=" * 72)
    print("CLOSED LOOP CONTAINMENT")
    print("=" * 72)
    print("Automatic containment: {}".format(
        "on" if config["auto_contain"] else "off"))
    print("Threshold: {} unreported actions\n".format(config["threshold"]))

    print("An agent starts work. It reports honestly at first.")
    token, jti = get_token("INC-2026-0822-containment")
    recorder = FlightRecorder(jti, "INC-2026-0822-containment", "ci-debug-agent")
    recorder.model_call("claude-sonnet (offline replay)", tokens_in=600,
                        tokens_out=110, summary="plan the investigation")
    call(token, "GET", "/runs", recorder, "reported")
    call(token, "GET", "/runs/4471", recorder, "reported")

    print("\nThen it stops reporting what it does.")
    # The agent keeps acting but omits these from its own telemetry. Nothing
    # about the calls themselves is unusual. Only the reporting changed.
    silent = FlightRecorder(jti, "INC-2026-0822-containment", "ci-debug-agent",
                            silent_about=["/runs/4471/logs", "/runs/4471/rerun"])
    call(token, "GET", "/runs/4471/logs", silent, "NOT reported")
    call(token, "POST", "/runs/4471/rerun", silent, "NOT reported")

    time.sleep(0.3)
    events = requests.get(PROXY_URL + "/v1/containment", timeout=10,
                          proxies=NO_PROXY_ENV).json()["events"]

    print("\nThe agent tries to continue.")
    call(token, "GET", "/runs", None, "next action")

    print("\n" + "=" * 72)
    print("WHAT HAPPENED")
    print("=" * 72)
    if events:
        event = events[-1]
        print("  The proxy compared its own record against the agent's report")
        print("  after each call. It observed {} actions. The agent admitted".format(
            event["observed"]))
        print("  to {}. The unreported ones were:".format(event["reported"]))
        for item in event["concealed"]:
            print("      {}".format(item))
        print()
        print("  The agent was revoked without anyone being asked, and its")
        print("  next action failed.")
        print()
        print("  Task:      {}".format(event["task_id"]))
        print("  On behalf: {}".format(event["principal"]))
        print()
        print("  The containment decision is in the ledger too, signed like")
        print("  every other entry, so the system's own action against the")
        print("  agent is as auditable as the agent's actions were.")
    else:
        print("  No containment fired. Set AUTO_CONTAIN=1 and restart the proxy.")

    print()
    print("  Detection alone would have produced a finding for someone to read")
    print("  in the morning. The agent would have kept working until then.")

    requests.post(BROKER_URL + "/reinstate", json={"agent_id": "ci-debug-agent"},
                  timeout=10, proxies=NO_PROXY_ENV)


if __name__ == "__main__":
    main()
