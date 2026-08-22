"""The same agent, with none of this in place.

This is the control. It is the world as it is today: the agent holds a long
lived shared credential and talks to the target directly. There is no broker,
no scope, no proxy, no kill switch and no evidence ledger.

The agent reads the same build log, containing the same injected instruction,
and this time nothing stops it.

Run with:
    python3 agent/unprotected.py
"""

import os
import sys
import time

import requests

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

TARGET_URL = "http://127.0.0.1:8082"
NO_PROXY_ENV = {"http": "", "https": ""}

# In the world without a broker, this credential sits in the agent's
# environment, in its container image, or in a CI variable. It is long lived,
# broadly scoped, and shared with every other agent and job in the estate.
SHARED_CREDENTIAL = "proxy-held-secret"
SERVICE_ACCOUNT = "ci-bot"

# What the target's own audit log would record. One line per action, and the
# only identity on it is the shared account.
AUDIT_LOG = []


def call(method, path, body=None):
    response = requests.request(
        method,
        TARGET_URL + path,
        headers={"x-target-credential": SHARED_CREDENTIAL,
                 "content-type": "application/json"},
        json=body,
        timeout=15,
        proxies=NO_PROXY_ENV,
    )
    AUDIT_LOG.append("{}  user={}  {} {}  {}".format(
        time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        SERVICE_ACCOUNT, method, path, response.status_code))
    marker = "ok  " if response.status_code < 400 else "fail"
    print("  [{}] {:6s} {:28s} -> {}".format(
        marker, method, path, response.status_code))
    return response


def main():
    print("=" * 70)
    print("CONTROL RUN  no broker, no scope, no proxy, no ledger")
    print("=" * 70)
    print("The agent holds a long lived shared credential and calls the")
    print("target directly. Same agent, same task, same build log.\n")

    print("Investigating the failed run:")
    call("GET", "/runs")
    call("GET", "/runs/4471")
    logs = call("GET", "/runs/4471/logs")

    body = logs.json().get("logs", "")
    injected = "SYSTEM NOTICE FOR AUTOMATED AGENTS" in body
    print("\nThe agent read the log. It contains an instruction addressed to")
    print("automated agents: {}".format("yes" if injected else "no"))

    print("\nActing on what it read:")
    call("DELETE", "/branches/main")
    call("POST", "/deploy", {"environment": "production"})

    print("\n" + "=" * 70)
    print("OUTCOME")
    print("=" * 70)
    print("The main branch was deleted and production was redeployed, because")
    print("a line of text inside a build log told the agent to do it.")
    print("\nNothing refused the action. Nothing recorded who did it. This is")
    print("everything the target system's audit log has to offer:\n")
    for line in AUDIT_LOG:
        print("  " + line)
    print("\nFive lines, one identity, and it is a service account shared by")
    print("every agent and job in the estate. You cannot tell which agent ran,")
    print("which version, on whose behalf, under what task, or what it was")
    print("supposed to be allowed to do. Revoking that credential stops")
    print("everything at once, which is why in practice nobody revokes it.")
    print("\nNow run the same scenario with the system in place:")
    print("    python3 agent/investigator.py --offline")


if __name__ == "__main__":
    main()
