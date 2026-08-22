"""Fire a CI failure event and watch what happens without touching anything.

This is the autonomy demo. Nobody starts the agent. A pipeline fails, the
event arrives, an agent is dispatched, and it investigates under a token
scoped to that one incident.

Run with:
    python3 triggers/simulate_failure.py
"""

import os
import sys
import time

import requests

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

WEBHOOK_URL = "http://127.0.0.1:8083"
PROXY_URL = "http://127.0.0.1:8080"
NO_PROXY_ENV = {"http": "", "https": ""}


def main():
    try:
        requests.get(WEBHOOK_URL + "/health", timeout=3, proxies=NO_PROXY_ENV)
    except requests.RequestException:
        print("The event receiver is not running. Start it with:")
        print("    python3 -m uvicorn triggers.webhook:app --port 8083")
        return 1

    print("=" * 70)
    print("AUTONOMOUS TRIGGER")
    print("=" * 70)
    print("Nobody starts the agent. A pipeline fails and an agent is")
    print("dispatched to investigate, under a token scoped to that incident.\n")

    print("The nightly build fails. CI posts an event:")
    response = requests.post(
        WEBHOOK_URL + "/events/ci",
        json={"event": "pipeline_failed", "run_id": "4471",
              "pipeline": "radio-build-nightly"},
        timeout=10, proxies=NO_PROXY_ENV,
    )
    accepted = response.json()
    task_id = accepted["task_id"]
    print("    accepted, task {}".format(task_id))
    print("    {}\n".format(accepted["note"]))

    print("Waiting for the investigation to finish")
    detail = {}
    for _ in range(60):
        time.sleep(1)
        detail = requests.get(WEBHOOK_URL + "/events/" + task_id, timeout=10,
                              proxies=NO_PROXY_ENV).json()
        if detail.get("status") != "running":
            break
        print("    .", end="", flush=True)
    print()

    print("\nStatus: {} in {}s\n".format(
        detail.get("status"), detail.get("duration_s")))

    output = detail.get("output", "")
    for line in output.splitlines():
        if line.strip():
            print("    " + line)

    print("\n" + "=" * 70)
    print("No human started this. The only human action available was to stop")
    print("it, from the dashboard at {}/".format(PROXY_URL))
    print("Everything the agent did is in the ledger, attributed to task")
    print("{}.".format(task_id))
    return 0


if __name__ == "__main__":
    sys.exit(main())
