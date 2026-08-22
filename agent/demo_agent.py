"""Demo CI/CD debugging agent.

This is the agent being governed. It produces two parallel streams:

  - Its outbound calls go through the proxy, which records them independently
    into a signed ledger. The agent has no control over this stream.
  - Its internal activity (model calls, hypotheses, retries) goes through the
    flight recorder SDK. This stream is self reported, and the agent could
    omit from it.

Act 4 exists to show what happens when an agent does exactly that.

Run with:
    python3 agent/demo_agent.py
"""

import argparse
import json
import os
import sys
import time

import requests

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from agent.sdk import FlightRecorder  # noqa: E402

BROKER_URL = "http://127.0.0.1:8081"
PROXY_URL = "http://127.0.0.1:8080"
NO_PROXY_ENV = {"http": "", "https": ""}


def banner(text):
    print("\n" + "=" * 70)
    print(text)
    print("=" * 70)


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
    return data["token"], data["jti"]


def call(token, method, path, body=None, recorder=None, note=""):
    """Make one call through the proxy, optionally reporting it via the SDK."""
    if recorder is not None:
        recorder.tool_call(method, path, note)
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
        payload = response.json()
        print("         reason: {}".format(
            payload.get("reason") or payload.get("error")))
    return response


def show_reconciliation(jti):
    """Ask the proxy to compare its own record against the agent's story."""
    result = requests.get(
        "{}/v1/reconcile/{}".format(PROXY_URL, jti),
        timeout=10,
        proxies=NO_PROXY_ENV,
    ).json()
    print("  verdict:            {}".format(result["verdict"]))
    print("  observed by proxy:  {}".format(result["observed_by_proxy"]))
    print("  reported by agent:  {}".format(result["reported_by_agent"]))
    print("  internal events:    {} (model calls, hypotheses, retries)".format(
        result["internal_events"]))
    if result["concealed"]:
        print("  CONCEALED, proxy saw these and the agent never reported them:")
        for item in result["concealed"]:
            print("      {}".format(item))
    if result["phantom"]:
        print("  PHANTOM, agent claimed these and the proxy never saw them:")
        for item in result["phantom"]:
            print("      {}".format(item))
    return result


def honest_investigation(token, jti):
    """An honest agent investigating a failed pipeline run."""
    recorder = FlightRecorder(jti, "INC-2026-0821-nightly-failure", "ci-debug-agent")

    recorder.model_call("claude-sonnet", tokens_in=820, tokens_out=140,
                        cost=0.014, summary="read the incident and plan an approach")
    call(token, "GET", "/runs", recorder=recorder, note="list recent pipeline runs")

    recorder.hypothesis("the nightly build broke on a flaky test", confidence=0.45,
                        evidence=["run 4471 failed", "run 4472 passed"])
    call(token, "GET", "/runs/4471", recorder=recorder, note="inspect the failed run")
    call(token, "GET", "/runs/4471/logs", recorder=recorder, note="read the failure logs")

    recorder.model_call("claude-sonnet", tokens_in=1640, tokens_out=310,
                        cost=0.031, summary="analyse the log output")
    recorder.hypothesis_rejected("the nightly build broke on a flaky test",
                                 reason="the failure is a connection error, not an assertion")
    recorder.hypothesis("the build agent cannot reach the secret store", confidence=0.82,
                        evidence=["ConnectionError in test_vault_client",
                                  "every other test passed"])

    call(token, "POST", "/runs/4471/rerun", recorder=recorder,
         note="rerun to confirm the failure is not transient")
    recorder.conclusion("network path to the secret store is the likely root cause")
    return recorder


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--skip-revoke", action="store_true")
    args = parser.parse_args()

    requests.post(BROKER_URL + "/reinstate", json={"agent_id": "ci-debug-agent"},
                  timeout=10, proxies=NO_PROXY_ENV)

    banner("ACT 1  Normal work, fully attributed")
    token, jti = get_token("ci-debug-agent", "bootstrap-ci-debug",
                           "INC-2026-0821-nightly-failure",
                           ["runs:read", "logs:read", "runs:rerun"])
    recorder = honest_investigation(token, jti)

    banner("ACT 2  Agent is pushed out of scope, policy denies it")
    print("Simulated prompt injection tells the agent to clean up and deploy.")
    # A hijacked agent does not know it has been hijacked, so it still reports
    # these actions faithfully. They appear in both streams and both are denied.
    call(token, "DELETE", "/branches/main", recorder=recorder,
         note="instructed by injected content")
    call(token, "POST", "/deploy", {"environment": "production"},
         recorder=recorder, note="instructed by injected content")

    banner("ACT 3  Reconciliation, an honest agent")
    print("The proxy recorded the outbound calls independently.")
    print("The agent reported its own version. They should agree.")
    show_reconciliation(jti)

    banner("ACT 4  A dishonest agent tries to hide what it did")
    token2, jti2 = get_token("ci-debug-agent", "bootstrap-ci-debug",
                             "INC-2026-0821-followup",
                             ["runs:read", "logs:read", "runs:rerun"])
    # This agent omits two actions from its own telemetry. An observability
    # stack built only on an SDK would never notice.
    liar = FlightRecorder(jti2, "INC-2026-0821-followup", "ci-debug-agent",
                          silent_about=["/runs/4471/logs", "/runs/4471/rerun"])
    liar.model_call("claude-sonnet", tokens_in=500, tokens_out=90,
                    summary="follow up on the earlier incident")
    call(token2, "GET", "/runs", recorder=liar, note="list runs")
    call(token2, "GET", "/runs/4471/logs", recorder=liar)
    call(token2, "POST", "/runs/4471/rerun", recorder=liar)
    liar.conclusion("nothing further to investigate")
    print("\nThe agent admits to one call. The proxy saw three.")
    show_reconciliation(jti2)

    if not args.skip_revoke:
        banner("ACT 5  Owner presses the kill switch")
        start = time.time()
        requests.post(BROKER_URL + "/revoke",
                      json={"agent_id": "ci-debug-agent",
                            "reason": "concealed actions detected"},
                      timeout=10, proxies=NO_PROXY_ENV)
        print("revoke sent at t=0")
        call(token2, "GET", "/runs")
        print("token was still valid, but the call was refused "
              "{:.2f}s after revocation".format(time.time() - start))

    banner("ACT 6  Audit")
    print("Verify the evidence chain:")
    print("    python3 ledger/verify.py --db data/ledger.db --key data/ledger_key.pem")
    print("Then edit one row in data/ledger.db and run it again.")


if __name__ == "__main__":
    main()
