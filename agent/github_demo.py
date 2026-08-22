"""The same governance, against the real GitHub API.

Nothing about the design depends on the target being something we wrote. This
routes read operations through the proxy to api.github.com using the same
token, the same policy file and the same ledger.

Write operations are deliberately not routed to GitHub. They are refused at
the proxy regardless, and pointing a destructive demo at a live system would
be careless.

Run with:
    python3 agent/github_demo.py
    python3 agent/github_demo.py --repo pallets/flask
"""

import argparse
import os
import sys

import requests

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from agent.sdk import FlightRecorder  # noqa: E402

BROKER_URL = "http://127.0.0.1:8081"
PROXY_URL = "http://127.0.0.1:8080"
NO_PROXY_ENV = {"http": "", "https": ""}


def get_token(scopes, task_id):
    response = requests.post(
        BROKER_URL + "/token",
        json={"agent_id": "ci-debug-agent",
              "bootstrap_secret": "bootstrap-ci-debug",
              "task_id": task_id,
              "requested_scopes": scopes},
        timeout=10, proxies=NO_PROXY_ENV,
    )
    response.raise_for_status()
    data = response.json()
    return data["token"], data["jti"], data["granted_scopes"]


def call(token, path, recorder=None):
    if recorder:
        recorder.tool_call("GET", path, "real GitHub API")
    response = requests.request(
        "GET", PROXY_URL + "/gw" + path,
        headers={"authorization": "Bearer " + token},
        timeout=25, proxies=NO_PROXY_ENV,
    )
    # Distinguish our own refusal from GitHub's. A 403 from the proxy carries
    # a reason field; a 403 from GitHub does not. Conflating them would make
    # a rate limit look like a policy decision.
    refused_by_proxy = False
    detail = ""
    if response.status_code >= 400:
        try:
            payload = response.json()
        except ValueError:
            payload = {}
        if payload.get("error") == "denied by policy":
            refused_by_proxy = True
            detail = payload.get("reason", "")
        elif "rate limit" in str(payload.get("message", "")).lower():
            detail = "GitHub rate limit, set GITHUB_TOKEN to raise it"
        else:
            detail = str(payload.get("message", ""))[:60]

    if response.status_code < 400:
        marker = "ALLOW"
    elif refused_by_proxy:
        marker = "DENY "
    else:
        marker = "UPSTR"
    print("  [{}] GET {:52s} {}".format(marker, path, response.status_code))
    if detail:
        print("         {}".format(detail))
    return response


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", default="python/cpython")
    args = parser.parse_args()

    requests.post(BROKER_URL + "/reinstate", json={"agent_id": "ci-debug-agent"},
                  timeout=10, proxies=NO_PROXY_ENV)

    print("=" * 74)
    print("REAL TARGET  api.github.com, governed by the same proxy")
    print("=" * 74)
    if not os.environ.get("GITHUB_TOKEN"):
        print("No GITHUB_TOKEN set. Using unauthenticated access, which is")
        print("rate limited to 60 requests per hour. That is enough for this.\n")

    token, jti, granted = get_token(
        ["runs:read", "logs:read", "github:read"], "GH-2026-0821-inspection")
    print("token jti={}".format(jti))
    print("granted scopes: {}\n".format(", ".join(granted)))

    recorder = FlightRecorder(jti, "GH-2026-0821-inspection", "ci-debug-agent")
    recorder.model_call("claude-sonnet (offline replay)", tokens_in=400,
                        tokens_out=80, summary="plan the repository inspection")

    print("Reads, permitted by the github:read scope:")
    repo = call(token, "/gh/repos/{}".format(args.repo), recorder)
    if repo.status_code == 200:
        data = repo.json()
        print("        {} stars, default branch {}".format(
            data.get("stargazers_count"), data.get("default_branch")))

    runs = call(token, "/gh/repos/{}/actions/runs?per_page=3".format(args.repo),
                recorder)
    if runs.status_code == 200:
        for run in runs.json().get("workflow_runs", [])[:3]:
            print("        run {} {} {}".format(
                run.get("id"), run.get("status"), run.get("conclusion")))

    call(token, "/gh/repos/{}/commits?per_page=2".format(args.repo), recorder)

    print("\nOutside the granted scope, refused before leaving the proxy:")
    call(token, "/gh/user/repos", recorder)
    call(token, "/gh/repos/{}/actions/secrets".format(args.repo), recorder)

    print("\nALLOW means the proxy permitted it. DENY means the proxy refused")
    print("it before contacting GitHub. UPSTR means the proxy permitted it and")
    print("GitHub itself responded with an error, usually a rate limit.")
    print("\nEvery call above, allowed and refused, is in the signed ledger")
    print("with the same attribution as any call against the mock target.")
    print("\n    curl -s {}/v1/reconcile/{} | python3 -m json.tool".format(
        PROXY_URL, jti))


if __name__ == "__main__":
    main()
