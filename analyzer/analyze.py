"""Trace analyzer.

Owner: Sebastian.

Everything mechanical is already done here. The trace is fetched from both
streams, merged into one ordered timeline, reconciled, and rule based findings
are computed without a model. The parts left for you are marked TODO and are
the parts that actually need judgement.

What is already working:
  - fetch_trace()      pulls the signed ledger and the self reported telemetry
                       for one token and merges them into one timeline
  - rule_findings()    detects duplicate calls, retry loops, denied attempts,
                       concealment and cost, all in plain code
  - build_prompt()     assembles the prompt for the model
  - llm_findings()     calls the model and parses the response

What is left for you:
  1. Extend rule_findings with any pattern you think is worth catching.
     Cheap, deterministic and does not need a model. Do these first.
  2. Tune the prompt in build_prompt. The current one is a starting point.
  3. Decide how findings render. Right now they print. The dashboard has a
     panel waiting at /v1/analysis.

Design note worth keeping. Use code for anything the system already knows
exactly (counts, timings, cost, duplicates, denials) and the model only for
things that need interpretation (was this a reasonable investigation order,
did the agent waste effort, what should change). Asking a model to count is
slow, expensive and less reliable than a loop.

Run with:
    python3 analyzer/analyze.py --jti <token id>
    python3 analyzer/analyze.py --latest
"""

import argparse
import collections
import json
import os
import sys

import requests

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

PROXY_URL = "http://127.0.0.1:8080"
API_URL = "https://api.anthropic.com/v1/messages"
MODEL = os.environ.get("AGENT_MODEL", "claude-sonnet-4-6")
NO_PROXY_ENV = {"http": "", "https": ""}


def fetch_trace(jti):
    """Pull both streams for one token and merge them into one timeline."""
    ledger = requests.get(PROXY_URL + "/v1/ledger?limit=500", timeout=15,
                          proxies=NO_PROXY_ENV).json()["entries"]
    telemetry = requests.get(PROXY_URL + "/v1/telemetry?limit=500", timeout=15,
                             proxies=NO_PROXY_ENV).json()["events"]
    reconciliation = requests.get(PROXY_URL + "/v1/reconcile/" + jti, timeout=15,
                                  proxies=NO_PROXY_ENV).json()

    observed = [e for e in ledger if e.get("jti") == jti]
    reported = [e for e in telemetry if e.get("jti") == jti]

    timeline = []
    for entry in observed:
        timeline.append({
            "source": "proxy",
            "trusted": True,
            "kind": entry["decision"],
            "method": entry.get("method"),
            "path": entry.get("path"),
            "scope": entry.get("required_scope"),
            "reason": entry.get("reason"),
            "status": entry.get("status_code"),
            "ts": entry.get("ts"),
        })
    for event in reported:
        timeline.append({
            "source": "agent",
            "trusted": False,
            "kind": event.get("event_type"),
            "method": event.get("method"),
            "path": event.get("path"),
            "summary": event.get("summary"),
            "confidence": event.get("confidence"),
            "model": event.get("model"),
            "tokens_in": event.get("tokens_in"),
            "tokens_out": event.get("tokens_out"),
            "cost": event.get("cost"),
            "ts": event.get("received_ts"),
        })
    timeline.sort(key=lambda item: item.get("ts") or "")

    return {
        "jti": jti,
        "timeline": timeline,
        "reconciliation": reconciliation,
        "observed_count": len(observed),
        "reported_count": len(reported),
    }


def rule_findings(trace):
    """Deterministic findings. No model involved.

    TODO Sebastian: add more patterns here. Candidates worth catching are
    reading the same log twice, rerunning before reading anything, a hypothesis
    that is never tested, and a confidence that never moves across the run.
    """
    findings = []
    timeline = trace["timeline"]

    calls = [(i["method"], i["path"]) for i in timeline
             if i["source"] == "proxy" and i.get("method")]
    duplicates = [call for call, count in collections.Counter(calls).items()
                  if count > 1]
    if duplicates:
        findings.append({
            "severity": "low",
            "type": "duplicate_calls",
            "detail": "repeated the same call: {}".format(
                ", ".join("{} {}".format(m, p) for m, p in duplicates)),
        })

    denied = [i for i in timeline if i.get("kind") == "DENY"]
    if denied:
        findings.append({
            "severity": "high",
            "type": "denied_attempts",
            "detail": "{} action(s) were refused by policy: {}".format(
                len(denied),
                ", ".join("{} {}".format(d.get("method"), d.get("path"))
                          for d in denied)),
        })

    reconciliation = trace["reconciliation"]
    if reconciliation["verdict"] != "CONSISTENT":
        findings.append({
            "severity": "critical",
            "type": "telemetry_mismatch",
            "detail": "{}. proxy observed {}, agent reported {}. concealed: {}".format(
                reconciliation["verdict"],
                reconciliation["observed_by_proxy"],
                reconciliation["reported_by_agent"],
                ", ".join(reconciliation["concealed"]) or "none"),
        })

    retries = [i for i in timeline if i.get("kind") == "retry"]
    if len(retries) >= 2:
        findings.append({
            "severity": "medium",
            "type": "retry_loop",
            "detail": "{} retries recorded, agent may not be changing "
                      "strategy after failure".format(len(retries)),
        })

    model_calls = [i for i in timeline if i.get("kind") == "model_call"]
    total_cost = sum(i.get("cost") or 0 for i in model_calls)
    total_tokens = sum((i.get("tokens_in") or 0) + (i.get("tokens_out") or 0)
                       for i in model_calls)
    if model_calls:
        findings.append({
            "severity": "info",
            "type": "cost",
            "detail": "{} model calls, {} tokens, {:.4f} estimated cost".format(
                len(model_calls), total_tokens, total_cost),
        })

    return findings


def build_prompt(trace, findings):
    """Assemble the analyst prompt.

    TODO Sebastian: this is a starting point, not a finished prompt. Things
    worth trying: give the model the policy file so it can comment on whether
    the granted scopes were the right ones, and ask it for a concrete diff to
    the agent instructions rather than prose advice.
    """
    compact = []
    for item in trace["timeline"]:
        if item["source"] == "proxy":
            compact.append("[proxy,trusted] {} {} {} -> {}".format(
                item["kind"], item.get("method"), item.get("path"),
                item.get("status")))
        else:
            compact.append("[agent,self-reported] {} {}".format(
                item["kind"], item.get("summary") or item.get("path") or ""))

    return (
        "You are analysing one execution of an autonomous DevOps agent.\n\n"
        "The timeline below comes from two sources. Lines marked trusted were "
        "captured independently by a proxy the agent cannot bypass. Lines "
        "marked self-reported come from the agent's own telemetry and may be "
        "incomplete or false. Weigh them accordingly.\n\n"
        "Timeline:\n" + "\n".join(compact) + "\n\n"
        "Deterministic findings already computed:\n" +
        json.dumps(findings, indent=2) + "\n\n"
        "Identify the root cause of any failure, wasted effort, and anything "
        "the agent should do differently. Do not repeat the deterministic "
        "findings. Respond with a single JSON object and nothing else:\n"
        '{"assessment": "...", "wasted_effort": ["..."], '
        '"security_concerns": ["..."], '
        '"proposed_instruction_change": "...", "confidence": 0.0}'
    )


def llm_findings(prompt):
    """Call the model. Returns None when no API key is configured."""
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        return None
    response = requests.post(
        API_URL,
        headers={
            "content-type": "application/json",
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
        },
        json={
            "model": MODEL,
            "max_tokens": 1000,
            "messages": [{"role": "user", "content": prompt}],
        },
        timeout=60,
        proxies=NO_PROXY_ENV,
    )
    response.raise_for_status()
    text = "".join(
        block.get("text", "") for block in response.json().get("content", [])
        if block.get("type") == "text"
    )
    try:
        return json.loads(text.replace("```json", "").replace("```", "").strip())
    except ValueError:
        return {"assessment": text.strip()}


def analyze(jti):
    trace = fetch_trace(jti)
    findings = rule_findings(trace)

    print("=" * 72)
    print("TRACE ANALYSIS  {}".format(jti))
    print("=" * 72)
    print("{} proxy observed events, {} self reported events".format(
        trace["observed_count"], trace["reported_count"]))
    print("reconciliation: {}".format(trace["reconciliation"]["verdict"]))
    print()
    print("Deterministic findings:")
    for finding in findings:
        print("  [{:8s}] {:20s} {}".format(
            finding["severity"], finding["type"], finding["detail"]))

    prompt = build_prompt(trace, findings)
    result = llm_findings(prompt)
    print()
    if result is None:
        print("Model analysis skipped, ANTHROPIC_API_KEY is not set.")
        print("The deterministic findings above do not need a model and are "
              "the ones to build on first.")
    else:
        print("Model analysis:")
        print(json.dumps(result, indent=2))

    return {"trace": trace, "findings": findings, "model_analysis": result}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--jti")
    parser.add_argument("--latest", action="store_true")
    args = parser.parse_args()

    jti = args.jti
    if args.latest or not jti:
        tokens = requests.get(PROXY_URL + "/v1/tokens", timeout=10,
                              proxies=NO_PROXY_ENV).json()["tokens"]
        if not tokens:
            print("No tokens in the ledger yet. Run an agent first.")
            return
        jti = tokens[0]

    analyze(jti)


if __name__ == "__main__":
    main()
