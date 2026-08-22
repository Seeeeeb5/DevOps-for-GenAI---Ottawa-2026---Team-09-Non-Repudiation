# Attributable Agent Actions

**An Identity Broker and Revocation Proxy for Autonomous DevOps Agents**

Team 09 · Track 1 (Autonomous DevOps) · DevOps for GenAI Ottawa 2026

---

## The Problem

Nobody lets an agent run unattended against production.

Not because models aren't good enough — because the audit log shows a **shared service account**.

When something goes wrong, you can't answer:

- Who triggered it?
- Which agent, which version?
- What task was it executing, on whose behalf?
- What was it authorized to do?
- How do you shut down ONE agent without killing them all?

**No attribution → No accountability → No trust → No adoption**

---

## Our Solution: Three Components

<!-- TODO: paste architecture diagram screenshot here -->
![Architecture Diagram](images/architecture.png)

```
┌───────────┐                        ┌───────────────┐
│  AI Agent │──── ① Get Token ──────→│    Broker     │
│           │←── short-lived JWT ────│  (Identity)   │
└─────┬─────┘                        └───────────────┘
      │                                     ↑
      │ ② All requests                      │ ③ Live status check
      ↓                                     │
┌─────────────────────────────────────────────┐
│                 Proxy                        │
│  ┌────────────┐  ┌──────────────────────┐   │
│  │ Token      │  │    policy.json        │   │
│  │ Validator  │  │  (15 rules, deny by   │   │
│  └─────┬──────┘  │   default, hot-reload)│   │
│        │         └──────────┬───────────┘   │
│        ▼                    ▼               │
│  ┌──────────────────────────────────────┐   │
│  │  Enforce → Redact → Record to Ledger │   │
│  └──────────────────┬──────────────────-┘   │
└─────────────────────┼───────────────────────┘
                      │ ④ Only if all checks pass
                      ▼
┌───────────────────────────┐    ┌─────────────────┐
│    Target System          │    │  Evidence Ledger │
│  (CI/CD, GitHub, etc)     │    │  (hash-chained,  │
└───────────────────────────┘    │   Ed25519 signed)│
                                 └─────────────────┘
```

The agent never holds the target credential. The proxy is the only path.

---

## Identity Broker

- Issues **short-lived** tokens (2 minutes TTL)
- Tokens are **single-task**, **scope-limited**
- Agent can only get scopes it was registered for
- Owns the **kill switch** — revocation takes effect instantly

<!-- TODO: paste broker token example or dashboard agent panel screenshot here -->
![Broker Panel](images/broker-panel.png)

---

## Revocation Proxy

The single enforcement point. Four checks on every request:

| Step | What | Failure mode |
|------|------|-------------|
| 1 | Token signature valid? | Forged token → 401 |
| 2 | Agent still active? (live check) | Revoked → 403 |
| 3 | Policy allows this? | No matching scope → 403 |
| 4 | Forward to target | Only reached if 1-3 pass |

Every request, **allowed or denied**, is recorded in the signed ledger.

---

## Evidence Ledger

- Hash-chained: each entry contains the hash of the previous one
- Ed25519 signed: agent cannot forge or deny a record
- Tamper-evident: edit one row → entire chain breaks from that point

<!-- TODO: paste ledger verification output screenshot here -->
![Ledger Verification](images/ledger-verify.png)

```
$ python3 ledger/verify.py
OK. 44 entries verified.
Chain head: 3be4d067dcdfdc920132a412ec58e8f3...
```

---

## Policy Engine

**Rules are data, not code. Default decision: DENY.**

```json
{
  "id": "runs-rerun",
  "method": "POST",
  "path": "^/runs/[^/]+/rerun/?$",
  "scope": "runs:rerun",
  "risk": "medium",
  "note": "Retrigger a pipeline, consumes CI capacity"
}
```

- 15 rules covering pipelines, deploys, branches, secrets, webhooks, env vars, workflows, artifacts
- Hot-reloads on file change — no restart, no code deploy
- Undeclared endpoints are **denied by default**

<!-- TODO: paste policy.json screenshot or dashboard policy view here -->
![Policy Rules](images/policy-rules.png)

---

## Attack Validation Suite

**Security claims are tests, not assertions.**

24 scenarios across 8 attack categories — all PASS:

| Category | Scenarios | What it proves |
|----------|-----------|---------------|
| Privilege escalation | 7 | Agent can't exceed its registered permissions |
| Evasion techniques | 4 | Path traversal, method swap, encoded paths all fail |
| Prompt injection | 3 | Malicious instructions in data can't break boundaries |
| Token security | 3 | Forged/missing/over-privileged tokens are rejected |
| Baseline (allow) | 3 | Legitimate operations still work |
| Least privilege | 2 | Each scope is independently enforced |
| Bypass protection | 1 | Target unreachable without proxy credential |
| Kill switch | 1 | Revoked token fails even before expiry |

<!-- TODO: paste attack suite terminal output screenshot here -->
![Attack Results](images/attack-results.png)

---

## Two Streams, Two Trust Levels

| Stream | Source | Trust | Can agent skip it? |
|--------|--------|-------|-------------------|
| **Proxy record** | Captured at gateway | Signed, unforgeable | No |
| **Agent telemetry** | Self-reported via SDK | Untrusted narrative | Yes (can lie) |

Both streams carry the same token ID → **Reconciliation** compares them.

- Proxy saw 3 calls, agent reported 1 → **CONCEALMENT DETECTED**
- Names the exact actions the agent hid

An SDK-only observability stack would never notice.

<!-- TODO: paste reconciliation panel screenshot showing concealment here -->
![Reconciliation](images/reconciliation.png)

---

## Kill Switch

```
Owner clicks "Revoke"
  → Broker marks agent status = revoked
  → Agent's next request arrives at proxy
  → Proxy checks broker: "still active?"
  → Answer: NO
  → DENIED in 0.07 seconds
  → Token was still cryptographically valid — doesn't matter
```

Revocation is enforced at the proxy on **every request**, not left to token expiry.

<!-- TODO: paste dashboard showing revoked agent and denied request here -->
![Kill Switch](images/kill-switch.png)

---

## Live Demo

<!-- TODO: paste dashboard screenshot with live traffic running here -->
![Live Dashboard](images/live-dashboard.png)

- Green rows = normal work, fully attributed
- Red rows = attacks blocked by policy in real-time
- Right panel = reconciliation (honest vs concealment)
- Kill switch = one click to shut down any agent

```bash
# One command to run everything:
.\scripts\run_all.ps1    # Windows
bash scripts/run_all.sh  # macOS/Linux
```

---

## Tamper Detection Demo

```bash
# 1. Verify — all good
$ python3 ledger/verify.py
OK. 44 entries verified.

# 2. Tamper — change a DENY to ALLOW in the database
$ sqlite3 data/ledger.db "UPDATE entries SET decision='ALLOW' WHERE seq=5"

# 3. Verify again — caught
$ python3 ledger/verify.py
FAIL at entry 5: content does not match its hash.
This entry was modified after it was written.
```

<!-- TODO: paste terminal screenshot showing tamper detection here -->
![Tamper Detection](images/tamper-detection.png)

---

## Production Direction

Same three components, hardened:

| Prototype | Production |
|-----------|-----------|
| Shared secret bootstrap | SPIFFE/SPIRE workload attestation |
| In-memory signing key | KMS/Vault with rotation |
| PEM endpoint | JWKS endpoint |
| In-memory agent registry | Enterprise identity provider |
| Local SQLite ledger | Append-only transparency log with published roots |
| Pattern-based redaction | Trained PII detector |
| Explicit proxy endpoint | Sidecar / egress gateway |
| JSON policy file | OPA (versioned, reviewable) |

---

## Team

| Member | Responsibility |
|--------|---------------|
| Freeman | Broker, proxy, ledger, integration |
| Nina | Investigation agent and tools |
| Jiaqi | Policy rules, attack scenarios |
| Sebastian | Trace analyzer, AI analysis |

---

## Summary

> Let agents work. Record everything they do. Stop them the instant they misbehave.

- **Attribution**: Every action tied to agent + version + owner + task
- **Least privilege**: Scoped tokens, deny-by-default policy
- **Non-repudiation**: Signed hash chain the agent cannot forge or deny
- **Instant revocation**: Kill switch works in under 100ms
- **Verifiable honesty**: Two-stream reconciliation detects concealment
- **Testable security**: 24 attack scenarios prove the boundary holds
