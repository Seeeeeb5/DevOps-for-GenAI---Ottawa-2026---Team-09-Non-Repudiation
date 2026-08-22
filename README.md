# Non-Repudiation

**Attributable Agent Actions: An Identity Broker and Revocation Proxy for Autonomous DevOps Agents**

Team 09, Track 1 (Autonomous DevOps), DevOps for GenAI Ottawa 2026.

## The problem

Nobody lets an agent run unattended against production, and the reason is not
that the models are not good enough. It is that the audit log shows a shared
service account. When something goes wrong you cannot answer who triggered it,
which agent it was, which version, what task it was executing, on whose behalf,
or what it was authorised to do. There is no attribution, so there is no
non-repudiation, and there is no way to shut down one misbehaving agent without
taking every other agent down with it.

## What we build

Three components sitting between agents and the systems they act on.

**Identity broker.** Issues short lived, single task, scope limited tokens.
An agent holds a capability for the next two minutes, not a standing identity.
The broker also owns the kill switch.

**Revocation proxy.** The only path from an agent to a target system. It
validates the token, checks revocation live against the broker, maps the
request to a required scope and denies anything outside it, redacts secrets and
PII, then forwards using a credential the agent never sees.

**Evidence ledger.** Every call, allowed or denied, becomes a hash chained
record signed with a key the agent cannot reach. The agent cannot forge a
record and cannot deny one.

**Flight recorder SDK.** Records what happens inside the agent: model calls,
hypotheses, retries. The proxy cannot see any of this, because none of it
crosses the network boundary.

### Two streams, two different trust levels

The proxy and the SDK record different things and carry different weight, and
conflating them is the mistake most agent observability stacks make.

The proxy records what the agent *did*. This has to be unforgeable and
unskippable, because it is what accountability rests on. The agent has no
control over it, since the proxy holds the only credential the target accepts.

The SDK records why the agent did it. This is self reported, so it cannot be
trusted on its own. An agent can lie, or stay silent, and an observability
stack built only on an SDK would never know.

What makes the self reported stream useful anyway is that both streams carry
the same token id. The proxy independently knows how many calls happened under
a given token. If the agent admits to fewer, the gap is evidence of
concealment. If it claims more, it is inventing work it never did. Anchoring
an untrusted narrative to an independently captured spine is what turns it
from unverifiable into verifiable.

`GET /v1/reconcile/{jti}` returns that comparison.

## Run it

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
bash scripts/run_all.sh
python3 agent/demo_agent.py
```

On macOS, run source before run_all.sh, otherwise the script cannot
find uvicorn. Tested on Python 3.12.

Dashboard at http://127.0.0.1:8080/

## The demo, in four acts

**Act 1. Normal work, fully attributed.** A CI/CD debugging agent investigates
a failed pipeline run: lists runs, reads run 4471, reads its logs, reruns it.
Every call lands in the ledger with agent id, agent version, owner, principal,
task id, token jti and the scope that authorised it. The log payload contains
an email address and an internal IP, and the ledger shows both were redacted
before anything was stored.

**Act 2. The agent is pushed out of scope.** A simulated prompt injection tells
it to delete the main branch and deploy to production. Both are refused at the
proxy, before the target is ever contacted, and both refusals are recorded.

**Act 3. Reconciliation, honest baseline.** Six calls observed by the proxy,
six reported by the agent, plus six internal events the proxy could never have
seen. Verdict: consistent.

**Act 4. A dishonest agent.** A second agent performs three calls but omits two
of them from its own telemetry. Reconciliation names both concealed actions.
This is the case an SDK only stack cannot detect at all.

**Act 5. Kill switch.** The owner revokes the agent from the dashboard. The
token is still cryptographically valid and has not expired, but the next call
is refused in well under a second, because revocation is enforced at the proxy
rather than left to token expiry.

**Act 6. Audit.** `ledger/verify.py` recomputes every hash, checks every chain
link and verifies every signature. Then edit one row in `data/ledger.db` to
make a denied action look allowed, run the verifier again, and it names the
exact entry that was changed.

```bash
python3 ledger/verify.py --db data/ledger.db --key data/ledger_key.pem
```

## Layout

```
broker/app.py        identity broker, token issuance, kill switch
proxy/app.py         enforcement and capture point
proxy/policy.py      request to scope mapping, deny by default
proxy/redact.py      secret and PII redaction
ledger/store.py      hash chained, Ed25519 signed evidence store
ledger/verify.py     standalone auditor
target/app.py        mock CI/CD system standing in for GitLab or Jenkins
agent/sdk.py         flight recorder for in-agent events, self reported
agent/investigator.py real agent loop, live model or offline replay
agent/demo_agent.py  scripted walkthrough of every act
ledger/telemetry.py  untrusted telemetry store and reconciliation
policies/policy.json the scope rules, edited as data not code
agent/unprotected.py control run with no broker, proxy or ledger
agent/isolation.py   two agents, one revoked, the other unaffected
agent/github_demo.py the same governance against api.github.com
triggers/webhook.py  CI event receiver that dispatches agents
attacks/run_attacks.py  twenty-four adversarial scenarios with expected outcomes
scripts/benchmark.py measured proxy overhead
analyzer/analyze.py  rule based and model based trace analysis
scripts/demo.sh      narrated end to end demo for the presentation
tests/               117 unit and integration tests
audit.py             standalone third party auditor, zero project imports
docs/PITCH.md        slide content, judge questions, demo runbook
docs/THREAT_MODEL.md what is defended, what is not, what is assumed
dashboard/index.html live ledger and kill switch
```

## Other entry points

```bash
bash scripts/demo.sh                      # the whole story, one command
python3 agent/unprotected.py              # the control: no protection at all
python3 triggers/simulate_failure.py      # event triggered, nobody starts it
python3 agent/isolation.py                # revoke one agent, others unaffected
python3 scripts/benchmark.py              # measured overhead
python3 agent/github_demo.py              # real GitHub API, same governance
python3 agent/containment.py              # the agent lies, the system stops it
python3 audit.py evidence-bundle.json     # independent audit, no imports from us
python3 -m pytest tests/ -v               # 117 tests, 42 need the stack up
python3 agent/investigator.py --offline   # agent loop, no API key needed
python3 attacks/run_attacks.py            # twenty-four adversarial scenarios
python3 analyzer/analyze.py --triage      # rank recent runs by what needs attention
python3 analyzer/analyze.py --latest      # analyse the most recent trace
```

`agent/investigator.py` runs a real tool loop. With `ANTHROPIC_API_KEY` set it
asks a model for each decision. Without one it replays a scripted reasoning
path of the same shape, so the demo never depends on a network call.

`attacks/run_attacks.py` covers prompt injection, privilege escalation, path
traversal, method swapping, a missing token and a forged token. Each scenario
declares the outcome it expects, so the security claim is measurable rather
than asserted.

`analyzer/analyze.py` reads both streams for one token, merges them into one
ordered timeline and computes twelve findings in plain code before a model is
involved at all: the probable carrier of an injected instruction, refusals
weighted by the risk the policy file assigns them, activity attempted after
revocation, scopes granted but never used, writes that happened before any
read, hypotheses that were never tested, confidence that never moved, repeated
calls, retry loops, cost, concealment, and whether the trace it is looking at
is even complete. A model is then asked only for interpretation: whether the
investigation order made sense and what should change. `--triage` ranks recent
runs so nobody has to pick a token id off a screen.

Analysis is a third trust level and the weakest one. The ledger is evidence,
agent telemetry is narrative, and analysis is an opinion about both. It is
published to `/v1/analysis`, rendered in the dashboard as visibly derived
rather than recorded, and read back by nothing that makes a decision. No model
runs anywhere in the request path.

## Owners

- Broker, proxy, ledger, integration: Freeman
- Investigation agent and its tools: Nina
- Policy rules and attack scenarios: Jiaqi
- Trace explorer and AI analysis: Sebastian

## Known limits of the prototype

We would rather name these than have a judge find them.

- Agent bootstrap uses a shared secret. Real workload attestation (SPIFFE or
  SPIRE, or cloud instance identity) is the production answer.
- The broker signing key is generated in memory at startup. Production puts it
  in a KMS or in Vault with rotation.
- The broker exposes a PEM rather than a JWKS endpoint.
- The agent registry is in memory. Production backs it with an enterprise
  identity provider.
- The ledger is a local SQLite file. Production appends to write once storage
  and publishes periodic chain roots so that even an operator with database
  access cannot rewrite history undetected.
- Redaction is pattern based. Production would add a trained detector.

## Production direction

Same three components, hardened. Attestation replaces bootstrap secrets, the
proxy runs as a sidecar or egress gateway rather than an explicit endpoint,
policy moves to OPA so it can be versioned and reviewed, the ledger becomes an
append only transparency log with published roots, and the dashboard becomes
the control plane where an owner can see every action any agent took on their
behalf and stop any of it in one click.
