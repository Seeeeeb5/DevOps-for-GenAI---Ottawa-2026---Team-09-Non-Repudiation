# Non-Repudiation

**Attributable Agent Actions: An Identity Broker and Revocation Proxy for Autonomous DevOps Agents**

Team 09, Track 1 (Autonomous DevOps), DevOps for GenAI Ottawa 2026.

Project lead: Freeman Liu. Participants: Jiaqi Li, Nina Li, Sebastian Petelle.

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

### Why capture at the proxy instead of in an agent SDK

An SDK records what the agent chooses to report. An agent that goes off the
rails can simply not report. The proxy is a path the agent cannot avoid,
because the proxy holds the only credential the target accepts. One
interception point gives us authentication, authorisation, redaction and
tamper evident capture at the same time, and it works with any agent framework
without writing an adapter for each one.

## Run it

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
bash scripts/run_all.sh
python3 agent/demo_agent.py
```

On macOS, run source before run_all.sh, otherwise the script cannot find
uvicorn. Tested on Python 3.12.

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

**Act 3. Kill switch.** The owner revokes the agent from the dashboard. The
token is still cryptographically valid and has not expired, but the next call
is refused in well under a second, because revocation is enforced at the proxy
rather than left to token expiry.

**Act 4. Audit.** `ledger/verify.py` recomputes every hash, checks every chain
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
agent/demo_agent.py  the governed agent, runs the four act scenario
dashboard/index.html live ledger and kill switch
```

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
