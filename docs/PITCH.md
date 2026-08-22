# Pitch content

Team 09, Non-Repudiation. Track 1, Autonomous DevOps.

This is the raw material for the deck, not the deck itself. Each section below
is one slide: a title, the points to make, and where relevant the command to
run and what it will print. Take what is useful and cut what is not.

The rule that should govern the whole thing: every number on a slide must come
from a command anyone can run in front of the judges. Nothing invented.

---

## Slide 1. The problem

**Title:** Nobody lets an agent run unattended, and the reason is not the model

Points:

- Autonomous DevOps agents authenticate with a long lived shared service
  account. The audit log records that account, not the agent.
- So after the fact nobody can answer: which agent, which version, on whose
  behalf, running what task, authorised to do what.
- No attribution means no accountability. And the only lever available is
  revoking the shared credential, which stops every agent at once. In practice
  that means nobody revokes anything.
- The blocker on autonomy is not capability. It is that we cannot say who did
  what, and we cannot stop one agent without stopping all of them.

Optional opening, and it is true: we lost twenty minutes tonight to a GitHub
token. Long lived, broad scope, nobody could say which account held it or
whether it was still valid. That is exactly the problem, at human scale.

---

## Slide 2. What we built

**Title:** Give every agent action a name, a scope, a signature and an off switch

Three components between agents and the systems they act on:

- **Identity broker.** Issues short lived, single task, scope limited tokens.
  120 second TTL. The agent holds a capability, not a standing identity. The
  broker also owns the kill switch.
- **Revocation proxy.** The only path from an agent to a target. Validates the
  token, checks revocation live, maps the request to a required scope and
  denies anything outside it, redacts secrets, then forwards using a credential
  the agent never sees.
- **Evidence ledger.** Every call, allowed or denied, becomes a hash chained
  record signed with a key the agent cannot reach.

---

## Slide 3. The design decision worth defending

**Title:** Two streams, two different trust levels

This is the slide to spend time on. It is the part reviewers will push on.

- The proxy records what the agent **did**. Unforgeable and unskippable,
  because the proxy holds the only credential the target accepts.
- An in-agent SDK records **why**. Model calls, hypotheses, retries. The proxy
  cannot see any of this, because none of it crosses the network.
- Self reported telemetry cannot be trusted on its own. A compromised agent can
  stay silent exactly when the record matters most.
- Both streams carry the same token id. The proxy independently knows how many
  calls happened under a token. If the agent admits to fewer, that gap is
  evidence of concealment. If it claims more, it is inventing work.
- Anchoring an untrusted narrative to an independently captured spine is what
  turns it from unverifiable into verifiable.

Say plainly that the proxy alone is not enough either. It is blind to
everything inside the agent. Neither stream is sufficient; the pairing is the
contribution.

---

## Slide 4. Live: normal work, fully attributed

```bash
python3 agent/investigator.py --offline
```

A real agent loop. It decides its own next step: lists runs, forms a
hypothesis, reads the failed run, reads the logs, rejects its first hypothesis,
forms a second, reruns to confirm, concludes.

Every outbound call went through the proxy. Every internal step was recorded.
The ledger now holds agent id, version, owner, principal, task id, token jti
and the scope that authorised each action.

Note that the build log contained an email address and an internal IP, and both
were redacted before anything was stored. We record behaviour, not secrets.

---

## Slide 5. Live: containment

```bash
python3 attacks/run_attacks.py
```

Nine adversarial scenarios, each declaring the outcome it expects. Prompt
injection telling the agent to delete the main branch or ship to production,
privilege escalation toward the secret store, an undeclared endpoint, path
traversal, a method swap on a permitted path, a missing token, a forged token.

Expected output: **9 of 9 scenarios behaved as expected.**

Two things to point out:

- Refusals happen at the proxy, before the target system is ever contacted.
- Every refusal is recorded. Most systems log only successful actions, so
  attack attempts leave no trace at all.

---

## Slide 6. Live: the agent lies

```bash
python3 agent/demo_agent.py
```

Act 4 is the moment. A second agent performs three calls and omits two of them
from its own telemetry.

Expected output:

```
verdict:            CONCEALMENT DETECTED
observed by proxy:  3
reported by agent:  1
CONCEALED, proxy saw these and the agent never reported them:
    GET /runs/4471/logs
    POST /runs/4471/rerun
```

An observability stack built only on an agent SDK cannot detect this case at
all. It would show a clean single call trace and nobody would know.

---

## Slide 7. Live: control

Act 5 of the same run, or click Revoke on the dashboard.

The token is cryptographically valid and has not expired. The next call is
refused in under a second, because revocation is enforced at the proxy rather
than left to token expiry.

Say the trade-off out loud: JWTs are stateless, which is why revoking them is
normally hard. We accept a live status check on every call to buy instant
revocation, and we cap exposure at 120 seconds with the TTL.

---

## Slide 8. Live: the evidence holds

```bash
python3 ledger/verify.py --db data/ledger.db --key data/ledger_key.pem
```

Prints `OK. N entries verified.`

Then edit one row in the database to make a denied action look allowed, and run
the verifier again. It names the exact entry that changed.

Two mechanisms doing two different jobs:

- The hash chain stops history being rewritten. Editing entry 5 breaks entry 5
  and every entry after it.
- The Ed25519 signature stops records being forged. The agent never holds the
  key, so it can neither create a false record nor deny a true one.

Either alone is insufficient. Chain only, and an attacker recomputes the whole
chain. Signature only, and an attacker deletes a record undetected.

---

## Slide 9. What we know is not finished

Name these before a judge finds them. Naming them is a strength.

- Agent bootstrap uses a shared secret. Real workload attestation, SPIFFE or
  SPIRE or cloud instance identity, is the production answer.
- The broker signing key is generated in memory at startup. Production puts it
  in a KMS or Vault with rotation.
- The agent registry is in memory rather than backed by an enterprise IdP.
- The ledger is a local SQLite file. Production appends to write once storage
  and publishes chain roots, so that even an operator with database access
  cannot rewrite history undetected.
- Redaction is pattern based and will miss novel secret formats.
- The target is a mock CI/CD system, not a live GitLab or Jenkins.

---

## Slide 10. Production direction

Same three components, hardened. Attestation replaces bootstrap secrets. The
proxy runs as a sidecar or egress gateway rather than an explicit endpoint.
Policy moves to OPA so it is versioned and reviewed like code. The ledger
becomes an append only transparency log with published roots. The dashboard
becomes the control plane where an owner sees every action any agent took on
their behalf and can stop any of it in one click.

---

## Slide 11. Close

Three sentences:

You cannot let an agent run unattended today because your audit log shows a
shared service account.

We give every agent action a name, a scope, a signature and an off switch, and
we check the agent's own story against a record it cannot edit.

That is the control that makes autonomy something you can actually authorise.

---

# Judge questions and how to answer

**Why not just use existing IAM or short lived cloud credentials?**
Those bind a credential to a workload. They do not bind it to a task, a
principal or an agent version, and they carry no record of intent. Our token
claims include task id, principal, agent version and the scope granted for that
one task, and every use of it is recorded against those claims.

**Isn't the proxy a single point of failure?**
Yes, and deliberately so, because that is what makes it unskippable. It fails
closed: if the broker is unreachable the proxy denies rather than allows. In
production it runs as multiple instances behind a load balancer, and the
failure mode is agents stop working, not agents running unsupervised.

**Couldn't a compromised agent just call the target directly?**
Not with anything. It has no target credential. The proxy holds it. This is
tested: `test_agent_cannot_reach_target_directly` calls the target without the
proxy credential and gets a 401.

**What if someone compromises the proxy itself?**
Then this design fails, and we would say so. The proxy is the trust anchor. In
production it is the component that gets the hardening budget: separate host,
minimal surface, its signing key in an HSM or KMS. Moving the trust anchor from
a diffuse set of agents to one auditable component is the point, not a claim
that the anchor cannot be attacked.

**Isn't a live revocation check on every call too slow?**
It is one local call. The alternative is waiting for token expiry, which means
a revoked agent keeps working for the remainder of its TTL. In production this
is a cache with a short TTL or a push based revocation feed.

**Why can't a model just be told not to do these things?**
Because the model is the thing being manipulated. A prompt injection targets
exactly the layer that instructions live in. Enforcement has to sit somewhere
the injected text cannot reach, which is why it is in the proxy rather than in
the system prompt. Our attack suite includes injection cases that a
well-instructed agent might still comply with, and the proxy refuses them
regardless.

**How much of this actually works?**
All of it. 36 tests pass, 9 of 9 attack scenarios behave as expected, and every
number on these slides comes from a command you can run right now.

---

# Demo runbook

One command runs the whole thing with pauses between acts:

```bash
bash scripts/demo.sh
```

Or `bash scripts/demo.sh --fast` for a recording.

Individual pieces:

```bash
bash scripts/run_all.sh                  # start broker, target, proxy
python3 agent/demo_agent.py              # six act walkthrough
python3 attacks/run_attacks.py           # nine adversarial scenarios
python3 agent/investigator.py --offline  # real agent loop
python3 analyzer/analyze.py --latest     # trace analysis
python3 -m pytest tests/ -v              # 36 tests
python3 ledger/verify.py --db data/ledger.db --key data/ledger_key.pem
```

Dashboard at http://127.0.0.1:8080/

Before presenting, run `bash scripts/demo.sh --fast` once end to end and
confirm every act produces the expected output. If a laptop is being shared,
run `pkill -f uvicorn` first so ports 8080 to 8082 are free.
