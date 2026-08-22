# Threat model

What this system defends against, what it does not, and what it assumes is
trustworthy. Written down because a security control whose boundaries are
vague is a security control nobody can rely on.

The short version: we protect the **effects** of an autonomous agent on the
systems it can reach, and we make the record of those effects independently
verifiable. We do not protect the agent's own reasoning, and we do not claim to.

---

## Assets

| Asset | Why it matters |
|---|---|
| Target systems (CI, repos, deploy) | The thing an agent can actually damage |
| Target credentials | Compromise makes every other control irrelevant |
| The evidence ledger | If it can be rewritten, accountability is theatre |
| The ledger signing key | Holder can fabricate history |
| The broker signing key | Holder can mint tokens with any scope |
| Policy rules | Define the blast radius of every agent |

---

## Adversaries

**A1. The manipulated agent.** Not malicious, but acting on injected content.
It reads a build log, an issue comment, a commit message or a dependency
changelog containing an instruction, and complies. This is the adversary we
consider most likely, because it requires no attacker access at all.

**A2. The misconfigured agent.** Granted more scope than its task needs, or
holding a token that outlives the task. Causes real damage without anyone
intending harm.

**A3. The dishonest agent.** Acts, then under reports or misreports what it
did. Includes an agent whose telemetry is silently broken, which is
indistinguishable from concealment and should be treated the same way.

**A4. The opportunistic insider.** Has database access and edits the record
after the fact to remove or alter an entry.

**A5. The external attacker at the network layer.** Forges a token, replays
one, or calls the proxy without one.

---

## What is defended, and by what

| Threat | Control | Demonstrated by |
|---|---|---|
| A1 Injected instruction leads to a destructive action | Scope enforced at the proxy, deny by default | `agent/investigator.py --offline`, steps 6 and 7 |
| A1 Same attack without the system | Control run for comparison | `agent/unprotected.py` |
| A2 Over broad or long lived authority | 120 second TTL, single task, scope capped at registration | `tests/test_integration.py::TestBroker` |
| A2 New endpoint silently reachable | No matching rule means deny | `attacks/run_attacks.py`, undeclared endpoint |
| A3 Agent under reports its actions | Reconciliation against an independently captured record | `agent/demo_agent.py` act 4 |
| A3 Continues acting after concealment | Automatic containment, no human needed | `agent/containment.py` |
| A4 Entry edited after the fact | Hash chain, entry no longer hashes to its stored value | `audit.py` |
| A4 Entry deleted or reordered | Hash chain, the link breaks | `audit.py` |
| A4 Entry fabricated | Ed25519 signature over the entry hash | `audit.py` |
| A5 Forged or absent token | Signature and issuer verification | `attacks/run_attacks.py` |
| Agent bypasses the proxy | Agent holds no target credential | `tests/test_integration.py::test_agent_cannot_reach_target_directly` |
| Secrets accumulating in telemetry | Redaction before storage, digests only | `tests/test_units.py::TestRedaction` |
| Revoked agent keeps working until expiry | Live revocation check on every call | `agent/isolation.py`, 17 ms |
| Stopping one agent stops all of them | Per agent identity, not a shared credential | `agent/isolation.py` |

---

## What is not defended

Stated plainly, because a judge who finds these unprompted will trust
everything else less.

**The agent's reasoning.** We cannot stop an agent from being convinced by
injected text. We stop the conviction from having an effect. Those are
different claims and only the second is achievable at this layer. An agent that
is manipulated into producing a wrong but authorised answer will produce it,
and the record will show it did so faithfully.

**A compromised proxy.** The proxy is the trust anchor. Whoever controls it
controls enforcement and capture. This design does not defend against that, and
we would not claim otherwise. What it does is move the trust anchor from a
diffuse set of agents holding credentials to one component that can be
hardened, isolated and audited. That is the argument, not that the anchor is
unattackable.

**Someone holding the ledger signing key.** They can rewrite history and
resign it, and `audit.py` will report the chain as valid. In the prototype the
key sits in a local file. Production moves it to a KMS or HSM and publishes
periodic chain roots to an external witness, so that a rewrite becomes visible
even to a holder of the key.

**Denial of service.** The proxy fails closed, so making the broker unreachable
stops every agent. This is deliberate: a security control should fail toward
nothing happening rather than toward agents running unsupervised. But the
availability cost is real and we do not hide it. See the open question below.

**Covert channels and timing.** An agent could encode information in the
pattern or timing of permitted calls. We record every call, so the channel is
recorded, but we do not detect it.

**Data exfiltration through permitted reads.** If `logs:read` is granted, the
agent can read logs, and what it does with the content afterward is outside
this boundary. Scope minimisation reduces the surface; it does not remove it.

**Local actions.** File writes, subprocesses and anything else that does not
cross the network are invisible to the proxy. The SDK reports them, and the
SDK is untrusted. This is a real gap, and it is why we say the proxy covers
effects on *reachable systems* rather than all effects.

---

## What is assumed trustworthy

If any of these is false, the guarantees weaken. They are listed so that
someone deploying this knows exactly what they are betting on.

1. The proxy process and the host it runs on.
2. The broker and its signing key.
3. The ledger signing key, and the storage layer's inability to be rewritten
   without detection. In the prototype the second half of this is weak.
4. The policy file having been reviewed by a person. Nothing validates that
   the granted scopes are the right ones, only that they are enforced.
5. The target systems honouring their own credential checks.
6. Standard cryptographic assumptions for SHA-256 and Ed25519.

---

## Residual risk we accept, and why

**Ledger appends are not safe under concurrent writers.** `Ledger.append()` reads
the chain head on one connection and inserts on another, with no transaction
spanning the two and no lock. Two concurrent appends both read the same head,
both claim the same sequence number, and one loses. Reproduced directly against
the store: 120 appends across 16 threads produced 1 row, 118 `database is locked`
errors and one `UNIQUE constraint failed: entries.seq`.

It does not happen in the running system, and the reason is an accident rather
than a decision. The gateway handler is `async def` but makes a blocking HTTP
call inside it, which holds the event loop, so uvicorn with one worker serialises
every request. Verified: 60 concurrent calls through the proxy produce 60
entries, contiguous sequence numbers, chain intact.

The consequence if that ever stops being true is the worst one available. The
ledger write happens *after* the upstream call, so a failed append means the
action was performed and there is no record of it. Adding `--workers 2`, or
moving to async HTTP to reduce the measured per-call overhead, would remove the
accidental serialisation silently.

We attempted the fix (WAL, a write lock, and `BEGIN IMMEDIATE` spanning the head
read and the insert) and reverted it, because it introduced a worse problem: per
call latency went from 37 ms to over 20 seconds under the same load, and the
two stores sharing one database file contended with each other. Shipping a
performance collapse to fix a bug that cannot currently occur was the wrong
trade with a demo pending. The correct fix is one writer owning the file, or
Postgres, and it is not a change to make in a hurry.

**Bootstrap secrets instead of attestation.** An agent authenticates to the
broker with a shared secret. Anyone who reads that secret can impersonate the
agent. Real workload attestation (SPIFFE, SPIRE, cloud instance identity) is
the answer and is not in the prototype. Accepted because attestation is
orthogonal to the contribution being demonstrated.

**Pattern based redaction.** Novel secret formats will pass through. A trained
detector is the production answer. Accepted because the digest, not the
payload, is what the ledger stores, so the exposure window is the proxy process
rather than the record.

**In memory agent registry.** Restarting the broker resets agent state,
including revocations. Accepted for a prototype, unacceptable in production.

**A 5 ms per call cost.** Measured, dominated by the live revocation check.
Accepted because instant revocation is the feature being bought.

---

## Open question we have not settled

The proxy fails closed, so the broker becoming unavailable stops every agent.
That is the same blast radius we criticise in the shared credential model.

The distinction we would draw is directional: the shared credential model fails
toward agents continuing to act with authority nobody can withdraw, and this
fails toward nothing happening at all. For a security control the second is the
right direction.

But it converts a security property into an availability dependency, and saying
"it fails safe" is not a complete answer to someone whose pipeline is down. The
honest position is that the broker needs the availability engineering of any
other critical path component, and that a short lived local cache of revocation
state would trade a bounded revocation delay for independence from the broker.
We chose not to build that cache because instant revocation is the thing we are
demonstrating, but in a real deployment the tradeoff deserves a decision rather
than a default.
