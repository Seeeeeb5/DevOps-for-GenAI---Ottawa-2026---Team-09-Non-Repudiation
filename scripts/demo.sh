#!/usr/bin/env bash
# Full narrated demo. One command, six acts, no memorised sequence needed.
#
# Usage:
#   bash scripts/demo.sh          pause between acts, press enter to advance
#   bash scripts/demo.sh --fast   no pauses, for a recording
#
# Anyone on the team can run this on stage. Nothing here depends on a network
# call or an API key.

set -e
cd "$(dirname "$0")/.."

FAST=0
[ "$1" = "--fast" ] && FAST=1

BOLD=$'\033[1m'
DIM=$'\033[2m'
RESET=$'\033[0m'
CYAN=$'\033[36m'

pause() {
  if [ "$FAST" = "0" ]; then
    printf "\n${DIM}press enter to continue${RESET}"
    read -r _
  else
    sleep 1
  fi
}

act() {
  printf "\n\n${CYAN}%s${RESET}\n" "$(printf '=%.0s' $(seq 1 72))"
  printf "${BOLD}%s${RESET}\n" "$1"
  printf "${DIM}%s${RESET}\n" "$2"
  printf "${CYAN}%s${RESET}\n\n" "$(printf '=%.0s' $(seq 1 72))"
}

# Fresh state so the ledger sequence numbers start at 1 on stage.
pkill -f uvicorn 2>/dev/null || true
sleep 1
rm -rf data logs
mkdir -p data logs

printf "${BOLD}Starting broker, target and proxy${RESET}\n"
python3 -m uvicorn broker.app:app --port 8081 --log-level warning > logs/broker.log 2>&1 &
python3 -m uvicorn target.app:app --port 8082 --log-level warning > logs/target.log 2>&1 &
sleep 2
python3 -m uvicorn proxy.app:app --port 8080 --log-level warning > logs/proxy.log 2>&1 &
python3 -m uvicorn triggers.webhook:app --port 8083 --log-level warning > logs/webhook.log 2>&1 &
sleep 3
printf "dashboard at http://127.0.0.1:8080/\n"
pause

act "THE PROBLEM" \
    "An agent acting through a shared service account leaves no usable trace."
cat <<'EOF'
  Today an autonomous DevOps agent authenticates with a long lived service
  account. The audit log records that service account, not the agent.

  When something goes wrong nobody can answer:
      which agent was it, which version, on whose behalf,
      what task was it running, what was it authorised to do

  No attribution means no accountability. And revoking the shared credential
  stops every agent at once, so in practice nobody revokes anything.
EOF
pause

act "THE CONTROL  the same agent with none of this in place" \
    "It reads a build log containing an injected instruction, and complies."
python3 agent/unprotected.py
pause

act "ACT 1 to 6  The system in operation" \
    "The same agent and the same log, now behind a broker and a proxy."
python3 agent/demo_agent.py
pause

act "THE ATTACK SUITE" \
    "Nine adversarial scenarios, each declaring the outcome it expects."
python3 attacks/run_attacks.py
pause

act "A REAL AGENT LOOP" \
    "The agent decides its own next step. Every call still goes through the proxy."
python3 agent/investigator.py --offline
pause

act "AUTONOMY  nobody starts the agent" \
    "A pipeline fails, an event arrives, an agent is dispatched."
python3 triggers/simulate_failure.py || true
pause

act "ISOLATION  stopping one agent, not all of them" \
    "Two agents, different scopes. One is revoked mid flight."
python3 agent/isolation.py
pause

act "WHAT IT COSTS" \
    "Measured, not asserted."
python3 scripts/benchmark.py --n 150
pause

act "CLOSED LOOP  the agent lies and the system stops it" \
    "Detection is not a control. This one acts."
python3 agent/containment.py
pause

act "TRACE ANALYSIS" \
    "Findings computed in code first, a model only for what needs judgement."
python3 analyzer/analyze.py --triage 12
pause

act "AUDIT  the evidence chain is intact" \
    "Recompute every hash, check every link, verify every signature."
python3 ledger/verify.py --db data/ledger.db --key data/ledger_key.pem
pause

act "AUDIT  do not take our word for it" \
    "Export the evidence, verify it with a script that imports none of our code."
curl -s --noproxy '*' http://127.0.0.1:8080/v1/export > evidence-bundle.json
python3 audit.py evidence-bundle.json
pause

act "AUDIT  someone edits the record" \
    "Rewrite a denied action to look like it was allowed."
python3 - <<'PYEOF'
import sqlite3
conn = sqlite3.connect('data/ledger.db')
row = conn.execute(
    "SELECT seq, method, path FROM entries WHERE decision='DENY' ORDER BY seq LIMIT 1"
).fetchone()
if row is None:
    print("no denied entry to tamper with")
else:
    seq, method, path = row
    conn.execute(
        "UPDATE entries SET decision='ALLOW', reason='approved' WHERE seq=?", (seq,)
    )
    conn.commit()
    print("entry {} rewritten: {} {} now reads as ALLOW".format(seq, method, path))
PYEOF
echo
python3 ledger/verify.py --db data/ledger.db --key data/ledger_key.pem || true
echo
printf "${DIM}The same edit, made to the bundle a third party is holding:${RESET}\n\n"
python3 scripts/tamper_bundle.py evidence-bundle.json
echo
python3 audit.py evidence-bundle.json || true
pause

act "WHAT THIS GIVES YOU" ""
cat <<'EOF'
  Attribution     every action carries agent, version, owner, task and scope
  Containment     out of scope actions never reach the target system
  Verification    the agent's own story is checked against an independent record
  Control         one agent can be stopped in under a second, others unaffected
  Evidence        the record is signed and chained, and tampering is detectable
  Independence    anyone can verify it without trusting or contacting us

  Services are still running. Dashboard at http://127.0.0.1:8080/
  Stop them with: pkill -f uvicorn
EOF
echo
