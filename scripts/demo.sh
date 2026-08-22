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
sleep 2
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

act "ACT 1 to 6  The system in operation" \
    "A CI/CD debugging agent under an identity broker and a revocation proxy."
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

act "TRACE ANALYSIS" \
    "Findings computed in code first, a model only for what needs judgement."
python3 analyzer/analyze.py --latest
pause

act "AUDIT  the evidence chain is intact" \
    "Recompute every hash, check every link, verify every signature."
python3 ledger/verify.py --db data/ledger.db --key data/ledger_key.pem
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
pause

act "WHAT THIS GIVES YOU" ""
cat <<'EOF'
  Attribution     every action carries agent, version, owner, task and scope
  Containment     out of scope actions never reach the target system
  Verification    the agent's own story is checked against an independent record
  Control         one agent can be stopped in under a second, others unaffected
  Evidence        the record is signed and chained, and tampering is detectable

  Services are still running. Dashboard at http://127.0.0.1:8080/
  Stop them with: pkill -f uvicorn
EOF
echo
