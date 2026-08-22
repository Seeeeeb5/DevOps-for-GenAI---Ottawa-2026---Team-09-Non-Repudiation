#!/usr/bin/env bash
# One-click demo runner for macOS / Linux
# Usage: bash scripts/run_all.sh
set -e
cd "$(dirname "$0")/.."

# Create directories
mkdir -p data logs

# Clean old data for a fresh run
rm -f data/ledger.db data/ledger_key.pem

echo "========================================================================"
echo "STARTING SERVICES"
echo "========================================================================"

# Start broker (port 8081)
python3 -m uvicorn broker.app:app --port 8081 --log-level warning > logs/broker.log 2>&1 &
BROKER_PID=$!
echo "  broker    PID=$BROKER_PID  http://127.0.0.1:8081"

# Start target (port 8082)
python3 -m uvicorn target.app:app --port 8082 --log-level warning > logs/target.log 2>&1 &
TARGET_PID=$!
echo "  target    PID=$TARGET_PID  http://127.0.0.1:8082"

sleep 2

# Start proxy (port 8080)
python3 -m uvicorn proxy.app:app --port 8080 --log-level warning > logs/proxy.log 2>&1 &
PROXY_PID=$!
echo "  proxy     PID=$PROXY_PID  http://127.0.0.1:8080"

# Start webhook trigger (port 8083)
python3 -m uvicorn triggers.webhook:app --port 8083 --log-level warning > logs/webhook.log 2>&1 &
WEBHOOK_PID=$!
echo "  webhook   PID=$WEBHOOK_PID  http://127.0.0.1:8083"

sleep 2

# Start the trace analyzer as a watcher.
#
# Analysis is produced out of band, by a separate process, deliberately: it is
# the only component allowed to use a model, and keeping it out of the request
# path is what stops a model ever sitting where an enforcement decision is made.
#
# Running it as a service rather than a command matters for a duller reason.
# Every token needs analysing for the dashboard panel to have anything to show,
# and a finding nobody remembered to generate is indistinguishable from no
# finding at all.
python3 -u analyzer/analyze.py --watch 3 --no-model > logs/analyzer.log 2>&1 &
ANALYZER_PID=$!
echo "  analyzer  PID=$ANALYZER_PID  watching for new tokens"

# Backfill anything already in the ledger from a previous run.
python3 analyzer/analyze.py --backfill --no-model > /dev/null 2>&1 || true

echo ""
echo "All services running. Dashboard: http://127.0.0.1:8080/"
echo ""

# Cleanup function
cleanup() {
    echo ""
    echo "Shutting down..."
    kill $BROKER_PID $TARGET_PID $PROXY_PID $WEBHOOK_PID $ANALYZER_PID 2>/dev/null || true
    wait $BROKER_PID $TARGET_PID $PROXY_PID $WEBHOOK_PID $ANALYZER_PID 2>/dev/null || true
    echo "Done."
}
trap cleanup EXIT

# Run the demo agent (6 acts)
echo "========================================================================"
echo "RUNNING DEMO AGENT"
echo "========================================================================"
python3 agent/demo_agent.py

echo ""

# Run attack scenarios
echo "========================================================================"
echo "RUNNING ATTACK SCENARIOS"
echo "========================================================================"
python3 attacks/run_attacks.py

echo ""

# Run investigator in offline mode
echo "========================================================================"
echo "RUNNING INVESTIGATOR (offline mode)"
echo "========================================================================"
python3 agent/investigator.py --offline

echo ""

# Verify the ledger
echo "========================================================================"
echo "VERIFYING LEDGER INTEGRITY"
echo "========================================================================"
python3 ledger/verify.py --db data/ledger.db --key data/ledger_key.pem

echo ""
echo "========================================================================"
echo "ALL DONE. Starting live traffic simulator..."
echo "Dashboard: http://127.0.0.1:8080/"
echo "Live traffic running (Ctrl+C to stop and shut down)"
echo "========================================================================"

# Run live traffic in foreground (Ctrl+C triggers the EXIT trap for cleanup)
python3 scripts/live_traffic.py --fast
