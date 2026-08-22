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

echo ""
echo "All services running. Dashboard: http://127.0.0.1:8080/"
echo ""

# Cleanup function
cleanup() {
    echo ""
    echo "Shutting down..."
    kill $BROKER_PID $TARGET_PID $PROXY_PID $WEBHOOK_PID 2>/dev/null || true
    wait $BROKER_PID $TARGET_PID $PROXY_PID $WEBHOOK_PID 2>/dev/null || true
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
echo "ALL DONE. Dashboard still live at http://127.0.0.1:8080/"
echo "Press Enter to shut down services..."
echo "========================================================================"
read -r
