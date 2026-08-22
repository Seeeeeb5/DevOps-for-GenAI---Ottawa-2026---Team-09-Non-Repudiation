#!/usr/bin/env bash
# Start the three services in the background.
set -e
cd "$(dirname "$0")/.."
mkdir -p data logs
python3 -m uvicorn broker.app:app --port 8081 --log-level warning > logs/broker.log 2>&1 &
python3 -m uvicorn target.app:app --port 8082 --log-level warning > logs/target.log 2>&1 &
sleep 2
python3 -m uvicorn proxy.app:app --port 8080 --log-level warning > logs/proxy.log 2>&1 &
sleep 2
echo "broker    http://127.0.0.1:8081"
echo "target    http://127.0.0.1:8082"
echo "proxy     http://127.0.0.1:8080"
echo "dashboard http://127.0.0.1:8080/"
echo ""
echo "Now run: python3 agent/demo_agent.py"
