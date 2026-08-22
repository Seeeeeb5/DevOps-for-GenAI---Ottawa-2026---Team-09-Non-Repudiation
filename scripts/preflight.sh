#!/usr/bin/env bash
# Preflight. Run this before presenting. If it does not print READY, do not go up.
#
# It checks the things that have actually broken, not a generic health check:
#
#   - ports free or already serving us, rather than occupied by someone else
#   - dependencies importable in the interpreter that will run the demo
#   - the ledger chain intact, since the tamper act used to leave it broken
#   - the proxy holding a current broker key, since a broker restart used to
#     make every token fail with a misleading "invalid token"
#   - every demo segment smoke tested, so a broken one is found here
#   - an analysis published for the newest token, or the dashboard panel is empty
#
# Usage:
#   bash scripts/preflight.sh          check a stack that is already running
#   bash scripts/preflight.sh --start  start the stack first, then check

set -u
cd "$(dirname "$0")/.."

# localhost must bypass any corporate proxy, or every check below fails with a
# 400 from something that is not ours.
export no_proxy="localhost,127.0.0.1,::1,${no_proxy:-}"
export NO_PROXY="$no_proxy"

PASS=0
FAIL=0
WARN=0

ok()   { printf "  \033[32mok\033[0m    %s\n" "$1"; PASS=$((PASS+1)); }
bad()  { printf "  \033[31mFAIL\033[0m  %s\n" "$1"; FAIL=$((FAIL+1)); }
warn() { printf "  \033[33mwarn\033[0m  %s\n" "$1"; WARN=$((WARN+1)); }
head2() { printf "\n\033[1m%s\033[0m\n" "$1"; }

PY=python3
[ -x .venv/bin/python ] && PY=.venv/bin/python

curl_code() { curl -s -o /dev/null -w "%{http_code}" -m 10 "$1" 2>/dev/null; }

if [ "${1:-}" = "--start" ]; then
  head2 "Starting the stack"
  bash scripts/run_all.sh > logs/preflight_start.log 2>&1 &
  sleep 12
  ok "start requested, see logs/preflight_start.log"
fi

# ---------------------------------------------------------------------------
head2 "Interpreter and dependencies"

printf "  using %s (%s)\n" "$PY" "$($PY --version 2>&1)"
for module in fastapi uvicorn jwt cryptography requests pytest; do
  if $PY -c "import $module" 2>/dev/null; then
    ok "import $module"
  else
    bad "import $module  ->  pip install -r requirements.txt"
  fi
done

# ---------------------------------------------------------------------------
head2 "Services"

for entry in "8080 proxy" "8081 broker" "8082 target" "8083 webhook"; do
  port=${entry%% *}; name=${entry##* }
  if ss -ltn 2>/dev/null | grep -q ":${port} "; then
    ok "$name listening on $port"
  else
    bad "$name not listening on $port  ->  bash scripts/run_all.sh"
  fi
done

if pgrep -f "analyze.py --watch" > /dev/null 2>&1; then
  ok "analyzer watching for new tokens"
else
  warn "analyzer watcher not running; the Analysis panel will go stale"
fi

code=$(curl_code http://127.0.0.1:8080/)
if [ "$code" = "200" ]; then
  ok "dashboard serving (HTTP 200)"
else
  bad "dashboard returned HTTP $code"
fi

# ---------------------------------------------------------------------------
head2 "Token path end to end"

TOKEN_CHECK=$($PY - <<'PYEOF' 2>&1
import requests
NP = {"http": "", "https": ""}
try:
    t = requests.post("http://127.0.0.1:8081/token", timeout=10, proxies=NP,
                      json={"agent_id": "ci-debug-agent",
                            "bootstrap_secret": "bootstrap-ci-debug",
                            "task_id": "PREFLIGHT",
                            "requested_scopes": ["runs:read", "logs:read"]}).json()
    if "token" not in t:
        print("FAIL broker refused to issue a token: {}".format(t)); raise SystemExit
    h = {"authorization": "Bearer " + t["token"]}
    allowed = requests.get("http://127.0.0.1:8080/gw/runs", headers=h,
                           timeout=15, proxies=NP)
    denied = requests.post("http://127.0.0.1:8080/gw/deploy", headers=h,
                           timeout=15, proxies=NP)
    if allowed.status_code == 401:
        print("FAIL proxy rejects a valid token; it is holding a stale broker "
              "key. Restart the proxy.")
    elif allowed.status_code != 200:
        print("FAIL permitted call returned {}".format(allowed.status_code))
    else:
        print("OK   permitted call allowed (200)")
    if denied.status_code == 403:
        print("OK   out-of-scope call refused (403)")
    else:
        print("FAIL out-of-scope deploy returned {}, expected 403".format(
            denied.status_code))
except requests.RequestException as exc:
    print("FAIL cannot reach the stack: {}".format(exc))
PYEOF
)
while IFS= read -r line; do
  case "$line" in
    OK*)   ok   "${line#OK   }" ;;
    FAIL*) bad  "${line#FAIL }" ;;
    *)     warn "$line" ;;
  esac
done <<< "$TOKEN_CHECK"

# ---------------------------------------------------------------------------
head2 "Evidence chain"

if [ ! -f data/ledger.db ]; then
  bad "data/ledger.db missing  ->  run an agent first"
elif $PY ledger/verify.py --db data/ledger.db --key data/ledger_key.pem > /tmp/pf_verify 2>&1; then
  ok "$(tail -2 /tmp/pf_verify | head -1)"
else
  bad "ledger does not verify: $(head -1 /tmp/pf_verify)"
  printf "        the tamper act may not have been restored. Rebuild with:\n"
  printf "        rm -f data/ledger.db data/ledger_key.pem && bash scripts/run_all.sh\n"
fi

if curl -s -m 15 http://127.0.0.1:8080/v1/export > /tmp/pf_bundle.json 2>/dev/null; then
  if $PY audit.py /tmp/pf_bundle.json > /tmp/pf_audit 2>&1; then
    ok "independent auditor verifies the exported bundle"
  else
    bad "audit.py rejected the bundle: $(grep -m1 -E 'ALTERED|BROKEN|BAD' /tmp/pf_audit)"
  fi
  if $PY scripts/tamper_bundle.py /tmp/pf_bundle.json > /dev/null 2>&1 \
     && ! $PY audit.py /tmp/pf_bundle.json > /dev/null 2>&1; then
    ok "tamper detection works on a modified bundle"
  else
    bad "tampering with the bundle was NOT detected"
  fi
else
  bad "could not export an evidence bundle"
fi

# ---------------------------------------------------------------------------
head2 "Analysis"

ANALYSIS=$($PY - <<'PYEOF' 2>&1
import requests
NP = {"http": "", "https": ""}
try:
    tokens = requests.get("http://127.0.0.1:8080/v1/tokens", timeout=20,
                          proxies=NP).json()["tokens"]
    if not tokens:
        print("FAIL no tokens in the ledger; run an agent")
        raise SystemExit
    missing = [t for t in tokens[:10]
               if not requests.get("http://127.0.0.1:8080/v1/analysis",
                                   params={"jti": t}, timeout=10,
                                   proxies=NP).json().get("available")]
    if missing:
        print("FAIL {} of the 10 newest tokens have no analysis  ->  "
              "python3 analyzer/analyze.py --backfill".format(len(missing)))
    else:
        print("OK   the 10 newest tokens all have a published analysis")
except requests.RequestException as exc:
    print("FAIL cannot reach the proxy: {}".format(exc))
PYEOF
)
while IFS= read -r line; do
  case "$line" in
    OK*)   ok   "${line#OK   }" ;;
    FAIL*) bad  "${line#FAIL }" ;;
    *)     warn "$line" ;;
  esac
done <<< "$ANALYSIS"

# ---------------------------------------------------------------------------
head2 "Demo segments, smoke tested"

smoke() {  # name, command
  if timeout 120 bash -c "$2" > /tmp/pf_seg 2>&1; then
    ok "$1"
  else
    bad "$1  (last line: $(tail -1 /tmp/pf_seg | cut -c1-70))"
  fi
}

smoke "attack suite"            "$PY attacks/run_attacks.py | grep -q 'of .* scenarios behaved as expected'"
smoke "agent loop, offline"     "$PY agent/investigator.py --offline | grep -q 'root cause'"
smoke "control run"             "$PY agent/unprotected.py | grep -q OUTCOME"
smoke "isolation"               "$PY agent/isolation.py | grep -q 'still working'"
smoke "closed loop containment" "$PY agent/containment.py | grep -q 'WHAT HAPPENED'"
smoke "trace analysis"          "$PY analyzer/analyze.py --triage 5 | grep -q TRIAGE"
smoke "overhead benchmark"      "$PY scripts/benchmark.py | grep -q 'added latency'"
smoke "event trigger"           "$PY triggers/simulate_failure.py | grep -qi 'task\\|accepted'"
smoke "test suite"              "$PY -m pytest tests/ -q | tail -1 | grep -q passed"

# ---------------------------------------------------------------------------
head2 "Result"

printf "  %d passed, %d failed, %d warnings\n\n" "$PASS" "$FAIL" "$WARN"
rm -f /tmp/pf_verify /tmp/pf_audit /tmp/pf_bundle.json /tmp/pf_seg

if [ "$FAIL" -gt 0 ]; then
  printf "\033[31m  NOT READY. %d check(s) failed. Fix them before presenting.\033[0m\n\n" "$FAIL"
  exit 1
fi

printf "\033[32m  READY\033[0m\n"
printf "  Dashboard  http://127.0.0.1:8080/\n"
printf "  Demo       bash scripts/demo.sh\n"
if [ "$WARN" -gt 0 ]; then
  printf "  %d warning(s) above are not blocking.\n" "$WARN"
fi
printf "\n"
