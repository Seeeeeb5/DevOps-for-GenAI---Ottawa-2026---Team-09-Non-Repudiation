"""Revocation proxy.

This is the only path an agent has to a target system, and it is the single
point where four things happen at once:

  1. Token validation. Signature, expiry and issuer are checked.
  2. Live revocation check against the broker, so the kill switch takes effect
     on the next call instead of waiting for the token to expire.
  3. Policy enforcement. The request is mapped to a required scope and denied
     if the token does not carry it.
  4. Capture. Every call, allowed or denied, is redacted and written to the
     signed evidence ledger.

Capturing here rather than inside an agent SDK matters: an agent that goes off
the rails can decline to report itself, but it cannot decline to go through the
proxy, because the proxy holds the only credentials that the target accepts.
"""

import json
import os
import sqlite3
import sys

import jwt
import requests
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from common import digest_of  # noqa: E402
from ledger.store import Ledger  # noqa: E402
from ledger.telemetry import TelemetryStore, reconcile  # noqa: E402
from proxy import policy, redact  # noqa: E402

BROKER_URL = os.environ.get("BROKER_URL", "http://127.0.0.1:8081")
TARGET_URL = os.environ.get("TARGET_URL", "http://127.0.0.1:8082")
DATA_DIR = os.environ.get("DATA_DIR", os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data"))
NO_PROXY_ENV = {"http": "", "https": ""}

os.makedirs(DATA_DIR, exist_ok=True)

app = FastAPI(title="Revocation Proxy")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

ledger = Ledger(
    db_path=os.path.join(DATA_DIR, "ledger.db"),
    key_path=os.path.join(DATA_DIR, "ledger_key.pem"),
)

# Self reported agent telemetry lives in the same file but a separate table,
# because it does not carry the same trust level as the signed ledger.
telemetry = TelemetryStore(db_path=os.path.join(DATA_DIR, "ledger.db"))

_broker_public_key = None

# When the agent's own telemetry stops matching what the proxy observed, the
# system contains the agent itself rather than waiting for a person to notice.
# A discrepancy is not a debugging signal, it is the agent's account of its own
# behaviour becoming unreliable, and there is no safe reason to keep trusting
# it while that is true.
AUTO_CONTAIN = os.environ.get("AUTO_CONTAIN", "1") == "1"

# How many concealed actions are tolerated before containment. One is enough to
# act on, but a small threshold avoids reacting to a telemetry post that simply
# has not arrived yet.
CONCEAL_THRESHOLD = int(os.environ.get("CONCEAL_THRESHOLD", "2"))

# Agents already contained, so we do not revoke repeatedly.
CONTAINED = {}


def check_and_contain(claims):
    """Compare the two streams for this token and revoke on concealment.

    Runs after every allowed call. The agent has no way to opt out of this,
    because it does not know the check is happening and could not skip the
    proxy even if it did.
    """
    if not AUTO_CONTAIN:
        return None

    agent_id = claims.get("sub")
    jti = claims.get("jti")
    if not agent_id or not jti:
        return None

    # Containment is tracked per token, not per agent. A later token for the
    # same agent is a fresh grant and gets judged on its own behaviour, which
    # also means a reinstated agent is not permanently pre-judged.
    if jti in CONTAINED:
        return None

    # Only this token's entries are relevant, so only they are read. Reading
    # the whole ledger here made the cost of every allowed call grow with the
    # size of the ledger: measured +35 ms at an empty ledger rising to +53 ms
    # at 1435 entries, against a flat +22 ms with containment disabled.
    result = reconcile(ledger.by_token(jti), telemetry.by_token(jti), jti)

    # Only act when the agent reported something. An agent with no telemetry
    # at all is not instrumented, which is a configuration gap rather than
    # evidence of concealment.
    if result["reported_by_agent"] == 0:
        return None
    if len(result["concealed"]) < CONCEAL_THRESHOLD:
        return None

    reason = "automatic containment: {} action(s) performed but not reported ({})".format(
        len(result["concealed"]), ", ".join(result["concealed"]))
    try:
        requests.post(
            BROKER_URL + "/revoke",
            json={"agent_id": agent_id, "reason": reason},
            timeout=5,
            proxies=NO_PROXY_ENV,
        )
    except requests.RequestException:
        return None

    CONTAINED[jti] = {
        "agent_id": agent_id,
        "jti": jti,
        "task_id": claims.get("task_id"),
        "principal": claims.get("principal"),
        "concealed": result["concealed"],
        "observed": result["observed_by_proxy"],
        "reported": result["reported_by_agent"],
        "reason": reason,
    }

    # The containment decision is itself evidence and belongs in the ledger.
    record("CONTAIN", reason, claims, "SYSTEM", "/containment", None, "critical",
           0, "", "")
    return CONTAINED[jti]


def broker_public_key(force=False):
    """Fetch and cache the broker token verification key.

    The cache has to be droppable. The broker generates its signing key in
    memory at startup, so restarting it produces a new key, and a proxy holding
    the old one rejected every token from that point on, including freshly
    issued valid ones. The symptom was "invalid token", which sends whoever is
    debugging to the agent or the broker rather than to a stale cache in a third
    process. Verified before this change: restart the broker, request a brand new
    token, get 401.

    The same mechanism is what makes ordinary key rotation survivable.
    """
    global _broker_public_key
    if force or _broker_public_key is None:
        response = requests.get(BROKER_URL + "/public-key", timeout=5, proxies=NO_PROXY_ENV)
        response.raise_for_status()
        _broker_public_key = response.json()["public_key_pem"]
    return _broker_public_key


def decode_token(token):
    """Verify a token, refreshing the broker key once if verification fails.

    A signature that does not verify has two causes that look identical: a forged
    token, or a key we should no longer be trusting. Retrying once with a fresh
    key distinguishes them, and a forged token still fails the second time.
    """
    try:
        return jwt.decode(token, broker_public_key(), algorithms=["ES256"],
                          issuer="non-repudiation-broker")
    except jwt.ExpiredSignatureError:
        # Expiry is not a key problem. Refetching would prove nothing.
        raise
    except jwt.InvalidTokenError:
        return jwt.decode(token, broker_public_key(force=True), algorithms=["ES256"],
                          issuer="non-repudiation-broker")


def record(decision, reason, claims, method, path, required_scope, risk,
           status_code, request_body, response_body):
    """Redact both payloads and append one signed entry to the ledger."""
    redacted_request, request_marks = redact.redact(request_body or "")
    redacted_response, response_marks = redact.redact(response_body or "")
    return ledger.append({
        "agent_id": claims.get("sub", "unknown"),
        "agent_version": claims.get("agent_version"),
        "owner": claims.get("owner"),
        "principal": claims.get("principal"),
        "task_id": claims.get("task_id"),
        "jti": claims.get("jti"),
        "method": method,
        "path": path,
        "decision": decision,
        "reason": reason,
        "required_scope": required_scope,
        "status_code": status_code,
        "request_digest": digest_of(redacted_request),
        "response_digest": digest_of(redacted_response),
        "redactions": ",".join(request_marks + response_marks) or None,
    })


@app.get("/health")
def health():
    return {"status": "ok", "broker": BROKER_URL, "target": TARGET_URL}


@app.get("/v1/ledger")
def read_ledger(limit: int = 100, jti: str = None):
    """Expose the ledger so the dashboard can render the live trace.

    Passing jti returns every entry for that token and ignores limit. A client
    that filters by token itself has to guess a limit large enough to still
    contain the token it wants, and silently analyses a partial trace when the
    guess is wrong.
    """
    if jti:
        entries = ledger.by_token(jti)
    else:
        entries = ledger.read_all(limit=limit)
    return {
        "public_key_pem": ledger.public_key_pem(),
        "entries": list(reversed(entries)),
    }


@app.post("/v1/report")
async def report(request: Request):
    """Accept one self reported event from an agent.

    This endpoint is intentionally unauthenticated and intentionally trusting,
    because nothing here is treated as evidence. It is narrative that gets
    checked against the ledger, not a substitute for it.

    It also cannot be allowed to fail loudly. Telemetry is the weaker of the two
    streams by design, so losing one event is a gap in the narrative, not a loss
    of evidence. Returning a 500 here would let an unstorable event break the
    agent that reported it.
    """
    try:
        event = await request.json()
    except ValueError:
        return JSONResponse({"accepted": False, "reason": "not json"},
                            status_code=400)
    try:
        telemetry.record(event)
    except sqlite3.Error as exc:
        return {"accepted": False, "reason": "telemetry store busy: {}".format(exc)}
    return {"accepted": True}


@app.get("/v1/telemetry")
def read_telemetry(limit: int = 200, jti: str = None):
    """Return recent self reported events for the trace view.

    Passing jti returns every event for that token and ignores limit, for the
    same reason as /v1/ledger.
    """
    if jti:
        return {"events": telemetry.by_token(jti)}
    return {"events": telemetry.all_events(limit=limit)}


@app.get("/v1/reconcile/{jti}")
def reconcile_token(jti: str):
    """Compare what the proxy observed against what the agent admitted to."""
    return reconcile(ledger.read_all(), telemetry.by_token(jti), jti)


@app.get("/v1/containment")
def containment_events():
    """Agents the system stopped on its own, and why."""
    return {"auto_contain": AUTO_CONTAIN,
            "threshold": CONCEAL_THRESHOLD,
            "events": list(CONTAINED.values())}


# Trace analysis published by analyzer/analyze.py, keyed by token id.
#
# This is a third trust level and the weakest of the three. The ledger is
# evidence: signed, and captured by a component the agent cannot bypass. Agent
# telemetry is narrative: unsigned, and credible only as far as reconciliation
# can confirm it. Analysis is interpretation: derived from the other two, partly
# produced by a model, and therefore a claim about the record rather than an
# observation of anything.
#
# It is held here so the dashboard has one place to read it from. Nothing in the
# request path reads it back. The proxy does not import the analyzer and never
# calls a model, because a control that can be argued with is not a control, and
# that property is what the rest of this design rests on.
#
# Persisted to its own directory rather than into ledger.db. Telemetry shares
# that file because it is at least a record of something an agent claimed;
# interpretation is not a record at all, and keeping it out of the evidence file
# means an operator with the database in front of them cannot mistake one for
# the other.
ANALYSES = {}
ANALYSIS_LIMIT = 50
ANALYSIS_DIR = os.path.join(DATA_DIR, "analysis")
os.makedirs(ANALYSIS_DIR, exist_ok=True)


def _analysis_path(jti):
    """Path for one token's analysis, with the token id sanitised."""
    safe = "".join(c for c in jti if c.isalnum() or c in "-_")[:80]
    return os.path.join(ANALYSIS_DIR, safe + ".json")


def _load_analysis(jti):
    """Read one analysis from disk, or None. Memory is only a cache."""
    if jti in ANALYSES:
        return ANALYSES[jti]
    path = _analysis_path(jti)
    if not os.path.exists(path):
        return None
    try:
        with open(path) as handle:
            document = json.load(handle)
    except (OSError, ValueError):
        return None
    ANALYSES[jti] = document
    return document


def _newest_analysis():
    """The most recently published analysis, from memory or from disk."""
    if ANALYSES:
        return next(reversed(list(ANALYSES.values())), None)
    try:
        files = [os.path.join(ANALYSIS_DIR, name)
                 for name in os.listdir(ANALYSIS_DIR) if name.endswith(".json")]
    except OSError:
        return None
    if not files:
        return None
    try:
        with open(max(files, key=os.path.getmtime)) as handle:
            return json.load(handle)
    except (OSError, ValueError):
        return None


@app.post("/v1/analysis")
async def publish_analysis(request: Request):
    """Accept one analysis document from the analyzer.

    Unauthenticated and unvalidated for the same reason as /v1/report: nothing
    stored here is treated as evidence, and nothing downstream acts on it.
    """
    from common import now_iso

    document = await request.json()
    jti = document.get("jti")
    if not jti:
        return JSONResponse({"error": "analysis must name a jti"}, status_code=400)

    document["trust"] = "derived"
    document["stored_at"] = now_iso()

    # Re-inserting moves this token to the end, so the newest publication is
    # always last and /v1/analysis with no argument returns it.
    ANALYSES.pop(jti, None)
    ANALYSES[jti] = document
    while len(ANALYSES) > ANALYSIS_LIMIT:
        ANALYSES.pop(next(iter(ANALYSES)))

    try:
        with open(_analysis_path(jti), "w") as handle:
            json.dump(document, handle)
    except OSError:
        # Losing the copy on disk costs a restart's worth of history and
        # nothing else. It must not fail the publication.
        pass

    return {"accepted": True, "jti": jti}


@app.get("/v1/analysis")
def read_analysis(jti: str = None):
    """Return the analysis for one token, or the most recently published one."""
    document = _load_analysis(jti) if jti else _newest_analysis()
    if document is None:
        try:
            stored = len([n for n in os.listdir(ANALYSIS_DIR)
                          if n.endswith(".json")])
        except OSError:
            stored = 0
        return {"available": False, "jti": jti, "analysed_tokens": stored}
    return dict(document, available=True)


@app.get("/v1/export")
def export_bundle():
    """Export a self contained evidence bundle for independent audit.

    The bundle carries the entries, the public key and the chain head. It is
    everything a third party needs to check the record without trusting us or
    contacting us again. audit.py in the project root reads exactly this.
    """
    from common import now_iso

    entries = ledger.read_all()
    return {
        "format": "non-repudiation-evidence-bundle/1",
        "exported_at": now_iso(),
        "public_key_pem": ledger.public_key_pem(),
        "chain_head": entries[-1]["entry_hash"] if entries else None,
        "entry_count": len(entries),
        "entries": entries,
        "how_to_verify": "python3 audit.py <this file>",
    }


@app.get("/v1/tokens")
def list_tokens(limit: int = None):
    """List the token ids seen in the ledger, newest first, for the dashboard.

    Polled by the dashboard every 1.5s and by the analyzer watcher, so it does
    the grouping in SQL rather than scanning the whole ledger in Python.
    """
    return {"tokens": ledger.token_ids(limit=limit)}


@app.get("/v1/agents")
def list_agents():
    """The agent registry, fetched from the broker on the dashboard's behalf.

    The dashboard used to call the broker directly on port 8081. That works on
    one machine and fails everywhere else: over an SSH tunnel it needs a second
    forwarded port, and the agent list silently stays empty when only the
    dashboard's own port is reachable.

    It is also the wrong shape. The broker is a control plane service and a
    browser should not need a route to it. Serving this from the same origin as
    the page means the dashboard has exactly one dependency, which is the
    process that served it.
    """
    try:
        response = requests.get(BROKER_URL + "/agents", timeout=5,
                                proxies=NO_PROXY_ENV)
        response.raise_for_status()
        return {"agents": response.json(), "broker": "reachable"}
    except requests.RequestException as exc:
        # Say so rather than returning an empty list. An empty registry and an
        # unreachable broker look identical on screen and mean opposite things.
        return JSONResponse(
            {"agents": [], "broker": "unreachable", "detail": str(exc)},
            status_code=503,
        )


@app.post("/v1/agents/{agent_id}/{action}")
def set_agent_state(agent_id: str, action: str):
    """Revoke or reinstate one agent, forwarded to the broker.

    Note for anyone hardening this: the kill switch is now reachable on the
    dashboard's port as well as the broker's, and neither is authenticated. That
    was already true of the broker, so this widens nothing that was closed, but
    it does make the case for putting authentication in front of the control
    plane harder to defer. Who may stop an agent is itself a privileged
    decision.
    """
    if action not in ("revoke", "reinstate"):
        return JSONResponse({"error": "action must be revoke or reinstate"},
                            status_code=400)
    try:
        response = requests.post(
            "{}/{}".format(BROKER_URL, action),
            json={"agent_id": agent_id, "reason": "from control plane"},
            timeout=5, proxies=NO_PROXY_ENV,
        )
        return JSONResponse(_safe_json(response.text),
                            status_code=response.status_code)
    except requests.RequestException as exc:
        return JSONResponse({"error": "broker unreachable", "detail": str(exc)},
                            status_code=503)


@app.get("/")
def dashboard():
    path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "dashboard",
        "index.html",
    )
    return FileResponse(path)


@app.api_route("/gw/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
async def gateway(path: str, request: Request):
    """The single enforced path from any agent to any target system."""
    method = request.method
    target_path = "/" + path
    raw_body = (await request.body()).decode("utf-8", errors="replace")

    auth = request.headers.get("authorization", "")
    if not auth.lower().startswith("bearer "):
        record("DENY", "missing bearer token", {}, method, target_path,
               None, None, 401, raw_body, "")
        return JSONResponse({"error": "missing bearer token"}, status_code=401)

    token = auth.split(" ", 1)[1].strip()

    # Step 1. Validate the token signature and expiry.
    try:
        claims = decode_token(token)
    except jwt.ExpiredSignatureError:
        record("DENY", "token expired", {}, method, target_path, None, None,
               401, raw_body, "")
        return JSONResponse({"error": "token expired"}, status_code=401)
    except jwt.InvalidTokenError as exc:
        record("DENY", "invalid token: {}".format(exc), {}, method, target_path,
               None, None, 401, raw_body, "")
        return JSONResponse({"error": "invalid token"}, status_code=401)

    # Step 2. Live revocation check. This is what makes the kill switch instant.
    try:
        status = requests.get(
            "{}/status/{}".format(BROKER_URL, claims["sub"]),
            timeout=5,
            proxies=NO_PROXY_ENV,
        ).json()
    except requests.RequestException:
        record("DENY", "broker unreachable, failing closed", claims, method,
               target_path, None, None, 503, raw_body, "")
        return JSONResponse({"error": "broker unreachable"}, status_code=503)

    if status.get("status") != "active":
        entry = record("DENY", "agent revoked at {}".format(status.get("revoked_at")),
                       claims, method, target_path, None, None, 403, raw_body, "")
        return JSONResponse(
            {"error": "agent revoked", "ledger_seq": entry["seq"]}, status_code=403
        )

    # Step 3. Policy enforcement.
    allowed, required_scope, risk, reason = policy.decide(
        method, target_path, claims.get("scopes", [])
    )
    if not allowed:
        entry = record("DENY", reason, claims, method, target_path,
                       required_scope, risk, 403, raw_body, "")
        return JSONResponse(
            {"error": "denied by policy", "reason": reason, "ledger_seq": entry["seq"]},
            status_code=403,
        )

    # Step 4. Forward using the proxy credential. The agent never holds it.
    #
    # Paths under /gh/ route to the real GitHub API. This exists to show that
    # nothing about the design depends on the target being a mock: the same
    # token, the same policy file and the same ledger govern a real third
    # party API. Only read operations are routed this way. Destructive
    # operations stay on the mock, because they are refused at the proxy
    # anyway and there is no reason to point them at a live system.
    if target_path.startswith("/gh/"):
        upstream_url = "https://api.github.com" + target_path[3:]
        upstream_headers = {
            "accept": "application/vnd.github+json",
            "user-agent": "non-repudiation-proxy",
        }
        github_token = os.environ.get("GITHUB_TOKEN")
        if github_token:
            upstream_headers["authorization"] = "Bearer " + github_token
        upstream = requests.request(
            method, upstream_url, headers=upstream_headers, timeout=20
        )
    else:
        upstream = requests.request(
            method,
            TARGET_URL + target_path,
            data=raw_body.encode() if raw_body else None,
            headers={
                "content-type": request.headers.get("content-type", "application/json"),
                "x-target-credential": os.environ.get("TARGET_CREDENTIAL", "proxy-held-secret"),
            },
            timeout=15,
            proxies=NO_PROXY_ENV,
        )

    entry = record("ALLOW", reason, claims, method, target_path, required_scope,
                   risk, upstream.status_code, raw_body, upstream.text)

    # Step 5. Check the agent's account of itself against our own record.
    containment = check_and_contain(claims)

    headers = {"x-ledger-seq": str(entry["seq"])}
    if containment:
        headers["x-contained"] = "true"

    return JSONResponse(
        content=_safe_json(upstream.text),
        status_code=upstream.status_code,
        headers=headers,
    )


def _safe_json(text):
    try:
        return json.loads(text)
    except (ValueError, TypeError):
        return {"raw": text}
