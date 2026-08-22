"""Identity broker.

Responsibilities:
  1. Hold the registry of known agents, their owners and their maximum scopes.
  2. Issue short lived, single task, scope limited tokens.
  3. Own the kill switch. Revocation takes effect immediately because the
     proxy checks agent status on every call instead of waiting for expiry.

The broker never forwards traffic. It only decides who an agent is and what
it is allowed to ask for.
"""

import os
import sys
import uuid

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from common import now_iso  # noqa: E402

TOKEN_TTL_SECONDS = int(os.environ.get("TOKEN_TTL_SECONDS", "120"))
ISSUER = "non-repudiation-broker"

app = FastAPI(title="Identity Broker")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Signing key for agent tokens. Generated at startup for the prototype.
# In production this key lives in a KMS or in Vault and is rotated.
_signing_key = ec.generate_private_key(ec.SECP256R1())
_signing_pem = _signing_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption(),
).decode()
_public_pem = (
    _signing_key.public_key()
    .public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    .decode()
)

# Agent registry. A real deployment would back this with a database and an
# enterprise identity provider. The bootstrap secret stands in for workload
# attestation, which is listed as future work in the README.
AGENTS = {
    "ci-debug-agent": {
        "agent_id": "ci-debug-agent",
        "agent_version": "1.0.3",
        "owner": "freeman.liu@example.com",
        "bootstrap_secret": "bootstrap-ci-debug",
        "max_scopes": ["runs:read", "logs:read", "runs:rerun"],
        "status": "active",
        "revoked_at": None,
    },
    "deploy-agent": {
        "agent_id": "deploy-agent",
        "agent_version": "0.9.1",
        "owner": "nina.li@example.com",
        "bootstrap_secret": "bootstrap-deploy",
        "max_scopes": ["runs:read", "deploy:write"],
        "status": "active",
        "revoked_at": None,
    },
}

# Tokens that were issued and then explicitly killed before their expiry.
REVOKED_JTI = set()


class TokenRequest(BaseModel):
    agent_id: str
    bootstrap_secret: str
    task_id: str
    requested_scopes: list[str]
    principal: str | None = None


class RevokeRequest(BaseModel):
    agent_id: str
    reason: str = "revoked by owner"


@app.get("/public-key")
def public_key():
    """Return the token verification key so the proxy can validate signatures."""
    return {"algorithm": "ES256", "issuer": ISSUER, "public_key_pem": _public_pem}


@app.get("/agents")
def list_agents():
    """Return the agent registry without secrets, for the dashboard."""
    return [
        {k: v for k, v in agent.items() if k != "bootstrap_secret"}
        for agent in AGENTS.values()
    ]


@app.get("/status/{agent_id}")
def agent_status(agent_id: str):
    """Return the live status of one agent. The proxy calls this on every request."""
    agent = AGENTS.get(agent_id)
    if agent is None:
        raise HTTPException(status_code=404, detail="unknown agent")
    return {
        "agent_id": agent_id,
        "status": agent["status"],
        "revoked_at": agent["revoked_at"],
    }


@app.post("/token")
def issue_token(req: TokenRequest):
    """Issue a short lived token bound to one agent, one task and one scope set."""
    agent = AGENTS.get(req.agent_id)
    if agent is None or agent["bootstrap_secret"] != req.bootstrap_secret:
        raise HTTPException(status_code=401, detail="agent authentication failed")
    if agent["status"] != "active":
        raise HTTPException(status_code=403, detail="agent is revoked")

    # An agent can never receive more than its registered maximum scopes.
    granted = [s for s in req.requested_scopes if s in agent["max_scopes"]]
    if not granted:
        raise HTTPException(status_code=403, detail="no requested scope is permitted")

    jti = str(uuid.uuid4())
    import time

    issued_at = int(time.time())
    claims = {
        "iss": ISSUER,
        "sub": agent["agent_id"],
        "jti": jti,
        "iat": issued_at,
        "exp": issued_at + TOKEN_TTL_SECONDS,
        "agent_version": agent["agent_version"],
        "owner": agent["owner"],
        "principal": req.principal or agent["owner"],
        "task_id": req.task_id,
        "scopes": granted,
    }
    token = jwt.encode(claims, _signing_pem, algorithm="ES256")
    return {
        "token": token,
        "jti": jti,
        "granted_scopes": granted,
        "expires_in": TOKEN_TTL_SECONDS,
        "issued_at": now_iso(),
    }


@app.post("/revoke")
def revoke(req: RevokeRequest):
    """Kill switch. The next proxied call from this agent is denied."""
    agent = AGENTS.get(req.agent_id)
    if agent is None:
        raise HTTPException(status_code=404, detail="unknown agent")
    agent["status"] = "revoked"
    agent["revoked_at"] = now_iso()
    agent["revocation_reason"] = req.reason
    return {"agent_id": req.agent_id, "status": "revoked", "revoked_at": agent["revoked_at"]}


@app.post("/reinstate")
def reinstate(req: RevokeRequest):
    """Restore an agent. Useful when running the demo more than once."""
    agent = AGENTS.get(req.agent_id)
    if agent is None:
        raise HTTPException(status_code=404, detail="unknown agent")
    agent["status"] = "active"
    agent["revoked_at"] = None
    return {"agent_id": req.agent_id, "status": "active"}
