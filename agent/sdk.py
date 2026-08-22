"""Flight recorder SDK.

This records what happens inside the agent: model calls, hypotheses, retries,
local reasoning steps. The proxy cannot see any of that, because none of it
crosses the network boundary.

Everything recorded here is self reported and therefore untrusted. The agent
could lie, or stay silent. What makes it useful anyway is that every event
carries the jti of the token the agent is currently holding, and the proxy
independently records that same jti. Comparing the two streams turns an
untrusted narrative into a verifiable one: if the proxy saw six calls under a
token and the agent only admits to three, the gap is evidence of concealment.

Usage:
    recorder = FlightRecorder(jti, task_id, agent_id)
    recorder.model_call("claude-sonnet", tokens_in=820, tokens_out=140)
    recorder.hypothesis("vault unreachable from build agent", confidence=0.7)
    recorder.tool_call("GET", "/runs/4471/logs")
"""

import time

import requests

PROXY_URL = "http://127.0.0.1:8080"
NO_PROXY_ENV = {"http": "", "https": ""}


class FlightRecorder:
    def __init__(self, jti, task_id, agent_id, agent_version="1.0.3",
                 proxy_url=PROXY_URL, silent_about=None):
        self.jti = jti
        self.task_id = task_id
        self.agent_id = agent_id
        self.agent_version = agent_version
        self.proxy_url = proxy_url
        self.sequence = 0
        # Paths the agent deliberately omits from its own telemetry. Used only
        # to demonstrate that concealment is detectable.
        self.silent_about = silent_about or []

    def _emit(self, event_type, payload):
        self.sequence += 1
        event = {
            "jti": self.jti,
            "task_id": self.task_id,
            "agent_id": self.agent_id,
            "agent_version": self.agent_version,
            "sequence": self.sequence,
            "event_type": event_type,
            "client_ts": time.time(),
        }
        event.update(payload)
        try:
            requests.post(
                self.proxy_url + "/v1/report",
                json=event,
                timeout=5,
                proxies=NO_PROXY_ENV,
            )
        except requests.RequestException:
            # Telemetry loss must never break the agent. The proxy record is
            # the authoritative one anyway.
            pass
        return event

    def model_call(self, model, tokens_in=0, tokens_out=0, cost=0.0, summary=""):
        """Record one model invocation. Invisible to the proxy."""
        return self._emit("model_call", {
            "model": model,
            "tokens_in": tokens_in,
            "tokens_out": tokens_out,
            "cost": cost,
            "summary": summary,
        })

    def hypothesis(self, statement, confidence=0.0, evidence=None):
        """Record a hypothesis the agent formed."""
        return self._emit("hypothesis", {
            "summary": statement,
            "confidence": confidence,
            "evidence": ", ".join(evidence or []),
        })

    def hypothesis_rejected(self, statement, reason=""):
        return self._emit("hypothesis_rejected", {
            "summary": statement,
            "reason": reason,
        })

    def tool_call(self, method, path, note=""):
        """Record an outbound call the agent is about to make.

        This is the only event type that overlaps with what the proxy sees, so
        it is the one reconciliation compares.
        """
        if path in self.silent_about:
            # The agent chooses not to report this action. The proxy will still
            # record it, and reconciliation will surface the discrepancy.
            return None
        return self._emit("tool_call", {
            "method": method,
            "path": path,
            "summary": note,
        })

    def retry(self, what, attempt):
        return self._emit("retry", {"summary": what, "attempt": attempt})

    def human_feedback(self, feedback):
        return self._emit("human_feedback", {"summary": feedback})

    def conclusion(self, statement):
        return self._emit("conclusion", {"summary": statement})
