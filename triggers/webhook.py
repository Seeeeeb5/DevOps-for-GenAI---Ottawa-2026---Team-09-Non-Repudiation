"""Event triggered investigation.

Until now every run started because a person typed a command. Track 1 is
Autonomous DevOps, so the agent should start itself.

This is a webhook receiver. A CI system posts a failure event, the receiver
requests a token scoped to that specific incident, and the investigation runs
with no human in the loop. The human only appears if they want to stop it.

Start it:
    python3 triggers/webhook.py

Fire an event at it, the way a CI system would:
    curl -X POST http://127.0.0.1:8083/events/ci \\
      -H 'content-type: application/json' \\
      -d '{"event":"pipeline_failed","run_id":"4471","pipeline":"radio-build-nightly"}'

Or use the helper:
    python3 triggers/simulate_failure.py
"""

import os
import subprocess
import sys
import threading
import time

from fastapi import BackgroundTasks, FastAPI
from pydantic import BaseModel

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

app = FastAPI(title="CI Event Receiver")

# Every event that arrived, and what was launched in response. This is not the
# evidence ledger. It only records that an investigation was started, and by
# what. What the investigation then did is recorded by the proxy, where the
# agent cannot influence it.
HISTORY = []
LOCK = threading.Lock()


class CIEvent(BaseModel):
    event: str
    run_id: str
    pipeline: str = "unknown"


def launch_investigation(run_id, task_id):
    """Start the agent as its own process, exactly as a scheduler would."""
    started = time.time()
    result = subprocess.run(
        [sys.executable, os.path.join(ROOT, "agent", "investigator.py"),
         "--offline", "--task", task_id, "--run", run_id],
        cwd=ROOT, capture_output=True, text=True, timeout=180,
    )
    with LOCK:
        for record in HISTORY:
            if record["task_id"] == task_id:
                record["status"] = "finished" if result.returncode == 0 else "failed"
                record["duration_s"] = round(time.time() - started, 2)
                record["output"] = result.stdout[-4000:]
                break


@app.get("/health")
def health():
    return {"status": "ok", "events_received": len(HISTORY)}


@app.get("/events")
def list_events():
    with LOCK:
        return {"events": [
            {k: v for k, v in record.items() if k != "output"}
            for record in HISTORY
        ]}


@app.get("/events/{task_id}")
def event_detail(task_id: str):
    with LOCK:
        for record in HISTORY:
            if record["task_id"] == task_id:
                return record
    return {"error": "unknown task"}


@app.post("/events/ci")
def ci_event(event: CIEvent, background: BackgroundTasks):
    """Receive a CI failure and start an investigation without asking anyone."""
    if event.event != "pipeline_failed":
        return {"ignored": event.event}

    task_id = "AUTO-{}-{}".format(event.run_id, int(time.time()))
    with LOCK:
        HISTORY.append({
            "task_id": task_id,
            "run_id": event.run_id,
            "pipeline": event.pipeline,
            "received_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "status": "running",
        })

    print("event: {} failed on {}, starting investigation {}".format(
        event.run_id, event.pipeline, task_id))
    background.add_task(launch_investigation, event.run_id, task_id)

    return {
        "accepted": True,
        "task_id": task_id,
        "note": "an agent has been dispatched. its actions are governed by the "
                "proxy and can be stopped from the dashboard at any time.",
    }
