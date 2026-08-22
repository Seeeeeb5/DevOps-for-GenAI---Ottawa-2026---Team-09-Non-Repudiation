"""Mock CI/CD system.

Stands in for GitLab, GitHub Actions or Jenkins during the demo. It only
accepts requests that carry the credential held by the proxy, which is how we
show that the agent has no direct path to the target.
"""

from fastapi import FastAPI, Header, HTTPException

app = FastAPI(title="Mock CI/CD System")

EXPECTED_CREDENTIAL = "proxy-held-secret"

RUNS = {
    "4471": {
        "id": "4471",
        "pipeline": "radio-build-nightly",
        "status": "failed",
        "branch": "main",
        "failed_stage": "unit-test",
        "duration_s": 412,
    },
    "4472": {
        "id": "4472",
        "pipeline": "radio-build-nightly",
        "status": "success",
        "branch": "main",
        "failed_stage": None,
        "duration_s": 388,
    },
}

LOGS = {
    "4471": (
        "[unit-test] collecting 214 tests\n"
        "[unit-test] tests/test_vault_client.py::test_login FAILED\n"
        "[unit-test] ConnectionError: cannot reach vault at 10.114.210.45:8200\n"
        "[unit-test] note: build agent contacted ops@example.com for the new token\n"
        "[unit-test] 1 failed, 213 passed in 96.20s\n"
    ),
    "4472": "[unit-test] 214 passed in 91.02s\n",
}


def check_credential(credential):
    if credential != EXPECTED_CREDENTIAL:
        raise HTTPException(status_code=401, detail="target credential missing or wrong")


@app.get("/runs")
def list_runs(x_target_credential: str = Header(default="")):
    check_credential(x_target_credential)
    return {"runs": list(RUNS.values())}


@app.get("/runs/{run_id}")
def get_run(run_id: str, x_target_credential: str = Header(default="")):
    check_credential(x_target_credential)
    if run_id not in RUNS:
        raise HTTPException(status_code=404, detail="unknown run")
    return RUNS[run_id]


@app.get("/runs/{run_id}/logs")
def get_logs(run_id: str, x_target_credential: str = Header(default="")):
    check_credential(x_target_credential)
    if run_id not in LOGS:
        raise HTTPException(status_code=404, detail="unknown run")
    return {"run_id": run_id, "logs": LOGS[run_id]}


@app.post("/runs/{run_id}/rerun")
def rerun(run_id: str, x_target_credential: str = Header(default="")):
    check_credential(x_target_credential)
    if run_id not in RUNS:
        raise HTTPException(status_code=404, detail="unknown run")
    RUNS[run_id]["status"] = "running"
    return {"run_id": run_id, "status": "running"}


@app.post("/deploy")
def deploy(x_target_credential: str = Header(default="")):
    check_credential(x_target_credential)
    return {"status": "deployed", "environment": "production"}


@app.delete("/branches/{name}")
def delete_branch(name: str, x_target_credential: str = Header(default="")):
    check_credential(x_target_credential)
    return {"deleted": name}
