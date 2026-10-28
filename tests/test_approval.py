"""Approval gate: `done` is approved as-is, `partial` only with a reason.

A partial verdict means the verifier could not prove everything (a test was
added, product code merely mentions the report path, the baseline was
unmeasurable). Approving it is a human judgement, so the reason is required and
is written into the trace together with the findings being overridden.
``verification-failed`` and ``blocked`` are never approvable.

No Docker: the run directories are hand-built traces.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.main import app
from ega import pipeline
from ega.trace import Trace, summarize

client = TestClient(app)


def make_run(
    root,
    token: str,
    codes: list[str] | None = None,
    run_id: str = "run-1",
    *,
    status: str | None = "ok",
    truncated: bool = False,
) -> str:
    trace = Trace(root / run_id / "trace.jsonl", run_id)
    trace.append("fixture.copy", data={})
    findings = []
    for code in codes or []:
        finding = {"code": code, "severity": "medium", "message": "", "evidence": ""}
        if truncated:
            finding["truncated"] = True
        findings.append(finding)
    trace.append(
        "verify",
        data={
            "verdict": {
                "exit_token": token,
                "first_line": f"exit: {token} — canned",
                "counts": {"collected": 6, "passed": 6},
                "findings": findings,
            }
        },
    )
    if status is not None:
        trace.append("pipeline.end", data={"status": status})
    return run_id


def test_a_done_run_is_approved_without_a_reason(tmp_path):
    run_id = make_run(tmp_path, "done")

    summary = pipeline.approve(run_id, runs_root=tmp_path)

    assert summary["approved"] is True


def test_a_partial_run_needs_a_reason(tmp_path):
    run_id = make_run(tmp_path, "partial", ["TESTS_ADDED"])

    with pytest.raises(PermissionError) as excinfo:
        pipeline.approve(run_id, runs_root=tmp_path)

    assert "requires a non-empty reason" in str(excinfo.value)
    assert "TESTS_ADDED" in str(excinfo.value)


def test_a_partial_run_is_approved_with_a_reason_and_the_reason_is_traced(tmp_path):
    run_id = make_run(tmp_path, "partial", ["TESTS_ADDED"])

    summary = pipeline.approve(
        run_id, runs_root=tmp_path, reason="added regression test, reviewed the diff"
    )

    assert summary["approved"] is True
    record = [r for r in _records(tmp_path, run_id) if r["step"] == "approve"][0]
    assert record["inputs"]["reason"] == "added regression test, reviewed the diff"
    assert record["data"]["verdict"] == "partial"
    assert record["data"]["overridden_findings"] == ["TESTS_ADDED"]
    assert record["data"]["side_effect"] == "none (scaffolding phase)"


def test_a_blank_reason_is_not_a_reason(tmp_path):
    run_id = make_run(tmp_path, "partial", ["SUSPICIOUS_PRODUCT_CODE"])

    with pytest.raises(PermissionError):
        pipeline.approve(run_id, runs_root=tmp_path, reason="   ")


@pytest.mark.parametrize("token", ["verification-failed", "blocked"])
def test_a_failed_or_blocked_run_is_never_approvable(tmp_path, token):
    run_id = make_run(tmp_path, token, ["TESTS_FAILED"])

    with pytest.raises(PermissionError):
        pipeline.approve(run_id, runs_root=tmp_path, reason="please")


def test_a_run_that_crashed_after_its_verdict_is_not_approvable(tmp_path):
    """Review L1: a done verdict inside a run that never finished proves nothing."""
    run_id = make_run(tmp_path, "done", status="failed")

    with pytest.raises(PermissionError) as excinfo:
        pipeline.approve(run_id, runs_root=tmp_path)

    assert "not 'ok'" in str(excinfo.value)


def test_a_run_that_never_finished_is_not_approvable(tmp_path):
    run_id = make_run(tmp_path, "done", status=None)

    with pytest.raises(PermissionError) as excinfo:
        pipeline.approve(run_id, runs_root=tmp_path)

    assert "running" in str(excinfo.value)


def test_a_finding_with_truncated_evidence_is_not_approvable(tmp_path):
    """Review M1: a human cannot approve a diff they were not shown."""
    run_id = make_run(tmp_path, "partial", ["TESTS_ADDED"], truncated=True)

    with pytest.raises(PermissionError) as excinfo:
        pipeline.approve(run_id, runs_root=tmp_path, reason="read the diff")

    message = str(excinfo.value)
    assert "truncated" in message
    assert "harness.diff" in message


def _records(root, run_id: str) -> list[dict]:
    from ega.trace import read_trace

    return read_trace(root / run_id / "trace.jsonl")


# --- the HTTP surface -----------------------------------------------------


@pytest.fixture
def runs_in(tmp_path, monkeypatch):
    monkeypatch.setattr(pipeline, "runs_dir", lambda: tmp_path)
    return tmp_path


def test_the_api_returns_409_for_a_partial_run_without_a_reason(runs_in):
    run_id = make_run(runs_in, "partial", ["TESTS_ADDED"])

    response = client.post(f"/api/runs/{run_id}/approve", json={"reason": ""})

    assert response.status_code == 409
    assert "reason" in response.json()["detail"]


def test_the_api_approves_a_partial_run_with_a_reason(runs_in):
    run_id = make_run(runs_in, "partial", ["TESTS_ADDED"])

    response = client.post(
        f"/api/runs/{run_id}/approve", json={"reason": "regression test is a genuine addition"}
    )

    assert response.status_code == 200, response.text
    assert response.json()["summary"]["approved"] is True
    assert summarize(runs_in / run_id / "trace.jsonl")["approved"] is True


def test_the_api_returns_409_for_verification_failed(runs_in):
    run_id = make_run(runs_in, "verification-failed", ["TESTS_FAILED"])

    response = client.post(f"/api/runs/{run_id}/approve", json={"reason": "trust me"})

    assert response.status_code == 409