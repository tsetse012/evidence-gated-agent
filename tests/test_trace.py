"""Trace: append-only JSONL, summary derived by a pure function."""

from __future__ import annotations

import json

import pytest

from ega.trace import Trace, read_trace, summarize, write_summary


def test_append_is_append_only(tmp_path):
    path = tmp_path / "trace.jsonl"
    trace = Trace(path, "run-1")
    trace.append("fixture.copy", inputs={"fixture": "buggy_invoice"})
    trace.append("pipeline.end", data={"status": "ok", "exit_token": "done"})

    records = read_trace(path)
    assert [r["step"] for r in records] == ["fixture.copy", "pipeline.end"]
    assert [r["seq"] for r in records] == [1, 2]
    assert all(r["ts"] for r in records)


def test_reopening_a_trace_continues_the_sequence(tmp_path):
    path = tmp_path / "trace.jsonl"
    Trace(path, "run-1").append("a")
    Trace(path, "run-1").append("b")
    assert [r["seq"] for r in read_trace(path)] == [1, 2]


def test_summary_is_derived_and_regenerable(tmp_path):
    path = tmp_path / "trace.jsonl"
    trace = Trace(path, "run-1")
    trace.append("author.work", data={"claim": {"status": "done", "tests_claimed_passed": 6}})
    trace.append(
        "verify",
        stdout="6 passed in 0.04s",
        exit_code=0,
        data={
            "verdict": {
                "exit_token": "done",
                "first_line": "exit: done — 6/6 tests passed",
                "counts": {"collected": 6, "passed": 6},
                "findings": [],
                "isolation": "runc",
            }
        },
    )
    trace.append("pipeline.end", data={"status": "ok", "exit_token": "done", "duration_s": 1.5})

    summary = summarize(path)
    assert summary["status"] == "ok"
    assert summary["exit_token"] == "done"
    assert summary["claim"]["tests_claimed_passed"] == 6
    assert summary["isolation"] == "runc"
    assert summary["approved"] is False
    assert summary["step_count"] == 3

    written = write_summary(path)
    assert json.loads((tmp_path / "summary.json").read_text(encoding="utf-8")) == written
    # regenerating changes nothing: the summary is a pure function of the trace
    assert write_summary(path) == written


def test_summary_without_end_step_is_running(tmp_path):
    path = tmp_path / "trace.jsonl"
    Trace(path, "run-1").append("fixture.copy")
    assert summarize(path)["status"] == "running"


def test_approve_step_flips_approved(tmp_path):
    path = tmp_path / "trace.jsonl"
    trace = Trace(path, "run-1")
    trace.append("verify", data={"verdict": {"exit_token": "done"}})
    trace.append("pipeline.end", data={"status": "ok"})
    assert summarize(path)["approved"] is False
    Trace(path, "run-1").append("approve", data={"action": "would open PR"})
    assert summarize(path)["approved"] is True


def test_write_failures_raise(tmp_path):
    blocker = tmp_path / "not-a-dir"
    blocker.write_text("x", encoding="utf-8")
    with pytest.raises(OSError):
        Trace(blocker / "trace.jsonl", "run-1")


def test_missing_trace_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        read_trace(tmp_path / "nope.jsonl")