"""Unit tests for the false-green detectors: handcrafted junit XML, no Docker."""

from __future__ import annotations

import time

from ega.evidence import (
    MEDIUM,
    Finding,
    analyze,
    empty_counts,
    parse_junit,
    parse_stdout_summary,
    verdict_token,
)

XML_HEAD = '<?xml version="1.0" encoding="utf-8"?><testsuites><testsuite name="pytest" '


def junit(*cases: str) -> str:
    """Build a pytest-shaped junit xml. Cases: pass/fail/error/skip/xfail."""
    body = {
        "pass": "<testcase classname=\"t\" name=\"c\"/>",
        "fail": '<testcase classname="t" name="c"><failure message="boom">trace</failure></testcase>',
        "error": '<testcase classname="t" name="c"><error message="err">trace</error></testcase>',
        "skip": '<testcase classname="t" name="c"><skipped type="pytest.skip" message="later"/></testcase>',
        "xfail": '<testcase classname="t" name="c"><skipped type="pytest.xfail" message="known"/></testcase>',
    }
    rendered = "".join(body[c] for c in cases)
    return f"{XML_HEAD}>" + rendered + "</testsuite></testsuites>"


def codes(report) -> list[str]:
    return report.codes()


# --- parsing ---------------------------------------------------------------


def test_parse_junit_counts_each_outcome():
    counts = parse_junit(junit("pass", "pass", "fail", "error", "skip", "xfail"))
    assert counts == {
        "collected": 6,
        "passed": 2,
        "failed": 1,
        "errors": 1,
        "skipped": 1,
        "xfailed": 1,
        "xpassed": 0,
    }


def test_parse_stdout_summary_reads_pytest_line():
    assert parse_stdout_summary("..F\n2 failed, 4 passed, 2 skipped in 0.05s\n") == {
        "failed": 2,
        "passed": 4,
        "skipped": 2,
    }


def test_parse_stdout_summary_without_summary_is_empty():
    assert parse_stdout_summary("collected 0 items\n") == {}


# --- ZERO_COLLECTED --------------------------------------------------------


def test_zero_collected_positive_even_with_exit_zero(tmp_path):
    path = tmp_path / "junit.xml"
    path.write_text(junit(), encoding="utf-8")
    report = analyze(stdout="no tests ran in 0.01s", stderr="", exit_code=0, junit_path=path)
    assert "ZERO_COLLECTED" in codes(report)


def test_zero_collected_negative_with_tests(tmp_path):
    path = tmp_path / "junit.xml"
    path.write_text(junit("pass", "pass"), encoding="utf-8")
    report = analyze(stdout="2 passed in 0.01s", stderr="", exit_code=0, junit_path=path)
    assert "ZERO_COLLECTED" not in codes(report)


# --- SKIP_RATIO ------------------------------------------------------------


def test_skip_ratio_positive_with_junit(tmp_path):
    path = tmp_path / "junit.xml"
    path.write_text(junit("pass", "pass", "pass", "skip", "skip"), encoding="utf-8")
    report = analyze(
        stdout="3 passed, 2 skipped in 0.05s", stderr="", exit_code=0, junit_path=path
    )
    assert "SKIP_RATIO" in codes(report)


def test_skip_ratio_negative_at_threshold(tmp_path):
    path = tmp_path / "junit.xml"
    cases = ["pass"] * 8 + ["skip", "skip"]  # exactly 20%, not above
    path.write_text(junit(*cases), encoding="utf-8")
    report = analyze(
        stdout="8 passed, 2 skipped in 0.05s", stderr="", exit_code=0, junit_path=path
    )
    assert "SKIP_RATIO" not in codes(report)


def test_skip_ratio_threshold_is_configurable(tmp_path):
    path = tmp_path / "junit.xml"
    path.write_text(junit("pass", "pass", "pass", "skip", "skip"), encoding="utf-8")
    report = analyze(
        stdout="3 passed, 2 skipped in 0.05s",
        stderr="",
        exit_code=0,
        junit_path=path,
        skip_ratio_threshold=0.5,
    )
    assert "SKIP_RATIO" not in codes(report)


# --- BELOW_EXPECTED --------------------------------------------------------


def test_below_expected_positive(tmp_path):
    path = tmp_path / "junit.xml"
    path.write_text(junit("pass", "pass"), encoding="utf-8")
    report = analyze(
        stdout="2 passed in 0.01s",
        stderr="",
        exit_code=0,
        junit_path=path,
        expected_min_tests=6,
    )
    assert "BELOW_EXPECTED" in codes(report)


def test_below_expected_negative(tmp_path):
    path = tmp_path / "junit.xml"
    path.write_text(junit("pass", "pass"), encoding="utf-8")
    report = analyze(
        stdout="2 passed in 0.01s",
        stderr="",
        exit_code=0,
        junit_path=path,
        expected_min_tests=2,
    )
    assert "BELOW_EXPECTED" not in codes(report)


# --- EXIT_MASKED -----------------------------------------------------------


def test_exit_masked_positive(tmp_path):
    path = tmp_path / "junit.xml"
    path.write_text(junit("pass", "fail", "fail"), encoding="utf-8")
    report = analyze(
        stdout="1 failed, 2 passed in 0.05s", stderr="", exit_code=0, junit_path=path
    )
    assert "EXIT_MASKED" in codes(report)


def test_exit_masked_negative_when_exit_code_is_honest(tmp_path):
    path = tmp_path / "junit.xml"
    path.write_text(junit("pass", "fail"), encoding="utf-8")
    report = analyze(
        stdout="1 failed, 1 passed in 0.05s", stderr="", exit_code=1, junit_path=path
    )
    assert "EXIT_MASKED" not in codes(report)


# --- JUNIT_MISSING ---------------------------------------------------------


def test_junit_missing_positive():
    report = analyze(stdout="", stderr="", exit_code=0, junit_path=None)
    assert "JUNIT_MISSING" in codes(report)
    assert "ZERO_COLLECTED" in codes(report)


def test_junit_missing_negative(tmp_path):
    path = tmp_path / "junit.xml"
    path.write_text(junit("pass"), encoding="utf-8")
    report = analyze(stdout="1 passed in 0.01s", stderr="", exit_code=0, junit_path=path)
    assert "JUNIT_MISSING" not in codes(report)


def test_junit_missing_not_reported_when_exit_code_is_nonzero():
    report = analyze(stdout="", stderr="boom", exit_code=2, junit_path=None)
    assert "JUNIT_MISSING" not in codes(report)
    assert "ZERO_COLLECTED" in codes(report)


# --- COUNT_MISMATCH --------------------------------------------------------


def test_count_mismatch_positive(tmp_path):
    path = tmp_path / "junit.xml"
    path.write_text(junit("pass", "pass"), encoding="utf-8")
    report = analyze(
        stdout="4 passed in 0.05s", stderr="", exit_code=0, junit_path=path
    )
    assert "COUNT_MISMATCH" in codes(report)


def test_count_mismatch_negative(tmp_path):
    path = tmp_path / "junit.xml"
    path.write_text(junit("pass", "pass"), encoding="utf-8")
    report = analyze(
        stdout="2 passed in 0.05s", stderr="", exit_code=0, junit_path=path
    )
    assert "COUNT_MISMATCH" not in codes(report)


# --- ARTIFACT_EMPTY / ARTIFACT_STALE --------------------------------------


def test_artifact_empty_positive(tmp_path):
    artifact = tmp_path / "report.txt"
    artifact.write_text("", encoding="utf-8")
    report = analyze(
        stdout="", stderr="", exit_code=0, junit_path=None, artifacts=[artifact]
    )
    assert "ARTIFACT_EMPTY" in codes(report)


def test_artifact_missing_is_reported_as_empty(tmp_path):
    report = analyze(
        stdout="", stderr="", exit_code=0, junit_path=None, artifacts=[tmp_path / "nope.txt"]
    )
    assert "ARTIFACT_EMPTY" in codes(report)


def test_artifact_empty_negative(tmp_path):
    artifact = tmp_path / "report.txt"
    artifact.write_text("content", encoding="utf-8")
    report = analyze(
        stdout="",
        stderr="",
        exit_code=0,
        junit_path=None,
        artifacts=[artifact],
        run_started=artifact.stat().st_mtime - 10,
    )
    assert "ARTIFACT_EMPTY" not in codes(report)
    assert "ARTIFACT_STALE" not in codes(report)


def test_artifact_stale_positive(tmp_path):
    artifact = tmp_path / "report.txt"
    artifact.write_text("content", encoding="utf-8")
    report = analyze(
        stdout="",
        stderr="",
        exit_code=0,
        junit_path=None,
        artifacts=[artifact],
        run_started=time.time() + 60,  # run "started" after the file was written
    )
    assert "ARTIFACT_STALE" in codes(report)


def test_artifact_stale_negative():
    report = analyze(stdout="", stderr="", exit_code=0, junit_path=None, artifacts=[])
    assert report.codes() == ["JUNIT_MISSING", "ZERO_COLLECTED"]


# --- verdict mapping -------------------------------------------------------


def test_verdict_done_requires_no_findings_and_passing_tests():
    counts = {**empty_counts(), "collected": 3, "passed": 3}
    assert verdict_token(counts=counts, findings=[], sandbox_ok=True) == "done"


def test_verdict_blocked_when_sandbox_cannot_run():
    counts = empty_counts()
    assert verdict_token(counts=counts, findings=[], sandbox_ok=False) == "blocked"


def test_verdict_verification_failed_on_failed_tests():
    counts = {**empty_counts(), "collected": 2, "passed": 1, "failed": 1}
    assert verdict_token(counts=counts, findings=[], sandbox_ok=True) == "verification-failed"


def test_verdict_partial_when_only_minor_findings():
    minor = Finding("ARTIFACT_EMPTY", MEDIUM, "declared artifact is empty", "size=0")
    counts = {**empty_counts(), "collected": 3, "passed": 3}
    assert verdict_token(counts=counts, findings=[minor]) == "partial"