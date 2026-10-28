"""The project's own gate must not be a false green either.

Review N7: 148 of 149 tests xfailed, and a docker report where the required
tests never ran, both used to read as CHECK PASSED — xfailed tests were counted
as executed and a skipped testcase still counted as a required node id.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import check_counts  # noqa: E402


def junit(*cases: tuple[str, str]) -> str:
    """A pytest-shaped report; outcome is ``passed``/``xfail``/``skipped``/``failed``."""
    body = []
    for name, outcome in cases:
        child = {
            "passed": "",
            "xfail": '<skipped type="pytest.xfail" message="xfail"/>',
            "skipped": '<skipped type="pytest.skip" message="skip"/>',
            "failed": '<failure message="boom">boom</failure>',
        }[outcome]
        body.append(
            f'<testcase classname="tests.test_app" name="{name}" time="0.001">'
            f"{child}</testcase>"
        )
    return (
        '<?xml version="1.0" encoding="utf-8"?><testsuites><testsuite name="pytest">'
        + "".join(body)
        + "</testsuite></testsuites>"
    )


def run_check(
    monkeypatch,
    tmp_path: Path,
    *,
    report: str,
    docker_report: str | None = None,
    expected: str | None = None,
    pytest_status: int = 0,
    docker: bool = False,
) -> int:
    junit_path = tmp_path / "junit.xml"
    junit_path.write_text(report, encoding="utf-8")
    argv = [
        "check_counts.py",
        "--junit",
        str(junit_path),
        "--pytest-status",
        str(pytest_status),
    ]
    if docker_report is not None:
        docker_path = tmp_path / "docker-junit.xml"
        docker_path.write_text(docker_report, encoding="utf-8")
        argv += ["--docker-junit", str(docker_path)]
    if expected is not None:
        expected_path = tmp_path / "expected.txt"
        expected_path.write_text(expected, encoding="utf-8")
        argv += ["--expected-tests", str(expected_path)]
    monkeypatch.setattr(sys, "argv", argv)
    monkeypatch.setattr(check_counts, "docker_available", lambda: docker)
    return check_counts.main()


def test_a_fully_green_suite_passes(monkeypatch, tmp_path, capsys):
    status = run_check(
        monkeypatch,
        tmp_path,
        report=junit(("test_a", "passed"), ("test_b", "passed")),
        expected="[full]\ntests/test_app.py::test_a\ntests/test_app.py::test_b\n",
    )

    assert status == 0, capsys.readouterr().out
    assert "CHECK PASSED" in capsys.readouterr().out


def test_xfailed_tests_fail_the_gate(monkeypatch, tmp_path, capsys):
    """Review N7 repro: 148 xfailed + 1 passed must not be a green."""
    cases = [("test_ok", "passed")] + [(f"test_x{i}", "xfail") for i in range(148)]
    status = run_check(monkeypatch, tmp_path, report=junit(*cases))

    output = capsys.readouterr().out
    assert status == 1, output
    assert "CHECK FAILED" in output
    assert "148 test(s) xfailed" in output


def test_a_skipped_test_fails_the_gate(monkeypatch, tmp_path, capsys):
    status = run_check(
        monkeypatch,
        tmp_path,
        report=junit(("test_a", "passed"), ("test_b", "skipped")),
        docker_report=junit(("test_a", "passed")),
        docker=True,
    )

    output = capsys.readouterr().out
    assert status == 1, output
    assert "1 test(s) skipped" in output


def test_a_required_node_that_only_ran_skipped_does_not_count(monkeypatch, tmp_path, capsys):
    """A required node id must have *passed*, not merely appeared in the report."""
    status = run_check(
        monkeypatch,
        tmp_path,
        report=junit(("test_a", "passed"), ("test_required", "skipped")),
        expected="[full]\ntests/test_app.py::test_a\ntests/test_app.py::test_required\n",
    )

    output = capsys.readouterr().out
    assert status == 1, output
    assert "required test did not pass: tests/test_app.py::test_required" in output


def test_an_xpassed_test_fails_the_gate(monkeypatch, tmp_path, capsys):
    """junit reports a strict xpass as a failure of type ``pytest.xpass``."""
    report = (
        '<?xml version="1.0" encoding="utf-8"?><testsuites><testsuite name="pytest">'
        '<testcase classname="tests.test_app" name="test_a" time="0.001"/>'
        '<testcase classname="tests.test_app" name="test_b" time="0.001">'
        '<failure type="pytest.xpass" message="xpass">xpass</failure></testcase>'
        "</testsuite></testsuites>"
    )
    status = run_check(monkeypatch, tmp_path, report=report)

    output = capsys.readouterr().out
    assert status == 1, output
    assert "1 test(s) xpassed" in output


def test_a_required_docker_node_missing_from_the_docker_report_fails(monkeypatch, tmp_path, capsys):
    """Review N7 repro: a docker junit whose required tests never ran."""
    status = run_check(
        monkeypatch,
        tmp_path,
        report=junit(("test_a", "passed")),
        docker_report=junit(("test_other", "passed")),
        expected="[full]\ntests/test_app.py::test_a\n[docker]\ntests/test_docker.py::test_real\n",
        docker=True,
    )

    output = capsys.readouterr().out
    assert status == 1, output
    assert "required docker test did not pass: tests/test_docker.py::test_real" in output