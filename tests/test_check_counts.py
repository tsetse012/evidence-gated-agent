"""The project's own gate must not be a false green either.

Review N7: 148 of 149 tests xfailed, and a docker report where the required
tests never ran, both used to read as CHECK PASSED — xfailed tests were counted
as executed and a skipped testcase still counted as a required node id.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from ega import sandbox

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
            "docker_skip": (
                f'<skipped type="pytest.skip" message="{sandbox.DOCKER_SKIP_REASON}"/>'
            ),
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
    docker: bool = True,
    allow_no_docker: bool = False,
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
    if docker and docker_report is None:
        docker_report = junit(("test_docker_ok", "passed"))
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
    if allow_no_docker:
        monkeypatch.setenv("EGA_ALLOW_NO_DOCKER", "1")
    else:
        monkeypatch.delenv("EGA_ALLOW_NO_DOCKER", raising=False)
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


# --- C9: a run without Docker is not a pass --------------------------------


def test_without_docker_the_gate_fails_by_default(monkeypatch, tmp_path, capsys):
    """Review C9 repro: 28 sandbox tests never ran, and the gate still said PASSED."""
    status = run_check(
        monkeypatch,
        tmp_path,
        report=junit(("test_a", "passed"), ("test_sandbox", "docker_skip")),
        docker=False,
    )

    output = capsys.readouterr().out
    assert status == 1, output
    assert "CHECK FAILED" in output
    assert "CHECK PASSED" not in output


def test_without_docker_the_degraded_opt_in_exits_three(monkeypatch, tmp_path, capsys):
    status = run_check(
        monkeypatch,
        tmp_path,
        report=junit(("test_a", "passed"), ("test_sandbox", "docker_skip")),
        docker=False,
        allow_no_docker=True,
    )

    output = capsys.readouterr().out
    assert status == 3, output
    assert "DEGRADED" in output
    assert "CHECK PASSED" not in output


def test_only_the_docker_unavailable_reason_is_tolerated(monkeypatch, tmp_path, capsys):
    """A skip for any other reason proves nothing, even in degraded mode."""
    status = run_check(
        monkeypatch,
        tmp_path,
        report=junit(("test_a", "passed"), ("test_other", "skipped")),
        docker=False,
        allow_no_docker=True,
    )

    output = capsys.readouterr().out
    assert status == 1, output
    assert "did not carry the docker-unavailable reason" in output


def test_a_required_xfail_node_does_not_pass(monkeypatch, tmp_path, capsys):
    """Review R3: an xfailed testcase still appears in junit, but it did not pass."""
    status = run_check(
        monkeypatch,
        tmp_path,
        report=junit(("test_a", "passed"), ("test_required", "xfail")),
        expected="[full]\ntests/test_app.py::test_a\ntests/test_app.py::test_required\n",
    )

    output = capsys.readouterr().out
    assert status == 1, output
    assert "required test did not pass: tests/test_app.py::test_required" in output


def test_a_pytest8_strict_xpass_is_counted(monkeypatch, tmp_path, capsys):
    """pytest 8.3.4 writes a strict xpass as an untyped failure, not `type=pytest.xpass`."""
    report = (
        '<?xml version="1.0" encoding="utf-8"?><testsuites><testsuite name="pytest">'
        '<testcase classname="tests.test_app" name="test_a" time="0.001"/>'
        '<testcase classname="tests.test_app" name="test_b" time="0.001">'
        '<failure message="[XPASS(strict)] known bug">x</failure></testcase>'
        "</testsuite></testsuites>"
    )
    status = run_check(monkeypatch, tmp_path, report=report)

    output = capsys.readouterr().out
    assert status == 1, output
    assert "xpassed" in output


def test_the_suite_forces_strict_xfail_so_a_non_strict_xpass_cannot_pass():
    """Review R3: junit records a non-strict xpass as a plain pass, so the setting
    that turns it into a failure must stay on."""
    text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")

    assert "xfail_strict = true" in text