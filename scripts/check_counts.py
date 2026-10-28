#!/usr/bin/env python3
"""Post-pytest gate: our own suite must not be a false green.

Fails when: pytest itself failed, nothing was collected, any test failed or
errored, any test was skipped/xfailed/xpassed, a required node id from
``--expected-tests`` did not **pass**, or docker-marked tests were skipped while
Docker is available.

Without a Docker daemon the sandbox tests — the verifier end-to-end tests, the
forgery regressions, the leak tests — never run at all, so the default is
``CHECK FAILED``. ``EGA_ALLOW_NO_DOCKER=1`` accepts that as a **degraded** run:
it prints ``DEGRADED`` and exits 3, a distinct code so a caller cannot mistake
it for a pass. In that mode only skips whose junit message is exactly the
conftest's docker reason are tolerated; every other skip still fails.

The node-id check is what closes the "an outside filter shrank the run" hole:
counting alone cannot tell a full run from a selected one. It counts only
testcases that passed — a required test that merely *ran* (skipped, xfailed,
xpassed) proves nothing, which is exactly how 148/149 xfails used to read as
green. A non-strict xpass is written to junit as a plain childless pass, so the
suite sets ``xfail_strict = true``: a passing xfail then becomes a junit
failure and cannot count as a passed node (``tests/test_check_counts.py``
asserts the setting stays on).
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ega.evidence import node_ids, parse_junit, skipped_messages  # noqa: E402
from ega.sandbox import DOCKER_SKIP_REASON, docker_available  # noqa: E402

FULL = "full"
DOCKER = "docker"
# Distinct from 1 (a real failure) so a wrapper can tell "we proved less than we
# claim" from "the suite is broken".
DEGRADED_EXIT = 3


def allow_no_docker() -> bool:
    return os.environ.get("EGA_ALLOW_NO_DOCKER", "") == "1"


def counts_from(path: Path) -> dict[str, int] | None:
    if not path.is_file():
        return None
    return parse_junit(path.read_text(encoding="utf-8"))


def load_expected(path: Path) -> dict[str, list[str]]:
    """Parse ``[full]`` / ``[docker]`` sections of required node ids."""
    sections: dict[str, list[str]] = {FULL: [], DOCKER: []}
    current = FULL
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("[") and line.endswith("]"):
            current = line[1:-1].strip().lower()
            sections.setdefault(current, [])
            continue
        sections.setdefault(current, []).append(line)
    return sections


def show(label: str, counts: dict[str, int] | None) -> None:
    if counts is None:
        print(f"{label}: <no junit report>")
        return
    print(
        f"{label}: collected={counts['collected']} passed={counts['passed']} "
        f"failed={counts['failed']} errors={counts['errors']} "
        f"skipped={counts['skipped']} xfailed={counts['xfailed']}"
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--junit", required=True, type=Path)
    parser.add_argument("--pytest-status", required=True, type=int)
    parser.add_argument("--docker-junit", type=Path)
    parser.add_argument("--expected-tests", type=Path)
    args = parser.parse_args()

    problems: list[str] = []
    degraded: list[str] = []
    counts = counts_from(args.junit)
    docker_is_available = docker_available()
    show("full suite", counts)

    if args.pytest_status != 0:
        problems.append(f"pytest exited {args.pytest_status}")
    if counts is None:
        problems.append("no junit report was written")
    else:
        if counts["collected"] == 0:
            problems.append("collected == 0 (an empty run is not a green)")
        if counts["failed"]:
            problems.append(f"{counts['failed']} test(s) failed")
        if counts["errors"]:
            problems.append(f"{counts['errors']} test(s) errored")
        if counts["passed"] == 0:
            problems.append("no test passed")
        if counts["xfailed"]:
            problems.append(
                f"{counts['xfailed']} test(s) xfailed; an expected failure is not a pass"
            )
        if counts["xpassed"]:
            problems.append(f"{counts['xpassed']} test(s) xpassed; a strict xpass is a failure")
        if counts["skipped"]:
            _judge_skips(args.junit, counts["skipped"], docker_is_available, problems, degraded)

    expected = load_expected(args.expected_tests) if args.expected_tests else None

    if expected is not None:
        actual = node_ids(args.junit)
        missing = [node for node in expected.get(FULL, []) if node not in actual]
        print(
            f"required node ids [full]: {len(expected.get(FULL, []))} required, "
            f"{len(actual)} passed, {len(missing)} missing"
        )
        for node in missing:
            problems.append(f"required test did not pass: {node}")

    if docker_is_available:
        docker_counts = counts_from(args.docker_junit) if args.docker_junit else None
        show("docker-marked suite", docker_counts)
        if docker_counts is None:
            problems.append("docker is available but the docker-marked suite has no report")
        else:
            if docker_counts["collected"] == 0:
                problems.append("docker-marked suite collected nothing")
            if docker_counts["skipped"]:
                problems.append(
                    f"{docker_counts['skipped']} docker-marked test(s) skipped while docker is available"
                )
            if docker_counts["xfailed"] or docker_counts["xpassed"]:
                problems.append("docker-marked suite has xfailed/xpassed tests")
            if docker_counts["failed"] or docker_counts["errors"]:
                problems.append("docker-marked suite failed")
        if expected is not None and args.docker_junit:
            docker_actual = node_ids(args.docker_junit)
            missing = [node for node in expected.get(DOCKER, []) if node not in docker_actual]
            print(
                f"required node ids [docker]: {len(expected.get(DOCKER, []))} required, "
                f"{len(docker_actual)} passed, {len(missing)} missing"
            )
            for node in missing:
                problems.append(f"required docker test did not pass: {node}")
    else:
        message = (
            "docker is not available, so the sandbox tests (verifier end-to-end, "
            "forgeries, leak checks) never ran"
        )
        print(f"docker-marked suite: {message}")
        if expected is not None and expected.get(DOCKER):
            print(
                f"required node ids [docker]: {len(expected[DOCKER])} NOT checked "
                "(docker unavailable)"
            )
        if allow_no_docker():
            degraded.append(message)
        else:
            problems.append(
                f"{message}; start Docker, or set EGA_ALLOW_NO_DOCKER=1 to accept a "
                "degraded gate (exit 3)"
            )

    if problems:
        print("\nCHECK FAILED:")
        for problem in problems:
            print(f"  - {problem}")
        return 1
    if degraded:
        print("\nDEGRADED — this run does not prove what a full one would:")
        for reason in degraded:
            print(f"  - {reason}")
        print("(EGA_ALLOW_NO_DOCKER=1 was set; exit code 3, not a pass)")
        return DEGRADED_EXIT
    print("\nCHECK PASSED")
    return 0


def _judge_skips(
    junit_path: Path,
    skipped: int,
    docker_is_available: bool,
    problems: list[str],
    degraded: list[str],
) -> None:
    """Skip tolerance is by *reason*, not by marker name or by count.

    Only the conftest's docker-unavailable string is ever accepted, and only
    when Docker really is missing. Anything else — a stray ``skip`` marker, a
    skipif that fired — is a test that proved nothing.
    """
    if docker_is_available:
        problems.append(f"{skipped} test(s) skipped while docker is available; a skipped test proves nothing")
        return
    messages = skipped_messages(junit_path)
    tolerated = sum(1 for message in messages if message.strip() == DOCKER_SKIP_REASON)
    unexpected = skipped - tolerated
    if unexpected > 0:
        problems.append(
            f"{unexpected} of {skipped} skipped test(s) did not carry the "
            f"docker-unavailable reason; only that exact reason is tolerated"
        )
    if tolerated > 0:
        note = f"{tolerated} test(s) skipped because Docker is unavailable"
        if allow_no_docker():
            degraded.append(note)
        else:
            problems.append(
                f"{note} and EGA_ALLOW_NO_DOCKER is not set; the gate cannot certify "
                "a run that never executed them"
            )


if __name__ == "__main__":
    raise SystemExit(main())