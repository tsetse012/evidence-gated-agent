#!/usr/bin/env python3
"""Post-pytest gate: our own suite must not be a false green.

Fails when: pytest itself failed, nothing was collected, any test failed or
errored, any test was skipped/xfailed/xpassed (skips are tolerated only when
Docker is unavailable, where they are the named-reason docker skips), a
required node id from ``--expected-tests`` did not **pass**, or docker-marked
tests were skipped while Docker is available.

The node-id check is what closes the "an outside filter shrank the run" hole:
counting alone cannot tell a full run from a selected one. It counts only
testcases that passed — a required test that merely *ran* (skipped, xfailed)
proves nothing, which is exactly how 148/149 xfails used to read as green.
"""

from __future__ import annotations

import argparse
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ega.evidence import parse_junit  # noqa: E402
from ega.sandbox import docker_available  # noqa: E402

FULL = "full"
DOCKER = "docker"


def counts_from(path: Path) -> dict[str, int] | None:
    if not path.is_file():
        return None
    return parse_junit(path.read_text(encoding="utf-8"))


def node_ids(path: Path | None, *, passed_only: bool = True) -> set[str]:
    """``tests/mod.py::test_name`` for every testcase pytest actually wrote.

    junit has no node id column, but pytest fills ``classname`` with the dotted
    module and ``name`` with the function (plus ``[param]``), which rebuilds it.
    With ``passed_only`` a testcase carrying a failure/error/skipped child does
    not count: it ran, but it did not pass. Collection errors carry an empty
    classname and are not test node ids.
    """
    if path is None or not path.is_file():
        return set()
    found: set[str] = set()
    for case in ET.parse(path).getroot().iter("testcase"):
        classname = case.get("classname") or ""
        name = case.get("name") or ""
        if not classname or not name:
            continue
        if passed_only and (
            case.find("failure") is not None
            or case.find("error") is not None
            or case.find("skipped") is not None
        ):
            continue
        found.add(f"{classname.replace('.', '/')}.py::{name}")
    return found


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
            if docker_is_available:
                problems.append(
                    f"{counts['skipped']} test(s) skipped; a skipped test proves nothing"
                )
            else:
                print(
                    f"note: {counts['skipped']} skipped test(s) tolerated because Docker is "
                    "unavailable (named-reason docker skips)"
                )

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
        print("docker-marked suite: docker is NOT available; skipped with a named reason")
        if expected is not None and expected.get(DOCKER):
            print(
                f"required node ids [docker]: {len(expected[DOCKER])} NOT checked "
                "(docker unavailable)"
            )

    if problems:
        print("\nCHECK FAILED:")
        for problem in problems:
            print(f"  - {problem}")
        return 1
    print("\nCHECK PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())