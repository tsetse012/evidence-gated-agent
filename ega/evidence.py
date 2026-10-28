"""False-green detectors.

Deterministic code only: junit XML + raw stdout + exit code in, findings out.
Every detector is a ``Finding`` with a stable ``code`` so the UI, the trace and
the tests can all point at the same thing.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Sequence

CRITICAL = "critical"
HIGH = "high"
MEDIUM = "medium"
WARNING = "warning"

COUNT_KEYS = ("collected", "passed", "failed", "errors", "skipped", "xfailed", "xpassed")

# pytest's final summary line, e.g. "2 failed, 4 passed in 0.05s". The same
# line is printed with heavy decoration at normal verbosity
# ("========== 2 failed, 4 passed in 0.05s =========="), possibly wrapped in
# ANSI colour codes, so both are normalised before parsing.
_SUMMARY_TAIL = re.compile(r"\bin \d+\.\d+s\b")
_ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
_SUMMARY_PAIR = re.compile(
    r"(\d+) (passed|failed|errors?|skipped|xfailed|xpassed|deselected)"
)
_SUMMARY_KEY = {
    "passed": "passed",
    "failed": "failed",
    "error": "errors",
    "errors": "errors",
    "skipped": "skipped",
    "xfailed": "xfailed",
    "xpassed": "xpassed",
    "deselected": "deselected",
}
# "6 tests collected in 0.05s" / "no tests collected in 0.01s"
_COLLECTED_LINE = re.compile(r"^(?:(\d+)|no)\s+tests?\s+collected\b", re.IGNORECASE)


@dataclass(frozen=True)
class Finding:
    code: str
    severity: str
    message: str
    evidence: str

    def as_dict(self) -> dict:
        return {
            "code": self.code,
            "severity": self.severity,
            "message": self.message,
            "evidence": self.evidence,
        }


@dataclass
class EvidenceReport:
    counts: dict[str, int]
    findings: list[Finding] = field(default_factory=list)

    def codes(self) -> list[str]:
        return [f.code for f in self.findings]

    def as_dict(self) -> dict:
        return {
            "counts": dict(self.counts),
            "findings": [f.as_dict() for f in self.findings],
        }


def empty_counts() -> dict[str, int]:
    return {key: 0 for key in COUNT_KEYS}


def _is_strict_xpass(failure: ET.Element) -> bool:
    """Whether a ``<failure>`` is pytest's strict-xpass marker.

    pytest 8.x writes a strict xpass as a plain failure whose message starts
    with ``[XPASS(strict)]`` and sets no ``type``; older/other releases set
    ``type="pytest.xpass"``. Both shapes are recognised so the count never
    depends on which one the image happens to produce.
    """
    if (failure.get("type") or "") == "pytest.xpass":
        return True
    return (failure.get("message") or "").startswith("[XPASS")


def node_id_for_case(classname: str, name: str) -> str:
    """Rebuild pytest's node id from a junit ``testcase``.

    junit has no node-id column: pytest writes the dotted module as
    ``classname`` and the test name (with any ``[param]``) as ``name``.
    ``tests.test_invoice`` / ``test_x`` rebuilds to
    ``tests/test_invoice.py::test_x``; a doctest's ``invoice.core`` /
    ``invoice.core._money`` rebuilds to ``invoice/core.py::invoice.core._money``,
    which is the node id pytest itself prints. The verifier's baseline
    comparison and the project's own gate therefore share this one function —
    the same lesson (counting alone cannot tell a full run from a filtered one)
    applies to both.
    """
    if not classname or not name:
        return ""
    return f"{classname.replace('.', '/')}.py::{name}"


def _case_outcome(case: ET.Element) -> str:
    """One of ``passed/failed/error/skipped/xfailed/xpassed`` for a testcase."""
    failure = case.find("failure")
    error = case.find("error")
    skipped = case.find("skipped")
    if failure is not None:
        return "xpassed" if _is_strict_xpass(failure) else "failed"
    if error is not None:
        return "error"
    if skipped is not None:
        return "xfailed" if (skipped.get("type") or "") == "pytest.xfail" else "skipped"
    return "passed"


def parse_junit(xml_text: str) -> dict[str, int]:
    """Count testcases in a pytest junit report.

    ``skipped`` excludes xfail markers (counted as ``xfailed``); ``xpassed`` is
    counted in addition to ``failed`` because a strict xpass is a failure.
    """
    counts = empty_counts()
    root = ET.fromstring(xml_text)
    for case in root.iter("testcase"):
        counts["collected"] += 1
        outcome = _case_outcome(case)
        if outcome == "xpassed":
            counts["failed"] += 1
            counts["xpassed"] += 1
        elif outcome == "error":
            counts["errors"] += 1
        elif outcome == "failed":
            counts["failed"] += 1
        elif outcome == "skipped":
            counts["skipped"] += 1
        elif outcome == "xfailed":
            counts["xfailed"] += 1
    counts["passed"] = (
        counts["collected"]
        - counts["failed"]
        - counts["errors"]
        - counts["skipped"]
        - counts["xfailed"]
    )
    return counts


def node_outcomes(junit_path: Path | None) -> dict[str, str]:
    """``node id -> outcome`` for every testcase in a junit report.

    An unreadable or missing report is an empty mapping (never an exception):
    the caller decides what an unreadable baseline means, and that is never
    "no changes".
    """
    if junit_path is None:
        return {}
    path = Path(junit_path)
    if not path.is_file():
        return {}
    try:
        root = ET.parse(path).getroot()
    except (ET.ParseError, OSError):
        return {}
    outcomes: dict[str, str] = {}
    for case in root.iter("testcase"):
        node = node_id_for_case(case.get("classname") or "", case.get("name") or "")
        if node:
            outcomes[node] = _case_outcome(case)
    return outcomes


def node_ids(junit_path: Path | None, *, passed_only: bool = True) -> set[str]:
    """Every node id in a report, by default only the ones that **passed**.

    With ``passed_only`` a testcase carrying a failure/error/skipped child does
    not count: it ran, but it did not pass. Collection errors carry an empty
    classname and are not test node ids.
    """
    return {
        node
        for node, outcome in node_outcomes(junit_path).items()
        if outcome == "passed" or not passed_only
    }


def skipped_messages(junit_path: Path | None) -> list[str]:
    """Messages of plain skips in a report — an xfail is not a skip.

    Used by the project's gate to tolerate only the skips whose reason is the
    named "Docker is unavailable" string, and nothing else.
    """
    if junit_path is None:
        return []
    path = Path(junit_path)
    if not path.is_file():
        return []
    try:
        root = ET.parse(path).getroot()
    except (ET.ParseError, OSError):
        return []
    messages: list[str] = []
    for case in root.iter("testcase"):
        skipped = case.find("skipped")
        if skipped is None or (skipped.get("type") or "") == "pytest.xfail":
            continue
        messages.append(skipped.get("message") or "")
    return messages


def _normalise(line: str) -> str:
    """Strip ANSI colours and pytest's ``=====`` decoration from a line."""
    return _ANSI.sub("", line).strip("= \t").strip()


def parse_stdout_summary(stdout: str) -> dict[str, int]:
    """Return the counts printed on pytest's last summary line.

    Handles the plain ``-q`` form and the decorated normal-verbosity form
    (``===== 2 failed, 4 passed in 0.05s =====``) and ANSI colour codes. Empty
    dict when no summary line can be found (e.g. the process died).
    """
    summary_line = ""
    for line in stdout.splitlines():
        clean = _normalise(line)
        if _SUMMARY_TAIL.search(clean):
            summary_line = clean
    if not summary_line:
        return {}
    found: dict[str, int] = {}
    for raw_count, raw_key in _SUMMARY_PAIR.findall(summary_line):
        key = _SUMMARY_KEY[raw_key]
        found[key] = int(raw_count)
    return found


def parse_collected_count(stdout: str) -> int | None:
    """How many tests a ``pytest --collect-only -q`` run collected.

    ``None`` means "could not tell" — which is different from ``0``
    ("no tests collected") and must never be treated as a green baseline.
    """
    lines = [_normalise(line) for line in stdout.splitlines()]
    for line in reversed(lines):
        match = _COLLECTED_LINE.match(line)
        if match:
            return int(match.group(1)) if match.group(1) is not None else 0
    node_ids = [line for line in stdout.splitlines() if "::" in line]
    if node_ids:
        return len(node_ids)
    return None


def analyze(
    *,
    stdout: str,
    stderr: str,
    exit_code: int,
    junit_path: Path | None,
    expected_min_tests: int | None = None,
    skip_ratio_threshold: float = 0.2,
    artifacts: Sequence[Path] = (),
    run_started: float | None = None,
    oom_killed: bool = False,
) -> EvidenceReport:
    """Run every detector over one verifier run."""
    findings: list[Finding] = []
    counts = empty_counts()

    junit_text = ""
    if junit_path is not None:
        path = Path(junit_path)
        if path.is_file():
            junit_text = path.read_text(encoding="utf-8", errors="replace").strip()
    if junit_text:
        try:
            counts = parse_junit(junit_text)
        except ET.ParseError as exc:
            findings.append(
                Finding(
                    "JUNIT_MISSING",
                    CRITICAL,
                    "junit file exists but is not valid XML; nothing can be proven",
                    f"{junit_path}: {exc}",
                )
            )
            counts = empty_counts()
    else:
        # Missing/empty junit is only reportable as its own finding when the
        # run claims success; a non-zero exit already fails the claim and
        # ZERO_COLLECTED fires below regardless.
        if exit_code == 0:
            findings.append(
                Finding(
                    "JUNIT_MISSING",
                    CRITICAL,
                    "exit code 0 but no junit report was produced",
                    f"junit_path={junit_path} exists={Path(junit_path).is_file() if junit_path else False} "
                    f"exit_code={exit_code}",
                )
            )

    # ZERO_COLLECTED — an empty run proves nothing, whatever the exit code says.
    if counts["collected"] == 0:
        findings.append(
            Finding(
                "ZERO_COLLECTED",
                CRITICAL,
                "0 tests were collected; a run that proves nothing must not read as green",
                f"collected=0 exit_code={exit_code} "
                f"stdout_tail={(stdout.strip().splitlines() or ['<empty>'])[-1]!r}",
            )
        )

    # SKIP_RATIO — skips counted as passes.
    if counts["collected"] > 0:
        skipped_ratio = counts["skipped"] / counts["collected"]
        if skipped_ratio > skip_ratio_threshold:
            findings.append(
                Finding(
                    "SKIP_RATIO",
                    HIGH,
                    f"{counts['skipped']}/{counts['collected']} tests were skipped "
                    f"({skipped_ratio:.0%} > {skip_ratio_threshold:.0%}); skipped tests are not proof",
                    f"collected={counts['collected']} skipped={counts['skipped']} "
                    f"passed={counts['passed']} threshold={skip_ratio_threshold}",
                )
            )

    # BELOW_EXPECTED — fewer tests than the fixture is known to have.
    if expected_min_tests is not None and counts["collected"] < expected_min_tests:
        findings.append(
            Finding(
                "BELOW_EXPECTED",
                HIGH,
                f"collected {counts['collected']} tests but at least {expected_min_tests} were expected; "
                "tests may have been deleted or hidden",
                f"collected={counts['collected']} expected_min_tests={expected_min_tests}",
            )
        )

    # EXIT_MASKED — the command was weakened (`pytest || true`, `; exit 0`).
    if exit_code == 0 and (counts["failed"] or counts["errors"]):
        findings.append(
            Finding(
                "EXIT_MASKED",
                CRITICAL,
                "exit code 0 while junit shows failures/errors; the test command was masked",
                f"exit_code=0 failed={counts['failed']} errors={counts['errors']} "
                f"stderr_tail={(stderr.strip().splitlines() or ['<empty>'])[-1]!r}",
            )
        )

    # COUNT_MISMATCH — the printed summary disagrees with the report.
    #
    # junit has no row for a *non-strict* xpass: pytest writes a plain,
    # childless <testcase>, which parse_junit can only count as passed. So
    # `passed` and `xpassed` are compared as a pair against junit's `passed`;
    # comparing them one by one made a known-bug-fixing patch whose fixture
    # already carried an xfail marker look like a forged report.
    summary = parse_stdout_summary(stdout)
    stdout_executed = summary.get("passed", 0) + summary.get("xpassed", 0)
    for key, printed in summary.items():
        if counts["collected"] == 0:
            break
        if key in ("passed", "xpassed"):
            if printed != counts[key] and stdout_executed != counts["passed"]:
                findings.append(
                    Finding(
                        "COUNT_MISMATCH",
                        HIGH,
                        f"stdout says {printed} {key} but junit reports {counts[key]}",
                        f"key={key} stdout={printed} junit={counts[key]} "
                        f"stdout_passed_plus_xpassed={stdout_executed} summary={summary}",
                    )
                )
        elif key in counts and printed != counts[key]:
            findings.append(
                Finding(
                    "COUNT_MISMATCH",
                    HIGH,
                    f"stdout says {printed} {key} but junit reports {counts[key]}",
                    f"key={key} stdout={printed} junit={counts[key]} summary={summary}",
                )
            )

    # ARTIFACT_EMPTY / ARTIFACT_STALE — declared output files.
    for artifact in artifacts:
        path = Path(artifact)
        if not path.is_file():
            findings.append(
                Finding(
                    "ARTIFACT_EMPTY",
                    MEDIUM,
                    f"declared artifact is missing: {path.name}",
                    f"{path} does not exist",
                )
            )
            continue
        stat = path.stat()
        if stat.st_size == 0:
            findings.append(
                Finding(
                    "ARTIFACT_EMPTY",
                    MEDIUM,
                    f"declared artifact is empty: {path.name}",
                    f"{path} size=0",
                )
            )
        elif run_started is not None and stat.st_mtime < run_started:
            findings.append(
                Finding(
                    "ARTIFACT_STALE",
                    MEDIUM,
                    f"declared artifact was not rewritten by this run: {path.name}",
                    f"{path} mtime={stat.st_mtime:.0f} < run_start={run_started:.0f}",
                )
            )

    # TESTS_FAILED — the run's actual result, independent of how the command
    # exited or what the command was allowed to mask.
    if counts["failed"] or counts["errors"]:
        findings.append(
            Finding(
                "TESTS_FAILED",
                CRITICAL,
                f"{counts['failed']} test(s) failed and {counts['errors']} errored; "
                "failing tests are never proof",
                f"failed={counts['failed']} errors={counts['errors']} "
                f"exit_code={exit_code}",
            )
        )

    # NONZERO_EXIT — the run did not complete successfully, whatever the report
    # says. A green report attached to a failed process proves nothing.
    if exit_code != 0:
        findings.append(
            Finding(
                "NONZERO_EXIT",
                CRITICAL,
                f"the test process exited {exit_code}; a run that did not finish "
                "successfully cannot prove the claim",
                f"exit_code={exit_code} junit_present={bool(junit_text)} "
                f"stderr_tail={(stderr.strip().splitlines() or ['<empty>'])[-1]!r}",
            )
        )

    # OOM_KILLED — the process was killed by the kernel, so the suite never
    # reached its own conclusion.
    if oom_killed:
        findings.append(
            Finding(
                "OOM_KILLED",
                CRITICAL,
                "the test process was OOM-killed; the run did not complete",
                f"oom_killed=True exit_code={exit_code} "
                f"stdout_tail={(stdout.strip().splitlines() or ['<empty>'])[-1]!r}",
            )
        )

    # DESELECTED — tests were removed from the run without being marked in the
    # source, which also makes the count comparison meaningless.
    deselected = summary.get("deselected", 0)
    if deselected > 0:
        findings.append(
            Finding(
                "DESELECTED",
                MEDIUM,
                f"{deselected} test(s) were deselected; the run does not cover the suite",
                f"deselected={deselected} summary={summary}",
            )
        )

    return EvidenceReport(counts=counts, findings=findings)


def verdict_token(
    *,
    counts: dict[str, int],
    findings: Iterable[Finding],
    sandbox_ok: bool = True,
) -> str:
    """Map evidence to the closed set of first-line tokens.

    done                -> no findings, passed > 0, failed == 0
    verification-failed -> any critical/high finding, or failed/errors > 0
    partial             -> only minor (medium/warning) findings survived
    blocked             -> the sandbox could not run the tests at all
    """
    findings = list(findings)
    if not sandbox_ok:
        return "blocked"
    if any(f.severity in (CRITICAL, HIGH) for f in findings):
        return "verification-failed"
    if counts["failed"] or counts["errors"]:
        return "verification-failed"
    if findings:
        return "partial"
    if counts["passed"] > 0 and counts["failed"] == 0:
        return "done"
    return "verification-failed"