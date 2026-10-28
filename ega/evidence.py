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

# pytest's final summary line, e.g. "2 failed, 4 passed in 0.05s"
_SUMMARY_TAIL = re.compile(r"\bin \d+\.\d+s\s*$")
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
}


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


def parse_junit(xml_text: str) -> dict[str, int]:
    """Count testcases in a pytest junit report.

    ``skipped`` excludes xfail markers (counted as ``xfailed``); ``xpassed`` is
    counted in addition to ``failed`` because a strict xpass is a failure.
    """
    counts = empty_counts()
    root = ET.fromstring(xml_text)
    for case in root.iter("testcase"):
        counts["collected"] += 1
        failure = case.find("failure")
        error = case.find("error")
        skipped = case.find("skipped")
        if failure is not None:
            counts["failed"] += 1
            if (failure.get("type") or "") == "pytest.xpass":
                counts["xpassed"] += 1
        elif error is not None:
            counts["errors"] += 1
        elif skipped is not None:
            if (skipped.get("type") or "") == "pytest.xfail":
                counts["xfailed"] += 1
            else:
                counts["skipped"] += 1
    counts["passed"] = (
        counts["collected"]
        - counts["failed"]
        - counts["errors"]
        - counts["skipped"]
        - counts["xfailed"]
    )
    return counts


def parse_stdout_summary(stdout: str) -> dict[str, int]:
    """Return the counts printed on pytest's last summary line.

    Empty dict when no summary line can be found (e.g. the process died).
    """
    summary_line = ""
    for line in stdout.splitlines():
        if _SUMMARY_TAIL.search(line):
            summary_line = line
    if not summary_line:
        return {}
    found: dict[str, int] = {}
    for raw_count, raw_key in _SUMMARY_PAIR.findall(summary_line):
        key = _SUMMARY_KEY[raw_key]
        found[key] = int(raw_count)
    return found


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
    summary = parse_stdout_summary(stdout)
    for key, printed in summary.items():
        if counts["collected"] == 0:
            break
        if key in counts and printed != counts[key]:
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