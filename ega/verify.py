"""The independent verifier pipeline.

The verifier receives only a snapshot directory and the author's *claim*. It
never reads the author's logs or output directory: a fresh sandbox re-runs the
declared test command and the evidence detectors decide the verdict.
"""

from __future__ import annotations

import time
import tomllib
from dataclasses import dataclass
from pathlib import Path

from . import sandbox
from .evidence import EvidenceReport, Finding, analyze, verdict_token
from .sandbox import Limits, SandboxResult

JUNIT_REL = Path(".ega") / "junit.xml"
DEFAULT_TEST_COMMAND = "python -m pytest -q --junitxml=/work/.ega/junit.xml"
CONFIG_FILE = "ega.toml"


@dataclass(frozen=True)
class Claim:
    """What the author said about its own work."""

    status: str
    tests_claimed_passed: int | None = None
    text: str = ""

    @classmethod
    def from_dict(cls, data: dict) -> "Claim":
        return cls(
            status=str(data.get("status", "")),
            tests_claimed_passed=data.get("tests_claimed_passed"),
            text=str(data.get("text", "")),
        )

    def as_dict(self) -> dict:
        return {
            "status": self.status,
            "tests_claimed_passed": self.tests_claimed_passed,
            "text": self.text,
        }


@dataclass
class Verdict:
    exit_token: str
    sentence: str
    claim_vs_observed: list[dict]
    findings: list[Finding]
    counts: dict[str, int]
    isolation: str
    duration_s: float
    sandbox: SandboxResult
    test_command: str
    junit_path: Path | None

    def first_line(self) -> str:
        return f"exit: {self.exit_token} — {self.sentence}"

    def as_dict(self) -> dict:
        return {
            "exit_token": self.exit_token,
            "sentence": self.sentence,
            "first_line": self.first_line(),
            "claim_vs_observed": self.claim_vs_observed,
            "findings": [f.as_dict() for f in self.findings],
            "counts": dict(self.counts),
            "isolation": self.isolation,
            "duration_s": round(self.duration_s, 3),
            "test_command": self.test_command,
            "junit_path": str(self.junit_path) if self.junit_path else None,
            "sandbox": self.sandbox.as_dict(),
        }


@dataclass(frozen=True)
class ProjectConfig:
    """What the snapshot declares about how to test itself.

    The verifier honours this command, which is exactly why an agent can weaken
    it (`pytest || true`) — and exactly why EXIT_MASKED exists.
    """

    test_command: str = DEFAULT_TEST_COMMAND
    artifacts: tuple[str, ...] = ()


def load_project_config(snapshot_dir: Path) -> ProjectConfig:
    path = Path(snapshot_dir) / CONFIG_FILE
    if not path.is_file():
        return ProjectConfig()
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    command = data.get("test_command") or DEFAULT_TEST_COMMAND
    artifacts = tuple(str(a) for a in data.get("artifacts", ()))
    return ProjectConfig(test_command=str(command), artifacts=artifacts)


def _describe(result: SandboxResult) -> str:
    if result.error:
        return f"sandbox error: {result.error}"
    if result.timed_out:
        return f"timed out after {result.duration_s:.1f}s"
    tail = (result.stderr or result.stdout).strip().splitlines()
    return tail[-1] if tail else "no output"


def verify(
    snapshot_dir: Path,
    claim: Claim,
    *,
    expected_min_tests: int | None = None,
    limits: Limits | None = None,
    run_id: str | None = None,
    skip_ratio_threshold: float = 0.2,
) -> Verdict:
    """Re-run the snapshot's tests in a brand-new sandbox and judge the claim."""
    snapshot_dir = Path(snapshot_dir).resolve()
    if not snapshot_dir.is_dir():
        raise FileNotFoundError(f"snapshot_dir does not exist: {snapshot_dir}")

    config = load_project_config(snapshot_dir)
    started = time.time()
    result = sandbox.run(
        ["sh", "-c", config.test_command],
        snapshot_dir,
        limits or Limits(),
        run_id=run_id,
    )
    junit_path = result.workdir_after / JUNIT_REL
    artifacts = [result.workdir_after / rel for rel in config.artifacts]

    report: EvidenceReport = analyze(
        stdout=result.stdout,
        stderr=result.stderr,
        exit_code=result.exit_code,
        junit_path=junit_path,
        expected_min_tests=expected_min_tests,
        skip_ratio_threshold=skip_ratio_threshold,
        artifacts=artifacts,
        run_started=started,
    )

    sandbox_ok = result.error is None and not result.timed_out
    token = verdict_token(
        counts=report.counts, findings=report.findings, sandbox_ok=sandbox_ok
    )

    claim_vs_observed = [
        {
            "field": "status",
            "claim": claim.status,
            "observed": token,
            "agrees": claim.status.strip().lower() == token,
        }
    ]
    if claim.tests_claimed_passed is not None:
        claim_vs_observed.append(
            {
                "field": "tests_passed",
                "claim": claim.tests_claimed_passed,
                "observed": report.counts["passed"],
                "agrees": claim.tests_claimed_passed == report.counts["passed"],
            }
        )

    counts = report.counts
    codes = [f.code for f in report.findings]
    if not sandbox_ok:
        sentence = f"the sandbox could not run the tests: {_describe(result)}"
    elif token == "done":
        sentence = (
            f"{counts['passed']}/{counts['collected']} tests passed in a fresh sandbox "
            f"({result.isolation}, {result.duration_s:.1f}s); no false-green findings"
        )
    elif token == "partial":
        sentence = (
            f"the claim is not fully proven — {', '.join(codes)} "
            f"({counts['passed']}/{counts['collected']} passed)"
        )
    else:
        sentence = (
            f"the claim does not hold — {', '.join(codes) or 'tests failed'} "
            f"(collected={counts['collected']} passed={counts['passed']} "
            f"failed={counts['failed']} errors={counts['errors']} skipped={counts['skipped']})"
        )

    return Verdict(
        exit_token=token,
        sentence=sentence,
        claim_vs_observed=claim_vs_observed,
        findings=report.findings,
        counts=counts,
        isolation=result.isolation,
        duration_s=result.duration_s,
        sandbox=result,
        test_command=config.test_command,
        junit_path=junit_path if junit_path.is_file() else None,
    )