"""The independent verifier pipeline.

The verifier trusts nothing the author controls. Concretely:

* the pytest command is **fixed here**; whatever the snapshot declares in
  ``ega.toml`` is recorded but never executed (``AUTHOR_COMMAND_IGNORED`` when
  the declared command differs from the pristine fixture's);
* the junit report goes to ``/ega-out`` — a second, empty host directory
  created for this run only, mounted only into the verifier container, under a
  random nonce name — so a pre-planted ``.ega/junit.xml`` is never read. Any
  ``.ega/`` inside the snapshot is deleted before the run, and the report must
  have been written after the run started (``JUNIT_STALE``);
* the expected test count comes from the **pristine** fixture, collected in its
  own fresh sandbox (``BELOW_BASELINE``);
* the test harness itself is compared against the pristine fixture
  (``TEST_HARNESS_CHANGED``, ``XFAIL_ADDED``), and pytest's own deselection
  count is reported (``DESELECTED``);
* declared artifacts must resolve inside the result workspace
  (``ARTIFACT_ESCAPE``), and nothing that escaped the workspace is ever read
  on the host.
"""

from __future__ import annotations

import difflib
import itertools
import re
import shutil
import tempfile
import time
import tomllib
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Sequence

from . import sandbox
from .evidence import (
    CRITICAL,
    HIGH,
    MEDIUM,
    EvidenceReport,
    Finding,
    analyze,
    parse_collected_count,
    verdict_token,
)
from .sandbox import Limits, SandboxResult

CONFIG_FILE = "ega.toml"
# What the author's own sandbox is told to run when it declares nothing. The
# verifier intentionally runs neither this nor a declared variant.
DEFAULT_TEST_COMMAND = "python -m pytest -q --junitxml=/work/.ega/junit.xml"
# The verifier's own command: no shell, no cache, and a junit outside /work.
VERIFIER_JUNIT_DIR = sandbox.OUT_MOUNT
HARNESS_FILE_NAMES = frozenset({"pytest.ini", "setup.cfg", "tox.ini", "pyproject.toml"})
_XFAIL_MARKER = re.compile(r"(?:mark\.xfail|pytest\.xfail)\s*\(")
_SKIP_DIRS = frozenset({".ega", ".pytest_cache", "__pycache__", ".git", "patches"})


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
    baseline_collected: int | None = None
    harness_changes: list[str] = field(default_factory=list)

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
            "baseline_collected": self.baseline_collected,
            "harness_changes": list(self.harness_changes),
            "sandbox": self.sandbox.as_dict(),
        }


@dataclass(frozen=True)
class ProjectConfig:
    """What the snapshot declares about how to test itself.

    Recorded for the audit trail, never executed by the verifier: the author
    controls this file, so it can only describe what the author *wanted* run.
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


def verifier_command(junit_name: str) -> list[str]:
    """The one command the verifier runs. Nothing from the snapshot feeds it."""
    return [
        "python",
        "-m",
        "pytest",
        "-q",
        "-p",
        "no:cacheprovider",
        f"--junitxml={VERIFIER_JUNIT_DIR}/{junit_name}",
    ]


def _describe(result: SandboxResult) -> str:
    if result.error:
        return f"sandbox error: {result.error}"
    if result.timed_out:
        return f"timed out after {result.duration_s:.1f}s"
    tail = (result.stderr or result.stdout).strip().splitlines()
    return tail[-1] if tail else "no output"


# --- pristine baseline ------------------------------------------------------


def collect_baseline(
    baseline_dir: Path,
    limits: Limits | None = None,
    run_id: str | None = None,
) -> tuple[int | None, Finding | None]:
    """Count the pristine fixture's tests in a sandbox of its own.

    ``patches/`` and ``expectation.json`` are authoring metadata, not part of
    the repo under test, so they are left out of the staging copy.
    """
    baseline_dir = Path(baseline_dir)
    scratch = Path(tempfile.mkdtemp(prefix="ega-baseline-"))
    try:
        src = scratch / "src"
        shutil.copytree(
            baseline_dir,
            src,
            symlinks=True,
            ignore=shutil.ignore_patterns(
                "patches", "expectation.json", "__pycache__", ".pytest_cache", ".ega"
            ),
        )
        result = sandbox.run(
            ["python", "-m", "pytest", "-q", "-p", "no:cacheprovider", "--collect-only"],
            src,
            limits or Limits(),
            run_id=f"{run_id}-baseline" if run_id else None,
        )
        shutil.rmtree(result.workdir_after, ignore_errors=True)
        if result.error or result.timed_out:
            return None, Finding(
                "BASELINE_UNAVAILABLE",
                MEDIUM,
                "the pristine fixture could not be collected, so BELOW_BASELINE is unproven",
                f"{_describe(result)} exit_code={result.exit_code}",
            )
        collected = parse_collected_count(result.stdout)
        if collected is None:
            return None, Finding(
                "BASELINE_UNAVAILABLE",
                MEDIUM,
                "the pristine fixture's collection count could not be read",
                f"stdout_tail={(result.stdout.strip().splitlines() or ['<empty>'])[-1]!r}",
            )
        return collected, None
    finally:
        shutil.rmtree(scratch, ignore_errors=True)


# --- test harness comparison ------------------------------------------------


def _harness_paths(root: Path) -> dict[str, Path]:
    """Every file pytest's harness depends on, keyed by relative posix path."""
    found: dict[str, Path] = {}
    root = Path(root)
    for path in root.rglob("*"):
        if not path.is_file() and not path.is_symlink():
            continue
        rel = path.relative_to(root)
        if any(part in _SKIP_DIRS for part in rel.parts):
            continue
        if rel.name == "expectation.json":
            continue
        if rel.parts[0] == "tests" or rel.name == "conftest.py" or rel.name in HARNESS_FILE_NAMES:
            found[rel.as_posix()] = path
    return found


def _pyproject_pytest_section(path: Path | None) -> dict:
    if path is None or not path.is_file():
        return {}
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError):
        return {"__unparsable__": True}
    tool = data.get("tool")
    if not isinstance(tool, dict):
        return {}
    section = tool.get("pytest")
    return section if isinstance(section, dict) else {}


def _read_bytes(path: Path | None) -> bytes | None:
    if path is None or not path.is_file():
        return None
    try:
        return path.read_bytes()
    except OSError:
        return None


def _diff_head(left: Path | None, right: Path | None, rel: str, limit: int = 40) -> str:
    def lines(path: Path | None) -> list[str]:
        if path is None or not path.is_file():
            return []
        try:
            return path.read_text(encoding="utf-8", errors="replace").splitlines(keepends=True)
        except OSError:
            return []

    diff = difflib.unified_diff(
        lines(left), lines(right), fromfile=f"pristine/{rel}", tofile=f"snapshot/{rel}", n=2
    )
    return "".join(itertools.islice(diff, limit))


def harness_changes(baseline_dir: Path, snapshot_dir: Path) -> list[tuple[str, str]]:
    """``(relative path, diff head)`` for every harness file that differs.

    ``pyproject.toml`` only counts through its ``[tool.pytest*]`` sections:
    changing the packaging metadata is not tampering with the tests.
    """
    base = _harness_paths(baseline_dir)
    snap = _harness_paths(snapshot_dir)
    changes: list[tuple[str, str]] = []
    for rel in sorted(set(base) | set(snap)):
        left, right = base.get(rel), snap.get(rel)
        if rel.rsplit("/", 1)[-1] == "pyproject.toml":
            if _pyproject_pytest_section(left) != _pyproject_pytest_section(right):
                changes.append((rel, _diff_head(left, right, rel)))
        elif _read_bytes(left) != _read_bytes(right):
            changes.append((rel, _diff_head(left, right, rel)))
    return changes


def count_xfail_markers(root: Path) -> int:
    """How many ``xfail`` markers the test harness carries, statically."""
    total = 0
    for path in _harness_paths(root).values():
        if path.suffix != ".py" or path.is_symlink():
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        total += len(_XFAIL_MARKER.findall(text))
    return total


# --- declared artifacts -----------------------------------------------------


def artifact_paths(
    workdir: Path, declared: Sequence[str]
) -> tuple[list[Path], list[Finding]]:
    """Resolve declared artifacts, refusing anything outside the workspace.

    ``Path(base) / "/etc/passwd"`` silently drops ``base``, and ``..`` climbs
    out of it; both would make the verifier inspect host files. Symlinks are
    resolved for the same reason.
    """
    base = Path(workdir).resolve()
    paths: list[Path] = []
    findings: list[Finding] = []
    for rel in declared:
        raw = Path(rel)
        candidate = (base / raw).resolve()
        if raw.is_absolute() or ".." in raw.parts or not (
            candidate == base or base in candidate.parents
        ):
            findings.append(
                Finding(
                    "ARTIFACT_ESCAPE",
                    HIGH,
                    f"declared artifact leaves the workspace and was not evaluated: {rel}",
                    f"artifact={rel!r} resolved={candidate} workspace={base}",
                )
            )
            continue
        paths.append(candidate)
    return paths, findings


# --- the pipeline -----------------------------------------------------------


def verify(
    snapshot_dir: Path,
    claim: Claim,
    *,
    baseline_dir: Path | None = None,
    expected_min_tests: int | None = None,
    limits: Limits | None = None,
    run_id: str | None = None,
    skip_ratio_threshold: float = 0.2,
    junit_keep_path: Path | None = None,
    run_baseline: bool = True,
) -> Verdict:
    """Re-run the snapshot's tests in a brand-new sandbox and judge the claim."""
    snapshot_dir = Path(snapshot_dir).resolve()
    if not snapshot_dir.is_dir():
        raise FileNotFoundError(f"snapshot_dir does not exist: {snapshot_dir}")

    config = load_project_config(snapshot_dir)
    baseline_dir = Path(baseline_dir).resolve() if baseline_dir is not None else None
    config_baseline = (
        load_project_config(baseline_dir) if baseline_dir is not None else ProjectConfig()
    )

    verifier_findings: list[Finding] = []

    # The author's own evidence never enters the verifier.
    shutil.rmtree(snapshot_dir / ".ega", ignore_errors=True)

    # The author's command is recorded, never run.
    if config.test_command != config_baseline.test_command:
        verifier_findings.append(
            Finding(
                "AUTHOR_COMMAND_IGNORED",
                MEDIUM,
                "the snapshot declares a different test command; the verifier ran its own fixed command",
                f"declared={config.test_command!r} "
                f"pristine={config_baseline.test_command!r}",
            )
        )

    baseline_collected: int | None = None
    if baseline_dir is not None and run_baseline:
        baseline_collected, baseline_finding = collect_baseline(baseline_dir, limits, run_id)
        if baseline_finding is not None:
            verifier_findings.append(baseline_finding)

    junit_name = f"junit-{uuid.uuid4().hex[:12]}.xml"
    out_root = Path(tempfile.mkdtemp(prefix="ega-out-"))
    workdir: Path | None = None
    kept_junit: Path | None = None
    harness_changed: list[str] = []
    try:
        started = time.time()
        result = sandbox.run(
            verifier_command(junit_name),
            snapshot_dir,
            limits or Limits(),
            run_id=run_id,
            out_dir=out_root,
        )
        workdir = result.workdir_after
        junit_path = out_root / junit_name

        artifacts, artifact_findings = artifact_paths(workdir, config.artifacts)
        verifier_findings.extend(artifact_findings)

        report: EvidenceReport = analyze(
            stdout=result.stdout,
            stderr=result.stderr,
            exit_code=result.exit_code,
            junit_path=junit_path,
            expected_min_tests=expected_min_tests,
            skip_ratio_threshold=skip_ratio_threshold,
            artifacts=artifacts,
            run_started=started,
            oom_killed=result.oom_killed,
        )

        # Freshness: the report must have been produced by this run.
        if junit_path.is_file():
            mtime = junit_path.stat().st_mtime
            if mtime < started:
                verifier_findings.append(
                    Finding(
                        "JUNIT_STALE",
                        CRITICAL,
                        "the junit report predates this run; it was not written by the verifier",
                        f"{junit_path} mtime={mtime:.0f} < run_start={started:.0f}",
                    )
                )

        # The test harness itself must be the one the fixture shipped.
        if baseline_dir is not None:
            changes = harness_changes(baseline_dir, snapshot_dir)
            harness_changed = [rel for rel, _ in changes]
            if changes:
                verifier_findings.append(
                    Finding(
                        "TEST_HARNESS_CHANGED",
                        HIGH,
                        "the test harness differs from the pristine fixture: "
                        + ", ".join(harness_changed),
                        " | ".join(f"{rel}: {diff[:400]}" for rel, diff in changes)[:2000],
                    )
                )
            pristine_xfail = count_xfail_markers(baseline_dir)
            snapshot_xfail = max(count_xfail_markers(snapshot_dir), report.counts["xfailed"])
            if snapshot_xfail > pristine_xfail:
                verifier_findings.append(
                    Finding(
                        "XFAIL_ADDED",
                        MEDIUM,
                        f"xfail markers went from {pristine_xfail} to {snapshot_xfail}; "
                        "an expected failure is not a pass",
                        f"pristine_xfail={pristine_xfail} snapshot_xfail={snapshot_xfail} "
                        f"junit_xfailed={report.counts['xfailed']}",
                    )
                )
            if (
                baseline_collected is not None
                and report.counts["collected"] < baseline_collected
            ):
                verifier_findings.append(
                    Finding(
                        "BELOW_BASELINE",
                        HIGH,
                        f"collected {report.counts['collected']} tests but the pristine "
                        f"fixture collects {baseline_collected}; tests may have been removed",
                        f"collected={report.counts['collected']} "
                        f"baseline={baseline_collected}",
                    )
                )

        # Anything the container left behind that cannot be copied out safely.
        if result.excluded_output:
            verifier_findings.append(
                Finding(
                    "OUTPUT_ESCAPE",
                    HIGH,
                    "the workspace contains entries that must not be copied to the host: "
                    + ", ".join(result.excluded_output),
                    "; ".join(result.excluded_output),
                )
            )
        if result.cleanup_errors:
            verifier_findings.append(
                Finding(
                    "SANDBOX_CLEANUP_FAILED",
                    MEDIUM,
                    "the sandbox could not clean up after itself",
                    "; ".join(result.cleanup_errors),
                )
            )

        findings = list(report.findings) + verifier_findings
        sandbox_ok = result.error is None and not result.timed_out
        token = verdict_token(
            counts=report.counts, findings=findings, sandbox_ok=sandbox_ok
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
        codes = [f.code for f in findings]
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
                f"failed={counts['failed']} errors={counts['errors']} "
                f"skipped={counts['skipped']})"
            )

        if junit_keep_path is not None and junit_path.is_file():
            kept_junit = Path(junit_keep_path)
            kept_junit.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(junit_path, kept_junit)

        return Verdict(
            exit_token=token,
            sentence=sentence,
            claim_vs_observed=claim_vs_observed,
            findings=findings,
            counts=counts,
            isolation=result.isolation,
            duration_s=result.duration_s,
            sandbox=result,
            test_command=" ".join(verifier_command(junit_name)),
            junit_path=kept_junit,
            baseline_collected=baseline_collected,
            harness_changes=harness_changed,
        )
    finally:
        # The verifier owns both temp trees; neither outlives the call.
        if workdir is not None:
            shutil.rmtree(workdir, ignore_errors=True)
        shutil.rmtree(out_root, ignore_errors=True)