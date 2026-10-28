"""The independent verifier pipeline.

The verifier trusts nothing the author controls. Concretely:

* the pytest command is **fixed here**; whatever the snapshot declares in
  ``ega.toml`` is recorded but never executed (``AUTHOR_COMMAND_IGNORED`` when
  the declared command differs from the pristine fixture's). It runs in
  **isolated mode** (``python -I``) with plugin auto-loading disabled, so a
  ``pytest.py`` / ``sitecustomize.py`` / ``.pth`` / ``*.dist-info`` plugin the
  author dropped into the workspace is never imported at interpreter start;
* the junit report goes to ``/ega-out`` — a second, empty host directory
  created for this run only, mounted only into the verifier container, under a
  random nonce name — so a pre-planted ``.ega/junit.xml`` is never read. Any
  ``.ega/`` inside the snapshot is deleted before the run, and the report must
  have been written after the run started (``JUNIT_STALE``);
* the expected test count comes from the **pristine** fixture, collected in its
  own fresh sandbox, and an unclean baseline run is never trusted
  (``BELOW_BASELINE``, ``BASELINE_UNAVAILABLE``);
* the test harness itself is compared against the pristine fixture: pytest's
  own ``python_files`` patterns anywhere in the tree, any ``conftest.py``,
  the config files, and anything that can shadow or extend pytest itself
  (``TEST_HARNESS_CHANGED``, ``XFAIL_ADDED``), plus pytest's deselection count
  (``DESELECTED``). Nothing but run byproducts is ignored in that comparison;
* **threat model split.** A sloppy author (skips, xfails, masking, weakened
  tests) is *blocked*. An author attacking the verifier — product code that
  forges the report from inside the same process as pytest — cannot be blocked
  by the runner alone, so added product-code lines that can forge a result are
  reported as ``SUSPICIOUS_PRODUCT_CODE``: a signal that keeps the verdict at
  best ``partial``, not a proof of innocence;
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
# pytest's default `python_files` patterns, matched anywhere in the tree: a test
# file outside `tests/` is still part of the harness.
_TEST_FILE_NAME = re.compile(r"^(?:test_.*|.*_test)\.py$")
# Anything that can shadow or extend pytest inside the workspace. None of these
# is loaded any more (`-I` + `PYTEST_DISABLE_PLUGIN_AUTOLOAD=1`), but creating
# one is still a harness change and must never pass unnoticed.
_SHADOW_NAMES = frozenset({"pytest.py", "_pytest.py", "sitecustomize.py", "usercustomize.py"})
_SHADOW_SUFFIXES = (".pth", ".egg-link")
_SHADOW_DIR_SUFFIXES = (".dist-info", ".egg-info")
# Runtime byproducts only. Every other entry — every directory, every file — is
# compared, so there is no per-path ignore list a cheat can hide in.
_RUN_BYPRODUCTS = frozenset({"__pycache__", ".pytest_cache", ".ega", ".git"})
# Authoring metadata that never reaches the author's workspace in the first
# place (the fixture copy drops it); the pristine baseline is staged the same
# way before it is compared, so the diff has nothing to ignore.
AUTHORING_METADATA = ("patches", "expectation.json")
# Added product-code lines that can write a test result from inside the pytest
# process. Not proof of guilt — an honest CLI patch may legitimately touch
# `sys.argv` — but a hit keeps the run from ever reading as `done`.
SUSPICIOUS_PRODUCT_TOKENS = (
    "/ega-out",
    "junit",
    "--junitxml",
    "os._exit",
    "os.kill",
    "getppid",
    "sys.argv",
    "/proc/self",
    "builtins",
    "sys.modules[",
    "atexit",
)
# Environment for the verifier's own pytest run. `-I` implies `-E`, so
# PYTHON* variables are ignored by the interpreter and the command carries
# `-B`/`-u` itself; pytest reads PYTEST_* from os.environ normally.
VERIFIER_ENV = {"PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1"}
_XFAIL_MARKER = re.compile(r"(?:mark\.xfail|pytest\.xfail)\s*\(")


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


def _isolated_pytest(*extra: str) -> list[str]:
    """Our own pytest invocation, isolated from anything inside the workspace.

    ``-I`` implies ``-E``, ``-P`` and ``-s``: the workspace is not on
    ``sys.path`` at interpreter start, so ``pytest.py`` or ``sitecustomize.py``
    planted next to the code is never imported; ``PYTHON*`` variables are
    ignored, hence the explicit ``-B``/``-u``. ``-o pythonpath=.`` re-adds the
    rootdir *after* startup, through pytest's own config, so the package under
    test is importable while an interpreter-start hook is not.
    """
    return [
        "python",
        "-I",
        "-B",
        "-u",
        "-m",
        "pytest",
        "-q",
        "-p",
        "no:cacheprovider",
        "-o",
        "pythonpath=.",
        *extra,
    ]


def verifier_command(junit_name: str) -> list[str]:
    """The one command the verifier runs. Nothing from the snapshot feeds it."""
    return _isolated_pytest(f"--junitxml={VERIFIER_JUNIT_DIR}/{junit_name}")


def baseline_command() -> list[str]:
    """The pristine fixture is collected with the same isolated invocation."""
    return _isolated_pytest("--collect-only")


def _describe(result: SandboxResult) -> str:
    if result.error:
        return f"sandbox error: {result.error}"
    if result.timed_out:
        return f"timed out after {result.duration_s:.1f}s"
    tail = (result.stderr or result.stdout).strip().splitlines()
    return tail[-1] if tail else "no output"


# --- pristine baseline ------------------------------------------------------


def stage_repo(source: Path) -> Path:
    """A temporary copy of ``source`` as the repo the author was handed.

    ``patches/`` and ``expectation.json`` are authoring metadata: they are
    dropped when the author's workspace is created, so the pristine baseline is
    staged the same way here. That is the *only* filtering the comparison gets
    — the diff itself ignores nothing but ``_RUN_BYPRODUCTS``.
    """
    target = Path(tempfile.mkdtemp(prefix="ega-base-"))
    try:
        shutil.copytree(
            source,
            target,
            symlinks=True,
            dirs_exist_ok=True,
            ignore=shutil.ignore_patterns(*AUTHORING_METADATA, *sorted(_RUN_BYPRODUCTS)),
        )
    except OSError:
        shutil.rmtree(target, ignore_errors=True)
        raise
    return target


def collect_baseline(
    staged_dir: Path,
    limits: Limits | None = None,
    run_id: str | None = None,
) -> tuple[int | None, Finding | None]:
    """Count the pristine fixture's tests in a sandbox of its own.

    An unclean baseline (container error, timeout, OOM kill, any non-zero exit
    — a collection error is exit 2) is never trusted: its count is thrown away
    and ``BASELINE_UNAVAILABLE`` says why.
    """
    result = sandbox.run(
        baseline_command(),
        staged_dir,
        limits or Limits(),
        run_id=f"{run_id}-baseline" if run_id else None,
        env=dict(VERIFIER_ENV),
    )
    shutil.rmtree(result.workdir_after, ignore_errors=True)
    if (
        result.error
        or result.timed_out
        or result.oom_killed
        or result.exit_code != 0
    ):
        return None, Finding(
            "BASELINE_UNAVAILABLE",
            MEDIUM,
            "the pristine fixture could not be collected cleanly, so BELOW_BASELINE "
            "is unproven",
            f"{_describe(result)} exit_code={result.exit_code} "
            f"timed_out={result.timed_out} oom_killed={result.oom_killed}",
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


# --- test harness comparison ------------------------------------------------


def _is_harness_path(rel: Path) -> bool:
    """Whether ``rel`` is a file pytest's behaviour depends on."""
    name = rel.name
    if name == "conftest.py" or name in HARNESS_FILE_NAMES:
        return True
    if _TEST_FILE_NAME.match(name):
        return True
    if rel.parts[0] == "tests":
        return True
    if name in _SHADOW_NAMES or name.endswith(_SHADOW_SUFFIXES):
        return True
    if any(part.endswith(_SHADOW_DIR_SUFFIXES) for part in rel.parts):
        return True
    if "_pytest" in rel.parts[:-1] or name == "_pytest.py":
        return True
    return False


def _repo_files(root: Path) -> dict[str, Path]:
    """Every regular file in ``root`` except run byproducts, by relative posix path."""
    found: dict[str, Path] = {}
    root = Path(root)
    for path in root.rglob("*"):
        if not path.is_file() and not path.is_symlink():
            continue
        rel = path.relative_to(root)
        if any(part in _RUN_BYPRODUCTS for part in rel.parts):
            continue
        found[rel.as_posix()] = path
    return found


def _harness_paths(root: Path) -> dict[str, Path]:
    """Every file the pytest harness depends on, keyed by relative posix path."""
    root = Path(root)
    return {
        rel: path
        for rel, path in _repo_files(root).items()
        if _is_harness_path(Path(rel))
    }


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


def xfail_marker_counts(baseline_dir: Path, snapshot_dir: Path) -> tuple[int, int]:
    """``(pristine, snapshot)`` xfail markers — like for like.

    Both sides are counted the same way, statically. Mixing a marker count with
    the junit ``xfailed`` count made an untouched ``parametrize`` xfail
    (one marker, two outcomes) look like an added one.
    """
    return count_xfail_markers(baseline_dir), count_xfail_markers(snapshot_dir)


# --- product code that can forge a result -----------------------------------


def added_lines(left_text: str, right_text: str) -> list[tuple[int, str]]:
    """``(1-based line number in the new file, line)`` for every added line."""
    left = left_text.splitlines()
    right = right_text.splitlines()
    matcher = difflib.SequenceMatcher(a=left, b=right, autojunk=False)
    added: list[tuple[int, str]] = []
    for tag, _i1, _i2, j1, j2 in matcher.get_opcodes():
        if tag in ("insert", "replace"):
            added.extend((number, right[number - 1]) for number in range(j1 + 1, j2 + 1))
    return added


def _product_py_files(root: Path) -> dict[str, Path]:
    """Python files that are *not* part of the test harness, by relative path."""
    return {
        rel: path
        for rel, path in _repo_files(root).items()
        if rel.endswith(".py") and not _is_harness_path(Path(rel)) and not path.is_symlink()
    }


def suspicious_product_code(
    baseline_dir: Path, snapshot_dir: Path, limit: int = 12
) -> Finding | None:
    """Report added product-code lines that could forge a test result.

    Product code runs in the same process as pytest, so it can write the junit
    file itself (or kill the process). That cannot be prevented from outside
    that process; it can be spotted. A hit is a signal, not a conviction: the
    verdict can no longer be ``done``, and the evidence carries the lines.
    """
    base = _product_py_files(baseline_dir)
    snap = _product_py_files(snapshot_dir)
    hits: list[tuple[str, int, str, str]] = []
    for rel, path in sorted(snap.items()):
        left = base.get(rel)
        try:
            left_text = (
                left.read_text(encoding="utf-8", errors="replace") if left is not None else ""
            )
            right_text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for number, line in added_lines(left_text, right_text):
            for token in SUSPICIOUS_PRODUCT_TOKENS:
                if token in line:
                    hits.append((rel, number, token, line.strip()))
                    break
    if not hits:
        return None
    evidence = " | ".join(
        f"{rel}:{number}: matched {token!r} in {text[:160]!r}"
        for rel, number, token, text in hits[:limit]
    )
    return Finding(
        "SUSPICIOUS_PRODUCT_CODE",
        HIGH,
        f"product code added {len(hits)} line(s) that can forge a test result "
        "(the verdict cannot be `done`)",
        evidence[:2000],
    )


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
    baseline_repo: Path | None = None
    junit_name = f"junit-{uuid.uuid4().hex[:12]}.xml"
    out_root: Path | None = None
    workdir: Path | None = None
    kept_junit: Path | None = None
    harness_changed: list[str] = []
    try:
        # A fresh, author-free view of the pristine fixture: the same repo the
        # author was handed. Without it nothing about the baseline can be shown.
        if baseline_dir is None:
            verifier_findings.append(
                Finding(
                    "BASELINE_UNAVAILABLE",
                    MEDIUM,
                    "no pristine baseline was supplied, so the harness diff, the "
                    "product-code check and BELOW_BASELINE could not run",
                    "baseline_dir=None",
                )
            )
        else:
            try:
                baseline_repo = stage_repo(baseline_dir)
            except OSError as exc:
                verifier_findings.append(
                    Finding(
                        "BASELINE_UNAVAILABLE",
                        MEDIUM,
                        "the pristine baseline could not be staged for comparison",
                        f"baseline_dir={baseline_dir} error={exc}",
                    )
                )

        if baseline_repo is not None and run_baseline:
            baseline_collected, baseline_finding = collect_baseline(
                baseline_repo, limits, run_id
            )
            if baseline_finding is not None:
                verifier_findings.append(baseline_finding)

        out_root = Path(tempfile.mkdtemp(prefix="ega-out-"))
        started = time.time()
        result = sandbox.run(
            verifier_command(junit_name),
            snapshot_dir,
            limits or Limits(),
            run_id=run_id,
            env=dict(VERIFIER_ENV),
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
        if baseline_repo is not None:
            changes = harness_changes(baseline_repo, snapshot_dir)
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
            pristine_xfail, snapshot_xfail = xfail_marker_counts(
                baseline_repo, snapshot_dir
            )
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
            product_finding = suspicious_product_code(baseline_repo, snapshot_dir)
            if product_finding is not None:
                verifier_findings.append(product_finding)

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
        # The verifier owns every temp tree it made; none outlives the call.
        if workdir is not None:
            shutil.rmtree(workdir, ignore_errors=True)
        if out_root is not None:
            shutil.rmtree(out_root, ignore_errors=True)
        if baseline_repo is not None:
            shutil.rmtree(baseline_repo, ignore_errors=True)