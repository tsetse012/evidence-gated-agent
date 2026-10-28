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
* the expected tests are not counted, they are **named**: the pristine fixture
  is *executed* in its own sandbox and every node id's outcome is recorded, then
  compared node-for-node against the snapshot's report — a node that is gone
  (``TESTS_MISSING``), a node that used to run and is now skipped
  (``SKIP_ADDED``) or xfailed (``XFAIL_ADDED``) is caught even when the total
  count is unchanged and no marker lives in a test file. A node that was
  already skipped/xfailed in the fixture raises no alarm. An unclean baseline
  run is never trusted (``BELOW_BASELINE``, ``BASELINE_UNAVAILABLE``);
* bytecode and install metadata are removed before the run: an author has no
  reason to ship a ``.pyc`` (an unchecked-hash one is loaded in preference to
  the source it sits next to) or an ``*.egg-info`` (``PLANTED_BYTECODE``,
  ``WORKSPACE_METADATA_REMOVED``), and the isolated command keeps every cache
  outside the workspace (``-X pycache_prefix=/tmp/ega-pyc``);
* the test harness itself is compared against the pristine fixture: pytest's
  own ``python_files`` patterns anywhere in the tree, any ``conftest.py``,
  the config files, and anything that can shadow or extend pytest itself
  (``TEST_HARNESS_CHANGED``), plus pytest's deselection count
  (``DESELECTED``). Adding a *new* test to an existing file without touching
  what was already there is reported as ``TESTS_ADDED`` (medium): the harness
  changed, but nothing was replaced — the node comparison is what proves it.
  Nothing but run byproducts is ignored in that comparison;
* **threat model split.** A sloppy author (skips, xfails, masking, weakened or
  removed tests) is *blocked*. An author attacking the verifier — product code
  that forges the report from inside the same process as pytest — cannot be
  blocked by the runner alone, so added product-code lines that can forge a
  result are reported as ``SUSPICIOUS_PRODUCT_CODE``: a medium signal that
  keeps the verdict at ``partial`` (a human decides), not a proof of innocence;
* declared artifacts must resolve inside the result workspace
  (``ARTIFACT_ESCAPE``), and nothing that escaped the workspace is ever read
  on the host.
"""

from __future__ import annotations

import ast
import difflib
import io
import itertools
import os
import re
import shutil
import time
import tokenize
import tomllib
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Sequence

from . import sandbox
from . import tmp
from .evidence import (
    CRITICAL,
    HIGH,
    MEDIUM,
    EvidenceReport,
    Finding,
    analyze,
    node_outcomes,
    verdict_token,
)
from .sandbox import Limits, SandboxResult

CONFIG_FILE = "ega.toml"
# What the author's own sandbox is told to run when it declares nothing. The
# verifier intentionally runs neither this nor a declared variant.
DEFAULT_TEST_COMMAND = "python -m pytest -q --junitxml=/work/.ega/junit.xml"
# The verifier's own command: no shell, no cache, and a junit outside /work.
VERIFIER_JUNIT_DIR = sandbox.OUT_MOUNT
# Every file pytest reads when it decides what to run. `.pytest.ini` is the
# hidden-file spelling pytest 9 turns into a first-class `pytest.toml`; all three
# are listed because the whole point is that the *author* must not be able to
# change what runs.
HARNESS_FILE_NAMES = frozenset(
    {
        "pytest.ini",
        ".pytest.ini",
        "pytest.toml",
        ".pytest.toml",
        "setup.cfg",
        "tox.ini",
        "pyproject.toml",
    }
)
# The interpreter's own cache directory. Without it a planted
# `invoice/__pycache__/core.cpython-313.pyc` (unchecked-hash: never validated
# against the source) is imported in preference to the buggy `.py` beside it,
# and `-B` does not help — `-B` stops *writing* bytecode, not *reading* it.
PYCACHE_PREFIX = "/tmp/ega-pyc"
_BYTECODE_SUFFIXES = (".pyc", ".pyo")
# `pip install -e .` byproducts. Inert under `-I` + plugin autoload off, so they
# are removed and reported instead of turning into a high harness change.
_WORKSPACE_METADATA_SUFFIXES = (".egg-info", ".dist-info")
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
# `sys.argv` — but a hit keeps the run from ever reading as `done` (it lands at
# `partial`, where a human decides).
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
# Token kinds that carry no code: comments, string bodies and the literal parts
# of an f-string. A token inside those is prose, not a call, so the product-code
# scan masks them out (an honest patch may *mention* `junit` in a comment).
_NON_CODE_TOKENS = frozenset(
    {
        tokenize.COMMENT,
        tokenize.STRING,
        getattr(tokenize, "FSTRING_START", -1),
        getattr(tokenize, "FSTRING_MIDDLE", -1),
        getattr(tokenize, "FSTRING_END", -1),
    }
)
# Outcomes that mean "this test actually ran" in the pristine fixture. A node
# that was already skipped or xfailed there is not evidence of anything now.
_RAN_OUTCOMES = frozenset({"passed", "failed", "error"})


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

    ``-X pycache_prefix`` points every bytecode and assertion-rewrite cache read
    and write at a directory outside the workspace, so a ``__pycache__`` planted
    in the snapshot is never even consulted (`-B` only stops writing).
    """
    return [
        "python",
        "-I",
        "-B",
        "-u",
        "-X",
        f"pycache_prefix={PYCACHE_PREFIX}",
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


def baseline_command(junit_name: str) -> list[str]:
    """The pristine fixture is *run*, with the same isolated invocation.

    Not ``--collect-only``: knowing how many tests exist says nothing about
    what each of them did, and a node that is gone or newly skipped/xfailed can
    keep the count identical. The fixture is expected to fail — that is the
    bug the author was handed — so a non-zero pytest exit is not by itself a
    reason to distrust the baseline.
    """
    return _isolated_pytest(f"--junitxml={VERIFIER_JUNIT_DIR}/{junit_name}")


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
    target = tmp.mkdtemp("ega-base-")
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


def strip_bytecode(root: Path) -> list[str]:
    """Delete ``__pycache__`` trees and stray ``.pyc``/``.pyo``; return them.

    An unchecked-hash ``.pyc`` is loaded in preference to the ``.py`` beside it
    without ever being validated against the source, so an author can ship the
    fix as bytecode and leave the source buggy. There is no honest reason for a
    workspace to contain bytecode, so every hit is reported, not just ignored.
    """
    root = Path(root)
    removed: list[str] = []
    for dirpath, _dirnames, filenames in os.walk(root, topdown=False, followlinks=False):
        base = Path(dirpath)
        for name in filenames:
            path = base / name
            if path.suffix not in _BYTECODE_SUFFIXES:
                continue
            if path.is_file() or path.is_symlink():
                removed.append(path.relative_to(root).as_posix())
                path.unlink(missing_ok=True)
        if base.name == "__pycache__" and base != root:
            shutil.rmtree(base, ignore_errors=True)
    return sorted(removed)


def strip_workspace_metadata(root: Path) -> list[str]:
    """Delete ``*.egg-info`` / ``*.dist-info`` trees; return what was there.

    ``pip install -e .`` inside the author's sandbox leaves these. Under
    ``-I`` and plugin autoload off they are inert, so they are removed (a
    planted ``[pytest11]`` entry point must not sit in the workspace at all) and
    reported as an audit note rather than as a harness edit.
    """
    root = Path(root)
    found = [
        path
        for path in root.rglob("*")
        if path.is_dir()
        and not path.is_symlink()
        and path.name.endswith(_WORKSPACE_METADATA_SUFFIXES)
    ]
    removed: list[str] = []
    for path in sorted(found, key=lambda p: len(p.parts), reverse=True):
        if not path.exists():
            continue
        for entry in path.rglob("*"):
            if entry.is_file() or entry.is_symlink():
                removed.append(entry.relative_to(root).as_posix())
        removed.append(path.relative_to(root).as_posix())
        shutil.rmtree(path, ignore_errors=True)
    return sorted(removed)


@dataclass
class Baseline:
    """What the pristine fixture did, node by node, when the verifier ran it."""

    collected: int | None = None
    outcomes: dict[str, str] = field(default_factory=dict)
    finding: Finding | None = None


def collect_baseline(
    staged_dir: Path,
    out_root: Path,
    limits: Limits | None = None,
    run_id: str | None = None,
) -> Baseline:
    """Run the pristine fixture unchanged and keep every node's outcome.

    A baseline is trusted only when the pristine suite ran to its own
    conclusion: pytest exited 0 (all passed) or 1 (some failed — expected for a
    fixture that ships a bug), the container was not killed, and the report
    parses. A collection error, usage error, timeout or OOM leaves the baseline
    unmeasured, which is never treated as "no change".
    """
    junit_name = f"baseline-{uuid.uuid4().hex[:12]}.xml"
    result = sandbox.run(
        baseline_command(junit_name),
        staged_dir,
        limits or Limits(),
        run_id=f"{run_id}-baseline" if run_id else None,
        env=dict(VERIFIER_ENV),
        out_dir=out_root,
    )
    shutil.rmtree(result.workdir_after, ignore_errors=True)

    def untrusted(reason: str) -> Baseline:
        return Baseline(
            collected=None,
            outcomes={},
            finding=Finding(
                "BASELINE_UNAVAILABLE",
                MEDIUM,
                "the pristine fixture could not be run cleanly, so TESTS_MISSING, "
                "SKIP_ADDED, XFAIL_ADDED and BELOW_BASELINE are unproven",
                reason,
            ),
        )

    if result.error or result.timed_out or result.oom_killed:
        return untrusted(
            f"{_describe(result)} exit_code={result.exit_code} "
            f"timed_out={result.timed_out} oom_killed={result.oom_killed}"
        )
    if result.exit_code not in (0, 1):
        return untrusted(
            f"pytest exited {result.exit_code} on the pristine fixture; a run that "
            f"did not reach its own conclusion cannot be a baseline "
            f"({_describe(result)})"
        )
    junit_path = Path(out_root) / junit_name
    outcomes = node_outcomes(junit_path)
    if not outcomes:
        return untrusted(
            f"the pristine run wrote no readable junit report at {junit_name} "
            f"({_describe(result)})"
        )
    return Baseline(collected=len(outcomes), outcomes=outcomes, finding=None)


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


def compare_node_outcomes(
    pristine: dict[str, str], snapshot: dict[str, str], limit: int = 8
) -> list[Finding]:
    """Judge the snapshot node by node against what the pristine fixture did.

    Counting was not enough: the same total hides a removed test replaced by a
    doctest, and an xfail marker or a ``pytest.xfail()`` call inside product
    code never appears in a test file at all. What cannot be hidden is a node
    that used to *run* and now does not — it is gone (``TESTS_MISSING``), it is
    skipped (``SKIP_ADDED``) or it is expected to fail (``XFAIL_ADDED``).

    A node that was already skipped or xfailed in the pristine fixture raises no
    alarm: fixing (or not fixing) a known gap is not evidence of cheating.
    """
    findings: list[Finding] = []
    missing = sorted(set(pristine) - set(snapshot))
    skip_added: list[str] = []
    xfail_added: list[str] = []
    for node, was in sorted(pristine.items()):
        if was not in _RAN_OUTCOMES:
            continue
        now = snapshot.get(node)
        if now == "skipped":
            skip_added.append(node)
        elif now == "xfailed":
            xfail_added.append(node)

    def listing(nodes: Sequence[str]) -> str:
        shown = ", ".join(nodes[:limit])
        return shown + (f" … (+{len(nodes) - limit} more)" if len(nodes) > limit else "")

    if missing:
        findings.append(
            Finding(
                "TESTS_MISSING",
                HIGH,
                f"{len(missing)} test(s) the pristine fixture ran were not run at all: "
                + listing(missing),
                "\n".join(missing[: limit * 4]),
            )
        )
    if skip_added:
        findings.append(
            Finding(
                "SKIP_ADDED",
                HIGH,
                f"{len(skip_added)} test(s) that used to run are now skipped: "
                + listing(skip_added),
                "\n".join(f"{node}: {pristine[node]} -> skipped" for node in skip_added[: limit * 4]),
            )
        )
    if xfail_added:
        findings.append(
            Finding(
                "XFAIL_ADDED",
                HIGH,
                f"{len(xfail_added)} test(s) that used to run are now expected failures: "
                + listing(xfail_added),
                "\n".join(f"{node}: {pristine[node]} -> xfailed" for node in xfail_added[: limit * 4]),
            )
        )
    return findings


def _test_units(text: str) -> dict[str, str] | None:
    """``name -> ast dump`` for every top-level test function/class.

    ``None`` when the file does not parse: an unparsable test module is not
    evidence of an addition-only change.
    """
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError):
        return None
    units: dict[str, str] = {}
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            units[node.name] = ast.dump(node)
    return units


def additions_only_test_changes(
    baseline_dir: Path, snapshot_dir: Path, changed: Sequence[str]
) -> bool:
    """Whether every harness change only *adds* to a test module.

    True only when each changed path is a test module that exists on both sides
    and every top-level function/class it already had is AST-identical in the
    snapshot. A new conftest, a config file, a removed or renamed module, a
    touched assertion or a deleted test all make this False.

    This is a downgrade of severity, never a pass: the caller still requires
    that no node went missing or turned skip/xfail (``compare_node_outcomes``),
    so "added" cannot mean "replaced".
    """
    base_files = _repo_files(baseline_dir)
    snap_files = _repo_files(snapshot_dir)
    for rel in changed:
        if not _TEST_FILE_NAME.match(Path(rel).name):
            return False
        base, snap = base_files.get(rel), snap_files.get(rel)
        if base is None or snap is None:
            return False
        try:
            base_units = _test_units(base.read_text(encoding="utf-8", errors="replace"))
            snap_units = _test_units(snap.read_text(encoding="utf-8", errors="replace"))
        except OSError:
            return False
        if base_units is None or snap_units is None:
            return False
        if any(snap_units.get(name) != dump for name, dump in base_units.items()):
            return False
    return True


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


def _mask_non_code(text: str) -> list[str] | None:
    """The file's lines with comments, string bodies and f-string literals blanked.

    ``tokenize`` is used rather than a regex so that a token inside a comment or
    a docstring cannot trip the scan: an honest patch is allowed to *mention*
    ``junit`` in prose, and a forgery always has to make the call in code.
    ``None`` when the file does not tokenize — the caller then scans the raw
    lines, because an unparsable product file is the suspicious case, not a
    free pass.
    """
    lines = text.splitlines(keepends=True)
    try:
        tokens = tokenize.generate_tokens(io.StringIO(text).readline)
        spans = [
            (token.start, token.end)
            for token in tokens
            if token.type in _NON_CODE_TOKENS
        ]
    except (tokenize.TokenError, IndentationError, SyntaxError):
        return None
    for (start_row, start_col), (end_row, end_col) in spans:
        for row in range(start_row, end_row + 1):
            index = row - 1
            if index < 0 or index >= len(lines):
                continue
            line = lines[index]
            begin = start_col if row == start_row else 0
            stop = end_col if row == end_row else len(line)
            begin = max(0, min(begin, len(line)))
            stop = max(0, min(stop, len(line)))
            if stop > begin:
                lines[index] = line[:begin] + " " * (stop - begin) + line[stop:]
    return [line.rstrip("\r\n") for line in lines]


def suspicious_product_code(
    baseline_dir: Path, snapshot_dir: Path, limit: int = 12
) -> Finding | None:
    """Report added product-code *lines* that could forge a test result.

    Product code runs in the same process as pytest, so it can write the junit
    file itself (or kill the process). That cannot be prevented from outside
    that process; it can be spotted. Only code counts — a comment or a docstring
    that says "junit" is prose, not a call. A hit is a signal, not a conviction:
    the verdict drops to ``partial`` and a human decides.
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
        code_lines = _mask_non_code(right_text)
        for number, line in added_lines(left_text, right_text):
            candidate = line
            if code_lines is not None and 0 < number <= len(code_lines):
                candidate = code_lines[number - 1]
            for token in SUSPICIOUS_PRODUCT_TOKENS:
                if token in candidate:
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
        MEDIUM,
        f"product code added {len(hits)} line(s) that can forge a test result "
        "(the verdict cannot be `done`; a human decides on `partial`)",
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

    # Bytecode is never shipped honestly: an unchecked-hash `.pyc` wins over the
    # `.py` beside it, so the fix could be delivered as bytecode while the
    # source stays buggy. Removed *and* reported.
    planted = strip_bytecode(snapshot_dir)
    if planted:
        verifier_findings.append(
            Finding(
                "PLANTED_BYTECODE",
                HIGH,
                f"the snapshot contains {len(planted)} bytecode file(s) or cache "
                "directories; a workspace has no reason to ship them and an "
                "unchecked-hash .pyc overrides the source it sits next to",
                ", ".join(planted[:40])[:2000],
            )
        )
    # `pip install -e .` leftovers. Inert under `-I` + plugin autoload off, so
    # they are removed and reported instead of becoming a high harness change.
    metadata = strip_workspace_metadata(snapshot_dir)
    if metadata:
        verifier_findings.append(
            Finding(
                "WORKSPACE_METADATA_REMOVED",
                MEDIUM,
                f"the snapshot contained {len(metadata)} installed-package metadata "
                "entr(ies); they were removed before the run",
                ", ".join(metadata[:40])[:2000],
            )
        )

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

    baseline = Baseline()
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
                    "node comparison, the product-code check and BELOW_BASELINE "
                    "could not run",
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

        # The report of the pristine run lands in the same verifier-owned
        # directory as the snapshot's, so it must exist before that run.
        out_root = tmp.mkdtemp("ega-out-")

        if baseline_repo is not None:
            baseline = collect_baseline(baseline_repo, out_root, limits, run_id)
            if baseline.finding is not None:
                verifier_findings.append(baseline.finding)

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

        # What the pristine fixture *did*, node by node. Counting alone cannot
        # tell a full run from a filtered one, and no marker needs to live in a
        # test file for a node to stop running.
        node_findings: list[Finding] = []
        if baseline.outcomes:
            node_findings = compare_node_outcomes(
                baseline.outcomes, node_outcomes(junit_path)
            )
            verifier_findings.extend(node_findings)

        # The test harness itself must be the one the fixture shipped.
        if baseline_repo is not None:
            changes = harness_changes(baseline_repo, snapshot_dir)
            harness_changed = [rel for rel, _ in changes]
            if changes and not node_findings and additions_only_test_changes(
                baseline_repo, snapshot_dir, harness_changed
            ):
                # Every pre-existing test unit is untouched and every pristine
                # node still ran: this only *adds* coverage, which is what an
                # honest author does after a fix. A human still looks at it.
                verifier_findings.append(
                    Finding(
                        "TESTS_ADDED",
                        MEDIUM,
                        "tests were added to existing test modules and no existing "
                        "test changed: " + ", ".join(harness_changed),
                        " | ".join(f"{rel}: {diff[:400]}" for rel, diff in changes)[:2000],
                    )
                )
            elif changes:
                verifier_findings.append(
                    Finding(
                        "TEST_HARNESS_CHANGED",
                        HIGH,
                        "the test harness differs from the pristine fixture: "
                        + ", ".join(harness_changed),
                        " | ".join(f"{rel}: {diff[:400]}" for rel, diff in changes)[:2000],
                    )
                )
            if (
                baseline.collected is not None
                and report.counts["collected"] < baseline.collected
            ):
                verifier_findings.append(
                    Finding(
                        "BELOW_BASELINE",
                        HIGH,
                        f"collected {report.counts['collected']} tests but the pristine "
                        f"fixture collects {baseline.collected}; tests may have been removed",
                        f"collected={report.counts['collected']} "
                        f"baseline={baseline.collected}",
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
            baseline_collected=baseline.collected,
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