"""One run, end to end: author in sandbox A, verifier in a fresh sandbox B.

Everything the run does lands in ``runs/<run_id>/trace.jsonl`` as raw steps;
``summary.json`` is regenerated from that trace.
"""

from __future__ import annotations

import json
import shutil
import uuid
from datetime import datetime, timezone
from pathlib import Path

from . import probes as probes_module
from .author import ScriptedAuthor, available_patches
from .sandbox import Limits, run as sandbox_run
from .trace import Trace, summarize, write_summary
from .verify import Claim, load_project_config, verify

REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURES_DIR = Path(__file__).resolve().parents[1] / "fixtures"
RUNS_DIR = REPO_ROOT / "runs"

# Copy into the author workspace, not into the sandbox.
_IGNORE = shutil.ignore_patterns("patches", "expectation.json", "__pycache__", ".pytest_cache")


def fixtures_dir() -> Path:
    return FIXTURES_DIR


def runs_dir() -> Path:
    return RUNS_DIR


def fixture_meta(name: str) -> dict:
    """Trusted metadata about a fixture (never read from the agent's snapshot)."""
    path = fixtures_dir() / name
    if not path.is_dir():
        raise FileNotFoundError(f"unknown fixture: {name}")
    meta = {"name": name, "patches": available_patches(path)}
    expectation = path / "expectation.json"
    if expectation.is_file():
        data = json.loads(expectation.read_text(encoding="utf-8"))
        meta["expected_min_tests"] = data.get("expected_min_tests")
        meta["description"] = data.get("description")
    else:
        meta["expected_min_tests"] = None
        meta["description"] = None
    return meta


def list_fixtures() -> list[dict]:
    root = fixtures_dir()
    return [fixture_meta(p.name) for p in sorted(root.iterdir()) if p.is_dir()]


def new_run_id() -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return f"{stamp}-{uuid.uuid4().hex[:6]}"


def _count_files(root: Path) -> int:
    return sum(1 for p in root.rglob("*") if p.is_file())


def run_pipeline(
    fixture: str,
    patch: str,
    *,
    run_id: str | None = None,
    runs_root: Path | None = None,
    limits: Limits | None = None,
    probe_limits: Limits | None = None,
    run_probes_too: bool = True,
) -> dict:
    """Author -> snapshot -> fresh verifier -> containment probes."""
    meta = fixture_meta(fixture)
    if patch not in meta["patches"]:
        raise FileNotFoundError(
            f"unknown patch {patch!r} for fixture {fixture!r} (have {meta['patches']})"
        )

    run_id = run_id or new_run_id()
    run_dir = Path(runs_root or runs_dir()) / run_id
    trace_path = run_dir / "trace.jsonl"
    trace = Trace(trace_path, run_id)
    task = f"Fix the failing tests in {fixture}"

    try:
        author_dir = run_dir / "author"
        fixture_dir = fixtures_dir() / fixture
        shutil.copytree(fixture_dir, author_dir, ignore=_IGNORE)
        trace.append(
            "fixture.copy",
            inputs={"fixture": fixture, "source": str(fixture_dir)},
            data={"files": _count_files(author_dir), "run_dir": str(run_dir)},
        )

        author = ScriptedAuthor(fixture_dir=fixture_dir, patch_name=patch)
        claim: Claim = author.work(task, author_dir)
        trace.append(
            "author.work",
            inputs={"task": task, "author": author.name},
            data={"claim": claim.as_dict(), "workdir": str(author_dir)},
        )

        # Sandbox A: the author's own run. Recorded for the timeline only —
        # the verifier never reads it.
        config = load_project_config(author_dir)
        author_run = sandbox_run(
            ["sh", "-c", config.test_command],
            author_dir,
            limits or Limits(),
            run_id=f"{run_id}-a",
            workdir_after=run_dir / "author_after",
        )
        trace.append(
            "author.run",
            inputs={"command": config.test_command, "sandbox": author_run.container_name},
            stdout=author_run.stdout,
            stderr=author_run.stderr,
            exit_code=author_run.exit_code,
            data={
                "isolation": author_run.isolation,
                "duration_s": author_run.duration_s,
                "timed_out": author_run.timed_out,
                "oom_killed": author_run.oom_killed,
                "workdir_after": str(author_run.workdir_after),
            },
        )

        # Snapshot taken before the verifier ever looks at the work.
        snapshot_dir = run_dir / "snapshot"
        shutil.copytree(author_dir, snapshot_dir)

        # Sandbox B: a brand-new container, given only the snapshot + the claim.
        verdict = verify(
            snapshot_dir,
            claim,
            expected_min_tests=meta.get("expected_min_tests"),
            limits=limits,
            run_id=f"{run_id}-b",
        )
        # Keep the junit report inside the run dir so the trace stays auditable.
        verdict_data = verdict.as_dict()
        if verdict.junit_path is not None:
            saved = run_dir / "verify_junit.xml"
            shutil.copyfile(verdict.junit_path, saved)
            verdict_data["junit_path"] = str(saved)
        trace.append(
            "verify",
            inputs={
                "snapshot": str(snapshot_dir),
                "expected_min_tests": meta.get("expected_min_tests"),
                "claim": claim.as_dict(),
            },
            stdout=verdict.sandbox.stdout,
            stderr=verdict.sandbox.stderr,
            exit_code=verdict.sandbox.exit_code,
            data={"verdict": verdict_data},
        )

        results = []
        if run_probes_too:
            results = probes_module.run_probes(probe_limits or probes_module.PROBE_LIMITS)
            trace.append(
                "probes",
                inputs={"count": len(results)},
                data={"results": [r.as_dict() for r in results]},
            )

        trace.append(
            "pipeline.end",
            data={
                "status": "ok",
                "exit_token": verdict.exit_token,
                "duration_s": round(verdict.duration_s + author_run.duration_s, 3),
            },
        )
        write_summary(trace_path)
        return {
            "run_id": run_id,
            "status": "ok",
            "trace_path": str(trace_path),
            "verdict": verdict.as_dict(),
            "claim": claim.as_dict(),
        }
    except BaseException as exc:
        trace.append(
            "pipeline.end",
            status="failed",
            stderr=f"{type(exc).__name__}: {exc}",
            data={"status": "failed", "error": f"{type(exc).__name__}: {exc}"},
        )
        write_summary(trace_path)
        raise


def approve(run_id: str, *, runs_root: Path | None = None, actor: str = "human") -> dict:
    """Record the human approval. No external side effect in this phase."""
    run_dir = Path(runs_root or runs_dir()) / run_id
    trace_path = run_dir / "trace.jsonl"
    if not trace_path.is_file():
        raise FileNotFoundError(f"unknown run: {run_id}")
    summary = summarize(trace_path)
    if summary.get("exit_token") != "done":
        raise PermissionError(
            f"run {run_id} is not approvable (verdict={summary.get('exit_token')!r})"
        )
    if summary.get("approved"):
        return summary
    trace = Trace(trace_path, run_id)
    trace.append(
        "approve",
        inputs={"actor": actor},
        data={"action": "would open PR", "side_effect": "none (scaffolding phase)"},
    )
    return write_summary(trace_path)