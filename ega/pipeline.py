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

def build_llm_author(trace: Trace, client=None, options: dict | None = None):
    """The LLM author, with the model client injectable.

    ``client=None`` builds the real Vultr client from the environment; the tests
    pass a fake that replays tool calls, so the gate never needs the network.
    """
    from .llm_author import LLMAuthor, VultrChatClient

    if client is None:
        client = VultrChatClient.from_env()
    return LLMAuthor(client, trace=trace, **(options or {}))


def build_judge(trace: Trace, client=None, *, threshold: float | None = None):
    """The judge layer, off unless asked for; ``client=None`` reads the env.

    A missing key is not an error here: the layer is built with no client and
    reports ``JUDGE_UNAVAILABLE``, which keeps the run out of ``done``. Failing
    the run instead would lose the deterministic verdict a human still wants.
    """
    from .judge import JUDGE_THRESHOLD, Judge, JudgeError, VultrJudgeClient

    if client is None:
        try:
            client = VultrJudgeClient.from_env()
        except JudgeError:
            client = None
    return Judge(
        client=client,
        threshold=JUDGE_THRESHOLD if threshold is None else threshold,
        trace=trace,
    )


def build_explainer(trace: Trace, client=None):
    """The explanation client (a different vendor's chat model), injectable."""
    from .explain import ExplainError, Explainer, VultrExplainClient

    if client is None:
        try:
            client = VultrExplainClient.from_env()
        except ExplainError:
            client = None
    return Explainer(client=client, trace=trace)


def run_pipeline(
    fixture: str,
    patch: str | None = None,
    *,
    author: str = "scripted",
    llm_client=None,
    llm_options: dict | None = None,
    run_id: str | None = None,
    runs_root: Path | None = None,
    limits: Limits | None = None,
    probe_limits: Limits | None = None,
    run_probes_too: bool = True,
    judge: bool = False,
    judge_client=None,
    judge_threshold: float | None = None,
    explain: bool = False,
    explain_client=None,
) -> dict:
    """Author -> snapshot -> fresh verifier -> containment probes.

    ``author`` is ``"scripted"`` (a canned patch, needs ``patch``) or ``"llm"``
    (a chat model driving three sandboxed tools; ``llm_client`` is the seam the
    tests fake, so the suite never needs the network).

    ``judge`` enables the judge layer (one model question per changed file,
    medium findings only — it cannot raise a verdict). ``explain`` asks a
    different vendor's chat model to describe the finished verdict in words;
    the verdict is not touched. Both are off by default so every existing
    offline verdict is unchanged.
    """
    meta = fixture_meta(fixture)
    if author == "scripted":
        if patch is None:
            raise ValueError(f"the scripted author needs a patch for fixture {fixture!r}")
        if patch not in meta["patches"]:
            raise FileNotFoundError(
                f"unknown patch {patch!r} for fixture {fixture!r} (have {meta['patches']})"
            )
    elif author == "llm":
        patch = None
    else:
        raise ValueError(f"unknown author kind {author!r} (use 'scripted' or 'llm')")

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

        if author == "llm":
            author_impl = build_llm_author(trace, llm_client, llm_options)
        else:
            author_impl = ScriptedAuthor(fixture_dir=fixture_dir, patch_name=patch)
        claim: Claim = author_impl.work(task, author_dir)
        trace.append(
            "author.work",
            inputs={"task": task, "author": author_impl.name},
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
        # The pristine fixture is the baseline the verifier compares against;
        # the junit report is written outside the workspace and kept here.
        verify_junit = run_dir / "verify_junit.xml"
        judge_layer = (
            build_judge(trace, judge_client, threshold=judge_threshold) if judge else None
        )
        verdict = verify(
            snapshot_dir,
            claim,
            baseline_dir=fixture_dir,
            expected_min_tests=meta.get("expected_min_tests"),
            limits=limits,
            run_id=f"{run_id}-b",
            junit_keep_path=verify_junit,
            judge=judge_layer,
            agent_attempts=list(getattr(author_impl, "attempts", [])),
        )
        # Keep the junit report inside the run dir so the trace stays auditable.
        verdict_data = verdict.as_dict()
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

        # A truncated finding points the human here for the full diff; this is
        # the copy the approval gate's refusal refers to.
        if verdict.harness_diffs:
            trace.append(
                "harness.diff",
                data={
                    "diffs": verdict.harness_diffs,
                    "note": "full added lines for evidence truncated in the verdict",
                },
            )

        # The explanation is generated *after* the verdict is final and never
        # feeds back into it: a failed call leaves text empty with the reason.
        explanation = None
        if explain:
            explanation = build_explainer(trace, explain_client).explain(verdict.as_dict())

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
            "author": author_impl.name,
            "trace_path": str(trace_path),
            "verdict": verdict.as_dict(),
            "claim": claim.as_dict(),
            "explanation": explanation.as_dict() if explanation is not None else None,
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


def approve(
    run_id: str,
    *,
    runs_root: Path | None = None,
    actor: str = "human",
    reason: str = "",
) -> dict:
    """Record the human approval. No external side effect in this phase.

    ``done`` is approved as-is. ``partial`` means the verifier could not prove
    everything — a test was added, product code merely *mentions* the report
    path, the baseline was unmeasurable — so it is approvable **only with a
    written reason**, which is recorded in the trace together with the findings
    the human is overriding. ``verification-failed`` and ``blocked`` stay
    unapprovable: nothing there is a judgement call.

    Two more gates: the run itself must have finished (``pipeline.end`` with
    status ``ok`` — a run that crashed after its verdict, or that never
    finished, is not a conclusion), and no finding may carry truncated
    evidence (a human cannot approve what they were not shown).
    """
    run_dir = Path(runs_root or runs_dir()) / run_id
    trace_path = run_dir / "trace.jsonl"
    if not trace_path.is_file():
        raise FileNotFoundError(f"unknown run: {run_id}")
    summary = summarize(trace_path)
    if summary.get("status") != "ok":
        raise PermissionError(
            f"run {run_id} has pipeline status {summary.get('status')!r}, not 'ok'; "
            "only a run that reached its own conclusion can be approved"
        )
    token = summary.get("exit_token")
    if token not in ("done", "partial"):
        raise PermissionError(f"run {run_id} is not approvable (verdict={token!r})")
    reason = (reason or "").strip()
    findings = [f for f in (summary.get("findings") or []) if isinstance(f, dict)]
    codes = [str(f.get("code")) for f in findings if f.get("code")]
    truncated = [str(f.get("code")) for f in findings if f.get("truncated")]
    if truncated:
        raise PermissionError(
            f"run {run_id} has truncated evidence for {', '.join(truncated)}; the full "
            f"diff is in {trace_path} (step 'harness.diff') and the run is not "
            "approvable until the whole change has been read"
        )
    if token == "partial" and not reason:
        raise PermissionError(
            f"run {run_id} is partial; approving it requires a non-empty reason "
            f"({', '.join(codes) or 'no findings listed'})"
        )
    if summary.get("approved"):
        return summary
    trace = Trace(trace_path, run_id)
    trace.append(
        "approve",
        inputs={"actor": actor, "reason": reason},
        data={
            "action": "would open PR",
            "side_effect": "none (scaffolding phase)",
            "verdict": token,
            "reason": reason,
            "overridden_findings": codes,
        },
    )
    return write_summary(trace_path)