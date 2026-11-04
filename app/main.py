"""Web skeleton: start a run, watch it, read the trace, approve a verdict.

No build step: one static HTML page talks to the JSON API.
"""

from __future__ import annotations

import os
import re
import threading
from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from ega import pipeline
from ega.trace import summarize

STATIC_DIR = Path(__file__).resolve().parent / "static"

app = FastAPI(title="Evidence-Gated Agent", version="0.1.0")
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

# In-memory run registry: id -> {status, error, fixture, author, run_dir}
_runs: dict[str, dict] = {}
_lock = threading.Lock()

# The demo is public, so every run costs containers and every model run costs
# credit. Both are capped by the server, not by the page.
MAX_ACTIVE_RUNS = int(os.environ.get("EGA_MAX_ACTIVE_RUNS", "2"))
DAILY_MODEL_RUNS = int(os.environ.get("EGA_DAILY_MODEL_RUNS", "40"))
_model_runs_by_day: dict[str, int] = {}

# Letters, digits, "_" and "-" only: no ".", no "/", so a run id can never
# climb out of the runs directory. (pipeline.new_run_id() is 20261104T012345Z-1a2b3c.)
RUN_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")


def _checked_run_id(run_id: str) -> str:
    if not RUN_ID_PATTERN.fullmatch(run_id):
        raise HTTPException(status_code=404, detail=f"unknown run: {run_id}")
    return run_id


class RunRequest(BaseModel):
    fixture: str
    author: str = Field(
        default="scripted:honest",
        description="scripted:<patch> (a canned patch) or llm (a model driving the sandbox)",
    )
    judge: bool = Field(
        default=False,
        description="ask the judge model one question per changed file (adds medium findings only)",
    )
    explain: bool = Field(
        default=False,
        description="have a different vendor's chat model describe the finished verdict",
    )


class ApproveRequest(BaseModel):
    """A ``partial`` verdict may only be approved with a written reason."""

    reason: str = Field(default="", description="why a human accepts a partial verdict")


def _runs_root() -> Path:
    return pipeline.runs_dir()


def _execute(
    run_id: str, fixture: str, patch: str | None, author: str, judge: bool, explain: bool
) -> None:
    with _lock:
        _runs[run_id]["status"] = "running"
    try:
        pipeline.run_pipeline(
            fixture,
            patch,
            author=author,
            run_id=run_id,
            judge=judge,
            explain=explain,
        )
        status = "done"
    except Exception as exc:  # reported through the API, not swallowed
        with _lock:
            _runs[run_id]["error"] = f"{type(exc).__name__}: {exc}"
        status = "failed"
    with _lock:
        _runs[run_id]["status"] = status


def _parse_author(author: str) -> tuple[str, str | None]:
    """``scripted:<patch>`` -> a canned patch; ``llm`` -> a model in the sandbox."""
    if author == "llm":
        return "llm", None
    if author.startswith("scripted:"):
        return "scripted", author.split(":", 1)[1]
    raise HTTPException(
        status_code=400,
        detail=f"author must be 'scripted:<patch>' or 'llm'; got {author!r}",
    )


def llm_available() -> bool:
    return bool(os.environ.get("VULTR_INFERENCE_API_KEY"))


@app.get("/")
def index() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/api/fixtures")
def get_fixtures() -> dict:
    return {"fixtures": pipeline.list_fixtures()}


@app.post("/api/runs", status_code=202)
def create_run(request: RunRequest) -> dict:
    try:
        meta = pipeline.fixture_meta(request.fixture)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    kind, patch = _parse_author(request.author)
    if kind == "scripted" and patch not in meta["patches"]:
        raise HTTPException(
            status_code=400,
            detail=f"unknown patch {patch!r} for {request.fixture!r}; have {meta['patches']}",
        )
    if kind == "llm" and not llm_available():
        raise HTTPException(
            status_code=503,
            detail="the llm author needs VULTR_INFERENCE_API_KEY in the server environment",
        )
    uses_model = kind == "llm" or request.judge or request.explain
    run_id = pipeline.new_run_id()
    with _lock:
        active = sum(1 for r in _runs.values() if r["status"] in ("queued", "running"))
        if active >= MAX_ACTIVE_RUNS:
            raise HTTPException(
                status_code=429,
                detail=f"{active} run(s) already in progress; try again when one finishes",
            )
        if uses_model:
            day = datetime.now(timezone.utc).strftime("%Y-%m-%d")
            used = _model_runs_by_day.get(day, 0)
            if used >= DAILY_MODEL_RUNS:
                raise HTTPException(
                    status_code=429,
                    detail=f"today's model-run allowance ({DAILY_MODEL_RUNS}) is used up; "
                    "scripted runs without the judge still work",
                )
            _model_runs_by_day[day] = used + 1
        _runs[run_id] = {
            "status": "queued",
            "error": None,
            "fixture": request.fixture,
            "author": request.author,
        }
    threading.Thread(
        target=_execute,
        args=(run_id, request.fixture, patch, kind, request.judge, request.explain),
        daemon=True,
    ).start()
    return {"run_id": run_id, "status": "queued"}


@app.get("/api/runs/{run_id}")
def get_run(run_id: str) -> dict:
    run_id = _checked_run_id(run_id)
    with _lock:
        state = dict(_runs.get(run_id) or {})
    run_dir = _runs_root() / run_id
    trace_path = run_dir / "trace.jsonl"
    if not state and not trace_path.is_file():
        raise HTTPException(status_code=404, detail=f"unknown run: {run_id}")
    summary = summarize(trace_path) if trace_path.is_file() else None
    status = state.get("status") or ("done" if summary else "unknown")
    return {
        "run_id": run_id,
        "status": status,
        "fixture": state.get("fixture"),
        "author": state.get("author"),
        "error": state.get("error"),
        "summary": summary,
    }


@app.get("/api/runs/{run_id}/trace", response_class=PlainTextResponse)
def get_trace(run_id: str) -> PlainTextResponse:
    run_id = _checked_run_id(run_id)
    trace_path = _runs_root() / run_id / "trace.jsonl"
    if not trace_path.is_file():
        raise HTTPException(status_code=404, detail=f"no trace for run {run_id}")
    return PlainTextResponse(trace_path.read_text(encoding="utf-8"))


@app.post("/api/runs/{run_id}/approve")
def approve_run(run_id: str, request: ApproveRequest | None = None) -> dict:
    run_id = _checked_run_id(run_id)
    try:
        summary = pipeline.approve(run_id, reason=(request.reason if request else ""))
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except PermissionError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return {"run_id": run_id, "approved": True, "summary": summary}