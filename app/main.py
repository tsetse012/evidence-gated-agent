"""Web skeleton: start a run, watch it, read the trace, approve a verdict.

No build step: one static HTML page talks to the JSON API.
"""

from __future__ import annotations

import threading
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


class RunRequest(BaseModel):
    fixture: str
    author: str = Field(default="scripted:honest", description="scripted:<patch>")


def _runs_root() -> Path:
    return pipeline.runs_dir()


def _execute(run_id: str, fixture: str, patch: str) -> None:
    with _lock:
        _runs[run_id]["status"] = "running"
    try:
        pipeline.run_pipeline(fixture, patch, run_id=run_id)
        status = "done"
    except Exception as exc:  # reported through the API, not swallowed
        with _lock:
            _runs[run_id]["error"] = f"{type(exc).__name__}: {exc}"
        status = "failed"
    with _lock:
        _runs[run_id]["status"] = status


def _parse_author(author: str) -> str:
    if not author.startswith("scripted:"):
        raise HTTPException(
            status_code=400,
            detail=f"only scripted authors exist in this phase; got {author!r}",
        )
    return author.split(":", 1)[1]


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
    patch = _parse_author(request.author)
    if patch not in meta["patches"]:
        raise HTTPException(
            status_code=400,
            detail=f"unknown patch {patch!r} for {request.fixture!r}; have {meta['patches']}",
        )
    run_id = pipeline.new_run_id()
    with _lock:
        _runs[run_id] = {
            "status": "queued",
            "error": None,
            "fixture": request.fixture,
            "author": request.author,
        }
    threading.Thread(
        target=_execute, args=(run_id, request.fixture, patch), daemon=True
    ).start()
    return {"run_id": run_id, "status": "queued"}


@app.get("/api/runs/{run_id}")
def get_run(run_id: str) -> dict:
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
    trace_path = _runs_root() / run_id / "trace.jsonl"
    if not trace_path.is_file():
        raise HTTPException(status_code=404, detail=f"no trace for run {run_id}")
    return PlainTextResponse(trace_path.read_text(encoding="utf-8"))


@app.post("/api/runs/{run_id}/approve")
def approve_run(run_id: str) -> dict:
    try:
        summary = pipeline.approve(run_id)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except PermissionError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return {"run_id": run_id, "approved": True, "summary": summary}