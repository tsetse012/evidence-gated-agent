"""Append-only dual record: raw steps in JSONL, summary derived from them.

Every step keeps the raw inputs and the raw stdout/stderr/exit code. The
summary is a pure function of the trace, so it can always be regenerated after
the fact (and never needs to be trusted on its own).
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


class Trace:
    """Append-only writer. Any write failure propagates."""

    def __init__(self, path: Path, run_id: str):
        self.path = Path(path)
        self.run_id = run_id
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._seq = self._last_seq()

    def _last_seq(self) -> int:
        if not self.path.is_file():
            return 0
        last = 0
        for line in self.path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            last = max(last, int(json.loads(line).get("seq", 0)))
        return last

    def append(
        self,
        step: str,
        *,
        status: str = "ok",
        inputs: dict | None = None,
        stdout: str = "",
        stderr: str = "",
        exit_code: int | None = None,
        data: dict | None = None,
    ) -> dict:
        self._seq += 1
        record = {
            "seq": self._seq,
            "ts": _now(),
            "run_id": self.run_id,
            "step": step,
            "status": status,
            "inputs": inputs or {},
            "stdout": stdout,
            "stderr": stderr,
            "exit_code": exit_code,
            "data": data or {},
        }
        line = json.dumps(record, ensure_ascii=False)
        # Append per step: a crash mid-run leaves every completed step on disk.
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(line + "\n")
            fh.flush()
            os.fsync(fh.fileno())
        return record


def read_trace(trace_path: Path) -> list[dict]:
    path = Path(trace_path)
    if not path.is_file():
        raise FileNotFoundError(f"no trace at {path}")
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def summarize(trace_path: Path) -> dict:
    """Pure function: trace JSONL in, summary dict out."""
    records = read_trace(trace_path)
    by_step: dict[str, dict] = {}
    for record in records:
        by_step[record["step"]] = record

    end = by_step.get("pipeline.end", {})
    verify_record = by_step.get("verify", {})
    author_record = by_step.get("author.work", {})
    probes_record = by_step.get("probes", {})
    approve_record = by_step.get("approve")

    verify_data = verify_record.get("data", {})
    verdict = verify_data.get("verdict", {})

    return {
        "run_id": records[0]["run_id"] if records else trace_path.parent.name,
        "status": (end.get("data", {}) or {}).get("status", "running"),
        "steps": [
            {
                "seq": r["seq"],
                "ts": r["ts"],
                "step": r["step"],
                "status": r["status"],
                "exit_code": r["exit_code"],
            }
            for r in records
        ],
        "claim": (author_record.get("data", {}) or {}).get("claim"),
        "verdict": verdict or None,
        "exit_token": verdict.get("exit_token"),
        "first_line": verdict.get("first_line"),
        "counts": verdict.get("counts"),
        "findings": verdict.get("findings", []),
        "isolation": verdict.get("isolation"),
        "probes": (probes_record.get("data", {}) or {}).get("results", []),
        "approved": approve_record is not None,
        "approved_at": approve_record["ts"] if approve_record else None,
        "step_count": len(records),
        "duration_s": round(
            sum(step.get("data", {}).get("duration_s", 0.0) for step in records), 3
        ),
    }


def write_summary(trace_path: Path, summary_path: Path | None = None) -> dict:
    """Regenerate summary.json from the trace (derived, never authoritative)."""
    trace_path = Path(trace_path)
    summary = summarize(trace_path)
    target = Path(summary_path) if summary_path else trace_path.parent / "summary.json"
    target.write_text(json.dumps(summary, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return summary