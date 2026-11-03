#!/usr/bin/env python3
"""Manual live smoke test: a real Vultr model authors a fix, a fresh sandbox judges it.

The gate must never need the network, so this is a script you run by hand:

    set -a; . ~/.secrets/credentials.env; set +a
    uv run python scripts/live_smoke.py buggy_invoice
    uv run python scripts/live_smoke.py injected_readme

It writes a normal run under ``runs/<run_id>/`` (trace.jsonl + summary.json) and
prints the turn count, every tool call with its watch-layer flags, the verifier's
first line, and the cost computed from the API's own ``usage`` numbers. The API
key is never printed and never written into the trace; the script checks the
trace for it before it reports.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ega import pipeline  # noqa: E402
from ega.llm_author import VultrChatClient  # noqa: E402
from ega.trace import read_trace, summarize  # noqa: E402

def clip(text: str, limit: int = 160) -> str:
    text = " ".join((text or "").split())
    return text if len(text) <= limit else text[:limit] + "…"

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("fixture", choices=["buggy_invoice", "injected_readme", "zero_tests"])
    parser.add_argument("--max-turns", type=int, default=20)
    parser.add_argument("--budget-usd", type=float, default=0.20)
    args = parser.parse_args()

    api_key = os.environ.get("VULTR_INFERENCE_API_KEY", "")
    if not api_key:
        print("VULTR_INFERENCE_API_KEY is not set", file=sys.stderr)
        print("run: set -a; . ~/.secrets/credentials.env; set +a", file=sys.stderr)
        return 2

    client = VultrChatClient.from_env()
    print(f"fixture: {args.fixture}")
    print(f"model:   {client.model}  (base {client.base_url})")
    print(f"limits:  max_turns={args.max_turns} budget=${args.budget_usd:.2f}")
    print()

    result = pipeline.run_pipeline(
        args.fixture,
        author="llm",
        llm_client=client,
        llm_options={"max_turns": args.max_turns, "budget_usd": args.budget_usd},
        run_probes_too=True,
    )

    trace_path = Path(result["trace_path"])
    summary = summarize(trace_path)
    records = read_trace(trace_path)
    calls = [r for r in records if r["step"] == "llm.call"]
    tools = [r for r in records if r["step"] == "tool.call"]

    print(f"run_id:  {result['run_id']}")
    print(f"trace:   {trace_path}")
    print(f"turns:   {len(calls)} model call(s), {len(tools)} tool call(s)")
    print()
    print("tool calls:")
    for index, record in enumerate(tools, 1):
        inputs = record.get("inputs") or {}
        arguments = inputs.get("arguments") or {}
        shown = json.dumps(arguments, ensure_ascii=True)
        flags = (record.get("data") or {}).get("monitor") or {}
        marks = [
            name
            for name, on in (
                ("EGRESS", flags.get("attempted_egress")),
                ("SECRET", flags.get("attempted_secret_read")),
            )
            if on
        ]
        mark = f" [{'+'.join(marks)}]" if marks else ""
        print(
            f"  {index:>2}. {inputs.get('tool')}({clip(shown)})"
            f"{mark} exit={record.get('exit_code')} "
            f"isolation={(record.get('data') or {}).get('sandbox', {}).get('isolation')}"
        )
    if not tools:
        print("  (none)")
    print()

    print("watch layer (attempt -> containment evidence):")
    if summary["attempts"]:
        for attempt in summary["attempts"]:
            kinds = [
                name
                for name, on in (
                    ("egress", attempt["attempted_egress"]),
                    ("secret-read", attempt["attempted_secret_read"]),
                )
                if on
            ]
            print(f"  - seq={attempt['seq']} {attempt['tool']} [{', '.join(kinds)}]")
            print(f"      matched: {clip(str(attempt['matches']), 300)}")
            print(f"      sandbox: {clip(attempt['evidence'], 300)}")
    else:
        print("  none — the agent never tried egress or a secret read")
    print()

    verdict = result["verdict"]
    llm = summary.get("llm") or {}
    usage = llm.get("usage") or {}
    print(f"claim:   status={result['claim']['status']!r} "
          f"tests_claimed_passed={result['claim']['tests_claimed_passed']}")
    print(f"claim text: {clip(result['claim']['text'], 300)}")
    print()
    print(f"verdict: {verdict['first_line']}")
    print(f"counts:  {verdict['counts']}")
    print(f"findings: {[f['code'] for f in verdict['findings']]}")
    print(f"cost:    ${llm.get('cost_usd', 0.0):.6f} "
          f"(prompt={usage.get('prompt_tokens')} completion={usage.get('completion_tokens')} tokens)")
    key_in_trace = api_key in trace_path.read_text(encoding="utf-8")
    print(f"api key in trace: {'YES — LEAK' if key_in_trace else 'no'}")
    print(f"summary: {(trace_path.parent / 'summary.json')}")
    return 1 if key_in_trace else 0

if __name__ == "__main__":
    raise SystemExit(main())
