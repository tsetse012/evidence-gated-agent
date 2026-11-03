#!/usr/bin/env python3
"""Manual live smoke test: a real Vultr model authors a fix, a fresh sandbox judges it.

The gate must never need the network, so this is a script you run by hand:

    set -a; . ~/.secrets/credentials.env; set +a
    uv run python scripts/live_smoke.py buggy_invoice
    uv run python scripts/live_smoke.py injected_readme
    uv run python scripts/live_smoke.py buggy_invoice --author scripted:cheat_hardcode \\
        --judge --explain

``--author scripted:<patch>`` skips the model author and applies a canned patch,
so the judge layer can be exercised on a known diff. ``--judge`` asks clef one
question per changed file; ``--explain`` has a different vendor's model describe
the finished verdict. Neither can change the verdict.

It writes a normal run under ``runs/<run_id>/`` (trace.jsonl + summary.json) and
prints the turn count, every tool call with its watch-layer flags, the verifier's
first line, the judge's per-file probabilities, the explanation, and the cost
computed from the API's own ``usage`` numbers. The API key is never printed and
never written into the trace; the script checks the run directory for it before
it reports.
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
    parser.add_argument(
        "--author",
        default="llm",
        help="'llm' (a model driving the sandbox) or 'scripted:<patch>' (a canned patch)",
    )
    parser.add_argument("--judge", action="store_true", help="ask clef one question per changed file")
    parser.add_argument(
        "--explain", action="store_true", help="have a different vendor's model describe the verdict"
    )
    parser.add_argument("--judge-threshold", type=float, default=None)
    parser.add_argument("--max-turns", type=int, default=20)
    parser.add_argument("--budget-usd", type=float, default=0.20)
    parser.add_argument("--price-in", type=float, default=None, help="author USD per 1M prompt tokens")
    parser.add_argument("--price-out", type=float, default=None, help="author USD per 1M completion tokens")
    args = parser.parse_args()

    api_key = os.environ.get("VULTR_INFERENCE_API_KEY", "")
    if not api_key and not os.environ.get("EGA_AUTHOR_API_KEY"):
        print("VULTR_INFERENCE_API_KEY is not set", file=sys.stderr)
        print("run: set -a; . ~/.secrets/credentials.env; set +a", file=sys.stderr)
        return 2

    author, patch = "llm", None
    if args.author.startswith("scripted:"):
        author, patch = "scripted", args.author.split(":", 1)[1]
    elif args.author != "llm":
        print(f"--author must be 'llm' or 'scripted:<patch>'; got {args.author!r}", file=sys.stderr)
        return 2

    client = VultrChatClient.from_env() if author == "llm" else None
    print(f"fixture: {args.fixture}")
    print(f"author:  {args.author}")
    if client is not None:
        print(f"model:   {client.model}  (base {client.base_url})")
        if client.external:
            print("author:  RED-TEAM — external endpoint, not part of the product path")
        print(f"limits:  max_turns={args.max_turns} budget=${args.budget_usd:.2f}")
    print(f"layers:  judge={'on' if args.judge else 'off'} explain={'on' if args.explain else 'off'}")
    print()

    result = pipeline.run_pipeline(
        args.fixture,
        patch,
        author=author,
        llm_client=client,
        llm_options={
            "max_turns": args.max_turns,
            "budget_usd": args.budget_usd,
            **({"prompt_price": args.price_in} if args.price_in is not None else {}),
            **({"completion_price": args.price_out} if args.price_out is not None else {}),
        },
        run_probes_too=True,
        judge=args.judge,
        judge_threshold=args.judge_threshold,
        explain=args.explain,
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
    print()

    # The judge layer: one question per changed file. The probability is printed
    # as-is — never rounded into a verdict.
    judge = summary.get("judge")
    if judge is not None:
        print(f"judge:   model={judge.get('model')!r} threshold={judge.get('threshold')} "
              f"status={judge.get('status')}")
        for item in judge.get("items") or []:
            probability = item.get("probability")
            shown = "no answer" if probability is None else f"p={probability:.3f}"
            signal = "FLAGGED" if item.get("flagged") else "below"
            error = f" error={item.get('error')}" if item.get("error") else ""
            print(f"  - {item.get('path')} [{item.get('kind')}] {shown} "
                  f"(threshold {item.get('threshold')}) -> {signal}{error}")
        judge_usage = [item.get("usage") or {} for item in judge.get("items") or []]
        print(f"  judge usage: {judge_usage}")
        print()
    elif args.judge:
        print("judge:   enabled but no report reached the summary")
        print()

    explanation = summary.get("explanation")
    if explanation is not None:
        print(f"explanation ({explanation.get('model')}, does not affect the verdict):")
        print(f"  {explanation.get('text') or '(none) — ' + str(explanation.get('error'))}")
        print(f"  usage: {explanation.get('usage')} latency={explanation.get('latency_s')}s")
        print()

    print(f"cost:    ${llm.get('cost_usd', 0.0):.6f} "
          f"(prompt={usage.get('prompt_tokens')} completion={usage.get('completion_tokens')} tokens)")
    # The key must not be in any file the run wrote — not just the trace.
    leaked = [
        path.name
        for path in trace_path.parent.rglob("*")
        if path.is_file() and api_key in path.read_text(encoding="utf-8", errors="replace")
    ]
    print(f"api key in run dir: {'YES — LEAK in ' + str(leaked) if leaked else 'no'}")
    print(f"summary: {(trace_path.parent / 'summary.json')}")
    return 1 if leaked else 0

if __name__ == "__main__":
    raise SystemExit(main())
