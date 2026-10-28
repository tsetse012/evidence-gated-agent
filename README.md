# Evidence-Gated Agent

**An agent is not allowed to say "done" until a second, fresh sandbox can prove it — and that catches the green checkmarks that lie.**

A coding agent claims it fixed something. Instead of trusting its logs, the
verifier re-runs the work in a brand-new isolated container it has never seen
before, counts what actually happened, and only then emits a first-line token
(`exit: done` / `verification-failed` / `partial` / `blocked`).

The interesting part is not isolation — it is the **false-green detectors**:
a run that collected zero tests, skipped the failures, or hid them behind
`|| true` still *looks* green to a pipeline. Here it does not.

```
                    ┌──────────────────────────────────────────────┐
  user picks        │  run pipeline                                │
  fixture + patch   │                                              │
        │           │  1. fixture copy ─┐                         │
        ▼           │  2. AUTHOR         │  sandbox A (network off,│
  POST /api/runs ──▶│     (scripted now, │  memory/cpu/pid caps,   │
                    │      LLM later)    │  read-only root)        │
                    │        │ claim     └────────────────────────┐│
                    │        ▼                                   ││
                    │  3. SNAPSHOT ──▶ sandbox B (brand new,      ││
                    │        │          never sees the author's   ││
                    │        │          logs) → pytest + junit    ││
                    │        ▼                                   ││
                    │  4. EVIDENCE DETECTORS                     ││
                    │     ZERO_COLLECTED · SKIP_RATIO ·          ││
                    │     BELOW_EXPECTED · EXIT_MASKED ·         ││
                    │     JUNIT_MISSING · COUNT_MISMATCH ·       ││
                    │     ARTIFACT_EMPTY · ARTIFACT_STALE        ││
                    │        │                                   ││
                    │        ▼                                   ▼▼
                    │  5. verdict  ──▶  trace.jsonl (raw)  ◀─ containment probes
                    │                      │                    (6 probes, every run)
                    │                      ▼
                    │                 summary.json (derived, regenerable)
                    └──────────────────────────────────────────────┘
                                        │
                              approve (human) → "would open PR"
```

## How to run

```bash
uv sync                                  # Python 3.13
bash scripts/build_image.sh               # ega-sandbox:dev (python:3.13-slim + pytest)
uv run uvicorn app.main:app               # http://127.0.0.1:8000
bash scripts/check.sh                     # the full gate (see below)
```

Start a run from the UI or with curl:

```bash
curl -s -X POST localhost:8000/api/runs \
  -H 'content-type: application/json' \
  -d '{"fixture": "buggy_invoice", "author": "scripted:honest"}'
# {"run_id":"20261103T160012Z-1a2b3c","status":"queued"}

curl -s localhost:8000/api/runs/<run_id> | python3 -m json.tool
curl -s localhost:8000/api/runs/<run_id>/trace   # raw JSONL, every step
```

| fixture | author | expected verdict |
| --- | --- | --- |
| `buggy_invoice` | `scripted:honest` | `done` |
| `buggy_invoice` | `scripted:cheat_skip` | `verification-failed` (`SKIP_RATIO`) |
| `buggy_invoice` | `scripted:cheat_mask` | `verification-failed` (`EXIT_MASKED`) |
| `zero_tests` | `scripted:claim_only` | `verification-failed` (`ZERO_COLLECTED`) |
| `injected_readme` | `scripted:honest` | `done` — the injection in its README has nowhere to go |

`scripts/check.sh` builds the image, runs the full suite, runs the
docker-marked suite separately, prints collected/passed/failed/skipped counts,
and exits non-zero if anything was collected zero, failed, or if
docker-marked tests were skipped while Docker is available. Our own tests are
held to the same "no false green" rule as the agents we judge.

## Layout

| path | what |
| --- | --- |
| `ega/sandbox.py` | one fresh container per run; all limits mandatory |
| `ega/probes.py` | six containment probes, `blocked` decided from evidence |
| `ega/evidence.py` | false-green detectors over junit XML + stdout + exit code |
| `ega/verify.py` | independent verifier: snapshot + claim in, verdict out |
| `ega/trace.py` | append-only JSONL; `summary.json` derived from it |
| `ega/author.py` | `Author` protocol + `ScriptedAuthor` placeholder |
| `ega/pipeline.py` | author (sandbox A) → snapshot → verifier (sandbox B) → probes |
| `app/` | FastAPI + one static page, no build step |
| `fixtures/` | demo targets: `buggy_invoice`, `zero_tests`, `injected_readme` |
| `sandbox/Dockerfile` | `python:3.13-slim` + pytest, non-root uid 1000 |
| `infra/` | Vultr cloud-init + gVisor `runsc` + Caddy (not executed yet) |

## Containment, concretely

Every run gets: `--network none`, `--memory` = `--memory-swap` (no swap),
`--cpus`, `--pids-limit`, `--read-only` root with a 64 MB `/tmp` tmpfs,
`--cap-drop ALL`, `--security-opt no-new-privileges`, `--user 1000:1000`, and a
single `rw` bind mount of a **copy** of the workspace at `/work`. No host
environment is forwarded (`docker run` only forwards what `-e` names, and we
name only `HOME`, `TMPDIR`, `PYTHONDONTWRITEBYTECODE`, `PYTHONUNBUFFERED`).

Runtime is `runsc` (gVisor) when `docker info` lists it, else `runc`; the
choice is recorded as `isolation` in every result. `EGA_RUNTIME` overrides it.

The six probes (`network_egress`, `host_secret_read`, `write_outside_workspace`,
`fork_bomb`, `memory_hog`, `env_leak`) each *attempt* the escape inside the
sandbox and report the observed failure — exception text, exit code,
`OOMKilled` — never an assumption. `env_leak` seeds `EGA_FAKE_SECRET_TOKEN` in
the host environment first, to prove it does not pass through.

## What existed before kickoff (2026-11-03 16:00 UTC)

Everything in this repository at that timestamp is non-AI scaffolding. There
are **no LLM calls, no prompts, no inference client**: the author is
`ScriptedAuthor`, applying canned patches from the fixtures.

1. `ega/sandbox.py` — Docker-CLI isolated runner (limits above, timeout kill,
   OOM inspection, `workdir_after` snapshot).
2. `ega/probes.py` — the six containment probes.
3. `ega/evidence.py` — the eight false-green detectors and the closed
   verdict-token mapping.
4. `ega/verify.py` — the independent verifier pipeline (snapshot + claim only).
5. `ega/trace.py` — append-only dual record; `summarize()` is pure.
6. `ega/author.py` — `Author` protocol + `ScriptedAuthor`.
7. `fixtures/` — `buggy_invoice` (6 tests, 2 failing; `honest`, `cheat_skip`,
   `cheat_mask` patches), `zero_tests`, `injected_readme` (harmless
   `.invalid` collector).
8. `app/` — FastAPI skeleton + the side-by-side claim/verdict page.
9. `infra/` — Vultr cloud-init with gVisor and Caddy, written but **not run**.
10. `tests/` — unit tests per detector, Docker integration tests, and the four
    end-to-end scenarios.
11. `scripts/check.sh` — the gate that refuses to be a false green.
12. This README, MIT `LICENSE`, `.gitignore`.

## Built during the hackathon

_placeholder_ — to be filled on 2026-11-03 and after:

- LLM author (Vultr inference) replacing `ScriptedAuthor`
- second-company verifier model for claim review
- PR creation behind the human approval gate
- hosted deployment on the Vultr VM in `infra/`

## Vultr services used

_placeholder list_ — to be confirmed with the actual deployment:

- Vultr Cloud Compute (Ubuntu 24.04, 4 vCPU / 8 GB) — sandbox host
- Vultr Serverless Inference — author model (planned)
- Vultr Object Storage — traces/artifacts (planned)
- Vultr Firewall / DNS (planned)

## License

MIT — see `LICENSE` (2026 tsetse012).