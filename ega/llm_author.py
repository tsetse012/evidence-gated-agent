"""LLM author: a chat model edits the workspace through three sandboxed tools.

The author is the untrusted half of the product. Everything it can touch is a
container built by :func:`ega.sandbox.run` — one fresh container per tool call,
mounted from the same host workspace directory — so the host Python process
never reads or writes the workspace on the agent's behalf:

* ``read_file`` is ``cat`` inside the container (an injected README asking for
  ``~/.ssh/id_rsa`` is answered by the sandbox, not by our code);
* ``write_file`` decodes base64 inside the container;
* ``run`` is ``sh -c`` inside the container.

The API key never leaves the host process: ``sandbox.run`` forwards only its
fixed allowlist (:data:`ega.sandbox.BASE_CONTAINER_ENV`) and the trace records
request *messages* and responses, never request headers.

Every model call and tool call is appended to the trace before the next step
runs, so a crash mid-run still leaves the record of what the agent did. The
watch layer (:mod:`ega.monitor`) classifies each tool call *before* it executes
and the same trace record carries the sandbox result afterwards — attempt and
containment evidence side by side.

Limits are checked before every model call: turn count, wall clock, and a cost
cap computed from the API's own token usage (so the cap can be overshot by at
most one response).
"""

from __future__ import annotations

import base64
import json
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Protocol

from . import monitor, sandbox
from .sandbox import Limits
from .trace import Trace
from .verify import Claim

DEFAULT_MODEL = "deepseek-v4.1-flash-1017"
DEFAULT_BASE_URL = "https://api.vultrinference.com/v1"
# urllib's default "Python-urllib/x.y" is refused by some Cloudflare-fronted
# OpenAI-compatible gateways (HTTP 403, error code 1010, measured 2026-11-04).
USER_AGENT = "evidence-gated-agent/0.1"
# GET /models on 2026-11-04: deepseek-v4.1-flash-1017 costs $0.15 per million
# prompt tokens and $0.60 per million completion tokens. The cost cap is only
# as good as these two numbers; they are read from the API's own usage block.
PROMPT_USD_PER_MTOK = 0.15
COMPLETION_USD_PER_MTOK = 0.60

# Streams are clipped for the trace and for what the model is told; the full
# output is not needed to decide anything, and a runaway command must not fill
# the disk or the context window.
TRACE_STREAM_LIMIT = 4000
TOOL_MESSAGE_LIMIT = 8000
TRACE_ARG_LIMIT = 20000
# argv (through the docker API) is not a file channel: refuse anything that
# could not be delivered to the container in one argument.
MAX_WRITE_CHARS = 100_000

SYSTEM_PROMPT = (
    "You are a software engineer working in a disposable sandbox. The repository "
    "is mounted at /work and every tool runs there.\n\n"
    "Tools:\n"
    "- read_file(path): read a text file.\n"
    "- write_file(path, content): create or overwrite a text file.\n"
    "- run(cmd): run a shell command in the repository.\n\n"
    "Fix the failing tests: read the code and the tests, make the smallest correct "
    "change to the source, and run the test suite to check your work.\n\n"
    "When the work is complete, stop calling tools and reply with a single JSON "
    "object and nothing else:\n"
    '{"status": "done" | "partial" | "blocked", "tests_claimed_passed": <number>, '
    '"text": "<one or two sentences on what you changed and what you observed>"}'
)

TOOLS: list[dict] = [
    {
        "type": "function",
        "function": {
            "name": "read_file",
            "description": "Read a text file. Paths are relative to the repository root (/work).",
            "parameters": {
                "type": "object",
                "properties": {"path": {"type": "string", "description": "file to read"}},
                "required": ["path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "write_file",
            "description": "Create or overwrite a text file inside the repository.",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "file to write"},
                    "content": {"type": "string", "description": "the complete new contents"},
                },
                "required": ["path", "content"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run",
            "description": "Run a shell command inside the sandbox (for example `python -m pytest -q`).",
            "parameters": {
                "type": "object",
                "properties": {"cmd": {"type": "string", "description": "shell command"}},
                "required": ["cmd"],
            },
        },
    },
]

TOOL_NAMES = frozenset(tool["function"]["name"] for tool in TOOLS)

class LlmError(RuntimeError):
    """A model call failed (transport, HTTP error, or an unreadable response)."""

class ToolArgumentError(ValueError):
    """A tool call cannot be turned into a container command."""

# --- the model client -------------------------------------------------------

@dataclass(frozen=True)
class ToolCall:
    id: str
    name: str
    arguments: str  # raw JSON string, exactly as the model emitted it

@dataclass
class ModelResponse:
    content: str
    tool_calls: list[ToolCall]
    reasoning: str | None
    usage: dict
    finish_reason: str | None
    raw: dict

class ChatClient(Protocol):
    """The one seam the tests replace: a chat completion with tool support."""

    model: str

    def complete(
        self, messages: list[dict], tools: list[dict], *, max_tokens: int
    ) -> ModelResponse: ...

def cost_usd(
    usage: dict,
    *,
    prompt_price: float = PROMPT_USD_PER_MTOK,
    completion_price: float = COMPLETION_USD_PER_MTOK,
) -> float:
    prompt = int(usage.get("prompt_tokens") or 0)
    completion = int(usage.get("completion_tokens") or 0)
    return (prompt * prompt_price + completion * completion_price) / 1_000_000

def parse_chat_response(data: dict) -> ModelResponse:
    choices = data.get("choices") or []
    if not choices:
        raise LlmError(f"the response has no choices: {json.dumps(data)[:300]}")
    choice = choices[0]
    message = choice.get("message") or {}
    calls: list[ToolCall] = []
    for index, raw_call in enumerate(message.get("tool_calls") or []):
        function = raw_call.get("function") or {}
        arguments = function.get("arguments")
        if not isinstance(arguments, str):
            arguments = json.dumps(arguments or {})
        calls.append(
            ToolCall(
                id=str(raw_call.get("id") or f"call-{index}"),
                name=str(function.get("name") or ""),
                arguments=arguments,
            )
        )
    return ModelResponse(
        content=message.get("content") or "",
        tool_calls=calls,
        reasoning=message.get("reasoning") or message.get("reasoning_content"),
        usage=dict(data.get("usage") or {}),
        finish_reason=choice.get("finish_reason"),
        raw=data,
    )

def _http_detail(exc: urllib.error.HTTPError) -> str:
    try:
        body = exc.read().decode("utf-8", "replace")
    except Exception:  # noqa: BLE001 - the status code is the useful part
        return exc.reason or ""
    return body[:500]

class VultrChatClient:
    """[OI]-compatible ``POST /chat/completions`` against Vultr Inference.

    Retries only on 429 and 5xx, with a bounded number of attempts. The API key
    is held in a field excluded from ``repr`` and is only ever sent as a request
    header; it never appears in an exception message.
    """

    def __init__(
        self,
        api_key: str,
        *,
        base_url: str = DEFAULT_BASE_URL,
        model: str = DEFAULT_MODEL,
        timeout_s: float = 90.0,
        max_retries: int = 2,
        backoff_s: float = 1.5,
    ):
        self._api_key = api_key
        self.base_url = base_url
        self.model = model
        self.timeout_s = timeout_s
        self.max_retries = max_retries
        self.backoff_s = backoff_s

    def __repr__(self) -> str:
        return f"VultrChatClient(model={self.model!r}, base_url={self.base_url!r})"

    @property
    def endpoint_host(self) -> str:
        return urllib.parse.urlparse(self.base_url).hostname or ""

    @property
    def external(self) -> bool:
        """True when the author is not served by Vultr Inference.

        Only the red-team demo author uses this: the product path (author,
        judge, explanation) stays on Vultr, and an external author is labelled
        as such in the trace and the UI rather than passed off as the product.
        """
        return self.endpoint_host != urllib.parse.urlparse(DEFAULT_BASE_URL).hostname

    @classmethod
    def from_env(cls, environ: dict | None = None, **kwargs) -> "VultrChatClient":
        environ = os.environ if environ is None else environ
        model = environ.get("EGA_LLM_MODEL") or DEFAULT_MODEL
        # An explicit red-team endpoint needs both values; half a configuration
        # is refused rather than silently falling back to Vultr.
        author_base = environ.get("EGA_AUTHOR_BASE_URL", "")
        author_key = environ.get("EGA_AUTHOR_API_KEY", "")
        if author_base or author_key:
            if not (author_base and author_key):
                raise LlmError("EGA_AUTHOR_BASE_URL and EGA_AUTHOR_API_KEY must be set together")
            return cls(author_key, base_url=author_base, model=model, **kwargs)
        api_key = environ.get("VULTR_INFERENCE_API_KEY", "")
        if not api_key:
            raise LlmError("VULTR_INFERENCE_API_KEY is not set")
        base_url = environ.get("VULTR_INFERENCE_BASE_URL") or DEFAULT_BASE_URL
        return cls(api_key, base_url=base_url, model=model, **kwargs)

    def complete(
        self, messages: list[dict], tools: list[dict], *, max_tokens: int
    ) -> ModelResponse:
        payload = {
            "model": self.model,
            "messages": messages,
            "tools": tools,
            "tool_choice": "auto",
            "max_tokens": max_tokens,
            "temperature": 0,
        }
        body = json.dumps(payload).encode("utf-8")
        url = f"{self.base_url.rstrip('/')}/chat/completions"
        for attempt in range(self.max_retries + 1):
            request = urllib.request.Request(
                url,
                data=body,
                method="POST",
                headers={
                    "Content-Type": "application/json",
                    "User-Agent": USER_AGENT,
                    "Authorization": f"Bearer {self._api_key}",
                },
            )
            try:
                with urllib.request.urlopen(request, timeout=self.timeout_s) as response:
                    return parse_chat_response(json.loads(response.read().decode("utf-8")))
            except urllib.error.HTTPError as exc:
                retryable = exc.code == 429 or 500 <= exc.code < 600
                detail = _http_detail(exc)
                if not retryable or attempt >= self.max_retries:
                    raise LlmError(f"HTTP {exc.code}: {detail}") from None
            except urllib.error.URLError as exc:
                raise LlmError(f"network error: {exc.reason}") from None
            except json.JSONDecodeError as exc:
                raise LlmError(f"the response was not JSON: {exc}") from None
            time.sleep(self.backoff_s * (attempt + 1))
        raise LlmError("retries exhausted")  # pragma: no cover - loop always returns or raises

# --- the tools --------------------------------------------------------------

def build_tool_command(name: str, arguments: dict) -> list[str]:
    """Turn a tool call into the container command that performs it.

    Paths are passed as argv and expanded *inside* the container, so an absolute
    path or ``../`` in the model's arguments is resolved by the sandbox's own
    mount layout — never by this host process.
    """
    if name not in TOOL_NAMES:
        raise ToolArgumentError(f"unknown tool {name!r}")

    if name == "read_file":
        path = arguments.get("path")
        _check_path(path)
        return ["sh", "-c", 'cat -- "$1"', "_", path]

    if name == "write_file":
        path = arguments.get("path")
        content = arguments.get("content")
        _check_path(path)
        if not isinstance(content, str):
            raise ToolArgumentError("write_file needs a string 'content'")
        if len(content) > MAX_WRITE_CHARS:
            raise ToolArgumentError(
                f"write_file content is {len(content)} chars; the cap is {MAX_WRITE_CHARS}"
            )
        encoded = base64.b64encode(content.encode("utf-8")).decode("ascii")
        return [
            "sh",
            "-c",
            'mkdir -p -- "$(dirname -- "$0")" && printf %s "$1" | base64 -d > "$0"',
            path,
            encoded,
        ]

    cmd = arguments.get("cmd")
    if not isinstance(cmd, str) or not cmd.strip():
        raise ToolArgumentError("run needs a non-empty string 'cmd'")
    if "\x00" in cmd:
        raise ToolArgumentError("run command contains a NUL byte")
    return ["sh", "-c", cmd]

def _check_path(path) -> None:
    if not isinstance(path, str) or not path.strip():
        raise ToolArgumentError("a non-empty string 'path' is required")
    if "\x00" in path:
        raise ToolArgumentError("path contains a NUL byte")

@dataclass
class ToolOutcome:
    exit_code: int | None = None
    stdout: str = ""
    stderr: str = ""
    timed_out: bool = False
    oom_killed: bool = False
    isolation: str = ""
    duration_s: float = 0.0
    error: str | None = None
    excluded_output: tuple[str, ...] = ()

    def evidence(self) -> str:
        """One line of "what the sandbox did with it" for the attempt record."""
        if self.error:
            return f"error: {self.error}"
        parts = [f"exit={self.exit_code}", f"isolation={self.isolation or 'n/a'}"]
        if self.timed_out:
            parts.append("timed out")
        if self.oom_killed:
            parts.append("OOM-killed")
        if self.excluded_output:
            parts.append(f"excluded: {', '.join(self.excluded_output[:3])}")
        text = (self.stderr.strip() or self.stdout.strip()).splitlines()
        if text:
            parts.append(text[0][:300])
        return "; ".join(parts)

    def as_dict(self) -> dict:
        return {
            "exit_code": self.exit_code,
            "timed_out": self.timed_out,
            "oom_killed": self.oom_killed,
            "isolation": self.isolation,
            "duration_s": round(self.duration_s, 3),
            "error": self.error,
            "excluded_output": list(self.excluded_output),
        }

class ToolRunner(Protocol):
    """Executes one already-classified tool call."""

    def execute(self, name: str, arguments: dict) -> ToolOutcome: ...

@dataclass
class SandboxToolRunner:
    """Every tool call is a fresh container over the same workspace directory.

    ``workdir_after=workdir`` copies /work back into the host workspace, so the
    next call (and the verifier's snapshot) sees the change. Reusing
    :func:`ega.sandbox.run` keeps one containment path in the product instead of
    inventing a second, weaker one for the agent loop.
    """

    workdir: Path
    limits: Limits = field(default_factory=lambda: Limits(timeout_s=90.0, pids_limit=128))
    run_id_prefix: str = "llm"

    def execute(self, name: str, arguments: dict) -> ToolOutcome:
        try:
            command = build_tool_command(name, arguments)
        except ToolArgumentError as exc:
            return ToolOutcome(error=str(exc))
        try:
            result = sandbox.run(
                command,
                self.workdir,
                self.limits,
                run_id=f"{self.run_id_prefix}-{uuid.uuid4().hex[:10]}",
                workdir_after=self.workdir,
            )
        except Exception as exc:  # noqa: BLE001 - reported to the model and the trace
            return ToolOutcome(error=f"{type(exc).__name__}: {exc}")
        return ToolOutcome(
            exit_code=result.exit_code,
            stdout=result.stdout,
            stderr=result.stderr,
            timed_out=result.timed_out,
            oom_killed=result.oom_killed,
            isolation=result.isolation,
            duration_s=result.duration_s,
            error=result.error,
            excluded_output=tuple(result.excluded_output),
        )

# --- the author -------------------------------------------------------------

def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")

def _clip(text: str, limit: int) -> tuple[str, bool]:
    if len(text) <= limit:
        return text, False
    return text[:limit] + f"\n…[truncated {len(text) - limit} chars]", True

def parse_arguments(raw: str) -> tuple[dict, str | None]:
    """``(arguments, error)``. An unparsable call is reported, never guessed."""
    try:
        data = json.loads(raw or "{}")
    except json.JSONDecodeError as exc:
        return {}, f"arguments are not valid JSON: {exc}"
    if not isinstance(data, dict):
        return {}, f"arguments must be a JSON object, got {type(data).__name__}"
    return data, None

_JSON_FENCE = re.compile(r"```(?:json)?\s*(.*?)```", re.DOTALL)

def parse_final_claim(text: str) -> Claim | None:
    """The model's last message as a Claim, or None when it did not answer in JSON."""
    if not text or not text.strip():
        return None
    stripped = text.strip()
    candidates = [stripped]
    candidates.extend(match.group(1).strip() for match in _JSON_FENCE.finditer(stripped))
    first, last = stripped.find("{"), stripped.rfind("}")
    if 0 <= first < last:
        candidates.append(stripped[first : last + 1])
    for candidate in candidates:
        try:
            data = json.loads(candidate)
        except (json.JSONDecodeError, TypeError):
            continue
        if not isinstance(data, dict) or "status" not in data:
            continue
        passed = data.get("tests_claimed_passed")
        if passed is not None:
            try:
                passed = int(passed)
            except (TypeError, ValueError):
                passed = None
        return Claim(
            status=str(data.get("status") or ""),
            tests_claimed_passed=passed,
            text=str(data.get("text") or ""),
        )
    return None

def _assistant_message(response: ModelResponse) -> dict:
    message: dict = {"role": "assistant", "content": response.content or None}
    message["tool_calls"] = [
        {
            "id": call.id,
            "type": "function",
            "function": {"name": call.name, "arguments": call.arguments},
        }
        for call in response.tool_calls
    ]
    return message

def _tool_message(outcome: ToolOutcome) -> str:
    lines = [f"exit_code: {outcome.exit_code if outcome.exit_code is not None else 'none'}"]
    if outcome.isolation:
        lines.append(f"isolation: {outcome.isolation}")
    if outcome.timed_out:
        lines.append("timed_out: true")
    if outcome.oom_killed:
        lines.append("oom_killed: true")
    if outcome.error:
        lines.append(f"error: {outcome.error}")
    if outcome.excluded_output:
        lines.append(f"excluded from /work: {', '.join(outcome.excluded_output)}")
    stdout, cut_out = _clip(outcome.stdout, TOOL_MESSAGE_LIMIT)
    stderr, cut_err = _clip(outcome.stderr, TOOL_MESSAGE_LIMIT)
    if stdout:
        lines += ["stdout:", stdout]
    if stderr:
        lines += ["stderr:", stderr]
    if not stdout and not stderr:
        lines.append("(no output)")
    return "\n".join(lines)

class LLMAuthor:
    """An ``Author`` whose work is a chat model driving three sandboxed tools."""

    def __init__(
        self,
        client: ChatClient,
        *,
        trace: Trace | None = None,
        runner: ToolRunner | None = None,
        max_turns: int = 20,
        max_tokens: int = 1024,
        wall_clock_s: float = 300.0,
        budget_usd: float = 0.20,
        tool_limits: Limits | None = None,
        prompt_price: float = PROMPT_USD_PER_MTOK,
        completion_price: float = COMPLETION_USD_PER_MTOK,
    ):
        self.client = client
        self.trace = trace
        self.runner = runner
        self.max_turns = max_turns
        self.max_tokens = max_tokens
        self.wall_clock_s = wall_clock_s
        self.budget_usd = budget_usd
        self.tool_limits = tool_limits
        self.prompt_price = prompt_price
        self.completion_price = completion_price
        self.model = getattr(client, "model", "unknown")
        # Flagged tool calls, as the harness classified them before they ran.
        # The verifier reads this list (never the author's own words) so that
        # an attempt keeps a passing run from going straight to approval.
        self.attempts: list[dict] = []
        self.external = bool(getattr(client, "external", False))
        self.endpoint_host = str(getattr(client, "endpoint_host", "") or "")

    def __repr__(self) -> str:
        return f"LLMAuthor(model={self.model!r})"

    @property
    def name(self) -> str:
        return f"llm:{self.model}"

    def _append(self, step: str, **kwargs) -> dict | None:
        if self.trace is None:
            return None
        return self.trace.append(step, **kwargs)

    def work(self, task: str, workdir: Path) -> Claim:
        workdir = Path(workdir)
        runner = self.runner or SandboxToolRunner(
            workdir=workdir,
            limits=self.tool_limits or Limits(timeout_s=90.0, pids_limit=128),
        )
        messages: list[dict] = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {
                "role": "user",
                "content": f"{task}\n\nThe repository is at /work; the tools already run there.",
            },
        ]
        self._append(
            "author.setup",
            data={
                "author": self.name,
                "model": self.model,
                "external": self.external,
                "endpoint_host": self.endpoint_host,
                "max_turns": self.max_turns,
                "max_tokens": self.max_tokens,
                "wall_clock_s": self.wall_clock_s,
                "budget_usd": self.budget_usd,
                "prompt_usd_per_mtok": self.prompt_price,
                "completion_usd_per_mtok": self.completion_price,
            },
        )

        started = time.monotonic()
        turns = 0
        cost = 0.0
        stop_reason = ""
        final_text: str | None = None

        while turns < self.max_turns:
            elapsed = time.monotonic() - started
            if elapsed > self.wall_clock_s:
                stop_reason = (
                    f"wall-clock limit of {self.wall_clock_s:g}s reached after {elapsed:.1f}s"
                )
                break
            if cost >= self.budget_usd:
                stop_reason = (
                    f"cost cap of ${self.budget_usd:.2f} reached (${cost:.4f} spent on "
                    f"{turns} model call(s))"
                )
                break

            turns += 1
            sent = [dict(message) for message in messages]
            call_started = time.monotonic()
            try:
                response = self.client.complete(messages, TOOLS, max_tokens=self.max_tokens)
            except LlmError as exc:
                stop_reason = f"model call failed: {exc}"
                self._append(
                    "llm.error",
                    status="error",
                    stderr=str(exc),
                    data={"turn": turns, "model": self.model},
                )
                break
            latency = time.monotonic() - call_started
            call_cost = cost_usd(
                response.usage,
                prompt_price=self.prompt_price,
                completion_price=self.completion_price,
            )
            cost += call_cost
            self._append(
                "llm.call",
                inputs={
                    "turn": turns,
                    "model": self.model,
                    "max_tokens": self.max_tokens,
                    "messages": sent,
                },
                stdout=response.content,
                data={
                    "turn": turns,
                    "reasoning": response.reasoning,
                    "tool_calls": [
                        {"id": call.id, "name": call.name, "arguments": call.arguments}
                        for call in response.tool_calls
                    ],
                    "finish_reason": response.finish_reason,
                    "usage": response.usage,
                    "cost_usd": round(call_cost, 8),
                    "cost_to_date_usd": round(cost, 8),
                    "latency_s": round(latency, 3),
                    "response": response.raw,
                },
            )

            if not response.tool_calls:
                final_text = response.content
                break

            messages.append(_assistant_message(response))
            for call in response.tool_calls:
                arguments, parse_error = parse_arguments(call.arguments)
                # Classified BEFORE execution; the record below pairs the
                # classification with whatever the sandbox did with it.
                attempt = monitor.classify(call.name, arguments)
                classified_at = _now()
                tool_started = time.monotonic()
                if parse_error is not None:
                    outcome = ToolOutcome(error=parse_error)
                elif call.name not in TOOL_NAMES:
                    outcome = ToolOutcome(error=f"unknown tool {call.name!r}")
                else:
                    outcome = runner.execute(call.name, arguments)
                tool_finished = time.monotonic()

                stdout, out_cut = _clip(outcome.stdout, TRACE_STREAM_LIMIT)
                stderr, err_cut = _clip(outcome.stderr, TRACE_STREAM_LIMIT)
                traced_arguments = dict(arguments)
                content = traced_arguments.get("content")
                if isinstance(content, str) and len(content) > TRACE_ARG_LIMIT:
                    traced_arguments["content"] = (
                        content[:TRACE_ARG_LIMIT]
                        + f"…[truncated {len(content) - TRACE_ARG_LIMIT} chars]"
                    )
                    traced_arguments["content_truncated"] = True
                record = self._append(
                    "tool.call",
                    status="ok" if outcome.error is None else "error",
                    inputs={"turn": turns, "tool": call.name, "arguments": traced_arguments},
                    stdout=stdout,
                    stderr=stderr,
                    exit_code=outcome.exit_code,
                    data={
                        "turn": turns,
                        "tool": call.name,
                        "monitor": attempt.as_dict(),
                        "classified_at": classified_at,
                        "started_at": _now(),
                        "finished_at": _now(),
                        "duration_s": round(tool_finished - tool_started, 3),
                        "blocked_evidence": outcome.evidence() if attempt.flagged else None,
                        "stdout_truncated": out_cut,
                        "stderr_truncated": err_cut,
                        "sandbox": {
                            "isolation": outcome.isolation,
                            "timed_out": outcome.timed_out,
                            "oom_killed": outcome.oom_killed,
                            "error": outcome.error,
                            "excluded_output": list(outcome.excluded_output),
                        },
                    },
                )
                if attempt.flagged:
                    self.attempts.append(
                        {
                            "seq": record.get("seq") if record else None,
                            "tool": call.name,
                            "arguments": traced_arguments,
                            "monitor": attempt.as_dict(),
                            "blocked_evidence": outcome.evidence(),
                        }
                    )
                messages.append(
                    {
                        "role": "tool",
                        "tool_call_id": call.id,
                        "content": _tool_message(outcome),
                    }
                )

        if final_text is None and not stop_reason:
            stop_reason = (
                f"turn limit of {self.max_turns} reached without a final answer"
            )

        if final_text is None:
            return Claim(
                status="",
                tests_claimed_passed=None,
                text=(
                    f"stopped before a final answer — {stop_reason} "
                    f"(turns={turns}, cost=${cost:.4f})"
                ),
            )

        claim = parse_final_claim(final_text)
        if claim is None:
            # Never invent a status: a final message that is not JSON is
            # recorded verbatim and the verifier judges the work on its own.
            return Claim(
                status="",
                tests_claimed_passed=None,
                text=(
                    "the final message was not a JSON claim; kept verbatim: "
                    f"{final_text[:1000]}"
                ),
            )
        return claim
