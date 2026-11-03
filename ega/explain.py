"""The explanation: a different company's chat model says the verdict in words.

The verdict is already final when this runs. The explainer is a *reader*: it
gets the verdict JSON (first line, findings, counts, probe/judge summary) and
writes three to five plain English sentences for a person. It has no tool, no
vote and no path back into the verdict — a failed call leaves the explanation
empty with the reason recorded, and the verdict is untouched.

The prompt forbids inventing facts ("use only what the JSON says"). The
explanation is shown with its source label — ``Explanation (glm-5.3, does not
affect the verdict)`` — so nobody mistakes prose for evidence.

The raw prompt, the raw response and the usage are appended to the run trace.
The API key never leaves :class:`VultrExplainClient` and never reaches a trace.
"""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Protocol

from .trace import Trace

DEFAULT_BASE_URL = "https://api.vultrinference.com/v1"
# urllib's default "Python-urllib/x.y" is refused by some Cloudflare-fronted
# OpenAI-compatible gateways (HTTP 403, error code 1010, measured 2026-11-04).
USER_AGENT = "evidence-gated-agent/0.1"
# A different vendor from the author's model (deepseek) and from the judge
# (clef): writing and reviewing stay separate. Override with EGA_EXPLAIN_MODEL.
DEFAULT_EXPLAIN_MODEL = "glm-5.3"

EXPLAIN_SYSTEM_PROMPT = (
    "You explain a machine verification verdict to a person. "
    "Use ONLY facts that appear in the JSON you are given. Never invent a test "
    "name, a file, a number, a reason or a check that is not in the JSON; if the "
    "JSON does not say why, say that it does not. "
    "Write 3 to 5 plain English sentences: what was checked, what the verdict "
    "is, and what a human should look at next. No bullet points, no headings. "
    "The verdict is already final — you do not decide it and you do not change it."
)

# What the model is shown. Evidence strings can be long; they are clipped here
# (the full text stays in the trace) so one absurd finding cannot crowd out the
# rest of the verdict.
EVIDENCE_CLIP = 400
PROMPT_LIMIT = 12_000
# Reasoning tokens are drawn from this same budget and `reasoning` /
# `reasoning_effort` are silently ignored by this API (measured 2026-11-04:
# glm-5.3 spent 851 reasoning tokens and wrote nothing with a 400 cap, and a
# 1200 cap produced the answer). So the cap has to hold both.
MAX_TOKENS = 2000


class ExplainError(RuntimeError):
    """An explanation call failed (transport, HTTP error, unreadable response)."""


@dataclass
class Explanation:
    model: str
    text: str = ""
    error: str | None = None
    usage: dict = field(default_factory=dict)
    latency_s: float = 0.0

    def as_dict(self) -> dict:
        return {
            "model": self.model,
            "text": self.text,
            "error": self.error,
            "usage": dict(self.usage),
            "latency_s": round(self.latency_s, 3),
        }


class ExplainClient(Protocol):
    """The one seam the tests replace: one chat completion, no tools."""

    model: str

    def complete(self, messages: list[dict]) -> tuple[str, dict]: ...


def _http_detail(exc: urllib.error.HTTPError) -> str:
    try:
        body = exc.read().decode("utf-8", "replace")
    except Exception:  # noqa: BLE001 - the status code is the useful part
        return exc.reason or ""
    return body[:500]


class VultrExplainClient:
    """``POST /chat/completions`` against Vultr Serverless Inference, no tools."""

    def __init__(
        self,
        api_key: str,
        *,
        base_url: str = DEFAULT_BASE_URL,
        model: str = DEFAULT_EXPLAIN_MODEL,
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
        return f"VultrExplainClient(model={self.model!r}, base_url={self.base_url!r})"

    @classmethod
    def from_env(cls, environ: dict | None = None, **kwargs) -> "VultrExplainClient":
        environ = os.environ if environ is None else environ
        api_key = environ.get("VULTR_INFERENCE_API_KEY", "")
        if not api_key:
            raise ExplainError("VULTR_INFERENCE_API_KEY is not set")
        base_url = environ.get("VULTR_INFERENCE_BASE_URL") or DEFAULT_BASE_URL
        model = environ.get("EGA_EXPLAIN_MODEL") or DEFAULT_EXPLAIN_MODEL
        return cls(api_key, base_url=base_url, model=model, **kwargs)

    def complete(self, messages: list[dict]) -> tuple[str, dict]:
        payload = {
            "model": self.model,
            "messages": messages,
            "max_tokens": MAX_TOKENS,
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
                    data = json.loads(response.read().decode("utf-8"))
            except urllib.error.HTTPError as exc:
                retryable = exc.code == 429 or 500 <= exc.code < 600
                detail = _http_detail(exc)
                if not retryable or attempt >= self.max_retries:
                    raise ExplainError(f"HTTP {exc.code}: {detail}") from None
            except urllib.error.URLError as exc:
                raise ExplainError(f"network error: {exc.reason}") from None
            except json.JSONDecodeError as exc:
                raise ExplainError(f"the response was not JSON: {exc}") from None
            else:
                choices = data.get("choices") or []
                if not choices:
                    raise ExplainError(
                        f"the response has no choices: {json.dumps(data)[:300]}"
                    )
                choice = choices[0]
                message = choice.get("message") or {}
                text = (message.get("content") or "").strip()
                if not text:
                    # Name the likely cause instead of reporting a bare empty
                    # string: a reasoning model that ran out of output budget
                    # is a different failure from one that answered nothing.
                    details = data.get("usage") or {}
                    reasoning = (details.get("completion_tokens_details") or {}).get(
                        "reasoning_tokens"
                    )
                    if choice.get("finish_reason") == "length":
                        raise ExplainError(
                            "the model used its whole output budget before writing "
                            f"an explanation (finish_reason=length, max_tokens={MAX_TOKENS}, "
                            f"reasoning_tokens={reasoning})"
                        )
                    raise ExplainError(
                        f"the model returned an empty explanation: {json.dumps(data)[:300]}"
                    )
                return text, dict(data.get("usage") or {})
            time.sleep(self.backoff_s * (attempt + 1))
        raise ExplainError("retries exhausted")  # pragma: no cover


def prompt_verdict(verdict: dict) -> dict:
    """The facts the explainer is allowed to use, clipped for the prompt."""
    findings = []
    for finding in verdict.get("findings") or []:
        if not isinstance(finding, dict):
            continue
        findings.append(
            {
                "code": finding.get("code"),
                "severity": finding.get("severity"),
                "message": finding.get("message"),
                "evidence": str(finding.get("evidence") or "")[:EVIDENCE_CLIP],
            }
        )
    judge = verdict.get("judge")
    judge_view = None
    if isinstance(judge, dict):
        judge_view = {
            "model": judge.get("model"),
            "status": judge.get("status"),
            "threshold": judge.get("threshold"),
            "items": [
                {
                    "path": item.get("path"),
                    "kind": item.get("kind"),
                    "question": item.get("question"),
                    "probability": item.get("probability"),
                    "flagged": item.get("flagged"),
                }
                for item in judge.get("items") or []
                if isinstance(item, dict)
            ],
        }
    return {
        "first_line": verdict.get("first_line"),
        "sentence": verdict.get("sentence"),
        "exit_token": verdict.get("exit_token"),
        "counts": verdict.get("counts"),
        "claim_vs_observed": verdict.get("claim_vs_observed"),
        "findings": findings,
        "judge": judge_view,
        "isolation": verdict.get("isolation"),
    }


@dataclass
class Explainer:
    """Reads a finished verdict and writes words about it. Never writes a verdict."""

    client: ExplainClient | None = None
    trace: Trace | None = None
    model: str = ""

    def __post_init__(self) -> None:
        if not self.model:
            self.model = getattr(self.client, "model", "") if self.client is not None else ""

    def explain(self, verdict: dict) -> Explanation:
        facts = prompt_verdict(verdict)
        text = json.dumps(facts, indent=2, ensure_ascii=False)
        if len(text) > PROMPT_LIMIT:
            text = text[:PROMPT_LIMIT] + "\n…[truncated]"
        messages = [
            {"role": "system", "content": EXPLAIN_SYSTEM_PROMPT},
            {
                "role": "user",
                "content": "Verdict JSON (the only facts you may use):\n" + text,
            },
        ]

        if self.client is None:
            explanation = Explanation(
                model="",
                error=(
                    "no explanation client is configured "
                    "(VULTR_INFERENCE_API_KEY unset?) — the verdict is unchanged"
                ),
            )
            self._record(messages, explanation)
            return explanation

        started = time.monotonic()
        try:
            body, usage = self.client.complete(messages)
            explanation = Explanation(
                model=self.model,
                text=body,
                usage=dict(usage),
                latency_s=time.monotonic() - started,
            )
        except ExplainError as exc:
            explanation = Explanation(
                model=self.model,
                error=str(exc),
                latency_s=time.monotonic() - started,
            )
        self._record(messages, explanation)
        return explanation

    def _record(self, messages: list[dict], explanation: Explanation) -> None:
        if self.trace is None:
            return
        self.trace.append(
            "explain",
            status="ok" if explanation.error is None else "error",
            inputs={
                "model": self.model,
                "messages": messages,
                "note": "generated after the verdict was final; it cannot change it",
            },
            stdout=explanation.text,
            stderr=explanation.error or "",
            data={
                "model": self.model,
                "error": explanation.error,
                "usage": dict(explanation.usage),
                "latency_s": round(explanation.latency_s, 3),
            },
        )
