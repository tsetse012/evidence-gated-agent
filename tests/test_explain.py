"""The explanation: prose about a finished verdict, and nothing else.

A different vendor's chat model describes the verdict *after* it is final. The
tests here hold the two halves that matter: the text is written from the
verdict JSON and only from it, and no path exists from the explanation back
into the verdict — a failed call leaves a named gap, not a changed verdict.
"""

from __future__ import annotations

import copy
import io
import json
import urllib.error
import urllib.request

import pytest

from ega.explain import (
    DEFAULT_EXPLAIN_MODEL,
    EVIDENCE_CLIP,
    EXPLAIN_SYSTEM_PROMPT,
    ExplainError,
    Explainer,
    VultrExplainClient,
    prompt_verdict,
)
from ega.trace import Trace, read_trace

SECRET = "vultr-secret-key-never-in-a-trace"


def verdict_dict() -> dict:
    return {
        "first_line": "exit: partial — the suite passes, but the judge flagged a diff.",
        "sentence": "the suite passes, but the judge flagged a diff.",
        "exit_token": "partial",
        "counts": {"passed": 6, "failed": 0, "collected": 6},
        "claim_vs_observed": [{"claim": "done", "observed": "partial", "agrees": False}],
        "findings": [
            {
                "code": "JUDGE_SPECIAL_CASING",
                "severity": "medium",
                "message": "the judge model (clef) puts p=0.97 on this diff",
                "evidence": "invoice/core.py p=0.970 threshold=0.50\n+ return 99.00",
            }
        ],
        "judge": {
            "model": "clef",
            "threshold": 0.5,
            "status": "ok",
            "items": [
                {
                    "path": "invoice/core.py",
                    "kind": "product",
                    "question": "`diff` special-cases the inputs the tests use",
                    "probability": 0.97,
                    "threshold": 0.5,
                    "flagged": True,
                    "error": None,
                }
            ],
        },
        "isolation": "gvisor",
    }


class FakeExplainClient:
    model = "fake-explainer"

    def __init__(self, text: str = "The suite passed six tests.", error: str | None = None):
        self.text = text
        self.error = error
        self.calls: list[list[dict]] = []

    def complete(self, messages: list[dict]) -> tuple[str, dict]:
        self.calls.append(messages)
        if self.error is not None:
            raise ExplainError(self.error)
        return self.text, {"prompt_tokens": 120, "completion_tokens": 40}


# --- the layer --------------------------------------------------------------


def test_the_explanation_never_touches_the_verdict():
    verdict = verdict_dict()
    before = copy.deepcopy(verdict)

    explanation = Explainer(client=FakeExplainClient("Six tests passed.")).explain(verdict)

    assert explanation.text == "Six tests passed."
    assert explanation.error is None
    assert verdict == before


def test_a_failed_call_leaves_a_named_gap_and_the_verdict_stands():
    verdict = verdict_dict()
    before = copy.deepcopy(verdict)

    explanation = Explainer(client=FakeExplainClient(error="HTTP 500: boom")).explain(verdict)

    assert explanation.text == ""
    assert "HTTP 500" in explanation.error
    assert verdict == before


def test_no_client_is_an_explicit_gap_not_silence():
    explanation = Explainer(client=None).explain(verdict_dict())

    assert explanation.text == ""
    assert explanation.error and "no explanation client" in explanation.error


def test_the_prompt_forbids_facts_outside_the_json():
    client = FakeExplainClient()
    Explainer(client=client).explain(verdict_dict())

    system = client.calls[0][0]
    assert system["role"] == "system"
    assert system["content"] == EXPLAIN_SYSTEM_PROMPT
    assert "ONLY facts" in system["content"]
    assert "Never invent" in system["content"]
    assert "you do not change it" in system["content"]


def test_the_prompt_carries_the_findings_the_judge_and_the_counts():
    client = FakeExplainClient()
    Explainer(client=client).explain(verdict_dict())

    user = client.calls[0][1]["content"]
    assert user.startswith("Verdict JSON")
    assert "JUDGE_SPECIAL_CASING" in user
    assert '"probability": 0.97' in user
    assert '"passed": 6' in user


def test_long_evidence_is_clipped_in_the_prompt_but_not_invented():
    verdict = verdict_dict()
    verdict["findings"][0]["evidence"] = "x" * (EVIDENCE_CLIP * 3)

    facts = prompt_verdict(verdict)

    assert len(facts["findings"][0]["evidence"]) == EVIDENCE_CLIP


# --- the trace --------------------------------------------------------------


def test_the_trace_records_the_prompt_the_answer_and_the_note(tmp_path):
    trace_path = tmp_path / "trace.jsonl"
    trace = Trace(trace_path, "run-explain")

    Explainer(client=FakeExplainClient("Six tests passed."), trace=trace).explain(
        verdict_dict()
    )

    records = read_trace(trace_path)
    (record,) = [r for r in records if r["step"] == "explain"]
    assert record["inputs"]["messages"][1]["content"].startswith("Verdict JSON")
    assert "cannot change it" in record["inputs"]["note"]
    assert record["stdout"] == "Six tests passed."
    assert record["data"]["usage"] == {"prompt_tokens": 120, "completion_tokens": 40}
    assert "latency_s" in record["data"]


# --- the HTTP client --------------------------------------------------------


class _FakeHTTPResponse:
    def __init__(self, payload: dict):
        self._payload = payload

    def read(self) -> bytes:
        return json.dumps(self._payload).encode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def test_the_client_posts_one_completion_with_no_tools_and_hides_the_key(monkeypatch):
    seen: dict = {}

    def fake_urlopen(request, timeout=None):
        seen["url"] = request.full_url
        seen["headers"] = dict(request.headers)
        seen["body"] = json.loads(request.data.decode("utf-8"))
        return _FakeHTTPResponse(
            {
                "choices": [{"message": {"content": " The verdict is partial. "}}],
                "usage": {"prompt_tokens": 90, "completion_tokens": 12},
            }
        )

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    client = VultrExplainClient(SECRET, model=DEFAULT_EXPLAIN_MODEL)
    messages = [{"role": "user", "content": "verdict"}]

    text, usage = client.complete(messages)

    assert text == "The verdict is partial."
    assert usage == {"prompt_tokens": 90, "completion_tokens": 12}
    assert seen["url"].endswith("/v1/chat/completions")
    assert seen["headers"]["Authorization"] == f"Bearer {SECRET}"
    assert seen["body"]["model"] == DEFAULT_EXPLAIN_MODEL == "glm-5.3"
    assert seen["body"]["messages"] == messages
    assert "tools" not in seen["body"]
    assert SECRET not in repr(client)


def test_the_client_does_not_put_the_key_in_its_error(monkeypatch):
    def fake_urlopen(request, timeout=None):
        raise urllib.error.HTTPError(
            request.full_url, 500, "boom", None, io.BytesIO(b'{"error":"boom"}')
        )

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    client = VultrExplainClient(SECRET, max_retries=0)

    with pytest.raises(ExplainError) as raised:
        client.complete([{"role": "user", "content": "x"}])

    assert SECRET not in str(raised.value)
    assert "HTTP 500" in str(raised.value)


def test_an_empty_completion_is_an_error_not_an_empty_explanation(monkeypatch):
    def fake_urlopen(request, timeout=None):
        return _FakeHTTPResponse({"choices": [{"message": {"content": "   "}}]})

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    client = VultrExplainClient(SECRET, max_retries=0)

    with pytest.raises(ExplainError):
        client.complete([{"role": "user", "content": "x"}])


def test_a_reasoning_model_that_ran_out_of_budget_names_the_cause(monkeypatch):
    """Measured 2026-11-04: glm-5.3 spent 851 reasoning tokens and answered nothing.

    The error has to say that, because "empty explanation" alone reads like a
    model that had nothing to say.
    """

    def fake_urlopen(request, timeout=None):
        return _FakeHTTPResponse(
            {
                "choices": [
                    {
                        "message": {"content": "", "reasoning": "…"},
                        "finish_reason": "length",
                    }
                ],
                "usage": {
                    "prompt_tokens": 383,
                    "completion_tokens": 400,
                    "completion_tokens_details": {"reasoning_tokens": 400},
                },
            }
        )

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    client = VultrExplainClient(SECRET, max_retries=0)

    with pytest.raises(ExplainError) as raised:
        client.complete([{"role": "user", "content": "x"}])

    message = str(raised.value)
    assert "finish_reason=length" in message
    assert "reasoning_tokens=400" in message
    assert SECRET not in message


def test_from_env_needs_a_key_and_reads_the_model_override():
    with pytest.raises(ExplainError):
        VultrExplainClient.from_env({"EGA_EXPLAIN_MODEL": "glm-5.3"})

    client = VultrExplainClient.from_env(
        {
            "VULTR_INFERENCE_API_KEY": "k",
            "EGA_EXPLAIN_MODEL": "qwen3.8-27b",
            "VULTR_INFERENCE_BASE_URL": "https://example.invalid/v1",
        }
    )
    assert client.model == "qwen3.8-27b"
    assert client.base_url == "https://example.invalid/v1"
