"""The judge layer: one question per changed file, append-only, never silent.

No network here: a fake judge client answers with a probability the test
chooses. The request count is asserted, because the Jev rule that batching
several items into one state degrades the answer is a measured result, not a
style preference.
"""

from __future__ import annotations

import io
import json
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from ega.judge import (
    DEFAULT_JUDGE_MODEL,
    JUDGE_THRESHOLD,
    QUESTION_SPECIAL_CASING,
    QUESTION_TEST_WEAKENING,
    Judge,
    JudgeAnswer,
    JudgeError,
    JudgeTarget,
    VultrJudgeClient,
    parse_judge_response,
    request_body,
)
from ega.trace import Trace, read_trace
from ega.verify import judge_targets

SECRET = "vultr-secret-key-never-in-a-trace"


class FakeJudgeClient:
    model = "fake-judge"

    def __init__(self, probability: float | None = 0.9, error: str | None = None):
        self.probability = probability
        self.error = error
        self.calls: list[tuple[dict, str]] = []

    def ask(self, state: dict, question: str) -> JudgeAnswer:
        self.calls.append((state, question))
        if self.error is not None:
            raise JudgeError(self.error)
        return JudgeAnswer(probability=self.probability, usage={"input_tokens": 10})


def write_tree(root: Path, files: dict[str, str]) -> Path:
    for rel, text in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return root


def make_pair(tmp_path: Path, changed: dict[str, str]) -> tuple[Path, Path]:
    base = write_tree(
        tmp_path / "pristine",
        {
            "app.py": "VALUE = 1\n",
            "tests/test_app.py": "def test_a():\n    assert True\n",
            "README.md": "hello\n",
        },
    )
    snap = write_tree(
        tmp_path / "snapshot",
        {
            "app.py": "VALUE = 1\n",
            "tests/test_app.py": "def test_a():\n    assert True\n",
            "README.md": "hello\n",
        },
    )
    write_tree(snap, changed)
    return base, snap


# --- targets ----------------------------------------------------------------


def test_one_target_per_changed_file_and_no_request_for_other_files(tmp_path):
    base, snap = make_pair(
        tmp_path,
        {
            "app.py": "VALUE = 2\n",
            "tests/test_app.py": "def test_a():\n    assert True\ndef test_b():\n    assert True\n",
            "README.md": "hello, world\n",
        },
    )
    targets = judge_targets(base, snap)

    # The README changed, but neither question can be asked of a README: it is
    # not the harness and not product code, so no request is spent on it.
    assert [t.path for t in targets] == ["app.py", "tests/test_app.py"]
    kinds = {t.path: t.kind for t in targets}
    assert kinds["app.py"] == "product"
    assert kinds["tests/test_app.py"] == "tests"


def test_each_kind_gets_its_own_question(tmp_path):
    base, snap = make_pair(
        tmp_path,
        {
            "app.py": "VALUE = 2\n",
            "tests/test_app.py": "def test_a():\n    assert True\ndef test_b():\n    assert True\n",
        },
    )
    targets = {t.path: t for t in judge_targets(base, snap)}

    assert targets["tests/test_app.py"].question == QUESTION_TEST_WEAKENING
    assert targets["app.py"].question == QUESTION_SPECIAL_CASING
    assert "special-cases the inputs" in QUESTION_SPECIAL_CASING


def test_an_unchanged_tree_has_no_targets(tmp_path):
    base, snap = make_pair(tmp_path, {})
    assert judge_targets(base, snap) == []


def test_the_diff_carries_only_the_changed_lines(tmp_path):
    base, snap = make_pair(tmp_path, {"app.py": "VALUE = 1\nOTHER = 2\n"})
    (target,) = judge_targets(base, snap)
    assert "+OTHER = 2" in target.diff
    # The unchanged line may appear as context, but never as a change.
    assert "-VALUE = 1" not in target.diff
    assert target.diff.startswith("--- pristine/app.py")


# --- the layer --------------------------------------------------------------


def test_the_layer_asks_one_request_per_target(tmp_path):
    base, snap = make_pair(
        tmp_path,
        {
            "app.py": "VALUE = 2\n",
            "tests/test_app.py": "def test_a():\n    assert True\ndef test_b():\n    assert True\n",
        },
    )
    targets = judge_targets(base, snap)
    client = FakeJudgeClient(probability=0.9)

    report = Judge(client=client).evaluate(targets)

    assert len(client.calls) == len(targets) == 2
    for state, question in client.calls:
        assert set(state) == {"file", "diff"}
        assert isinstance(question, str) and question
    assert report.status == "ok"
    assert len(report.items) == 2


def test_a_probability_at_the_threshold_is_flagged():
    target = JudgeTarget(path="app.py", kind="product", diff="+VALUE = 2\n")

    at = Judge(client=FakeJudgeClient(probability=JUDGE_THRESHOLD)).evaluate([target])
    below = Judge(client=FakeJudgeClient(probability=JUDGE_THRESHOLD - 0.001)).evaluate(
        [target]
    )

    assert at.items[0].flagged is True
    assert [f.code for f in at.findings] == ["JUDGE_SPECIAL_CASING"]
    assert below.items[0].flagged is False
    assert below.findings == []


def test_a_weakened_test_diff_gets_the_weakening_code():
    target = JudgeTarget(
        path="tests/test_app.py", kind="tests", diff="-    assert value == 3\n"
    )
    report = Judge(client=FakeJudgeClient(probability=0.99)).evaluate([target])

    assert [f.code for f in report.findings] == ["JUDGE_TEST_WEAKENING"]
    assert "p=0.99" in report.findings[0].message
    assert "tests/test_app.py" in report.findings[0].evidence
    assert "assert value == 3" in report.findings[0].evidence


def test_the_finding_evidence_carries_the_probability_and_the_threshold():
    target = JudgeTarget(path="app.py", kind="product", diff="+return 99.0\n")
    report = Judge(client=FakeJudgeClient(probability=0.87)).evaluate([target])

    evidence = report.findings[0].evidence
    assert "p=0.870" in evidence
    assert f"threshold={JUDGE_THRESHOLD:.2f}" in evidence


def test_a_failed_call_is_reported_not_skipped():
    """An unanswered question must not read as a clean one."""
    target = JudgeTarget(path="app.py", kind="product", diff="+VALUE = 2\n")
    report = Judge(client=FakeJudgeClient(error="HTTP 500: boom")).evaluate([target])

    assert report.status == "unproven"
    assert report.items[0].probability is None
    assert [f.code for f in report.findings] == ["JUDGE_UNPROVEN"]
    assert "HTTP 500" in report.findings[0].evidence


def test_one_failed_call_does_not_hide_the_answered_ones():
    targets = [
        JudgeTarget(path="a.py", kind="product", diff="+A = 1\n"),
        JudgeTarget(path="b.py", kind="product", diff="+B = 1\n"),
    ]
    client = FakeJudgeClient(probability=0.9)
    reports = iter(
        [
            JudgeAnswer(probability=0.95, usage={}),
            JudgeAnswer(probability=None, error="timeout", usage={}),
        ]
    )
    client.ask = lambda state, question: next(reports)  # type: ignore[assignment]

    report = Judge(client=client).evaluate(targets)

    codes = [f.code for f in report.findings]
    assert codes == ["JUDGE_SPECIAL_CASING", "JUDGE_UNPROVEN"]
    assert report.status == "unproven"


def test_no_client_is_reported_as_unavailable():
    report = Judge(client=None).evaluate(
        [JudgeTarget(path="app.py", kind="product", diff="+VALUE = 2\n")]
    )

    assert report.status == "unavailable"
    assert [f.code for f in report.findings] == ["JUDGE_UNAVAILABLE"]


def test_no_baseline_is_reported_as_unproven():
    report = Judge(client=FakeJudgeClient()).evaluate([], reason="no pristine baseline")

    assert report.status == "unproven"
    assert [f.code for f in report.findings] == ["JUDGE_UNPROVEN"]
    assert "no pristine baseline" in report.findings[0].evidence


def test_an_empty_target_list_is_ok_not_unproven(tmp_path):
    report = Judge(client=FakeJudgeClient()).evaluate([])
    assert report.status == "ok"
    assert report.findings == []


# --- the trace --------------------------------------------------------------


def test_every_request_lands_in_the_trace_with_its_raw_answer(tmp_path):
    trace_path = tmp_path / "trace.jsonl"
    trace = Trace(trace_path, "run-judge")
    target = JudgeTarget(path="app.py", kind="product", diff="+VALUE = 2\n")

    Judge(client=FakeJudgeClient(probability=0.91), trace=trace).evaluate([target])

    records = read_trace(trace_path)
    calls = [r for r in records if r["step"] == "judge.call"]
    assert len(calls) == 1
    call = calls[0]
    assert call["inputs"]["state"] == {"file": "app.py", "diff": "+VALUE = 2\n"}
    assert call["inputs"]["questions"]["q"]["type"] == "noul"
    assert call["inputs"]["questions"]["q"]["instructions"] == QUESTION_SPECIAL_CASING
    assert call["data"]["probability"] == 0.91
    assert call["data"]["threshold"] == JUDGE_THRESHOLD
    assert call["data"]["flagged"] is True
    assert "latency_s" in call["data"]
    assert "usage" in call["data"]
    assert [r["step"] for r in records][-1] == "judge.report"


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


def test_the_client_sends_one_noul_question_and_hides_the_key(monkeypatch):
    seen: dict = {}

    def fake_urlopen(request, timeout=None):
        seen["url"] = request.full_url
        seen["headers"] = dict(request.headers)
        seen["body"] = json.loads(request.data.decode("utf-8"))
        return _FakeHTTPResponse(
            {
                "answers": {"q": {"type": "noul", "noul": 0.99}},
                "usage": {"input_tokens": 203, "output_tokens": 0},
            }
        )

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    client = VultrJudgeClient(SECRET, model=DEFAULT_JUDGE_MODEL)

    answer = client.ask({"file": "app.py", "diff": "+x = 1"}, QUESTION_SPECIAL_CASING)

    assert answer.probability == 0.99
    assert answer.usage == {"input_tokens": 203, "output_tokens": 0}
    assert seen["url"].endswith("/v1/systemone")
    assert seen["headers"]["Authorization"] == f"Bearer {SECRET}"
    assert seen["body"]["model"] == DEFAULT_JUDGE_MODEL
    assert seen["body"]["state"] == {"file": "app.py", "diff": "+x = 1"}
    assert list(seen["body"]["questions"]) == ["q"]
    assert seen["body"]["questions"]["q"] == {
        "type": "noul",
        "instructions": QUESTION_SPECIAL_CASING,
    }
    assert SECRET not in repr(client)


def test_the_client_does_not_put_the_key_in_its_error(monkeypatch):
    def fake_urlopen(request, timeout=None):
        raise urllib.error.HTTPError(
            request.full_url, 500, "boom", None, io.BytesIO(b'{"error":"boom"}')
        )

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    client = VultrJudgeClient(SECRET, max_retries=0)

    with pytest.raises(JudgeError) as raised:
        client.ask({"file": "a.py", "diff": "+x"}, QUESTION_SPECIAL_CASING)

    assert SECRET not in str(raised.value)
    assert "HTTP 500" in str(raised.value)


def test_from_env_needs_a_key():
    with pytest.raises(JudgeError):
        VultrJudgeClient.from_env({"EGA_JUDGE_MODEL": "clef"})


def test_from_env_reads_the_model_override():
    client = VultrJudgeClient.from_env(
        {
            "VULTR_INFERENCE_API_KEY": "k",
            "EGA_JUDGE_MODEL": "clef-flash",
            "VULTR_INFERENCE_BASE_URL": "https://example.invalid/v1",
        }
    )
    assert client.model == "clef-flash"
    assert client.base_url == "https://example.invalid/v1"


def test_the_response_parser_refuses_a_missing_or_bad_noul():
    assert parse_judge_response({"answers": {"q": {"noul": 0.42}}}) == (0.42, None)

    for payload in (
        {},
        {"answers": {}},
        {"answers": {"q": {"type": "noul"}}},
        {"answers": {"q": {"noul": "high"}}},
        {"answers": {"q": {"noul": 1.5}}},
        {"answers": {"q": {"noul": True}}},
    ):
        probability, error = parse_judge_response(payload)
        assert probability is None, payload
        assert error, payload


def test_the_request_body_is_exactly_one_question():
    body = request_body({"file": "a.py"}, QUESTION_TEST_WEAKENING, "clef")
    assert body == {
        "model": "clef",
        "state": {"file": "a.py"},
        "questions": {"q": {"type": "noul", "instructions": QUESTION_TEST_WEAKENING}},
    }


# --- the layer's place in the verdict ---------------------------------------


def test_every_judge_finding_is_medium_so_it_cannot_fail_a_run():
    """Medium is the whole safety argument: at worst a done becomes a partial."""
    from ega.evidence import MEDIUM

    target = JudgeTarget(path="app.py", kind="product", diff="+return 99.0\n")
    flagged = Judge(client=FakeJudgeClient(probability=0.99)).evaluate([target])
    failed = Judge(client=FakeJudgeClient(error="boom")).evaluate([target])
    unavailable = Judge(client=None).evaluate([target])

    for report in (flagged, failed, unavailable):
        assert report.findings, report.status
        assert {finding.severity for finding in report.findings} == {MEDIUM}


def test_the_pipeline_builds_no_client_without_a_key(monkeypatch, tmp_path):
    """A missing key is a reported gap, not a crash and not a silent pass."""
    from ega import pipeline
    from ega.trace import Trace

    monkeypatch.delenv("VULTR_INFERENCE_API_KEY", raising=False)
    trace = Trace(tmp_path / "trace.jsonl", "run-nokey")

    judge = pipeline.build_judge(trace)
    report = judge.evaluate([JudgeTarget(path="app.py", kind="product", diff="+x\n")])

    assert report.status == "unavailable"
    assert [f.code for f in report.findings] == ["JUDGE_UNAVAILABLE"]

    explainer = pipeline.build_explainer(trace)
    explanation = explainer.explain({"first_line": "exit: done — ok", "findings": []})
    assert explanation.text == ""
    assert "no explanation client" in (explanation.error or "")
