"""API surface: fixtures, run creation, unknown ids, approval guard.

These do not need Docker: nothing here starts a pipeline thread to completion.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_index_serves_the_static_page():
    response = client.get("/")
    assert response.status_code == 200
    assert "Evidence-Gated Agent" in response.text


def test_the_probe_panel_has_a_not_proven_state():
    """A probe that could not observe anything must not read as ALLOWED.

    The page is checked as text: the gate has no JS engine, and shipping one to
    run three assertions would cost more than it proves. The behaviour itself is
    unit-tested against ``ProbeResult.outcome`` in ``test_probes.py``.
    """
    page = client.get("/").text

    assert 'unproven: "NOT PROVEN"' in page
    assert 'const probeOutcome = (p) => (p.outcome in OUTCOME_LABELS ? p.outcome : "unproven")' in page


def test_the_judge_and_explanation_panels_are_labelled_as_non_decisive():
    """The page must not let prose read as evidence.

    The judge panel says it can only add findings; the explanation header names
    its model and says it does not affect the verdict.
    """
    page = client.get("/").text

    assert 'id="judge"' in page and 'id="explain"' in page
    assert "Judge model signal (adds findings — it cannot remove any)" in page
    assert "it can only add findings; it cannot remove one or raise the verdict" in page
    assert 'Explanation (${e.model || "no model"}, does not affect the verdict)' in page
    assert 'judge: $("judge").checked, explain: $("explain").checked' in page
    # the result panels must not share an id with the checkboxes, or getElementById
    # returns the checkbox and the panel never shows the judge or the explanation
    for element_id in ("judge", "explain", "judge-panel", "explain-panel"):
        assert page.count(f'id="{element_id}"') == 1, element_id


def test_the_approve_button_needs_a_reason_for_a_partial_verdict():
    page = client.get("/").text

    # done → enabled; partial → enabled only once the reason box is non-empty;
    # anything else never. The server keeps refusing a reasonless partial (409).
    assert 'const enabled = !approved && (token === "done" || (partial && reason.length > 0))' in page
    assert '$("approve").disabled = !enabled' in page
    assert 'addEventListener("input", updateApproveState)' in page


def test_fixtures_endpoint_lists_the_demo_targets():
    response = client.get("/api/fixtures")
    assert response.status_code == 200
    fixtures = {f["name"]: f for f in response.json()["fixtures"]}
    assert {"buggy_invoice", "zero_tests", "injected_readme"} <= set(fixtures)
    assert fixtures["buggy_invoice"]["patches"] == [
        "cheat_conftest",
        "cheat_fake_junit",
        "cheat_hardcode",
        "cheat_mask",
        "cheat_skip",
        "cheat_xfail",
        "forge_core",
        "forge_entrypoint",
        "forge_pytest_shadow",
        "forge_sitecustomize",
        "honest",
        "honest_comment_junit",
        "honest_with_added_test",
        "product_skiptest",
        "product_xfail",
        "pytest_ini_doctest",
    ]
    assert fixtures["buggy_invoice"]["expected_min_tests"] == 6


def test_unknown_fixture_is_404():
    response = client.post("/api/runs", json={"fixture": "nope", "author": "scripted:honest"})
    assert response.status_code == 404


def test_unknown_patch_is_400():
    response = client.post(
        "/api/runs", json={"fixture": "buggy_invoice", "author": "scripted:nope"}
    )
    assert response.status_code == 400
    assert "unknown patch" in response.json()["detail"]


def test_only_scripted_authors_exist_in_this_phase():
    response = client.post(
        "/api/runs", json={"fixture": "buggy_invoice", "author": "llm:gpt"}
    )
    assert response.status_code == 400
    assert "scripted" in response.json()["detail"]


def test_unknown_run_is_404():
    assert client.get("/api/runs/does-not-exist").status_code == 404
    assert client.get("/api/runs/does-not-exist/trace").status_code == 404
    assert client.post("/api/runs/does-not-exist/approve").status_code == 404


def test_a_run_id_that_is_not_one_never_reaches_a_path():
    for bad in ("..", "%2e%2e", "20261104T012345Z-1a2b3c.json", ".hidden", "x" * 65):
        assert client.get(f"/api/runs/{bad}").status_code == 404, bad
        assert client.get(f"/api/runs/{bad}/trace").status_code == 404, bad
        assert client.post(f"/api/runs/{bad}/approve").status_code == 404, bad


def test_the_public_demo_caps_runs_in_flight(monkeypatch):
    import app.main as main

    busy = {f"20261104T00000{i}Z-00000{i}": {"status": "running"} for i in range(2)}
    monkeypatch.setattr(main, "_runs", busy)
    monkeypatch.setattr(main, "MAX_ACTIVE_RUNS", 2)
    response = client.post("/api/runs", json={"fixture": "buggy_invoice", "author": "scripted:honest"})
    assert response.status_code == 429
    assert "in progress" in response.json()["detail"]


def test_the_public_demo_caps_model_runs_per_day(monkeypatch):
    import app.main as main
    from datetime import datetime, timezone

    day = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    monkeypatch.setattr(main, "_runs", {})
    monkeypatch.setattr(main, "DAILY_MODEL_RUNS", 3)
    monkeypatch.setattr(main, "_model_runs_by_day", {day: 3})
    response = client.post(
        "/api/runs",
        json={"fixture": "buggy_invoice", "author": "scripted:honest", "judge": True},
    )
    assert response.status_code == 429
    assert "allowance" in response.json()["detail"]


@pytest.mark.docker
def test_run_endpoint_reaches_a_verdict():
    created = client.post(
        "/api/runs", json={"fixture": "buggy_invoice", "author": "scripted:honest"}
    )
    assert created.status_code == 202
    run_id = created.json()["run_id"]

    import time

    for _ in range(120):
        payload = client.get(f"/api/runs/{run_id}").json()
        if payload["status"] in ("done", "failed"):
            break
        time.sleep(1)
    assert payload["status"] == "done", payload
    assert payload["summary"]["exit_token"] == "done"
    assert len(payload["summary"]["probes"]) == 6

    trace = client.get(f"/api/runs/{run_id}/trace")
    assert trace.status_code == 200
    assert '"step": "verify"' in trace.text

    approved = client.post(f"/api/runs/{run_id}/approve")
    assert approved.status_code == 200
    assert approved.json()["summary"]["approved"] is True