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


def test_fixtures_endpoint_lists_the_demo_targets():
    response = client.get("/api/fixtures")
    assert response.status_code == 200
    fixtures = {f["name"]: f for f in response.json()["fixtures"]}
    assert {"buggy_invoice", "zero_tests", "injected_readme"} <= set(fixtures)
    assert fixtures["buggy_invoice"]["patches"] == [
        "cheat_conftest",
        "cheat_fake_junit",
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