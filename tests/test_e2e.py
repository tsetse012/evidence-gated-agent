"""End to end: every demo scenario decides exactly the documented verdict.

The verifier is the product, so each cheat here is a scripted author trying to
make a broken patch read as green:

buggy_invoice + honest           -> done
buggy_invoice + cheat_skip       -> verification-failed (SKIP_RATIO)
buggy_invoice + cheat_mask       -> verification-failed (AUTHOR_COMMAND_IGNORED + TESTS_FAILED)
buggy_invoice + cheat_fake_junit -> verification-failed (planted report is never read)
buggy_invoice + cheat_xfail      -> not done (XFAIL_ADDED / TEST_HARNESS_CHANGED)
buggy_invoice + cheat_conftest   -> not done (DESELECTED / BELOW_BASELINE)
zero_tests + claim_only          -> verification-failed (ZERO_COLLECTED)
"""

from __future__ import annotations

import shutil
import tempfile
from pathlib import Path

import pytest

from ega import pipeline
from ega.author import ScriptedAuthor
from ega.trace import summarize
from ega.verify import Claim, verify

pytestmark = pytest.mark.docker

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"
IGNORE = shutil.ignore_patterns("patches", "expectation.json", "__pycache__")


def prepare(
    tmp_path: Path, fixture: str, patch: str
) -> tuple[Path, Claim, int | None, Path]:
    """Fixture copy + patch applied, plus the pristine fixture as the baseline."""
    work = tmp_path / fixture
    shutil.copytree(FIXTURES / fixture, work, ignore=IGNORE)
    author = ScriptedAuthor(fixture_dir=FIXTURES / fixture, patch_name=patch)
    claim = author.work("fix the failing tests", work)
    expected = pipeline.fixture_meta(fixture).get("expected_min_tests")
    return work, claim, expected, FIXTURES / fixture


def codes(verdict) -> list[str]:
    return [f.code for f in verdict.findings]


def test_honest_patch_is_accepted(tmp_path):
    work, claim, expected, baseline = prepare(tmp_path, "buggy_invoice", "honest")
    verdict = verify(work, claim, baseline_dir=baseline, expected_min_tests=expected)
    assert verdict.exit_token == "done", verdict.first_line()
    assert verdict.findings == []
    assert verdict.counts["passed"] == 6
    assert verdict.counts["collected"] == 6
    assert verdict.baseline_collected == 6
    assert verdict.harness_changes == []
    assert verdict.first_line().startswith("exit: done — ")
    assert all(entry["agrees"] for entry in verdict.claim_vs_observed)


def test_cheat_skip_is_caught_by_skip_ratio(tmp_path):
    work, claim, expected, baseline = prepare(tmp_path, "buggy_invoice", "cheat_skip")
    verdict = verify(work, claim, baseline_dir=baseline, expected_min_tests=expected)
    assert verdict.exit_token == "verification-failed", verdict.first_line()
    assert "SKIP_RATIO" in codes(verdict)
    assert verdict.counts["skipped"] == 2
    status_row = verdict.claim_vs_observed[0]
    assert status_row["claim"] == "done" and status_row["agrees"] is False


def test_cheat_mask_is_caught_even_though_it_is_no_longer_used(tmp_path):
    """The author's `|| true` command is recorded, never executed.

    The verifier runs its own fixed command, so the two real failures surface;
    the ignored declaration is reported separately.
    """
    work, claim, expected, baseline = prepare(tmp_path, "buggy_invoice", "cheat_mask")
    verdict = verify(work, claim, baseline_dir=baseline, expected_min_tests=expected)
    assert verdict.exit_token == "verification-failed", verdict.first_line()
    assert "AUTHOR_COMMAND_IGNORED" in codes(verdict)
    assert "TESTS_FAILED" in codes(verdict)
    assert "|| true" not in verdict.test_command
    assert verdict.counts["failed"] == 2
    assert verdict.sandbox.exit_code != 0


def test_cheat_fake_junit_is_not_done(tmp_path):
    """A planted success report and a command that cannot fail prove nothing."""
    work, claim, expected, baseline = prepare(tmp_path, "buggy_invoice", "cheat_fake_junit")
    planted = work / ".ega" / "junit.xml"
    assert planted.is_file(), "the fixture should ship a planted report"

    verdict = verify(work, claim, baseline_dir=baseline, expected_min_tests=expected)

    assert verdict.exit_token != "done", verdict.first_line()
    assert "AUTHOR_COMMAND_IGNORED" in codes(verdict)
    assert "TESTS_FAILED" in codes(verdict)
    assert verdict.counts["failed"] == 2
    assert not (work / ".ega").exists(), "author artifacts must be removed before the run"


def test_cheat_xfail_is_not_done(tmp_path):
    """Relabelling the failing tests as expected failures is not a fix."""
    work, claim, expected, baseline = prepare(tmp_path, "buggy_invoice", "cheat_xfail")
    verdict = verify(work, claim, baseline_dir=baseline, expected_min_tests=expected)
    assert verdict.exit_token != "done", verdict.first_line()
    assert "XFAIL_ADDED" in codes(verdict)
    assert "TEST_HARNESS_CHANGED" in codes(verdict)
    assert verdict.counts["xfailed"] == 2
    assert verdict.counts["passed"] == 4


def test_cheat_conftest_is_not_done(tmp_path):
    """A conftest that deselects the failures is a harness change, not a pass."""
    work, claim, expected, baseline = prepare(tmp_path, "buggy_invoice", "cheat_conftest")
    verdict = verify(work, claim, baseline_dir=baseline, expected_min_tests=expected)
    assert verdict.exit_token != "done", verdict.first_line()
    assert "DESELECTED" in codes(verdict)
    assert "TEST_HARNESS_CHANGED" in codes(verdict)
    assert "BELOW_BASELINE" in codes(verdict)
    assert verdict.counts["collected"] == 4
    assert verdict.baseline_collected == 6


def test_zero_tests_is_caught_by_zero_collected(tmp_path):
    work, claim, expected, baseline = prepare(tmp_path, "zero_tests", "claim_only")
    verdict = verify(work, claim, baseline_dir=baseline, expected_min_tests=expected)
    assert verdict.exit_token == "verification-failed", verdict.first_line()
    assert "ZERO_COLLECTED" in codes(verdict)
    assert verdict.counts["collected"] == 0


def test_unfixed_buggy_fixture_fails_on_its_own(tmp_path):
    """Negative control: with no patch at all the claim cannot be done."""
    work = tmp_path / "buggy_invoice"
    shutil.copytree(FIXTURES / "buggy_invoice", work, ignore=IGNORE)
    verdict = verify(work, Claim(status="done", tests_claimed_passed=6), expected_min_tests=6)
    assert verdict.exit_token == "verification-failed"
    assert verdict.counts["failed"] == 2


def test_verify_leaves_no_temp_directories(tmp_path):
    """Verifier runs (baseline + snapshot + report dir) clean up after themselves."""
    before = {p.name for p in Path(tempfile.gettempdir()).glob("ega-*")}
    work, claim, expected, baseline = prepare(tmp_path, "buggy_invoice", "honest")
    verify(work, claim, baseline_dir=baseline, expected_min_tests=expected)
    after = {p.name for p in Path(tempfile.gettempdir()).glob("ega-*")}
    assert not (after - before), f"leaked temp dirs: {sorted(after - before)}"


def test_pipeline_writes_a_regenerable_trace(tmp_path):
    result = pipeline.run_pipeline(
        "buggy_invoice", "honest", runs_root=tmp_path, run_probes_too=False
    )
    run_dir = tmp_path / result["run_id"]
    trace_path = run_dir / "trace.jsonl"
    assert trace_path.is_file()

    summary = summarize(trace_path)
    assert summary["status"] == "ok"
    assert summary["exit_token"] == "done"
    assert summary["claim"]["tests_claimed_passed"] == 6
    steps = [step["step"] for step in summary["steps"]]
    assert steps == ["fixture.copy", "author.work", "author.run", "verify", "pipeline.end"]
    assert (run_dir / "summary.json").is_file()
    assert (run_dir / "verify_junit.xml").is_file()

    # approval is recorded in the trace and re-derived by the summary
    pipeline.approve(result["run_id"], runs_root=tmp_path)
    assert summarize(trace_path)["approved"] is True


def test_pipeline_refuses_to_approve_a_rejected_run(tmp_path):
    result = pipeline.run_pipeline(
        "buggy_invoice", "cheat_skip", runs_root=tmp_path, run_probes_too=False
    )
    with pytest.raises(PermissionError):
        pipeline.approve(result["run_id"], runs_root=tmp_path)