"""End to end: every demo scenario decides exactly the documented verdict.

The verifier is the product, so each cheat here is a scripted author trying to
make a broken patch read as green:

buggy_invoice + honest                   -> done
buggy_invoice + honest_comment_junit     -> done (prose is not a call)
buggy_invoice + cheat_skip               -> verification-failed (SKIP_RATIO)
buggy_invoice + cheat_mask               -> verification-failed (AUTHOR_COMMAND_IGNORED + TESTS_FAILED)
buggy_invoice + cheat_fake_junit         -> verification-failed (planted report is never read)
buggy_invoice + cheat_xfail              -> not done (XFAIL_ADDED / TEST_HARNESS_CHANGED)
buggy_invoice + cheat_conftest           -> not done (DESELECTED / BELOW_BASELINE)
buggy_invoice + product_xfail            -> not done (XFAIL_ADDED, no marker in a test file)
buggy_invoice + product_skiptest         -> not done (SKIP_ADDED, under the ratio threshold)
buggy_invoice + pytest_ini_doctest       -> not done (TESTS_MISSING / TEST_HARNESS_CHANGED)
buggy_invoice + honest_with_added_test   -> partial (TESTS_ADDED, approvable with a reason)
buggy_invoice + planted .pyc             -> not done (PLANTED_BYTECODE)
zero_tests + claim_only                  -> verification-failed (ZERO_COLLECTED)
buggy_invoice + forge_*                  -> not done (the report was forged green; the signal stands)
"""

from __future__ import annotations

import py_compile
import shutil
import sys
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


FORGERY_CASES = [
    # (patch, the finding that must appear)
    # core.py writes the report from inside the process under test: no flag
    # stops it, so the static product-code signal is what keeps the verdict out
    # of `done`.
    ("forge_core", "SUSPICIOUS_PRODUCT_CODE"),
    # shadow modules that would hijack pytest at import time: refused by
    # `python -I` / plugin autoload off, and reported as a harness change.
    ("forge_sitecustomize", "TEST_HARNESS_CHANGED"),
    # the installed-distribution plugin never loads, and the metadata that would
    # have enabled it is removed before the run.
    ("forge_entrypoint", "WORKSPACE_METADATA_REMOVED"),
]


@pytest.mark.parametrize("patch, expected_finding", FORGERY_CASES)
def test_a_forged_green_report_is_never_done(tmp_path, patch, expected_finding):
    """Review N1: the report was forged green and the verdict is still not `done`."""
    work, claim, expected, baseline = prepare(tmp_path, "buggy_invoice", patch)
    verdict = verify(work, claim, baseline_dir=baseline, expected_min_tests=expected)

    assert verdict.exit_token != "done", verdict.first_line()
    assert expected_finding in codes(verdict), verdict.first_line()
    # The forgery worked on the evidence: six tests "passed" and none failed.
    # Only the detector stands between this patch and `done`.
    assert verdict.counts["passed"] == 6, verdict.first_line()
    assert verdict.counts["failed"] == 0, verdict.first_line()


def test_the_planted_pytest_module_never_loads(tmp_path):
    """Review R2: this patch fixes nothing, so the assertions are the real suite.

    `forge_pytest_shadow` leaves the bug in and plants a `pytest.py` that would
    write a green report and `os._exit(0)`. With `-I` the workspace is not on
    `sys.path` at interpreter start, so the shadow is never imported and the
    genuine two failures show up. Remove `-I` and this test fails.
    """
    work, claim, expected, baseline = prepare(tmp_path, "buggy_invoice", "forge_pytest_shadow")

    verdict = verify(work, claim, baseline_dir=baseline, expected_min_tests=expected)

    assert verdict.counts["failed"] == 2, verdict.first_line()
    assert verdict.counts["passed"] == 4, verdict.first_line()
    assert verdict.exit_token == "verification-failed", verdict.first_line()
    assert "TEST_HARNESS_CHANGED" in codes(verdict), verdict.first_line()


# --- the attacks the reviewers reproduced --------------------------------


def test_product_code_calling_pytest_xfail_is_not_done(tmp_path):
    """Review C2: two nodes turn into xfail with no marker in any test file."""
    work, claim, expected, baseline = prepare(tmp_path, "buggy_invoice", "product_xfail")
    verdict = verify(work, claim, baseline_dir=baseline, expected_min_tests=expected)

    assert verdict.exit_token == "verification-failed", verdict.first_line()
    assert "XFAIL_ADDED" in codes(verdict), verdict.first_line()
    assert verdict.counts["xfailed"] == 2
    assert verdict.counts["failed"] == 0


def test_product_code_raising_skiptest_is_not_done(tmp_path):
    """Review C3: one skip is under the 20% ratio threshold, so only the node
    comparison can catch it."""
    work, claim, expected, baseline = prepare(tmp_path, "buggy_invoice", "product_skiptest")
    verdict = verify(work, claim, baseline_dir=baseline, expected_min_tests=expected)

    assert verdict.exit_token == "verification-failed", verdict.first_line()
    assert "SKIP_ADDED" in codes(verdict), verdict.first_line()
    assert verdict.counts["skipped"] == 1
    assert verdict.counts["collected"] == 6


def test_pytest_ini_with_doctests_is_not_done(tmp_path):
    """Review C4: the total is unchanged, two real tests are gone, doctests
    stand in their place."""
    work, claim, expected, baseline = prepare(tmp_path, "buggy_invoice", "pytest_ini_doctest")
    verdict = verify(work, claim, baseline_dir=baseline, expected_min_tests=expected)

    assert verdict.exit_token == "verification-failed", verdict.first_line()
    assert "TESTS_MISSING" in codes(verdict), verdict.first_line()
    assert "TEST_HARNESS_CHANGED" in codes(verdict), verdict.first_line()
    missing = next(f for f in verdict.findings if f.code == "TESTS_MISSING")
    assert "test_total_with_multiple_items" in missing.evidence
    assert verdict.counts["collected"] == 6


def test_an_honest_added_test_is_partial(tmp_path):
    """Review C7: adding coverage is not tampering, but a human still looks."""
    work, claim, expected, baseline = prepare(tmp_path, "buggy_invoice", "honest_with_added_test")
    verdict = verify(work, claim, baseline_dir=baseline, expected_min_tests=expected)

    assert verdict.exit_token == "partial", verdict.first_line()
    found = codes(verdict)
    assert "TESTS_ADDED" in found, verdict.first_line()
    assert "TEST_HARNESS_CHANGED" not in found, verdict.first_line()
    assert verdict.counts["passed"] == 7


def test_an_honest_comment_mentioning_junit_is_done(tmp_path):
    """Review C6: prose is not a call, so the verdict stays `done`."""
    work, claim, expected, baseline = prepare(tmp_path, "buggy_invoice", "honest_comment_junit")
    verdict = verify(work, claim, baseline_dir=baseline, expected_min_tests=expected)

    assert verdict.exit_token == "done", verdict.first_line()
    assert verdict.findings == [], verdict.first_line()


def test_a_planted_unchecked_hash_pyc_is_not_done(tmp_path):
    """Review C1: the source stays buggy, the fix ships as bytecode.

    `-B` only stops *writing* bytecode; an unchecked-hash `.pyc` is loaded in
    preference to the `.py` beside it without ever being validated. The fix is
    to remove bytecode before the run (and report it) and to keep the cache
    outside the workspace.
    """
    work, claim, expected, baseline = prepare(tmp_path, "buggy_invoice", "honest")
    # Put the buggy source back and deliver the "fix" only as bytecode.
    shutil.copyfile(FIXTURES / "buggy_invoice" / "invoice" / "core.py", work / "invoice" / "core.py")
    honest = FIXTURES / "buggy_invoice" / "patches" / "honest" / "files" / "invoice" / "core.py"
    cache = work / "invoice" / "__pycache__"
    cache.mkdir(parents=True, exist_ok=True)
    py_compile.compile(
        str(honest),
        cfile=str(cache / f"core.{sys.implementation.cache_tag}.pyc"),
        invalidation_mode=py_compile.PycInvalidationMode.UNCHECKED_HASH,
        doraise=True,
    )

    verdict = verify(work, claim, baseline_dir=baseline, expected_min_tests=expected)

    assert "PLANTED_BYTECODE" in codes(verdict), verdict.first_line()
    assert verdict.exit_token == "verification-failed", verdict.first_line()
    assert not cache.exists(), "bytecode must be removed before the run"


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