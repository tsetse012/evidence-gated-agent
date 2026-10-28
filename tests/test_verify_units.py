"""Unit: the verifier's own machinery, without Docker.

The command it runs is fixed and isolated, declared artifacts may not leave the
workspace, the test-harness comparison covers every file pytest reads (and
anything that can shadow pytest itself), and product code that forges a report
is reported even when the run looks green.
"""

from __future__ import annotations

import shutil
import textwrap
from pathlib import Path

import pytest

from ega.evidence import HIGH
from ega.sandbox import SandboxResult
from ega.verify import (
    CONFIG_FILE,
    artifact_paths,
    baseline_command,
    count_xfail_markers,
    harness_changes,
    load_project_config,
    stage_repo,
    suspicious_product_code,
    verifier_command,
    xfail_marker_counts,
)


def make_repo(root: Path) -> Path:
    (root / "tests").mkdir(parents=True)
    (root / "tests" / "test_app.py").write_text("def test_ok():\n    assert True\n", encoding="utf-8")
    (root / "conftest.py").write_text("import sys\n", encoding="utf-8")
    (root / "app.py").write_text("VALUE = 1\n", encoding="utf-8")
    (root / CONFIG_FILE).write_text('test_command = "python -m pytest"\n', encoding="utf-8")
    return root


# --- the command -----------------------------------------------------------


def test_the_verifier_command_is_fixed_and_outside_the_workspace():
    cmd = verifier_command("junit-abc.xml")
    assert cmd[:6] == ["python", "-I", "-B", "-u", "-m", "pytest"]
    assert cmd[cmd.index("-p") + 1] == "no:cacheprovider"
    assert cmd[cmd.index("-o") + 1] == "pythonpath=."
    assert cmd[-1] == "--junitxml=/ega-out/junit-abc.xml"
    assert not any("/work" in part for part in cmd)
    assert "sh" not in cmd and "-c" not in cmd


def test_the_baseline_command_is_isolated_in_the_same_way():
    cmd = baseline_command()
    assert cmd[:6] == ["python", "-I", "-B", "-u", "-m", "pytest"]
    assert cmd[-1] == "--collect-only"
    assert not any("/work" in part for part in cmd)


def test_the_verifier_disables_plugin_autoload():
    from ega.verify import VERIFIER_ENV

    assert VERIFIER_ENV["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] == "1"


def test_a_declared_command_is_only_recorded(tmp_path):
    repo = make_repo(tmp_path)
    (repo / CONFIG_FILE).write_text(
        'test_command = "pytest || true"\n', encoding="utf-8"
    )
    config = load_project_config(repo)
    assert config.test_command == "pytest || true"
    assert "||" not in " ".join(verifier_command("junit-x.xml"))


# --- artifacts -------------------------------------------------------------


def test_an_artifact_inside_the_workspace_is_accepted(tmp_path):
    work = tmp_path / "work"
    (work / "reports").mkdir(parents=True)
    (work / "reports" / "out.txt").write_text("ok\n", encoding="utf-8")

    paths, findings = artifact_paths(work, ["reports/out.txt"])

    assert findings == []
    assert paths == [(work / "reports" / "out.txt").resolve()]


def test_an_absolute_artifact_path_is_refused(tmp_path):
    work = tmp_path / "work"
    work.mkdir()

    paths, findings = artifact_paths(work, ["/etc/passwd"])

    assert paths == []
    assert [f.code for f in findings] == ["ARTIFACT_ESCAPE"]
    assert "/etc/passwd" in findings[0].evidence


def test_a_dotdot_artifact_path_is_refused(tmp_path):
    work = tmp_path / "work"
    work.mkdir()
    (tmp_path / "outside.txt").write_text("host\n", encoding="utf-8")

    paths, findings = artifact_paths(work, ["../outside.txt"])

    assert paths == []
    assert [f.code for f in findings] == ["ARTIFACT_ESCAPE"]


def test_a_symlinked_artifact_that_leaves_the_workspace_is_refused(tmp_path):
    work = tmp_path / "work"
    work.mkdir()
    (tmp_path / "outside.txt").write_text("host\n", encoding="utf-8")
    (work / "link.txt").symlink_to(tmp_path / "outside.txt")

    paths, findings = artifact_paths(work, ["link.txt"])

    assert paths == []
    assert [f.code for f in findings] == ["ARTIFACT_ESCAPE"]


def test_a_nested_artifact_is_accepted(tmp_path):
    work = tmp_path / "work"
    (work / "a" / "b").mkdir(parents=True)
    (work / "a" / "b" / "c.txt").write_text("ok\n", encoding="utf-8")

    paths, findings = artifact_paths(work, ["a/b/c.txt"])

    assert findings == []
    assert paths == [(work / "a" / "b" / "c.txt").resolve()]


def test_any_dotdot_component_is_refused_even_when_it_stays_inside(tmp_path):
    """`a/../a/b/c.txt` resolves inside, but `..` is refused outright."""
    work = tmp_path / "work"
    (work / "a" / "b").mkdir(parents=True)
    (work / "a" / "b" / "c.txt").write_text("ok\n", encoding="utf-8")

    paths, findings = artifact_paths(work, ["a/../a/b/c.txt"])

    assert paths == []
    assert [f.code for f in findings] == ["ARTIFACT_ESCAPE"]


# --- harness comparison ----------------------------------------------------


def test_an_unchanged_harness_has_no_changes(tmp_path):
    base = make_repo(tmp_path / "base")
    snap = make_repo(tmp_path / "snap")
    assert harness_changes(base, snap) == []


def test_a_changed_conftest_is_a_harness_change(tmp_path):
    base = make_repo(tmp_path / "base")
    snap = make_repo(tmp_path / "snap")
    (snap / "conftest.py").write_text(
        "import sys\n\ndef pytest_collection_modifyitems(config, items):\n    items[:] = []\n",
        encoding="utf-8",
    )

    changes = harness_changes(base, snap)

    assert [rel for rel, _ in changes] == ["conftest.py"]
    assert "pytest_collection_modifyitems" in changes[0][1]


def test_a_changed_test_file_is_a_harness_change(tmp_path):
    base = make_repo(tmp_path / "base")
    snap = make_repo(tmp_path / "snap")
    (snap / "tests" / "test_app.py").write_text(
        "def test_ok():\n    assert True\n\ndef test_extra():\n    assert True\n",
        encoding="utf-8",
    )

    assert [rel for rel, _ in harness_changes(base, snap)] == ["tests/test_app.py"]


def test_a_removed_test_file_is_a_harness_change(tmp_path):
    base = make_repo(tmp_path / "base")
    snap = make_repo(tmp_path / "snap")
    (snap / "tests" / "test_app.py").unlink()

    assert [rel for rel, _ in harness_changes(base, snap)] == ["tests/test_app.py"]


def test_pytest_ini_is_a_harness_change(tmp_path):
    base = make_repo(tmp_path / "base")
    snap = make_repo(tmp_path / "snap")
    (snap / "pytest.ini").write_text("[pytest]\naddopts = -k not failing\n", encoding="utf-8")

    assert [rel for rel, _ in harness_changes(base, snap)] == ["pytest.ini"]


def test_changing_packaging_metadata_only_is_not_a_harness_change(tmp_path):
    base = make_repo(tmp_path / "base")
    snap = make_repo(tmp_path / "snap")
    (base / "pyproject.toml").write_text(
        '[project]\nname = "app"\nversion = "0.1"\n', encoding="utf-8"
    )
    (snap / "pyproject.toml").write_text(
        '[project]\nname = "app"\nversion = "0.2"\n', encoding="utf-8"
    )

    assert harness_changes(base, snap) == []


def test_changing_the_pytest_section_of_pyproject_is_a_harness_change(tmp_path):
    base = make_repo(tmp_path / "base")
    snap = make_repo(tmp_path / "snap")
    (base / "pyproject.toml").write_text(
        '[project]\nname = "app"\n\n[tool.pytest.ini_options]\naddopts = ""\n', encoding="utf-8"
    )
    (snap / "pyproject.toml").write_text(
        '[project]\nname = "app"\n\n[tool.pytest.ini_options]\naddopts = "-k ok"\n',
        encoding="utf-8",
    )

    assert [rel for rel, _ in harness_changes(base, snap)] == ["pyproject.toml"]


def test_changing_the_code_under_test_is_not_a_harness_change(tmp_path):
    base = make_repo(tmp_path / "base")
    snap = make_repo(tmp_path / "snap")
    (snap / "app.py").write_text("VALUE = 2\n", encoding="utf-8")

    assert harness_changes(base, snap) == []


def test_authoring_metadata_is_staged_away_before_the_comparison(tmp_path):
    """`patches/` never reaches the author's workspace, so it is dropped when the
    pristine baseline is staged — not ignored inside the diff itself."""
    base = make_repo(tmp_path / "base")
    (base / "patches").mkdir()
    (base / "patches" / "conftest.py").write_text("x = 1\n", encoding="utf-8")
    (base / "expectation.json").write_text("{}\n", encoding="utf-8")
    snap = make_repo(tmp_path / "snap")

    staged = stage_repo(base)
    try:
        assert not (staged / "patches").exists()
        assert not (staged / "expectation.json").exists()
        assert harness_changes(staged, snap) == []
    finally:
        shutil.rmtree(staged, ignore_errors=True)


def test_a_conftest_hidden_under_patches_is_still_a_harness_change(tmp_path):
    """Review N4 repro: a conftest planted in an always-ignored directory."""
    base = make_repo(tmp_path / "base")
    snap = make_repo(tmp_path / "snap")
    (snap / "patches").mkdir()
    (snap / "patches" / "conftest.py").write_text(
        "def pytest_collection_modifyitems(config, items):\n    items[:] = []\n",
        encoding="utf-8",
    )

    changes = harness_changes(base, snap)

    assert [rel for rel, _ in changes] == ["patches/conftest.py"]


# --- harness discovery -----------------------------------------------------


def test_a_test_file_outside_tests_is_a_harness_change(tmp_path):
    """Review N2 repro: a test file at the repo root was invisible."""
    base = make_repo(tmp_path / "base")
    snap = make_repo(tmp_path / "snap")
    text = "def test_a():\n    assert True\n"
    (base / "test_invoice.py").write_text(text, encoding="utf-8")
    (snap / "test_invoice.py").write_text(
        text + "\n\ndef test_b():\n    assert True\n", encoding="utf-8"
    )

    assert [rel for rel, _ in harness_changes(base, snap)] == ["test_invoice.py"]


def test_a_newly_added_suffix_style_test_file_is_a_harness_change(tmp_path):
    base = make_repo(tmp_path / "base")
    snap = make_repo(tmp_path / "snap")
    (snap / "tests" / "checks_invoice_test.py").write_text(
        "def test_a():\n    assert True\n", encoding="utf-8"
    )

    assert [rel for rel, _ in harness_changes(base, snap)] == [
        "tests/checks_invoice_test.py"
    ]


def test_a_removed_top_level_test_file_is_a_harness_change(tmp_path):
    base = make_repo(tmp_path / "base")
    snap = make_repo(tmp_path / "snap")
    (base / "test_invoice.py").write_text("def test_a():\n    assert True\n", encoding="utf-8")

    assert [rel for rel, _ in harness_changes(base, snap)] == ["test_invoice.py"]


@pytest.mark.parametrize(
    "rel",
    [
        "pytest.py",
        "sitecustomize.py",
        "usercustomize.py",
        "extra.pth",
        "vendor.egg-link",
        "evil-1.0.dist-info/entry_points.txt",
        "evil-1.0.egg-info/PKG-INFO",
        "_pytest/__init__.py",
    ],
)
def test_a_planted_pytest_shadow_is_a_harness_change(tmp_path, rel):
    """Review N1 repro (b)(c)(d): modules that hijack pytest at import time."""
    base = make_repo(tmp_path / "base")
    snap = make_repo(tmp_path / "snap")
    planted = snap / rel
    planted.parent.mkdir(parents=True, exist_ok=True)
    planted.write_text("[pytest11]\nevil = evil_plugin\n", encoding="utf-8")

    assert [change for change, _ in harness_changes(base, snap)] == [rel]


# --- xfail markers ---------------------------------------------------------


def test_xfail_marker_counting(tmp_path):
    repo = make_repo(tmp_path)
    (repo / "tests" / "test_app.py").write_text(
        textwrap.dedent(
            """
            import pytest

            @pytest.mark.xfail(reason="a")
            def test_a():
                assert False

            @pytest.mark.xfail(run=False, reason="b")
            def test_b():
                assert False

            def test_c():
                assert True
            """
        ),
        encoding="utf-8",
    )

    assert count_xfail_markers(repo) == 2


PARAMETRISED_XFAIL = '''\
import pytest


@pytest.mark.parametrize("value", [1, 2])
@pytest.mark.xfail(reason="known rounding difference")
def test_known_failure(value):
    assert value < 0
'''


def test_an_untouched_parametrised_xfail_is_not_an_increase(tmp_path):
    """Review N6 repro: one marker, two junit xfails — like is compared to like."""
    base = make_repo(tmp_path / "base")
    snap = make_repo(tmp_path / "snap")
    for root in (base, snap):
        (root / "tests" / "test_app.py").write_text(PARAMETRISED_XFAIL, encoding="utf-8")

    assert xfail_marker_counts(base, snap) == (1, 1)


def test_a_newly_added_xfail_marker_is_an_increase(tmp_path):
    base = make_repo(tmp_path / "base")
    snap = make_repo(tmp_path / "snap")
    (base / "tests" / "test_app.py").write_text(PARAMETRISED_XFAIL, encoding="utf-8")
    (snap / "tests" / "test_app.py").write_text(
        PARAMETRISED_XFAIL
        + '\n\n@pytest.mark.xfail(reason="added")\ndef test_other():\n    assert False\n',
        encoding="utf-8",
    )

    assert xfail_marker_counts(base, snap) == (1, 2)


# --- product code that can forge a result ----------------------------------


def test_product_code_that_forges_a_report_is_flagged(tmp_path):
    """Review N1 repro (a): the code under test writes the junit file itself."""
    base = make_repo(tmp_path / "base")
    snap = make_repo(tmp_path / "snap")
    (snap / "app.py").write_text(
        textwrap.dedent(
            """\
            VALUE = 1
            import os
            import sys


            def _forge():
                target = next(a for a in sys.argv if a.startswith("--junitxml="))
                open(target.split("=", 1)[1], "w").write("<testsuites/>")
                os._exit(0)


            _forge()
            """
        ),
        encoding="utf-8",
    )

    finding = suspicious_product_code(base, snap)

    assert finding is not None
    assert finding.code == "SUSPICIOUS_PRODUCT_CODE"
    assert finding.severity == HIGH
    assert "app.py:7" in finding.evidence
    assert "sys.argv" in finding.evidence


def test_an_honest_product_change_is_not_flagged(tmp_path):
    base = make_repo(tmp_path / "base")
    snap = make_repo(tmp_path / "snap")
    (snap / "app.py").write_text("VALUE = 2\n", encoding="utf-8")

    assert suspicious_product_code(base, snap) is None


def test_a_changed_test_file_is_not_product_code(tmp_path):
    """The harness diff owns test files; the product-code scan must not double-count."""
    base = make_repo(tmp_path / "base")
    snap = make_repo(tmp_path / "snap")
    (snap / "app.py").write_text(
        "VALUE = 1\nimport os\nos._exit(0)\n", encoding="utf-8"
    )
    (snap / "tests" / "test_app.py").write_text(
        "import sys\n\ndef test_ok():\n    assert sys.argv\n", encoding="utf-8"
    )

    finding = suspicious_product_code(base, snap)

    assert finding is not None
    assert "app.py" in finding.evidence
    assert "tests/test_app.py" not in finding.evidence


# --- the whole verifier path, with the sandbox faked -----------------------


def _junit(*cases: tuple[str, str]) -> str:
    """A pytest-shaped junit document; outcome is ``passed``/``xfail``/``failed``."""
    body = []
    for name, outcome in cases:
        if outcome == "passed":
            body.append(f'<testcase classname="tests.test_app" name="{name}" time="0.001"/>')
        elif outcome == "xfail":
            body.append(
                f'<testcase classname="tests.test_app" name="{name}" time="0.001">'
                '<skipped type="pytest.xfail" message="xfail"/></testcase>'
            )
        else:
            body.append(
                f'<testcase classname="tests.test_app" name="{name}" time="0.001">'
                '<failure message="boom">boom</failure></testcase>'
            )
    return (
        '<?xml version="1.0" encoding="utf-8"?><testsuites><testsuite name="pytest">'
        + "".join(body)
        + "</testsuite></testsuites>"
    )


def fake_sandbox(
    monkeypatch,
    tmp_path,
    *,
    verify_junit,
    verify_stdout,
    baseline_stdout,
    baseline_exit=0,
    baseline_oom=False,
):
    """Replace ``sandbox.run`` with a canned run; the junit is written for real."""
    from ega import verify as verify_module

    after_dirs: list[Path] = []

    def fake_run(cmd, src_dir, limits=None, *, run_id=None, env=None, workdir_after=None, out_dir=None):
        after = Path(tmp_path) / f"after-{len(after_dirs)}"
        after.mkdir(parents=True, exist_ok=True)
        after_dirs.append(after)
        assert env == {"PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1"}, env
        if "--collect-only" in cmd:
            return SandboxResult(
                exit_code=baseline_exit,
                stdout=baseline_stdout,
                stderr="" if baseline_exit == 0 else "ERROR: found no collectors",
                duration_s=0.01,
                timed_out=False,
                oom_killed=baseline_oom,
                isolation="runc",
                workdir_after=after,
                container_name="ega-fake",
            )
        junit_arg = next(part for part in cmd if part.startswith("--junitxml="))
        name = junit_arg.split("=", 1)[1].rsplit("/", 1)[-1]
        (Path(out_dir) / name).write_text(verify_junit, encoding="utf-8")
        return SandboxResult(
            exit_code=0, stdout=verify_stdout, stderr="", duration_s=0.01,
            timed_out=False, oom_killed=False, isolation="runc",
            workdir_after=after, container_name="ega-fake",
        )

    monkeypatch.setattr(verify_module.sandbox, "run", fake_run)
    return after_dirs


def test_a_pristine_parametrised_xfail_raises_no_alarm(tmp_path, monkeypatch):
    """Review N6 end to end: the fixture already xfails; an untouched snapshot is `done`."""
    from ega.verify import Claim, verify

    base = make_repo(tmp_path / "fixture")
    snap = make_repo(tmp_path / "snapshot")
    for root in (base, snap):
        (root / "tests" / "test_app.py").write_text(PARAMETRISED_XFAIL, encoding="utf-8")

    fake_sandbox(
        monkeypatch,
        tmp_path,
        verify_junit=_junit(("test_known_failure[1]", "xfail"), ("test_known_failure[2]", "xfail"),
                            ("test_ok", "passed")),
        verify_stdout="1 passed, 2 xfailed in 0.01s",
        baseline_stdout="3 tests collected in 0.01s",
    )

    verdict = verify(snap, Claim(status="done", tests_claimed_passed=1), baseline_dir=base)

    assert "XFAIL_ADDED" not in [f.code for f in verdict.findings], verdict.first_line()
    assert verdict.counts["xfailed"] == 2
    assert verdict.exit_token == "done", verdict.first_line()


def test_an_added_xfail_marker_is_reported(tmp_path, monkeypatch):
    from ega.verify import Claim, verify

    base = make_repo(tmp_path / "fixture")
    snap = make_repo(tmp_path / "snapshot")
    (base / "tests" / "test_app.py").write_text(PARAMETRISED_XFAIL, encoding="utf-8")
    (snap / "tests" / "test_app.py").write_text(
        PARAMETRISED_XFAIL + '\n\n@pytest.mark.xfail(reason="added")\ndef test_other():\n    assert False\n',
        encoding="utf-8",
    )

    fake_sandbox(
        monkeypatch,
        tmp_path,
        verify_junit=_junit(("test_known_failure[1]", "xfail"), ("test_known_failure[2]", "xfail"),
                            ("test_other", "xfail"), ("test_ok", "passed")),
        verify_stdout="1 passed, 3 xfailed in 0.01s",
        baseline_stdout="3 tests collected in 0.01s",
    )

    verdict = verify(snap, Claim(status="done", tests_claimed_passed=1), baseline_dir=base)

    codes = [f.code for f in verdict.findings]
    assert "XFAIL_ADDED" in codes, verdict.first_line()
    assert verdict.exit_token != "done", verdict.first_line()


def test_without_a_baseline_the_verdict_is_never_done(tmp_path, monkeypatch):
    """Review N3 repro: `baseline_dir=None` used to skip every harness check."""
    from ega.verify import Claim, verify

    snap = make_repo(tmp_path / "snapshot")
    (snap / "tests" / "test_app.py").write_text(
        "def test_a():\n    assert True\n", encoding="utf-8"
    )

    fake_sandbox(
        monkeypatch,
        tmp_path,
        verify_junit=_junit(("test_a", "passed")),
        verify_stdout="1 passed in 0.01s",
        baseline_stdout="1 test collected in 0.01s",
    )

    verdict = verify(snap, Claim(status="done", tests_claimed_passed=1), baseline_dir=None)

    codes = [f.code for f in verdict.findings]
    assert "BASELINE_UNAVAILABLE" in codes, verdict.first_line()
    assert verdict.exit_token == "partial", verdict.first_line()


@pytest.mark.parametrize(
    "baseline_exit, baseline_oom",
    [(2, False), (0, True)],
    ids=["collection-error", "oom-killed"],
)
def test_an_unclean_baseline_is_not_trusted(tmp_path, monkeypatch, baseline_exit, baseline_oom):
    """Review N5 repro: a baseline that exited 2 / was OOM-killed used to be counted.

    Its count must be thrown away rather than compared against, and the run can
    never be `done` on top of a number the baseline was not able to produce.
    """
    from ega.verify import Claim, verify

    base = make_repo(tmp_path / "fixture")
    snap = make_repo(tmp_path / "snapshot")
    (base / "tests" / "test_app.py").write_text("def test_a():\n    assert True\n", encoding="utf-8")
    (snap / "tests" / "test_app.py").write_text("def test_a():\n    assert True\n", encoding="utf-8")

    fake_sandbox(
        monkeypatch,
        tmp_path,
        verify_junit=_junit(("test_a", "passed")),
        verify_stdout="1 passed in 0.01s",
        baseline_stdout="12 tests collected in 0.01s",
        baseline_exit=baseline_exit,
        baseline_oom=baseline_oom,
    )

    verdict = verify(snap, Claim(status="done", tests_claimed_passed=1), baseline_dir=base)

    codes = [f.code for f in verdict.findings]
    assert "BASELINE_UNAVAILABLE" in codes, verdict.first_line()
    assert verdict.baseline_collected is None, verdict.baseline_collected
    assert "BELOW_BASELINE" not in codes, verdict.first_line()
    assert verdict.exit_token != "done", verdict.first_line()