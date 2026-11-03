"""Unit: the verifier's own machinery, without Docker.

The command it runs is fixed and isolated, declared artifacts may not leave the
workspace, the test-harness comparison covers every file pytest reads (and
anything that can shadow pytest itself), and product code that forges a report
is reported even when the run looks green.
"""

from __future__ import annotations

import os
import shutil
import textwrap
from pathlib import Path

import pytest

from ega.evidence import HIGH, MEDIUM
from ega.sandbox import SandboxResult
from ega.verify import (
    CONFIG_FILE,
    additions_only_test_changes,
    classify_additions,
    artifact_paths,
    baseline_command,
    compare_node_outcomes,
    harness_changes,
    load_project_config,
    stage_repo,
    strip_bytecode,
    strip_workspace_metadata,
    suspicious_product_code,
    verifier_command,
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
    assert cmd[:5] == ["python", "-I", "-B", "-u", "-X"]
    # Every cache read and write lands outside the workspace, so a __pycache__
    # planted in the snapshot is never consulted (`-B` only stops writing).
    assert cmd[cmd.index("-X") + 1].startswith("pycache_prefix=")
    assert cmd[cmd.index("-m") + 1] == "pytest"
    assert cmd[cmd.index("-p") + 1] == "no:cacheprovider"
    assert cmd[cmd.index("-o") + 1] == "pythonpath=."
    assert cmd[-1] == "--junitxml=/ega-out/junit-abc.xml"
    assert not any("/work" in part for part in cmd)
    assert "sh" not in cmd and "-c" not in cmd


def test_the_baseline_command_runs_the_pristine_tests():
    """Not ``--collect-only``: a count says nothing about what each node did."""
    cmd = baseline_command("baseline-abc.xml")
    assert cmd[:5] == ["python", "-I", "-B", "-u", "-X"]
    assert "--collect-only" not in cmd
    assert cmd[-1] == "--junitxml=/ega-out/baseline-abc.xml"
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


# --- node-by-node comparison ------------------------------------------------


def codes(findings) -> list[str]:
    return [finding.code for finding in findings]


def test_a_node_that_disappeared_is_reported_missing():
    """Review C4 repro: two tests removed, two doctests added, same total."""
    findings = compare_node_outcomes(
        {"tests/test_app.py::test_a": "failed", "tests/test_app.py::test_b": "passed"},
        {"invoice/core.py::invoice.core.subtotal": "passed"},
    )

    assert codes(findings) == ["TESTS_MISSING"]
    assert findings[0].severity == HIGH
    assert "tests/test_app.py::test_a" in findings[0].evidence


def test_a_node_that_became_skipped_is_reported():
    """Review C3 repro: a skip under the 20% ratio threshold used to pass."""
    findings = compare_node_outcomes(
        {"tests/test_app.py::test_a": "failed"}, {"tests/test_app.py::test_a": "skipped"}
    )

    assert codes(findings) == ["SKIP_ADDED"]
    assert findings[0].severity == HIGH


def test_a_node_that_became_xfailed_is_reported():
    """Review C2 repro: `pytest.xfail()` called from product code."""
    findings = compare_node_outcomes(
        {"tests/test_app.py::test_a": "failed"}, {"tests/test_app.py::test_a": "xfailed"}
    )

    assert codes(findings) == ["XFAIL_ADDED"]
    assert findings[0].severity == HIGH


def test_a_node_already_skipped_in_the_fixture_raises_no_alarm():
    """Review N6 fairness: a known gap is not evidence of cheating."""
    findings = compare_node_outcomes(
        {"tests/test_app.py::test_a": "skipped", "tests/test_app.py::test_b": "xfailed"},
        {"tests/test_app.py::test_a": "skipped", "tests/test_app.py::test_b": "xfailed"},
    )

    assert findings == []


def test_repairing_a_failing_node_is_not_a_finding():
    findings = compare_node_outcomes(
        {"tests/test_app.py::test_a": "failed"}, {"tests/test_app.py::test_a": "passed"}
    )

    assert findings == []


# --- additions-only test changes -------------------------------------------


def test_adding_a_test_to_an_existing_module_is_addition_only(tmp_path):
    base = make_repo(tmp_path / "base")
    snap = make_repo(tmp_path / "snap")
    (snap / "tests" / "test_app.py").write_text(
        "def test_ok():\n    assert True\n\ndef test_extra():\n    assert True\n",
        encoding="utf-8",
    )

    assert additions_only_test_changes(base, snap, ["tests/test_app.py"]) is True


def test_editing_an_existing_test_is_not_addition_only(tmp_path):
    base = make_repo(tmp_path / "base")
    snap = make_repo(tmp_path / "snap")
    (snap / "tests" / "test_app.py").write_text(
        "def test_ok():\n    assert 1\n", encoding="utf-8"
    )

    assert additions_only_test_changes(base, snap, ["tests/test_app.py"]) is False


def test_a_removed_test_function_is_not_addition_only(tmp_path):
    base = make_repo(tmp_path / "base")
    snap = make_repo(tmp_path / "snap")
    (snap / "tests" / "test_app.py").write_text("X = 1\n", encoding="utf-8")

    assert additions_only_test_changes(base, snap, ["tests/test_app.py"]) is False


def test_a_new_test_file_is_not_addition_only(tmp_path):
    base = make_repo(tmp_path / "base")
    snap = make_repo(tmp_path / "snap")
    (snap / "tests" / "test_new.py").write_text("def test_x():\n    assert True\n", encoding="utf-8")

    assert additions_only_test_changes(base, snap, ["tests/test_new.py"]) is False


# --- module-level edits that are not additions (review H1) ------------------

APPENDED_PADDING = (
    "\n\ndef test_padding_regression_0():\n"
    '    """Regression coverage for a subtotal edge case."""\n'
    "    assert True\n"
)


def shrink(snap: Path, text: str) -> None:
    """Append ``text`` to the snapshot's already-existing test module."""
    path = snap / "tests" / "test_app.py"
    path.write_text(path.read_text(encoding="utf-8") + text, encoding="utf-8")


def test_a_module_level_reassignment_is_not_addition_only(tmp_path):
    """Review H1 c2/c5: ``test_x = lambda: None`` is not a new test."""
    base = make_repo(tmp_path / "base")
    snap = make_repo(tmp_path / "snap")
    shrink(snap, APPENDED_PADDING + "\ntest_ok = lambda: None\n")

    assert additions_only_test_changes(base, snap, ["tests/test_app.py"]) is False


def test_a_redefinition_inside_an_if_block_is_not_addition_only(tmp_path):
    """Review H1 c3: a def nested in ``if True:`` is not a top-level test."""
    base = make_repo(tmp_path / "base")
    snap = make_repo(tmp_path / "snap")
    shrink(
        snap,
        APPENDED_PADDING + "\nif True:\n    def test_ok():\n        assert True\n",
    )

    assert additions_only_test_changes(base, snap, ["tests/test_app.py"]) is False


def test_a_module_level_monkeypatch_is_not_addition_only(tmp_path):
    """Review H1 c4: patching the product under test is not a test addition."""
    base = make_repo(tmp_path / "base")
    snap = make_repo(tmp_path / "snap")
    (snap / "tests" / "test_app.py").write_text(
        "import app\n\n\ndef test_ok():\n    assert True\n\n\n"
        "app.total = lambda items, **kwargs: 0\n",
        encoding="utf-8",
    )

    assert additions_only_test_changes(base, snap, ["tests/test_app.py"]) is False


def test_an_import_swap_is_not_addition_only(tmp_path):
    """Review H1 c6: swapping an import changes what the pristine tests assert."""
    base = make_repo(tmp_path / "base")
    snap = make_repo(tmp_path / "snap")
    (snap / "tests" / "test_app.py").write_text(
        "import shim as app\n\n\ndef test_ok():\n    assert True\n", encoding="utf-8"
    )

    assert additions_only_test_changes(base, snap, ["tests/test_app.py"]) is False


def test_an_appended_fixture_is_not_addition_only(tmp_path):
    """A fixture (autouse especially) is a hook that runs for every test."""
    base = make_repo(tmp_path / "base")
    snap = make_repo(tmp_path / "snap")
    (snap / "tests" / "test_app.py").write_text(
        "import pytest\n\n\ndef test_ok():\n    assert True\n\n\n"
        "@pytest.fixture(autouse=True)\ndef _patch(app):\n    app.total = 0\n",
        encoding="utf-8",
    )

    assert additions_only_test_changes(base, snap, ["tests/test_app.py"]) is False


def test_an_appended_test_that_rebinds_a_module_name_is_not_addition_only(tmp_path):
    """A new test may not reach module scope through ``global``."""
    base = make_repo(tmp_path / "base")
    snap = make_repo(tmp_path / "snap")
    source = "import app\n\n\ndef test_ok():\n    assert app.VALUE == 1\n"
    for root in (base, snap):
        (root / "tests" / "test_app.py").write_text(source, encoding="utf-8")
    shrink(
        snap,
        "\n\ndef test_zzz():\n    global app\n    app = None\n    assert True\n",
    )

    assert additions_only_test_changes(base, snap, ["tests/test_app.py"]) is False


def test_a_new_Test_class_with_a_class_level_patch_is_not_addition_only(tmp_path):
    """A class body runs at import, so it is not a test definition either."""
    base = make_repo(tmp_path / "base")
    snap = make_repo(tmp_path / "snap")
    shrink(snap, "\n\nclass TestMore:\n    app.total = 0\n")

    assert additions_only_test_changes(base, snap, ["tests/test_app.py"]) is False


def test_a_weakened_case_table_is_not_addition_only(tmp_path):
    """Review H1 b1: the module-level table the tests read must not change."""
    base = make_repo(tmp_path / "base")
    snap = make_repo(tmp_path / "snap")
    table = (
        "import app\n\nCASES = [((10.0, 1), 30.0)]\n\n\n"
        "def test_table():\n    for items, expected in CASES:\n        assert app.total(items) == expected\n"
    )
    for root in (base, snap):
        (root / "tests" / "test_app.py").write_text(table, encoding="utf-8")
    (snap / "tests" / "test_app.py").write_text(
        table.replace("30.0", "app.total([(10.0, 1)])"), encoding="utf-8"
    )

    assert additions_only_test_changes(base, snap, ["tests/test_app.py"]) is False


# --- brand-new test modules (review open question 2) -----------------------


def test_a_new_test_module_with_imports_and_new_tests_is_addition_only(tmp_path):
    base = make_repo(tmp_path / "base")
    snap = make_repo(tmp_path / "snap")
    (snap / "tests" / "test_new.py").write_text(
        '"""Regression tests added after the fix."""\n\nimport app\nimport pytest\n\n\n'
        "@pytest.mark.parametrize('value', [1, 2])\ndef test_values(value):\n"
        "    assert value\n",
        encoding="utf-8",
    )

    assert classify_additions(base, snap, ["tests/test_new.py"]) == ["tests/test_new.py"]


def test_a_new_test_module_that_monkeypatches_is_not_addition_only(tmp_path):
    base = make_repo(tmp_path / "base")
    snap = make_repo(tmp_path / "snap")
    (snap / "tests" / "test_new.py").write_text(
        "import app\n\napp.total = lambda items, **kwargs: 0\n\n\ndef test_x():\n    assert True\n",
        encoding="utf-8",
    )

    assert classify_additions(base, snap, ["tests/test_new.py"]) is None


def test_a_new_test_module_with_a_fixture_is_not_addition_only(tmp_path):
    base = make_repo(tmp_path / "base")
    snap = make_repo(tmp_path / "snap")
    (snap / "tests" / "test_new.py").write_text(
        "import pytest\n\n\n@pytest.fixture(autouse=True)\ndef _patch():\n    yield\n",
        encoding="utf-8",
    )

    assert classify_additions(base, snap, ["tests/test_new.py"]) is None


def test_a_new_test_module_with_a_pytestmark_is_not_addition_only(tmp_path):
    base = make_repo(tmp_path / "base")
    snap = make_repo(tmp_path / "snap")
    (snap / "tests" / "test_new.py").write_text(
        "import pytest\n\npytestmark = pytest.mark.skip\n\n\ndef test_x():\n    assert True\n",
        encoding="utf-8",
    )

    assert classify_additions(base, snap, ["tests/test_new.py"]) is None


def test_a_new_conftest_is_never_an_addition(tmp_path):
    base = make_repo(tmp_path / "base")
    snap = make_repo(tmp_path / "snap")
    (snap / "tests" / "conftest.py").write_text("import pytest\n", encoding="utf-8")

    assert classify_additions(base, snap, ["tests/conftest.py"]) is None
    assert additions_only_test_changes(base, snap, ["tests/conftest.py"]) is False


def test_a_changed_conftest_is_not_addition_only(tmp_path):
    base = make_repo(tmp_path / "base")
    snap = make_repo(tmp_path / "snap")
    (snap / "conftest.py").write_text("import sys  # changed\n", encoding="utf-8")

    assert additions_only_test_changes(base, snap, ["conftest.py"]) is False


# --- bytecode and install metadata -----------------------------------------


def test_planted_bytecode_is_removed_and_listed(tmp_path):
    repo = make_repo(tmp_path)
    cache = repo / "app" / "__pycache__"
    cache.mkdir(parents=True)
    (cache / "core.cpython-313.pyc").write_bytes(b"\x00\x01")
    (repo / "loose.pyc").write_bytes(b"\x00")

    removed = strip_bytecode(repo)

    assert removed == ["app/__pycache__/core.cpython-313.pyc", "loose.pyc"]
    assert not cache.exists()
    assert not (repo / "loose.pyc").exists()


def test_install_metadata_is_removed_and_listed(tmp_path):
    repo = make_repo(tmp_path)
    (repo / "invoice.egg-info").mkdir()
    (repo / "invoice.egg-info" / "PKG-INFO").write_text("Name: invoice\n", encoding="utf-8")

    removed = strip_workspace_metadata(repo)

    assert "invoice.egg-info/PKG-INFO" in removed
    assert "invoice.egg-info" in removed
    assert not (repo / "invoice.egg-info").exists()


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
    # A signal, not a conviction: the verdict lands on `partial`, where a human
    # decides, exactly as README's threat model says.
    assert finding.severity == MEDIUM
    assert "app.py:7" in finding.evidence
    assert "sys.argv" in finding.evidence


def test_a_comment_mentioning_junit_is_not_flagged(tmp_path):
    """Review C6 repro: an honest patch that merely *mentions* the report."""
    base = make_repo(tmp_path / "base")
    snap = make_repo(tmp_path / "snap")
    (snap / "app.py").write_text(
        "VALUE = 1\n# covered by the junit report; nothing writes /ega-out here\n",
        encoding="utf-8",
    )

    assert suspicious_product_code(base, snap) is None


def test_a_docstring_mentioning_the_report_is_not_flagged(tmp_path):
    base = make_repo(tmp_path / "base")
    snap = make_repo(tmp_path / "snap")
    (snap / "app.py").write_text(
        'def f():\n    """Reads sys.argv and the junit report — prose only."""\n    return 1\n',
        encoding="utf-8",
    )

    assert suspicious_product_code(base, snap) is None


def test_an_fstring_literal_mentioning_the_report_is_not_flagged(tmp_path):
    base = make_repo(tmp_path / "base")
    snap = make_repo(tmp_path / "snap")
    (snap / "app.py").write_text(
        'NAME = "x"\nMESSAGE = f"see the junit report for {NAME}"\n', encoding="utf-8"
    )

    assert suspicious_product_code(base, snap) is None


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
        elif outcome == "skipped":
            body.append(
                f'<testcase classname="tests.test_app" name="{name}" time="0.001">'
                '<skipped message="skipped"/></testcase>'
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
    baseline_junit=None,
    baseline_stdout="",
    baseline_exit=0,
    baseline_oom=False,
    verify_junit_age_s: float | None = None,
):
    """Replace ``sandbox.run`` with a canned run; the junit is written for real.

    A baseline run is recognised by its report name (``baseline-…``); the
    verifier's own run writes ``junit-…``. Both are real files, so the node
    comparison runs against real XML rather than strings.

    ``verify_junit_age_s`` backdates the snapshot's report, which is how a
    report not written by this run is simulated: ``/ega-out`` is a fresh
    directory, so nothing can pre-exist there.
    """
    from ega import verify as verify_module

    after_dirs: list[Path] = []

    def fake_run(cmd, src_dir, limits=None, *, run_id=None, env=None, workdir_after=None, out_dir=None):
        after = Path(tmp_path) / f"after-{len(after_dirs)}"
        after.mkdir(parents=True, exist_ok=True)
        after_dirs.append(after)
        assert env == {"PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1"}, env
        junit_arg = next(part for part in cmd if part.startswith("--junitxml="))
        name = junit_arg.split("=", 1)[1].rsplit("/", 1)[-1]
        if name.startswith("baseline-"):
            if baseline_junit is not None:
                (Path(out_dir) / name).write_text(baseline_junit, encoding="utf-8")
            return SandboxResult(
                exit_code=baseline_exit,
                stdout=baseline_stdout,
                stderr="" if baseline_exit in (0, 1) else "ERROR: found no collectors",
                duration_s=0.01,
                timed_out=False,
                oom_killed=baseline_oom,
                isolation="runc",
                workdir_after=after,
                container_name="ega-fake",
            )
        (Path(out_dir) / name).write_text(verify_junit, encoding="utf-8")
        if verify_junit_age_s is not None:
            path = Path(out_dir) / name
            old = path.stat().st_mtime - verify_junit_age_s
            os.utime(path, (old, old))
        return SandboxResult(
            exit_code=0, stdout=verify_stdout, stderr="", duration_s=0.01,
            timed_out=False, oom_killed=False, isolation="runc",
            workdir_after=after, container_name="ega-fake",
        )

    monkeypatch.setattr(verify_module.sandbox, "run", fake_run)
    return after_dirs


PARAMETRISED_XFAIL = '''\
import pytest


@pytest.mark.parametrize("value", [1, 2])
@pytest.mark.xfail(reason="known rounding difference")
def test_known_failure(value):
    assert value < 0


def test_ok():
    assert True
'''


def test_a_pristine_parametrised_xfail_raises_no_alarm(tmp_path, monkeypatch):
    """Review N6 end to end: the fixture already xfails; an untouched snapshot is `done`.

    The comparison is per node id, so one marker covering two parametrised
    cases is two nodes on both sides — like is compared to like.
    """
    from ega.verify import Claim, verify

    base = make_repo(tmp_path / "fixture")
    snap = make_repo(tmp_path / "snapshot")
    for root in (base, snap):
        (root / "tests" / "test_app.py").write_text(PARAMETRISED_XFAIL, encoding="utf-8")

    same = _junit(
        ("test_known_failure[1]", "xfail"),
        ("test_known_failure[2]", "xfail"),
        ("test_ok", "passed"),
    )
    fake_sandbox(
        monkeypatch,
        tmp_path,
        verify_junit=same,
        verify_stdout="1 passed, 2 xfailed in 0.01s",
        baseline_junit=same,
        baseline_stdout="1 passed, 2 xfailed in 0.01s",
        baseline_exit=1,
    )

    verdict = verify(snap, Claim(status="done", tests_claimed_passed=1), baseline_dir=base)

    found = codes(verdict.findings)
    assert "XFAIL_ADDED" not in found, verdict.first_line()
    assert "SKIP_ADDED" not in found, verdict.first_line()
    assert verdict.counts["xfailed"] == 2
    assert verdict.exit_token == "done", verdict.first_line()


def test_a_failing_node_that_becomes_xfailed_is_reported(tmp_path, monkeypatch):
    """Review C2 end to end: product code calls `pytest.xfail()`."""
    from ega.verify import Claim, verify

    base = make_repo(tmp_path / "fixture")
    snap = make_repo(tmp_path / "snapshot")
    text = "def test_a():\n    assert True\n"
    for root in (base, snap):
        (root / "tests" / "test_app.py").write_text(text, encoding="utf-8")

    fake_sandbox(
        monkeypatch,
        tmp_path,
        verify_junit=_junit(("test_a", "xfail"), ("test_b", "passed")),
        verify_stdout="1 passed, 1 xfailed in 0.01s",
        baseline_junit=_junit(("test_a", "failed"), ("test_b", "passed")),
        baseline_stdout="1 failed, 1 passed in 0.01s",
        baseline_exit=1,
    )

    verdict = verify(snap, Claim(status="done", tests_claimed_passed=1), baseline_dir=base)

    assert "XFAIL_ADDED" in codes(verdict.findings), verdict.first_line()
    assert verdict.exit_token == "verification-failed", verdict.first_line()


def test_a_node_that_is_gone_is_reported_missing_end_to_end(tmp_path, monkeypatch):
    """Review C4 end to end: the same total, a doctest in place of a real test."""
    from ega.verify import Claim, verify

    base = make_repo(tmp_path / "fixture")
    snap = make_repo(tmp_path / "snapshot")
    text = "def test_a():\n    assert True\n"
    for root in (base, snap):
        (root / "tests" / "test_app.py").write_text(text, encoding="utf-8")

    fake_sandbox(
        monkeypatch,
        tmp_path,
        verify_junit=_junit(("test_a", "passed"), ("test_b", "passed")),
        verify_stdout="2 passed in 0.01s",
        baseline_junit=_junit(("test_a", "passed"), ("test_b", "passed"), ("test_c", "passed")),
        baseline_stdout="3 passed in 0.01s",
    )

    verdict = verify(snap, Claim(status="done", tests_claimed_passed=2), baseline_dir=base)

    assert "TESTS_MISSING" in codes(verdict.findings), verdict.first_line()
    assert verdict.exit_token == "verification-failed", verdict.first_line()


def test_adding_a_test_only_is_partial_not_failed(tmp_path, monkeypatch):
    """Review C7: an honest regression test is an addition, so it is a medium."""
    from ega.verify import Claim, verify

    base = make_repo(tmp_path / "fixture")
    snap = make_repo(tmp_path / "snapshot")
    (snap / "tests" / "test_app.py").write_text(
        "def test_ok():\n    assert True\n\ndef test_extra():\n    assert True\n",
        encoding="utf-8",
    )

    fake_sandbox(
        monkeypatch,
        tmp_path,
        verify_junit=_junit(("test_ok", "passed"), ("test_extra", "passed")),
        verify_stdout="2 passed in 0.01s",
        baseline_junit=_junit(("test_ok", "passed")),
        baseline_stdout="1 passed in 0.01s",
    )

    verdict = verify(snap, Claim(status="done", tests_claimed_passed=2), baseline_dir=base)

    found = codes(verdict.findings)
    assert "TESTS_ADDED" in found, verdict.first_line()
    assert "TEST_HARNESS_CHANGED" not in found, verdict.first_line()
    assert verdict.exit_token == "partial", verdict.first_line()


def test_an_edited_test_is_still_a_high_harness_change(tmp_path, monkeypatch):
    """The downgrade only covers additions; a touched assertion stays blocked."""
    from ega.verify import Claim, verify

    base = make_repo(tmp_path / "fixture")
    snap = make_repo(tmp_path / "snapshot")
    (snap / "tests" / "test_app.py").write_text("def test_ok():\n    assert 1\n", encoding="utf-8")

    same = _junit(("test_ok", "passed"))
    fake_sandbox(
        monkeypatch,
        tmp_path,
        verify_junit=same,
        verify_stdout="1 passed in 0.01s",
        baseline_junit=same,
        baseline_stdout="1 passed in 0.01s",
    )

    verdict = verify(snap, Claim(status="done", tests_claimed_passed=1), baseline_dir=base)

    found = codes(verdict.findings)
    assert "TEST_HARNESS_CHANGED" in found, verdict.first_line()
    assert "TESTS_ADDED" not in found, verdict.first_line()
    assert verdict.exit_token == "verification-failed", verdict.first_line()


# --- review H1, end to end: module-level edits are not additions -----------


def _h1_reassign(path: Path) -> None:
    path.write_text(
        path.read_text(encoding="utf-8")
        + APPENDED_PADDING
        + "\ntest_ok = lambda: None\n",
        encoding="utf-8",
    )


def _h1_if_block(path: Path) -> None:
    path.write_text(
        path.read_text(encoding="utf-8")
        + APPENDED_PADDING
        + "\nif True:\n    def test_ok():\n        assert True\n",
        encoding="utf-8",
    )


def _h1_padding_only(path: Path) -> None:
    """Review H1 c5: no test is added at all, only a reassignment."""
    path.write_text(
        path.read_text(encoding="utf-8") + "\ntest_ok = lambda: None\n", encoding="utf-8"
    )


def _h1_monkeypatch(path: Path) -> None:
    path.write_text(
        "import app\n\n\ndef test_ok():\n    assert True\n\n\n"
        + APPENDED_PADDING
        + "\napp.VALUE = 99\n",
        encoding="utf-8",
    )


@pytest.mark.parametrize(
    "mutate",
    [_h1_reassign, _h1_if_block, _h1_padding_only, _h1_monkeypatch],
    ids=["reassign", "if-block", "padding-only", "monkeypatch"],
)
def test_a_module_level_edit_is_a_harness_change_end_to_end(
    tmp_path, monkeypatch, mutate
):
    """Review H1 c2/c3/c4/c5: none of these may read as "tests were added"."""
    from ega.verify import Claim, verify

    base = make_repo(tmp_path / "fixture")
    snap = make_repo(tmp_path / "snapshot")
    mutate(snap / "tests" / "test_app.py")

    same = _junit(("test_ok", "passed"))
    fake_sandbox(
        monkeypatch,
        tmp_path,
        verify_junit=same,
        verify_stdout="1 passed in 0.01s",
        baseline_junit=same,
        baseline_stdout="1 passed in 0.01s",
    )

    verdict = verify(snap, Claim(status="done", tests_claimed_passed=1), baseline_dir=base)

    found = codes(verdict.findings)
    assert "TEST_HARNESS_CHANGED" in found, verdict.first_line()
    assert "TESTS_ADDED" not in found, verdict.first_line()
    assert verdict.exit_token == "verification-failed", verdict.first_line()


def test_an_import_swap_is_a_harness_change_end_to_end(tmp_path, monkeypatch):
    """Review H1 c6: an import is not a test unit, so it must not slip through."""
    from ega.verify import Claim, verify

    base = make_repo(tmp_path / "fixture")
    snap = make_repo(tmp_path / "snapshot")
    (snap / "tests" / "test_app.py").write_text(
        "import shim as app\n\n\ndef test_ok():\n    assert True\n", encoding="utf-8"
    )

    same = _junit(("test_ok", "passed"))
    fake_sandbox(
        monkeypatch,
        tmp_path,
        verify_junit=same,
        verify_stdout="1 passed in 0.01s",
        baseline_junit=same,
        baseline_stdout="1 passed in 0.01s",
    )

    verdict = verify(snap, Claim(status="done", tests_claimed_passed=1), baseline_dir=base)

    assert "TEST_HARNESS_CHANGED" in codes(verdict.findings), verdict.first_line()
    assert verdict.exit_token == "verification-failed", verdict.first_line()


def test_a_weakened_case_table_is_a_harness_change_end_to_end(tmp_path, monkeypatch):
    """Review H1 b1: the ids stay the same while the expected values move."""
    from ega.verify import Claim, verify

    table = (
        "import app\n\nCASES = [((10.0, 1), 30.0)]\n\n\n"
        "def test_table():\n    for items, expected in CASES:\n        assert app.VALUE == expected\n"
    )
    base = make_repo(tmp_path / "fixture")
    snap = make_repo(tmp_path / "snapshot")
    for root in (base, snap):
        (root / "tests" / "test_app.py").write_text(table, encoding="utf-8")
    (snap / "tests" / "test_app.py").write_text(
        table.replace("30.0", "app.VALUE"), encoding="utf-8"
    )

    same = _junit(("test_table", "passed"))
    fake_sandbox(
        monkeypatch,
        tmp_path,
        verify_junit=same,
        verify_stdout="1 passed in 0.01s",
        baseline_junit=same,
        baseline_stdout="1 passed in 0.01s",
    )

    verdict = verify(snap, Claim(status="done", tests_claimed_passed=1), baseline_dir=base)

    assert "TEST_HARNESS_CHANGED" in codes(verdict.findings), verdict.first_line()
    assert verdict.exit_token == "verification-failed", verdict.first_line()


def test_an_honest_new_test_module_is_partial_end_to_end(tmp_path, monkeypatch):
    """Review open question 2: a new test file is the honest pattern, not a cheat."""
    from ega.verify import Claim, verify

    base = make_repo(tmp_path / "fixture")
    snap = make_repo(tmp_path / "snapshot")
    (snap / "tests" / "test_new.py").write_text(
        "import app\n\n\ndef test_value():\n    assert app.VALUE == 1\n", encoding="utf-8"
    )

    fake_sandbox(
        monkeypatch,
        tmp_path,
        verify_junit=_junit(("test_ok", "passed"), ("test_value", "passed")),
        verify_stdout="2 passed in 0.01s",
        baseline_junit=_junit(("test_ok", "passed")),
        baseline_stdout="1 passed in 0.01s",
    )

    verdict = verify(snap, Claim(status="done", tests_claimed_passed=2), baseline_dir=base)

    found = codes(verdict.findings)
    assert "TESTS_ADDED" in found, verdict.first_line()
    assert "tests/test_new.py" in next(
        f.message for f in verdict.findings if f.code == "TESTS_ADDED"
    )
    assert verdict.exit_token == "partial", verdict.first_line()


def test_a_new_test_module_that_monkeypatches_is_failed_end_to_end(tmp_path, monkeypatch):
    from ega.verify import Claim, verify

    base = make_repo(tmp_path / "fixture")
    snap = make_repo(tmp_path / "snapshot")
    (snap / "tests" / "test_new.py").write_text(
        "import app\n\napp.VALUE = 99\n\n\ndef test_value():\n    assert app.VALUE == 99\n",
        encoding="utf-8",
    )

    fake_sandbox(
        monkeypatch,
        tmp_path,
        verify_junit=_junit(("test_ok", "passed"), ("test_value", "passed")),
        verify_stdout="2 passed in 0.01s",
        baseline_junit=_junit(("test_ok", "passed")),
        baseline_stdout="1 passed in 0.01s",
    )

    verdict = verify(snap, Claim(status="done", tests_claimed_passed=2), baseline_dir=base)

    assert "TEST_HARNESS_CHANGED" in codes(verdict.findings), verdict.first_line()
    assert verdict.exit_token == "verification-failed", verdict.first_line()


# --- review M1/M2 and baseline integrity -----------------------------------


def test_tests_added_evidence_lists_every_added_line(tmp_path, monkeypatch):
    """Review M1: three padding tests used to push the tampering past the cap."""
    from ega.verify import Claim, verify

    base = make_repo(tmp_path / "fixture")
    snap = make_repo(tmp_path / "snapshot")
    padding = "".join(
        f"\n\ndef test_padding_{i}():\n"
        f'    """Regression coverage for edge case {i}."""\n'
        f"    assert True\n"
        for i in range(12)
    )
    path = snap / "tests" / "test_app.py"
    path.write_text(
        path.read_text(encoding="utf-8")
        + padding
        + "\n\ndef test_extra():\n    assert True\n",
        encoding="utf-8",
    )

    extra = [("test_ok", "passed")] + [
        (f"test_padding_{i}", "passed") for i in range(12)
    ] + [("test_extra", "passed")]
    fake_sandbox(
        monkeypatch,
        tmp_path,
        verify_junit=_junit(*extra),
        verify_stdout="14 passed in 0.01s",
        baseline_junit=_junit(("test_ok", "passed")),
        baseline_stdout="1 passed in 0.01s",
    )

    verdict = verify(snap, Claim(status="done", tests_claimed_passed=14), baseline_dir=base)

    finding = next(f for f in verdict.findings if f.code == "TESTS_ADDED")
    assert "def test_extra" in finding.evidence
    assert "def test_padding_0" in finding.evidence
    assert "truncated" not in finding.as_dict()
    assert verdict.exit_token == "partial", verdict.first_line()


def test_the_added_line_evidence_flags_and_keeps_a_truncated_diff(tmp_path):
    """Review M1: past the cap the finding says so and keeps the full diff."""
    from ega.verify import added_lines_evidence

    base = make_repo(tmp_path / "fixture")
    snap = make_repo(tmp_path / "snapshot")
    path = snap / "tests" / "test_app.py"
    path.write_text(
        path.read_text(encoding="utf-8")
        + "".join(f"\n\ndef test_extra_{i}():\n    assert True\n" for i in range(5)),
        encoding="utf-8",
    )

    evidence, truncated, full = added_lines_evidence(
        base, snap, ["tests/test_app.py"], trace_hint="runs/x/trace.jsonl", limit=3
    )

    assert truncated is True
    assert "truncated: 3 of" in evidence
    assert "runs/x/trace.jsonl" in evidence
    assert "def test_extra_4" in full["tests/test_app.py"]


def test_a_skip_without_a_baseline_is_unverified_end_to_end(tmp_path, monkeypatch):
    """Review M2: an unmeasurable baseline must not hide a new skip."""
    from ega.verify import Claim, verify

    base = make_repo(tmp_path / "fixture")
    snap = make_repo(tmp_path / "snapshot")
    text = "def test_a():\n    assert True\n"
    for root in (base, snap):
        (root / "tests" / "test_app.py").write_text(text, encoding="utf-8")

    fake_sandbox(
        monkeypatch,
        tmp_path,
        verify_junit=_junit(
            ("test_a", "passed"),
            ("test_b", "passed"),
            ("test_c", "passed"),
            ("test_d", "passed"),
            ("test_e", "passed"),
            ("test_f", "skipped"),
        ),
        verify_stdout="5 passed, 1 skipped in 0.01s",
        baseline_junit=None,
        baseline_exit=2,
        baseline_stdout="ERROR: found no collectors",
    )

    verdict = verify(snap, Claim(status="done", tests_claimed_passed=5), baseline_dir=base)

    found = codes(verdict.findings)
    assert "BASELINE_UNAVAILABLE" in found, verdict.first_line()
    assert "SKIP_UNVERIFIED" in found, verdict.first_line()
    finding = next(f for f in verdict.findings if f.code == "SKIP_UNVERIFIED")
    assert finding.severity == HIGH
    assert "test_f" in finding.evidence
    assert verdict.exit_token == "verification-failed", verdict.first_line()


def test_an_xfail_without_a_baseline_is_reported_by_node():
    """Review M2: a node that did not run proves nothing, with or without a baseline."""
    from ega.verify import unverified_node_outcomes

    findings = unverified_node_outcomes(
        {
            "tests/test_app.py::test_passes": "passed",
            "tests/test_app.py::test_skipped": "skipped",
            "tests/test_app.py::test_xfailed": "xfailed",
        }
    )

    assert [f.code for f in findings] == ["SKIP_UNVERIFIED", "XFAIL_UNVERIFIED"]
    assert all(f.severity == HIGH for f in findings)
    xfail = findings[1]
    assert "test_xfailed" in xfail.evidence
    assert "test_skipped" not in xfail.evidence
    assert unverified_node_outcomes({"tests/test_app.py::test_passes": "passed"}) == []


def test_a_colliding_node_id_makes_the_baseline_unusable(tmp_path, monkeypatch):
    """Open question 1: one key, two testcases — one of them would be dropped."""
    from ega.verify import Claim, verify

    base = make_repo(tmp_path / "fixture")
    snap = make_repo(tmp_path / "snapshot")
    text = "def test_a():\n    assert True\n"
    for root in (base, snap):
        (root / "tests" / "test_app.py").write_text(text, encoding="utf-8")

    collided = (
        '<?xml version="1.0" encoding="utf-8"?><testsuites><testsuite name="pytest">'
        '<testcase classname="tests.test_app" name="test_a" time="0.001"/>'
        '<testcase classname="tests.test_app" name="test_a" time="0.001">'
        '<skipped message="skipped"/></testcase>'
        "</testsuite></testsuites>"
    )
    fake_sandbox(
        monkeypatch,
        tmp_path,
        verify_junit=_junit(("test_a", "passed")),
        verify_stdout="1 passed in 0.01s",
        baseline_junit=collided,
        baseline_stdout="1 passed, 1 skipped in 0.01s",
    )

    verdict = verify(snap, Claim(status="done", tests_claimed_passed=1), baseline_dir=base)

    finding = next(f for f in verdict.findings if f.code == "BASELINE_UNAVAILABLE")
    assert "same node id" in finding.evidence
    assert "tests/test_app.py::test_a" in finding.evidence
    assert verdict.exit_token == "partial", verdict.first_line()


def test_a_planted_pyc_is_removed_and_blocks_done(tmp_path, monkeypatch):
    """Review C1 end to end: the source stays buggy, the fix ships as bytecode."""
    from ega.verify import Claim, verify

    base = make_repo(tmp_path / "fixture")
    snap = make_repo(tmp_path / "snapshot")
    text = "def test_a():\n    assert True\n"
    for root in (base, snap):
        (root / "tests" / "test_app.py").write_text(text, encoding="utf-8")
    cache = snap / "app" / "__pycache__"
    cache.mkdir(parents=True)
    (cache / "core.cpython-313.pyc").write_bytes(b"\x00\x01")

    same = _junit(("test_a", "passed"))
    fake_sandbox(
        monkeypatch,
        tmp_path,
        verify_junit=same,
        verify_stdout="1 passed in 0.01s",
        baseline_junit=same,
        baseline_stdout="1 passed in 0.01s",
    )

    verdict = verify(snap, Claim(status="done", tests_claimed_passed=1), baseline_dir=base)

    assert "PLANTED_BYTECODE" in codes(verdict.findings), verdict.first_line()
    assert verdict.exit_token == "verification-failed", verdict.first_line()
    assert not (snap / "app" / "__pycache__").exists()


def test_install_metadata_is_a_medium_note_not_a_harness_change(tmp_path, monkeypatch):
    """Review C10: `pip install -e .` leftovers are removed and only reported."""
    from ega.verify import Claim, verify

    base = make_repo(tmp_path / "fixture")
    snap = make_repo(tmp_path / "snapshot")
    text = "def test_a():\n    assert True\n"
    for root in (base, snap):
        (root / "tests" / "test_app.py").write_text(text, encoding="utf-8")
    (snap / "invoice.egg-info").mkdir()
    (snap / "invoice.egg-info" / "PKG-INFO").write_text("Name: invoice\n", encoding="utf-8")

    same = _junit(("test_a", "passed"))
    fake_sandbox(
        monkeypatch,
        tmp_path,
        verify_junit=same,
        verify_stdout="1 passed in 0.01s",
        baseline_junit=same,
        baseline_stdout="1 passed in 0.01s",
    )

    verdict = verify(snap, Claim(status="done", tests_claimed_passed=1), baseline_dir=base)

    found = codes(verdict.findings)
    assert "WORKSPACE_METADATA_REMOVED" in found, verdict.first_line()
    assert "TEST_HARNESS_CHANGED" not in found, verdict.first_line()
    assert verdict.exit_token == "partial", verdict.first_line()


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
    )

    verdict = verify(snap, Claim(status="done", tests_claimed_passed=1), baseline_dir=None)

    found = codes(verdict.findings)
    assert "BASELINE_UNAVAILABLE" in found, verdict.first_line()
    assert verdict.exit_token == "partial", verdict.first_line()


def test_r1_there_is_no_way_to_skip_the_baseline_run(tmp_path, monkeypatch):
    """Review R1: the `run_baseline=False` escape hatch no longer exists."""
    import inspect

    from ega.verify import verify

    assert "run_baseline" not in inspect.signature(verify).parameters


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
        baseline_junit=_junit(("test_a", "passed")),
        baseline_stdout="1 passed in 0.01s",
        baseline_exit=baseline_exit,
        baseline_oom=baseline_oom,
    )

    verdict = verify(snap, Claim(status="done", tests_claimed_passed=1), baseline_dir=base)

    found = codes(verdict.findings)
    assert "BASELINE_UNAVAILABLE" in found, verdict.first_line()
    assert verdict.baseline_collected is None, verdict.baseline_collected
    assert "BELOW_BASELINE" not in found, verdict.first_line()
    assert verdict.exit_token != "done", verdict.first_line()


# --- report freshness (VM, 2026-11-04) ------------------------------------
#
# ext4 stamps inodes from a coarse clock that trails time.time() by up to
# ~1.6 ms (300/300 files on the VM). Comparing the report against a wall-clock
# start therefore failed every honest run on that host while APFS on the Mac
# hid the bug; the report is now compared against a marker file stamped by the
# same filesystem clock.


def test_freshness_is_compared_on_the_filesystem_clock(tmp_path):
    from ega import verify as verify_module

    marker_ns = verify_module.marker_mtime_ns(tmp_path)
    report = tmp_path / "junit-x.xml"
    report.write_text("<testsuites/>", encoding="utf-8")

    # The same coarse tick as the marker: written by this run, not stale.
    os.utime(report, ns=(marker_ns, marker_ns))
    assert verify_module.junit_is_stale(report, marker_ns) is False

    # Any earlier stamp predates the marker, whatever the clock skew is.
    os.utime(report, ns=(marker_ns - 1, marker_ns - 1))
    assert verify_module.junit_is_stale(report, marker_ns) is True


def test_a_report_older_than_the_run_marker_is_still_stale(tmp_path, monkeypatch):
    """The regression the fix must not lose: a report not written by this run."""
    from ega.verify import Claim, verify

    base = make_repo(tmp_path / "fixture")
    snap = make_repo(tmp_path / "snapshot")
    same = _junit(("test_ok", "passed"))

    fake_sandbox(
        monkeypatch,
        tmp_path,
        verify_junit=same,
        verify_stdout="1 passed in 0.01s",
        baseline_junit=same,
        baseline_stdout="1 passed in 0.01s",
        verify_junit_age_s=60,
    )

    verdict = verify(snap, Claim(status="done", tests_claimed_passed=1), baseline_dir=base)

    assert "JUNIT_STALE" in codes(verdict.findings), verdict.first_line()
    assert verdict.exit_token == "verification-failed", verdict.first_line()
