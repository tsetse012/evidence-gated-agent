"""Unit: the verifier's own machinery, without Docker.

The command it runs is fixed, declared artifacts may not leave the workspace,
and the test-harness comparison only looks at files pytest actually reads.
"""

from __future__ import annotations

import textwrap
from pathlib import Path

from ega.verify import (
    CONFIG_FILE,
    artifact_paths,
    count_xfail_markers,
    harness_changes,
    load_project_config,
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
    assert cmd[:6] == ["python", "-m", "pytest", "-q", "-p", "no:cacheprovider"]
    assert cmd[-1] == "--junitxml=/ega-out/junit-abc.xml"
    assert not any("/work" in part for part in cmd)
    assert "sh" not in cmd and "-c" not in cmd


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


def test_patches_directory_is_ignored(tmp_path):
    """Fixture patches are authoring metadata, not part of the repo."""
    base = make_repo(tmp_path / "base")
    snap = make_repo(tmp_path / "snap")
    (base / "patches").mkdir()
    (base / "patches" / "conftest.py").write_text("x = 1\n", encoding="utf-8")
    (snap / "patches").mkdir()
    (snap / "patches" / "conftest.py").write_text("x = 2\n", encoding="utf-8")

    assert harness_changes(base, snap) == []


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