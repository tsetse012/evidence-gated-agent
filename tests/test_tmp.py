"""Unit: every temporary directory is parented under one process-owned root.

Two processes share the machine (the demo server on :8765 and this suite), and
the 2026-10-28 incident was one of them deleting the other's ``ega-*``
directories out of the shared tempdir. ``ega/tmp.py`` is what makes that
impossible: nothing here ever looks at the whole tempdir.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

from ega import tmp

REPO_ROOT = Path(__file__).resolve().parents[1]


def test_temporary_directories_live_under_the_process_root():
    root = tmp.root()
    created = tmp.mkdtemp("ega-test-")
    try:
        assert created.parent == root
        assert created.name.startswith("ega-test-")
    finally:
        shutil.rmtree(created, ignore_errors=True)


def test_the_root_is_made_once_per_process():
    assert tmp.root() is tmp.root()


def test_a_vanished_root_is_recreated_instead_of_poisoning_the_process(tmp_path, monkeypatch):
    """Review L2: a cached path that no longer exists must not fail every run.

    The system tempdir cleaner can remove the root of a long-lived process
    (the demo server). Before this, every later ``mkdtemp`` raised for the rest
    of the process.
    """
    gone = tmp_path / "gone-root"
    gone.mkdir()
    original = tmp._root
    monkeypatch.setattr(tmp, "_root", gone)
    shutil.rmtree(gone)

    recreated = tmp.root()

    try:
        assert recreated != gone
        assert recreated.is_dir()
        created = tmp.mkdtemp("ega-test-")
        assert created.parent == recreated
        shutil.rmtree(created, ignore_errors=True)
    finally:
        monkeypatch.setattr(tmp, "_root", original)
        shutil.rmtree(recreated, ignore_errors=True)


def test_a_recreated_root_is_cleaned_up_at_exit(tmp_path):
    """A replacement root must be registered for removal, not just the first."""
    env = dict(os.environ, EGA_TMPDIR=str(tmp_path))
    probe = (
        "from ega import tmp\n"
        "import shutil\n"
        "first = tmp.root()\n"
        "shutil.rmtree(first)\n"
        "second = tmp.root()\n"
        "assert second != first, (first, second)\n"
        "assert second.is_dir()\n"
    )
    proc = subprocess.run(
        [sys.executable, "-c", probe],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stderr
    leftovers = sorted(p.name for p in tmp_path.iterdir())
    assert leftovers == [], f"a re-created empty root survived the process: {leftovers}"


def test_the_sweep_only_touches_its_own_root(tmp_path):
    """The 2026-10-28 regression, as a unit: another process's dir survives.

    ``sweep`` deletes *only* entries that appeared under the root it was given,
    and only ones that are new since the snapshot. Anything in the surrounding
    tempdir belongs to someone else.
    """
    root = tmp_path / "root"
    root.mkdir()
    foreign = tmp_path / "ega-foreign-1"
    (foreign).mkdir()
    (foreign / "probe.py").write_text("# another process's work\n", encoding="utf-8")
    kept = root / "ega-before-1"
    kept.mkdir()

    before = set(root.iterdir())
    leaked = root / "ega-work-leak"
    leaked.mkdir()
    (leaked / "work").mkdir()

    removed = tmp.sweep(root, before)

    assert removed == [leaked]
    assert not leaked.exists()
    assert kept.is_dir(), "an entry that existed before the snapshot is not ours to delete"
    assert (foreign / "probe.py").is_file(), "another process's directory was deleted"


def test_no_test_scans_the_whole_tempdir():
    """Cleanup must never enumerate the shared tempdir.

    This is the exact line that caused the incident (``Path(tempfile
    .gettempdir()).glob("ega-*")``). Checked as text because the damage is a
    cross-*process* race that no single-process test can reproduce reliably;
    ``test_the_sweep_only_touches_its_own_root`` covers behaviour.
    """
    offenders = [
        path.name
        for path in sorted((REPO_ROOT / "tests").glob("*.py"))
        # this file names the pattern it forbids
        if path.name != Path(__file__).name
        and "gettempdir" in path.read_text(encoding="utf-8")
    ]
    assert offenders == [], (
        f"{offenders} scan the shared tempdir; use ega.tmp.root() instead"
    )


def test_the_root_comes_from_ega_tmpdir(tmp_path):
    """``EGA_TMPDIR`` is the parent of the per-process root, not the root itself.

    The gate sets it, so two processes pointed at the same variable still get
    separate roots.
    """
    env = dict(os.environ, EGA_TMPDIR=str(tmp_path))
    probe = (
        "from ega import tmp\n"
        "import shutil\n"
        "created = tmp.mkdtemp('ega-test-')\n"
        "print(tmp.root())\n"
        "print(created.parent)\n"
        "shutil.rmtree(created)\n"
    )
    proc = subprocess.run(
        [sys.executable, "-c", probe],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stderr
    root_line, parent_line = proc.stdout.strip().splitlines()

    root = Path(root_line)
    assert root.parent == tmp_path, proc.stdout
    assert Path(parent_line) == root
    # A process that leaves nothing behind removes its (empty) root on exit.
    assert not root.exists(), f"an empty root must not survive the process: {root}"


def test_a_leaked_directory_keeps_the_root_visible(tmp_path):
    """A leak must stay on disk for the gate to find, not vanish on exit."""
    env = dict(os.environ, EGA_TMPDIR=str(tmp_path))
    probe = (
        "from ega import tmp\n"
        "import pathlib\n"
        "leak = tmp.mkdtemp('ega-leak-')\n"
        "(leak / 'file.txt').write_text('x')\n"
    )
    proc = subprocess.run(
        [sys.executable, "-c", probe],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stderr
    leftovers = [p for p in tmp_path.rglob("*") if p.is_dir()]
    assert any("ega-leak-" in p.name for p in leftovers), (
        f"the leak check needs the leaked directory to survive: {list(tmp_path.iterdir())}"
    )