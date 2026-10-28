"""Unit: the copy boundary never follows a symlink out of the tree, and the
ownership boundary always leaves the tree writable by uid 1000.

No Docker here — these are the helpers ``sandbox.run`` calls around every
container, so they can be checked on a machine without a daemon.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from ega.sandbox import (
    UnsafeTreeError,
    copy_tree,
    make_shared,
    scan_unsafe_entries,
)

CANARY = "HOST-ONLY-SECRET-4d1f"


def make_tree(root: Path) -> Path:
    src = root / "src"
    (src / "pkg").mkdir(parents=True)
    (src / "README.md").write_text("fixture\n", encoding="utf-8")
    (src / "pkg" / "mod.py").write_text("x = 1\n", encoding="utf-8")
    return src


def test_a_clean_tree_has_no_unsafe_entries(tmp_path):
    src = make_tree(tmp_path)
    assert scan_unsafe_entries(src) == []


def test_an_internal_symlink_is_allowed(tmp_path):
    src = make_tree(tmp_path)
    (src / "alias.py").symlink_to(src / "pkg" / "mod.py")
    assert scan_unsafe_entries(src) == []


def test_an_absolute_symlink_out_of_the_tree_is_found(tmp_path):
    src = make_tree(tmp_path)
    canary = tmp_path / "canary.txt"
    canary.write_text(CANARY + "\n", encoding="utf-8")
    (src / "leak.txt").symlink_to(canary)

    unsafe = scan_unsafe_entries(src)
    assert [rel for rel, _ in unsafe] == ["leak.txt"]
    assert "escapes root" in unsafe[0][1]


def test_a_relative_symlink_out_of_the_tree_is_found(tmp_path):
    src = make_tree(tmp_path)
    (tmp_path / "canary.txt").write_text(CANARY + "\n", encoding="utf-8")
    (src / "leak.txt").symlink_to("../canary.txt")

    assert [rel for rel, _ in scan_unsafe_entries(src)] == ["leak.txt"]


def test_a_symlinked_directory_out_of_the_tree_is_not_descended(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.txt").write_text(CANARY + "\n", encoding="utf-8")
    src = make_tree(tmp_path)
    (src / "secrets").symlink_to(outside)

    unsafe = scan_unsafe_entries(src)
    assert [rel for rel, _ in unsafe] == ["secrets"]
    assert not any(rel.startswith("secrets" + os.sep) for rel, _ in unsafe)


def test_a_fifo_is_found(tmp_path):
    src = make_tree(tmp_path)
    os.mkfifo(src / "pipe")

    unsafe = scan_unsafe_entries(src)
    assert [rel for rel, _ in unsafe] == ["pipe"]
    assert "fifo" in unsafe[0][1]


def test_strict_copy_refuses_before_copying_anything(tmp_path):
    src = make_tree(tmp_path)
    (tmp_path / "canary.txt").write_text(CANARY + "\n", encoding="utf-8")
    (src / "leak.txt").symlink_to(tmp_path / "canary.txt")
    dst = tmp_path / "dst"

    with pytest.raises(UnsafeTreeError) as excinfo:
        copy_tree(src, dst, strict=True)
    assert "leak.txt" in str(excinfo.value)
    assert not dst.exists(), "nothing may be copied when the tree is refused"


def test_non_strict_copy_leaves_the_unsafe_entry_out_and_reports_it(tmp_path):
    src = make_tree(tmp_path)
    canary = tmp_path / "canary.txt"
    canary.write_text(CANARY + "\n", encoding="utf-8")
    (src / "leak.txt").symlink_to(canary)
    dst = tmp_path / "dst"

    refused = copy_tree(src, dst, strict=False)

    assert any("leak.txt" in entry for entry in refused)
    assert not (dst / "leak.txt").exists()
    assert (dst / "README.md").is_file()
    assert (dst / "pkg" / "mod.py").is_file()
    for path in dst.rglob("*"):
        if path.is_file():
            assert CANARY not in path.read_text(encoding="utf-8", errors="replace")


def test_symlinks_are_copied_as_symlinks(tmp_path):
    """copytree(symlinks=True): an internal link must not become a copy."""
    src = make_tree(tmp_path)
    (src / "alias.py").symlink_to(src / "pkg" / "mod.py")
    dst = tmp_path / "dst"

    copy_tree(src, dst, strict=True)

    assert (dst / "alias.py").is_symlink()


def test_make_shared_makes_a_0700_tree_writable_by_the_container_uid(tmp_path):
    root = tmp_path / "private"
    root.mkdir(mode=0o700)
    (root / "file.txt").write_text("x\n", encoding="utf-8")
    os.chmod(root, 0o700)
    os.chmod(root / "file.txt", 0o600)

    problems = make_shared(root)

    assert problems == []
    if os.getuid() != 1000:  # chown succeeds trivially as uid 1000; otherwise chmod widens
        assert os.stat(root).st_uid == os.getuid()
        dir_mode = stat.S_IMODE(os.stat(root).st_mode)
        assert dir_mode & 0o777 == 0o777, f"directory is not reachable: {oct(dir_mode)}"
        file_mode = stat.S_IMODE(os.stat(root / "file.txt").st_mode)
        assert file_mode & 0o666 == 0o666, f"file is not writable: {oct(file_mode)}"


def test_make_shared_keeps_the_executable_bit_meaning(tmp_path):
    """X = directories and files that are already executable."""
    root = tmp_path / "tree"
    root.mkdir()
    script = root / "run.sh"
    script.write_text("#!/bin/sh\n", encoding="utf-8")
    plain = root / "data.txt"
    plain.write_text("x\n", encoding="utf-8")
    os.chmod(root, 0o700)
    os.chmod(script, 0o700)
    os.chmod(plain, 0o600)

    make_shared(root)

    assert stat.S_IMODE(os.stat(script).st_mode) & 0o111 == 0o111
    assert stat.S_IMODE(os.stat(plain).st_mode) & 0o111 == 0