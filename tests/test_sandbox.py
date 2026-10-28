"""Integration: the sandbox really applies its limits (needs Docker).

The copy boundary and the ownership boundary are exercised here end to end;
the pure helpers behind them are unit-tested in ``test_copy_boundary.py``.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import textwrap
from pathlib import Path

import pytest

from ega import tmp
from ega.sandbox import Limits, run

CANARY = "HOST-ONLY-SECRET-4d1f"


@pytest.fixture(autouse=True)
def _no_temp_leaks():
    """Sandbox runs may leave an ega-after-* copy; never leave it behind here.

    Only this process's own root is swept. A glob of the whole tempdir would
    delete a demo server's live probe source on the same machine — measured
    2026-10-28, three probes then reported "could not copy the source tree".
    """
    root = tmp.root()
    before = set(root.iterdir()) if root.is_dir() else set()
    yield
    tmp.sweep(root, before)


def make_src(tmp_path: Path, files: dict[str, str] | None = None) -> Path:
    src = tmp_path / "src"
    src.mkdir()
    (src / "README.md").write_text("fixture\n", encoding="utf-8")
    for name, content in (files or {}).items():
        path = src / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    return src


def find_canary(root: Path) -> list[Path]:
    """Every regular file under ``root`` whose bytes contain the canary."""
    hits = []
    for path in root.rglob("*"):
        if path.is_file() and not path.is_symlink():
            try:
                if CANARY in path.read_text(encoding="utf-8", errors="replace"):
                    hits.append(path)
            except OSError:
                continue
    return hits


# --- copy boundary ---------------------------------------------------------


def test_a_source_symlink_out_of_the_tree_is_refused(tmp_path):
    """The host canary must never reach /work, so the run never starts."""
    canary = tmp_path / "canary.txt"
    canary.write_text(CANARY + "\n", encoding="utf-8")
    src = make_src(tmp_path)
    (src / "leak.txt").symlink_to(canary)

    result = run(["sh", "-c", "cat /work/leak.txt"], src, Limits())

    assert result.error is not None, "an escaping source symlink must reject the run"
    assert "unsafe input tree" in result.error
    assert "leak.txt" in result.error
    assert CANARY not in result.stdout
    assert result.exit_code == -1
    assert find_canary(result.workdir_after) == []


@pytest.mark.docker
def test_a_symlink_written_by_the_container_is_not_followed_out(tmp_path):
    """A symlink created *inside* /work is dropped on the way back, and reported."""
    canary = tmp_path / "canary.txt"
    canary.write_text(CANARY + "\n", encoding="utf-8")
    src = make_src(tmp_path)
    script = f"ln -s '{canary}' /work/leak.txt; echo ok > /work/fine.txt; echo done"

    result = run(["sh", "-c", script], src, Limits())

    assert result.error is None, result.error
    assert result.exit_code == 0
    after = result.workdir_after
    assert not (after / "leak.txt").exists(), "the escaping symlink must not be copied"
    assert any("leak.txt" in entry for entry in result.excluded_output), result.excluded_output
    assert find_canary(after) == [], "host file contents must never be copied into the output"
    assert (after / "fine.txt").read_text(encoding="utf-8").strip() == "ok"


@pytest.mark.docker
def test_container_can_write_into_a_0700_source_tree():
    """A mkdtemp() 0700 tree must be writable by uid 1000 (ownership boundary)."""
    root = tmp.mkdtemp("ega-0700-")
    try:
        src = root / "src"
        src.mkdir()
        os.chmod(root, 0o700)
        os.chmod(src, 0o700)
        (src / "README.md").write_text("fixture\n", encoding="utf-8")
        assert src.stat().st_mode & 0o777 == 0o700

        result = run(["sh", "-c", "echo hi > /work/new.txt; echo ok"], src, Limits())

        assert result.error is None, result.error
        assert result.exit_code == 0, result.stderr
        assert (result.workdir_after / "new.txt").read_text(encoding="utf-8").strip() == "hi"
    finally:
        shutil.rmtree(root, ignore_errors=True)


# --- containment limits ----------------------------------------------------


def test_run_records_isolation_and_workdir_after(tmp_path):
    src = make_src(tmp_path)
    result = run(["sh", "-c", "echo hello; echo written > /work/new.txt"], src, Limits())
    assert result.error is None, result.error
    assert result.exit_code == 0
    assert "hello" in result.stdout
    assert result.isolation in {"runc", "gvisor"}
    assert (result.workdir_after / "new.txt").read_text(encoding="utf-8") == "written\n"
    # the container is gone
    inspect = subprocess.run(
        ["docker", "inspect", result.container_name], capture_output=True, text=True
    )
    assert inspect.returncode != 0


def test_read_only_root_blocks_writes_outside_work(tmp_path):
    src = make_src(tmp_path)
    result = run(["sh", "-c", "echo x > /etc/x"], src, Limits())
    assert result.exit_code != 0
    assert "Read-only file system" in (result.stderr + result.stdout)


def test_host_environment_does_not_pass_through(tmp_path, monkeypatch):
    monkeypatch.setenv("EGA_FAKE_SECRET_TOKEN", "should-not-leak")
    monkeypatch.setenv("SUPER_SECRET_API_KEY", "should-not-leak-either")
    src = make_src(tmp_path)
    result = run(["sh", "-c", "env"], src, Limits())
    assert result.exit_code == 0
    assert "should-not-leak" not in result.stdout


def test_timeout_kills_the_container(tmp_path):
    src = make_src(tmp_path)
    result = run(["sh", "-c", "sleep 30"], src, Limits(timeout_s=2))
    assert result.timed_out is True
    assert result.exit_code == -1
    inspect = subprocess.run(
        ["docker", "inspect", result.container_name], capture_output=True, text=True
    )
    assert inspect.returncode != 0, "container should have been removed"


def test_memory_limit_is_enforced(tmp_path):
    """Only the kernel's OOMKilled flag counts as proof (exit 137 alone does not)."""
    script = textwrap.dedent(
        """
        chunks = []
        for _ in range(64):
            chunks.append(bytearray(16 * 1024 * 1024))
        print("allocated", len(chunks) * 16, "MB")
        """
    )
    src = make_src(tmp_path, {"hog.py": script})
    result = run(["python", "hog.py"], src, Limits(memory="64m", timeout_s=60))
    assert result.oom_killed is True, (
        f"expected OOMKilled, got exit={result.exit_code} "
        f"oom_killed={result.oom_killed} stderr={result.stderr}"
    )


def test_pid_limit_is_enforced(tmp_path):
    script = textwrap.dedent(
        """
        import os

        children = []
        failure = None
        for _ in range(200):
            try:
                pid = os.fork()
            except OSError as exc:
                failure = str(exc)
                break
            if pid == 0:
                os._exit(0)
            children.append(pid)
        for pid in children:
            try:
                os.waitpid(pid, 0)
            except OSError:
                pass
        print("children", len(children), "failure", failure)
        """
    )
    src = make_src(tmp_path, {"forker.py": script})
    result = run(["python", "forker.py"], src, Limits(pids_limit=32, timeout_s=60))
    assert result.exit_code == 0, result.stderr
    assert "failure" in result.stdout
    assert "failure None" not in result.stdout