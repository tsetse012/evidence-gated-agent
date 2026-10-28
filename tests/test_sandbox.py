"""Integration: the sandbox really applies its limits (needs Docker)."""

from __future__ import annotations

import subprocess
import textwrap
from pathlib import Path

import pytest

from ega.sandbox import Limits, run

pytestmark = pytest.mark.docker


def make_src(tmp_path: Path, files: dict[str, str] | None = None) -> Path:
    src = tmp_path / "src"
    src.mkdir()
    (src / "README.md").write_text("fixture\n", encoding="utf-8")
    for name, content in (files or {}).items():
        path = src / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    return src


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
    killed = result.oom_killed or result.exit_code in (137, -9)
    assert killed, f"expected OOM, got exit={result.exit_code} stderr={result.stderr}"


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