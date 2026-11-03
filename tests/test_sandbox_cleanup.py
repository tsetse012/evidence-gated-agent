"""Unit: cleanup guarantees of ``sandbox.run`` without a Docker daemon.

Two failure paths the review flagged: a failed output copy used to leak the
temporary mount directory, and a failed ``docker rm`` used to disappear.
Both are checked here with the CLI faked, so they run on any machine.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

from ega import sandbox
from ega import tmp
from ega.sandbox import Limits


class FakeProc:
    def __init__(self):
        self.returncode = 0

    def communicate(self, timeout=None):
        return "", ""

    def kill(self):
        pass


@pytest.fixture
def fake_docker(monkeypatch):
    """Fake the docker CLI; returns the recorded argv list."""
    calls: list[tuple[str, ...]] = []

    def _docker(*args, timeout=120.0):
        calls.append(args)
        if args[0] == "rm":  # container removal succeeds unless a test overrides it
            return subprocess.CompletedProcess(["docker", *args], 0, "", "")
        return subprocess.CompletedProcess(["docker", *args], 0, "", "")

    monkeypatch.setattr(sandbox, "_docker", _docker)
    monkeypatch.setattr(sandbox, "detect_runtime", lambda: ("runc", "runc"))
    monkeypatch.setattr(sandbox.subprocess, "Popen", lambda *a, **k: FakeProc())
    return calls


def make_src(tmp_path: Path) -> Path:
    src = tmp_path / "src"
    src.mkdir()
    (src / "README.md").write_text("fixture\n", encoding="utf-8")
    return src


def temp_dirs() -> set[str]:
    return {p.name for p in tmp.root().glob("ega-work-*")}


def test_a_failed_output_copy_still_deletes_the_mount_dir(tmp_path, fake_docker, monkeypatch):
    src = make_src(tmp_path)
    real_copy = sandbox.copy_tree

    def failing_copy(source, dst, *, strict):
        if strict:
            return real_copy(source, dst, strict=strict)
        raise OSError("disk full")

    monkeypatch.setattr(sandbox, "copy_tree", failing_copy)
    before = temp_dirs()

    result = sandbox.run(["true"], src, Limits())

    assert temp_dirs() - before == set(), "the temporary mount directory must be removed"
    assert any("output copy failed" in entry for entry in result.cleanup_errors), (
        result.cleanup_errors
    )
    shutil.rmtree(result.workdir_after, ignore_errors=True)


def test_a_failed_container_removal_is_recorded(tmp_path, fake_docker, monkeypatch):
    src = make_src(tmp_path)

    def failing_rm(*args, timeout=120.0):
        if args[0] == "rm":
            return subprocess.CompletedProcess(
                ["docker", *args], 1, "", "Error response from daemon: permission denied"
            )
        return subprocess.CompletedProcess(["docker", *args], 0, "", "")

    monkeypatch.setattr(sandbox, "_docker", failing_rm)

    result = sandbox.run(["true"], src, Limits())

    assert any("docker rm -f" in entry for entry in result.cleanup_errors), result.cleanup_errors
    assert any("permission denied" in entry for entry in result.cleanup_errors)
    shutil.rmtree(result.workdir_after, ignore_errors=True)


def test_removing_an_already_gone_container_is_not_an_error(tmp_path, fake_docker, monkeypatch):
    src = make_src(tmp_path)

    def no_such_container(*args, timeout=120.0):
        if args[0] == "rm":
            return subprocess.CompletedProcess(
                ["docker", *args], 1, "", "Error: No such container: ega-x"
            )
        return subprocess.CompletedProcess(["docker", *args], 0, "", "")

    monkeypatch.setattr(sandbox, "_docker", no_such_container)

    result = sandbox.run(["true"], src, Limits())

    assert result.cleanup_errors == []
    shutil.rmtree(result.workdir_after, ignore_errors=True)


def test_the_container_is_always_removed(tmp_path, fake_docker):
    src = make_src(tmp_path)

    result = sandbox.run(["true"], src, Limits())

    removals = [call for call in fake_docker if call[0] == "rm"]
    assert len(removals) == 1, fake_docker
    assert result.container_name in removals[0]
    shutil.rmtree(result.workdir_after, ignore_errors=True)

# --- flags: the cap the guest sees, and the uid the container runs as ------
#
# Measured 2026-11-04 on the VM: `--pids-limit 128` limited nothing inside
# gVisor (400/400 forks succeeded, the fork_bomb probe read "allowed") and the
# same value killed the container outright. And with the container on a uid
# other than the host process's, the 14 temp directories it filled could not be
# removed by the user running the gate.


def flag(args, name):
    return args[args.index(name) + 1]


def make_args(runtime: str, pids_limit: int):
    return sandbox._docker_args(
        name="ega-test",
        runtime=runtime,
        work=Path("/tmp/ega-work/work"),
        limits=Limits(pids_limit=pids_limit),
    )


def test_the_guest_process_cap_is_an_rlimit_not_just_a_cgroup():
    """`--pids-limit` alone does not stop fork() inside gVisor."""
    for runtime in ("runc", "runsc"):
        args = make_args(runtime, 64)
        assert flag(args, "--ulimit") == "nproc=64:64", (runtime, args)


def test_runc_keeps_the_pids_limit_as_the_host_cap():
    args = make_args("runc", 64)
    assert flag(args, "--pids-limit") == "64"


def test_runsc_gets_host_headroom_for_its_sentry():
    """The sentry's own tasks live in the host pids cgroup; a guest-sized cap kills it."""
    args = make_args("runsc", 128)
    host_cap = int(flag(args, "--pids-limit"))
    assert host_cap >= 1024, host_cap
    assert host_cap > 128
    assert flag(args, "--ulimit") == "nproc=128:128"


def test_the_sandbox_runs_as_the_host_user_so_its_files_can_be_deleted():
    args = make_args("runc", 64)
    assert flag(args, "--user") == f"{os.getuid()}:{os.getgid()}"


def test_a_root_host_never_runs_the_sandbox_as_root(monkeypatch):
    """Running as root would drop the non-root flag; root can delete any file anyway."""
    monkeypatch.setattr(sandbox.os, "getuid", lambda: 0)
    monkeypatch.setattr(sandbox.os, "getgid", lambda: 0)
    assert sandbox.container_user() == (sandbox.CONTAINER_UID, sandbox.CONTAINER_GID)
    assert flag(make_args("runc", 64), "--user") == "1000:1000"


def test_a_temp_tree_that_cannot_be_removed_is_reported(tmp_path, monkeypatch):
    """`ignore_errors=True` used to turn a real leak into a silent green."""
    problems: list[str] = []

    def refusing_rmtree(path, *args, **kwargs):
        raise PermissionError(f"[Errno 13] Permission denied: {path}")

    monkeypatch.setattr(sandbox.shutil, "rmtree", refusing_rmtree)

    sandbox._remove_tree(tmp_path / "ega-work-x", problems)

    assert problems, "a failed removal must not be swallowed"
    assert "could not remove" in problems[0]
    assert "Permission denied" in problems[0]
