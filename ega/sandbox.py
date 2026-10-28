"""Isolated runner: one fresh container per call, Docker CLI via subprocess.

The sandbox is the whole point of the project, so every flag that keeps a
container away from the host is mandatory and appears in ``_docker_args``:
no network, memory/CPU/pid caps, read-only root, no capabilities, no
privilege escalation, non-root uid, and no host environment passthrough.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import time
import uuid
from dataclasses import dataclass
from pathlib import Path

DEFAULT_IMAGE = "ega-sandbox:dev"

# Container-side environment. This is an allowlist: nothing from the host is
# forwarded (`docker run` only forwards what `-e` names explicitly).
BASE_CONTAINER_ENV = {
    "HOME": "/tmp",
    "PYTHONDONTWRITEBYTECODE": "1",
    "PYTHONUNBUFFERED": "1",
    "TMPDIR": "/tmp",
}


def image_name() -> str:
    return os.environ.get("EGA_IMAGE", DEFAULT_IMAGE)


@dataclass(frozen=True)
class Limits:
    """Resource ceiling for one sandbox."""

    memory: str = "512m"
    cpus: float = 1.0
    pids_limit: int = 256
    timeout_s: float = 120.0


@dataclass
class SandboxResult:
    exit_code: int
    stdout: str
    stderr: str
    duration_s: float
    timed_out: bool
    oom_killed: bool
    isolation: str  # "gvisor" (runsc) | "runc"
    workdir_after: Path
    container_name: str
    error: str | None = None

    @property
    def ran(self) -> bool:
        """True when the container actually executed and produced a status."""
        return self.error is None and not self.timed_out

    def as_dict(self) -> dict:
        return {
            "exit_code": self.exit_code,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "duration_s": round(self.duration_s, 3),
            "timed_out": self.timed_out,
            "oom_killed": self.oom_killed,
            "isolation": self.isolation,
            "workdir_after": str(self.workdir_after),
            "container_name": self.container_name,
            "error": self.error,
        }


def _docker(*args: str, timeout: float = 120.0) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["docker", *args],
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def docker_available() -> bool:
    try:
        return _docker("info", "--format", "{{.ServerVersion}}", timeout=20).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def docker_runtimes() -> dict:
    try:
        out = _docker("info", "--format", "{{json .Runtimes}}", timeout=20)
    except (OSError, subprocess.TimeoutExpired):
        return {}
    if out.returncode != 0:
        return {}
    try:
        return json.loads(out.stdout or "{}")
    except json.JSONDecodeError:
        return {}


def detect_runtime() -> tuple[str, str]:
    """Return (docker --runtime value, isolation label).

    gVisor is used when the daemon lists ``runsc``; otherwise plain ``runc``.
    ``EGA_RUNTIME`` overrides the decision (e.g. ``EGA_RUNTIME=runsc``).
    """
    override = os.environ.get("EGA_RUNTIME")
    if override:
        return override, ("gvisor" if override == "runsc" else override)
    if "runsc" in docker_runtimes():
        return "runsc", "gvisor"
    return "runc", "runc"


def _docker_args(
    *,
    name: str,
    runtime: str,
    work: Path,
    limits: Limits,
    env: dict[str, str] | None = None,
) -> list[str]:
    env = env or {}
    args = [
        "docker",
        "run",
        "--name",
        name,
        "--runtime",
        runtime,
        # containment flags (all mandatory)
        "--network",
        "none",
        "--memory",
        limits.memory,
        "--memory-swap",
        limits.memory,  # no swap: the memory cap is the real cap
        "--cpus",
        str(limits.cpus),
        "--pids-limit",
        str(limits.pids_limit),
        "--read-only",
        "--tmpfs",
        "/tmp:rw,size=64m",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--user",
        "1000:1000",
        # only /work is mounted; nothing else from the host
        "-v",
        f"{work}:/work",
        "-w",
        "/work",
    ]
    for key in sorted(BASE_CONTAINER_ENV):
        args += ["-e", f"{key}={BASE_CONTAINER_ENV[key]}"]
    for key, value in sorted(env.items()):
        args += ["-e", f"{key}={value}"]
    args.append(image_name())
    return args


def run(
    cmd: list[str],
    src_dir: Path,
    limits: Limits | None = None,
    *,
    run_id: str | None = None,
    env: dict[str, str] | None = None,
    workdir_after: Path | None = None,
) -> SandboxResult:
    """Run ``cmd`` in a fresh container with a copy of ``src_dir`` at /work.

    The container is always removed and the temporary mount directory always
    deleted. ``workdir_after`` is a durable copy of /work taken after the run
    so a verifier can diff it; when omitted a temp dir is kept instead.
    """
    limits = limits or Limits()
    src_dir = Path(src_dir).resolve()
    if not src_dir.is_dir():
        raise FileNotFoundError(f"src_dir does not exist: {src_dir}")

    run_id = run_id or uuid.uuid4().hex[:12]
    name = f"ega-{run_id}"
    runtime, isolation = detect_runtime()

    work_root = Path(tempfile.mkdtemp(prefix="ega-work-"))
    work = work_root / "work"
    shutil.copytree(src_dir, work)
    # The junit path lives here; the verifier writes /work/.ega/junit.xml.
    (work / ".ega").mkdir(exist_ok=True)

    stdout = stderr = ""
    exit_code = -1
    timed_out = False
    oom_killed = False
    error: str | None = None
    after_dir = Path(workdir_after) if workdir_after else None

    started = time.monotonic()
    try:
        args = _docker_args(
            name=name, runtime=runtime, work=work, limits=limits, env=env
        ) + list(cmd)
        proc = subprocess.Popen(
            args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            stdout, stderr = proc.communicate(timeout=limits.timeout_s)
            exit_code = proc.returncode
        except subprocess.TimeoutExpired:
            timed_out = True
            # The docker CLI is not the container: kill the container itself,
            # then reap the CLI so we can still read what it printed.
            try:
                _docker("kill", name, timeout=30)
            except (OSError, subprocess.TimeoutExpired):
                pass
            try:
                stdout, stderr = proc.communicate(timeout=30)
            except subprocess.TimeoutExpired:
                proc.kill()
                stdout, stderr = proc.communicate()
            exit_code = -1

        try:
            inspect = _docker(
                "inspect",
                "--format",
                "{{.State.OOMKilled}}",
                name,
                timeout=30,
            )
            oom_killed = inspect.stdout.strip() == "true"
        except (OSError, subprocess.TimeoutExpired):
            oom_killed = False

        if exit_code == 125 and not timed_out:
            # `docker run` itself failed (bad image, bad flag, daemon down...).
            error = (stderr or stdout).strip() or "docker run failed (exit 125)"
    except FileNotFoundError as exc:  # docker CLI missing
        error = f"docker CLI not available: {exc}"
    finally:
        duration = time.monotonic() - started
        try:
            _docker("rm", "-f", name, timeout=60)
        except (OSError, subprocess.TimeoutExpired):
            pass
        if after_dir is None:
            after_dir = Path(tempfile.mkdtemp(prefix="ega-after-"))
        else:
            after_dir.mkdir(parents=True, exist_ok=True)
        shutil.copytree(work, after_dir, dirs_exist_ok=True)
        shutil.rmtree(work_root, ignore_errors=True)

    return SandboxResult(
        exit_code=exit_code,
        stdout=stdout,
        stderr=stderr,
        duration_s=duration,
        timed_out=timed_out,
        oom_killed=oom_killed,
        isolation=isolation,
        workdir_after=after_dir,
        container_name=name,
        error=error,
    )