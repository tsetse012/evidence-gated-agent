"""Isolated runner: one fresh container per call, Docker CLI via subprocess.

The sandbox is the whole point of the project, so every flag that keeps a
container away from the host is mandatory and appears in ``_docker_args``:
no network, memory/CPU/pid caps, read-only root, no capabilities, no
privilege escalation, non-root uid, and no host environment passthrough.

Two boundaries are enforced in addition to the docker flags, because a mount
is not the only way out:

* **the copy boundary** — a host tree is copied into ``/work`` and the result
  is copied back out. A symlink that resolves outside its tree, or a special
  file (FIFO/device/socket), would make that copy read (or block on) host
  paths, so both directions refuse them (input: the run is rejected; output:
  the entry is left out and reported).
* **the ownership boundary** — the copied tree is made readable and writable
  by the container uid (1000), otherwise a Linux bind mount under a different
  host user is a read-only mount in practice.
"""

from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path

from . import tmp

DEFAULT_IMAGE = "ega-sandbox:dev"

# The one reason this project accepts a skip for. Both the conftest that skips
# docker-marked tests and the gate that reads the junit report use *this*
# string, so the gate can tolerate exactly those skips — and nothing else — by
# comparing messages instead of trusting a marker name.
DOCKER_SKIP_REASON = (
    "docker daemon not available (`docker info` failed); cannot run sandbox tests"
)

CONTAINER_UID = 1000
CONTAINER_GID = 1000
# Optional second mount, used by the verifier for its own junit report. It is a
# separate, empty host directory — never the workspace — so nothing the author
# put inside /work can be mistaken for a report this run produced.
OUT_MOUNT = "/ega-out"

# Container-side environment. This is an allowlist: nothing from the host is
# forwarded (`docker run` only forwards what `-e` names explicitly).
BASE_CONTAINER_ENV = {
    "HOME": "/tmp",
    "PYTHONDONTWRITEBYTECODE": "1",
    "PYTHONUNBUFFERED": "1",
    "TMPDIR": "/tmp",
    # `python:*` images bake a public OpenPGP fingerprint into GPG_KEY. Empty it
    # here rather than teaching the env_leak probe to ignore the *name*: the
    # probe has no name-based allowlist, so an empty value is the only thing
    # that keeps a KEY-shaped variable out of the suspicious list.
    "GPG_KEY": "",
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
    # Entries that existed in /work but were refused by the output copy
    # (symlink escaping the tree, FIFO, device, socket).
    excluded_output: list[str] = field(default_factory=list)
    # Container removal and output-copy failures. Reported, never swallowed.
    cleanup_errors: list[str] = field(default_factory=list)
    # Permission adjustments that did not stick (ownership boundary).
    setup_warnings: list[str] = field(default_factory=list)

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
            "excluded_output": list(self.excluded_output),
            "cleanup_errors": list(self.cleanup_errors),
            "setup_warnings": list(self.setup_warnings),
        }


class UnsafeTreeError(RuntimeError):
    """A source tree contains entries that must not cross the sandbox boundary."""


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


# --- copy boundary ----------------------------------------------------------


def _leaves_root(path: Path, root: Path) -> bool:
    """True when ``path`` is a symlink whose target resolves outside ``root``."""
    if not path.is_symlink():
        return False
    target = Path(os.path.realpath(path))
    root_real = Path(os.path.realpath(root))
    return target != root_real and root_real not in target.parents


def _special_kind(path: Path) -> str | None:
    mode = os.lstat(path).st_mode
    for kind, check in (
        ("fifo", stat.S_ISFIFO),
        ("char device", stat.S_ISCHR),
        ("block device", stat.S_ISBLK),
        ("socket", stat.S_ISSOCK),
    ):
        if check(mode):
            return kind
    return None


def scan_unsafe_entries(root: Path) -> list[tuple[str, str]]:
    """``(relative path, reason)`` for entries that would cross the boundary.

    Two kinds are refused in both directions: symlinks whose target resolves
    outside ``root`` (a copy that follows them would read host files) and
    special files (FIFOs, devices, sockets) that block or leak on copy.
    """
    root = Path(root)
    unsafe: list[tuple[str, str]] = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        for name in list(dirnames) + list(filenames):
            path = Path(dirpath) / name
            rel = str(path.relative_to(root))
            if _leaves_root(path, root):
                unsafe.append((rel, f"symlink escapes root -> {os.readlink(path)}"))
                if name in dirnames:
                    dirnames.remove(name)  # never descend into it
                continue
            kind = _special_kind(path)
            if kind is not None:
                unsafe.append((rel, kind))
    return unsafe


def copy_tree(src: Path, dst: Path, *, strict: bool) -> list[str]:
    """Copy ``src`` to ``dst`` without ever following a symlink.

    Returns the entries that were refused, formatted for evidence. With
    ``strict`` anything unsafe aborts before a single byte is copied;
    otherwise those entries are left out and returned.
    """
    src, dst = Path(src), Path(dst)
    unsafe = scan_unsafe_entries(src)
    if not unsafe:
        shutil.copytree(src, dst, symlinks=True, dirs_exist_ok=True)
        return []
    if strict:
        raise UnsafeTreeError("; ".join(f"{rel} ({reason})" for rel, reason in unsafe))
    refused = {rel for rel, _ in unsafe}

    def ignore(directory: str, names: list[str]) -> list[str]:
        rel = Path(directory).relative_to(src)
        return [name for name in names if str(rel / name) in refused]

    shutil.copytree(src, dst, symlinks=True, ignore=ignore, dirs_exist_ok=True)
    return [f"{rel} ({reason})" for rel, reason in unsafe]


# --- ownership boundary -----------------------------------------------------


def _permissive_mode(mode: int) -> int:
    """``u+rwX,g+rwX,o+rwX`` as bits (X = directories and executable files)."""
    new = mode | 0o666
    if stat.S_ISDIR(mode) or mode & 0o111:
        new |= 0o111
    return new


def make_shared(root: Path) -> list[str]:
    """Let uid 1000 read and write ``root`` (bind mounts keep host ownership).

    ``chown`` first; when it is not permitted (never as a normal user) fall
    back to permissive bits so the container uid can still work inside the
    mount. Problems are returned, never swallowed.
    """
    problems: list[str] = []
    root = Path(root)
    targets = [root, *root.rglob("*")]
    for target in targets:
        try:
            st = os.lstat(target)
        except OSError as exc:
            problems.append(f"cannot stat {target}: {exc}")
            continue
        if stat.S_ISLNK(st.st_mode):
            continue
        try:
            os.chown(target, CONTAINER_UID, CONTAINER_GID)
            continue
        except OSError:
            pass
        desired = _permissive_mode(st.st_mode)
        if stat.S_IMODE(st.st_mode) == desired:
            continue
        try:
            os.chmod(target, desired)
        except OSError as exc:
            problems.append(f"cannot widen permissions on {target}: {exc}")
    return problems


# --- docker plumbing --------------------------------------------------------


def _docker_args(
    *,
    name: str,
    runtime: str,
    work: Path,
    limits: Limits,
    env: dict[str, str] | None = None,
    out_dir: Path | None = None,
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
        f"{CONTAINER_UID}:{CONTAINER_GID}",
        # only /work (and the verifier's own /ega-out) is mounted
        "-v",
        f"{work}:/work",
        "-w",
        "/work",
    ]
    if out_dir is not None:
        args += ["-v", f"{out_dir}:{OUT_MOUNT}"]
    for key in sorted(BASE_CONTAINER_ENV):
        args += ["-e", f"{key}={BASE_CONTAINER_ENV[key]}"]
    for key, value in sorted(env.items()):
        args += ["-e", f"{key}={value}"]
    args.append(image_name())
    return args


def _inspect_oom_killed(name: str) -> bool:
    try:
        inspect = _docker(
            "inspect", "--format", "{{.State.OOMKilled}}", name, timeout=30
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return inspect.stdout.strip() == "true"


def _remove_container(name: str, problems: list[str]) -> None:
    """``docker rm -f``; a failure is recorded, not ignored."""
    try:
        removed = _docker("rm", "-f", name, timeout=60)
    except (OSError, subprocess.TimeoutExpired) as exc:
        problems.append(f"docker rm -f {name} failed: {exc}")
        return
    if removed.returncode != 0:
        message = (removed.stderr or removed.stdout or "").strip()
        if "No such container" not in message:
            problems.append(f"docker rm -f {name} exited {removed.returncode}: {message}")


def run(
    cmd: list[str],
    src_dir: Path,
    limits: Limits | None = None,
    *,
    run_id: str | None = None,
    env: dict[str, str] | None = None,
    workdir_after: Path | None = None,
    out_dir: Path | None = None,
) -> SandboxResult:
    """Run ``cmd`` in a fresh container with a copy of ``src_dir`` at /work.

    ``out_dir`` is a *separate* host directory mounted rw at ``/ega-out`` —
    the verifier keeps its junit report there, outside the workspace, so the
    report cannot be supplied by the workspace being judged.

    The container is always removed and the temporary mount directory always
    deleted (the output copy and the cleanup live in nested ``finally`` blocks
    so one cannot skip the other). ``workdir_after`` is a durable copy of
    /work taken after the run; when omitted a temp dir is created instead.
    """
    limits = limits or Limits()
    src_dir = Path(src_dir).resolve()
    if not src_dir.is_dir():
        raise FileNotFoundError(f"src_dir does not exist: {src_dir}")

    run_id = run_id or uuid.uuid4().hex[:12]
    name = f"ega-{run_id}"
    runtime, isolation = detect_runtime()
    after_dir = Path(workdir_after) if workdir_after else None

    stdout = stderr = ""
    exit_code = -1
    timed_out = False
    oom_killed = False
    error: str | None = None
    excluded: list[str] = []
    cleanup_errors: list[str] = []
    setup_warnings: list[str] = []
    duration = 0.0

    started = time.monotonic()
    work_root = tmp.mkdtemp("ega-work-")
    work = work_root / "work"
    try:
        try:
            # Input copy: refuse the whole run rather than partially copy.
            copy_tree(src_dir, work, strict=True)
        except UnsafeTreeError as exc:
            error = f"unsafe input tree: {exc}"
        except OSError as exc:
            error = f"could not copy the source tree: {exc}"
        else:
            (work / ".ega").mkdir(exist_ok=True)
            setup_warnings.extend(make_shared(work))
            if out_dir is not None:
                out_root = Path(out_dir)
                out_root.mkdir(parents=True, exist_ok=True)
                setup_warnings.extend(make_shared(out_root))
            try:
                proc = subprocess.Popen(
                    _docker_args(
                        name=name,
                        runtime=runtime,
                        work=work,
                        limits=limits,
                        env=env,
                        out_dir=out_dir,
                    )
                    + list(cmd),
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
            except FileNotFoundError as exc:  # docker CLI missing
                error = f"docker CLI not available: {exc}"
            except OSError as exc:
                error = f"could not start docker: {exc}"
            else:
                try:
                    stdout, stderr = proc.communicate(timeout=limits.timeout_s)
                    exit_code = proc.returncode
                except subprocess.TimeoutExpired:
                    timed_out = True
                    # The docker CLI is not the container: kill the container
                    # itself, then reap the CLI so we can still read what it
                    # printed.
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

                oom_killed = _inspect_oom_killed(name)

                if exit_code == 125 and not timed_out:
                    # `docker run` itself failed (bad image, bad flag, daemon
                    # down...).
                    error = (stderr or stdout).strip() or "docker run failed (exit 125)"
    finally:
        duration = time.monotonic() - started
        try:
            _remove_container(name, cleanup_errors)
        finally:
            # Output preservation and temp cleanup are separate: a failed copy
            # must not leak the temporary mount directory.
            try:
                target = (
                    after_dir
                    if after_dir is not None
                    else tmp.mkdtemp("ega-after-")
                )
                # Recorded before anything can fail: a failed copy must not
                # leave this directory behind with no reference to remove it.
                after_dir = target
                target.mkdir(parents=True, exist_ok=True)
                if work.is_dir():
                    excluded = copy_tree(work, target, strict=False)
            except OSError as exc:
                cleanup_errors.append(f"output copy failed: {exc}")
            finally:
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
        excluded_output=excluded,
        cleanup_errors=cleanup_errors,
        setup_warnings=setup_warnings,
    )