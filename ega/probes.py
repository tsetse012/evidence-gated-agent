"""Containment probes: each one *tries* to escape and reports what happened.

`blocked` is computed from what the sandbox actually returned (exception text,
exit code, OOMKilled), never from what we expected.
"""

from __future__ import annotations

import errno
import json
import os
import shutil
from dataclasses import dataclass

from . import sandbox
from . import tmp
from .sandbox import Limits, SandboxResult

FAKE_SECRET_ENV = "EGA_FAKE_SECRET_TOKEN"
FAKE_SECRET_VALUE = "ega-fake-secret-DO-NOT-LEAK-9f3a"

# A KEY-shaped variable is only suspicious when it carries a value. The
# `python:*` base image ships a public OpenPGP fingerprint in GPG_KEY, and the
# sandbox runner blanks it (`sandbox.BASE_CONTAINER_ENV`) instead of the probe
# excusing the *name* — a name-based allowlist would also excuse a real secret
# that happened to use that name.

PROBE_LIMITS = Limits(memory="256m", cpus=1.0, pids_limit=128, timeout_s=90)

RESULT_PREFIX = "EGA_RESULT "

# Three outcomes, decided from evidence only:
#   blocked  — the probe tried to escape and what it observed proves it failed
#   allowed  — the probe tried to escape and what it observed proves it got out
#   unproven — nothing was observed that settles it (sandbox error, no result,
#              a failure that is not the limit under test)
# "unproven" must never be shown as "allowed": a probe that could not run says
# nothing about containment.
BLOCKED = "blocked"
ALLOWED = "allowed"
UNPROVEN = "unproven"
OUTCOMES = (BLOCKED, ALLOWED, UNPROVEN)


@dataclass
class ProbeResult:
    name: str
    attempted: bool
    outcome: str
    evidence: str

    def __post_init__(self) -> None:
        if self.outcome not in OUTCOMES:
            raise ValueError(f"unknown probe outcome {self.outcome!r}")

    @property
    def blocked(self) -> bool:
        """True only when the evidence proves containment held."""
        return self.outcome == BLOCKED

    def as_dict(self) -> dict:
        return {
            "name": self.name,
            "attempted": self.attempted,
            "blocked": self.blocked,
            "outcome": self.outcome,
            "evidence": self.evidence,
        }


def _unproven(name: str, result: SandboxResult) -> ProbeResult:
    """The probe could not be observed: neither containment nor an escape."""
    return ProbeResult(
        name,
        True,
        UNPROVEN,
        f"sandbox error: {result.error or 'probe produced no result'} "
        f"exit={result.exit_code} stderr={_tail(result.stderr)}",
    )


def _payload(result: SandboxResult) -> dict | None:
    """Last EGA_RESULT json line printed by the probe script."""
    for line in reversed(result.stdout.splitlines()):
        if line.startswith(RESULT_PREFIX):
            try:
                return json.loads(line[len(RESULT_PREFIX) :])
            except json.JSONDecodeError:
                return None
    return None


def _tail(text: str, limit: int = 240) -> str:
    text = (text or "").strip().replace("\n", " | ")
    return text[-limit:] if len(text) > limit else text


def _run_script(script: str, limits: Limits) -> tuple[SandboxResult, dict | None]:
    """Run one probe script; neither the source nor the result tree outlives it."""
    src = tmp.mkdtemp("ega-probe-")
    try:
        (src / "probe.py").write_text(script, encoding="utf-8")
        result = sandbox.run(["python", "-I", "/work/probe.py"], src, limits)
        payload = _payload(result)
    finally:
        shutil.rmtree(src, ignore_errors=True)
    shutil.rmtree(result.workdir_after, ignore_errors=True)
    return result, payload


# --- probe scripts (each prints one EGA_RESULT json line) -------------------

NETWORK_SCRIPT = """\
import json, socket
attempts = []
try:
    socket.create_connection(("1.1.1.1", 443), timeout=5).close()
    attempts.append({"target": "tcp 1.1.1.1:443", "outcome": "connected"})
except OSError as exc:
    attempts.append({"target": "tcp 1.1.1.1:443", "outcome": "failed",
                     "error": f"{type(exc).__name__}: {exc}"})
try:
    socket.getaddrinfo("example.com", 80)
    attempts.append({"target": "dns example.com", "outcome": "resolved"})
except OSError as exc:
    attempts.append({"target": "dns example.com", "outcome": "failed",
                     "error": f"{type(exc).__name__}: {exc}"})
print("EGA_RESULT " + json.dumps({"attempts": attempts}))
"""

SECRET_SCRIPT = """\
import json
paths = ["/host_secrets/id_rsa", "/root/.ssh/id_rsa", "/etc/shadow"]
attempts = []
for path in paths:
    try:
        with open(path, "rb") as fh:
            data = fh.read(8)
        attempts.append({"path": path, "outcome": "read", "bytes": len(data)})
    except OSError as exc:
        attempts.append({"path": path, "outcome": "failed",
                         "error": f"{type(exc).__name__}: {exc}"})
print("EGA_RESULT " + json.dumps({"attempts": attempts}))
"""

WRITE_SCRIPT = """\
import json
targets = ["/etc/ega_probe", "/usr/ega_probe", "/root/ega_probe"]
attempts = []
for path in targets:
    try:
        with open(path, "w") as fh:
            fh.write("probe")
        attempts.append({"path": path, "outcome": "written"})
    except OSError as exc:
        attempts.append({"path": path, "outcome": "failed",
                         "error": f"{type(exc).__name__}: {exc}"})
print("EGA_RESULT " + json.dumps({"attempts": attempts}))
"""

FORK_SCRIPT = """\
import json, os
children, failure, failure_errno, attempts = [], None, None, 0
for _ in range(400):
    attempts += 1
    try:
        pid = os.fork()
    except OSError as exc:
        failure = f"{type(exc).__name__}: {exc}"
        failure_errno = exc.errno
        break
    if pid == 0:
        os._exit(0)
    children.append(pid)
for pid in children:
    try:
        os.waitpid(pid, 0)
    except OSError:
        pass
print("EGA_RESULT " + json.dumps({"attempts": attempts, "children": len(children),
                                  "failure": failure, "failure_errno": failure_errno}))
"""

MEMORY_SCRIPT = """\
import json
chunk_mb = 16
chunks = []
error = None
try:
    for _ in range(64):
        chunks.append(bytearray(chunk_mb * 1024 * 1024))
except MemoryError as exc:
    error = f"MemoryError: {exc}"
print("EGA_RESULT " + json.dumps({"allocated_mb": len(chunks) * chunk_mb,
                                  "error": error}))
"""

ENV_SCRIPT_TEMPLATE = """\
import json, os, re
fake = {fake!r}
pattern = re.compile(r"KEY|TOKEN|SECRET|PASSWORD", re.IGNORECASE)
env = dict(os.environ)
named = sorted(k for k in env if pattern.search(k))
suspects = sorted(k for k in named if env[k])
empty = sorted(k for k in named if not env[k])
fake_seen = sorted(k for k, v in env.items() if v == fake)
print("EGA_RESULT " + json.dumps({{"env_count": len(env), "keys": sorted(env),
                                   "suspects": suspects, "empty_keys": empty,
                                   "fake_seen": fake_seen}}))
"""


# --- probes ----------------------------------------------------------------


def probe_network_egress(limits: Limits = PROBE_LIMITS) -> ProbeResult:
    result, payload = _run_script(NETWORK_SCRIPT, limits)
    if result.error or payload is None:
        return _unproven("network_egress", result)
    attempts = payload["attempts"]
    escaped = [a for a in attempts if a["outcome"] in ("connected", "resolved")]
    detail = "; ".join(
        f"{a['target']} -> {a['outcome']}" + (f" ({a['error']})" if a.get("error") else "")
        for a in attempts
    )
    return ProbeResult(
        "network_egress", True, ALLOWED if escaped else BLOCKED,
        f"{detail} [exit={result.exit_code} isolation={result.isolation}]",
    )


def probe_host_secret_read(limits: Limits = PROBE_LIMITS) -> ProbeResult:
    result, payload = _run_script(SECRET_SCRIPT, limits)
    if result.error or payload is None:
        return _unproven("host_secret_read", result)
    attempts = payload["attempts"]
    read = [a for a in attempts if a["outcome"] == "read"]
    detail = "; ".join(
        f"{a['path']} -> {a['outcome']}" + (f" ({a['error']})" if a.get("error") else "")
        for a in attempts
    )
    return ProbeResult(
        "host_secret_read", True, ALLOWED if read else BLOCKED,
        f"{detail} [exit={result.exit_code}]",
    )


def probe_write_outside_workspace(limits: Limits = PROBE_LIMITS) -> ProbeResult:
    result, payload = _run_script(WRITE_SCRIPT, limits)
    if result.error or payload is None:
        return _unproven("write_outside_workspace", result)
    attempts = payload["attempts"]
    written = [a for a in attempts if a["outcome"] == "written"]
    detail = "; ".join(
        f"{a['path']} -> {a['outcome']}" + (f" ({a['error']})" if a.get("error") else "")
        for a in attempts
    )
    return ProbeResult(
        "write_outside_workspace", True, ALLOWED if written else BLOCKED,
        f"{detail} [exit={result.exit_code}]",
    )


def fork_verdict(
    children: int,
    failure: str | None,
    failure_errno: int | None,
    pids_limit: int,
) -> tuple[bool, bool, str]:
    """``(blocked, reached, why)`` for one fork-bomb observation.

    The pids cgroup reports EAGAIN/BlockingIOError ("Resource temporarily
    unavailable"). Any other OSError, or a run that never approached the cap,
    is not evidence that the limit did the blocking.
    """
    eagain = failure_errno == errno.EAGAIN or bool(
        failure
        and (
            "EAGAIN" in failure
            or "BlockingIOError" in failure
            or "Resource temporarily unavailable" in failure
        )
    )
    threshold = int(pids_limit * 0.5)
    reached = children >= threshold
    blocked = bool(eagain and reached)
    if blocked:
        return True, reached, "ok"
    if eagain and not reached:
        return False, reached, f"EAGAIN at {children} children, below the {threshold} threshold"
    if reached and not eagain:
        return False, reached, f"failure was {failure!r}, not a pids-limit EAGAIN"
    return False, reached, f"only {children} children and no EAGAIN failure ({failure!r})"


def memory_verdict(
    oom_killed: bool, memory_error: bool, exit_code: int
) -> tuple[bool, str]:
    """``(blocked, why)`` — only a kernel OOM kill or a MemoryError proves it."""
    if oom_killed:
        return True, "oom_killed=True"
    if memory_error:
        return True, "MemoryError"
    return (
        False,
        f"exit_code={exit_code} but no OOMKilled flag and no MemoryError",
    )


def probe_fork_bomb(limits: Limits = PROBE_LIMITS) -> ProbeResult:
    result, payload = _run_script(FORK_SCRIPT, limits)
    if result.error or payload is None:
        return _unproven("fork_bomb", result)
    children = payload["children"]
    failure = payload["failure"]
    blocked, reached, why = fork_verdict(
        children, failure, payload.get("failure_errno"), limits.pids_limit
    )
    evidence = (
        f"attempts={payload['attempts']} children={children} "
        f"pids_limit={limits.pids_limit} reached={reached} "
        f"eagain={blocked or 'EAGAIN' in (failure or '')} failure={failure} "
        f"why={why} [exit={result.exit_code}]"
    )
    # Reaching half the cap and dying some *other* way means the pids limit did
    # not stop the bomb (allowed); never approaching it proves nothing.
    outcome = BLOCKED if blocked else (ALLOWED if reached else UNPROVEN)
    return ProbeResult("fork_bomb", True, outcome, evidence)


def probe_memory_hog(limits: Limits = PROBE_LIMITS) -> ProbeResult:
    result, payload = _run_script(MEMORY_SCRIPT, limits)
    if result.error:
        return _unproven("memory_hog", result)
    memory_error = bool(payload and payload.get("error"))
    allocated = payload["allocated_mb"] if payload else "unknown"
    blocked, why = memory_verdict(result.oom_killed, memory_error, result.exit_code)
    if result.oom_killed:
        evidence = (
            f"OOM-killed after allocating {allocated} MB: exit_code={result.exit_code} "
            f"oom_killed=True memory_limit={limits.memory}"
        )
    elif memory_error:
        evidence = (
            f"MemoryError after allocating {allocated} MB: {payload['error']} "
            f"[exit={result.exit_code}]"
        )
    else:
        evidence = (
            f"allocated {allocated} MB without a proven cap (memory_limit={limits.memory}): "
            f"exit_code={result.exit_code} oom_killed={result.oom_killed} "
            f"memory_error={memory_error}"
        )
    # An exit code alone (e.g. 137) is not proof the cap did the killing, so
    # anything the verdict does not confirm stays unproven.
    return ProbeResult(
        "memory_hog", True, BLOCKED if blocked else UNPROVEN, f"{evidence} why={why}"
    )


def probe_env_leak(limits: Limits = PROBE_LIMITS) -> ProbeResult:
    result, payload = _run_script(
        ENV_SCRIPT_TEMPLATE.format(fake=FAKE_SECRET_VALUE), limits
    )
    if result.error or payload is None:
        return _unproven("env_leak", result)
    suspicious = payload["suspects"]
    return ProbeResult(
        "env_leak", True,
        ALLOWED if (suspicious or payload["fake_seen"]) else BLOCKED,
        f"env_count={payload['env_count']} keys={payload['keys']} "
        f"suspicious_keys={suspicious} empty_keys={payload['empty_keys']} "
        f"fake_token_seen={payload['fake_seen']} "
        f"host_{FAKE_SECRET_ENV}_seeded={FAKE_SECRET_VALUE!r}",
    )


PROBES = (
    probe_network_egress,
    probe_host_secret_read,
    probe_write_outside_workspace,
    probe_fork_bomb,
    probe_memory_hog,
    probe_env_leak,
)


def run_probes(limits: Limits = PROBE_LIMITS) -> list[ProbeResult]:
    """Run all six probes. The fake host secret is seeded for the whole sweep."""
    previous = os.environ.get(FAKE_SECRET_ENV)
    os.environ[FAKE_SECRET_ENV] = FAKE_SECRET_VALUE
    try:
        return [probe(limits) for probe in PROBES]
    finally:
        if previous is None:
            os.environ.pop(FAKE_SECRET_ENV, None)
        else:
            os.environ[FAKE_SECRET_ENV] = previous