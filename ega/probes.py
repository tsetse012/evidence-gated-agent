"""Containment probes: each one *tries* to escape and reports what happened.

`blocked` is computed from what the sandbox actually returned (exception text,
exit code, OOMKilled), never from what we expected.
"""

from __future__ import annotations

import errno
import json
import os
import shutil
import uuid
from dataclasses import dataclass
from pathlib import Path

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
    if result.workdir_after is not None:
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

# The host file this probe is really about is one *we seeded*: a path that does
# not exist on the host proves nothing when the container cannot open it. The
# canary's content is searched for as well, so "the name is not there" and "the
# bytes are not there" are both covered.
# __TOKEN__ / __PATHS__ / __SEEDED__ are substituted at run time (the token is
# split in two so the script's own text never contains it).
SECRET_SCRIPT = """\
import json, os

token = __TOKEN__
paths = __PATHS__
seeded = __SEEDED__
attempts = []
for path in paths:
    try:
        with open(path, "rb") as fh:
            data = fh.read(8)
        attempts.append({"path": path, "outcome": "read", "bytes": len(data),
                         "seeded": seeded.get(path, "not seeded")})
    except OSError as exc:
        attempts.append({"path": path, "outcome": "failed",
                         "error": f"{type(exc).__name__}: {exc}",
                         "seeded": seeded.get(path, "not seeded")})

# Content search over everything the container can see. A mount or a copy that
# leaked the host file carries the token; a failed open() alone cannot tell
# "absent" from "never created".
found = []
searched = 0
skip = {"/proc", "/sys", "/dev", "/work", "/ega-out", "/tmp"}
for base in ["/work", "/ega-out", "/tmp", "/"]:
    for dirpath, dirnames, filenames in os.walk(base):
        if dirpath in skip or dirpath.count(os.sep) > 6:
            dirnames[:] = []
            continue
        dirnames[:] = [d for d in dirnames if os.path.join(dirpath, d) not in skip]
        for name in filenames:
            path = os.path.join(dirpath, name)
            try:
                if os.path.getsize(path) > 1000000:
                    continue
                with open(path, "rb") as fh:
                    searched += 1
                    if token.encode() in fh.read():
                        found.append(path)
            except OSError:
                continue
print("EGA_RESULT " + json.dumps({"attempts": attempts, "found": found,
                                  "searched_files": searched}))
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


def secret_probe_script() -> tuple[str, dict[str, str], Path]:
    """``(script, seeded, canary_dir)`` for one host-secret probe.

    The canary is a real file on the host for the duration of the run: a path
    that was never created cannot prove anything by not being readable. The
    caller removes ``canary_dir`` afterwards.
    """
    canary_dir = tmp.mkdtemp("ega-canary-")
    canary_path = canary_dir / "id_rsa"
    token = f"ega-canary-{uuid.uuid4().hex}{uuid.uuid4().hex}"
    canary_path.write_text(f"{token}\n", encoding="utf-8")
    seeded = {
        str(canary_path): "seeded host canary (exists on the host for this run)",
        "/etc/shadow": "seeded by the image (root-only file)",
    }
    middle = len(token) // 2
    # Split so the probe's own text does not contain the token it searches for.
    script = (
        SECRET_SCRIPT.replace("__TOKEN__", f"{token[:middle]!r} + {token[middle:]!r}")
        .replace("__PATHS__", repr(sorted(seeded)))
        .replace("__SEEDED__", repr(seeded))
    )
    return script, seeded, canary_dir


def host_secret_verdict(
    attempts: list[dict], found: list[str], seeded: set[str]
) -> tuple[str, str]:
    """``(outcome, why)`` for one host-secret observation.

    ``blocked`` needs every seeded path to have actually been tried, nothing
    readable, and the canary's bytes nowhere in the container. A path the probe
    never reached, or a canary that could not be seeded, is ``unproven`` — the
    review caught "not found" being counted for paths that never existed.
    """
    tried = {a.get("path") for a in attempts if a.get("seeded") != "not seeded"}
    missing = sorted(seeded - tried)
    if missing:
        return UNPROVEN, f"the probe never tried the seeded path(s) {missing}"
    if found:
        return ALLOWED, f"the seeded content was found inside the container: {found}"
    read = [a["path"] for a in attempts if a.get("outcome") == "read"]
    if read:
        return ALLOWED, f"a seeded host file was readable: {read}"
    return BLOCKED, "no seeded host file was readable and no copy of its content was found"


def probe_host_secret_read(limits: Limits = PROBE_LIMITS) -> ProbeResult:
    script, seeded, canary_dir = secret_probe_script()
    try:
        result, payload = _run_script(script, limits)
    finally:
        shutil.rmtree(canary_dir, ignore_errors=True)
    if result.error or payload is None:
        return _unproven("host_secret_read", result)
    attempts = payload["attempts"]
    found = payload.get("found", [])
    outcome, why = host_secret_verdict(attempts, found, set(seeded))
    detail = "; ".join(
        f"{a['path']} -> {a['outcome']} ({a.get('seeded', 'not seeded')})"
        + (f" ({a['error']})" if a.get("error") else "")
        for a in attempts
    )
    return ProbeResult(
        "host_secret_read",
        True,
        outcome,
        f"{detail}; canary_content_found={found} searched_files={payload.get('searched_files')} "
        f"why={why} [exit={result.exit_code}]",
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


_MEMORY_UNITS = {"k": 1 / 1024, "m": 1.0, "g": 1024.0, "t": 1024.0 * 1024}


def memory_limit_mb(value: str) -> float | None:
    """The docker ``--memory`` value in MB (``"256m"`` -> ``256.0``)."""
    text = str(value or "").strip().lower()
    if not text:
        return None
    unit = text[-1]
    number = text[:-1] if unit in _MEMORY_UNITS else text
    try:
        amount = float(number)
    except ValueError:
        return None
    return amount * _MEMORY_UNITS.get(unit, 1.0)


def probe_memory_hog(limits: Limits = PROBE_LIMITS) -> ProbeResult:
    result, payload = _run_script(MEMORY_SCRIPT, limits)
    if result.error:
        return _unproven("memory_hog", result)
    memory_error = bool(payload and payload.get("error"))
    allocated = payload["allocated_mb"] if payload else "unknown"
    limit_mb = memory_limit_mb(limits.memory)
    # Allocating past the cap and living to report it *is* the escape: nothing
    # else in the observation could have kept the allocation in place.
    over_limit = isinstance(allocated, int) and limit_mb is not None and allocated > limit_mb
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
    elif over_limit:
        evidence = (
            f"allocated {allocated} MB past the {limits.memory} limit "
            f"({limit_mb:g} MB) and was not stopped: exit_code={result.exit_code} "
            f"oom_killed={result.oom_killed} memory_error={memory_error}"
        )
    else:
        evidence = (
            f"allocated {allocated} MB without a proven cap (memory_limit={limits.memory}): "
            f"exit_code={result.exit_code} oom_killed={result.oom_killed} "
            f"memory_error={memory_error}"
        )
    # An exit code alone (e.g. 137) is not proof the cap did the killing, so
    # anything the verdict does not confirm stays unproven.
    outcome = BLOCKED if blocked else (ALLOWED if over_limit else UNPROVEN)
    return ProbeResult("memory_hog", True, outcome, f"{evidence} why={why}")


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