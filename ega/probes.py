"""Containment probes: each one *tries* to escape and reports what happened.

`blocked` is computed from what the sandbox actually returned (exception text,
exit code, OOMKilled), never from what we expected.
"""

from __future__ import annotations

import json
import os
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from . import sandbox
from .sandbox import Limits, SandboxResult

FAKE_SECRET_ENV = "EGA_FAKE_SECRET_TOKEN"
FAKE_SECRET_VALUE = "ega-fake-secret-DO-NOT-LEAK-9f3a"

# Keys baked into the *image* that match KEY|TOKEN|SECRET|PASSWORD but are
# public metadata, not secrets (the python base image ships a public OpenPGP
# fingerprint). They are reported in the evidence as "excluded", never hidden,
# and this allowlist is deliberately tiny: anything else matching the pattern
# still fails the probe.
BASE_IMAGE_METADATA_KEYS = frozenset({"GPG_KEY"})

PROBE_LIMITS = Limits(memory="256m", cpus=1.0, pids_limit=128, timeout_s=90)

RESULT_PREFIX = "EGA_RESULT "


@dataclass
class ProbeResult:
    name: str
    attempted: bool
    blocked: bool
    evidence: str

    def as_dict(self) -> dict:
        return {
            "name": self.name,
            "attempted": self.attempted,
            "blocked": self.blocked,
            "evidence": self.evidence,
        }


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
    src = Path(tempfile.mkdtemp(prefix="ega-probe-"))
    (src / "probe.py").write_text(script, encoding="utf-8")
    result = sandbox.run(["python", "-I", "/work/probe.py"], src, limits)
    return result, _payload(result)


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
children, failure, attempts = [], None, 0
for _ in range(400):
    attempts += 1
    try:
        pid = os.fork()
    except OSError as exc:
        failure = f"{type(exc).__name__}: {exc}"
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
                                  "failure": failure}))
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
suspects = sorted(k for k in env if pattern.search(k))
fake_seen = sorted(k for k, v in env.items() if v == fake)
print("EGA_RESULT " + json.dumps({{"env_count": len(env), "keys": sorted(env),
                                   "suspects": suspects, "fake_seen": fake_seen}}))
"""


# --- probes ----------------------------------------------------------------


def probe_network_egress(limits: Limits = PROBE_LIMITS) -> ProbeResult:
    result, payload = _run_script(NETWORK_SCRIPT, limits)
    if result.error or payload is None:
        return ProbeResult(
            "network_egress", True, False,
            f"sandbox error: {result.error or 'probe produced no result'} "
            f"exit={result.exit_code} stderr={_tail(result.stderr)}",
        )
    attempts = payload["attempts"]
    escaped = [a for a in attempts if a["outcome"] in ("connected", "resolved")]
    blocked = not escaped
    detail = "; ".join(
        f"{a['target']} -> {a['outcome']}" + (f" ({a['error']})" if a.get("error") else "")
        for a in attempts
    )
    return ProbeResult(
        "network_egress", True, blocked,
        f"{detail} [exit={result.exit_code} isolation={result.isolation}]",
    )


def probe_host_secret_read(limits: Limits = PROBE_LIMITS) -> ProbeResult:
    result, payload = _run_script(SECRET_SCRIPT, limits)
    if result.error or payload is None:
        return ProbeResult(
            "host_secret_read", True, False,
            f"sandbox error: {result.error or 'probe produced no result'} "
            f"exit={result.exit_code} stderr={_tail(result.stderr)}",
        )
    attempts = payload["attempts"]
    read = [a for a in attempts if a["outcome"] == "read"]
    detail = "; ".join(
        f"{a['path']} -> {a['outcome']}" + (f" ({a['error']})" if a.get("error") else "")
        for a in attempts
    )
    return ProbeResult(
        "host_secret_read", True, not read,
        f"{detail} [exit={result.exit_code}]",
    )


def probe_write_outside_workspace(limits: Limits = PROBE_LIMITS) -> ProbeResult:
    result, payload = _run_script(WRITE_SCRIPT, limits)
    if result.error or payload is None:
        return ProbeResult(
            "write_outside_workspace", True, False,
            f"sandbox error: {result.error or 'probe produced no result'} "
            f"exit={result.exit_code} stderr={_tail(result.stderr)}",
        )
    attempts = payload["attempts"]
    written = [a for a in attempts if a["outcome"] == "written"]
    detail = "; ".join(
        f"{a['path']} -> {a['outcome']}" + (f" ({a['error']})" if a.get("error") else "")
        for a in attempts
    )
    return ProbeResult(
        "write_outside_workspace", True, not written,
        f"{detail} [exit={result.exit_code}]",
    )


def probe_fork_bomb(limits: Limits = PROBE_LIMITS) -> ProbeResult:
    result, payload = _run_script(FORK_SCRIPT, limits)
    if result.error or payload is None:
        return ProbeResult(
            "fork_bomb", True, False,
            f"sandbox error: {result.error or 'probe produced no result'} "
            f"exit={result.exit_code} stderr={_tail(result.stderr)}",
        )
    capped = payload["failure"] is not None
    evidence = (
        f"attempts={payload['attempts']} children={payload['children']} "
        f"pids_limit={limits.pids_limit} failure={payload['failure']} [exit={result.exit_code}]"
    )
    return ProbeResult("fork_bomb", True, capped, evidence)


def probe_memory_hog(limits: Limits = PROBE_LIMITS) -> ProbeResult:
    result, payload = _run_script(MEMORY_SCRIPT, limits)
    if result.error:
        return ProbeResult(
            "memory_hog", True, False,
            f"sandbox error: {result.error} exit={result.exit_code} stderr={_tail(result.stderr)}",
        )
    killed = result.oom_killed or result.exit_code == 137 or result.exit_code == -9
    memory_error = bool(payload and payload.get("error"))
    allocated = payload["allocated_mb"] if payload else "unknown"
    if killed:
        evidence = (
            f"process killed after allocating {allocated} MB: exit_code={result.exit_code} "
            f"oom_killed={result.oom_killed} memory_limit={limits.memory}"
        )
    elif memory_error:
        evidence = f"MemoryError after allocating {allocated} MB: {payload['error']} [exit={result.exit_code}]"
    else:
        evidence = (
            f"allocated {allocated} MB without being stopped "
            f"(memory_limit={limits.memory}) [exit={result.exit_code}]"
        )
    return ProbeResult("memory_hog", True, killed or memory_error, evidence)


def probe_env_leak(limits: Limits = PROBE_LIMITS) -> ProbeResult:
    result, payload = _run_script(
        ENV_SCRIPT_TEMPLATE.format(fake=FAKE_SECRET_VALUE), limits
    )
    if result.error or payload is None:
        return ProbeResult(
            "env_leak", True, False,
            f"sandbox error: {result.error or 'probe produced no result'} "
            f"exit={result.exit_code} stderr={_tail(result.stderr)}",
        )
    excluded = [k for k in payload["suspects"] if k in BASE_IMAGE_METADATA_KEYS]
    suspicious = [k for k in payload["suspects"] if k not in BASE_IMAGE_METADATA_KEYS]
    return ProbeResult(
        "env_leak", True, not (suspicious or payload["fake_seen"]),
        f"env_count={payload['env_count']} keys={payload['keys']} "
        f"suspicious_keys={suspicious} excluded_base_image_keys={excluded} "
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