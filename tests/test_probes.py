"""Probes: the six containment checks must be blocked, and the verdicts must be
decided by evidence (EAGAIN + a reached cap, OOMKilled/MemoryError) rather than
by any failure at all.

Only the tests that really start containers are marked `docker`; the decision
logic and the script templates are checked as plain unit tests so a machine
without Docker still covers the review's repro cases.
"""

from __future__ import annotations

import errno
import shutil

import pytest

from ega import probes

EXPECTED_NAMES = [
    "network_egress",
    "host_secret_read",
    "write_outside_workspace",
    "fork_bomb",
    "memory_hog",
    "env_leak",
]


@pytest.fixture(scope="module")
def results():
    return probes.run_probes()


# --- decision logic (no Docker needed) -------------------------------------


def test_fork_permission_error_with_no_children_is_not_blocked():
    """Review #11 repro: EPERM on the first fork must not read as containment."""
    blocked, reached, why = probes.fork_verdict(0, "PermissionError: [Errno 1] Operation not permitted", errno.EPERM, 128)
    assert blocked is False
    assert reached is False
    assert "no EAGAIN" in why


def test_fork_eagain_below_the_threshold_is_not_blocked():
    blocked, reached, why = probes.fork_verdict(10, "BlockingIOError: [Errno 11] Resource temporarily unavailable", errno.EAGAIN, 128)
    assert blocked is False
    assert reached is False
    assert "below the" in why


def test_fork_eagain_after_reaching_the_threshold_is_blocked():
    blocked, reached, why = probes.fork_verdict(64, "BlockingIOError: Resource temporarily unavailable", errno.EAGAIN, 128)
    assert blocked is True
    assert reached is True
    assert why == "ok"


def test_fork_reaching_the_cap_without_eagain_is_not_blocked():
    """Hitting the cap and dying some other way proves nothing about the limit."""
    blocked, reached, _ = probes.fork_verdict(400, "OSError: [Errno 12] Cannot allocate memory", errno.ENOMEM, 128)
    assert blocked is False
    assert reached is True


def test_memory_exit_137_without_oom_flag_is_not_blocked():
    """Review #11 repro: exit code alone is not evidence of the cap."""
    blocked, why = probes.memory_verdict(oom_killed=False, memory_error=False, exit_code=137)
    assert blocked is False
    assert "no OOMKilled flag" in why


def test_memory_oom_killed_is_blocked():
    blocked, why = probes.memory_verdict(oom_killed=True, memory_error=False, exit_code=137)
    assert blocked is True
    assert why == "oom_killed=True"


def test_memory_memory_error_is_blocked():
    blocked, why = probes.memory_verdict(oom_killed=False, memory_error=True, exit_code=0)
    assert blocked is True
    assert why == "MemoryError"


# --- script templates (no Docker needed) -----------------------------------


def test_env_probe_template_is_parameterised():
    """The fake value is injected at run time, not baked into the template."""
    assert "{fake!r}" in probes.ENV_SCRIPT_TEMPLATE
    assert probes.FAKE_SECRET_VALUE not in probes.ENV_SCRIPT_TEMPLATE


def test_env_probe_classifies_suspects_by_value_not_by_name():
    """A KEY-shaped name with an empty value is reported, not excused or hidden."""
    assert '"suspects": suspects' in probes.ENV_SCRIPT_TEMPLATE
    assert '"empty_keys": empty' in probes.ENV_SCRIPT_TEMPLATE
    assert "if env[k]" in probes.ENV_SCRIPT_TEMPLATE


def test_there_is_no_name_based_allowlist_left():
    """Review #12: exceptions by variable *name* hide a real secret of that name."""
    assert not hasattr(probes, "BASE_IMAGE_METADATA_KEYS")


def test_the_runner_blanks_image_metadata():
    from ega import sandbox

    assert sandbox.BASE_CONTAINER_ENV["GPG_KEY"] == ""


# --- container-backed integration -----------------------------------------


@pytest.mark.docker
def test_every_probe_ran(results):
    assert [r.name for r in results] == EXPECTED_NAMES
    assert all(r.attempted for r in results)


@pytest.mark.docker
def test_every_probe_is_blocked(results):
    escaped = [r.name for r in results if not r.blocked]
    assert not escaped, "probes escaped containment: " + ", ".join(
        f"{r.name} ({r.evidence})" for r in results if not r.blocked
    )


@pytest.mark.docker
def test_evidence_is_recorded_per_probe(results):
    for result in results:
        assert result.evidence, f"{result.name} recorded no evidence"
        assert "sandbox error" not in result.evidence


@pytest.mark.docker
def test_network_evidence_shows_the_failure(results):
    probe = next(r for r in results if r.name == "network_egress")
    assert "1.1.1.1" in probe.evidence
    assert "failed" in probe.evidence


@pytest.mark.docker
def test_secret_probe_cannot_read_etc_shadow(results):
    probe = next(r for r in results if r.name == "host_secret_read")
    assert "/etc/shadow" in probe.evidence
    assert "/etc/shadow -> read" not in probe.evidence


@pytest.mark.docker
def test_fork_bomb_reports_the_pid_cap(results):
    probe = next(r for r in results if r.name == "fork_bomb")
    assert "failure=None" not in probe.evidence
    assert "reached=True" in probe.evidence
    assert "eagain=True" in probe.evidence


@pytest.mark.docker
def test_memory_hog_is_oom_killed(results):
    probe = next(r for r in results if r.name == "memory_hog")
    assert probe.blocked is True
    assert "oom_killed=True" in probe.evidence or "MemoryError" in probe.evidence


@pytest.mark.docker
def test_env_probe_seeded_a_fake_host_secret_that_did_not_leak(results):
    probe = next(r for r in results if r.name == "env_leak")
    assert probes.FAKE_SECRET_ENV in probe.evidence
    assert "suspicious_keys=[]" in probe.evidence
    assert "fake_token_seen=[]" in probe.evidence
    # the base image's public GPG fingerprint is present but blanked
    assert "empty_keys=['GPG_KEY']" in probe.evidence


@pytest.mark.docker
def test_probe_write_targets_are_reported(results):
    probe = next(r for r in results if r.name == "write_outside_workspace")
    assert "/etc/ega_probe" in probe.evidence
    assert "written" not in probe.evidence


@pytest.mark.docker
def test_env_probe_would_detect_a_leak_if_one_were_forwarded(tmp_path):
    """Positive control: the detector fires when the value really is in the env."""
    from ega import sandbox

    src = tmp_path / "src"
    src.mkdir()
    (src / "probe.py").write_text(
        probes.ENV_SCRIPT_TEMPLATE.format(fake=probes.FAKE_SECRET_VALUE), encoding="utf-8"
    )
    result = sandbox.run(
        ["python", "-I", "/work/probe.py"],
        src,
        probes.PROBE_LIMITS,
        env={probes.FAKE_SECRET_ENV: probes.FAKE_SECRET_VALUE},
    )
    try:
        payload = probes._payload(result)
        assert payload is not None, result.stderr
        assert payload["fake_seen"] == [probes.FAKE_SECRET_ENV]
        assert probes.FAKE_SECRET_ENV in payload["suspects"]
    finally:
        # The run's own copy of /work is ours to remove; leaking it here is the
        # same "the harness leaves ega-* behind" failure the gate checks for.
        shutil.rmtree(result.workdir_after, ignore_errors=True)