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
import types

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


# --- outcomes (no Docker needed) -------------------------------------------


def fake_run_script(monkeypatch, payload, *, error=None):
    """Feed a probe a canned sandbox result instead of starting a container."""
    result = types.SimpleNamespace(
        error=error, exit_code=1, stderr="boom", isolation="runc", oom_killed=False
    )
    monkeypatch.setattr(
        probes, "_run_script", lambda script, limits: (result, payload)
    )


def test_a_probe_that_could_not_run_is_unproven_not_allowed(monkeypatch):
    """Measured 2026-10-28: a deleted probe source made the panel say ALLOWED."""
    fake_run_script(monkeypatch, None, error="could not copy the source tree: [Errno 2]")

    result = probes.probe_network_egress()

    assert result.outcome == probes.UNPROVEN
    assert result.blocked is False
    assert "sandbox error" in result.evidence
    assert result.as_dict()["outcome"] == "unproven"


def test_an_observed_escape_is_allowed(monkeypatch):
    fake_run_script(
        monkeypatch,
        {
            "attempts": [
                {"target": "tcp 1.1.1.1:443", "outcome": "connected"},
                {"target": "dns example.com", "outcome": "resolved"},
            ]
        },
    )

    result = probes.probe_network_egress()

    assert result.outcome == probes.ALLOWED
    assert result.blocked is False


def test_a_refused_escape_is_blocked(monkeypatch):
    fake_run_script(
        monkeypatch,
        {
            "attempts": [
                {"target": "tcp 1.1.1.1:443", "outcome": "failed", "error": "OSError"},
            ]
        },
    )

    result = probes.probe_network_egress()

    assert result.outcome == probes.BLOCKED
    assert result.blocked is True


def test_a_fork_bomb_that_reached_the_cap_without_eagain_is_allowed(monkeypatch):
    """Past half the cap and not stopped by it: the limit is not holding."""
    fake_run_script(
        monkeypatch,
        {
            "attempts": 400,
            "children": 400,
            "failure": "OSError: [Errno 12] Cannot allocate memory",
            "failure_errno": errno.ENOMEM,
        },
    )

    result = probes.probe_fork_bomb()

    assert result.outcome == probes.ALLOWED


def test_eagain_below_the_threshold_stays_unproven(monkeypatch):
    fake_run_script(
        monkeypatch,
        {
            "attempts": 11,
            "children": 10,
            "failure": "BlockingIOError: [Errno 11] Resource temporarily unavailable",
            "failure_errno": errno.EAGAIN,
        },
    )

    result = probes.probe_fork_bomb()

    assert result.outcome == probes.UNPROVEN


def test_the_env_leak_outcome_follows_the_fake_secret(monkeypatch):
    fake_run_script(
        monkeypatch,
        {
            "env_count": 3,
            "keys": ["A"],
            "suspects": [probes.FAKE_SECRET_ENV],
            "empty_keys": [],
            "fake_seen": [probes.FAKE_SECRET_ENV],
        },
    )

    assert probes.probe_env_leak().outcome == probes.ALLOWED


# --- host secret (review L3) ----------------------------------------------


def test_the_secret_probe_seeds_a_real_host_file_whose_bytes_are_not_in_the_script():
    """A path that never existed cannot prove anything by not being readable."""
    script, seeded, canary_dir = probes.secret_probe_script()
    try:
        canary = canary_dir / "id_rsa"
        assert canary.is_file(), "the canary must really exist on the host for the run"
        token = canary.read_text(encoding="utf-8").strip()
        assert token.startswith("ega-canary-")
        assert str(canary) in seeded
        # The probe searches for the token; its own text must not be a copy of it.
        assert token not in script
        assert repr(str(canary)) in script
    finally:
        shutil.rmtree(canary_dir, ignore_errors=True)
    assert not canary_dir.exists()


def test_a_seeded_path_the_probe_never_tried_is_unproven():
    outcome, why = probes.host_secret_verdict([], [], {"/a/canary"})

    assert outcome == probes.UNPROVEN
    assert "never tried" in why


def test_finding_the_canary_content_inside_the_container_is_allowed():
    attempts = [{"path": "/a/canary", "outcome": "failed", "seeded": "seeded"}]

    outcome, why = probes.host_secret_verdict(
        attempts, ["/ega-out/leaked"], {"/a/canary"}
    )

    assert outcome == probes.ALLOWED
    assert "content was found" in why


def test_reading_a_seeded_host_file_is_allowed():
    attempts = [{"path": "/a/canary", "outcome": "read", "seeded": "seeded"}]

    outcome, why = probes.host_secret_verdict(attempts, [], {"/a/canary"})

    assert outcome == probes.ALLOWED
    assert "readable" in why


def test_every_seeded_path_tried_and_nothing_readable_is_blocked():
    attempts = [
        {"path": "/a/canary", "outcome": "failed", "seeded": "seeded"},
        {"path": "/etc/shadow", "outcome": "failed", "seeded": "seeded"},
    ]

    outcome, why = probes.host_secret_verdict(attempts, [], {"/a/canary", "/etc/shadow"})

    assert outcome == probes.BLOCKED
    assert why.startswith("no seeded host file")


def test_an_unseeded_path_does_not_count_towards_blocked():
    """"not found" for a path nobody created is evidence of nothing."""
    attempts = [{"path": "/root/.aws/credentials", "outcome": "failed", "seeded": "not seeded"}]

    outcome, _ = probes.host_secret_verdict(attempts, [], {"/a/canary"})

    assert outcome == probes.UNPROVEN


# --- memory (review L4) ----------------------------------------------------


def test_allocating_past_the_limit_without_being_stopped_is_allowed(monkeypatch):
    fake_run_script(monkeypatch, {"allocated_mb": 1024, "error": None})

    result = probes.probe_memory_hog()

    assert result.outcome == probes.ALLOWED
    assert "past the 256m limit" in result.evidence


def test_allocating_under_the_limit_without_a_verdict_stays_unproven(monkeypatch):
    fake_run_script(monkeypatch, {"allocated_mb": 64, "error": None})

    result = probes.probe_memory_hog()

    assert result.outcome == probes.UNPROVEN
    assert "without a proven cap" in result.evidence


@pytest.mark.parametrize(
    ("value", "expected"), [("256m", 256.0), ("1g", 1024.0), ("512k", 0.5), ("", None), ("lots", None)]
)
def test_memory_limits_are_parsed(value, expected):
    assert probes.memory_limit_mb(value) == expected


def test_an_unknown_outcome_is_refused():
    with pytest.raises(ValueError):
        probes.ProbeResult("probe", True, "probably-fine", "no evidence")


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


# --- read-only root (VM, 2026-11-04) --------------------------------------
#
# gVisor's VFS refuses a write under a read-only root with EACCES where runc's
# overlayfs says EROFS. The verdict must follow "the write failed and nothing
# was created", not the wording — and it must not accept a failed write that
# still put the file on disk.


def test_a_refused_write_with_no_file_is_blocked():
    attempts = [
        {"path": "/etc/ega_probe", "outcome": "failed", "errno": errno.EROFS, "exists": False,
         "error": "OSError: [Errno 30] Read-only file system"},
        {"path": "/usr/ega_probe", "outcome": "failed", "errno": errno.EROFS, "exists": False,
         "error": "OSError: [Errno 30] Read-only file system"},
    ]

    outcome, why = probes.write_verdict(attempts)

    assert outcome == probes.BLOCKED
    assert "no file was created" in why


def test_gvisor_eacces_counts_as_a_refused_write():
    attempts = [
        {"path": "/etc/ega_probe", "outcome": "failed", "errno": errno.EACCES, "exists": False,
         "error": "PermissionError: [Errno 13] Permission denied"},
    ]

    outcome, _ = probes.write_verdict(attempts)

    assert outcome == probes.BLOCKED


def test_a_failed_write_that_left_the_file_is_allowed():
    """A failed write that still created the file is an escape, not a refusal."""
    attempts = [
        {"path": "/etc/ega_probe", "outcome": "failed", "errno": errno.EACCES, "exists": True,
         "error": "PermissionError: [Errno 13] Permission denied"},
    ]

    outcome, why = probes.write_verdict(attempts)

    assert outcome == probes.ALLOWED
    assert "file exists" in why


def test_a_write_that_failed_for_another_reason_is_unproven():
    attempts = [
        {"path": "/etc/ega_probe", "outcome": "failed", "errno": errno.ENOENT, "exists": False,
         "error": "FileNotFoundError: [Errno 2] No such file or directory"},
    ]

    outcome, why = probes.write_verdict(attempts)

    assert outcome == probes.UNPROVEN
    assert "not a refused permission" in why


# --- container-backed integration -----------------------------------------


@pytest.mark.docker
def test_every_probe_ran(results):
    assert [r.name for r in results] == EXPECTED_NAMES
    assert all(r.attempted for r in results)
    assert {r.outcome for r in results} <= set(probes.OUTCOMES)


@pytest.mark.docker
def test_every_probe_is_blocked(results):
    escaped = [r.name for r in results if r.outcome != probes.BLOCKED]
    assert not escaped, "probes did not prove containment: " + ", ".join(
        f"{r.name} ({r.outcome}: {r.evidence})"
        for r in results
        if r.outcome != probes.BLOCKED
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
    # Refused *and* absent on every target: the file was never created either.
    assert probe.evidence.count("exists=False") == 3, probe.evidence
    assert "errno=" in probe.evidence


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