"""Integration: all six containment probes must be blocked (needs Docker)."""

from __future__ import annotations

import pytest

from ega import probes

pytestmark = pytest.mark.docker

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


def test_every_probe_ran(results):
    assert [r.name for r in results] == EXPECTED_NAMES
    assert all(r.attempted for r in results)


def test_every_probe_is_blocked(results):
    escaped = [r.name for r in results if not r.blocked]
    assert not escaped, "probes escaped containment: " + ", ".join(
        f"{r.name} ({r.evidence})" for r in results if not r.blocked
    )


def test_evidence_is_recorded_per_probe(results):
    for result in results:
        assert result.evidence, f"{result.name} recorded no evidence"
        assert "sandbox error" not in result.evidence


def test_network_evidence_shows_the_failure(results):
    probe = next(r for r in results if r.name == "network_egress")
    assert "1.1.1.1" in probe.evidence
    assert "failed" in probe.evidence


def test_secret_probe_cannot_read_etc_shadow(results):
    probe = next(r for r in results if r.name == "host_secret_read")
    assert "/etc/shadow" in probe.evidence
    assert "/etc/shadow -> read" not in probe.evidence


def test_fork_bomb_reports_the_pid_cap(results):
    probe = next(r for r in results if r.name == "fork_bomb")
    assert "failure=" in probe.evidence
    assert "failure=None" not in probe.evidence


def test_memory_hog_is_killed_or_raises(results):
    probe = next(r for r in results if r.name == "memory_hog")
    assert "MemoryError" in probe.evidence or "killed" in probe.evidence


def test_env_probe_seeded_a_fake_host_secret_that_did_not_leak(results):
    probe = next(r for r in results if r.name == "env_leak")
    assert probes.FAKE_SECRET_ENV in probe.evidence
    assert "suspicious_keys=[]" in probe.evidence
    assert "fake_token_seen=[]" in probe.evidence
    # the base image's public GPG fingerprint is reported, not hidden
    assert "excluded_base_image_keys=['GPG_KEY']" in probe.evidence


def test_base_image_allowlist_is_narrow_and_does_not_cover_secrets():
    assert probes.BASE_IMAGE_METADATA_KEYS == frozenset({"GPG_KEY"})
    assert probes.FAKE_SECRET_ENV not in probes.BASE_IMAGE_METADATA_KEYS


def test_env_probe_template_is_parameterised():
    """The fake value is injected at run time, not baked into the template."""
    assert "{fake!r}" in probes.ENV_SCRIPT_TEMPLATE
    assert probes.FAKE_SECRET_VALUE not in probes.ENV_SCRIPT_TEMPLATE


def test_probe_write_targets_are_reported(results):
    probe = next(r for r in results if r.name == "write_outside_workspace")
    assert "/etc/ega_probe" in probe.evidence
    assert "written" not in probe.evidence


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
    payload = probes._payload(result)
    assert payload is not None, result.stderr
    assert payload["fake_seen"] == [probes.FAKE_SECRET_ENV]
    assert probes.FAKE_SECRET_ENV in payload["suspects"]