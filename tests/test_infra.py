"""infra/cloud-init.yaml must stay valid YAML and keep the gVisor wiring."""

from __future__ import annotations

import json
import re
from pathlib import Path

import yaml

INFRA = Path(__file__).resolve().parents[1] / "infra"


def load_cloud_init() -> dict:
    return yaml.safe_load((INFRA / "cloud-init.yaml").read_text(encoding="utf-8"))


def test_cloud_init_is_valid_yaml():
    raw = (INFRA / "cloud-init.yaml").read_text(encoding="utf-8")
    assert raw.startswith("#cloud-config")
    data = load_cloud_init()
    assert isinstance(data, dict)
    assert "runcmd" in data
    assert "write_files" in data


def test_daemon_json_registers_the_gvisor_runtime():
    data = load_cloud_init()
    daemon = next(f for f in data["write_files"] if f["path"] == "/etc/docker/daemon.json")
    parsed = json.loads(daemon["content"])
    assert parsed["runtimes"]["runsc"]["path"] == "/usr/local/bin/runsc"


def test_gvisor_is_installed_from_the_official_release_bucket():
    text = (INFRA / "cloud-init.yaml").read_text(encoding="utf-8")
    assert "storage.googleapis.com/gvisor/releases" in text
    assert "containerd-shim-runsc-v1" in text


def test_docker_comes_from_the_official_apt_repo():
    text = (INFRA / "cloud-init.yaml").read_text(encoding="utf-8")
    assert "download.docker.com/linux/ubuntu" in text


def test_firewall_and_service_units_are_present():
    text = (INFRA / "cloud-init.yaml").read_text(encoding="utf-8")
    for port in ("22/tcp", "80/tcp", "443/tcp"):
        assert f"ufw allow {port}" in text
    assert "ega.service" in text
    assert "/etc/caddy/Caddyfile" in text


def test_the_service_runs_as_the_dedicated_non_root_user():
    """Review #4: the API ran as root and therefore as root next to the socket."""
    data = load_cloud_init()
    unit = next(
        f for f in data["write_files"] if f["path"] == "/etc/systemd/system/ega.service"
    )["content"]
    assert "User=ega" in unit
    assert "Group=ega" in unit
    assert "SupplementaryGroups=docker" in unit
    assert "User=root" not in unit


def test_the_service_user_is_created_without_sudo_and_jointed_to_docker():
    text = (INFRA / "cloud-init.yaml").read_text(encoding="utf-8")
    assert "useradd" in text and "ega" in text
    assert "usermod -aG docker ega" in text
    assert "NOPASSWD" not in text


def test_the_app_is_owned_and_built_by_the_service_user():
    text = (INFRA / "cloud-init.yaml").read_text(encoding="utf-8")
    assert "chown -R ega:ega /opt/evidence-gated-agent" in text
    assert "su ega -s /bin/bash -c 'cd /opt/evidence-gated-agent && ./scripts/build_image.sh'" in text
    assert "uv sync --frozen" in text


def test_the_runs_directory_belongs_to_the_service_user():
    text = (INFRA / "cloud-init.yaml").read_text(encoding="utf-8")
    assert "chown -R ega:ega /var/lib/ega" in text


def test_no_placeholder_secrets_are_committed():
    text = (INFRA / "cloud-init.yaml").read_text(encoding="utf-8")
    assert not re.search(r"(AKIA|sk-[A-Za-z0-9]{16,}|BEGIN [A-Z ]*PRIVATE KEY)", text)


def test_readme_documents_the_smoke_tests():
    readme = (INFRA / "README.md").read_text(encoding="utf-8")
    assert "docker run --runtime=runsc --rm hello-world" in readme
    assert "run_probes" in readme


# --- the three failures measured on the VM (2026-11-04) --------------------


def _runcmd_lines() -> list[str]:
    return [str(line) for line in load_cloud_init()["runcmd"]]


def test_gvisor_comes_from_the_verified_tarball():
    """The per-binary URLs under latest/<arch>/ are gone (404, measured 2026-11-04).

    The tarball is the only artifact left, and it carries `gvisor-bin/` — the
    sentry sidecar without which `docker run --runtime=runsc` cannot create a
    sandbox at all.
    """
    lines = [line for line in _runcmd_lines() if "gvisor" in line]
    assert lines, "no gVisor install step"
    text = "\n".join(lines)
    assert "gvisor.tar.bz2" in text
    assert "gvisor.tar.bz2.sha512" in text
    assert any("/latest/${ARCH}/runsc" in line for line in lines) is False, (
        "the removed per-binary URL must not come back"
    )
    assert "gvisor-bin" in text, "the sentry sidecar ships inside the tarball"


def test_the_gvisor_checksum_is_verified_before_extraction():
    """One `&&` chain: a failed checksum can never be followed by an extract."""
    install = next(
        line for line in _runcmd_lines() if "gvisor.tar.bz2.sha512" in line and "curl" in line
    )
    assert "sha512sum -c" in install
    assert install.index("sha512sum -c") < install.index("tar -xjf")
    # ... and the install only counts as done when the sidecar is in place.
    assert "test -d /usr/local/bin/gvisor-bin" in install


def test_caddy_install_keeps_the_caddyfile_we_wrote():
    """write_files writes /etc/caddy/Caddyfile first, so dpkg hits a conffile prompt."""
    install = next(line for line in _runcmd_lines() if "caddy" in line and "apt-get install" in line)
    assert "-o Dpkg::Options::=--force-confold" in install


def test_the_service_user_uid_is_not_pinned():
    """The sandbox runs as the service user (ega.sandbox.container_user), so a
    host whose uid 1000 is taken (Vultr's `linuxuser`) provisions fine."""
    text = (INFRA / "cloud-init.yaml").read_text(encoding="utf-8")
    assert "--uid 1000" not in text
    assert "ega.sandbox.container_user" in text
