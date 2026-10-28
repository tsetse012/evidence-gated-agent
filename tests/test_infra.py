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


def test_no_placeholder_secrets_are_committed():
    text = (INFRA / "cloud-init.yaml").read_text(encoding="utf-8")
    assert not re.search(r"(AKIA|sk-[A-Za-z0-9]{16,}|BEGIN [A-Z ]*PRIVATE KEY)", text)


def test_readme_documents_the_smoke_tests():
    readme = (INFRA / "README.md").read_text(encoding="utf-8")
    assert "docker run --runtime=runsc --rm hello-world" in readme
    assert "run_probes" in readme