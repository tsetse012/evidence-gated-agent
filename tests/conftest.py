"""Shared fixtures. Docker-marked tests are skipped only with a named reason."""

from __future__ import annotations

import pytest

from ega import sandbox


def pytest_collection_modifyitems(config, items):
    if sandbox.docker_available():
        return
    reason = "docker daemon not available (`docker info` failed); cannot run sandbox tests"
    skip = pytest.mark.skip(reason=reason)
    for item in items:
        if "docker" in item.keywords:
            item.add_marker(skip)