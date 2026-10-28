"""Shared fixtures. Docker-marked tests are skipped only with a named reason."""

from __future__ import annotations

import pytest

from ega import sandbox


def pytest_collection_modifyitems(config, items):
    if sandbox.docker_available():
        return
    skip = pytest.mark.skip(reason=sandbox.DOCKER_SKIP_REASON)
    for item in items:
        if "docker" in item.keywords:
            item.add_marker(skip)