"""Shared fixtures. Docker-marked tests are skipped only with a named reason."""

from __future__ import annotations

import shutil
import tempfile
from pathlib import Path

import pytest

from ega import sandbox
from ega import tmp


@pytest.fixture(scope="session", autouse=True)
def concurrent_process_tempdir():
    """A directory belonging to *another* process must survive this session.

    Regression, measured 2026-10-28: the suite's own cleanup globbed the whole
    tempdir and deleted every ``ega-*`` directory that appeared while a test
    was running — including a demo server's live probe source on the same
    machine. Three probes then reported ``could not copy the source tree`` and
    containment read as broken.

    Scope of this oracle: it catches a cleanup that deletes everything it finds
    (an unconditional sweep). The window semantics — "only directories that
    appeared after my snapshot" — cannot be exercised from here, because a
    pytest fixture snapshot always predates the directory this fixture creates;
    ``test_tmp.py`` covers that half against ``ega.tmp.sweep`` directly. The
    directory is never swept here, so a session that removes it fails at
    teardown.
    """
    foreign = Path(tempfile.mkdtemp(prefix="ega-foreign-", dir=tmp.root().parent))
    (foreign / "probe.py").write_text("# another process's work\n", encoding="utf-8")
    yield foreign
    assert (foreign / "probe.py").is_file(), (
        f"this session deleted a concurrent process's temp dir: {foreign}"
    )
    shutil.rmtree(foreign, ignore_errors=True)


def pytest_collection_modifyitems(config, items):
    if sandbox.docker_available():
        return
    skip = pytest.mark.skip(reason=sandbox.DOCKER_SKIP_REASON)
    for item in items:
        if "docker" in item.keywords:
            item.add_marker(skip)