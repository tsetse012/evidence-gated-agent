"""The one temporary root this process owns.

Two processes share one machine: the demo server on :8765 and the project's own
test gate. Both create dozens of temporary directories per run. Sweeping the
*whole* tempdir for ``ega-*`` and deleting whatever appeared during a window
therefore deletes the other process's live work: the server's probe source
disappears between ``mkdtemp`` and the copy into the container, the probe
reports ``could not copy the source tree``, and containment reads as unproven.
(Measured 2026-10-28: eleven of another process's directories removed.)

So every temporary directory this project creates lives under a root owned by
*this* process, and cleanup only ever looks inside that root:

* ``$EGA_TMPDIR`` when it is set — a fresh per-process directory is made
  underneath it, so two processes may share the variable safely;
* otherwise ``tempfile.mkdtemp(prefix="ega-root-")`` inside the system tempdir.

The root is made once per process, lazily, and removed at interpreter exit
**only when empty** — a directory that leaked stays on disk for the leak check
to find instead of being swept up by the same exit handler.
"""

from __future__ import annotations

import atexit
import os
import shutil
import tempfile
from pathlib import Path

ENV_VAR = "EGA_TMPDIR"
PREFIX = "ega-root-"

_root: Path | None = None


def root() -> Path:
    """This process's temporary root, created on first use and then reused."""
    global _root
    if _root is None:
        parent = os.environ.get(ENV_VAR)
        if parent:
            base = Path(parent).expanduser()
            base.mkdir(parents=True, exist_ok=True)
            path = Path(
                tempfile.mkdtemp(prefix=f"{PREFIX}{os.getpid()}-", dir=str(base))
            )
        else:
            path = Path(tempfile.mkdtemp(prefix=PREFIX))
        _root = path
        atexit.register(_remove_if_empty)
    return _root


def mkdtemp(prefix: str) -> Path:
    """A new temporary directory, parented under :func:`root`."""
    return Path(tempfile.mkdtemp(prefix=prefix, dir=str(root())))


def sweep(root: Path, before: set[Path]) -> list[Path]:
    """Delete entries that appeared under *root* after *before* was taken.

    *root* is the only directory ever enumerated. Another process's work lives
    beside it (in the shared tempdir, or in ``$EGA_TMPDIR``) and is never
    touched — that is the whole point of the split.
    """
    if not root.is_dir():
        return []
    removed = []
    for entry in sorted(set(root.iterdir()) - before):
        shutil.rmtree(entry, ignore_errors=True)
        removed.append(entry)
    return removed


def _remove_if_empty() -> None:
    current = _root
    if current is None:
        return
    try:
        current.rmdir()
    except OSError:  # not empty (a leak) or already gone
        pass