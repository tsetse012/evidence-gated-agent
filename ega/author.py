"""Author interface plus the scripted placeholder.

`ScriptedAuthor` is the stand-in for the LLM author that arrives after
kickoff: it applies a canned patch from the fixture and returns a canned
claim. Nothing here calls a model.
"""

from __future__ import annotations

import json
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, runtime_checkable

from .verify import Claim


@runtime_checkable
class Author(Protocol):
    """An author edits ``workdir`` and says what it thinks it achieved."""

    def work(self, task: str, workdir: Path) -> Claim: ...


def _patch_dir(fixture_dir: Path, patch_name: str) -> Path:
    path = Path(fixture_dir) / "patches" / patch_name
    if not path.is_dir():
        raise FileNotFoundError(f"no patch {patch_name!r} in {Path(fixture_dir) / 'patches'}")
    return path


def available_patches(fixture_dir: Path) -> list[str]:
    root = Path(fixture_dir) / "patches"
    if not root.is_dir():
        return []
    return sorted(p.name for p in root.iterdir() if p.is_dir())


@dataclass(frozen=True)
class ScriptedAuthor:
    fixture_dir: Path
    patch_name: str

    @property
    def name(self) -> str:
        return f"scripted:{self.patch_name}"

    def claim(self) -> Claim:
        path = _patch_dir(self.fixture_dir, self.patch_name) / "claim.json"
        return Claim.from_dict(json.loads(path.read_text(encoding="utf-8")))

    def work(self, task: str, workdir: Path) -> Claim:
        patch = _patch_dir(self.fixture_dir, self.patch_name)
        files = patch / "files"
        if files.is_dir():
            shutil.copytree(files, Path(workdir), dirs_exist_ok=True)
        return self.claim()