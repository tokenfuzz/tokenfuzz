#!/usr/bin/env python3
"""Helpers for resolving real tools when audit wrappers lead PATH."""

from __future__ import annotations

import os
import stat
from pathlib import Path
from collections.abc import Iterable, Mapping


def marked_executable(path: str | os.PathLike[str]) -> bool:
    """Whether a regular file carries an execute bit.

    For deciding what a file is (a built program rather than an input), read
    the mode, not os.access: on a Docker Desktop bind mount access(X_OK)
    reports a 0644 file executable to root, so an input whose bytes libmagic
    calls "executable" was taken for a program.
    """
    try:
        mode = os.stat(path).st_mode
    except OSError:
        return False
    return stat.S_ISREG(mode) and bool(mode & 0o111)


def find_executable(
    name: str,
    *,
    skip: Iterable[str | Path] = (),
    env: Mapping[str, str] | None = None,
) -> str | None:
    environment = os.environ if env is None else env
    skipped = {Path(path).resolve() for path in skip}
    for entry in environment.get("PATH", "").split(os.pathsep):
        directory = Path(entry or ".")
        try:
            if directory.resolve() in skipped:
                continue
        except OSError:
            continue
        candidate = directory / name
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate)
    return None
