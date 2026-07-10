#!/usr/bin/env python3
"""Helpers for resolving real tools when audit wrappers lead PATH."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Iterable, Mapping


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
