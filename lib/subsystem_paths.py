"""Map target-relative source paths to audit subsystems."""

from __future__ import annotations

import re
from pathlib import Path


_MODE_TOKENS = {"browser", "shell", "both"}


def load_subsystems(path: Path) -> list[str]:
    """Load path prefixes from a subsystem overlay, ignoring mode columns."""
    if not path.is_file():
        return []
    prefixes: list[str] = []
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        fields = line.split(None, 1)
        if len(fields) == 2 and fields[0] in _MODE_TOKENS:
            line = fields[1].strip()
        if line:
            prefixes.append(line)
    return prefixes


def _subsystem_pattern(subsystems: list[str]) -> re.Pattern[str] | None:
    prefixes = sorted({value for value in subsystems if value}, key=len, reverse=True)
    if not prefixes:
        return None
    return re.compile(r"^(?:" + "|".join(re.escape(value) for value in prefixes) + r")(?=/|:|$)")


def subsystem_from_path(path: str, *, subsystems: list[str] | None = None) -> str:
    """Return the matching browser prefix or first two generic path components."""
    if not path or path.startswith("/"):
        return ""
    pattern = _subsystem_pattern(subsystems or [])
    if pattern is not None:
        match = pattern.search(path)
        return match.group(0) if match else ""
    parts = [part for part in path.split("/") if part]
    if len(parts) >= 2:
        return f"{parts[0]}/{parts[1]}"
    return parts[0] if parts else ""
