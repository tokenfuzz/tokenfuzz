#!/usr/bin/env python3
"""Behavior tests for subsystem path attribution."""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "lib"))

import subsystem_paths


passed = failed = 0


def check(expected: object, actual: object, name: str) -> None:
    global passed, failed
    if expected == actual:
        passed += 1
        print(f"  \033[0;32m✓\033[0m {name}")
    else:
        failed += 1
        print(f"  \033[0;31m✗\033[0m {name}")
        print(f"    expected={expected!r} actual={actual!r}")


with tempfile.TemporaryDirectory(prefix="subsystem-paths-") as temporary:
    overlay = Path(temporary) / "subsystems.txt"
    overlay.write_text(
        "# mode-aware overlay\n"
        "browser dom/media\n"
        "browser dom/media/webcodecs\n"
        "shell js/src/jit\n",
        encoding="utf-8",
    )
    prefixes = subsystem_paths.load_subsystems(overlay)
    check(
        ["dom/media", "dom/media/webcodecs", "js/src/jit"], prefixes,
        "mode columns are removed from subsystem overlays",
    )
    check(
        "dom/media/webcodecs",
        subsystem_paths.subsystem_from_path(
            "dom/media/webcodecs/codec.cpp:parse:42", subsystems=prefixes,
        ),
        "longest browser prefix wins",
    )
    check(
        "js/src/jit",
        subsystem_paths.subsystem_from_path("js/src/jit/lower.cpp", subsystems=prefixes),
        "shell-mode overlay paths remain attributable",
    )

check("src/lib", subsystem_paths.subsystem_from_path("src/lib/parser.c"), "generic paths use two components")
check("parser.c", subsystem_paths.subsystem_from_path("parser.c"), "flat generic paths stay attributable")
check("", subsystem_paths.subsystem_from_path("/host/source/parser.c"), "absolute paths do not leak host prefixes")
check("", subsystem_paths.subsystem_from_path("unknown/file.c", subsystems=["src/core"]), "unknown browser paths stay unassigned")
check("", subsystem_paths.subsystem_from_path("src/corelib/file.c", subsystems=["src/core"]), "subsystem prefixes stop at path boundaries")

print(f"\n{passed}/{passed + failed} passed, {failed} failed")
raise SystemExit(1 if failed else 0)
