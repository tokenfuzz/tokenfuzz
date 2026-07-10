#!/usr/bin/env python3
"""Metadata snapshot tests for lib/housekeeping.py."""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "lib"))

import housekeeping

with tempfile.TemporaryDirectory() as directory:
    root = Path(directory) / "artifacts"
    root.mkdir()
    regular = root / "finding.txt"
    regular.write_text("finding", encoding="utf-8")
    link = root / "link"
    link.symlink_to("finding.txt")
    missing = root / "missing"
    lines = housekeeping.metadata_lines(str(root)) + housekeeping.metadata_lines(str(missing))
    checks = [
        (any(line.startswith(f"D\t{root}\t") for line in lines), "directory metadata"),
        (any(line.startswith(f"F\t{regular}\t") for line in lines), "file metadata"),
        (any("\tlink\t" in line or line.startswith(f"L\t{link}\t") for line in lines),
         "symlink metadata"),
        (any(line.startswith(f"MISSING\t{missing}\t") for line in lines), "missing marker"),
    ]

failed = 0
for condition, name in checks:
    if condition:
        print(f"  \033[0;32m\u2713\033[0m {name}")
    else:
        failed += 1
        print(f"  \033[0;31m\u2717\033[0m {name}")
print(f"\n  {len(checks) - failed}/{len(checks)} passed")
raise SystemExit(0 if failed == 0 else 1)
