#!/usr/bin/env python3
"""CLI tests for sanitizer text helpers."""

from __future__ import annotations

import base64
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
TOOL = ROOT / "lib" / "sanitizer_helpers.py"
passed = 0
failed = 0


def check(condition: bool, name: str) -> None:
    global passed, failed
    if condition:
        passed += 1
        print(f"  \033[0;32m\u2713\033[0m {name}")
    else:
        failed += 1
        print(f"  \033[0;31m\u2717\033[0m {name}")


def run(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, str(TOOL), *args], capture_output=True, text=True)


with tempfile.TemporaryDirectory() as directory:
    root = Path(directory)
    noisy = root / "browser.log"
    noisy.write_text(
        "Nightly GPU Helper[1] noise\n"
        "AddressSanitizer: heap-buffer-overflow\n"
        "Exiting due to channel error.\n",
        encoding="utf-8",
    )
    output = run("filter-browser", str(noisy)).stdout
    check("AddressSanitizer" in output, "browser filter preserves diagnostics")
    check("GPU Helper" not in output and "channel error" not in output,
          "browser filter removes known console noise")

    (root / "source.cpp").write_text(
        "MOZ_FUZZING_INTERFACE_RAW(x, y, target_beta)\n"
        "MOZ_FUZZING_INTERFACE_STREAM(x, y, target_alpha)\n",
        encoding="utf-8",
    )
    skipped = root / "build-asan-image"
    skipped.mkdir()
    (skipped / "hidden.cpp").write_text(
        "MOZ_FUZZING_INTERFACE_RAW(x, y, hidden_target)\n", encoding="utf-8"
    )
    output = run("list-firefox-fuzz-targets", str(root)).stdout.splitlines()
    check(output == ["target_alpha", "target_beta"],
          "fuzz target listing sorts, deduplicates, and prunes build trees")

value = "detect_leaks=1:note=two words"
encoded = run("encode-options", value).stdout.strip()
check(base64.b64decode(encoded).decode() == value, "option encoding round-trips")

print(f"\n  {passed}/{passed + failed} passed")
raise SystemExit(0 if failed == 0 else 1)
