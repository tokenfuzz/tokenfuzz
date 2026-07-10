#!/usr/bin/env python3
"""Behavior tests for lib/probe_helpers.py's command interface."""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
HELPER = ROOT / "lib" / "probe_helpers.py"
passed = 0
failed = 0


def check(condition: bool, name: str, detail: str = "") -> None:
    global passed, failed
    if condition:
        passed += 1
        print(f"  \033[0;32m\u2713\033[0m {name}")
    else:
        failed += 1
        print(f"  \033[0;31m\u2717\033[0m {name}: {detail}")


def run(*args: str, text: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(HELPER), *args],
        capture_output=True,
        text=text,
    )


print("path-under")
with tempfile.TemporaryDirectory() as directory:
    root = Path(directory) / "root"
    child = root / "child"
    sibling = Path(directory) / "root-sibling"
    child.mkdir(parents=True)
    sibling.mkdir()
    check(run("path-under", str(root), str(child)).returncode == 0,
          "accepts descendant")
    check(run("path-under", str(root), str(sibling)).returncode == 1,
          "rejects lexical-prefix sibling")
    link = root / "escape"
    link.symlink_to(sibling, target_is_directory=True)
    check(run("path-under", str(root), str(link)).returncode == 1,
          "rejects symlink escape")

print("split-shell-words")
proc = run("split-shell-words", "-DNAME='two words' 'line1\nline2'", text=False)
check(proc.returncode == 0, "valid words exit zero")
check(proc.stdout.split(b"\0")[:-1] == [b"-DNAME=two words", b"line1\nline2"],
      "emits lossless NUL-delimited arguments", repr(proc.stdout))
proc = run("split-shell-words", "'unterminated")
check(proc.returncode == 2, "invalid quoting exits two")
check("cannot parse shell words" in proc.stderr, "invalid quoting is legible")

print("build-log-digest")
with tempfile.TemporaryDirectory() as directory:
    log = Path(directory) / "build.log"
    log.write_bytes(b"HEAD" + b"x" * 600 + b"TAIL")
    proc = run("build-log-digest", str(log), "4", "4")
    check(proc.returncode == 0, "digest exits zero")
    check("HEAD" in proc.stderr and "TAIL" in proc.stderr,
          "digest retains head and tail")
    check("compiler log elided 600 bytes" in proc.stderr,
          "digest reports omitted byte count", proc.stderr)
    proc = run("build-log-digest", str(log), "bad", "bad")
    check("compiler log elided" not in proc.stderr,
          "invalid bounds use compatible 8192-byte defaults")

print(f"\n  {passed}/{passed + failed} passed")
raise SystemExit(0 if failed == 0 else 1)
