#!/usr/bin/env python3
"""Behavior tests for shared binary-safe file tools."""

from __future__ import annotations

import subprocess
import sys
import tempfile
import os
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parent.parent
TOOL = ROOT / "lib" / "file_tools.py"
sys.path.insert(0, str(ROOT / "lib"))
from command_tools import find_executable
from file_tools import cap_output_bytes, clipped_prefix_bytes, tail_lines
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


def run(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, str(TOOL), *args], capture_output=True)


with tempfile.TemporaryDirectory() as directory:
    path = Path(directory) / "data.bin"
    path.write_bytes(b"first line\nsecond line\nthird line\n")
    process = run("clip", str(path), "20")
    check(process.stdout == b"first line\n", "clip emits only complete prefix lines")
    check(path.read_bytes().startswith(b"first line\nsecond"), "stdout clip does not mutate input")
    process = run("clip", str(path), "20", "--in-place")
    check(path.read_bytes() == b"first line\n", "in-place clip uses identical boundary")

    large = Path(directory) / "large.bin"
    large.write_bytes(b"head\n" + b"middle\n" * 100 + b"tail\n")
    process = run("head-tail", str(large), "8", "8", "sample", "/tmp/full.log")
    check(b"head\n" in process.stdout and b"tail\n" in process.stdout,
          "head-tail retains both ends")
    check(b"output_cap: sample truncated" in process.stdout,
          "head-tail emits the established marker")
    check(b"Full output: /tmp/full.log" in process.stdout,
          "head-tail reports spill path")

    check(clipped_prefix_bytes(b"one\ntwo\nthree\n", 9) == b"one\ntwo\n",
          "byte clipping shares the newline-aligned boundary")
    spill = Path(directory) / "spill"
    rendered = cap_output_bytes(
        b"head\n" + b"middle\n" * 20 + b"tail\n",
        "sample/path",
        {
            "OUTCAP_MAX_BYTES": "32",
            "OUTCAP_HEAD_BYTES": "12",
            "OUTCAP_TAIL_BYTES": "12",
            "OUTCAP_SPILL_DIR": str(spill),
        },
    )
    check(b"output_cap: sample-path truncated" in rendered,
          "shared cap sanitizes labels and emits the established marker")
    spills = list(spill.glob("outcap-sample-path-*.txt"))
    check(len(spills) == 1 and spills[0].stat().st_mode & 0o077 == 0,
          "shared cap writes one private spill")

    wrapped = Path(directory) / "wrapped"
    real = Path(directory) / "real"
    wrapped.mkdir()
    real.mkdir()
    for directory_path in (wrapped, real):
        executable = directory_path / "sample-tool"
        executable.write_text("#!/bin/sh\nexit 0\n")
        executable.chmod(0o755)
    resolved = find_executable(
        "sample-tool", skip=(wrapped,), env={"PATH": f"{wrapped}{os.pathsep}{real}"}
    )
    check(resolved == str(real / "sample-tool"),
          "command resolution skips the audit wrapper directory")

    broken = Path(directory) / "broken"
    broken.mkdir()
    broken_tool = broken / "sample-tool"
    broken_tool.write_text("#!/bin/sh\nexit 0\n")
    broken_tool.chmod(0o755)
    original_resolve = Path.resolve

    def fail_broken_resolve(path, *args, **kwargs):
        if path == broken:
            raise OSError("synthetic broken PATH entry")
        return original_resolve(path, *args, **kwargs)

    with mock.patch.object(Path, "resolve", fail_broken_resolve):
        resolved = find_executable(
            "sample-tool", env={"PATH": f"{broken}{os.pathsep}{real}"}
        )
    check(resolved == str(real / "sample-tool"),
          "command resolution ignores PATH entries that cannot be resolved")

    transcript = Path(directory) / "large.raw"
    transcript.write_bytes(b"prefix\n" * 400_000 + b"tail-one\n\n tail-two\n")
    check(
        tail_lines(transcript, 2, nonempty=True) == ["tail-one", " tail-two"],
        "tail reader returns final non-empty lines from a large transcript",
    )
    check(
        tail_lines(transcript, 2) == ["", " tail-two"],
        "tail reader does not invent an empty line after a terminal newline",
    )

print(f"\n  {passed}/{passed + failed} passed")
raise SystemExit(0 if failed == 0 else 1)
