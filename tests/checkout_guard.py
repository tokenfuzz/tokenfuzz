#!/usr/bin/env python3
"""Compare tracked-file metadata before and after the test run.

Usage: checkout_guard.py {record,check} ROOT SNAPSHOT_FILE

An ordinary write-and-restore changes timestamps even when bytes are restored.
Two synchronous scans avoid startup races and a polling process per runner.
This is a test-isolation check, not a filesystem event log: it cannot attribute
changes to a process or guarantee detection on filesystems that retain identical
metadata or transient paths absent at both scans. Do not edit the checkout
while tests run. Existing dirty files are OK.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from collections.abc import Iterable
from pathlib import Path


def tracked_files(root: Path) -> list[str] | None:
    if not (root / ".git").exists():
        print("checkout guard: no .git; tracked-file check skipped", file=sys.stderr)
        return None
    completed = subprocess.run(
        # The container's uid may differ from the bind mount's owner.
        ["git", "-c", f"safe.directory={root}", "-C", str(root), "ls-files", "-z"],
        capture_output=True, check=True,
    )
    return [os.fsdecode(path) for path in completed.stdout.split(b"\0") if path]


def snapshot(root: Path, paths: Iterable[str]) -> dict[str, list[int] | None]:
    state = {}
    for relative in paths:
        try:
            stat = os.lstat(root / relative)
        except (FileNotFoundError, NotADirectoryError):
            state[relative] = None
        else:
            # ctime also catches a writer restoring mtime; inode catches replacement.
            state[relative] = [stat.st_mtime_ns, stat.st_ctime_ns, stat.st_size,
                               stat.st_mode, stat.st_ino]
    return state


def main(argv: list[str]) -> int:
    if len(argv) != 4 or argv[1] not in {"record", "check"}:
        print(__doc__, file=sys.stderr)
        return 2
    operation, root, saved = argv[1], Path(argv[2]).resolve(), Path(argv[3])
    try:
        if operation == "record":
            paths = tracked_files(root)
            state = None if paths is None else snapshot(root, paths)
            saved.write_text(json.dumps(state), encoding="utf-8")
            return 0
        previous = json.loads(saved.read_text(encoding="utf-8"))
        if previous is None:
            return 0
        current = snapshot(root, previous)
        changed = [path for path in previous if previous[path] != current[path]]
        for path in changed:
            print(f"{path}: tracked-file metadata changed")
        # Keep detected changes distinct from Python failures (exit 1).
        return 3 if changed else 0
    except (OSError, ValueError, subprocess.CalledProcessError) as exc:
        print(f"checkout guard: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
