#!/usr/bin/env python3
"""Fail the suite when a test writes a tracked file of the checkout.

The checkout is shared by every suite the runner has in flight, so a test that
edits it — even one that restores the bytes a moment later — races every peer
that reads the tree: a benchmark run snapshots the control plane and re-digests
the checkout seconds later, and a test that patched ``lib/`` in between failed
it as "the checkout's harness files differ from the run's saved snapshot".
Whether the race lands depends on host speed and load, so the developer's
machine stayed green while CI did not. The write is the defect, not the
collision, and this guard reports the write itself.

Usage: checkout_guard.py ROOT STOP_FILE REPORT_FILE

Every tracked path is polled by ``lstat`` until STOP_FILE exists; a changed
mtime, size or mode, or a path that vanishes or reappears, is appended to
REPORT_FILE as it is seen. Comparing mtimes makes a write-and-restore visible
however quickly it happened, since the restore is itself a write. A checkout
without git has nothing to compare against and the guard says so and exits.
"""
from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path

POLL_SECONDS = 0.2


def tracked_files(root: Path) -> list[str] | None:
    """Every path git tracks under *root*, or None when git cannot say."""
    try:
        completed = subprocess.run(
            # A bind-mounted checkout is owned by another uid than the container's
            # root; without the safe.directory override git refuses to read it.
            ["git", "-c", "safe.directory=*", "-C", str(root), "ls-files", "-z"],
            capture_output=True, check=False,
        )
    except OSError:
        return None
    if completed.returncode:
        return None
    return [path for path in completed.stdout.decode("utf-8").split("\0") if path]


def snapshot(root: Path, paths: list[str]) -> dict[str, tuple[int, int, int] | None]:
    state: dict[str, tuple[int, int, int] | None] = {}
    for relative in paths:
        try:
            stat = os.lstat(root / relative)
        except FileNotFoundError:
            state[relative] = None
        else:
            state[relative] = (stat.st_mtime_ns, stat.st_size, stat.st_mode)
    return state


def describe(state: tuple[int, int, int] | None) -> str:
    if state is None:
        return "absent"
    mtime, size, mode = state
    return f"mtime={mtime} size={size} mode={mode:o}"


def main(argv: list[str]) -> int:
    if len(argv) != 4:
        print(__doc__, file=sys.stderr)
        return 2
    root = Path(argv[1]).resolve()
    stop = Path(argv[2])
    report = Path(argv[3])
    paths = tracked_files(root)
    if paths is None:
        print(
            "checkout guard: not a git checkout; tracked-file writes are not "
            "watched",
            file=sys.stderr,
        )
        return 0
    previous = snapshot(root, paths)
    with report.open("a", encoding="utf-8") as sink:
        while True:
            stopping = stop.exists()
            current = snapshot(root, paths)
            for relative in paths:
                if previous[relative] != current[relative]:
                    sink.write(
                        f"{time.strftime('%H:%M:%S')} {relative}: "
                        f"{describe(previous[relative])} -> "
                        f"{describe(current[relative])}\n"
                    )
                    sink.flush()
            previous = current
            if stopping:
                return 0
            time.sleep(POLL_SECONDS)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
