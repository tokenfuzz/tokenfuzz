#!/usr/bin/env python3
"""Small process-tree helpers for backend orchestrators."""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import time


def _children_by_parent() -> dict[int, list[int]]:
    out = subprocess.check_output(["ps", "-axo", "pid=,ppid="], text=True)
    children: dict[int, list[int]] = {}
    for line in out.splitlines():
        parts = line.split()
        if len(parts) != 2:
            continue
        try:
            pid, ppid = int(parts[0]), int(parts[1])
        except ValueError:
            continue
        children.setdefault(ppid, []).append(pid)
    return children


def descendants(root: int) -> list[int]:
    children = _children_by_parent()
    mine = os.getpid()
    out: list[int] = []
    stack = [root]
    while stack:
        cur = stack.pop()
        for child in children.get(cur, []):
            if child == mine:
                continue
            out.append(child)
            stack.append(child)
    return out


def _signum(name: str) -> signal.Signals:
    name = name.upper()
    if not name.startswith("SIG"):
        name = f"SIG{name}"
    return signal.Signals[name]


def _kill(pids: list[int], sig: signal.Signals) -> None:
    for pid in reversed(pids):
        try:
            os.kill(pid, sig)
        except ProcessLookupError:
            pass
        except PermissionError:
            pass


def kill_descendants(root: int, sig: signal.Signals, grace: float) -> None:
    pids = descendants(root)
    _kill(pids, sig)
    if grace > 0:
        time.sleep(grace)
    _kill([pid for pid in pids if _alive(pid)], signal.SIGKILL)


def _alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def main(argv: list[str]) -> int:
    if len(argv) < 3 or argv[1] != "kill-descendants":
        print("usage: process_tree.py kill-descendants <pid> [signal] [grace]", file=sys.stderr)
        return 2
    root = int(argv[2])
    sig = _signum(argv[3] if len(argv) > 3 else "TERM")
    grace = float(argv[4]) if len(argv) > 4 else 1.0
    kill_descendants(root, sig, grace)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
