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


def _process_rows() -> list[tuple[int, int, int, str]]:
    """(pid, ppid, uid, command) for every process, in one snapshot.

    ``-ww`` disables ps's argv-column truncation so a cell path that sits late
    in a long fuzzer command line is still seen — procps otherwise clips the
    ``command`` column to the terminal width, or 80 columns when stdout is a
    pipe, which would silently drop the match. ``command`` exposes argv even
    when the environment is hidden (macOS redacts env for same-uid processes),
    and a leaked target binary or its input still carries its cell directory in
    argv after escaping the session group.
    """
    try:
        out = subprocess.check_output(
            ["ps", "-axww", "-o", "pid=,ppid=,uid=,command="], text=True,
        )
    except (OSError, subprocess.SubprocessError):
        return []
    rows: list[tuple[int, int, int, str]] = []
    for line in out.splitlines():
        parts = line.split(None, 3)
        if len(parts) < 4:
            continue
        try:
            pid, ppid, uid = int(parts[0]), int(parts[1]), int(parts[2])
        except ValueError:
            continue
        rows.append((pid, ppid, uid, parts[3]))
    return rows


def _protected_pids(rows: list[tuple[int, int, int, str]], pid: int) -> set[int]:
    """``pid`` plus its ancestor chain: the reap must never signal its own
    process tree upward, even if an ancestor's argv happens to name the path."""
    parent = {row[0]: row[1] for row in rows}
    chain = {pid}
    cur = parent.get(pid)
    while cur and cur not in chain:
        chain.add(cur)
        cur = parent.get(cur)
    return chain


def kill_under_path(directory: str | os.PathLike[str], grace: float = 1.0) -> list[int]:
    """TERM then KILL every same-uid process a completed unit of work left
    behind, identified by ``directory``.

    A process is reaped when its argv references a path under ``directory`` — an
    escaped fuzzer keeps its cell directory in argv through ``nohup``, a
    trailing ``&``, a new session, or reparenting to PID 1 — together with the
    descendants of such a match whose own argv may not name the path (a fuzzer's
    helper children). The trailing separator makes the match a true path
    boundary, so cell ``-r1`` never matches ``-r10``; this process and its
    ancestors are never signalled. Returns the reaped PIDs, ascending, for the
    caller to log.
    """
    prefix = os.path.abspath(os.fspath(directory)).rstrip("/") + "/"
    rows = _process_rows()
    if not rows:
        return []
    uid = os.getuid()
    protected = _protected_pids(rows, os.getpid())
    matched = {
        pid for pid, _ppid, puid, cmd in rows
        if puid == uid and pid not in protected and prefix in cmd
    }
    if not matched:
        return []
    children: dict[int, list[int]] = {}
    for pid, ppid, puid, _cmd in rows:
        if puid == uid and pid not in protected:
            children.setdefault(ppid, []).append(pid)
    targets = set(matched)
    stack = list(matched)
    while stack:
        for child in children.get(stack.pop(), []):
            if child not in targets:
                targets.add(child)
                stack.append(child)
    ordered = sorted(targets)
    _kill(ordered, signal.SIGTERM)
    deadline = time.monotonic() + grace
    while grace > 0 and time.monotonic() < deadline:
        if not any(_alive(pid) for pid in ordered):
            break
        time.sleep(0.05)
    _kill([pid for pid in ordered if _alive(pid)], signal.SIGKILL)
    return ordered


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
