#!/usr/bin/env python3
"""Behaviour tests for lib/process_tree.kill_under_path — the cell-leak reaper.

A benchmark cell can leave a fuzzer running after its command returns: escaped
via ``nohup``, a trailing ``&``, a new session, or reparenting to PID 1. The
reaper finds and kills those by the cell directory in their argv. Exercises:

  * reap — a leaked process whose argv references the cell dir is TERM/KILLed
  * no false positive — a sibling process outside the cell dir is untouched
  * path boundary — cell ``-r1`` never matches sibling ``-r10``
  * descendants — a match's helper child (argv without the cell dir) is reaped
  * self-safety — a process whose OWN argv names the cell dir never kills itself
  * ancestor guard — _protected_pids walks the parent chain and breaks on cycles
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "lib"))

import process_tree as pt  # noqa: E402

PASSED = 0
FAILED = 0


def ok(cond: bool, name: str, detail: str = "") -> None:
    global PASSED, FAILED
    if cond:
        PASSED += 1
        print(f"  \033[0;32m✓\033[0m {name}")
    else:
        FAILED += 1
        print(f"  \033[0;31m✗\033[0m {name}")
        if detail:
            print(f"    {detail}")


def _alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _spawn_marker(marker: str) -> subprocess.Popen:
    """A long-lived process carrying ``marker`` as an argv token (ignored by
    the -c program). Puts an arbitrary path into argv without running it."""
    return subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(120)", marker]
    )


def _wait_dead(pid: int, timeout: float = 5.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not _alive(pid):
            return True
        time.sleep(0.05)
    return not _alive(pid)


def _signalled(proc: subprocess.Popen, timeout: float = 5.0) -> bool:
    """A Popen child the reaper killed dies with a negative (signalled) rc.
    Also collects the zombie so a still-listed <defunct> pid cannot confuse a
    later ps snapshot (test-only concern: real leaks reparent away from us)."""
    try:
        rc = proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        return False
    return rc is not None and rc < 0


def _cleanup(*items) -> None:
    """Best-effort teardown for Popen children (kill + reap) or raw pids."""
    for item in items:
        if isinstance(item, subprocess.Popen):
            try:
                item.kill()
            except OSError:
                pass
            try:
                item.wait(timeout=2)
            except (OSError, subprocess.TimeoutExpired):
                pass
        elif isinstance(item, int) and item > 0:
            try:
                os.kill(item, 9)
            except OSError:
                pass


with tempfile.TemporaryDirectory(prefix="process-tree-") as tmp:
    base = Path(tmp)

    # ── reap + no-false-positive + path boundary ──────────────────────
    print("reap / isolation")
    cell = base / "cell-r1"
    cell.mkdir()
    sibling = base / "cell-r10"       # shares the cell-r1 prefix sans separator
    sibling.mkdir()
    outside = base / "unrelated"
    outside.mkdir()

    victim = _spawn_marker(str(cell / "corpus" / "input"))
    control = _spawn_marker(str(outside / "corpus" / "input"))
    boundary = _spawn_marker(str(sibling / "corpus" / "input"))
    try:
        time.sleep(0.3)  # let the children settle into the ps snapshot
        reaped = pt.kill_under_path(cell, grace=1.0)

        ok(victim.pid in reaped, "leaked cell process is reaped",
           f"reaped={reaped} victim={victim.pid}")
        ok(_signalled(victim), "reaped cell process is dead")
        ok(control.pid not in reaped and _alive(control.pid),
           "process outside the cell dir is untouched",
           f"reaped={reaped} control={control.pid}")
        ok(boundary.pid not in reaped and _alive(boundary.pid),
           "cell-r1 reap does not match sibling cell-r10",
           f"reaped={reaped} boundary={boundary.pid}")
        ok(pt.kill_under_path(base / "cell-r99", grace=0.2) == [],
           "no match returns empty without signalling anything")
    finally:
        _cleanup(victim, control, boundary)

    # ── descendant expansion ──────────────────────────────────────────
    print("\ndescendants")
    dcell = base / "dcell"
    dcell.mkdir()
    pidfile = dcell / "child.pid"     # under the cell → parent argv matches
    # Parent argv carries the cell path (pidfile); its child `sleep` does not.
    parent = subprocess.Popen([
        sys.executable, "-c",
        "import subprocess,sys,time;"
        "p=subprocess.Popen([sys.executable,'-c','import time;time.sleep(120)']);"
        "open(sys.argv[1],'w').write(str(p.pid));time.sleep(120)",
        str(pidfile),
    ])
    child_pid = -1
    try:
        for _ in range(60):
            if pidfile.is_file() and pidfile.read_text().strip():
                child_pid = int(pidfile.read_text().strip())
                break
            time.sleep(0.05)
        ok(child_pid > 0, "descendant child spawned")
        reaped = pt.kill_under_path(dcell, grace=1.0)
        ok(parent.pid in reaped, "path-matched parent is reaped",
           f"reaped={reaped} parent={parent.pid}")
        ok(child_pid in reaped,
           "child whose argv omits the cell dir is reaped as a descendant",
           f"reaped={reaped} child={child_pid}")
        ok(_signalled(parent) and _wait_dead(child_pid),
           "parent and descendant are both dead")
    finally:
        _cleanup(parent, child_pid)

    # ── self-safety: a matcher never kills its own tree ───────────────
    print("\nself-safety")
    scell = base / "scell"
    scell.mkdir()
    helper = r"""
import json, os, subprocess, sys, time
sys.path.insert(0, os.path.join(sys.argv[2], "lib"))
import process_tree as pt
cell = sys.argv[1]
gc = subprocess.Popen(
    [sys.executable, "-c", "import time; time.sleep(120)",
     os.path.join(cell, "gc-input")]
)
time.sleep(0.3)
reaped = pt.kill_under_path(cell, grace=1.0)
open(os.path.join(cell, "result.json"), "w").write(
    json.dumps({"reaped": reaped, "self": os.getpid(), "gc": gc.pid})
)
"""
    # The helper's own argv carries the cell path (sys.argv[1]); it must reap
    # the grandchild but never itself.
    helper_proc = subprocess.Popen(
        [sys.executable, "-c", helper, str(scell), str(ROOT)]
    )
    gc_pid = -1
    try:
        rc = helper_proc.wait(timeout=15)
        result = json.loads((scell / "result.json").read_text())
        gc_pid = result["gc"]
        ok(rc == 0, "self-referencing matcher exits normally (did not kill itself)",
           f"rc={rc}")
        ok(result["self"] not in result["reaped"],
           "matcher excludes its own pid from the reap set",
           repr(result))
        ok(result["gc"] in result["reaped"] and _wait_dead(result["gc"]),
           "matcher still reaps a genuine leaked grandchild", repr(result))
    finally:
        _cleanup(helper_proc, gc_pid)

    # ── ancestor guard (unit) ─────────────────────────────────────────
    print("\nancestor guard")
    uid = 0
    rows = [(10, 1, uid, "a"), (11, 10, uid, "b"), (12, 11, uid, "c")]
    ok(pt._protected_pids(rows, 12) == {12, 11, 10, 1},
       "protected set is the pid plus its ancestor chain")
    cyc = [(20, 21, uid, "x"), (21, 20, uid, "y")]   # a ppid cycle
    ok(pt._protected_pids(cyc, 20) == {20, 21},
       "protected-chain walk terminates on a cycle")

    # ── ps snapshot sanity on this platform ───────────────────────────
    print("\nsnapshot")
    snap = pt._process_rows()
    me = os.getpid()
    ok(any(pid == me for pid, _pp, _u, _c in snap),
       "process snapshot includes this process")
    ok(all(len(r) == 4 for r in snap) and snap,
       "process snapshot rows are (pid, ppid, uid, command)")


print()
if FAILED:
    print(f"\033[0;31m{FAILED} failed, {PASSED} passed\033[0m")
    sys.exit(1)
print(f"\033[0;32m{PASSED}/{PASSED} passed\033[0m")
