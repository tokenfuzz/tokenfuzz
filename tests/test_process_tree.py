#!/usr/bin/env python3
"""Behaviour tests for lib/process_tree.kill_marked — the leaked-work reaper.

A benchmark cell can leave a fuzzer running after its command returns. The cell
command runs under a setsid'd timeout wrapper that reaps its own session group,
but bin/audit gives each agent a nested wrapper in a *new* session, so a leak
there survives the outer group kill. Ownership is therefore carried in the
environment: the launcher exports a unique reap id into the child only, and
every descendant inherits it — through `nohup`, `&`, setsid, and reparenting to
PID 1 — which makes it positive proof of ownership.

Exercises:
  * reap — a marked process is TERM/KILLed
  * escaped leak — a marked grandchild in a NEW session, reparented to PID 1
    (the shape that survives a session-group kill), is still reaped
  * inheritance — a child that never names the marker itself is still reaped
  * isolation — an unmarked process, and one carrying a different cell's
    marker, are both untouched
  * fail-safe — a caller whose OWN environment carries the marker reaps
    nothing (it would be killing its own tree)
  * empty marker is a no-op
"""

from __future__ import annotations

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


def _marked_env(marker: str) -> dict:
    return dict(os.environ, **{pt.REAP_MARKER_VAR: marker})


def _spawn_marked(marker: str, extra_env: dict | None = None) -> subprocess.Popen:
    """A long-lived process carrying ``marker`` in its environment."""
    env = _marked_env(marker)
    if extra_env:
        env.update(extra_env)
    return subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(120)"], env=env
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
    Also collects the zombie so a <defunct> entry cannot linger in a later
    scan (test-only concern: real leaks reparent away from us)."""
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


# ── reap + isolation ──────────────────────────────────────────────────
print("reap / isolation")
cell = pt.new_marker()
sibling = pt.new_marker()

ok(cell != sibling and len(cell) >= 16, "new_marker returns distinct opaque ids")

victim = _spawn_marked(cell)
other_cell = _spawn_marked(sibling)
unmarked = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(120)"])
try:
    time.sleep(0.3)  # let the children settle into the process scan
    reaped = pt.kill_marked(cell, grace=1.0)

    ok(victim.pid in reaped, "marked process is reaped",
       f"reaped={reaped} victim={victim.pid}")
    ok(_signalled(victim), "reaped process is dead")
    ok(other_cell.pid not in reaped and _alive(other_cell.pid),
       "a concurrent sibling cell's marker is untouched",
       f"reaped={reaped} sibling={other_cell.pid}")
    ok(unmarked.pid not in reaped and _alive(unmarked.pid),
       "an unmarked process is untouched",
       f"reaped={reaped} unmarked={unmarked.pid}")
    ok(pt.kill_marked(pt.new_marker(), grace=0.2) == [],
       "an unused marker reaps nothing")
    ok(pt.kill_marked("", grace=0.2) == [], "an empty marker is a no-op")
finally:
    _cleanup(victim, other_cell, unmarked)

# ── the escaped-leak shape: new session + reparented to PID 1 ─────────
print("\nescaped leak (new session, reparented)")
escaped = pt.new_marker()
with tempfile.TemporaryDirectory(prefix="process-tree-") as tmp:
    pidfile = Path(tmp) / "grandchild.pid"
    # Parent spawns a grandchild in its OWN session, writes its pid, and exits:
    # the grandchild reparents to PID 1 and leaves the parent's session group —
    # exactly what a session-group kill misses. It inherits the marker.
    launcher = subprocess.run(
        [
            sys.executable, "-c",
            "import subprocess,sys;"
            "p=subprocess.Popen([sys.executable,'-c','import time;time.sleep(120)'],"
            "start_new_session=True);"
            "open(sys.argv[1],'w').write(str(p.pid))",
            str(pidfile),
        ],
        env=_marked_env(escaped), check=False,
    )
    gpid = -1
    try:
        ok(launcher.returncode == 0, "launcher exited, orphaning the grandchild")
        for _ in range(60):
            if pidfile.is_file() and pidfile.read_text().strip():
                gpid = int(pidfile.read_text().strip())
                break
            time.sleep(0.05)
        ok(gpid > 0 and _alive(gpid), "escaped grandchild is running", f"pid={gpid}")
        reaped = pt.kill_marked(escaped, grace=1.0)
        ok(gpid in reaped,
           "grandchild in a new session, reparented to PID 1, is reaped",
           f"reaped={reaped} grandchild={gpid}")
        ok(_wait_dead(gpid), "escaped grandchild is dead")
    finally:
        _cleanup(gpid)

# ── inheritance: an unwitting child is still owned ───────────────────
print("\ninheritance")
inherit = pt.new_marker()
parent = _spawn_marked(inherit)
try:
    # Child inherits the marker through the environment without naming it.
    child = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(120)"],
        env=_marked_env(inherit),
    )
    try:
        time.sleep(0.3)
        reaped = pt.kill_marked(inherit, grace=1.0)
        ok(parent.pid in reaped and child.pid in reaped,
           "every process inheriting the marker is reaped",
           f"reaped={reaped} parent={parent.pid} child={child.pid}")
        ok(_signalled(parent) and _signalled(child), "both are dead")
    finally:
        _cleanup(child)
finally:
    _cleanup(parent)

# ── fail-safe: never reap our own tree ───────────────────────────────
print("\nfail-safe")
selfmark = pt.new_marker()
# A caller that wrongly exported the marker into its OWN environment must reap
# nothing rather than kill the run. Run it out-of-process so the marker really
# is in that interpreter's environ.
helper = (
    "import os,sys,subprocess,time;"
    "sys.path.insert(0, sys.argv[2]);"
    "import process_tree as pt;"
    "p=subprocess.Popen([sys.executable,'-c','import time;time.sleep(20)'],env=os.environ.copy());"
    "time.sleep(0.3);"
    "r=pt.kill_marked(sys.argv[1], grace=0.5);"
    "print('%s|%s' % (r, p.pid));"
    "p.kill()"
)
completed = subprocess.run(
    [sys.executable, "-c", helper, selfmark, str(ROOT / "lib")],
    env=_marked_env(selfmark), capture_output=True, text=True, check=False,
)
ok(completed.returncode == 0 and completed.stdout.startswith("[]|"),
   "a caller carrying the marker itself reaps nothing (fails safe)",
   f"rc={completed.returncode} out={completed.stdout.strip()!r} err={completed.stderr.strip()!r}")


print()
if FAILED:
    print(f"\033[0;31m{FAILED} failed, {PASSED} passed\033[0m")
    sys.exit(1)
print(f"\033[0;32m{PASSED}/{PASSED} passed\033[0m")
