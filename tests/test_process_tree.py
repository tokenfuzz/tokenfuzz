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


def _children_of(pid: int) -> list[int]:
    """Direct children of ``pid`` from the process table."""
    listing = subprocess.check_output(["ps", "-ax", "-o", "pid=,ppid="], text=True)
    return [
        int(row.split()[0]) for row in listing.splitlines()
        if len(row.split()) == 2 and int(row.split()[1]) == pid
    ]


def _script_pids(script: Path) -> list[int]:
    """PIDs running ``script``, read from the process table rather than the
    marker. A supervisor the probe cannot attribute is invisible to
    _pids_with_token after the reap as well as before it, so asking the marker
    whether one survived would answer no however the reap went."""
    listing = subprocess.check_output(["ps", "-ax", "-o", "pid=,command="], text=True)
    return [int(row.split()[0]) for row in listing.splitlines() if str(script) in row]


# ── reap + isolation ──────────────────────────────────────────────────
print("reap / isolation")
cell = pt.new_marker()
sibling = pt.new_marker()

ok(cell != sibling and len(cell) >= 16, "new_marker returns distinct opaque ids")

victim = _spawn_marked(cell)
other_cell = _spawn_marked(sibling)
unmarked = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(120)"])
marker_text = f"{pt.REAP_MARKER_VAR}={cell}"
argv_lookalike = subprocess.Popen(
    [sys.executable, "-c", "import time; time.sleep(120)", marker_text]
)
value_lookalike = subprocess.Popen(
    [sys.executable, "-c", "import time; time.sleep(120)"],
    env=dict(os.environ, OTHER_REAP_VALUE=marker_text),
)
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
    ok(argv_lookalike.pid not in reaped and _alive(argv_lookalike.pid),
       "marker-looking argv text is not mistaken for ownership",
       f"reaped={reaped} argv_lookalike={argv_lookalike.pid}")
    ok(value_lookalike.pid not in reaped and _alive(value_lookalike.pid),
       "marker text inside another environment value is untouched",
       f"reaped={reaped} value_lookalike={value_lookalike.pid}")
    ok(pt.kill_marked(pt.new_marker(), grace=0.2) == [],
       "an unused marker reaps nothing")
    ok(pt.kill_marked("", grace=0.2) == [], "an empty marker is a no-op")
finally:
    _cleanup(victim, other_cell, unmarked, argv_lookalike, value_lookalike)

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


# ── opaque supervisor: marker unreadable, parent link readable ───────
print("\nopaque supervisor")
# macOS refuses to disclose a platform binary's environment to a non-root
# caller, so a leaked `/bin/sh` supervisor is invisible to the environment
# probe while the driver it respawns is not. One pass then killed the child
# and left the supervisor to spawn another: the shape that outlived a real
# benchmark cell and wrote over the scratch tree the runner was reclaiming.
#
# The supervisors here are launched without the marker rather than waiting for
# a host to hide an inherited one. The probe reads an environment and finds no
# marker either way, so the reaper gets the same input — but by construction,
# on every host, instead of only where the platform happens to refuse.
opaque = pt.new_marker()
with tempfile.TemporaryDirectory() as tmp:
    supervisor = Path(tmp) / "respawn.sh"
    supervisor.write_text("while true; do sleep 60 & wait $!; done\n")
    launcher = Path(tmp) / "launch.py"
    launcher.write_text(
        "import os, subprocess, sys, time\n"
        f"env = {{k: v for k, v in os.environ.items() if k != {pt.REAP_MARKER_VAR!r}}}\n"
        "[subprocess.Popen(['/bin/sh', sys.argv[1]], env=env) for _ in range(2)]\n"
        "time.sleep(120)\n"
    )
    parent = subprocess.Popen(
        [sys.executable, str(launcher), str(supervisor)],
        env=_marked_env(opaque),
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    time.sleep(2.0)
    token = f"{pt.REAP_MARKER_VAR}={opaque}"
    env_only = pt._pids_with_token_env(token)
    closed = pt._pids_with_token(token)
    ok(len(closed) > len(env_only),
       "parent closure recovers descendants the environment probe cannot read",
       f"env_only={env_only} closed={closed}")
    try:
        reaped = pt.kill_marked(opaque, grace=0.5)
        time.sleep(0.5)
        # The launcher names the script on its own command line, and is marked,
        # so the token list already covers it.
        survivors = ([pid for pid in pt._pids_with_token(token) if pid != os.getpid()]
                     + [pid for pid in _script_pids(supervisor) if pid != parent.pid])
        ok(not survivors, "a respawning opaque supervisor is fully reaped",
           f"reaped={reaped} survivors={survivors}")
    finally:
        # A regressed reap leaves `while true` shells behind, and kill_marked
        # raises on a blind probe before the check above ever runs. Either way
        # they outlive this file and the suite running beside it, so take the
        # survivors the process table still shows rather than the pre-reap
        # closure, whose pids a respawn may already have recycled.
        _cleanup(parent, *(pid for pid in _script_pids(supervisor)
                           if pid != parent.pid))


# ── orphaned opaque supervisor: no readable marked relative above it ─
print("\norphaned opaque supervisor")
# The shape the previous fix did not reach, and the one a real cell hit: the
# launcher is gone, so the only marked process a probe can read is the driver
# at the BOTTOM. Its supervisor is a platform binary reparented to PID 1 —
# unreadable, with nothing marked above it — and it respawns the driver as
# fast as the reap kills it. Only the process group still ties the two
# together.
#
# As above, the supervisor simply never receives the marker; it exports one
# for each driver it spawns. That is the same input the platform's refusal
# produces, and it holds on every host.
orphaned = pt.new_marker()
with tempfile.TemporaryDirectory() as tmp:
    supervisor = Path(tmp) / "supervise.sh"
    supervisor.write_text(
        f"while true; do {pt.REAP_MARKER_VAR}={orphaned} "
        f"{sys.executable} -c 'import time; time.sleep(5)'; done\n"
    )
    subprocess.run(
        ["/bin/sh", "-c", f"nohup /bin/sh {supervisor} >/dev/null 2>&1 & exit 0"],
        start_new_session=True, check=False,
    )
    time.sleep(2.5)

    token = f"{pt.REAP_MARKER_VAR}={orphaned}"
    readable = pt._pids_with_token_env(token)
    widened = pt._pids_with_token(token)
    running = _script_pids(supervisor)
    ok(bool(running), "orphaned supervisor is running", f"pids={running}")
    ok(all(pid not in readable for pid in running),
       "the probe cannot attribute the supervisor, as the failure requires",
       f"readable={readable} supervisor={running}")
    ok(all(pid in widened for pid in running),
       "process-group widening claims a supervisor with no marked relative above it",
       f"readable={readable} widened={widened} supervisor={running}")
    try:
        reaped = pt.kill_marked(orphaned, grace=0.5)
        raised = ""
    except pt.ProcessLeakError as leak:  # pragma: no cover - the bug this fixes
        reaped, raised = [], str(leak)
    time.sleep(1.0)
    survivors = _script_pids(supervisor)
    ok(not raised and not survivors,
       "an orphaned opaque supervisor is reaped instead of respawning forever",
       f"reaped={reaped} raised={raised!r} survivors={survivors}")
    for pid in survivors:
        try:
            os.kill(pid, 9)
        except OSError:
            pass


# ── opaque supervisor whose driver left the group ────────────────────
print("\nopaque supervisor above a driver in its own group")
# The shape that stopped a real benchmark run. The supervisor is opaque, and
# the driver it respawns runs under `timeout`, which puts its child in a FRESH
# process group — so the group link the previous case relied on is severed and
# the only thing left tying the two together is the parent link upward.
#
# Opacity is constructed rather than waited for: the supervisor execs with an
# empty environment, which reads back exactly like the environment macOS
# withholds for a platform binary — present, and empty — on every host.
severed = pt.new_marker()
with tempfile.TemporaryDirectory() as tmp:
    supervisor = Path(tmp) / "supervise-newgroup.sh"
    supervisor.write_text(
        f"while true; do {pt.REAP_MARKER_VAR}={severed} "
        f"{sys.executable} -c 'import os, time; os.setpgrp(); time.sleep(5)'; done\n"
    )
    parent_proc = subprocess.Popen(
        ["/bin/sh", str(supervisor)], env={},
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    time.sleep(2.0)
    token = f"{pt.REAP_MARKER_VAR}={severed}"
    readable = pt._pids_with_token_env(token)
    _, groups = pt._process_table()
    ok(parent_proc.pid not in readable,
       "the probe cannot attribute the supervisor, as the failure requires",
       f"readable={readable} supervisor={parent_proc.pid}")
    ok(all(groups.get(pid) != groups.get(parent_proc.pid) for pid in readable),
       "the driver holds a process group of its own, as `timeout` gives it",
       f"driver groups={[groups.get(pid) for pid in readable]} "
       f"supervisor group={groups.get(parent_proc.pid)}")
    ok(parent_proc.pid in pt._pids_with_token(token),
       "parent widening claims a supervisor no group or child link reaches")
    try:
        reaped = pt.kill_marked(severed, grace=0.5)
        raised = ""
    except pt.ProcessLeakError as leak:  # pragma: no cover - the bug this fixes
        reaped, raised = [], str(leak)
    time.sleep(1.0)
    survivors = _script_pids(supervisor)
    ok(not raised and not survivors,
       "the supervisor is reaped instead of outrunning the reap",
       f"reaped={reaped} raised={raised!r} survivors={survivors}")
    _cleanup(parent_proc, *survivors)


# ── quiescent campaign: nothing marked is alive when the probe looks ──
print("\nquiescent campaign")
# The marker names a process only while one carrying it is alive. A campaign
# supervisor spends most of its life asleep between the children that carry
# it, so a reap can scan every round and see nothing: the cell above reported
# a clean reap while three supervisor fleets slept through it and went on
# fuzzing for hours. The cell's own directory is the second claim, and it is
# readable whatever the platform will say about environments.
quiet = pt.new_marker()
with tempfile.TemporaryDirectory() as tmp:
    cell = Path(tmp) / "cell"
    cell.mkdir()
    campaign = cell / "campaign.sh"
    campaign.write_text(
        f"while true; do {sys.executable} -c 'import time; time.sleep(30)'; done\n"
    )
    subprocess.Popen(
        ["/bin/sh", str(campaign)], env={},
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    time.sleep(1.5)
    token = f"{pt.REAP_MARKER_VAR}={quiet}"
    ok(pt._pids_with_token(token) == [],
       "no marked process is alive to find, as the failure requires",
       f"claimed={pt._pids_with_token(token)}")
    ok(bool(_script_pids(campaign)), "the campaign is running",
       f"pids={_script_pids(campaign)}")
    try:
        reaped = pt.kill_marked(quiet, grace=0.5, owner_dir=str(cell))
        raised = ""
    except pt.ProcessLeakError as leak:  # pragma: no cover - the bug this fixes
        reaped, raised = [], str(leak)
    time.sleep(0.5)
    survivors = _script_pids(campaign)
    ok(not raised and not survivors,
       "a campaign running from the cell's own directory is reaped anyway",
       f"reaped={reaped} raised={raised!r} survivors={survivors}")
    _cleanup(*survivors)

    # The claim is what a process runs from the directory, not any process
    # that names it: an operator reading a file under the cell is not cell
    # work, and `ps` gives one joined string rather than real argument bounds.
    onlooker = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(30)", f"{cell}/notes"],
    )
    time.sleep(0.5)
    ok(onlooker.pid not in pt._pids_with_token(token, str(cell)),
       "naming the directory inside an argument does not claim a process",
       f"claimed={pt._pids_with_token(token, str(cell))} onlooker={onlooker.pid}")
    _cleanup(onlooker)

    # An operator reading a cell file from a shell whose environment the host
    # withholds: the reader is not cell work, and neither the shell above it
    # nor the unrelated job beside it may be claimed through it.
    pipe = cell / "pipe"
    os.mkfifo(pipe)
    tab = subprocess.Popen(
        ["/bin/sh", "-c", f"sleep 60 & /bin/cat {pipe}; wait"], env={},
        start_new_session=True,
    )
    time.sleep(1.0)
    tab_children = _children_of(tab.pid)
    claimed = set(pt._pids_with_token(token, str(cell)))
    ok(tab_children and not ({tab.pid} | set(tab_children)) & claimed,
       "an operator's reader under an opaque shell claims nothing",
       f"claimed={sorted(claimed)} tab={tab.pid} children={tab_children}")
    _cleanup(tab, *tab_children)


# ── safety: a cell left in our own group never widens onto the runner ─
print("\nown-group safety")
# A cell that was never put in a session of its own shares the runner's
# process group. Widening by group would then sweep in the runner and every
# unrelated sibling, so the claim must stay exactly what the marker proved.
same_group = pt.new_marker()
marked = subprocess.Popen(
    [sys.executable, "-c", "import time; time.sleep(60)"], env=_marked_env(same_group),
)
unmarked = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
time.sleep(1.0)
claimed = pt._pids_with_token(f"{pt.REAP_MARKER_VAR}={same_group}")
ok(claimed == [marked.pid],
   "a marked process in our own group claims only itself",
   f"claimed={claimed} marked={marked.pid} unmarked={unmarked.pid} self={os.getpid()}")
_cleanup(marked, unmarked)


# ── blind probe is reported, never read as "nothing leaked" ──────────
print("\nblind probe")
# Every probe path degrades to an empty list when the platform refuses it, and
# "nothing to reap" then means the same as "cannot tell". Force the blind case
# and require it to raise rather than return clean.
blind_helper = (
    "import sys;"
    "sys.path.insert(0, sys.argv[1]);"
    "import process_tree as pt;"
    "pt._pids_with_token_env = lambda token: [];"
    "pt._EXEC_ENVIRON = {'PATH': '/definitely/not/this/process'};"
    "\ntry:\n"
    "    pt.kill_marked('some-marker', grace=0.1)\n"
    "    print('RETURNED')\n"
    "except pt.ProcessLeakError:\n"
    "    print('RAISED')\n"
)
completed = subprocess.run(
    [sys.executable, "-c", blind_helper, str(ROOT / "lib")],
    capture_output=True, text=True, check=False,
)
ok(completed.stdout.strip() == "RAISED",
   "a probe that cannot see this process refuses to report a clean reap",
   f"out={completed.stdout.strip()!r} err={completed.stderr.strip()[-200:]!r}")

# A working probe with genuinely nothing marked still returns clean.
ok(pt.kill_marked(pt.new_marker(), grace=0.1) == [],
   "an unused marker on a working probe reaps nothing without raising")


print()
if FAILED:
    print(f"\033[0;31m{FAILED} failed, {PASSED} passed\033[0m")
    sys.exit(1)
print(f"\033[0;32m{PASSED}/{PASSED} passed\033[0m")
