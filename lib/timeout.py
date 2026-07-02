#!/usr/bin/env python3
"""Portable timeout runner backing lib/timeout.sh.

Invoked as: timeout.py <secs> <TERM|KILL> <rss_mb> <cmd...>

Intentionally does not depend on GNU coreutils `timeout`, which is absent
on stock macOS.

Exit codes: the command's own status (128+sig if signaled), 124 on
wall-clock timeout, 137 on an RSS-cap kill, and 129/130/143 when the
wrapper itself is HUP/INT/TERM'd.
"""

import os
import signal
import subprocess
import sys
import time


def _die(msg):
    print(msg, file=sys.stderr)
    sys.exit(255)


def _ps_rows(fields, ncols):
    """Rows of `ps -axo <fields>` as int tuples; empty list if ps fails."""
    try:
        out = subprocess.run(
            ["ps", "-axo", fields], capture_output=True, text=True
        ).stdout
    except OSError:
        return []
    rows = []
    for line in out.splitlines():
        parts = line.split()
        if len(parts) == ncols and all(p.isdigit() for p in parts):
            rows.append(tuple(int(p) for p in parts))
    return rows


def _descendants(root):
    children = {}
    for pid, ppid in _ps_rows("pid=,ppid=", 2):
        children.setdefault(ppid, []).append(pid)
    out = []
    stack = [root]
    while stack:
        cur = stack.pop()
        for child in children.get(cur, []):
            out.append(child)
            stack.append(child)
    return out


def _tree_rss_kb(root):
    """Summed RSS (KB) of the child and every descendant. One ps call,
    parsed the same way as _descendants (pid/ppid) plus the rss column. ps
    reports rss in KB on macOS and Linux. Only used on the RSS-watch path."""
    children = {}
    rss = {}
    for pid, ppid, r in _ps_rows("pid=,ppid=,rss=", 3):
        children.setdefault(ppid, []).append(pid)
        rss[pid] = r
    total = rss.get(root, 0)
    seen = set()
    stack = [root]
    while stack:
        cur = stack.pop()
        for c in children.get(cur, []):
            if c in seen:
                continue
            seen.add(c)
            total += rss.get(c, 0)
            stack.append(c)
    return total


def main():
    argv = sys.argv[1:]
    if len(argv) < 3:
        _die("missing timeout seconds")
    secs, mode, rss_mb = argv[0], argv[1], argv[2]
    cmd = argv[3:]
    if not (secs.isdigit() and int(secs) > 0):
        _die("missing timeout seconds")
    secs = int(secs)
    rss_mb = int(rss_mb) if rss_mb.isdigit() else 0
    if not cmd:
        _die("missing command")

    pid = os.fork()
    if pid == 0:
        # setsid (not setpgrp) so the child has no controlling terminal.
        # setpgrp alone moves the child to a background pgrp while leaving
        # the inherited tty attached — any tty touch from a background pgrp
        # triggers SIGTTIN/SIGTTOU, which silently STOPS the process and
        # leaves waitpid blocked until the wall-clock alarm fires. That is
        # exactly how `claude auth status` froze a 7200s harness cell.
        # A fresh session has no controlling tty, so the stop class cannot
        # fire, and pgid == pid keeps the existing group-kill logic intact.
        try:
            os.setsid()
        except OSError:
            pass
        try:
            os.execvp(cmd[0], cmd)
        except OSError as exc:
            print("exec: %s" % exc, file=sys.stderr)
            os._exit(127)

    def kill_group(sig):
        for target in [pid] + _descendants(pid):
            for send in (os.killpg, os.kill):
                try:
                    send(target, sig)
                except (OSError, ProcessLookupError):
                    pass

    def reap_blocking():
        try:
            os.waitpid(pid, 0)
        except ChildProcessError:
            pass

    def escalate_and_exit(code):
        if mode == "KILL":
            kill_group(signal.SIGKILL)
        else:
            kill_group(signal.SIGTERM)
            time.sleep(1)
            kill_group(signal.SIGKILL)
        reap_blocking()
        os._exit(code)

    exit_for_signal = {
        signal.SIGHUP: 129,
        signal.SIGINT: 130,
        signal.SIGTERM: 143,
    }

    def on_forwarded(signum, _frame):
        kill_group(signal.SIGTERM)
        time.sleep(1)
        kill_group(signal.SIGKILL)
        reap_blocking()
        os._exit(exit_for_signal[signum])

    for sig in exit_for_signal:
        signal.signal(sig, on_forwarded)

    signal.signal(signal.SIGALRM, lambda *_: escalate_and_exit(124))

    if rss_mb > 0:
        # RSS-watch path: poll instead of a single blocking wait so we can
        # check the process-tree resident memory between waitpid sweeps. The
        # wall-clock timeout is enforced here too (not via SIGALRM) so both
        # ceilings share one loop and one kill path. A fast allocator can
        # overshoot the cap by up to one tick before the kill lands; the tick
        # is short and the cap is set well under host RAM, so the host is
        # protected either way.
        limit_kb = rss_mb * 1024
        deadline = time.time() + secs
        while True:
            try:
                w, status = os.waitpid(pid, os.WNOHANG)
            except ChildProcessError:  # already reaped
                status = 0
                break
            if w == pid:
                break
            if time.time() >= deadline:
                escalate_and_exit(124)
            rss_kb = _tree_rss_kb(pid)
            if rss_kb > limit_kb:
                used_mb = rss_kb // 1024
                # Marker is matched by triage (is_autodiscard_crash_output)
                # and bin/severity detect_primitive — the OOM /
                # host-protection class, so the kill is recorded, never
                # promoted to a memory-safety bug.
                print(
                    "tokenfuzz: probe rss limit exceeded "
                    "(%dMb > %dMb) -- host-protection kill" % (used_mb, rss_mb),
                    file=sys.stderr,
                    flush=True,
                )
                kill_group(signal.SIGKILL)
                reap_blocking()
                os._exit(137)
            time.sleep(0.5)
    else:
        signal.alarm(secs)
        _, status = os.waitpid(pid, 0)
        signal.alarm(0)

    # KILL-mode callers (the fuzz runners) want orphaned descendants
    # reaped: a libFuzzer-driven browser leaves content processes that
    # outlive the parent and would otherwise leak. The child put itself
    # in its own session (setsid above), so this group-directed signal
    # hits exactly this run and never a sibling agent running the same
    # fuzzer. Harmless no-op when the group is already empty.
    if mode == "KILL":
        try:
            os.killpg(pid, signal.SIGKILL)
        except (OSError, ProcessLookupError):
            pass

    if os.WIFSIGNALED(status):
        sys.exit(128 + os.WTERMSIG(status))
    sys.exit(os.WEXITSTATUS(status))


if __name__ == "__main__":
    main()
