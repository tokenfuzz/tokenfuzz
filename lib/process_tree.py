#!/usr/bin/env python3
"""Small process-tree helpers for backend orchestrators."""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import time
import uuid


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


# Ownership marker for reaping work that outlived its launcher. The launcher
# puts REAP_MARKER_VAR=<unique id> in the child's environment only (never its
# own), and every descendant inherits it — through `nohup`, a trailing `&`,
# setsid, and reparenting to PID 1, none of which clear the environment. That
# makes the marker positive proof of ownership, unlike a command-line path
# match, which both misses a leak invoked with relative arguments and can hit an
# unrelated process that merely names the same path.
REAP_MARKER_VAR = "TOKENFUZZ_REAP_ID"


def new_marker() -> str:
    """A fresh reap id. Unique per launch, so one unit of work never reaps a
    concurrent sibling's processes."""
    return uuid.uuid4().hex


def _ps_commands(include_environment: bool) -> dict[int, str]:
    args = ["ps", "-axww", "-o", "pid=,command="]
    if include_environment:
        args[1] = "-axEww"
    try:
        output = subprocess.check_output(
            args, text=True, errors="replace",
        )
    except (OSError, subprocess.SubprocessError):
        return {}
    commands: dict[int, str] = {}
    for line in output.splitlines():
        pid_text, separator, command = line.strip().partition(" ")
        if separator and pid_text.isdigit():
            commands[int(pid_text)] = command.lstrip()
    return commands


def _pids_with_token(token: str) -> list[int]:
    """PIDs whose environment contains ``token``.

    Linux reads /proc/<pid>/environ directly; elsewhere ``ps -E`` prints each
    environment after the command (``-ww`` keeps it untruncated). A separate
    argv-only snapshot identifies that boundary: without it, marker-looking
    text in an unrelated process's arguments is indistinguishable from an
    environment entry. Both expose only processes this uid may inspect, so the
    search is same-uid by construction. The result is then widened over process
    groups and parent links, which recovers the processes those probes are not
    permitted to read.
    """
    return _widen_ownership(_pids_with_token_env(token))


def _process_table() -> tuple[dict[int, int], dict[int, int]]:
    """(parent, process-group) by pid, or empty when ps cannot be read."""
    try:
        output = subprocess.check_output(
            ["ps", "-ax", "-o", "pid=,ppid=,pgid="], text=True,
        )
    except (OSError, subprocess.SubprocessError):
        return {}, {}
    parent: dict[int, int] = {}
    group: dict[int, int] = {}
    for line in output.splitlines():
        parts = line.split()
        if len(parts) != 3 or not all(part.lstrip("-").isdigit() for part in parts):
            continue
        pid, ppid, pgid = (int(part) for part in parts)
        parent[pid] = ppid
        group[pid] = pgid
    return parent, group


def _widen_ownership(pids: list[int]) -> list[int]:
    """Claim the processes the environment probe is not allowed to read.

    The marker is inherited by every descendant, so reading it is normally
    enough. It is not always readable: macOS refuses to disclose a platform
    binary's arguments and environment to a non-root caller, so a leaked
    `/bin/sh` supervisor is invisible while the driver it respawns is not. One
    real cell reaped that driver five times over while the supervisor calmly
    replaced it.

    Two links the kernel does expose recover it, applied together to a fixed
    point because each can reveal work the other then widens:

    * process group — inherited exactly like the marker, unaffected by the
      launcher exiting, and it outlives its own leader. This is what finds an
      opaque supervisor with no visible relative above it.
    * parent — finds an opaque child of a visible marked process, the case a
      group cannot cover once something has called setsid.

    Neither reaches a process that is opaque, reparented, *and* alone in a new
    group. Nothing readable ties such a process to this run, which is why
    kill_marked reports rather than assumes when the marker will not clear.
    """
    if not pids:
        return pids
    parent, group = _process_table()
    if not parent:
        return pids
    members: dict[int, list[int]] = {}
    children: dict[int, list[int]] = {}
    for pid, pgid in group.items():
        members.setdefault(pgid, []).append(pid)
    for pid, ppid in parent.items():
        children.setdefault(ppid, []).append(pid)

    # Never widen onto ourselves. A directly marked ancestor is still reaped —
    # that is the caller's declared ownership — but inferring one from a group
    # or parent link would take down the caller mid-reap. Our own group is
    # excluded wholesale: when a cell was never put in a session of its own,
    # widening by group would sweep the runner in with it.
    protected = {0, 1, os.getpid()}
    walker = parent.get(os.getpid(), 0)
    while walker > 1 and walker not in protected:
        protected.add(walker)
        walker = parent.get(walker, 0)
    own_groups = {group.get(pid, 0) for pid in protected} | {0, 1}

    claimed = {pid for pid in pids if pid not in protected}
    while True:
        widened = set(claimed)
        for pid in claimed:
            pgid = group.get(pid, 0)
            if pgid not in own_groups:
                widened.update(members.get(pgid, ()))
            widened.update(children.get(pid, ()))
        widened -= protected
        if widened == claimed:
            return sorted(claimed)
        claimed = widened


def _pids_with_token_env(token: str) -> list[int]:
    pids: list[int] = []
    if os.path.isdir("/proc"):
        raw = token.encode()
        try:
            entries = os.listdir("/proc")
        except OSError:
            return []
        for entry in entries:
            if not entry.isdigit():
                continue
            try:
                with open(f"/proc/{entry}/environ", "rb") as stream:
                    if raw in stream.read().split(b"\0"):
                        pids.append(int(entry))
            except (OSError, ValueError):
                continue
        return pids

    if sys.platform == "darwin":
        import ctypes
        raw = token.encode()
        try:
            output = subprocess.check_output(["ps", "-ax", "-o", "pid="], text=True)
        except (OSError, subprocess.SubprocessError):
            return []
        CTL_KERN, KERN_PROCARGS2 = 1, 49
        libc = ctypes.CDLL(None)
        for line in output.splitlines():
            pid_text = line.strip()
            if not pid_text.isdigit():
                continue
            pid = int(pid_text)
            mib = (ctypes.c_int * 3)(CTL_KERN, KERN_PROCARGS2, pid)
            size = ctypes.c_size_t(0)
            if libc.sysctl(mib, 3, None, ctypes.byref(size), None, 0) != 0:
                continue
            buf = ctypes.create_string_buffer(size.value)
            if libc.sysctl(mib, 3, buf, ctypes.byref(size), None, 0) != 0:
                continue
            data = buf.raw
            if len(data) < 4:
                continue
            argc = int.from_bytes(data[:4], sys.byteorder)
            idx = 4
            while idx < len(data) and data[idx] != 0:
                idx += 1
            while idx < len(data) and data[idx] == 0:
                idx += 1
            strings = data[idx:].split(b"\0")
            env_strings = strings[argc:]
            if raw in env_strings:
                pids.append(pid)
        return pids

    # Environment snapshot first: a pid it holds that the later argv snapshot
    # has lost merely exited, whereas taking argv first drops any process born
    # between the two calls — the still-spawning leak this exists to catch.
    environment_commands = _ps_commands(include_environment=True)
    plain_commands = _ps_commands(include_environment=False)
    for pid, command_and_environment in environment_commands.items():
        command = plain_commands.get(pid)
        if command is None:
            continue
        prefix = f"{command} "
        if not command_and_environment.startswith(prefix):
            continue
        environment = command_and_environment[len(prefix):]
        if token in environment.split():
            pids.append(pid)
    return pids


# Enough rounds to outlast a supervisor that respawns one replacement per
# kill, few enough that a genuinely unkillable tree is reported rather than
# spun on. Each round costs one process-table scan plus `grace`.
_REAP_ROUNDS = 5


class ProcessLeakError(RuntimeError):
    """A reap marker stayed live, or could not be observed at all."""


# Snapshotted before anything in-process can mutate it, so _probe_blind asks
# about a variable the kernel actually recorded for this pid.
_EXEC_ENVIRON = dict(os.environ)


def _probe_blind() -> bool:
    """Whether the marker probe cannot observe process environments here.

    Every probe path degrades to an empty list when the platform refuses it —
    a sandbox that denies `sysctl`, a hardened `ps` that drops `-E`, a
    container with no readable `/proc`. An empty result then means "nothing to
    reap" and "cannot tell", which are opposite answers, and the caller
    reported the second as the first. Ask the one question whose answer is
    known: a probe that cannot find this very process cannot find anything.

    The variable must come from the exec-time environment. What these probes
    read is the copy the kernel took at exec, so a token assigned into
    ``os.environ`` afterwards is invisible to them and every host would look
    blind.
    """
    for name in ("PATH", "HOME", "TMPDIR"):
        value = _EXEC_ENVIRON.get(name)
        if value:
            return os.getpid() not in _pids_with_token_env(f"{name}={value}")
    return False


def kill_marked(marker: str, grace: float = 1.0) -> list[int]:
    """TERM then KILL every process carrying ``marker`` in its environment.

    This is how a launcher reaps work that escaped its process group: the
    marker is inherited by every descendant, so a fuzzer that survived via
    setsid or reparenting is still identified, while an unrelated process can
    never carry another launch's random id. Returns the reaped PIDs, ascending.

    Refuses to act if this process itself carries the marker — that would mean
    reaping our own tree — so a caller that wrongly exported it into its own
    environment fails safe instead of killing the run.

    Sweeps until the marker is clear. One pass only kills the processes alive
    when it took its snapshot, so a restart loop whose child is killed spawns a
    replacement the pass never sees: a model-direct cell reaped 31 processes
    and still had campaigns writing files ten minutes later, into a scratch
    tree the runner was deleting under them. Rounds are bounded, and a marker
    that will not clear is raised rather than reported as reaped.
    """
    if not marker or os.environ.get(REAP_MARKER_VAR) == marker:
        return []
    reaped: set[int] = set()
    for _ in range(_REAP_ROUNDS):
        pids = sorted(
            pid for pid in _pids_with_token(f"{REAP_MARKER_VAR}={marker}")
            if pid != os.getpid()
        )
        if not pids:
            if not reaped and _probe_blind():
                raise ProcessLeakError(
                    "cannot read process environments on this host, so a "
                    "leaked cell process is undetectable; reaping nothing is "
                    "not evidence that nothing leaked"
                )
            return sorted(reaped)
        reaped.update(pids)
        _kill(pids, signal.SIGTERM)
        deadline = time.monotonic() + grace
        while grace > 0 and time.monotonic() < deadline:
            if not any(_alive(pid) for pid in pids):
                break
            time.sleep(0.05)
        _kill([pid for pid in pids if _alive(pid)], signal.SIGKILL)
    if [pid for pid in _pids_with_token(f"{REAP_MARKER_VAR}={marker}")
            if pid != os.getpid()]:
        raise ProcessLeakError(
            f"{len(reaped)} process(es) reaped over {_REAP_ROUNDS} rounds and "
            f"the reap marker is still live; something is respawning faster "
            f"than it can be killed"
        )
    return sorted(reaped)


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
