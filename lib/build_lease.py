#!/usr/bin/env python3
"""Reader/writer lease over one target's audit-owned sanitizer build tree.

A build tree is read by every probe and sanitizer runner, and rewritten *in
place* by `materialize` — the recipe records absolute paths, so the tree cannot
be built elsewhere and moved in without losing debug objects. Two consumers
therefore need to keep a rebuild out: a runner for as long as it is executing,
and a whole audit or benchmark run for as long as its evidence must stay
replayable against the build that produced it. That is a reader/writer lock, so
this module is the one place that takes it:

  * ``shared()``    — a consumer: one runner process, or an entire run.
  * ``exclusive()`` — ``materialize``, while it is replacing the tree.

One lock file per build directory, so alternate configurations and suffixed
trees stay independent. The lock is advisory and kernel-held: it is released
when the holder dies, needs no cleanup, and binds only cooperating TokenFuzz
processes — an agent running cmake by hand is outside it.

Convergence deliberately happens *outside* an exclusive hold: `build_preflight`
reaches a build through `bin/setup-target`, a child process, which would block
forever against a lease its own parent held. A run therefore converges first and
takes its shared lease after, re-verifying build identity once it holds it.
"""

from __future__ import annotations

import contextlib
import fcntl
import os
import time
from pathlib import Path
from typing import Callable, Iterator

# A cold sanitizer build on a large target is minutes, not seconds. A consumer
# that waits this long has hit something pathological; it says so and falls open
# rather than abandoning the work it was asked to do.
LEASE_WAIT_SECONDS = 900
# How long a consumer defers to a writer that has announced itself but has not
# acquired yet. Short: it exists to stop a stream of readers from starving a
# rebuild, not to block real work.
PENDING_DEFER_SECONDS = 30
_POLL_SECONDS = 0.2

# flock is per open file description, so a second acquisition inside one process
# would block against itself. Nesting is legitimate (materialize called by a
# caller that already converged under the same lock), so track what we hold.
_HELD: dict[str, list] = {}
# Descriptors for leases held until process exit (see hold_shared).
_KEPT: list[int] = []
# Source pins written by this process (see pin_source). Kept so a run's own pin
# is identifiable, and removed by the OS only when the process is gone.
_KEPT_PINS: list[Path] = []


def lease_path(target_root: "str | os.PathLike", build_dir_name: str) -> Path:
    return Path(target_root) / ".audit" / "build-locks" / f"{build_dir_name}.lock"


def _pending_path(lock: Path) -> Path:
    # One marker per announcing process: a single shared file would have writers
    # overwriting each other's announcement and clearing each other's on the way
    # out, which is worse than no marker at all.
    return lock.with_name(f"{lock.name}.pending.{os.getpid()}")


def _announce_pending(lock: Path) -> None:
    try:
        _pending_path(lock).write_text(f"{os.getpid()}\n", encoding="utf-8")
    except OSError:
        pass  # advisory only; losing the hint costs fairness, not correctness


def _clear_pending(lock: Path) -> None:
    try:
        _pending_path(lock).unlink(missing_ok=True)
    except OSError:
        pass


def _pending_writer_alive(lock: Path) -> bool:
    """Whether another live process has announced a rebuild of this tree.

    A marker left behind by a killed writer must not defer everyone forever, so
    an unreadable or dead-pid marker is reaped rather than believed. Our own
    announcement is never a reason to defer to ourselves.
    """
    mine = _pending_path(lock)
    for marker in sorted(lock.parent.glob(f"{lock.name}.pending.*")):
        if marker == mine:
            continue
        try:
            owner = int(marker.read_text(encoding="utf-8").split()[0])
        except (OSError, ValueError, IndexError):
            marker.unlink(missing_ok=True)
            continue
        if owner == os.getpid():
            continue
        try:
            os.kill(owner, 0)
        except ProcessLookupError:
            marker.unlink(missing_ok=True)
            continue
        except PermissionError:
            return True
        return True
    return False


def _acquire(lock: Path, operation: int, deadline: float) -> "int | None":
    """Poll for the lock until the deadline. Returns an fd, or None on timeout."""
    lock.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(lock, os.O_RDWR | os.O_CREAT, 0o600)
    while True:
        try:
            fcntl.flock(fd, operation | fcntl.LOCK_NB)
            return fd
        except OSError:
            if time.monotonic() >= deadline:
                os.close(fd)
                return None
            time.sleep(_POLL_SECONDS)


@contextlib.contextmanager
def _lease(
    target_root: "str | os.PathLike",
    build_dir_name: str,
    operation: int,
    timeout: float,
    logger: "Callable[[str], None] | None",
) -> Iterator[bool]:
    lock = lease_path(target_root, build_dir_name)
    key = str(lock)
    held = _HELD.get(key)
    if held is not None and (held[1] == fcntl.LOCK_EX or operation == held[1]):
        held[0] += 1
        try:
            yield True
        finally:
            held[0] -= 1
            if held[0] <= 0:
                _HELD.pop(key, None)
        return

    writer = operation == fcntl.LOCK_EX
    deadline = time.monotonic() + timeout
    if writer:
        _announce_pending(lock)
    else:
        defer_until = min(deadline, time.monotonic() + PENDING_DEFER_SECONDS)
        while time.monotonic() < defer_until and _pending_writer_alive(lock):
            time.sleep(_POLL_SECONDS)

    started = time.monotonic()
    fd = _acquire(lock, operation, deadline)
    waited = time.monotonic() - started
    try:
        if fd is None:
            if logger:
                logger(
                    f"WARN: timed out after {int(waited)}s waiting for the "
                    f"{'exclusive' if writer else 'shared'} build lease on "
                    f"{build_dir_name}; continuing without it | lock={lock}"
                )
            yield False
            return
        if waited >= 1 and logger:
            logger(f"Waited {int(waited)}s for the build lease on {build_dir_name}")
        _HELD[key] = [1, operation]
        try:
            yield True
        finally:
            _HELD.pop(key, None)
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)
    finally:
        if writer:
            _clear_pending(lock)


def shared(
    target_root: "str | os.PathLike",
    build_dir_name: str,
    *,
    timeout: float = LEASE_WAIT_SECONDS,
    logger: "Callable[[str], None] | None" = None,
):
    """Hold a build tree against replacement for the body's duration."""
    return _lease(target_root, build_dir_name, fcntl.LOCK_SH, timeout, logger)


def exclusive(
    target_root: "str | os.PathLike",
    build_dir_name: str,
    *,
    timeout: float = LEASE_WAIT_SECONDS,
    logger: "Callable[[str], None] | None" = None,
):
    """Hold a build tree for replacement, excluding readers and other writers."""
    return _lease(target_root, build_dir_name, fcntl.LOCK_EX, timeout, logger)


def _pin_dir(target_root: "str | os.PathLike") -> Path:
    return Path(target_root) / ".audit" / "source-pins"


@contextlib.contextmanager
def _pin_registry(target_root: "str | os.PathLike") -> Iterator[Path]:
    """Serialize the whole scan-and-publish, so no one sees it half done."""
    directory = _pin_dir(target_root)
    directory.mkdir(parents=True, exist_ok=True)
    fd = os.open(directory / ".registry.lock", os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield directory
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def _disagreeing_pins(directory: Path, signature: str) -> list[str]:
    """Live pins recording a different source state than ours.

    Liveness is the lock, not the pid: a recycled pid would make a dead run's
    pin look live. Pins whose owner is gone are reaped rather than believed, so
    a killed run cannot block every later one.
    """
    conflicts: list[str] = []
    for pin in sorted(directory.glob("*.pin")):
        if pin in _KEPT_PINS:
            continue
        try:
            recorded = pin.read_text(encoding="utf-8").strip()
            fd = os.open(pin, os.O_RDWR)
        except OSError:
            continue
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            if recorded and recorded != signature:
                conflicts.append(pin.stem)
        else:
            fcntl.flock(fd, fcntl.LOCK_UN)
            pin.unlink(missing_ok=True)  # owner is gone
        finally:
            os.close(fd)
    return conflicts


def claim_source_pin(target_root: "str | os.PathLike", signature: str) -> list[str]:
    """Claim this checkout for a source state, or name the runs that disagree.

    A build lease covers one build directory; the hazard it cannot cover is the
    *checkout*, where two runs reading one working tree at different source
    states are incomparable no matter where their builds live. Claiming applies
    equally to an isolated build for that reason.

    Scanning and publishing are one operation under one lock. Split in two, both
    halves of a divergent pair could pass the scan before either became visible,
    and a pin published before it was locked could be reaped as dead by a
    concurrent scanner and vanish underneath its owner. Returns the disagreeing
    pins; on an empty list this process holds the claim for its lifetime.
    """
    if not signature:
        return []
    with _pin_registry(target_root) as directory:
        conflicts = _disagreeing_pins(directory, signature)
        if conflicts:
            return conflicts
        pin = directory / f"{os.getpid()}.pin"
        fd = os.open(pin, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
        except OSError:
            os.close(fd)
            return []
        os.ftruncate(fd, 0)
        os.write(fd, f"{signature}\n".encode())
        _KEPT.append(fd)
        _KEPT_PINS.append(pin)
    return []


def hold_shared(
    target_root: "str | os.PathLike",
    build_dir_name: str,
    *,
    timeout: float = LEASE_WAIT_SECONDS,
    logger: "Callable[[str], None] | None" = None,
) -> bool:
    """Hold a build tree for the rest of this process's life.

    A run must keep its build from being replaced from the moment it converges
    one until its last replay — the whole process. There is deliberately nothing
    to release: the kernel drops the lock when the process exits, so no crash
    path can leave a stale hold behind, and no code path can drop it early.

    A rebuild already under way is waited out rather than deferred to, so the
    lease lands on the build this run will actually use. A rebuild that has
    announced itself but not yet acquired is briefly deferred to: taking a
    whole-run lease ahead of it would trap that builder for the full timeout,
    which is exactly the stall two simultaneous stale-build preflights hit.
    """
    lock = lease_path(target_root, build_dir_name)
    key = str(lock)
    if key in _HELD:
        return True
    deadline = time.monotonic() + timeout
    defer_until = min(deadline, time.monotonic() + PENDING_DEFER_SECONDS)
    while time.monotonic() < defer_until and _pending_writer_alive(lock):
        time.sleep(_POLL_SECONDS)
    fd = _acquire(lock, fcntl.LOCK_SH, deadline)
    if fd is None:
        if logger:
            logger(
                f"WARN: could not take the build lease on {build_dir_name}; a "
                f"concurrent rebuild could replace it mid-run | lock={lock}"
            )
        return False
    _KEPT.append(fd)
    _HELD[key] = [1, fcntl.LOCK_SH]
    return True


def writer_pending(target_root: "str | os.PathLike", build_dir_name: str) -> bool:
    """Whether another live process has announced a rebuild of this tree.

    Distinguishes the two reasons the lease can be busy: a peer builder, whose
    result may be exactly the build we wanted and is therefore worth waiting
    for, from a live consumer, which must not be built underneath.
    """
    return _pending_writer_alive(lease_path(target_root, build_dir_name))


def consumers_active(target_root: "str | os.PathLike", build_dir_name: str) -> bool:
    """Whether another process is holding this build tree right now.

    Asked before replacing a tree: a rebuild underneath a live run swaps the
    binary its recorded evidence was measured against. Locks this process holds
    are not foreign, so its own converge-then-lease sequence is not blocked by
    itself.
    """
    lock = lease_path(target_root, build_dir_name)
    if str(lock) in _HELD:
        return False
    if not lock.exists():
        return False
    try:
        fd = os.open(lock, os.O_RDWR)
    except OSError:
        return False
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        return True
    else:
        fcntl.flock(fd, fcntl.LOCK_UN)
        return False
    finally:
        os.close(fd)
