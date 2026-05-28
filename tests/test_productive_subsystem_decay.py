#!/usr/bin/env python3
"""tests/test_productive_subsystem_decay.py — productive-subsystem decay.

The bug-cluster relaxation in ``_claim_next_card_locked`` lets an agent
keep picking neighbouring cards within a subsystem after they already
filed a CRASH/FIND there. Without a decay condition the relaxation
keeps the agent re-investigating an already-closed bug every iteration
even after the subsystem stops producing new artifacts.

This file pins the decay contract: once the global per-subsystem dry
counter (written by ``bin/audit``'s ``bump_subsystem_dry_streak``)
reaches ``_PRODUCTIVE_DECAY_AFTER_ITERS`` (a module constant), the
subsystem drops out of the productive-relaxation set and the diversity
gate re-applies normally.
"""
from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "lib"))
import workqueue  # noqa: E402

_PASSED = 0
_FAILED = 0
_GREEN = "\033[0;32m"
_RED = "\033[0;31m"
_NC = "\033[0m"


def passed(name: str) -> None:
    global _PASSED
    _PASSED += 1
    print(f"  {_GREEN}✓{_NC} {name}")


def failed(name: str, detail: str = "") -> None:
    global _FAILED
    _FAILED += 1
    print(f"  {_RED}✗{_NC} {name}")
    if detail:
        print(f"    {detail}")


def assert_eq(expected, actual, name: str) -> None:
    if expected == actual:
        passed(name)
    else:
        failed(name, f"expected={expected!r} actual={actual!r}")


def assert_in(needle, haystack, name: str) -> None:
    if needle in haystack:
        passed(name)
    else:
        failed(name, f"missing={needle!r} in={haystack!r}")


def assert_not_in(needle, haystack, name: str) -> None:
    if needle not in haystack:
        passed(name)
    else:
        failed(name, f"present={needle!r} in={haystack!r}")


def _ctx(results_dir: Path, target_root: Path) -> workqueue.Context:
    return workqueue.Context(
        script_root=ROOT,
        target_root=target_root,
        target_slug="prod-decay-test",
        results_dir=results_dir,
        repo_type="git",
    )


def _seed_hypothesis(results_dir: Path, agent: str, subsystem: str, status: str) -> None:
    state_dir = results_dir / "state"
    state_dir.mkdir(parents=True, exist_ok=True)
    with (state_dir / "hypotheses.jsonl").open("a") as f:
        f.write(json.dumps({
            "id": f"H-{agent}-{subsystem}",
            "agent": agent,
            "subsystem": subsystem,
            "file": f"{subsystem}.c",
            "hypothesis": "demo",
            "strategy": "S7",
            "status": status,
            "created_at": "2026-01-01T00:00:00Z",
            "updated_at": "2026-01-01T00:00:00Z",
        }) + "\n")


def _set_dry_streak(results_dir: Path, subsystem: str, value: int) -> None:
    slug = subsystem.replace("/", "_")
    (results_dir / f".subsystem_dry_{slug}").write_text(str(value))


# subsystem_dry_streak helper — reads what bin/audit wrote.
with tempfile.TemporaryDirectory() as td:
    rdir = Path(td) / "results"
    rdir.mkdir()
    target = Path(td) / "target"
    target.mkdir()
    ctx = _ctx(rdir, target)
    workqueue.init_state(ctx)

    # Missing file → 0 (productive subsystem on the current iter).
    assert_eq(0, workqueue.subsystem_dry_streak(ctx, "src/parser.c"),
              "subsystem_dry_streak: missing file → 0")

    # Empty/unknown subsystem → 0 (skips the helper).
    assert_eq(0, workqueue.subsystem_dry_streak(ctx, ""),
              "subsystem_dry_streak: empty subsystem → 0")
    assert_eq(0, workqueue.subsystem_dry_streak(ctx, "unknown"),
              "subsystem_dry_streak: 'unknown' sentinel → 0")

    # File with an integer → that integer.
    _set_dry_streak(rdir, "src/parser.c", 3)
    assert_eq(3, workqueue.subsystem_dry_streak(ctx, "src/parser.c"),
              "subsystem_dry_streak: reads the integer back")

    # File with garbage → 0 (don't crash; treat as fresh).
    (rdir / ".subsystem_dry_corrupt").write_text("not-a-number")
    assert_eq(0, workqueue.subsystem_dry_streak(ctx, "corrupt"),
              "subsystem_dry_streak: non-integer payload → 0")

    # Negative → clamped to 0 (never negative).
    (rdir / ".subsystem_dry_neg").write_text("-5")
    assert_eq(0, workqueue.subsystem_dry_streak(ctx, "neg"),
              "subsystem_dry_streak: negative payload clamped to 0")

# Slash-bearing subsystems map to the same file layout bin/audit uses
# (slash → underscore). A mismatch here would silently make the helper
# return 0 forever.
with tempfile.TemporaryDirectory() as td:
    rdir = Path(td) / "results"
    rdir.mkdir()
    target = Path(td) / "target"
    target.mkdir()
    ctx = _ctx(rdir, target)
    workqueue.init_state(ctx)
    _set_dry_streak(rdir, "src/lib/parser.c", 4)
    assert_eq(4, workqueue.subsystem_dry_streak(ctx, "src/lib/parser.c"),
              "subsystem_dry_streak: nested path slug matches bin/audit's encoding")


# Productive subsystems: until the decay threshold is reached, the
# subsystem remains in the relaxation set even after the agent's
# hypothesis settled at CRASH/FIND. Beyond the threshold the subsystem
# drops out — the relaxation no longer protects further re-investigation.
def _decayed_productive_subsystems(
    rdir: Path, target: Path, agent: str,
) -> set[str]:
    """Apply the same decay filter _claim_next_card_locked applies."""
    ctx = _ctx(rdir, target)
    workqueue.init_state(ctx)
    base = workqueue.agent_productive_subsystems(ctx, agent)
    threshold = workqueue._PRODUCTIVE_DECAY_AFTER_ITERS
    return {s for s in base if workqueue.subsystem_dry_streak(ctx, s) < threshold}


# The threshold itself is a small positive integer — pinning the value
# catches accidental edits that turn the relaxation into a no-op (0)
# or stretch it out indefinitely (very large N).
assert_eq(2, workqueue._PRODUCTIVE_DECAY_AFTER_ITERS,
          "_PRODUCTIVE_DECAY_AFTER_ITERS: current value is 2")

with tempfile.TemporaryDirectory() as td:
    rdir = Path(td) / "results"
    rdir.mkdir()
    target = Path(td) / "target"
    target.mkdir()
    ctx = _ctx(rdir, target)
    workqueue.init_state(ctx)

    # Agent 1 has a confirmed CRASH at src/parser.c. The subsystem is
    # productive for this agent.
    _seed_hypothesis(rdir, agent="1", subsystem="src/parser.c", status="CRASH-001")
    base = workqueue.agent_productive_subsystems(ctx, "1")
    assert_in("src/parser.c", base,
              "agent_productive_subsystems: CRASH row makes subsystem productive")

    # Dry streak 0 → relaxation still applies (fresh productive subsystem).
    decayed0 = _decayed_productive_subsystems(rdir, target, "1")
    assert_in("src/parser.c", decayed0,
              "decay: streak=0 < threshold → subsystem stays productive")

    # Dry streak 1 (one dry iter) → still under threshold of 2.
    _set_dry_streak(rdir, "src/parser.c", 1)
    decayed1 = _decayed_productive_subsystems(rdir, target, "1")
    assert_in("src/parser.c", decayed1,
              "decay: streak=1 < threshold=2 → still productive")

    # Dry streak 2 (two dry iters) → reaches the threshold; subsystem
    # drops out so the diversity gate re-applies normally.
    _set_dry_streak(rdir, "src/parser.c", 2)
    decayed2 = _decayed_productive_subsystems(rdir, target, "1")
    assert_not_in("src/parser.c", decayed2,
                  "decay: streak=2 >= threshold=2 → subsystem decayed out")

    # A second productive subsystem with an independent (low) streak
    # remains in the set when the first one decays out. Decay is
    # per-subsystem, not all-or-nothing.
    _seed_hypothesis(rdir, agent="1", subsystem="src/codec.c", status="FIND-001")
    _set_dry_streak(rdir, "src/parser.c", 5)  # decayed out
    _set_dry_streak(rdir, "src/codec.c", 0)   # still fresh
    decayed_mixed = _decayed_productive_subsystems(rdir, target, "1")
    assert_not_in("src/parser.c", decayed_mixed,
                  "decay (mixed): stale subsystem dropped")
    assert_in("src/codec.c", decayed_mixed,
              "decay (mixed): fresh subsystem kept")


print()
print(f"  {_PASSED} passed, {_FAILED} failed")
sys.exit(0 if _FAILED == 0 else 1)
