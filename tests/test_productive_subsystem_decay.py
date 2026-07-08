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


def _write_jsonl(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w") as f:
        for row in rows:
            f.write(json.dumps(row) + "\n")


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


# A productive card may be claimed again while it is still being mined. If
# that later lease goes stale, cleanup must not replace the previous
# crash/find conclusion with "released"; otherwise card_closed_for_run reads
# a non-terminal status and the card looks freshly eligible forever, and the
# released row must not inflate the conclusion count that drives closure.
with tempfile.TemporaryDirectory() as td:
    rdir = Path(td) / "results"
    rdir.mkdir()
    target = Path(td) / "target"
    target.mkdir()
    ctx = _ctx(rdir, target)
    workqueue.init_state(ctx)
    _write_jsonl(rdir / "work-cards.jsonl", [{
        "id": "WORK-hot",
        "kind": "ranked-source",
        "file": "src/parser.c",
        "subsystem": "src/parser.c",
        "mode": "auto",
        "strategy": "S7",
        "status": "unclaimed",
    }])
    _write_jsonl(rdir / "state" / "claims.jsonl", [
        {
            "card_id": "WORK-hot",
            "agent": "1",
            "status": "crash",
            "updated_at": "2026-01-01T00:00:00Z",
        },
        {
            "card_id": "WORK-hot",
            "agent": "1",
            "status": "claimed",
            "claimed_at": "2026-01-01T00:01:00Z",
            "expires_at": "2026-01-01T00:31:00Z",
        },
    ])
    released = workqueue.release_stale_claims(
        ctx,
        grace=workqueue.timedelta(seconds=0),
        now=workqueue.datetime(2026, 1, 1, 1, 0, 0, tzinfo=workqueue.timezone.utc),
    )
    assert_eq(1, len(released),
              "release_stale_claims: stale post-crash lease is cleaned up")
    assert_eq("crash", released[0].get("status"),
              "release_stale_claims: preserves previous productive terminal status")
    latest = workqueue.latest_claims_by_card(ctx).get("WORK-hot", {})
    assert_eq("crash", latest.get("status"),
              "latest status remains crash after stale lease cleanup")
    assert_eq(1, workqueue.card_conclusion_counts(ctx).get("WORK-hot"),
              "preserved terminal cleanup row does not inflate conclusion count")


# Distinct-hypothesis closure (card_closed_for_run): a productive crash/find
# card stays claimable while it keeps yielding new distinct hypotheses, and
# retires once it has been re-concluded more times than it has distinct
# hypotheses (re-discovery of an already-recorded bug). This is the per-card
# signal that replaced subsystem-heat keep-alive.
def _hyp(card_id: str, shape: str, status: str = "CRASH-x") -> dict:
    return {
        "id": f"H-{card_id}-{shape}",
        "card_id": card_id,
        "agent": "1",
        "subsystem": "src/parser.c",
        "file": "src/parser.c",
        "hypothesis": shape,
        "strategy": "S7",
        "status": status,
        "created_at": "2026-01-01T00:00:00Z",
        "updated_at": "2026-01-01T00:00:00Z",
    }


def _crash_claim(card_id: str) -> dict:
    return {"card_id": card_id, "agent": "1", "status": "crash",
            "updated_at": "2026-01-01T00:00:00Z"}


# Concrete cards (recon-hypothesis) name a specific site: their opened
# hypotheses ARE their search space, so re-discovery is a valid exhaustion
# signal for them.
def _card(card_id: str, kind: str = "recon-hypothesis") -> dict:
    return {"id": card_id, "kind": kind, "file": "src/parser.c",
            "function": "foo", "subsystem": "src/parser.c", "mode": "auto",
            "strategy": "S7", "status": "unclaimed"}


assert_eq(1, workqueue._PRODUCTIVE_REDISCOVERY_MARGIN,
          "_PRODUCTIVE_REDISCOVERY_MARGIN: current value is 1")

# Concrete-card re-discovery closure.
with tempfile.TemporaryDirectory() as td:
    rdir = Path(td) / "results"
    rdir.mkdir()
    target = Path(td) / "target"
    target.mkdir()
    ctx = _ctx(rdir, target)
    workqueue.init_state(ctx)
    _write_jsonl(rdir / "work-cards.jsonl", [
        _card("WORK-single"), _card("WORK-rich"), _card("WORK-fresh"),
    ])
    _write_jsonl(rdir / "state" / "hypotheses.jsonl", [
        # single-bug surface: one distinct shape, concluded twice below.
        _hyp("WORK-single", "s1"),
        # rich surface: three distinct shapes.
        _hyp("WORK-rich", "r1"), _hyp("WORK-rich", "r2"), _hyp("WORK-rich", "r3"),
        # fresh surface: one distinct shape, concluded once.
        _hyp("WORK-fresh", "f1"),
    ])
    _write_jsonl(rdir / "state" / "claims.jsonl", [
        _crash_claim("WORK-single"), _crash_claim("WORK-single"),  # C=2, D=1 → closed
        _crash_claim("WORK-rich"), _crash_claim("WORK-rich"),      # C=2, D=3 → open
        _crash_claim("WORK-fresh"),                                # C=1, D=1 → open
    ])
    rows = {r.get("id"): r.get("reason") for r in workqueue.explain_queue(ctx, ["generic"])}
    assert_eq("terminal:crash", rows.get("WORK-single"),
              "concrete closure: re-concluded past distinct-hypothesis count → terminal")
    assert_eq("eligible", rows.get("WORK-rich"),
              "concrete closure: still has un-mined distinct hypotheses → stays eligible")
    assert_eq("eligible", rows.get("WORK-fresh"),
              "concrete closure: first conclusion with a distinct hypothesis → re-offerable")


# Broad ranked-source cards cover a whole file, whose bugs live across
# functions never yet hypothesised — so re-discovery must NOT close them
# (that would abandon the file after one bug). They retire on the file-level
# dry signal instead.
with tempfile.TemporaryDirectory() as td:
    rdir = Path(td) / "results"
    rdir.mkdir()
    target = Path(td) / "target"
    target.mkdir()
    ctx = _ctx(rdir, target)
    workqueue.init_state(ctx)
    _write_jsonl(rdir / "work-cards.jsonl", [_card("WORK-broad", kind="ranked-source")])
    _write_jsonl(rdir / "state" / "hypotheses.jsonl", [_hyp("WORK-broad", "b1")])
    _write_jsonl(rdir / "state" / "claims.jsonl", [
        _crash_claim("WORK-broad"), _crash_claim("WORK-broad"),  # C=2, D=1 (re-discovery)
    ])
    reason_hot = workqueue.explain_queue(ctx, ["generic"])[0].get("reason")
    assert_eq("eligible", reason_hot,
              "broad closure: re-discovery alone does NOT close a whole-file card")
    _set_dry_streak(rdir, "src/parser.c", workqueue._PRODUCTIVE_DECAY_AFTER_ITERS)
    reason_dry = workqueue.explain_queue(ctx, ["generic"])[0].get("reason")
    assert_eq("terminal:crash", reason_dry,
              "broad closure: retires once its subsystem dry-streak crosses the threshold")


# Legacy released mask: a bare "released" row (written before terminal
# preservation, or any resumed pre-fix state) must not reopen a mined card.
# The recorded conclusion still routes closure.
with tempfile.TemporaryDirectory() as td:
    rdir = Path(td) / "results"
    rdir.mkdir()
    target = Path(td) / "target"
    target.mkdir()
    ctx = _ctx(rdir, target)
    workqueue.init_state(ctx)
    _write_jsonl(rdir / "work-cards.jsonl", [_card("WORK-mask")])
    _write_jsonl(rdir / "state" / "hypotheses.jsonl", [_hyp("WORK-mask", "m1")])
    _write_jsonl(rdir / "state" / "claims.jsonl", [
        _crash_claim("WORK-mask"), _crash_claim("WORK-mask"),  # C=2, D=1 → re-discovery
        # legacy stale-lease cleanup wrote a bare "released" (no preserved status).
        {"card_id": "WORK-mask", "agent": "1", "status": "released",
         "reason": "all-hypotheses-terminal", "source": "release-stale-claims",
         "updated_at": "2026-01-01T00:02:00Z"},
    ])
    reason_masked = workqueue.explain_queue(ctx, ["generic"])[0].get("reason")
    assert_eq("terminal:released", reason_masked,
              "legacy released mask: recorded conclusion still closes a mined concrete card")


# Expired-lease mask: a re-claimed card whose lease later expires reads back as
# "unclaimed"; that must NOT reopen a mined card either. A *live* claim, by
# contrast, is left open — the owner is still investigating.
with tempfile.TemporaryDirectory() as td:
    rdir = Path(td) / "results"
    rdir.mkdir()
    target = Path(td) / "target"
    target.mkdir()
    ctx = _ctx(rdir, target)
    workqueue.init_state(ctx)
    _write_jsonl(rdir / "work-cards.jsonl", [_card("WORK-exp"), _card("WORK-live")])
    _write_jsonl(rdir / "state" / "hypotheses.jsonl", [_hyp("WORK-exp", "e1"), _hyp("WORK-live", "l1")])
    _write_jsonl(rdir / "state" / "claims.jsonl", [
        _crash_claim("WORK-exp"), _crash_claim("WORK-exp"),   # C=2, D=1 → re-discovery
        {"card_id": "WORK-exp", "agent": "1", "status": "claimed",
         "claimed_at": "2026-01-01T00:02:00Z", "expires_at": "2026-01-01T00:32:00Z"},  # long expired
        _crash_claim("WORK-live"), _crash_claim("WORK-live"),  # C=2, D=1 → re-discovery
        {"card_id": "WORK-live", "agent": "1", "status": "claimed",
         "claimed_at": "2999-01-01T00:00:00Z", "expires_at": "2999-01-01T01:00:00Z"},  # live lease
    ])
    rows = {r.get("id"): r for r in workqueue.explain_queue(ctx, ["generic"])}
    assert_eq("terminal:unclaimed", rows.get("WORK-exp", {}).get("reason"),
              "expired-lease mask: recorded conclusion still closes a mined card (no reopen as unclaimed)")
    assert_eq("claimed", rows.get("WORK-live", {}).get("status"),
              "live lease: a card still being investigated is left open, not force-closed")


print()
print(f"  {_PASSED} passed, {_FAILED} failed")
sys.exit(0 if _FAILED == 0 else 1)
