#!/usr/bin/env python3
"""tests/test_env_block_propagation.py — env-block fingerprint propagation.

When a hypothesis transitions to ENV-BLOCKED with a runtime/build env
failure note (ModuleNotFoundError, missing .h, library not loaded), the
matching ``update_hypothesis`` path in lib/workqueue.py blocks every
unclaimed work card that shares the hypothesis's compilation unit. The
sibling match is structural — same directory + same filename stem —
so ``yaml/_yaml.pyx`` propagates to ``yaml/_yaml.{c,h,pxd}`` without any
language-specific knowledge baked in.

This guards against regressions where an agent re-discovers the same
environmental wall once per card by adding a fresh hypothesis on each
sibling file, burning iterations.
"""
from __future__ import annotations

import argparse
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


def assert_true(cond, name: str, detail: str = "") -> None:
    if cond:
        passed(name)
    else:
        failed(name, detail)


def _ctx(results_dir: Path, target_root: Path) -> workqueue.Context:
    return workqueue.Context(
        script_root=ROOT,
        target_root=target_root,
        target_slug="env-block-test",
        results_dir=results_dir,
        repo_type="git",
    )


def _seed_work_cards(results_dir: Path, files: list[str]) -> None:
    cards_path = results_dir / "work-cards.jsonl"
    with cards_path.open("w") as f:
        for i, file in enumerate(files, start=1):
            f.write(json.dumps({
                "id": f"WORK-{i:04d}",
                "kind": "ranked-source",
                "target_slug": "env-block-test",
                "subsystem": file,
                "file": file,
                "function": "",
                "mode": "auto",
                "strategy": "S1",
                "score": 1,
                "status": "unclaimed",
                "created_at": "2026-01-01T00:00:00Z",
            }) + "\n")


def _seed_hypothesis(results_dir: Path, hid: str, file: str) -> None:
    state_dir = results_dir / "state"
    state_dir.mkdir(parents=True, exist_ok=True)
    with (state_dir / "hypotheses.jsonl").open("a") as f:
        f.write(json.dumps({
            "id": hid,
            "agent": "1",
            "hypothesis": "demo",
            "file": file,
            "input_shape": "x",
            "guard_gap": "y",
            "diagnostic": "size",
            "strategy": "S1",
            "status": "PENDING",
            "created_at": "2026-01-01T00:00:00Z",
            "updated_at": "2026-01-01T00:00:00Z",
        }) + "\n")


def _latest_claim(results_dir: Path, card_id: str) -> dict | None:
    path = results_dir / "state" / "claims.jsonl"
    if not path.exists():
        return None
    rows: list[dict] = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if obj.get("card_id") == card_id:
            rows.append(obj)
    return rows[-1] if rows else None


# Hypothesis at yaml/_yaml.pyx with a ModuleNotFoundError note should
# block sibling unclaimed cards (yaml/_yaml.c, .h, .pxd) but leave
# unrelated cards (lib/yaml/parser.py) alone.
with tempfile.TemporaryDirectory() as td:
    rdir = Path(td) / "results"
    rdir.mkdir()
    target = Path(td) / "target"
    target.mkdir()
    ctx = _ctx(rdir, target)
    workqueue.init_state(ctx)

    sibling_files = [
        "yaml/_yaml.pyx",
        "yaml/_yaml.c",
        "yaml/_yaml.h",
        "yaml/_yaml.pxd",
    ]
    unrelated_files = [
        "lib/yaml/parser.py",          # different dir
        "yaml/__init__.pxd",           # same dir, different stem
        "yaml/_yaml_other.c",          # same dir, different stem
    ]
    _seed_work_cards(rdir, sibling_files + unrelated_files)
    _seed_hypothesis(rdir, "H-env", "yaml/_yaml.pyx:CParser.__init__:4853")

    blocked = workqueue._propagate_env_block_to_sibling_cards(
        ctx, "yaml/_yaml.pyx:CParser.__init__:4853",
        "ModuleNotFoundError: No module named 'yaml._yaml'",
        "1",
    )
    assert_eq(4, blocked, "propagation: blocks all 4 sibling cards (.pyx,.c,.h,.pxd)")

    # Every sibling now has a 'blocked' claim row.
    for i in range(1, 5):
        row = _latest_claim(rdir, f"WORK-{i:04d}")
        assert_true(
            row is not None and row.get("status") == "blocked",
            f"propagation: sibling card WORK-{i:04d} ({sibling_files[i-1]}) is blocked",
            detail=f"row={row}",
        )

    # Unrelated cards (different dir / different stem) untouched.
    for i in range(5, 8):
        row = _latest_claim(rdir, f"WORK-{i:04d}")
        assert_eq(None, row,
                  f"propagation: unrelated card WORK-{i:04d} ({unrelated_files[i-5]}) untouched")


# Notes that do NOT match the fingerprint regex must not propagate
# (DISCARDED with "three clean variants" should never block siblings).
with tempfile.TemporaryDirectory() as td:
    rdir = Path(td) / "results"
    rdir.mkdir()
    target = Path(td) / "target"
    target.mkdir()
    ctx = _ctx(rdir, target)
    workqueue.init_state(ctx)
    _seed_work_cards(rdir, ["yaml/_yaml.pyx", "yaml/_yaml.c"])
    _seed_hypothesis(rdir, "H-clean", "yaml/_yaml.pyx:foo:1")

    blocked = workqueue._propagate_env_block_to_sibling_cards(
        ctx, "yaml/_yaml.pyx:foo:1",
        "three clean variants on this surface; rotating off",
        "1",
    )
    assert_eq(0, blocked, "propagation: clean-discard note does not propagate")
    assert_eq(None, _latest_claim(rdir, "WORK-0001"),
              "propagation: clean-discard note leaves siblings unclaimed")


# Each fingerprint phrase should fire propagation independently — guards
# against future edits that narrow the regex without realising the audit
# logs use a mix of phrasings.
fingerprints = [
    "ModuleNotFoundError: yaml._yaml missing",
    "ImportError: dynamic module not initialised",
    "fatal error: cannot find yaml.h",
    "build error: missing config.h on this platform",
    "dyld: unable to load shared library: libyaml.dylib",
    "Library not loaded: @rpath/libyaml.dylib",
]
for phrase in fingerprints:
    with tempfile.TemporaryDirectory() as td:
        rdir = Path(td) / "results"
        rdir.mkdir()
        target = Path(td) / "target"
        target.mkdir()
        ctx = _ctx(rdir, target)
        workqueue.init_state(ctx)
        _seed_work_cards(rdir, ["yaml/_yaml.pyx", "yaml/_yaml.c"])
        _seed_hypothesis(rdir, "H-fp", "yaml/_yaml.pyx:foo:1")
        n = workqueue._propagate_env_block_to_sibling_cards(
            ctx, "yaml/_yaml.pyx:foo:1", phrase, "1",
        )
        assert_eq(2, n, f"fingerprint matches and propagates: {phrase[:40]!r}")


# Already-terminal cards (the original env-blocked card itself, or
# previously-discarded cards) must not be re-blocked — only unclaimed
# siblings transition.
with tempfile.TemporaryDirectory() as td:
    rdir = Path(td) / "results"
    rdir.mkdir()
    target = Path(td) / "target"
    target.mkdir()
    ctx = _ctx(rdir, target)
    workqueue.init_state(ctx)
    _seed_work_cards(rdir, ["yaml/_yaml.pyx", "yaml/_yaml.c"])
    # Pre-mark WORK-0001 (.pyx) as discarded.
    (rdir / "state" / "claims.jsonl").write_text(
        json.dumps({"card_id": "WORK-0001", "agent": "1",
                    "status": "discarded", "updated_at": "2026-01-01T00:00:00Z"}) + "\n"
    )
    n = workqueue._propagate_env_block_to_sibling_cards(
        ctx, "yaml/_yaml.pyx:foo:1",
        "ModuleNotFoundError: yaml._yaml",
        "1",
    )
    assert_eq(1, n, "propagation: terminal cards skipped, only WORK-0002 blocked")
    pyx = _latest_claim(rdir, "WORK-0001")
    assert_eq("discarded", pyx.get("status") if pyx else "",
              "propagation: previously-discarded card retains discarded status")


# End-to-end: update_hypothesis with status=ENV-BLOCKED triggers
# propagation. Confirms wiring matches the public entry point that bin/state
# update-hyp uses.
with tempfile.TemporaryDirectory() as td:
    rdir = Path(td) / "results"
    rdir.mkdir()
    target = Path(td) / "target"
    target.mkdir()
    ctx = _ctx(rdir, target)
    workqueue.init_state(ctx)
    _seed_work_cards(rdir, ["yaml/_yaml.pyx", "yaml/_yaml.c"])
    _seed_hypothesis(rdir, "H-e2e", "yaml/_yaml.pyx:CEmitter:1063")

    workqueue.update_hypothesis(
        ctx, "H-e2e", "ENV-BLOCKED",
        "Configured runner cannot import yaml._yaml: ModuleNotFoundError",
    )
    assert_true(
        (_latest_claim(rdir, "WORK-0001") or {}).get("status") == "blocked"
        and (_latest_claim(rdir, "WORK-0002") or {}).get("status") == "blocked",
        "update_hypothesis(ENV-BLOCKED) propagates to both sibling cards",
    )


# --- ENV-BLOCKED own-card unconditional fix --------------------------------
# The ENV-BLOCKED hypothesis's OWN card_id must be marked blocked even
# when the note does NOT match ENV_BLOCK_FINGERPRINT_RE — the agent
# already proved the surface is unreachable, so re-offering it to
# another agent in the same run is wasted work. The fingerprint regex
# gates only the broader sibling-propagation expansion.
def _seed_hypothesis_with_card(
    results_dir: Path, hid: str, file: str, card_id: str
) -> None:
    state = results_dir / "state"
    state.mkdir(parents=True, exist_ok=True)
    with (state / "hypotheses.jsonl").open("a") as f:
        f.write(json.dumps({
            "id": hid,
            "agent": "1",
            "card_id": card_id,
            "hypothesis": "demo",
            "file": file,
            "input_shape": "x",
            "guard_gap": "y",
            "diagnostic": "size",
            "strategy": "S1",
            "status": "PENDING",
            "created_at": "2026-01-01T00:00:00Z",
            "updated_at": "2026-01-01T00:00:00Z",
        }) + "\n")


with tempfile.TemporaryDirectory() as td:
    rdir = Path(td) / "results"
    rdir.mkdir()
    target = Path(td) / "target"
    target.mkdir()
    ctx = _ctx(rdir, target)
    workqueue.init_state(ctx)
    # Two cards, neither a stem-sibling of the other.
    _seed_work_cards(rdir, ["a/x.c", "b/y.c"])
    _seed_hypothesis_with_card(rdir, "H-nofp", "a/x.c:foo:1", "WORK-0001")

    workqueue.update_hypothesis(
        ctx, "H-nofp", "ENV-BLOCKED",
        # Deliberately vague note that does NOT match the fingerprint regex.
        "Could not configure environment for this surface; rotating off.",
    )
    own = _latest_claim(rdir, "WORK-0001")
    assert_true(
        own is not None and own.get("status") == "blocked",
        "ENV-BLOCKED own card is blocked even when note has no fingerprint",
        detail=f"row={own}",
    )
    other = _latest_claim(rdir, "WORK-0002")
    assert_eq(
        None, other,
        "ENV-BLOCKED without fingerprint does NOT block unrelated cards",
    )

# Idempotency: re-marking an already-blocked own card should be a no-op
# (no duplicate blocked claim rows).
with tempfile.TemporaryDirectory() as td:
    rdir = Path(td) / "results"
    rdir.mkdir()
    target = Path(td) / "target"
    target.mkdir()
    ctx = _ctx(rdir, target)
    workqueue.init_state(ctx)
    _seed_work_cards(rdir, ["a/x.c"])
    first = workqueue._block_card_unconditional(
        ctx, card_id="WORK-0001", agent="1", note="first", source="t",
    )
    second = workqueue._block_card_unconditional(
        ctx, card_id="WORK-0001", agent="1", note="second", source="t",
    )
    assert_true(first, "first block returns True")
    assert_true(not second, "re-block on already-blocked card returns False")
    rows = (rdir / "state" / "claims.jsonl").read_text().splitlines()
    blocked_rows = [r for r in rows if '"status": "blocked"' in r]
    assert_eq(1, len(blocked_rows),
              "exactly one blocked row written for WORK-0001 (idempotent)")

    # Same path with a benign status (DISCARDED) must NOT propagate.
    rdir2 = Path(td) / "results2"
    rdir2.mkdir()
    ctx2 = _ctx(rdir2, target)
    workqueue.init_state(ctx2)
    _seed_work_cards(rdir2, ["yaml/_yaml.pyx", "yaml/_yaml.c"])
    _seed_hypothesis(rdir2, "H-d", "yaml/_yaml.pyx:CEmitter:1063")
    workqueue.update_hypothesis(
        ctx2, "H-d", "DISCARDED",
        "ModuleNotFoundError appeared in note but status is DISCARDED",
    )
    assert_eq(None, _latest_claim(rdir2, "WORK-0001"),
              "update_hypothesis(DISCARDED) does not propagate even with matching note")


# Blocked cards must not be re-offered inside the same result set. Env
# state can change in a fresh audit run, but within one configured run a
# blocked card just causes agents to re-prove the same missing feature.
# The status remains soft/distinct from discarded for reporting and
# propagation semantics.
with tempfile.TemporaryDirectory() as td:
    rdir = Path(td) / "results"
    rdir.mkdir()
    target = Path(td) / "target"
    target.mkdir()
    ctx = _ctx(rdir, target)
    workqueue.init_state(ctx)
    _seed_work_cards(rdir, ["a/x.c", "b/y.c"])
    # Mark WORK-0001 blocked, WORK-0002 discarded.
    (rdir / "state" / "claims.jsonl").write_text(
        json.dumps({"card_id": "WORK-0001", "agent": "1",
                    "status": "blocked", "updated_at": "2026-01-01T00:00:00Z"}) + "\n"
        + json.dumps({"card_id": "WORK-0002", "agent": "1",
                      "status": "discarded", "updated_at": "2026-01-01T00:00:00Z"}) + "\n"
    )
    # The rotator should skip both: WORK-0001 is blocked for this result
    # set, and WORK-0002 is permanently discarded.
    picked = workqueue.claim_next_card(ctx, agent="2", mode="generic", claim=False)
    assert_true(
        picked is None,
        "rotator does not re-attempt blocked card in same result set",
        f"picked={picked}",
    )

    # Sanity check on the split constants themselves so any future edit
    # that silently re-adds 'blocked' to the permanent set gets caught.
    assert_true(
        "blocked" in workqueue.SOFT_TERMINAL_CARD_STATUSES,
        "blocked is in SOFT_TERMINAL_CARD_STATUSES",
    )
    assert_true(
        "blocked" not in workqueue.PERMANENT_TERMINAL_CARD_STATUSES,
        "blocked is NOT in PERMANENT_TERMINAL_CARD_STATUSES",
    )
    assert_true(
        "blocked" in workqueue.TERMINAL_CARD_STATUSES,
        "blocked is in TERMINAL_CARD_STATUSES (union, for env-block propagation)",
    )


# --- workqueue.subsystem_for absolute-path rejection ----------------------
# A subsystem derived from an absolute path leaks host-local filesystem
# prefixes into the diversity bucket — every agent's hypothesis files
# end up under the same top-level segment ("$HOME", "/build", "/tmp",
# whatever the host uses) and the rotator can never spread agents
# across real subsystems. The function must refuse such inputs so
# callers fall back to "unknown" instead of saturating the diversity
# gate. Tests use placeholder absolute paths — the actual leading
# segment is irrelevant, only the leading slash matters.
absolute_path_cases = [
    "/abs-host/user/proj/foo.c",
    "/usr/local/include/x.h",
    "/build/asan/lib/m.c",
    "/tmp/checkout/parser/parse.c",
]
for case in absolute_path_cases:
    assert_eq("unknown", workqueue.subsystem_for(case),
              f"subsystem_for: absolute path rejected ({case!r})")
assert_eq("unknown", workqueue.subsystem_for("/"),
          "subsystem_for: bare root → unknown")
# Relative paths still work as before.
assert_eq("root", workqueue.subsystem_for(""),
          "subsystem_for: empty string → root sentinel")
# A single-component relative path returns itself.
assert_eq("foo.c", workqueue.subsystem_for("foo.c"),
          "subsystem_for: single component → itself")


print()
print(f"  {_PASSED} passed, {_FAILED} failed")
sys.exit(0 if _FAILED == 0 else 1)
