#!/usr/bin/env python3
"""Tests for mark_cards_blocked_by_find_id and the bin/state
`mark-finding-rejected` subcommand. Both surfaces propagate a judge
rejection from a FIND-RECON directory back to the originating
WORK-recon-* work-cards, so the queue ranker stops surfacing them.
"""
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "lib"))

import workqueue  # noqa: E402

PASSED = 0
FAILED = 0


def ok(cond: bool, name: str, detail: str = "") -> None:
    global PASSED, FAILED
    if cond:
        PASSED += 1
        print(f"  \033[0;32m✓\033[0m {name}")
    else:
        FAILED += 1
        suffix = f"\n    {detail}" if detail else ""
        print(f"  \033[0;31m✗\033[0m {name}{suffix}")


def make_ctx(td: Path) -> workqueue.Context:
    results = td / "results"
    target = td / "target"
    target.mkdir(parents=True, exist_ok=True)
    results.mkdir(parents=True, exist_ok=True)
    (results / "state").mkdir(parents=True, exist_ok=True)
    return workqueue.Context(
        script_root=ROOT,
        target_root=target,
        target_slug="testproject",
        results_dir=results,
        repo_type="git",
    )


def write_cards(ctx: workqueue.Context, cards: list[dict]) -> None:
    path = workqueue.work_cards_path(ctx)
    with path.open("w") as fh:
        for c in cards:
            fh.write(json.dumps(c) + "\n")


def latest_status(ctx: workqueue.Context, card_id: str) -> str:
    """Last status row for card_id in claims.jsonl (authoritative)."""
    claims = workqueue.state_dir(ctx.results_dir) / "claims.jsonl"
    last = ""
    if claims.exists():
        for line in claims.read_text().splitlines():
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            if row.get("card_id") == card_id:
                last = str(row.get("status", ""))
    return last


# ── Empty find_id: no-op, returns [] ───────────────────────────
with tempfile.TemporaryDirectory() as td:
    ctx = make_ctx(Path(td))
    write_cards(ctx, [{"id": "WORK-x", "find_id": "FIND-001"}])
    got = workqueue.mark_cards_blocked_by_find_id(ctx, "", "no reason")
    ok(got == [], "empty find_id returns empty list")
    ok(latest_status(ctx, "WORK-x") == "", "empty find_id leaves card status untouched")

# ── No matching cards: no-op, returns [] ───────────────────────
with tempfile.TemporaryDirectory() as td:
    ctx = make_ctx(Path(td))
    write_cards(ctx, [
        {"id": "WORK-x", "find_id": "FIND-RECON-aaa"},
        {"id": "WORK-y", "find_id": "FIND-RECON-bbb"},
    ])
    got = workqueue.mark_cards_blocked_by_find_id(ctx, "FIND-RECON-ccc", "missing target")
    ok(got == [], "non-matching find_id returns empty list")
    ok(latest_status(ctx, "WORK-x") == "" and latest_status(ctx, "WORK-y") == "",
       "non-matching find_id touches no card")

# ── Single matching card: blocked, note recorded ──────────────
with tempfile.TemporaryDirectory() as td:
    ctx = make_ctx(Path(td))
    write_cards(ctx, [
        {"id": "WORK-parse-id-asan", "find_id": "FIND-RECON-9201382210-parse-id-trunc"},
        {"id": "WORK-other", "find_id": "FIND-RECON-aaa"},
    ])
    got = workqueue.mark_cards_blocked_by_find_id(
        ctx,
        "FIND-RECON-9201382210-parse-id-trunc",
        "2/2 reject: non-security",
    )
    ok(got == ["WORK-parse-id-asan"], "matching card is identified")
    ok(latest_status(ctx, "WORK-parse-id-asan") == "blocked",
       "matching card transitions to blocked")
    ok(latest_status(ctx, "WORK-other") == "",
       "unrelated card is untouched")
    # Note is recorded for forensics.
    claims = workqueue.state_dir(ctx.results_dir) / "claims.jsonl"
    last_row = None
    for line in claims.read_text().splitlines():
        row = json.loads(line)
        if row.get("card_id") == "WORK-parse-id-asan":
            last_row = row
    ok(last_row is not None, "matching card leaves a claims row")
    ok("judge-rejected" in ((last_row or {}).get("note") or ""),
       "note carries judge-rejected marker")
    ok("non-security" in ((last_row or {}).get("note") or ""),
       "note carries the operator-visible reason")

# ── Multiple cards (sanitizer fan-out): all blocked ─────────────
with tempfile.TemporaryDirectory() as td:
    ctx = make_ctx(Path(td))
    write_cards(ctx, [
        {"id": "WORK-x-asan", "find_id": "FIND-RECON-X"},
        {"id": "WORK-x-ubsan", "find_id": "FIND-RECON-X"},
        {"id": "WORK-x-msan", "find_id": "FIND-RECON-X"},
        {"id": "WORK-y-asan", "find_id": "FIND-RECON-Y"},
    ])
    got = workqueue.mark_cards_blocked_by_find_id(ctx, "FIND-RECON-X", "fanned out")
    ok(set(got) == {"WORK-x-asan", "WORK-x-ubsan", "WORK-x-msan"},
       "fan-out: every WORK card with the find_id is marked")
    for cid in ("WORK-x-asan", "WORK-x-ubsan", "WORK-x-msan"):
        ok(latest_status(ctx, cid) == "blocked", f"{cid} blocked")
    ok(latest_status(ctx, "WORK-y-asan") == "",
       "unrelated find_id (Y) is not touched by X-rejection")

# ── claim_next_card stops surfacing the blocked card ───────────
with tempfile.TemporaryDirectory() as td:
    ctx = make_ctx(Path(td))
    write_cards(ctx, [
        {
            "id": "WORK-x",
            "kind": "recon-hypothesis",
            "find_id": "FIND-RECON-X",
            "file": "src/sampledb.cpp",
            "function": "parse_id",
            "subsystem": "src/sampledb.cpp",
            "score": 100,
            "status": "unclaimed",
            "mode": "auto",
        },
    ])
    # Sanity: before rejection, the card is claimable.
    first = workqueue.claim_next_card(ctx, agent="1", mode="generic", role="reproduce", claim=False)
    ok(first is not None and first.get("id") == "WORK-x",
       "pre-rejection: card is claimable")
    workqueue.mark_cards_blocked_by_find_id(ctx, "FIND-RECON-X", "rejected")
    second = workqueue.claim_next_card(ctx, agent="1", mode="generic", role="reproduce", claim=False)
    ok(second is None,
       "post-rejection: card is no longer claimable (queue picker skips blocked)")

# ── bin/state mark-finding-rejected CLI interface ──────────────
with tempfile.TemporaryDirectory() as td:
    ctx = make_ctx(Path(td))
    write_cards(ctx, [
        {"id": "WORK-cli", "find_id": "FIND-RECON-Z"},
    ])
    proc = subprocess.run(
        [
            sys.executable, str(ROOT / "bin/state"),
            "--results-dir", str(ctx.results_dir),
            "--target-path", str(ctx.target_root),
            "--target-slug", ctx.target_slug,
            "mark-finding-rejected",
            "--find-id", "FIND-RECON-Z",
            "--reason", "cli-test",
        ],
        capture_output=True, text=True,
    )
    ok(proc.returncode == 0, "bin/state mark-finding-rejected returns 0",
       f"stderr={proc.stderr!r}")
    try:
        payload = json.loads(proc.stdout)
    except json.JSONDecodeError:
        payload = {}
    ok(payload.get("find_id") == "FIND-RECON-Z",
       "CLI output reports the find_id")
    ok(payload.get("count") == 1,
       "CLI output reports the number of cards blocked")
    ok("WORK-cli" in (payload.get("blocked_cards") or []),
       "CLI output includes the blocked card ids")
    ok(latest_status(ctx, "WORK-cli") == "blocked",
       "CLI run actually marks the card blocked")

print()
print(f"  {PASSED}/{PASSED + FAILED} passed", end="")
if FAILED:
    print(f", {FAILED} failed")
    sys.exit(1)
print()
sys.exit(0)
