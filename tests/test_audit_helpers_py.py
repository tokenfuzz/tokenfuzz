#!/usr/bin/env python3
"""Regression tests for lib/audit_helpers.py.

Each subcommand is exercised through its argparse CLI (the same shape
bin/audit and bin/validate-finding invoke), so the test surface matches
production. Keeps zero coupling to internal helpers — only public CLI
behavior is asserted.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
HELPER = ROOT / "lib" / "audit_helpers.py"

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


def assert_eq(expected, actual, name: str) -> None:
    ok(expected == actual, name, f"expected={expected!r} actual={actual!r}")


def run(args, stdin: str = "", check: bool = False):
    proc = subprocess.run(
        [sys.executable, str(HELPER), *args],
        input=stdin,
        capture_output=True,
        text=True,
    )
    if check and proc.returncode != 0:
        raise AssertionError(f"helper failed rc={proc.returncode}: {proc.stderr}")
    return proc


# ── relpath-list ────────────────────────────────────────────────────
print("relpath-list")
with tempfile.TemporaryDirectory() as td:
    td_path = Path(td).resolve()
    (td_path / "a").mkdir()
    (td_path / "a" / "b.txt").write_text("x")
    stdin = "\n".join([str(td_path / "a"), str(td_path / "a" / "b.txt"), str(td_path)]) + "\n"
    proc = run(["relpath-list", str(td_path)], stdin=stdin)
    assert_eq(0, proc.returncode, "relpath-list exit code")
    lines = [ln for ln in proc.stdout.splitlines() if ln]
    assert_eq(["a", "a/b.txt"], sorted(lines), "relpath-list drops '.' and prints relpaths")

proc = run(["relpath-list", str(ROOT)], stdin="\n\n")
assert_eq("", proc.stdout, "relpath-list ignores blank stdin lines")


# ── waste-telemetry ─────────────────────────────────────────────────
print("\nwaste-telemetry")

proc = run(["waste-telemetry", "/nonexistent/path-that-cannot-exist.log"])
ok(
    "tool_bytes=0" in proc.stdout and "top_cmds=none" in proc.stdout,
    "missing log → zero-row default",
    proc.stdout.strip(),
)

with tempfile.NamedTemporaryFile("w", suffix=".log", delete=False) as f:
    codex_path = f.name
    json.dump(
        {
            "type": "item.completed",
            "item": {
                "type": "command_execution",
                "command": "rg --files src/ | head -3",
                "aggregated_output": "a\nb\nc\n",
            },
        },
        f,
    )
    f.write("\n")
try:
    proc = run(["waste-telemetry", codex_path])
    assert_eq(0, proc.returncode, "codex transcript rc=0")
    ok("rg:1" in proc.stdout, "codex command_execution → rg pattern", proc.stdout)
    ok("tool_bytes=6" in proc.stdout, "codex tool_bytes counts aggregated_output")
finally:
    os.unlink(codex_path)

with tempfile.NamedTemporaryFile("w", suffix=".log", delete=False) as f:
    claude_path = f.name
    json.dump(
        {
            "type": "assistant",
            "message": {
                "content": [
                    {
                        "type": "tool_use",
                        "id": "u1",
                        "name": "Read",
                        "input": {"file_path": "/x"},
                    }
                ]
            },
        },
        f,
    )
    f.write("\n")
    json.dump(
        {
            "type": "user",
            "message": {
                "content": [
                    {"type": "tool_result", "tool_use_id": "u1", "content": "hello"}
                ]
            },
        },
        f,
    )
    f.write("\n")
try:
    proc = run(["waste-telemetry", claude_path])
    ok("Read:1" in proc.stdout, "claude tool_use → native_tools Read:1", proc.stdout)
    ok("tool_bytes=5" in proc.stdout, "claude tool_result content size = 5")
finally:
    os.unlink(claude_path)

with tempfile.NamedTemporaryFile("w", suffix=".log", delete=False) as f:
    bad_path = f.name
    f.write("not json at all\n")
    f.write(
        '{"type":"item.completed","item":{"type":"command_execution",'
        '"command":"jq .","aggregated_output":"ok"}}\n'
    )
try:
    proc = run(["waste-telemetry", bad_path])
    assert_eq(0, proc.returncode, "garbage lines do not crash")
    ok("jq:1" in proc.stdout, "second valid line still parsed")
finally:
    os.unlink(bad_path)


# ── append-guard-card ───────────────────────────────────────────────
print("\nappend-guard-card")
with tempfile.TemporaryDirectory() as td:
    work = Path(td) / "work-cards.jsonl"
    proc = run(
        [
            "append-guard-card",
            str(work),
            "GUARD-aaa",
            "libxml2",
            "parser",
            "if (ctxt->state == XML_PARSER_DTD)",
            "2026-05-18T00:00:00Z",
        ],
        check=True,
    )
    assert_eq(0, proc.returncode, "append-guard-card rc=0")
    rows = [json.loads(ln) for ln in work.read_text().splitlines() if ln.strip()]
    assert_eq(1, len(rows), "single row appended")
    row = rows[0]
    assert_eq("GUARD-aaa", row["id"], "id field")
    assert_eq("guard-bypass", row["kind"], "kind field")
    assert_eq("S2", row["strategy"], "strategy is S2")
    assert_eq("unclaimed", row["status"], "status is unclaimed")
    assert_eq(100, row["score"], "score is 100")
    ok(
        "bypass-only" in row["reason"] and "XML_PARSER_DTD" in row["reason"],
        "reason embeds the guard string",
        row["reason"],
    )

    run(
        [
            "append-guard-card", str(work), "GUARD-aaa", "libxml2", "parser",
            "g", "2026-05-18T00:00:00Z",
        ],
        check=True,
    )
    rows = [json.loads(ln) for ln in work.read_text().splitlines() if ln.strip()]
    assert_eq(2, len(rows), "second invocation appends a second row (dedup is caller's job)")


# ── codex-usage-reset-at ────────────────────────────────────────────
print("\ncodex-usage-reset-at")

with tempfile.NamedTemporaryFile("w", suffix=".log", delete=False) as f:
    p1 = f.name
    f.write("You've hit your usage limit. Please try again at 9:01 AM.\n")
try:
    proc = run(["codex-usage-reset-at", p1])
    assert_eq(0, proc.returncode, "absolute time form rc=0")
    out = proc.stdout.strip()
    ok(re.fullmatch(r"\d{9,11}", out) is not None, "prints integer epoch", out)
finally:
    os.unlink(p1)

with tempfile.NamedTemporaryFile("w", suffix=".log", delete=False) as f:
    p2 = f.name
    f.write("rate limited, retry after 15 minutes\n")
try:
    before = int(time.time())
    proc = run(["codex-usage-reset-at", p2])
    after = int(time.time())
    assert_eq(0, proc.returncode, "relative form rc=0")
    parsed = int(proc.stdout.strip())
    ok(
        before + 15 * 60 - 2 <= parsed <= after + 15 * 60 + 2,
        "retry-after 15m yields ~15m from now",
        f"got {parsed}, window [{before + 15 * 60}, {after + 15 * 60}]",
    )
finally:
    os.unlink(p2)

with tempfile.NamedTemporaryFile("w", suffix=".log", delete=False) as f:
    p3 = f.name
    f.write("a routine log line that mentions nothing about limits\n")
try:
    proc = run(["codex-usage-reset-at", p3])
    assert_eq(1, proc.returncode, "no match → rc=1")
    assert_eq("", proc.stdout, "no match → empty stdout")
finally:
    os.unlink(p3)


# ── claims-activity-since ───────────────────────────────────────────
print("\nclaims-activity-since")
with tempfile.TemporaryDirectory() as td:
    claims = Path(td) / "claims.jsonl"
    rows = [
        {"claimed_at": "2026-05-18T00:00:01Z", "status": "claimed", "card_id": "A-1"},
        {"claimed_at": "2026-05-18T00:00:02Z", "status": "claimed", "card_id": "A-2"},
        {"claimed_at": "2026-05-18T00:00:03Z", "status": "released", "card_id": "A-1"},
        {"claimed_at": "2025-01-01T00:00:00Z", "status": "claimed", "card_id": "OLD"},
    ]
    claims.write_text("\n".join(json.dumps(r) for r in rows) + "\n")

    # since well before the rows above → all 4 rows count
    since = 1
    proc = run(["claims-activity-since", str(claims), str(since)])
    assert_eq(0, proc.returncode, "rc=0")
    out = proc.stdout.strip()
    ok("total=4" in out, "total counts every row at/after since", out)
    ok("claimed:3" in out, "histogram counts claimed:3")
    ok("released:1" in out, "histogram counts released:1")
    ok("claimed_ids=[" in out, "claimed_ids list emitted")

    proc = run(["claims-activity-since", str(claims), "99999999999"])
    assert_eq(0, proc.returncode, "future since rc=0")
    assert_eq("", proc.stdout, "future since silent")

    proc = run(["claims-activity-since", str(claims), "not-a-number"])
    assert_eq(0, proc.returncode, "non-numeric since is tolerated silently")
    assert_eq("", proc.stdout, "non-numeric since → empty stdout")


# ── extract-vote-json ───────────────────────────────────────────────
print("\nextract-vote-json")
proc = run(["extract-vote-json"], stdin='noise {"vote":"Promote","conf":0.9} tail')
assert_eq(0, proc.returncode, "Promote rc=0")
assert_eq('{"vote":"Promote","conf":0.9}', proc.stdout.strip(), "extracts trim-free")

proc = run(["extract-vote-json"], stdin='prose\n{"vote": "Reject", "reason": "no repro"}\nmore')
assert_eq(0, proc.returncode, "multi-line Reject rc=0")
ok('"vote": "Reject"' in proc.stdout, "multi-line vote object emitted")

proc = run(["extract-vote-json"], stdin="no vote at all here")
assert_eq(1, proc.returncode, "no vote → rc=1")
assert_eq("", proc.stdout, "no vote → empty stdout")

proc = run(
    ["extract-vote-json"],
    stdin='before {"vote":"Maybe"} mid {"vote":"Uncertain","x":1} after',
)
assert_eq(0, proc.returncode, "invalid-then-valid rc=0")
ok('"vote":"Uncertain"' in proc.stdout, "skips invalid vote, takes valid one")

proc = run(
    ["extract-vote-json"],
    stdin='{"vote":"Promote","note":"contains } and \\" quotes"}',
)
assert_eq(0, proc.returncode, "string-with-brace rc=0")
ok('"vote":"Promote"' in proc.stdout, "balanced parse survives '}' inside strings")


# ── emit-event ──────────────────────────────────────────────────────
print("\nemit-event")
with tempfile.TemporaryDirectory() as td:
    events = Path(td) / "deep" / "state" / "events.jsonl"
    proc = run(
        [
            "emit-event", str(events), "agent-plan",
            "agent=1", "launch=cold-start", "role=writer",
            "--int", "streak=3", "--int", "pending=5",
            "--bool", "productive=true",
        ],
        check=True,
    )
    assert_eq(0, proc.returncode, "emit-event rc=0")
    ok(events.parent.is_dir(), "parent dirs auto-created")
    rows = [json.loads(ln) for ln in events.read_text().splitlines() if ln.strip()]
    assert_eq(1, len(rows), "exactly one row written")
    row = rows[0]
    assert_eq("agent-plan", row["event"], "event field")
    assert_eq("1", row["agent"], "agent string-typed")
    assert_eq("cold-start", row["launch"], "launch string-typed")
    assert_eq(3, row["streak"], "streak coerced to int")
    assert_eq(5, row["pending"], "pending coerced to int")
    assert_eq(True, row["productive"], "productive coerced to bool")
    ok("created_at" in row and row["created_at"].endswith("Z"),
       "created_at present + RFC3339", row.get("created_at"))

    # Second emission appends, doesn't overwrite.
    run(["emit-event", str(events), "subsystem-claim",
         "agent=1", "before=unknown", "after=src/lib"],
        check=True)
    rows = [json.loads(ln) for ln in events.read_text().splitlines() if ln.strip()]
    assert_eq(2, len(rows), "second emission appended")
    assert_eq("subsystem-claim", rows[1]["event"], "second row event")

    # Bad --int value coerces to 0 (matches pre-port jq --argjson default behavior).
    run(["emit-event", str(events), "strategy-status",
         "agent=1", "--int", "streak=not-a-number"],
        check=True)
    rows = [json.loads(ln) for ln in events.read_text().splitlines() if ln.strip()]
    assert_eq(0, rows[2]["streak"], "bad int coerces to 0")

    # Argument shaped like 'key=value=more' keeps the full tail as the value.
    run(["emit-event", str(events), "strategy-rotation",
         "agent=1", "reason=S1 exhausted: drop=here"],
        check=True)
    rows = [json.loads(ln) for ln in events.read_text().splitlines() if ln.strip()]
    assert_eq("S1 exhausted: drop=here", rows[3]["reason"], "value tail preserved")

# Missing parent dir + write failure is silent (best-effort).
with tempfile.TemporaryDirectory() as td:
    # Use a file as the parent so mkdir + write both fail.
    blocker = Path(td) / "not-a-dir"
    blocker.write_text("blocking file")
    target = blocker / "state" / "events.jsonl"
    proc = run(["emit-event", str(target), "agent-plan", "agent=1"])
    assert_eq(0, proc.returncode, "broken target → rc=0 (best-effort)")


# Concurrent appenders must produce one well-formed JSON object per line.
# events.jsonl is shared across parallel agents + orchestrator
# (see docs/development.md logging discipline). This is a property test: each
# subprocess opens, writes one buffered line, and closes — the kernel
# does a single write() per process, which O_APPEND serializes for
# regular files. So the test passes regardless of whether the in-process
# flock around the write is present. The flock + flush-in-locked-region
# matter when a single Python process makes multiple writes on one fd
# or when a write is large enough to be split into multiple os.write()
# syscalls; the test below does not exercise that path. Kept as a
# regression sentinel for "concurrent emit-event produces valid JSONL".
print("\nemit-event concurrent writes")
import threading
with tempfile.TemporaryDirectory() as td:
    events = Path(td) / "state" / "events.jsonl"
    events.parent.mkdir(parents=True, exist_ok=True)
    long_reason = "x" * 8000  # exceeds PIPE_BUF on Linux (4096)
    n_workers = 8
    n_events_per_worker = 25

    def worker(idx: int) -> None:
        for i in range(n_events_per_worker):
            subprocess.run(
                [
                    sys.executable, str(HELPER), "emit-event",
                    str(events), "agent-plan",
                    f"agent={idx}", f"iter={i}",
                    f"reason={long_reason}",
                ],
                check=True,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(n_workers)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    raw_lines = events.read_text().splitlines()
    assert_eq(n_workers * n_events_per_worker, len(raw_lines),
              "every concurrent write produced exactly one line")
    parsed = 0
    for ln in raw_lines:
        if not ln.strip():
            continue
        try:
            row = json.loads(ln)
            ok_row = row.get("event") == "agent-plan" and row.get("reason") == long_reason
            if ok_row:
                parsed += 1
        except json.JSONDecodeError:
            pass
    assert_eq(n_workers * n_events_per_worker, parsed,
              "every line parses as JSON with the long reason intact")


# ── summary ─────────────────────────────────────────────────────────
print(f"\n  \033[1m{PASSED}/{PASSED + FAILED} passed\033[0m")
sys.exit(0 if FAILED == 0 else 1)
