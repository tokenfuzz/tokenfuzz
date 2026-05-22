#!/usr/bin/env python3
"""Regression tests for lib/quality.py.

Each subcommand is exercised through the argparse CLI shape that
lib/quality.sh uses in production. Tests build the real on-disk state
(scratch directories, .asan.txt sidecars, hits.log, corpus root) so the
assertions reflect what bin/audit observes at runtime.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
HELPER = ROOT / "lib" / "quality.py"

PASSED = 0
FAILED = 0


def ok(cond, name, detail=""):
    global PASSED, FAILED
    if cond:
        PASSED += 1
        print(f"  \033[0;32m✓\033[0m {name}")
    else:
        FAILED += 1
        print(f"  \033[0;31m✗\033[0m {name}")
        if detail:
            print(f"    {detail}")


def assert_eq(expected, actual, name):
    ok(expected == actual, name, f"expected={expected!r} actual={actual!r}")


def run(args, check=False):
    proc = subprocess.run(
        [sys.executable, str(HELPER), *args],
        capture_output=True, text=True,
    )
    if check and proc.returncode != 0:
        raise AssertionError(f"helper failed rc={proc.returncode}: {proc.stderr}")
    return proc


# ── testcase-mode ────────────────────────────────────────────────────
print("testcase-mode")
with tempfile.TemporaryDirectory() as td:
    p = Path(td)
    (p / "input.html").write_bytes(b"<html></html>")
    (p / "input.js").write_bytes(b"// js")
    (p / "input.mjs").write_bytes(b"// mjs")
    (p / "blob.bin").write_bytes(b"\x00\x01\x02")
    (p / "REPORT.md").write_bytes(b"# report")
    (p / "asan.txt").write_bytes(b"log")
    (p / "harness.c").write_bytes(b"int main(){}")
    (p / "tc-1.txt").write_bytes(b"some input")
    (p / "notes.txt").write_bytes(b"just notes")  # ambiguous .txt without stem prefix
    (p / "input.empty").write_bytes(b"")

    assert_eq(0, run(["testcase-mode", str(p / "input.html")]).returncode, "html → 0")
    assert_eq("browser", run(["testcase-mode", str(p / "input.html")]).stdout.strip(), "html → browser")
    assert_eq("js", run(["testcase-mode", str(p / "input.js")]).stdout.strip(), "js → js")
    assert_eq("js", run(["testcase-mode", str(p / "input.mjs")]).stdout.strip(), "mjs → js")
    assert_eq("generic", run(["testcase-mode", str(p / "blob.bin")]).stdout.strip(), "blob → generic")
    assert_eq(1, run(["testcase-mode", str(p / "REPORT.md")]).returncode, "REPORT.md skipped")
    assert_eq(1, run(["testcase-mode", str(p / "asan.txt")]).returncode, "asan.txt skipped")
    assert_eq(1, run(["testcase-mode", str(p / "harness.c")]).returncode, "harness.c skipped")
    assert_eq("generic", run(["testcase-mode", str(p / "tc-1.txt")]).stdout.strip(), "tc-* txt → generic")
    assert_eq(1, run(["testcase-mode", str(p / "notes.txt")]).returncode, "plain notes.txt skipped")
    assert_eq(1, run(["testcase-mode", str(p / "input.empty")]).returncode, "zero-byte file skipped")


# ── count-asan-runs + has-verified-asan ──────────────────────────────
print("\ncount-asan-runs / has-verified-asan")
with tempfile.TemporaryDirectory() as td:
    p = Path(td)
    # Three asan.txt files: two verified, one MISSED.
    (p / "tc1.asan.txt").write_text("ASAN_RUN_HEADER: ok\nfoo bar\n")
    (p / "tc2.asan.txt").write_text("EXECUTION_RATE: 5\n")
    (p / "tc3.asan.txt").write_text("COVERAGE_GATE: MISSED\nASAN_RUN_HEADER: still skipped\n")
    # A sidecar that should also count when filename matches asan_output*.
    (p / "asan_output_19.txt").write_text("ERROR: AddressSanitizer: heap-use-after-free\n")
    proc = run(["count-asan-runs", str(p)], check=True)
    assert_eq("3", proc.stdout.strip(), "three verified runs counted (MISSED excluded)")

    # Pair testcases with their sidecars so has-verified-asan works.
    (p / "tc1.js").write_text("// js")
    (p / "tc2.js").write_text("// js")
    (p / "tc3.js").write_text("// js")
    assert_eq(0, run(["has-verified-asan", str(p / "tc1.js")]).returncode, "tc1 has verified asan")
    assert_eq(0, run(["has-verified-asan", str(p / "tc2.js")]).returncode, "tc2 has verified asan")
    assert_eq(1, run(["has-verified-asan", str(p / "tc3.js")]).returncode, "tc3 disqualified by MISSED")


# ── list-testcases + count-testcases + count-orphans + scan-scratch ─
print("\nlist/count helpers")
with tempfile.TemporaryDirectory() as td:
    p = Path(td)
    (p / "good.html").write_text("<html>")
    (p / "good2.js").write_text("// js")
    (p / "asan.txt").write_text("not a testcase")
    (p / "good.asan.txt").write_text("EXECUTION_RATE: 4\n")  # sidecar for good.html
    # good2.js has no sidecar → orphan
    proc = run(["list-testcases", str(p)], check=True)
    listed = [s for s in proc.stdout.split("\0") if s]
    assert_eq(2, len(listed), "two testcases listed")
    ok(all(s.endswith(("good.html", "good2.js")) for s in listed), "list-testcases skips sidecars", listed)

    assert_eq("2", run(["count-testcases", str(p)], check=True).stdout.strip(), "count-testcases=2")
    assert_eq("1", run(["count-orphans", str(p)], check=True).stdout.strip(), "count-orphans=1 (good2.js)")

    proc = run(["scan-scratch", str(p)], check=True)
    assert_eq("asan_runs=1 testcases=2 orphans=1", proc.stdout.strip(), "scan-scratch one-line tally")

    proc = run(["scan-scratch", str(p), "--list-orphans"], check=True)
    body, _, tail = proc.stdout.partition("\n")
    assert_eq("asan_runs=1 testcases=2 orphans=1", body, "scan-scratch with orphans → stats line first")
    orphan_paths = [s for s in tail.split("\0") if s]
    ok(len(orphan_paths) == 1 and orphan_paths[0].endswith("good2.js"),
       "orphan path emitted", str(orphan_paths))


# ── promote-corpus + regenerate-corpus-index ─────────────────────────
print("\npromote-corpus / regenerate-corpus-index")
with tempfile.TemporaryDirectory() as td:
    p = Path(td)
    scratch = p / "scratch"
    scratch.mkdir()
    corpus = p / "corpus"
    corpus.mkdir()

    # Two testcases: one with a verified clean run and a HID header (promotable),
    # one with a HID but no edge-novelty (skipped under default gate), and a
    # crashing run that should be excluded.
    promotable = scratch / "tc-1.html"
    promotable.write_text(
        "<!-- HYPOTHESIS-ID: H42 -->\n"
        "<!-- TARGET: src/lib/parser.cpp -->\n"
        "<!-- CATEGORY: bounds -->\n"
        "<html></html>"
    )
    (scratch / "tc-1.asan.txt").write_text("EXECUTION_RATE: 5\n[run-asan] generic EXECUTION VERIFIED\n")

    crashing = scratch / "tc-2.html"
    crashing.write_text(
        "<!-- HYPOTHESIS-ID: H43 -->\n"
        "<!-- TARGET: src/lib/parser.cpp -->\n"
        "<html></html>"
    )
    (scratch / "tc-2.asan.txt").write_text("ERROR: AddressSanitizer: heap-use-after-free\n")

    no_new_edges = scratch / "tc-3.html"
    no_new_edges.write_text(
        "<!-- HYPOTHESIS-ID: H44 -->\n"
        "<!-- TARGET: src/other.cpp -->\n"
        "<html></html>"
    )
    (scratch / "tc-3.asan.txt").write_text("EXECUTION_RATE: 5\n")

    hits_log = scratch / "hits.log"
    hits_log.write_text(
        f"HIT: 2026-05-19T01:02:03Z testcase={promotable} want=xmlParse edges=12 new=3 frame=xmlParseDoc\n"
        f"HIT: 2026-05-19T01:02:04Z testcase={crashing} want=xmlParse edges=12 new=2 frame=xmlParseDoc\n"
        f"HIT: 2026-05-19T01:02:05Z testcase={no_new_edges} want=other edges=8 new=0 frame=otherFn\n"
    )

    proc = run(["promote-corpus", str(hits_log), str(scratch), str(corpus), "7"], check=True)
    tally = proc.stdout.strip()
    ok("promoted=1" in tally, "exactly one testcase promoted", tally)
    ok("skipped_crashing=1" in tally, "crashing run skipped", tally)
    ok("skipped_no_new_edges=1" in tally, "new=0 testcase gated out", tally)

    cover_dirs = sorted(d for d in corpus.iterdir() if d.is_dir() and d.name.startswith("COVER-"))
    assert_eq(1, len(cover_dirs), "one COVER- dir created")
    cover = cover_dirs[0]
    ok(cover.name == "COVER-001-7", "COVER name uses 3-digit seq + agent suffix")
    ok((cover / "tc-1.html").is_file(), "testcase copied")
    ok((cover / "tc-1.asan.txt").is_file(), "asan sidecar copied")
    meta_text = (cover / "metadata.md").read_text()
    ok("H42" in meta_text and "bounds" in meta_text and "new=3" not in meta_text,
       "metadata contains hypothesis + category", meta_text[:200])
    ok("**New edges contributed:** 3" in meta_text, "new-edge count recorded", meta_text[:300])

    # Re-running with the same hits log should NOT re-promote (basename
    # dedup) and tally should report 0 promoted.
    proc = run(["promote-corpus", str(hits_log), str(scratch), str(corpus), "7"], check=True)
    ok("promoted=0" in proc.stdout, "idempotent: no double-promotion", proc.stdout.strip())

    # Index regen: should write INDEX.md with our single row.
    run(["regenerate-corpus-index", str(corpus)], check=True)
    idx_text = (corpus / "INDEX.md").read_text()
    ok("COVER-001-7" in idx_text, "index lists promoted COVER", idx_text)
    ok("H42" in idx_text, "index includes hypothesis column", idx_text)

    # CORPUS_REQUIRE_NEW_EDGES=0 should also promote new=0 testcases.
    os.environ["CORPUS_REQUIRE_NEW_EDGES"] = "0"
    try:
        corpus2 = p / "corpus2"
        corpus2.mkdir()
        proc = subprocess.run(
            [sys.executable, str(HELPER), "promote-corpus",
             str(hits_log), str(scratch), str(corpus2), "1"],
            capture_output=True, text=True,
            env={**os.environ, "CORPUS_REQUIRE_NEW_EDGES": "0"},
        )
        ok("promoted=2" in proc.stdout,
           "CORPUS_REQUIRE_NEW_EDGES=0 promotes new=0 + new=3",
           proc.stdout.strip())
    finally:
        os.environ.pop("CORPUS_REQUIRE_NEW_EDGES", None)


# ── promote-corpus concurrency: COVER-NNN collisions ────────────────
# Two concurrent promote-corpus calls for the same agent_num must not
# silently lose promotions to a COVER-NNN-{agent_num} directory-name
# collision. The retry-with-incremented-seq loop in _cmd_promote_corpus
# walks past the loser's first attempt and lands on the next free slot.
print("\npromote-corpus concurrent same-agent promotions")
import threading
with tempfile.TemporaryDirectory() as td:
    p = Path(td)
    scratch = p / "scratch"
    scratch.mkdir()
    corpus = p / "corpus"
    corpus.mkdir()

    # Build N independent promotable testcases with distinct basenames so
    # the basename-dedup path doesn't mask the collision behavior we're
    # testing here.
    n_cases = 12
    hits_lines = []
    for i in range(n_cases):
        tc = scratch / f"tc-{i:02d}.html"
        tc.write_text(
            f"<!-- HYPOTHESIS-ID: H{i:02d} -->\n"
            f"<!-- TARGET: src/lib/parser.cpp -->\n"
            f"<!-- CATEGORY: bounds -->\n"
            f"<html></html>"
        )
        (scratch / f"tc-{i:02d}.asan.txt").write_text(
            "EXECUTION_RATE: 5\n[run-asan] generic EXECUTION VERIFIED\n"
        )
        hits_lines.append(
            f"HIT: 2026-05-19T01:02:{i:02d}Z testcase={tc} "
            f"want=xmlParse edges={10 + i} new={i + 1} frame=xmlParseDoc\n"
        )

    # Two hits logs split between two workers — each worker promotes half
    # the testcases, both targeting the SAME corpus root with the SAME
    # agent_num, so every iteration of the loop competes on COVER-NNN-9.
    hits_a = scratch / "hits_a.log"
    hits_a.write_text("".join(hits_lines[: n_cases // 2]))
    hits_b = scratch / "hits_b.log"
    hits_b.write_text("".join(hits_lines[n_cases // 2 :]))

    def promote(hits: Path) -> None:
        subprocess.run(
            [sys.executable, str(HELPER), "promote-corpus",
             str(hits), str(scratch), str(corpus), "9"],
            check=True, capture_output=True, text=True,
        )

    threads = [
        threading.Thread(target=promote, args=(hits_a,)),
        threading.Thread(target=promote, args=(hits_b,)),
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    cover_dirs = sorted(d for d in corpus.iterdir() if d.is_dir() and d.name.startswith("COVER-"))
    assert_eq(n_cases, len(cover_dirs),
              "every testcase produced a COVER- dir under concurrent promote")
    # Sequence numbers must be unique and contiguous (1..n_cases).
    seqs = sorted(int(d.name.split("-")[1]) for d in cover_dirs)
    assert_eq(list(range(1, n_cases + 1)), seqs,
              "COVER-NNN sequence numbers are unique + contiguous")
    # Every COVER- dir must hold a testcase + sidecar + metadata.
    incomplete = [
        d.name for d in cover_dirs
        if not (any(d.glob("tc-*.html")) and any(d.glob("tc-*.asan.txt")) and (d / "metadata.md").is_file())
    ]
    ok(not incomplete, "every COVER- dir has testcase + asan + metadata",
       f"incomplete={incomplete}")


print(f"\n  \033[1m{PASSED}/{PASSED + FAILED} passed\033[0m")
sys.exit(0 if FAILED == 0 else 1)
