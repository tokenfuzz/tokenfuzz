#!/usr/bin/env python3
"""Regression tests for lib/finding_dedup.py — deterministic finding clustering.

Exercises:
  * crash_state — sanitizer stack-state extraction (reused from stack_frames)
  * auto-merge — identical (class, file, line) site, identical crash state
  * class is part of the key — same file+line but a different class stays apart
  * site precision — same file different line, or no line at all, stays apart
  * order-independence — shuffling records yields identical components
  * merge provenance — exact-match vs singleton (no probabilistic tier)
  * no LLM surface — no dedup_key / keyer / adjudicator remains on the module
  * scale — no cap, no O(N^2): 300 findings / 60 sites → 60 clusters
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "lib"))

import finding_dedup as fd  # noqa: E402

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


def rec(id, cls="memory-safety", file="", line=""):
    """A cluster-findings signature record. Class is already normalized here,
    exactly as bin/cluster-findings hands it to finding_dedup."""
    return dict(id=id, **{"class": cls}, file=file, line=line)


def comps_of(records, **kw):
    """Return clustering as a set of frozensets for order-free comparison."""
    return {frozenset(c["members"]) for c in fd.cluster(records, **kw)}


def via_of(records, **kw):
    """Map frozenset(members) -> merged_via for provenance assertions."""
    return {frozenset(c["members"]): c["merged_via"] for c in fd.cluster(records, **kw)}


# ── crash_state extraction ─────────────────────────────────────────
print("crash_state")
stack = """SUMMARY: AddressSanitizer: heap-buffer-overflow
    #0 0x1 in proj::Store::set_blob(unsigned int) s.cpp:213
    #1 0x2 in proj::Engine::apply_line(char const*) s.cpp:367
"""
ok(fd.crash_state(stack) != (), "crash state extracted from an ASan stack")
ok(fd.crash_state("no stack here") == (), "no stack → empty crash state")


# ── auto-merge: identical (class, file, line) site ─────────────────
print("\nauto-merge — same (class, file, line) site")
# Two reports pinning the SAME class+file+line collapse — the line is the
# discriminator that makes a location edge safe.
site = [
    rec("FIND-s1", file="src/catalog.c", line="42"),
    rec("FIND-s2", file="src/catalog.c", line="42"),
]
ok(comps_of(site) == {frozenset({"FIND-s1", "FIND-s2"})},
   "same class+file+line → one cluster")

# Three re-discoveries at one site, filed independently, all collapse.
trio = [
    rec("FIND-t1", file="src/parse.c", line="100"),
    rec("FIND-t2", file="src/parse.c", line="100"),
    rec("FIND-t3", file="src/parse.c", line="100"),
]
ok(comps_of(trio) == {frozenset({"FIND-t1", "FIND-t2", "FIND-t3"})},
   "three reports at one site → one cluster")


# ── auto-merge: identical crash state ──────────────────────────────
print("\nauto-merge — identical crash state")
# Two stackless-on-paper findings that embed the SAME sanitizer stack merge on
# the crash state alone, even with no file/line extracted.
texts = {"FIND-x": stack, "FIND-y": stack}
recs2 = [rec("FIND-x"), rec("FIND-y")]
ok(comps_of(recs2, report_texts=texts) == {frozenset({"FIND-x", "FIND-y"})},
   "identical crash state → merge even with no site")


# ── class is part of the merge key ─────────────────────────────────
print("\nclass is part of the key")
# After normalization, mechanism and consequence collapse to ONE class
# (integer-overflow → memory-safety upstream), so two such findings at one
# site share the class and merge. The records reach finding_dedup already
# normalized, so both carry "memory-safety".
folded = [
    rec("FIND-mo1", cls="memory-safety", file="src/n.c", line="10"),
    rec("FIND-mo2", cls="memory-safety", file="src/n.c", line="10"),
]
ok(comps_of(folded) == {frozenset({"FIND-mo1", "FIND-mo2"})},
   "same normalized class at one site → merge")

# Genuinely different classes at one line stay apart — class is a merge field,
# so two unrelated defects that happen to touch one line are not fused.
diff_class = [
    rec("FIND-dc1", cls="memory-safety", file="src/n.c", line="10"),
    rec("FIND-dc2", cls="info-disclosure", file="src/n.c", line="10"),
]
ok(comps_of(diff_class) == {frozenset({"FIND-dc1"}), frozenset({"FIND-dc2"})},
   "different class at same file+line → stay separate")


# ── site precision ─────────────────────────────────────────────────
print("\nsite precision")
# Same file, DIFFERENT line stays apart — distinct bugs in one function at
# different lines are NOT fused (this is why (file,func) is unsafe but
# (file,line) is safe).
diff_line = [
    rec("FIND-d1", file="src/catalog.c", line="42"),
    rec("FIND-d2", file="src/catalog.c", line="91"),
]
ok(comps_of(diff_line) == {frozenset({"FIND-d1"}), frozenset({"FIND-d2"})},
   "same file, different line → stay separate (no func-level over-merge)")

# Same line, DIFFERENT file stays apart (same-named line in two files).
diff_file = [
    rec("FIND-f1", file="src/catalog.c", line="42"),
    rec("FIND-f2", file="src/tool.c", line="42"),
]
ok(comps_of(diff_file) == {frozenset({"FIND-f1"}), frozenset({"FIND-f2"})},
   "same line, different file → stay separate")

# A file with NO line gets no site edge — file alone never merges (that would
# be the unsafe (class, file) collapse).
no_line = [
    rec("FIND-n1", file="src/catalog.c", line=""),
    rec("FIND-n2", file="src/catalog.c", line=""),
]
ok(comps_of(no_line) == {frozenset({"FIND-n1"}), frozenset({"FIND-n2"})},
   "file present but no line → no site edge (file alone never merges)")

# Siteless, stackless findings degrade to singletons (bias-to-separate).
bare = [rec("FIND-b1"), rec("FIND-b2")]
ok(comps_of(bare) == {frozenset({"FIND-b1"}), frozenset({"FIND-b2"})},
   "no site and no stack → singletons (bias-to-separate)")


# ── composition: site and crash edges chain ────────────────────────
print("\nedge composition")
# A shares a site with B; B shares a crash state with C → all three in one
# cluster. The two edge types compose through union-find.
chain_texts = {"FIND-c2": stack, "FIND-c3": stack}
chain = [
    rec("FIND-c1", file="src/z.c", line="5"),
    rec("FIND-c2", file="src/z.c", line="5"),
    rec("FIND-c3"),
]
ok(comps_of(chain, report_texts=chain_texts)
   == {frozenset({"FIND-c1", "FIND-c2", "FIND-c3"})},
   "site edge + crash edge compose into one cluster")


# ── order-independence ─────────────────────────────────────────────
print("\norder-independence")
ok(comps_of(trio) == comps_of(list(reversed(trio))),
   "reversing record order yields identical components")


# ── merge provenance (merged_via) ──────────────────────────────────
print("\nmerge provenance")
via = via_of(trio)
ok(via.get(frozenset({"FIND-t1", "FIND-t2", "FIND-t3"})) == fd.MERGED_STRUCTURAL == "exact-match",
   "auto-merge (shared site) → merged_via=exact-match")
solo = via_of([rec("FIND-solo")])
ok(solo.get(frozenset({"FIND-solo"})) == fd.MERGED_SINGLETON == "singleton",
   "lone finding → merged_via=singleton")
ok(not hasattr(fd, "MERGED_ADJUDICATED") and not hasattr(fd, "make_llm_adjudicator"),
   "no LLM-judge surface remains on the module")
ok(not hasattr(fd, "canon_tokens") and "dedup_key" not in fd.Fingerprint.__dataclass_fields__,
   "no dedup_key / canon_tokens surface remains on the module")


# ── scale: no O(N^2) blowup, no cap, correct clustering ─────────────
print("\nscale")
# 60 distinct sites × 5 duplicates each = 300 findings over 6 classes. Each
# duplicate shares its site's (class, file, line), so we expect exactly 60
# clusters regardless of corpus size or filing order — no LLM, no pairwise
# comparison, no cap.
classes = ["memory-safety", "auth", "injection", "crypto", "race", "logic"]
big = []
for n in range(60):
    for d in range(5):
        big.append(rec(f"FIND-{n:03d}-{d}", cls=classes[n % len(classes)],
                       file=f"src/file_{n:03d}.c", line=str(100 + n)))
clusters_big = fd.cluster(big)
ok(len(clusters_big) == 60, "300 findings, 60 sites → 60 clusters (no cap)",
   f"got {len(clusters_big)}")
ok(all(len(c["members"]) == 5 for c in clusters_big),
   "every site cluster has its 5 duplicates")
ok(comps_of(big) == comps_of(list(reversed(big))),
   "scale clustering is order-independent")


print()
if FAILED:
    print(f"\033[0;31m{FAILED} failed, {PASSED} passed\033[0m")
    sys.exit(1)
print(f"\033[0;32m{PASSED}/{PASSED} passed\033[0m")
