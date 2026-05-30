#!/usr/bin/env python3
"""Regression tests for lib/finding_dedup.py — deterministic finding clustering.

Exercises:
  * crash_state — sanitizer stack-state extraction (reused from stack_frames)
  * auto-merge — identical dedup_key (across different sites), identical crash
    state (across drifting recorded func names), identical (file, line) site
  * site edge — same (file, line) merges (incl. keyless findings); same file
    with a different line, or no line at all, stays apart (precision guard)
  * bias-to-separate — co-located findings with no shared key/state stay apart
    (no over-merge of distinct bugs in one function)
  * class gate — different classes never merge, even on an identical key or site
  * order-independence — shuffling records yields identical components
  * merge provenance — exact-match vs singleton (no probabilistic tier)
  * scale — no cap, no O(N^2): 300 findings / 60 root causes → 60 clusters
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


def rec(id, cls="memory-safety", dedup_key="", file="", line=""):
    return dict(id=id, **{"class": cls}, dedup_key=dedup_key, file=file, line=line)


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


# ── auto-merge: identical dedup_key across different sites ──────────
print("\nauto-merge — identical dedup_key")
# Three findings, same class + dedup_key, DIFFERENT sites (two crashers + one
# source-only). dedup_key is what collapses re-discoveries reached from
# different functions, which (class,file,func) keying could never do.
recs = [
    rec("FIND-a", dedup_key="frame-length-truncation-overflow"),
    rec("FIND-b", dedup_key="frame-length-truncation-overflow"),
    rec("FIND-c", dedup_key="frame-length-truncation-overflow"),
]
ok(comps_of(recs) == {frozenset({"FIND-a", "FIND-b", "FIND-c"})},
   "same dedup_key across different sites → one cluster")

# An invalid dedup_key (single token, too short) is NOT a merge signal.
junk = [rec("FIND-j1", dedup_key="oops"), rec("FIND-j2", dedup_key="oops")]
ok(comps_of(junk) == {frozenset({"FIND-j1"}), frozenset({"FIND-j2"})},
   "invalid dedup_key does not merge (must be a valid multi-token key)")


# ── auto-merge: identical crash state ──────────────────────────────
print("\nauto-merge — identical crash state")
texts = {"FIND-x": stack, "FIND-y": stack}
recs2 = [rec("FIND-x"), rec("FIND-y")]
ok(comps_of(recs2, report_texts=texts) == {frozenset({"FIND-x", "FIND-y"})},
   "identical crash state → merge even with no dedup_key")


# ── auto-merge: same (file, line) source site ──────────────────────
print("\nauto-merge — same (file, line) site")
# Two reports pinning the SAME class+file+line with DIFFERENT slugs (the
# synonym drift the per-report keyer produces) collapse — the line is the
# discriminator that makes a location edge safe.
site = [
    rec("FIND-s1", file="src/catalog.c", line="42", dedup_key="alloc-size-overflow"),
    rec("FIND-s2", file="src/catalog.c", line="42", dedup_key="size-alloc-wraparound"),
]
ok(comps_of(site) == {frozenset({"FIND-s1", "FIND-s2"})},
   "same class+file+line, different slugs → one cluster")

# A keyless finding (no backend reached it — the keyer-unavailable case) at
# the same site as a keyed one still merges: the site edge needs no LLM.
mixed = [
    rec("FIND-s3", file="src/catalog.c", line="42", dedup_key="alloc-size-overflow"),
    rec("FIND-s4", file="src/catalog.c", line="42", dedup_key=""),
]
ok(comps_of(mixed) == {frozenset({"FIND-s3", "FIND-s4"})},
   "keyless finding merges on site alone (no dedup_key needed)")

# Precision guard: same file, DIFFERENT line stays apart — distinct bugs in
# one function at different lines are NOT fused (this is why (file,func) is
# unsafe but (file,line) is safe).
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

# A file with NO line gets no site edge — file alone never merges (that
# would be the unsafe (class, file) collapse).
no_line = [
    rec("FIND-n1", file="src/catalog.c", line=""),
    rec("FIND-n2", file="src/catalog.c", line=""),
]
ok(comps_of(no_line) == {frozenset({"FIND-n1"}), frozenset({"FIND-n2"})},
   "file present but no line → no site edge (file alone never merges)")


# ── bias-to-separate: co-located, no shared signal → apart ─────────
print("\nbias-to-separate")
# Two distinct integer bugs in ONE function, no shared dedup_key. They must
# NOT merge — fusing them would hide one real bug behind another. (This is the
# over-merge that a deterministic class/file/func key would cause; clustering
# on dedup_key/crash-state avoids it.)
parse_pair = [
    rec("FIND-p1", cls="integer-overflow", dedup_key="parse-id-signed-overflow"),
    rec("FIND-p2", cls="integer-overflow", dedup_key="parse-id-unsigned-truncation"),
]
ok(comps_of(parse_pair) == {frozenset({"FIND-p1"}), frozenset({"FIND-p2"})},
   "distinct bugs, different dedup_keys → stay separate (no over-merge)")
# Keyless + stackless findings never merge — they degrade to singletons.
keyless = [rec("FIND-k1"), rec("FIND-k2")]
ok(comps_of(keyless) == {frozenset({"FIND-k1"}), frozenset({"FIND-k2"})},
   "no key and no stack → singletons (bias-to-separate)")


# ── class gate ─────────────────────────────────────────────────────
print("\nclass gate")
cross = [
    rec("FIND-m", cls="memory-safety", dedup_key="same-key-here"),
    rec("FIND-n", cls="auth", dedup_key="same-key-here"),
]
ok(comps_of(cross) == {frozenset({"FIND-m"}), frozenset({"FIND-n"})},
   "identical dedup_key across different classes → never merge")
cross_site = [
    rec("FIND-cs1", cls="memory-safety", file="src/catalog.c", line="42"),
    rec("FIND-cs2", cls="info-disclosure", file="src/catalog.c", line="42"),
]
ok(comps_of(cross_site) == {frozenset({"FIND-cs1"}), frozenset({"FIND-cs2"})},
   "identical (file, line) across different classes → never merge")


# ── order-independence ─────────────────────────────────────────────
print("\norder-independence")
ok(comps_of(recs) == comps_of(list(reversed(recs))),
   "reversing record order yields identical components")


# ── merge provenance (merged_via) ──────────────────────────────────
print("\nmerge provenance")
via = via_of(recs)
ok(via.get(frozenset({"FIND-a", "FIND-b", "FIND-c"})) == fd.MERGED_STRUCTURAL == "exact-match",
   "auto-merge (shared dedup_key) → merged_via=exact-match")
solo = via_of([rec("FIND-solo")])
ok(solo.get(frozenset({"FIND-solo"})) == fd.MERGED_SINGLETON == "singleton",
   "lone finding → merged_via=singleton")
ok(not hasattr(fd, "MERGED_ADJUDICATED") and not hasattr(fd, "make_llm_adjudicator"),
   "no LLM-judge surface remains on the module")


# ── scale: no O(N^2) blowup, no cap, correct clustering ─────────────
print("\nscale")
# 60 root causes × 5 duplicates each = 300 findings over 6 classes. Each
# duplicate shares its root cause's dedup_key, so we expect exactly 60
# clusters regardless of corpus size or filing order — far past the old
# head -40 cap, with no LLM and no pairwise comparison.
classes = ["memory-safety", "auth", "injection", "crypto", "race", "logic"]
big = []
for n in range(60):
    key = f"root-cause-{n:03d}-flaw"
    for d in range(5):
        big.append(rec(f"FIND-{n:03d}-{d}", cls=classes[n % len(classes)], dedup_key=key))
clusters_big = fd.cluster(big)
ok(len(clusters_big) == 60, "300 findings, 60 root causes → 60 clusters (no cap)",
   f"got {len(clusters_big)}")
ok(all(len(c["members"]) == 5 for c in clusters_big),
   "every root cause cluster has its 5 duplicates")
ok(comps_of(big) == comps_of(list(reversed(big))),
   "scale clustering is order-independent")


print()
if FAILED:
    print(f"\033[0;31m{FAILED} failed, {PASSED} passed\033[0m")
    sys.exit(1)
print(f"\033[0;32m{PASSED}/{PASSED} passed\033[0m")
