# Deduplication

An audit run produces two kinds of duplicate-prone artifacts:

- **Crashes** — sanitizer aborts captured by the probe runner, under
  `output/<target>/<backend>/results/crashes/CRASH-*/`.
- **Findings** — security issues filed by agents and recon, under
  `output/<target>/<backend>/results/findings/FIND-*/`.

The same bug is usually discovered many times — reached through different
inputs, callers, or by different agents. Deduplication collapses those
re-discoveries into one **cluster** per root cause so a reviewer sees each
real bug once, with a *canonical* representative and the duplicates linked
to it.

The two artifact types use **different** dedup strategies, because they
carry different evidence:

| | Crashes | Findings |
|---|---|---|
| Evidence | a sanitizer **stack trace** | a written **report** (often no stack) |
| Strategy | ClusterFuzz **stack-state bucketing** | **deterministic clustering** (dedup_key · source site · crash state) |
| Owner | `bin/cluster-crashes` | `bin/cluster-findings` + `lib/finding_dedup.py` + `lib/finding_keyer.py` |

They are independent: nothing in the findings path can change crash
bucketing, and vice versa.

---

## Crash deduplication

A crash always comes with a sanitizer stack trace, so crashes dedup the
way ClusterFuzz does: by the **crash state** — the top few *interesting*
stack frames, normalized.

Owned by `bin/cluster-crashes`, reusing `lib/stack_frames.py` and the
upstream-derived `lib/clusterfuzz_stacktrace.py`.

### How it works

1. **Parse** the ASan/UBSan/MSan stack into frames (`#0 in func file:line`).
2. **Drop noise frames** — libc, the sanitizer runtime, allocator
   shims — via ClusterFuzz's ignore-regex list. What remains are the
   *interesting* frames: the target's own code.
3. **Normalize each function name** (`filter_function_name`): strip the
   argument list, anonymous-namespace markers, and `[abi:...]` tags, so
   `Store::set_blob(unsigned int)` and `Store::set_blob` are one symbol.
4. **Take the top N** interesting frames (`MAX_CRASH_STATE_FRAMES`) — the
   *crash state*. Two crashes with the same crash state are the same bug.
5. **Bucket** crashes by crash state. Near-identical stacks that differ
   only in deep tail frames still group via a longest-common-subsequence
   comparison of the top frames.

Crucially, the crash state **stops at allocation stacks** — the "freed
by" / "previously allocated by" sections of a use-after-free report are
*not* part of the state, so a UAF buckets by where it crashes, not where
the memory happened to be freed.

### Test-style example

```text
Crash 1 stack (raw):                         Crash 2 stack (raw):
  #0 __asan_memcpy            (ignored)        #0 __asan_memcpy           (ignored)
  #1 proj::Store::set_blob(unsigned)           #1 proj::Store::set_blob(unsigned int)
  #2 proj::Engine::apply_line(char const*)     #2 proj::Engine::run(int)
  #3 main                                      #3 main

  crash state (top 2 interesting):             crash state (top 2 interesting):
    [set_blob, apply_line]                       [set_blob, run]

→ Same #0-equivalent crash site (set_blob), overlapping top frames
  → SAME bucket. The argument-list difference is normalized away; the
    ignored __asan_memcpy frame never counts.
```

```text
Crash A: state [parse_id, run]      Crash B: state [decode_body, run]
→ Different crash sites → DIFFERENT buckets, even though both end in run().
```

---

## Findings deduplication

A finding is a *written report*, usually with **no stack trace** (especially
recon / source-analysis findings), so the crash strategy doesn't apply.
`bin/cluster-findings` (engine in `lib/finding_dedup.py`) reduces every finding
to a few **signals computed from its report alone**, then clusters by exact
equality on any of them — no pairwise comparison, no similarity threshold.

### One identity, every source

The single most important property: identity is a pure function of the report,
computed in **one place** (`bin/cluster-findings`). It does not depend on *how*
the finding was produced, so a harness-agent finding, a recon-materialized
finding, and a model-direct (bare-prompt baseline) finding are all keyed the
same way and land in the same identity space. There is no per-source path and
no pre-filing location dedup — a recon finding and an agent's re-discovery of
the same bug collapse here, at cluster time, like any other duplicate.

### Signals

`lib/finding_signature.py` + `lib/finding_keyer.py` reduce each finding to a
handful of fields, all parsed from the report itself. Three of them can
**merge** two findings; one is for display only.

- **class** — normalized issue class (`memory-safety`, `auth`, …; the accepted
  find-quality class is a hint when present). A hard **gate**: findings in
  different classes never merge, whatever else they share.
- **dedup_key** — a short canonical root-cause slug (e.g.
  `uint16-frame-capacity-truncation`), assigned by `lib/finding_keyer.py`: one
  cached LLM call per fresh finding, **on by default** (`--no-key` disables it).
  This is the signal that links re-discoveries reached from **different files or
  functions** — name the same root cause from two sites and you get the same
  slug. One keyer canonicalizes the whole pool, so keys stay comparable across
  the models a benchmark compares. It **no-ops without a backend**, so offline
  and in tests a finding simply has no key.
- **source site — `(file, line)`** — the exact file and line the report pins as
  the bug (the `| File |` / `| Line |` rows, or an inline `file:func:line`).
  Fully deterministic, no LLM. This links re-discoveries that land on the
  **same line** even when their slugs differ — and it is the only merge signal
  that keeps working when the keyer is offline or rate-limited.
- **crash state** — ClusterFuzz-normalized top frames (reused from
  `lib/stack_frames.py`), present only on the minority of findings that embed a
  sanitizer stack. Intrinsic to the report and model-independent.

A fifth field, **`(class, file, func)`**, is computed for *display* — it fills
the Signature column in `FINDING-CLUSTERS.md` and anchors the cluster id — but
it is deliberately **not** a merge signal. The next section explains why
location merges by *line* but never by *function*.

### Merging

Two findings merge iff, **within the same class**, they share **any one** of:

- an identical **dedup_key**, or
- an identical **source site** — the same `(file, line)`, or
- an identical **crash state**.

A **union-find** over those edges produces one cluster per root cause. The
three signals *compose*: if A and B share a key and B and C share a line, all
three land in one cluster. The canonical member is the highest-severity finding
(ties → lowest id).

That is the whole algorithm: bucket by class, union on exact equality of any
signal. No similarity threshold, no *O(N²)* scan, no cap on distinct root
causes — order-independent and recomputable from stored evidence. (Producing a
dedup_key costs one cached LLM call per fresh finding, in `.finding-key.json`;
the clustering over the cached keys, sites, and stacks is fully deterministic.)

#### Why location merges by line, never by function

`(class, file, line)` **is** a merge edge; `(class, file, func)` is **not**.
The gap between them is the whole reason location can be trusted at all:

- A single **function** routinely hosts several *distinct* bugs — a parser
  might have an integer overflow on one line and an unrelated out-of-bounds
  read forty lines down. Merging on `file:func` would fuse them and hide one
  bug behind the other.
- A single **source line** is one statement. Two findings of the same class
  that pin the same line are almost always the same defect. The line is the
  discriminator precise enough to merge on; the function is not.

This is **bias-to-separate**: wrongly splitting only shows a reviewer two
clusters to mentally join (cheap); wrongly merging hides a real bug (costly).
So location earns a merge edge only at line precision.

**Why keep both `dedup_key` and the site edge?** They catch different
re-discoveries and back each other up. `dedup_key` is the only signal that
links the same bug reached from a *different line or file* — but the slug is
LLM-authored, so two reports can drift to synonyms and miss, and it needs a
backend. The site edge links the same bug pinned at the *same line* with zero
LLM involvement, so deduplication keeps working when the keyer is rate-limited,
offline, or disabled. A finding matching none of the three signals stays its
own singleton.

### Examples

**Different sites, one root cause — `dedup_key` links them:**

```text
  FIND-a  class=memory-safety  src/store.c:212   key=uint16-frame-capacity-truncation
  FIND-b  class=memory-safety  (no file/line)    key=uint16-frame-capacity-truncation
  FIND-c  class=memory-safety  src/dfa.c:88      key=uint16-frame-capacity-truncation
→ different files, different lines, one with no location at all — only the
  shared slug ties them together → ONE cluster. The site edge can't reach this
  case; it is exactly what dedup_key is for.
```

**Same line, drifting slugs — the site edge links them:**

```text
  FIND-d  class=memory-safety  src/store.c:213   key=alloc-size-overflow
  FIND-e  class=memory-safety  src/store.c:213   key=size-alloc-wraparound
  FIND-f  class=memory-safety  src/store.c:213   key=∅ (keyer offline)
→ the LLM worded the slug three ways (one finding has no key at all), but the
  identical (class, file, line) merges all three → ONE cluster. This is what
  keeps dedup honest when slugs drift or the keyer is unavailable.
```

**Same function, different lines — two real bugs, kept apart:**

```text
  FIND-p1  class=memory-safety  src/parse.c:114   key=length-prefix-signed-overflow
  FIND-p2  class=memory-safety  src/parse.c:152   key=tag-table-index-oob
→ same file and function, but different lines AND different keys → TWO clusters.
  Merging on file:func would have fused two distinct bugs; the line keeps them
  apart.
```

These cases are pinned in `tests/test_finding_dedup_py.py` and
`tests/test_cluster_findings.sh`.

### Output

`bin/cluster-findings` writes `FINDING-CLUSTERS.md` (one row per cluster,
sorted by max-member severity then size), stamps a `Cluster:` line into
each member report, and drops a `.dup-of` marker in every non-canonical
member pointing at the canonical FIND. The canonical is the
highest-severity member, ties broken by lexicographic id.

Every merge is deterministic: a multi-member cluster was auto-merged on an
identical `dedup_key`, source site, or normalized crash stack, and a one-member
cluster is a singleton. There is no probabilistic tier to flag.
