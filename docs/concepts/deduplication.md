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
| Strategy | ClusterFuzz **stack-state bucketing** | **deterministic clustering** (dedup_key + crash state) |
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
`bin/cluster-findings` (engine in `lib/finding_dedup.py`) gives every finding
**one identity computed from its report alone**, then clusters on exact
equality of that identity — no pairwise comparison, no similarity threshold.

### One identity, every source

The single most important property: identity is a pure function of the report,
computed in **one place** (`bin/cluster-findings`). It does not depend on *how*
the finding was produced, so a harness-agent finding, a recon-materialized
finding, and a model-direct (bare-prompt baseline) finding are all keyed the
same way and land in the same identity space. There is no per-source path and
no pre-filing location dedup — a recon finding and an agent's re-discovery of
the same bug collapse here, at cluster time, like any other duplicate.

### Signals

`lib/finding_signature.py` + `lib/finding_keyer.py` reduce each finding to:

- **class** — normalized issue class (`memory-safety`, `auth`, …), parsed from
  the report (`extract_class`; the accepted find-quality class is a hint when
  present). A hard gate: findings in different classes never merge.
- **dedup_key** — a short canonical root-cause slug (e.g.
  `uint16-frame-capacity-truncation`). The **primary signal**, assigned by
  `lib/finding_keyer.py` at cluster time from the report *alone* — one cached
  LLM call per fresh finding, **on by default** (`cluster-findings --no-key`
  disables it). Because one keyer canonicalizes every finding, the key is
  independent of which model authored the report; run the keyer once over a
  pooled set and the keys are comparable across the models a benchmark pits
  against each other. The keyer **no-ops without a backend**, so offline and in
  tests a finding simply has no key and falls back to the label below.
- **crash state** — the ClusterFuzz-normalized top frames (reused from
  `lib/stack_frames.py`), present only when the report embeds a sanitizer
  stack, so it fires on the minority of findings that actually crash. Like the
  crash stack, it is intrinsic to the report and model-independent.
- **(class, file, func)** — the canonical bug site (`file` from the `| File |`
  row, `func` from ASan frame #0 when present; the `targets/<slug>/` prefix is
  stripped to a stable target-relative path). This is the deterministic
  **fallback label**: it fills the Signature column in `FINDING-CLUSTERS.md`
  and is used when a finding has no dedup_key. It is **not** a merge signal
  (see below).

### Merging

Two findings merge iff, **within the same class**, they share either an
identical **dedup_key** or an identical **crash state**. A **union-find**
over those edges gives one cluster per root cause; the canonical member is
the highest-severity one (ties → lowest id).

That's the whole algorithm: bucket by class, union on exact dedup_key /
crash-state equality. No similarity threshold, no *O(N²)* scan, no cap on
distinct root causes — order-independent and recomputable from stored
evidence. (The keying step that *produces* a dedup_key uses one LLM call per
fresh finding and caches it in `.finding-key.json`; the clustering over those
cached keys is fully deterministic.)

`(class, file, func)` is deliberately **not** a merge signal, even though it
*is* the finding's fallback label. One function routinely hosts several
distinct bugs, so fusing two findings just because they sit at the same
`file:func` would hide one behind the other. This is **bias-to-separate**:
wrongly splitting only shows a reviewer two clusters to mentally join
(cheap); wrongly merging hides a real bug (costly). A finding with neither a
dedup_key nor a crash state stays its own singleton.

### Examples

```text
Key case — one root cause, three sites (dedup_key collapses them):
  FIND-a  class=memory-safety  func=set_blob        key=uint16-frame-capacity-truncation
  FIND-b  class=memory-safety  func=∅ (no stack)    key=uint16-frame-capacity-truncation
  FIND-c  class=memory-safety  func=frame_capacity  key=uint16-frame-capacity-truncation
→ same class + dedup_key → ONE cluster, though the sites differ and one
  finding has no stack at all. The shared (file, func) label would have
  split FIND-c from the others; the dedup_key is what links them.
```

```text
Corner case — same class, file, AND func, but two distinct bugs:
  FIND-p1  class=integer-overflow  func=parse_id  key=parse-id-signed-overflow
  FIND-p2  class=integer-overflow  func=parse_id  key=parse-id-unsigned-truncation
→ identical (class, file, func) but DIFFERENT dedup_keys → TWO clusters.
  Location is only a label, never a merge edge, so two distinct bugs in one
  function are never fused.
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
identical `dedup_key` or normalized crash stack, and a one-member cluster is
a singleton. There is no probabilistic tier to flag.
