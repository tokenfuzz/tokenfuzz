# Deduplication

An audit run produces two kinds of duplicate-prone artifacts:

- **Crashes** — sanitizer aborts captured by the probe runner, under
  `output/<target>/<backend>/results/crashes/CRASH-*/`.
- **Findings** — security issues filed by agents and recon, under
  `output/<target>/<backend>/results/findings/FIND-*/`.

The same bug is usually discovered many times — reached through different
inputs, callers, or by different agents. Deduplication collapses those
re-discoveries into one **cluster** per root cause, so a reviewer sees each
real bug once, with a *canonical* representative and the duplicates linked to
it.

The two artifact types use **different** strategies, because they carry
different evidence:

| | Crashes | Findings |
|---|---|---|
| Evidence | a sanitizer **stack trace** | a written **report** (often no stack) |
| Strategy | ClusterFuzz **stack-state bucketing** | **exact-match clustering** on `(class, file, line)` or crash state |
| Owner | `bin/cluster-crashes` | `bin/cluster-findings` + [`lib/finding_dedup.py`](https://github.com/tokenfuzz/tokenfuzz/blob/main/lib/finding_dedup.py) + [`lib/finding_signature.py`](https://github.com/tokenfuzz/tokenfuzz/blob/main/lib/finding_signature.py) |

They are independent: nothing in the findings path can change crash
bucketing, and vice versa.

---

## Crash deduplication

A crash always comes with a sanitizer stack trace, so crashes dedup the
way ClusterFuzz does: by the **crash state** — the top few *interesting*
stack frames, normalized.

Owned by `bin/cluster-crashes`, reusing [`lib/stack_frames.py`](https://github.com/tokenfuzz/tokenfuzz/blob/main/lib/stack_frames.py) and the
upstream-derived [`lib/clusterfuzz_stacktrace.py`](https://github.com/tokenfuzz/tokenfuzz/blob/main/lib/clusterfuzz_stacktrace.py).

### How it works

1. **Parse** the ASan/UBSan/MSan stack into frames (`#0 in func file:line`).
2. **Drop noise frames** — libc, the sanitizer runtime, allocator
   shims — via ClusterFuzz's ignore-regex list. What remains are the
   *interesting* frames: the target's own code.
3. **Normalize each function name** (`filter_function_name`): strip the
   argument list, anonymous-namespace markers, and `[abi:...]` tags, so
   `Store::set_blob(unsigned int)` and `Store::set_blob` are one symbol.
4. **Take the top three** interesting frames—the *crash state*. Two crashes
   with the same crash state **and the same
   sanitizer primitive** (e.g. `heap-buffer-overflow READ`) are the same
   bug; identical stacks that report different primitives do not merge.
5. **Bucket** crashes by that (primitive, crash state) pair. Near-identical
   stacks that differ only in deep tail frames can still group through a
   longest-common-subsequence comparison of the top frames.

Crucially, the crash state **stops at allocation stacks** — the "freed
by" / "previously allocated by" sections of a use-after-free report are
*not* part of the state, so a UAF buckets by where it crashes, not where
the memory happened to be freed.

### Test-style example

```text
Crash 1 stack (raw):                         Crash 2 stack (raw):
  #0 __asan_memcpy            (ignored)        #0 __asan_memcpy           (ignored)
  #1 proj::Store::set_blob(unsigned)           #1 proj::Store::set_blob(unsigned int)
  #2 proj::Engine::apply_line(char const*)     #2 proj::Engine::apply_line(char const*)
  #3 proj::Script::run_file(char const*)       #3 proj::Script::run_file(std::string const&)
  #4 __libc_start_main        (ignored)        #4 start_thread            (ignored)

  crash state (top 3 interesting):             crash state (top 3 interesting):
    [set_blob, apply_line, run_file]             [set_blob, apply_line, run_file]

→ SAME bucket. The argument-list difference is normalized away; only the
  three interesting frames count, and ignored runtime frames do not consume
  that frame budget.
```

```text
Crash A: state [parse_id, read_record, run]
Crash B: state [decode_body, read_record, run]
→ Different crash sites → DIFFERENT buckets, even though the deeper frames
  overlap.
```

### Output

`bin/cluster-crashes` writes `CRASH-CLUSTERS.md` (one row per cluster, sorted
by max-member severity then size) and stamps a `Cluster:` line into each
member `REPORT.md`. Each row names a **Canonical** member — the
highest-severity crash in the cluster (the CVSS score breaks ties within a
severity band, then lowest id) — and the
**Members** column lists every crash sharing the root cause, ordered by
severity descending with the canonical in **bold**. This mirrors
`bin/cluster-findings`, so both pages pick and present the canonical the same
way. The `CL-<hash>` cluster id stays anchored on the bucket's crash state, so
it is stable regardless of which member is most severe.

---

## Findings deduplication

A finding is a *written report*, usually with **no stack trace** (especially
recon / source-analysis findings), so the crash strategy doesn't apply.
`bin/cluster-findings` (engine in [`lib/finding_dedup.py`](https://github.com/tokenfuzz/tokenfuzz/blob/main/lib/finding_dedup.py)) reduces every
finding to a small set of **signals parsed from its report alone**, then
clusters by **exact equality** — no LLM call, no fuzzy matching, no similarity
threshold.

### One identity, every source

Identity is a pure function of the report, computed in **one place**
(`bin/cluster-findings`). It does not depend on *how* the finding was produced,
so a harness-agent finding, a recon-materialized finding, and a model-direct
(bare-prompt baseline) finding are all keyed the same way and land in the same
identity space. There is no per-source path and no pre-filing location dedup —
a recon finding and an agent's re-discovery of the same bug collapse here, at
cluster time, like any other duplicate.

### The two merge signals

Two findings merge if they share **either** of:

- **`(class, file, line)`** — the same normalized issue class at the same
  source line. Deterministic, no LLM.
- **crash state** — the same ClusterFuzz-normalized top stack frames, on the
  minority of findings that embed a sanitizer stack (reused from
  [`lib/stack_frames.py`](https://github.com/tokenfuzz/tokenfuzz/blob/main/lib/stack_frames.py)).

A [**union-find**](https://en.wikipedia.org/wiki/Disjoint-set_data_structure)
over those edges produces one cluster per root cause; the signals compose, so
if A and B share a site and B and C share a crash state, all three land in one
cluster. The canonical member is chosen by **evidence first, then severity,
then id**: a finding backed by a proven exploit or reproducer outranks an
unproven one *even if the unproven one scores higher* — so a proven Low can be
canonical over an unproven Critical. Severity breaks ties among equally-proven
members, and lowest lexicographic id breaks the rest.

That is the whole algorithm: union on exact equality of either signal. No
similarity threshold, no *O(N²)* scan, no cap on distinct root causes — order
-independent and recomputable from stored evidence.

### Why the class is normalized first

The same defect is legitimately both its *mechanism* and its *consequence*:
an integer overflow that leads to an out-of-bounds write is filed by one
reviewer as `integer-overflow` and by another as `memory-safety`. Left raw,
that disagreement would split a true duplicate at one line into two clusters.

So [`lib/finding_signature.py`](https://github.com/tokenfuzz/tokenfuzz/blob/main/lib/finding_signature.py) **normalizes the class before it
becomes part of the key.** A small canonical vocabulary
(`memory-safety`, `auth`, `injection`, `info-disclosure`, `crypto`, `race`,
`dos`, `logic`, …) absorbs label drift, and one broad structural rule does the
heavy lifting: **any `*overflow*` label folds into `memory-safety`** — the
mechanism collapses into its consequence, so the two reviewers' labels agree
and their findings merge.

### Why location merges by line, never by function

The source site is `(file, line)`, never `(file, func)`:

- A single **function** routinely hosts several *distinct* bugs — a parser
  might have an integer overflow on one line and an unrelated out-of-bounds
  read forty lines down. Merging on `file:func` would fuse them and hide one
  bug behind the other.
- A single **source line** is one statement. Two findings that pin the same
  class and the same line are almost always the same defect.

A finding that pins a file but **no line** therefore gets *no* site edge — it
stays its own cluster rather than collapsing onto a coarse `(class, file)`
bucket. This is **bias-to-separate**: wrongly splitting only shows a reviewer
two clusters to mentally join (cheap); wrongly merging hides a real bug
(costly).

### The display label

Each cluster reports a **class** (its canonical member's, normalized) for the
table's Class column. A second display field, **`(class, file, func)`**, fills
the Signature column when a finding has no line — it anchors the cluster id but
is never a merge edge.

### Examples

**Same line, different class labels — they still merge:**

```text
  FIND-d  class=integer-overflow  src/calc.c:88
  FIND-e  class=memory-safety     src/calc.c:88
→ integer-overflow normalizes to memory-safety, so both key on
  (memory-safety, src/calc.c, 88) → ONE cluster. The mechanism-vs-consequence
  split is absorbed before the key is built.
```

**Same function, different lines — two real bugs, kept apart:**

```text
  FIND-p1  src/parse.c:114   class=memory-safety
  FIND-p2  src/parse.c:152   class=memory-safety
→ same file and function, but different lines → TWO clusters. Merging on
  file:func would have fused two distinct bugs; the line keeps them apart.
```

**A finding with a stack — the crash state is a second edge:**

```text
  FIND-x  (no file/line)   crash state [render_draw, main_loop]
  FIND-y  src/render.c:77  crash state [render_draw, main_loop]
→ even though FIND-x pins no source line, the shared crash state merges them
  → ONE cluster. The Signature column shows both signals, joined by ` or `.
```

**A siteless, stackless finding stays its own cluster:**

```text
  FIND-z  class=config   (no file/line, no stack)
→ nothing to key on but the title → a singleton, never force-merged.
```

These cases are pinned in [`tests/test_finding_dedup_py.py`](https://github.com/tokenfuzz/tokenfuzz/blob/main/tests/test_finding_dedup_py.py) and
[`tests/test_cluster_findings.sh`](https://github.com/tokenfuzz/tokenfuzz/blob/main/tests/test_cluster_findings.sh).

### Output

`bin/cluster-findings` writes `FINDING-CLUSTERS.md` (one row per cluster,
sorted by max-member severity then size), stamps a `Cluster:` line into
each member report, and drops a `.dup-of` marker in every non-canonical
member pointing at the canonical FIND. The canonical is picked by
evidence rank first, then severity, then lexicographic id (see above).

Every merge is deterministic: a multi-member cluster was auto-merged on an
identical `(class, file, line)` site or normalized crash state, and a
one-member cluster is a singleton. There is no probabilistic tier to flag.
