# Deduplication

The same bug is usually found many times: through different inputs,
callers, agents, or backends. TokenFuzz handles those repeats at three
points, from the strictest to the loosest:

| When | What happens | Rule |
| --- | --- | --- |
| Filing | `bin/probe` refuses to file a second crash bundle | Identical crash state through an identical probe route |
| Triage | A duplicate is folded under the artifact it repeats | Identical crash state and route as a `reportable` bundle, a byte-identical sanitizer report, or a memory-safety finding at a filed crash's exact line |
| Clustering | Index rows group matching reports; nothing moves | Crashes: similar primitive and stack state. Findings: identical site or crash state |

Filing and triage remove true repeats, so a second reproducer of one
execution does not buy another review. Clustering only groups what remains,
with a *canonical* member per group. A cluster is a review aid, not proof of
root-cause or fix equivalence: one defect can split when it reaches
different sinks, and distinct defects can merge when they share a sink.

Crashes and findings cluster differently because they carry different
evidence. A crash has a sanitizer stack, so `bin/cluster-crashes` compares
primitives and function-level stack states by similarity. A finding is a
written report, usually without a stack, so `bin/cluster-findings` matches
exactly on `(class family, file, line)` or a line-exact crash state. The two
tools are independent, and neither involves a model. Triage does move
artifacts between lanes before clustering (see
[Triage-time folding](#triage-time-folding)).

## Crash clustering

`bin/cluster-crashes` groups every `crashes/CRASH-*` directory, in any
review state; folded duplicates and rejected crashes are left out. It
compares ClusterFuzz-style **crash states** (the normalized top interesting
frames) by similarity rather than demanding one exact bucket.

### How it works

1. **Normalize the stack** of the first sanitizer diagnostic that has one:
   demangle it, drop runtime, interceptor, allocator, libc, and C++
   standard-library frames, and strip argument lists, ABI suffixes, and
   addresses. An unsymbolized frame keeps `module+offset`.
2. **Classify the primitive.** ASan reports keep their class and access
   direction (`heap-buffer-overflow-WRITE`); UBSan uses its check kind
   (`ubsan-<kind>`); MSan, TSan, and Go faults get their own names. Two
   crashes merge only when their primitives match, except that two lifetime
   diagnostics (both with a "freed by" stack) skip this check, so a
   use-after-free and a double free of the same free site join one cluster.
3. **Build the state** from the top three interesting frames, by function
   name only; line numbers are not part of it. For a lifetime bug the state
   comes from the "freed by" stack, because the defect is the free that left
   an owner dangling, and the later use is only where it was noticed. The
   index then shows the free site followed by `(use: …)`.
4. **Require the same faulting function.** Both crashes must fault in the
   same leaf function. The one allowance is inlining: one symbolizer may
   expand inlined frames that another folds into the outer function, and
   those renderings match.
5. **Compare the rest.** Identical states merge. Otherwise the crashes merge
   when the shared leaf plus the next two callers have a longest common
   subsequence of at least two frames: in practice, the same faulting
   function and at least one common caller in order
   (`CLUSTER_LCS_THRESHOLD` changes the two). A crash with an expanded
   inline chain must match every expanded member already in the group.

Grouping is greedy in directory-name order: each crash joins the first group
whose representative it matches.

Because the state is function-level, two faults on different lines of one
function that share a caller land in one cluster. Finding clustering is
stricter and keys on the exact line.

??? note "Fuzzy matching and fallback states"
    Per-line fuzzy similarity exists only as an opt-in mode
    (`CLUSTER_FUZZY_MATCH=1`, threshold `CLUSTER_FUZZY_THRESHOLD`, default
    `0.9`). It also applies to primitive names, so it can merge a READ with a
    WRITE of the same class.

    If no interesting frame survives normalization, the state falls back to
    an exact `fallback:` key built from a report location (the `Location`,
    `Target`, or `Crash site` field, or else the sanitizer summary) and an
    object (such as the ASan stack object). Fallback states merge only when
    they are identical and the primitives match. With no such signal at
    all, the state is `pending:<CRASH id>`, and the crash stays a cluster of
    its own.

### Examples

```text
Crash 1 stack (raw):                         Crash 2 stack (raw):
  #0 __asan_memcpy            (ignored)        #0 __asan_memcpy           (ignored)
  #1 proj::Store::set_blob(unsigned)           #1 proj::Store::set_blob(unsigned int)
  #2 proj::Engine::apply_line(char const*)     #2 proj::Engine::apply_line(char const*)
  #3 proj::Script::run_file(char const*)       #3 proj::Script::run_file(std::string const&)
  #4 __libc_start_main        (ignored)        #4 start_thread            (ignored)

  crash state (top 3 interesting):             crash state (top 3 interesting):
    [proj::Store::set_blob,                      [proj::Store::set_blob,
     proj::Engine::apply_line,                    proj::Engine::apply_line,
     proj::Script::run_file]                      proj::Script::run_file]

→ SAME cluster. The argument lists are normalized away and the states match.
```

```text
Crash A: state [parse_id, read_record, run]
Crash B: state [decode_body, read_record, run]
→ DIFFERENT clusters: two shared callers, but the faulting function differs.
```

### Output

`bin/cluster-crashes <results-dir>` writes `crashes/crash-clusters.md` and
`crashes/crash-clusters.html`, one row per cluster, and stamps two lines into
each member's `report.md`:

```text
Cluster: CL-4b21c7de (3 reports: CRASH-002-1, CRASH-004-2)
Dedup frames: <the top-three frame chain with source locations>
```

A cluster of one reads `Cluster: CL-… (singleton)`. The stamp names the
other members, not which one is canonical.

The **Canonical** member is the highest-severity crash, with the CVSS score
and then the lowest id breaking ties. It is listed first, in bold, and rows
are sorted by the canonical member's severity and score, then cluster size.

The cluster id is `CL-` plus eight hex digits of a hash of the
representative's primitive and crash state. The representative is the crash
that opened the group in directory-name order, so severity never changes the
id, but a new crash that sorts earlier can. The id is deterministic for the
same set of crashes; it is not a universal root-cause identifier.

## Finding clustering

A finding is a written report, usually with no stack trace, so
`bin/cluster-findings` reduces every `findings/FIND-*` report, in any review
state, to a few signals and clusters by **exact equality**: no fuzzy
matching and no similarity threshold.

The signals come from the report itself, with one exception: once the
substance gate has accepted the finding, the class its accepting reviewer
assigned replaces the report's own `Class`.

### The two merge signals

Two findings merge if they share **either** of:

- **site** `(class family, file, line)`: the same class family at the same
  source line;
- **crash state**: the same line-exact top three frames of a sanitizer stack
  quoted in the report text, for the minority of findings that carry one. A
  `sanitizer.txt` beside the report is not read.

The site's file and line come from the report's `File` and `Line` fields
when present, then from its `Location:` line, then from the first
`file:function:line` cited in prose outside code blocks. Paths are made
target-relative, so `targets/<slug>/src/calc.c` and `src/calc.c` are the same
file.

The signals compose: if A and B share a site and B and C share a crash
state, all three land in one cluster. That is the whole algorithm, and the
same input always produces the same clusters.

### Why the class is normalized first

One defect is legitimately both its *mechanism* and its *consequence*: an
integer overflow that leads to an out-of-bounds write is filed by one
reviewer as `integer-overflow` and by another as `oob-write`. Left raw, that
disagreement would split one bug into two clusters. So only the class's
**family** enters the key: `memory-safety`, `dos`, `injection`,
`deserialization`, `auth`, `crypto`, `info-disclosure`, `race`, `boundary`,
`config`, `logic`, or `other` (see [Bug classes](../reference/bug-classes.md)).
Aliases resolve first, and an unknown label containing `overflow` lands in
`memory-safety`. The Class column still shows the canonical class.

### Why location merges by line, never by function

The site is `(file, line)`, never `(file, function)`:

- A single **function** routinely hosts several distinct bugs: an integer
  overflow on one line and an unrelated out-of-bounds read forty lines down.
  Merging on `file:function` would hide one behind the other.
- A **source line** is a more precise identity, but it can still hold
  several operations, so a shared line is a deduplication rule, not proof
  that two reports need the same fix.

A finding that names a file but **no line** therefore gets no site edge and
stays its own cluster, rather than collapsing onto a coarse `(class, file)`
bucket. This is **bias-to-separate**: a wrong split shows a reviewer two
clusters to join by eye (cheap); a wrong merge hides a real bug (costly).

### Examples

```text
Same line, different class labels → ONE cluster
  FIND-d  class=integer-overflow  src/calc.c:88
  FIND-e  class=oob-write         src/calc.c:88
  both key on (memory-safety, src/calc.c, 88)

Same function, different lines → TWO clusters
  FIND-p1  src/parse.c:114   class=heap-buffer-overflow
  FIND-p2  src/parse.c:152   class=heap-buffer-overflow

A shared stack is a second edge → ONE cluster
  FIND-x  (no line)        crash state [render_draw render.c:77,
                                        render_frame render.c:210,
                                        app_run app.c:31]
  FIND-y  src/render.c:77  the same crash state

No site and no stack → a singleton, never force-merged
  FIND-z  class=cors-misconfig   (no file/line, no stack)
```

### Output

`bin/cluster-findings <results-dir>` writes `findings/finding-clusters.md`
and `findings/finding-clusters.html`, and stamps two lines into each member
report:

```text
Cluster: FCL-8c19a032 (2 reports: FIND-007-1) (canonical)
Dedup key: [loc] src/policy.c:142
```

The role suffix is `(canonical)` or `(duplicate of FIND-…)`, or
`(singleton)` alone. The key kind is `loc`, `title` for a report with no
location, or `missing` for a directory with no report. Every non-canonical
member also gets a `.dup-of` marker naming the canonical FIND.

The **Canonical** member is chosen by, in order:

1. security credit: a `reportable` or pending finding outranks a retained
   `not-reportable` one;
2. proven evidence: a report whose CVSS vector carries `E:P` or `E:A` (a
   reproducer that fires) outranks an argued one;
3. severity;
4. lowest id.

So a proven Low can represent an unproven Critical in the same cluster. Rows
are sorted by the canonical member's severity, then cluster size.

The **Signature** column shows the canonical member's merge signals, or,
with neither, a display key (`file:function` or a title slug) that is never
a merge edge. The id is `FCL-` plus eight hex digits of a hash of the
canonical member's key **and its id**, so two clusters kept apart never
share an id. Every multi-member cluster was merged on an identical site or
crash state; there is no probabilistic tier.

## Cross-backend indexes

Pointed at a target output root (`output/<target>/`), either tool aggregates
every backend's results into `output/<target>/crash-clusters.{md,html}` or
`finding-clusters.{md,html}`, with member ids prefixed by `<backend>/`.
During an audit, housekeeping runs this pass whenever results change. The
crash pass writes only the target-level index, but the finding pass also
restamps each member's `Cluster:` line and `.dup-of` marker, so a finding's
stamp can name a different `FCL-` id from its row in the backend-local
index.

## Filing-time refusal

When `bin/probe` would file a confirmed crash, it first looks for a filed
duplicate. It refuses when `crashes/` already holds a bundle with the same
**crash state** reached through the same **probe route**, whatever that
bundle's review state:

- The crash state is the sanitizer, the fault kind (with access direction
  for ASan), up to three line-exact frames of the use stack, and, for a
  lifetime diagnostic, up to three frames of the free stack. It is at least
  as fine as a crash cluster.
- The route is the sanitizer, execution mode, API harness (by content hash),
  target arguments, and alternate build configuration. Testcase bytes are
  deliberately excluded.

The probe prints:

```text
[probe] CRASH DUPLICATE: identical crash state and probe route are already filed as <crash dir> (<review state>) - not filed. ...
```

where the review state is `promoted`, `reviewed, not reportable`, or `under
review`. A different route or build is filed, because it can establish a
different boundary or severity even when it reaches the same internal
fault. A bundle with no recorded route never absorbs another, a diagnostic
with no parseable frames is never treated as a duplicate, and a rejected
bundle has left `crashes/` and absorbs nothing.

The check does not wait for review. A second reproducer of an identical
state through an identical route cannot earn a different verdict: the same
frames cross the same boundary the same way. When filing waited for
promotion, agents re-filed the same crash for as long as review lagged.

A crash whose diagnostic triage rejects outright (`null-deref`,
`stack exhaustion`, `resource exhaustion`, and the other classes in
[Common rejection reasons](../guides/triage-results.md#common-rejection-reasons))
is never filed, on an exploration run or under `--confirm`: the probe prints
`[probe] CRASH NOT FILED: <reason>` and records the reason as the run's
`not_filed`, so queue feedback reads the run as rejected and the card gates do
not count it as a crash. A bundle would only buy a report whose rejection the
sanitizer text already decides.

Two narrower checks run first: re-confirming the same bytes through the same
route reuses the existing bundle, and an agent that edits its harness and
re-confirms the same hypothesis and crash state refreshes its own
unexported bundle.

The same lookup warns agents before they file. An exploration probe that
repeats a filed state prints `[probe] CRASH STATE ALREADY FILED`,
`bin/state resume` lists the crash states already filed, and
`bin/state add-hyp` names filed crashes and live hypotheses at the same
function. These notices are advice: a testcase aimed past a filed crash
reshapes its input, and a different mechanism at the same function is a new
bug.

??? note "Where repeats are recorded"
    Each sanitizer crash row in `state/runs.jsonl` carries `duplicate_of`,
    naming the owning bundle for a repeat or empty for a new state.
    Benchmark telemetry counts those rows as `filed_state_repeats`; a ledger
    older than the field reports it as unknown, not zero.

## Triage-time folding

Triage folds duplicates that filing could not catch:

- **A promoted crash state.** A pending bundle whose crash state and probe
  route match a currently `reportable` bundle moves to
  `crashes/.duplicates/` with a `duplicate-of.txt` naming the owner, and its
  hypothesis closes with the owner's CRASH id, without review. Only a
  `reportable` bundle absorbs others here, and a bundle without route
  metadata is reviewed normally.
- **Siblings under review.** When several pending bundles share a state and
  route and none is promoted yet, the earliest filed is reviewed first and
  the rest wait. If it is promoted, they fold into it; otherwise each is
  reviewed on its own merits in the same pass.
- **A finding's copy of a filed crash.** A finding with its own sanitizer
  diagnostic and runnable testcase normally moves to `crashes/` for crash
  triage. When a bundle in `crashes/` holds a byte-identical sanitizer
  report, the finding folds into `crashes/.duplicates/` instead: a
  probe-written report carries its run header and process id, so an
  identical copy is the same execution. Matching input bytes are not
  enough, because another build or harness is another route.
- **Companion findings.** A memory-safety finding at the exact
  target-relative file and line of a filed crash (in `crashes/` or
  `crashes-rejected/`) moves under that crash as `.companion/<FIND-id>/`.
  The crash carries the reproducer and owns the verdict; the finding's
  argument stays beside it. When both name a function, the functions must
  agree too. Pinned findings are not moved.

Bundles in `.duplicates/` count as neither results nor rejections.
[Triage and review](../guides/triage-results.md#common-rejection-reasons)
covers what happens to the bundles that remain.
