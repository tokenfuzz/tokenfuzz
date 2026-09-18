# Review coverage

A clean run answers "what did the agents find?" but not "what did they never
look at?". The ranked queue is a bounded window over the source tree, so a
file outside the window has no card, and a card rewritten out of the window
leaves no trace in `work-cards.jsonl`. This page explains the ledger that
makes the untouched share visible.

## The manifest

Every ranking pass enumerates the auditable source tree before it scores
anything. That enumeration is now persisted as `state/manifest.jsonl`, one
row per file:

| Field | Meaning |
| --- | --- |
| `file` | Target-relative path. |
| `lines`, `bytes`, `sha1` | Identity of the content the row describes. A rerank re-hashes only files whose size or modification time changed. |
| `subsystem` | The same partition the queue uses for diversity. |
| `card_id` | The id the ranker mints for the file's primary card, so claims resolve to files even after the queue is rewritten. |
| `offered` | Whether the file has ever entered the ranked window. Sticky across rewrites: a file that left the window was still handed to the run. |
| `scope` | `tree` for a whole-tree audit, `delta` for `bin/audit --since <rev>`, where the manifest lists only the delta's files. |

The manifest is written from the same walk that produces the cards, so the
two cannot disagree about what is in scope. It is a materialized view,
rewritten atomically on every pass, not an append-only ledger.

## The report

```bash
bin/state --results-dir "$RESULTS" coverage
bin/state --results-dir "$RESULTS" coverage --depth 3 --format json
```

The report joins the manifest to `state/claims.jsonl` and groups by
directory:

- **Files** the ranker enumerated, with their line total.
- **Offered**: files that ever entered the ranked window.
- **Claimed**: files a session picked up a card on. A claim on a companion
  card or a patch card resolves to its file, so this is independent of
  `offered` rather than a subset of it.

Directories are listed least-covered first, and the largest files that were
never offered nor claimed are named, because those are what an operator acts
on: widen `RANK_WORK_LIMIT`, pin a lane, or run a delta over that directory.

## What it does and does not say

"Offered" and "claimed" are what the harness handed out. Neither proves an
agent read the file, and a claim is not a verdict on the file's contents. The
number to read a clean result against is the never-offered share: a tree
where most files were never in the window has been sampled, not reviewed,
and a clean result over it is silence, not evidence.

The benchmark telemetry carries the same totals as `coverage.tree`, beside the
per-lane card shares, so a run report shows how much of the tree its window
reached.
