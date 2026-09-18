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

## Receipts

A claim says a card was handed out. A receipt says which lines were read:

```bash
bin/state mark-examined --agent 1 --file src/parse.c --lines 1-120,200-260
bin/state mark-examined --agent 1 --file src/parse.c --functions app_parse,app_reset
```

Receipts append to `state/receipts.jsonl`, pinned to the file's content hash
from the manifest. The harness verifies each one before recording it: the
file must be in the manifest, every range must lie inside it, and a function
name must be one the [call graph](../getting-started/prerequisites.md#experimental-call-neighbourhood-context)
parsed in that file, resolved to the lines from its definition to the next
one. A receipt that cannot be checked is refused, and a receipt on content
that has since changed stops counting.

The unit is a line range because every language has lines. Functions are a
view over it: where the call graph parsed the file, the card and
`bin/state resume` list the functions no receipt reaches.

Receipts change three things:

- **The next pickup.** Every card and resume brief carries an **Examined so
  far** block with the receipted ranges and the unexamined functions, so a
  session after a context compaction, or a different agent on the same broad
  card, starts from what is left instead of the top of the file.
- **Reoffer order.** Among broad cards with the same number of prior
  conclusions, the claimer offers the least-read file first.
- **The report.** `bin/state coverage` adds receipted files and the examined
  line share per directory, and telemetry carries the same totals.

## Loaded, from transcripts

When a session ends, the harness scans its backend transcript for file reads
and appends them to `state/reads.jsonl`: the native read tool of each backend
(Claude `Read`, Gemini `read_file`, OpenCode `read`) with its offset and
limit, and the shell idioms the audit shell wraps (`sed -n 'A,Bp'`, `cat`,
`head`, `tail`, `nl`, `bin/peek FILE:A-B`). A pattern search loads matches,
not a range, and is not recorded. Only reads inside the target tree count.

The report shows these as **Loaded** beside **Receipted**. Loaded is what the
transcript proves entered the context window, without any claim about
attention. Receipted is the agent's own statement of what it read. The two
disagree in useful ways: loaded without a receipt is a session that read and
did not record, and a receipt on lines never loaded is worth a look. Neither
is a gate, because a read the parser does not recognise is simply absent.

## What it does and does not say

"Offered" and "claimed" are what the harness handed out. Neither proves an
agent read the file, and a claim is not a verdict on the file's contents. A
receipt is the agent's own record of reading, checked for shape but not for
attention, so it bounds what could have been reviewed rather than proving
what was understood. The number to read a clean result against is the
never-offered share together with the unexamined line share: a tree where
most files were never in the window has been sampled, not reviewed, and a
clean result over it is silence, not evidence.

The benchmark telemetry carries the same totals as `coverage.tree`, beside the
per-lane card shares, so a run report shows how much of the tree its window
reached.
