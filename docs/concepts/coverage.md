# Review coverage

A clean run answers "what did the agents find?" but not "what did they never
look at?". The ranked queue is a bounded window over the source tree, so a
file outside the window has no card, and a card rewritten out of the window
leaves no trace in `work-cards.jsonl`. This page explains the ledger that
makes the untouched share visible.

## The manifest

Every ranking pass enumerates the auditable source tree before it scores
anything. The walk applies the harness's scope rule (documentation, tests,
examples, benchmarks, and fuzz trees are out) and prunes what holds no target
source by definition: VCS metadata, runtime caches, sanitizer build trees, the
harness's own `.audit/` workspace, and any directory Python marks as a
virtualenv with `pyvenv.cfg`. On a VCS checkout only tracked files remain.
That enumeration is persisted as `state/manifest.jsonl`, one row per file:

| Field | Meaning |
| --- | --- |
| `file` | Target-relative path. |
| `lines`, `bytes`, `sha1` | Identity of the content the row describes. A rerank re-hashes only files whose size, modification time, or change time changed. |
| `subsystem` | The same partition the queue uses for diversity. |
| `card_id` | The id the ranker mints for the file's primary card, so claims resolve to files even after the queue is rewritten. |
| `offered` | Whether the file has ever entered the ranked window. Sticky across rewrites: a file that left the window was still handed to the run. |
| `scope` | `tree` for a whole-tree audit, `delta` for `bin/audit --since <rev>`. The runner pins one scope to a results tree, and the manifest contains exactly that scope. |

The manifest is written from the same walk that produces the cards, so the
two cannot disagree about what is in scope. It is a materialized view,
rewritten atomically under its own lock on every pass, not an append-only
ledger. A preview ranked into another file with `bin/rank-work --output`
leaves it alone, since a window the run never held was not offered.

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

A claim says a card was handed out. A receipt is an agent's attestation of
which lines it read:

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
that has since changed stops counting. Content is what is checked: a file a
checkout or build step touched without changing keeps taking receipts, since
a rerank happens only when tracked content changes. When a file has multiple
parsed definitions with the same name, use `--lines`; the name alone is
ambiguous and is refused.

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
- **The report.** `bin/state coverage` adds receipted files and the attested
  examined-line share per directory, and telemetry carries the same totals.

## The budgeted sweep

The ranked window buys depth on the files the scorer likes, and a session
pays for every file it opens again on every later turn. The sweep buys
breadth once: with `[sweep] token_budget` set, the audit starts `bin/sweep`
beside the agent slots. It walks the unreceipted units gap first (files the
window never offered, then the least-read files), hands each unit to a
one-shot decision with no tools, and requires a receipt plus zero or more
leads in return:

- A **unit** is a parsed function no longer than `unit_lines`, a
  `unit_lines` window of a longer function, or a fixed window where the call
  graph parsed nothing.
- The **reply** must attest the whole unit, give exactly one valid verdict per
  parsed function (or the named line window), and may return concrete leads.
  Incomplete ranges and missing, duplicate, or invalid verdicts refuse the
  receipt, so the unit stays open. A lead is retained only when it names that
  function or line window, lies inside the unit, carries a known diagnostic
  and strategy, and agrees with a non-clean verdict; malformed leads are
  dropped rather than becoming hypotheses or strategy metrics. The strategy
  label only routes a lead to a lane, so a missing or unknown one defaults to
  S3 instead of losing the claim. A reply carries at most three leads.
- **Receipts** land in `state/receipts.jsonl` with `source: sweep`. **Leads**
  become `NEEDS_TESTCASE` hypotheses owned by agent `sweep`, which the
  reproduce lane picks up through the ordinary handoff. The sweep never
  probes, claims a card, or files a finding.
- **Spend** is the estimated prompt and reply tokens of every call, failed
  ones included, accumulated in `state/sweep.json` across resumes. A call is
  not started when its prompt alone exceeds the remaining budget; its reply
  can take the final estimate beyond the budget. The sweep stops at
  that boundary, after three consecutive unusable replies, or when no
  unreceipted unit remains. A shutdown signal lets the in-flight unit finish
  its receipt and leads as one commit, so a resume never skips a receipted
  unit whose lead was lost. Failed or incomplete units remain counted as open.

The sweep's calls are recorded in the run's usage ledger like every other
decision, so the benchmark wall counts them.

## The second pass

File coverage says nothing about interactions. Once every parsed function of
a file carries a receipt, the ranker mints one **call-edge** card for its set
of resolved caller files. The card starts with the highest-count caller and
asks the session to compare caller guarantees against callee assumptions,
sampling other callers when their contracts differ. This is a bounded sample,
not an attestation that every caller was examined: `bin/state coverage` reports
the eligible caller sets, how many were sampled and concluded, how many cards
the current queue holds, and how many callers beyond the seeds receive no
individual card. One card represents each caller set, so a file with thousands
of callers cannot create thousands of agent sessions. Edge cards ride the
window with their file, add no distinct-file slot, and close like concrete
cards once probed. A file completing its receipts is part of the queue's
refresh signature, so the card appears on the next refresh even when no source
changed. Without receipts, or without a call graph, no edge card exists; the
pass follows the first one rather than competing with it.

## Observed read requests from transcripts

As a session transcript is tallied, the harness observes file-read requests
and appends them to `state/reads.jsonl`: the native read tool of each backend
(Claude `Read`, Gemini `read_file`, OpenCode `read`) with its offset and
limit, and the shell idioms the audit shell wraps (`sed -n 'A,Bp'`, `cat`,
`head`, `tail`, `nl`, `bin/peek FILE:A-B`). A pattern search loads matches,
not a range, and is not recorded. Only reads inside the target tree count.

The report shows these as **Read requested** beside **Receipted**. The request
scope is an upper bound: a shell command such as `cat` proves what was asked
for, while backend or tool truncation can mean less entered the context.
Receipted is the agent's own statement of what it read. The two disagree in
useful ways, but neither is a gate: transcript formats and shell idioms vary,
and a read the parser does not recognise is simply absent. Both ledgers are
pinned to the current manifest hash, so observations on changed content stop
counting.

The report also joins the two: **attested lines no transcript read
requested** is the share of receipts the transcript cannot corroborate. An
over-broad `mark-examined` on a file the session never opened shows up
there. Because the parser misses idioms it does not know, the number is a
place to look, not proof of a false receipt.

## What it does and does not say

"Offered" and "claimed" are what the harness handed out. Neither proves an
agent read the file, and a claim is not a verdict on the file's contents. A
receipt is the agent's own record of reading, checked for content identity,
range, and sweep verdict completeness, but not for attention. It bounds what
could have been reviewed rather than proving what was understood. The number
to read a clean result against is the never-offered share together with the
unattested line share: a tree where most files were never in the window has
been sampled, not reviewed, and a clean result over it is silence, not
evidence.

No instrumentation can prove that a model understood every delivered unit.
Repeated runs over planted defects estimate detection probability for the
classes and target shapes represented by those plants; they do not establish
recall for unplanted classes. Report manifest reach, attestations, and seeded
recall separately.

The benchmark telemetry carries the same totals as `coverage.tree`, beside the
per-lane card shares, so a run report shows how much of the tree its window
reached.
