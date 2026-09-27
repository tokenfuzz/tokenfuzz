# Review coverage

A clean run answers "what did the agents find?" but not "what did they never
look at?". Before you trust a clean result, check how much of the tree the
run actually reached:

```bash
RESULTS=output/<target>/<backend>/results
bin/state --results-dir "$RESULTS" coverage
bin/state --results-dir "$RESULTS" coverage --depth 3 --format json
```

The ranked queue is a bounded window over the source tree: `RANK_WORK_LIMIT`
files (120 by default), grown by the same step whenever agents have worked
every card in it. A file outside the window has no card, and a card
rewritten out of the window leaves no trace in `work-cards.jsonl`. This page
explains the ledgers that make the untouched share visible, and how far each
number can be trusted.

<span id="the-report"></span>

## Reading the report

The report joins four ledgers under `state/` and groups them by directory:

| Column | Ledger | What it counts |
| --- | --- | --- |
| **Files**, **Lines** | `manifest.jsonl` | Every auditable file the ranker enumerated. |
| **Offered** | `manifest.jsonl` | Files that ever entered the ranked window. |
| **Claimed** | `claims.jsonl` | Files a session picked up a card on. |
| **Read requested** | `reads.jsonl` | Files, and lines, a session transcript shows were requested. |
| **Receipted** | `receipts.jsonl` | Files, and lines, an agent attested reading or the budgeted sweep examined, on the current content. |

The columns are counted independently, not nested. A prior-fix patch card
comes from outside the ranking, so a file can be claimed without ever being
offered, and a session can request a read of a file it found on its own.

Directories are listed least-examined first, and the largest files that were
never offered, claimed, or receipted are named at the end (`--untouched N`,
10 by default). Those are what you act on: widen `RANK_WORK_LIMIT`, pin a
lane, or set a sweep budget.

The summary above the table also reports:

- **Agent-attested lines no transcript read requested**: the share of agent
  receipts the transcripts cannot corroborate (see
  [the cross-check](#observed-read-requests-from-transcripts)).
- **Sweep**: receipted units, leads, units left, estimated spend, and why the
  sweep stopped (see [the budgeted sweep](#the-budgeted-sweep)).
- **Cross-file second pass**: eligible caller sets, how many were sampled
  and concluded, and how many callers have no card of their own (see
  [the second pass](#the-second-pass)).

Benchmark telemetry carries the headline totals as `coverage.tree`, so a
run report shows how much of the tree its window reached.

`bin/state coverage` measures *review*. Which code a testcase *executed* is
a different measure, reported from edge journals by `bin/coverage-summary`
(see [Commands](../reference/commands.md#inspect-a-running-audit)).

## The manifest

Every ranking pass enumerates the auditable source tree before it scores
anything. A file is auditable when it has a source extension the language
registry knows and sits outside the harness's exclusions:

- documentation, examples, tests, benchmarks, and fuzzing directories, plus
  test-, fuzz-, harness-, and bench-named files;
- anything that holds no target source: VCS metadata, `node_modules`,
  runtime caches, build trees and install staging, virtualenvs, and the
  harness's own `.audit/` workspace.

On a git or Mercurial checkout, only tracked files count. The result is
`state/manifest.jsonl`, one row per file: its path, line count, size, and
content hash; its subsystem; the id of its primary card; whether it was ever
`offered` (sticky, so a file that left the window still counts as handed to
the run); and its `scope`, `tree` for a whole-tree audit or `delta` for
`bin/audit --since`.

The manifest is written from the same walk that produces the cards, so the
two cannot disagree about what is in scope. It is rewritten atomically on
every pass. Card ids are deterministic, so claims still resolve to files
after the queue is rewritten. A preview ranked into another file with
`bin/rank-work --output` leaves the manifest alone, since a window the run
never held was not offered.

## Receipts

A claim says a card was handed out. A receipt says which lines were read. An
agent records one with `bin/state mark-examined`:

```bash
bin/state mark-examined --agent 1 --file src/parse.c --lines 1-120,200-260
bin/state mark-examined --agent 1 --file src/parse.c --functions app_parse,app_reset
```

Receipts append to `state/receipts.jsonl`, pinned to the file's content hash
from the manifest. The harness refuses a receipt it cannot check:

- The file must be in the manifest, and its content on disk must still match
  the manifest row.
- Every range must start inside the file. An end past the last line is
  clamped, so `sed -n 90,140p` on a 100-line file is accepted.
- A function name must be one the
  [call graph](../getting-started/prerequisites.md#experimental-call-neighbourhood-context)
  parsed in that file, and it resolves to that definition's exact lines. A
  name defined more than once in the file is ambiguous and refused; use
  `--lines`.

Content, not file metadata, is what counts. A checkout or build step that
touches a file without changing its bytes does not affect its receipts. Once
the content does change, the file takes no new receipts until the next
ranking pass records its new hash, and from then on its earlier receipts
stop counting.

The unit is a line range because every language has lines; functions are a
view over it. Receipts change three things:

- **The next pickup.** Every card and resume brief carries an **Examined so
  far** block with the receipted share, the ranges, and up to eight
  unexamined functions. A session after a context compaction, or another
  agent on the same broad card, starts from what is left instead of the top
  of the file.
- **Reoffer order.** Among broad cards with the same amount of prior work,
  the least-read file is offered first.
- **The report.** `bin/state coverage` counts the files and lines verifiably
  examined by agents or the budgeted sweep.

## Observed read requests from transcripts

A receipt is the agent's own statement. The read ledger is the other side:
after each agent session ends, the runner scans its transcript once and
records the file reads it recognises in `state/reads.jsonl`:

- each backend's native read tool, with its offset and limit;
- shell reads using the idioms the audit shell wraps: `sed -n 'A,Bp'`,
  `cat`, `nl`, `head`, `tail`, and `bin/peek FILE:A-B`.

A pattern search (`rg`, `grep`) loads matches, not a range, so it is not
recorded. Only reads inside the target tree count, and only while the file
still matches its manifest row. A parser failure is logged and never fails
the session.

A request is an upper bound: `cat` proves what was asked for, but backend or
tool truncation can mean less entered the context. Transcript formats and
shell idioms vary, and a read the parser does not recognise is absent, so
neither ledger gates evidence.

The report joins the two as **agent-attested lines no transcript read
requested**. An over-broad `mark-examined` on a file the session never
opened shows up there. Sweep receipts are left out of this cross-check,
because the harness put their source directly in the prompt. Since the
parser misses idioms it does not know, the number is a place to look, not
proof of a false receipt.

## The budgeted sweep

The ranked window buys depth on the files the scorer likes, and a session
pays again on every later turn for each file it opens. The sweep buys
bounded breadth instead: it hands one unit of unreceipted source at a time to
a one-shot model decision with no tools, and requires a receipt plus any
leads in return.

It is off by default. Set a positive `[sweep] token_budget` in `target.toml`
to turn it on; `model` picks the model, and `unit_lines` (120 by default)
the longest unit one decision sees. See
[Target config](../reference/target-toml.md#the-budgeted-sweep-sweep). With a
budget set, `bin/audit` starts the sweep as its own process beside the agent
slots, except in delta audits and pinned `--strategy` runs. Only one sweep
may spend against a results tree at a time; see
[Commands](../reference/commands.md#inspect-a-running-audit) for the manual
`bin/sweep`.

**What it reads.** The sweep plans gap first: files the window never
offered, then files by receipted share, least-read first. Before each call
it re-reads the receipts, so it never buys a unit a session has just
covered. A unit is one parsed function, or a window of at most `unit_lines`
lines for a long function, for code between functions, or for a file the
call graph could not parse. The prompt carries the numbered source, the
target's attacker controls, and the call-graph neighbourhood. A file that
changed since the manifest was written is skipped without spending.

**What it must return.** A reply must attest the whole unit and give one
verdict (`clean`, `suspicious`, or `needs-context`) per function in it, or
one for a window that holds no function. Anything less refuses the receipt,
and the unit stays open. A lead is kept only when it points inside the unit
at code not judged `clean`, and states a diagnostic category, a hypothesis,
an input shape, and a guard gap. Kept leads become `NEEDS_TESTCASE`
hypotheses owned by agent `sweep`, which the reproduce lane picks up through
the ordinary handoff. The sweep itself never probes, claims a card, or files
a finding.

**What it spends.** Spend is *estimated* from prompt and reply size with a
characters-per-token heuristic, not read from the provider. Each prompt's
estimate is charged to `state/sweep.json` before the call is sent, so failed
calls count too, and the total carries across resumes. A call is not started
when its prompt alone would exceed the remaining budget, but its reply can
take the final figure past it. Each call's reported usage also lands in the
run's usage ledger as a `decision:sweep_unit` row, so it counts in the run's
totals. The sweep an audit launches is exempt from the cap on decision
calls, because its token budget already bounds it.

**Why it stopped.** `state/sweep.json` records the reason:

| `stop` | Meaning |
| --- | --- |
| `budget` | The next prompt did not fit the remaining budget. |
| `backend` | Three consecutive calls returned no usable reply. |
| `exhausted` | No unreceipted unit remains. |
| `incomplete` | The pass reached the end of its plan with units still open. |
| `unit-cap` | A manual `bin/sweep --max-units N` reached its cap. |
| `interrupted` | The sweep was stopped before any of the above. It is also the value while a sweep is still running. |

??? note "What happens when the audit ends"
    The runner signals the sweep, which dispatches nothing new. A call in
    flight gets its normal decision timeout, bounded by the audit's wall
    budget when one is set; a valid reply commits its receipt and leads
    together, and past that deadline the sweep is killed. Failed,
    timed-out, and incomplete units stay open. The same pass does not return
    to them, but the next sweep (a resumed audit or a manual `bin/sweep`)
    plans them again within the remaining budget.

## The second pass

File coverage says nothing about interactions. Once every parsed function of
a file carries a current receipt, the ranker mints one S3 **call-edge** card
for the file's set of resolved caller files. It starts from the caller with
the most calls into the file and asks the session to compare what callers
guarantee (length, ownership, lifetime, encoding, error state) with what the
callee assumes, sampling other callers when their contracts differ.

This is a bounded sample, not an attestation that every caller was
examined: one card stands for each caller set, so a file with thousands of
callers cannot spawn thousands of sessions. `bin/state coverage` reports the
eligible caller sets, how many were sampled and concluded, and how many
callers have no card of their own.

The rules that keep the pass honest and cheap:

- **It follows the first pass.** Without complete receipts or a call graph,
  no edge card exists. Delta audits mint none.
- **It rides with its file.** An edge card uses its callee's window slot,
  never one of its own. A pinned lane other than S3 carries none.
- **It closes like a concrete card.** A `done`, `discarded`, or `blocked`
  conclusion closes it for the run.
- **It is keyed to content.** A change to the callee or any caller mints a
  fresh card, and a file completing its receipts triggers a rerank on the
  next queue refresh.

<span id="what-it-does-and-does-not-say"></span>

## What coverage does and does not prove

"Offered" and "claimed" are what the harness handed out. Neither proves an
agent read the file, and a claim is not a verdict on the file's contents.

A receipt is checked for content identity and range, and a sweep receipt
also for complete verdicts, but nothing checks attention. An agent receipt
is the agent's own record of reading. A sweep receipt records that one
tool-less decision, possibly on a different model, saw the unit: breadth,
not an investigation. Receipts bound what could have been reviewed rather
than proving what was understood.

Read a clean result against two numbers, the never-offered share and the
examined-line share, with the uncorroborated share beside them. A tree where
most files were never in the window has been sampled, not reviewed, and a
clean result over it is silence, not evidence.

No instrumentation can prove that a model understood every unit it was
given. Repeated runs over planted defects estimate detection probability for
the classes and target shapes those plants represent; they do not establish
recall for unplanted classes. Report manifest reach, attestations, and
seeded recall separately.
