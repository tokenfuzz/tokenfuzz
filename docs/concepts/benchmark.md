# Benchmarking TokenFuzz

`bin/benchmark` compares TokenFuzz with a direct model prompt on the same
target, backend, model, and wall-clock budget. Both conditions are scored
through the same validation and clustering pipeline.

The question is whether the harness earns its overhead: does its coordination,
execution, and review produce stronger validated evidence within the same
budget? That is useful to a security lead comparing approaches or a contributor
checking a harness change. For routine target work, use `bin/audit`.

This page has three reading paths:

- **Run an experiment:** start with [Quick start](#quick-start), then read
  [resumption](#resuming-an-interrupted-run) before continuing an old run.
- **Assess the result:** read [How a result is counted](#how-a-result-is-counted)
  and [Reading the ledger](#reading-the-ledger).
- **Maintain saved results:** use
  [Regenerating results](#regenerating-results-after-code-changes).

A reported count represents reviewed evidence signatures. It is not a count
of independently proven root causes, and it is not a precision or recall
measurement without an answer key.

## The experiment

Each benchmark run is a small controlled experiment:

| Condition token | Rendered label | What runs |
| --- | --- | --- |
| `model-direct` | `<model>-direct` when the model is known, otherwise `<backend>-direct` | One launch of the backend CLI at its defaults with a bare vulnerability-hunting prompt. This is the control. It may delegate internally if the CLI does by default; how often is recorded as `delegation_events`. |
| `harness` | `tokenfuzz` | `bin/audit` as shipped: ranked work cards, strategy rotation, `bin/probe`, triage, validation, clustering, severity scoring, and reproducer bundling. |

Each cell isolates the backend from any instruction files, plugins, or skills
you have installed, using whatever per-run control that CLI provides. This
keeps an operator-installed security workflow from duplicating TokenFuzz's own
orchestration or contaminating the model-direct control. Antigravity turns
skill expansion off but has no plugin or memory switch, and Grok Build turns
memory off but has no plugin or skill switch, so disable their installed
plugins by hand before using them for benchmark claims. The per-backend detail
is in the [backends guide](../guides/backends.md#one-isolation-policy-for-every-launch).

The `--conditions` flag always uses the stable tokens `model-direct` and
`harness`. The rendered labels are reader-facing names; they can include the
selected model so old and new model runs do not blur together.

Every cell gets the same per-cell wall-clock budget. With the defaults,
`bin/benchmark --target <target>` runs three `model-direct` cells and three
`harness` cells, each with a 10,800 second budget. That is six cells, about 18
hours of audit time if run serially, plus a final validation pass that is
measurement, not audit time (see [The closing pass](#the-closing-pass)). Both
conditions are told when their budget ends (the direct prompt names a UTC
deadline and a `date -u` command to check it against), but nothing re-enters a
finished session to hold it there. A baseline driven back to work by the
runner would measure the runner, so the Scoreboard reports what each condition
spent of what it was granted instead.

The benchmark keeps normal audit output separate. Cells run under isolated
`bin/audit --experiment` trees, then the benchmark pools and scores their
evidence under `output/benchmark/`.

## Why it is not a stopwatch

A useful benchmark is not "which row printed the largest number".

The direct prompt can produce more raw crash directories because it has little
structure around API misuse, duplicates, or self-inflicted testcases.
TokenFuzz spends budget on work the direct prompt does not do: queue
construction, coverage-gated probes, validation, deduplication, severity
scoring, and maintainer-ready reproducers.

That overhead is part of the comparison. The question is whether the extra
machinery buys stronger evidence by the end of the same budget. Read the
severity and uniqueness columns before the raw counts.

Equal wall time does not mean equal worker capacity. `model-direct` is one
launch of the CLI at its defaults, which may delegate internally
(`delegation_events` records how often, and the Efficiency table marks such
conditions `≤`). The harness uses its configured worker pool, normally three
workers unless overridden. It is not sized automatically to the machine. The
scoreboard keeps the wall comparison visible and separately reports occupancy,
worker-hours, confirmed results per seat-hour, tokens, and cost, so that
concurrency is not mistaken for free efficiency.

## Quick start

```bash
bin/benchmark --target <target>
```

The target must already exist under `targets/<target>/` and have a usable
`output/<target>/target.toml`. A target slug may be nested, such as
`samples/sample-python`, which maps to `targets/samples/sample-python/` and
`output/samples/sample-python/`. If you have not created that yet, start with
[Add a target](../getting-started/add-a-target.md).

With all defaults, the command means:

| Setting | Default | Meaning |
| --- | --- | --- |
| `--backend` | `codex` | Agent backend. Valid values are `claude`, `codex`, `gemini`, `grok`, and `oss`. |
| `--model` | backend config default | Optional model override used by both conditions. |
| `--replicates` | `3` | Runs per condition. |
| `--budget-wall` | `10800` | Active audit seconds per cell, including housekeeping. Provider-recovery pauses are excluded. `0` is unlimited. |
| `--finalize-wall` | `0` | Wall-clock ceiling per final validation phase; crash triage and the finding drain each get a fresh one. A finding group admitted before the ceiling finishes its review; crash review stops at the deadline and may leave a candidate pending. `0`, the default, is unlimited. |
| `--finalize-workers` | `4` | Concurrent reviewers per final validation phase, for crash triage and the finding drain alike. Independent of `--agents`, which sizes the audit itself. It also scales the finding gate's admission groups, so raising it shortens the closing pass but coarsens where a finite `--finalize-wall` can stop admitting groups. |
| `--agents` | the audit's configured pool, normally `3` | Harness workers per cell. The direct baseline is always one launch. |
| `--conditions` | `model-direct,harness` | Run both the direct baseline and TokenFuzz. |
| `--bench-root` | `output/benchmark` | Shared benchmark artifact root. |
| `--run-id` | UTC timestamp | Run directory under `output/benchmark/<backend>/`; reuse it to resume. |

Run `bin/benchmark --help` for the full option list.

## What a run looks like

The commands below run the same target through three hosted backends, two
replicates per condition, at the default 3-hour cell budget:

```bash
bin/benchmark --target <target> --backend claude --replicates 2 --budget-wall 10800
bin/benchmark --target <target> --backend gemini --replicates 2 --budget-wall 10800 --agent-security external-bypass
bin/benchmark --target <target> --backend grok   --replicates 2 --budget-wall 10800 --agent-security external-bypass
```

The Gemini and Grok rows need `--agent-security external-bypass` because the
default mode refuses those backends, and they must run inside an environment
you hardened. A row measured under a different mode is not comparable to the
others (see [agent security modes](../guides/backends.md#agent-security-modes)).

That target has to be bootstrapped first: source in `targets/<target>/`, build
artifacts where the config says they are, and `output/<target>/target.toml`
reviewed. The shortest path is the
[Add a target](../getting-started/add-a-target.md) flow.

Treat a two-replicate, three-hour run as a layout and sanity check, not as a
statistical claim. LLM runs are stochastic. Five or more replicates across
more than one target is useful operational guidance for claims, not a formal
power calculation.

## How a result is counted

A benchmark row is only worth reading if both conditions were scored by the
same rule. This section is that rule. If you only want to run the thing, skip
to [Where results land](#where-results-land).

### The closing pass

When a cell's timed investigation stops, it triages its crashes and finishes
validating its findings before metrics are read. That pass is *measurement*,
not extra finding time: the artifact set is frozen when the audit wall ends,
so the closing pass cannot buy a cell another finding. Crash triage and the
finding drain each receive a fresh `--finalize-wall`, rather than sharing one
pool. The default value `0` is unlimited. With a finite value, finding
validation lets a bounded group admitted before expiry finish its allotted
review attempts; it does not invent a verdict when the response omits or
mangles an id. Crash triage passes the deadline through to its reviews, so a
review that does not settle in time can remain pending.

The finding drain repeats while its unjudged remainder keeps falling, because
a review batch that returns no keyed output leaves its ids unadjudicated even
on an unlimited budget. Cached receipts make each repeat pay only for what is
still missing.

### What happens to anything unsettled

Nothing is guessed at. An unvalidated finding does not enter the finding
total. A sanitizer-backed crash with unfinished validation stays a visible
crash candidate rather than receiving final credit or an assumed severity.

A cell that finished but still holds unjudged findings keeps its place and its
evidence. Its finding count carries the remainder, and a count whose remainder
outnumbers its verdicts is marked `≥`: read that as a lower bound on the
condition, not a yield to compare. `bin/benchmark --regenerate` retries
reviews that have no usable answer or need focused resolution; it removes the
mark only if those decisions settle.

A cell that could not produce a usable measurement at all (provider limit,
interruption before substantive evidence, failed post-processing) is marked
incomplete and kept out of the medians, though any evidence it did produce is
still reported as an observed count. A direct backend that terminates *after*
substantive evidence is instead retained and counted, carrying its shorter
actual wall and a replicate marker saying the count came from a shorter
experiment.

### The security-decision table

Every run report carries one compact table of review outcomes:

| Outcome | Meaning |
| --- | --- |
| **Report** | Settled: real security impact inside the declared attacker surface. The only outcome that enters security yield or receives a numeric severity. |
| **Not reportable** | Settled: a real engineering defect that crosses no security boundary, either an admitted contract violation or reviewers agreeing the trigger needs a control the threat model does not list. Preserved on disk, never presented as a security bug. |
| **Rejected** | The claim failed a gate or completed review could not establish its scope. Kept in the rejected tree; the reason distinguishes disproof, threat-model rejection, and `unsettled-scope`. |
| **Review unsettled** | Required review is incomplete or has no usable answer. No security credit; shown as an unjudged remainder. |

An `Uncertain` verdict or split review can receive focused resolution using
the prior rationales. While required output is missing, the artifact remains
pending and contributes to the unjudged remainder. When all required reviews
have answered but still cannot place the trigger inside the threat model,
triage rejects it with an `unsettled-scope:` reason. That terminal outcome is
not an unjudged remainder.

Review receipts bind decisions to the evidence they evaluated. Changed
substantive evidence requires fresh review. The linked crash and finding
indexes carry the detailed signatures and reasons.

### Scope is decided by reading source, not by the report

The scope half of that decision (is the trigger inside `attacker_controls`?)
is deliberately not taken from the report. A report's `Trigger source` is
written by whoever found the bug, and it errs in both directions: a driver
that exercises documented entry points reads as caller-driven even when
attacker bytes decide the fault, and an unreproduced claim reads as
byte-driven even when only a caller can reach it. Left uncorrected, that
penalises the condition that builds reproducers and rewards the one that does
not. The trigger-provenance reviewer reads the source and answers the question
itself, and its answer wins when the two disagree.

### Both conditions face the same bar

The baseline's crashes are replayed through the target's normal invocation
before they count, so a diagnostic that does not reproduce is not counted as a
crash.

A replay that never *ran* is a different thing, and is not read as a verdict:
the crash keeps its place under `crashes/`, takes no verdict, and is reported
as an unadjudicated remainder. Broken replay infrastructure can neither
destroy a real crash nor credit an unproven one. The failure is logged where
the operator sees it.

On either side, a crash that `bin/probe --confirm` reproduced 5/5 through the
ordinary target binary, faulting in the target's own code on an
attacker-controlled input, skips the trigger review it would otherwise get:
the evidence already answers the question that review asks. Everything weaker
takes the normal review.

## Where results land

All benchmark state lives under one root:

```text
output/benchmark/
  benchmark-result.md
  benchmark-result.html
  <backend>/
    benchmark-results.md
    benchmark-results.html
    <run-id>/
      run.json
      report.json
      cells/
      pool/
```

`run.json` records the model, reasoning effort, and agent-security profile
actually passed to the CLI, so an archived run stays reproducible even if your
global backend settings later change.

One profile covers both conditions of a run, so a cell and its control always
face the same boundary, and `--regenerate` re-scores a run under the profile
that run recorded rather than today's default. Across backends the boundaries
differ, most visibly in egress (see
[agent security modes](../guides/backends.md#agent-security-modes)). Read a
cross-backend row as two products under their own boundaries, and compare runs
only against runs that recorded the same profile.

The root `benchmark-result.html` is the cross-backend comparison, described
under [Reading the result page](#reading-the-result-page). You can open it
while the run is going: it refreshes as cells finish, under a provisional
banner, and a cell contributes nothing to the counts until its own triage and
validation are done. The full pooled comparison (revalidation, bundling,
clustering) is computed once at the end. `benchmark-result.md` beside it is
the same scoreboard as a Markdown table, for terminals and diffs.

Each backend also has a ledger,
`output/benchmark/<backend>/benchmark-results.html`, with one section per run.
A new run adds a section; resuming or regenerating an existing run replaces
that run's section instead of appending a duplicate. Open the backend ledger
when you want the full run narrative; open the root crosstab when you want to
compare targets, backends, conditions, and reruns in one table.

Every pooled crash that survives triage is bundled under the run's
`pool/crashes/` tree with a `REPORT.md`, a rendered `REPORT.html`, and a
`reproduce.sh`.

Every cell is pinned to the same primary build. Alternate ASan builds are an
ordinary-audit feature, deliberately kept out of the benchmark so backends and
conditions are compared on one identical compiled surface.

To hand a finished run to someone else, `bin/export-benchmark` packages it
into a self-contained, path-scrubbed archive (`--format zip|tar|dir`), taking
the same `--backend` / `--target` / `--run-id` selectors as `bin/benchmark`.

## Reading the ledger

Each run section is ordered for review.

**Verdict** gives the strongest observed crash and which condition found it.
If no sanitizer-confirmed crash exists, it says so.

**Scoreboard** is the main comparison table:

| Column | Meaning |
| --- | --- |
| `Condition` | `tokenfuzz` or the direct baseline label. |
| `Replicates` | `done/total`. Replicates that recovered from a mid-run provider pause got their full budget and fold in unmarked. A `(Np)` suffix flags N provider-limited replicates excluded from the totals (a same-run-id re-run retries them). A `(Nt)` suffix flags N counted replicates whose backend exited early, so their share of the counts came from a shorter wall than the grant. |
| `Wall (h)` | Median hours a cell spent finding things, over the hours it was granted (`0.52/5.00h`). Every cell in a run is granted the same wall, but a condition is free to stop early, so read the counts beside a short numerator as the yield of a shorter experiment. The triage and validation that follow the audit are measurement, not finding work, so they are not counted. |
| `Unique rejected findings` | FIND reports the validator rejected, after clustering merges duplicates where evidence permits. `up to N` marks an upper bound. |
| `Security findings` | Distinct evidence-signature clusters of reportable non-crash security findings, shown as `N` clusters with the Medium-or-higher subset and class breadth. Every term uses unique clusters as its denominator, so duplicate reports cannot inflate class breadth, and breadth counts canonical [bug classes](../reference/bug-classes.md), so two spellings of one class cannot either. These remain separate descriptive axes rather than an arbitrary weighted score. Links to the finding cluster report. |
| `Unique rejected crashes` | Crash candidates triage rejected, after stack/signature clustering merges duplicates where evidence permits. `up to N` marks an upper bound. |
| `Unique security crashes` | Distinct reportable sanitizer-signature clusters with real sanitizer output on disk, shown `N (M M+)`: N clusters, M scored Medium or higher. The crash-cluster link includes reportable crashes at every numeric severity, including Low. A reproduced crash the reviewer placed outside the declared attacker controls is rejected with that reason and counted under rejected crashes; a `K retained` term appears only on runs finalized before that rule, where such crashes stayed in the cell uncredited. |
| `Top crash severity` | Highest crash severity observed in the cell. |
| `Run` | The run's UTC id. A `‡` marks a run whose severities came from a superseded scorer: the same artifacts score differently once the rules change, so its `M+` counts are not on the same scale as an unmarked row and the two must not be compared or summed. `bin/benchmark --regenerate` rescores the run and clears the mark. |

**Efficiency** follows the scoreboard whenever a cell recorded any of it, and
says where each condition's wall went. Every value is a median over completed
replicates; an em dash means unrecorded, never zero.

| Column | Meaning |
| --- | --- |
| `Occupancy` | Occupied agent-seconds over seats × effective wall. A `†` marks a cell that predates recorded session spans, where the number comes from the prompt-render and transcript file clocks instead. |
| `Blocked housekeeping` | Share of the effective wall the worker pool sat empty while crash triage, the result gates, indexes, orphan enforcement, and corpus promotion ran. Still charged to the wall either way. |
| `Review s/artifact` | In-wall and post-cell crash-triage plus result-gate seconds per artifact those gates judged. Post-cell time is measurement and remains excluded from `Wall (h)`, but it is real review cost. |
| `First filed` / `First crash confirmed` / `First admitted` | Minutes from the run's first clock (its first backend call) to the first artifact filed, the first sanitizer-confirmed crash, and the first receipt claiming `reportable`. |
| `EXEC_FAIL share` | Fraction of probes whose command started but produced no valid result. This includes classified loader, usage, input-rejection, abort, unverified-exit, and other exit failures; a sanitizer launch may already have been spent. |
| `Duplicate roots` | Share of artifact signatures filed by more than one agent: convergence, not yield. |
| `Confirmed / seat-h` | Reportable finding and crash clusters per worker-hour (`Worker-h`), so a condition with more concurrent seats is charged for them. Seats count launches; a `≤` prefix marks a condition in which a launch delegated to subagents, or whose backend cannot show its fan-out (Grok), so the seat capacity is a floor and the rate an upper bound. |
| `$ / confirmed` | Measured cost per reportable cluster; absent when cost was estimated, a delegating cell's spend is a floor, or nothing was confirmed. |

The same numbers sit in each cell's `metrics.json` under `telemetry`, and a
`lineage.jsonl` beside it joins card, hypothesis, testcase, artifact, and
signature, one row per hypothesis. `telemetry.coverage` records, per strategy
lane, how many ranked work cards a session claimed (`examined`, a claim-based
proxy: it says the card was handed out, not that its file was read) and how
many reached a terminal claim status (`concluded`), with the claimed share of
the ranked surface. Yield per lane says what a run produced; this says what it
was handed, so a queue change that starves a lane shows as an unclaimed share
rather than a quiet drop in yield.

A direct backend that exits nonzero after writing substantive finding or crash
evidence becomes an early terminal outcome rather than losing the entire cell.
It counts, so it carries a `(Nt)` marker in `Replicates` and its shorter
actual wall in `Wall (h)`; only independently valid cell artifacts enter the
totals. A backend exit with no substantive evidence still fails, and a cell
already excluded for a provider limit or drift keeps that stronger reason.

Reportable and rejected results go through the same deduplication, because a
raw directory tally counts matching evidence many times over and would not be
comparable with a clustered one. Signature clustering is a deterministic
deduplication proxy: one root cause can split across different sites, and
different root causes can share a sink signature. Where duplicates could not
be resolved the count is shown as `up to N`. It over-states rather than hides,
so a rejected result never quietly vanishes from the column.

The count cells are links. They point into the condition-specific crash,
finding, rejected-crash, rejected-finding, and cluster reports that produced
the number.

## Reading the result page

Open `output/benchmark/benchmark-result.html` for the cross-run comparison.
It reads counts from each run's `report.json` and links them to the supporting
reports. The page opens locally, is included by `bin/export-benchmark`, and
retains plain tables when JavaScript is unavailable.

| Section | What to look for |
| --- | --- |
| **What each model surfaced** | Results by target revision and condition, split into signatures unique to that condition and signatures shared with other runs. Harness rows include a comparison with their own control. |
| **Models side by side** | Discovery timelines, which conditions reported each signature, attention by subsystem, strategy use, and available cost and timing measures. |
| **Run by run** | Each run's outcomes and hypothesis history, with probe events, notes, and links to evidence. Replay controls show how the recorded state changed over time. |
| **Ledger** | Sortable reference rows for every target, backend, condition, and run. Count links open the indexes that produced them. |
| **Token usage** | Agent and orchestration cost, including preflight and review. Estimated usage and incomplete delegated spend are marked. |
| **Bugs by severity** | Crash clusters ordered by severity, with links to the bundles. |
| **Ground truth** | Precision and recall, only when the target has an answer key. |

The page's “coverage” comparison is the share of distinct problems reported
by the runs shown on that revision. It is neither code coverage nor recall
against every bug in the target. “Unique” is also relative to those runs.

A harness cell marked “looked” has recorded hypotheses on that file. This does
not prove that it investigated the particular issue in the row. The direct
control does not produce the same state history, so its missing entry is
unknown rather than a measured miss.

Keep the ledger's markers with the values when quoting them: `≥` identifies a
count dominated by unjudged evidence, `~` marks non-exact usage or cost,
`up to` marks an upper bound, and `‡` identifies superseded severity scoring.
Do not subtract a floor from a control or compare severity subsets scored
under different versions.

## Ground truth: precision and recall

The scoreboard counts crashes by sanitizer evidence, which keeps the count
honest but cannot say *which* bug a crash is. On a real target there is no
oracle for that, so a run's precision and recall, and the triage gate
thresholds tuned to them, go unmeasured.

The **canary** target closes that gap. It is a small synthetic
record-processing program at `targets/canary/`, carrying three planted
memory-safety bugs and two deliberate false-positive traps (inputs that look
dangerous to a reviewer but are not a memory-safety fault): enough to exercise
detection, triage, clustering, and severity scoring end to end.

The answer key is deliberately **not** in the target tree. It lives at
`output/canary/.ground-truth.json`, outside the directory handed to the
audited agents. The deterministic scorer reads it after the run rather than
including it in the audit prompt. This separation is not an access control on
other files the backend can read; account for that when making blind-evaluation
claims. Each planted bug pins its sanitizer primitive and the stack frame it
crashes in; each trap declares the benign outcome it expects. The canary is
100% synthetic, so the answer key
discloses no real project's bug.

When one source defect has multiple runtime shapes, its entry may add
`alternate_signatures`, each with a `primitive` and `signature_symbol`. An
alternate may also declare `access: READ` or `access: WRITE` when an optimizer
inlines distinct operations into the same crash-site symbol. These are aliases
for the same bug id, not extra recall items; ambiguous or overlapping aliases
make the manifest fail validation.

A planted bug marked `findings_only: true` never crashes; it surfaces under
`findings/`. Those are scored by a second oracle beside the crash one: a
confirmed finding is credited when the function it names as at fault is the
bug's `signature_symbol`. An entry may also pin a `file`, which the finding
must agree with: a report at `a.c:parse` must not credit a bug planted at
`b.c:parse`. Only an entry that names a file is held to it. Two qualified
paths are compared whole, so `src/a/parse.c` and `src/b/parse.c` are
different files; a basename is compared only when one side is genuinely
basename-only, which happens because a report's location can come from a bare
stack frame. A report that locates nothing against an entry that pins a file
is **open-world** rather than credited: with no identity evidence it is
unattributed, not a true positive. A pinned file is part of an entry's
identity, so two bugs sharing a symbol in different files are distinct rather
than a duplicate match key. A confirmed finding at a clean-outcome trap's
symbol counts against precision (a trap that expects an abort refutes that
crash, not a source finding there), and every other confirmed finding is
listed as **open-world**, since real code has bugs the answer key never
planted, without counting for or against. `bin/benchmark score` reports both blocks;
pass `--findings-dir` to point it at a `findings/` tree that is not beside the
crashes.

The canary is not alone: seventeen `samples/sample-*` targets are committed
the same way, each with its own answer key, so the same measurement works for
Rust, Go, Python, Java, and the rest. Everything else under `targets/` and
`output/` is a gitignored working area. See
[Sample targets](../getting-started/sample-targets.md) for the full list and
the per-language caveats.

`targets/canary/run-benchmark.sh` builds the ASan binary and runs a short
benchmark (the canary is tiny, so one replicate and a small budget suffice):

```bash
targets/canary/run-benchmark.sh
# equivalently, by hand (bin/benchmark builds the ASan binary itself; add
# `bin/setup-target canary --build` first only to pre-build):
#   bin/setup-target canary --no-llm-config
#   bin/benchmark --target canary --replicates 1 --budget-wall 900
```

At the end of a run the same scorer reads the pooled crashes and, where
configured, findings-only entries against the answer key and adds the
**Ground truth** block to the ledger:

- **Recall**: the share of planted bugs confirmed at their crash site by a
  runtime sanitizer artifact. Attribution is read only from the sanitizer's
  own output file, never from an agent's `report.md`, so prose that merely
  names a planted bug cannot earn recall.
- **Precision**: the share of confirmed crashes that are real planted bugs. A
  fired trap, an unexpected crash, or a confirmed crash with no runtime
  artifact to attribute (unattributed prose) all count against it.

A healthy canary run shows high recall *and* high precision: planted issues
are confirmed and deliberate traps do not appear as accepted crashes. The
direct baseline is measured by the same rule; the result, not an expected
winner, is the point of the experiment.

The crash oracle trusts only runtime sanitizer attribution. A separate finding
oracle grades entries marked `findings_only: true` from confirmed report
locations. A target with no applicable oracle is reported as unscored rather
than as 0% recall, and a planted non-crashing bug stays out of the
crash-recall denominator.

Score an existing results or pool tree directly, without launching a run:

```bash
bin/benchmark score output/canary/<backend>/results \
  --ground-truth output/canary/.ground-truth.json
```

The positional argument is a `crashes/` directory, or a `results/` or `pool/`
directory holding one. `--findings-dir` names a findings tree that is not
beside it, `--members` and `--conditions` split the score per benchmark
condition, and `--out` writes the JSON next to the printed summary. Run
`bin/benchmark score --help` for the full list.

This is the labelled signal to tune gate thresholds against. Tune precision
first: a change that raises recall but lets a trap through is a regression the
canary catches before it reaches a real audit.

### Measuring recall on real bugs

The same `.ground-truth.json` shape works for any target. To measure recall
against real CVEs, add a manifest at `output/<slug>/.ground-truth.json` whose
`planted_bugs` reference the real crashing symbols and primitives, pin the
target to a vulnerable revision, and run the benchmark as usual. The scorer
keys on the runtime `(primitive, signature_symbol)` pair, plus `access` only
for an alternate that declares it.

!!! warning "Keep real-bug manifests local; never commit them"
    A real-bug manifest can contain disclosure-sensitive symbols, inputs, and
    diagnostic details. Keep these out of shared fixtures under the
    [neutral-fixture rule](../development.md#testing-discipline).
    A real-bug `output/<slug>/.ground-truth.json` is gitignored by default;
    leave it uncommitted. Gitignore prevents accidental tracking, not access
    or disclosure through an archive, report, or tool. The synthetic sample
    answer keys are the committed exception because they implement no real
    project.

## Common variations

```bash
# More replicates make the result more stable. Use 5+ for claims.
bin/benchmark --target <target> --replicates 5

# Give each cell 90 minutes instead of the default 180.
bin/benchmark --target <target> --budget-wall 5400

# Run only TokenFuzz, for example when refreshing a harness-only baseline.
bin/benchmark --target <target> --conditions harness

# Pick the backend and model explicitly.
bin/benchmark --target <target> --backend claude --model <model>

# Override the audit's configured harness worker count.
# The direct baseline is still one launch of the CLI at its defaults.
bin/benchmark --target <target> --agents 5

# Start a fresh backend ledger. The previous one is archived.
bin/benchmark --reset

# Build into a private tree keyed by build inputs instead of sharing the
# target's canonical build. For recipe or configuration comparisons.
bin/benchmark --target <target> --isolate-build
```

## Running several backends at once

Backends, including multiple runs of the same backend, can benchmark one
target concurrently. Run directories and target-config snapshots are private;
the checkout and matching build generation are shared. Result and ledger
writers serialize only their short file updates, not whole runs.

Artifacts belong in the cell's results directory. A `FIND-*` or `CRASH-*`
written into the shared target tree has no trustworthy run owner. The harness
leaves substantive evidence in place and marks the observing cell instead of
assigning it to whichever run finishes first. It never enters that cell's
metrics, so the cell's independent results remain comparable. An empty or
incomplete directory is not evidence and does not create a marker.

A run pins one build generation:

1. A fresh run snapshots `target.toml`, converges its selected native build
   once, then records the selected runner, executable, library, and
   build-stamp bytes.
2. It holds shared leases on those native build trees and any target-owned
   generic runner for the whole run, including replay, pooled triage, and
   metrics.
3. A peer run whose build inputs match takes its own shared lease and uses the
   same build. Nothing has to be duplicated.
4. While any run holds the build, no `bin/setup-target`, `bin/build-configs`,
   or audit preflight will replace it. They say so and leave it in place.
5. Cell startup, cell completion, resume, and replay use the same exact-pin
   verifier. Cells never run freshness checks and never build.

Two things end up excluded from the headline comparison instead of silently
averaged in. Their artifacts are always kept:

- `source_drift`: the target's tracked source differs from the run pin when
  the cell ends. The harness checkout is not pinned: editing `bin/`, `lib/`,
  or `.agents/` while a run is in flight is ordinary development, and
  excluding a cell for it discarded hours of real evidence over a change the
  audit never read.
- `build_drift`: the build changed since the run pinned it, which only a build
  command run outside the harness can cause.

`unowned_artifacts` records a separate provenance warning: substantive
evidence appeared in the shared target tree without a run identifier. It
remains unassigned and uncounted. Because it is never imported into the cell,
it does not invalidate evidence already written through the cell's private
results directory.

Each run also pins the *source state* it is auditing, at the checkout rather
than at the build directory. Start a run while another has pinned a different
state and it refuses immediately: sharing the live build would measure a
binary the current source did not produce, and rebuilding would corrupt that
run. Use a separate checkout, or wait. Source pinning and the single
end-of-cell boundary check read the VCS, so they cover git and Mercurial
checkouts. There is no polling thread. They compare the revision and tracked
working-tree content; untracked testcases and generated output do not
invalidate a cell.

Before the first cell, build freshness remains conservative: a non-ignored
untracked file may be a real build input, so preflight converges the build
against the complete checkout once, naming the paths responsible if it must
refuse. The benchmark then pins the selected execution routes and their bytes.
Every cell receives the run's immutable `target.toml` snapshot and verifies
that it still selects those routes. It does not ask whether a hypothetical
rebuild would be fresh, so testcases and other by-products an earlier cell
left in the checkout cannot invalidate an unchanged pinned build.

A resumed `--run-id` never runs freshness and never rebuilds. It loads the
run-owned config snapshot and verifies the recorded paths, bytes, and build
generation directly. A refusal names the changed route or path and tells the
operator to start a new run id or restore that generation. It also refuses if
the source state or an experiment-defining setting has moved: model, reasoning
effort, `--budget-wall`, `--agents`, or the target revision. Raising
`--replicates` and resuming a subset of `--conditions` remain the supported
ways to continue a run, because neither changes what the finished cells
measured.

`--isolate-build` gives a run its own `build-asan+bench-<input-hash>/` tree,
keyed by build inputs so runs that diverge identically still share one tree,
and composed with a container's suffix when there is one. It is for comparing
build recipes or configurations over the same source. It cannot isolate a
different source revision, because both runs still read this one checkout, and
the source pin above still applies.

Isolated trees outlive their run, because `--regenerate` replays crashes
against the build they were found on. A finished run collects only the
isolated trees no run on disk still refers to; the canonical build,
container-suffixed trees, and `build-asan-repro` are never candidates.

## Resuming an interrupted run

Provider quota, local interruption, or a timeout can leave cells unfinished.
Resume by re-running the same command with the run id:

```bash
bin/benchmark --target <target> --backend claude --replicates 2 \
  --run-id 20260530-142558
```

Cells already marked `done` are skipped. Incomplete cells are wiped and run
cleanly, so half-written artifacts are never folded into the result.
`--replicates` is the desired total, so you can raise it during resume to add
more cells.

Harness cells pause and retry provider-withheld capacity for up to six hours;
that wait counts against neither their audit budget nor reported `Wall (h)`.
The model-direct condition is one backend session and cannot be steered back
into work after its CLI exits. A nonzero capacity-limited direct exit is
excluded rather than scored at a truncated wall, its artifacts remain on disk,
and resuming the run reruns that cell.

## Regenerating results after code changes

When you change deterministic post-processing, the cells on disk can still be
valid. Re-derive the rollups instead of launching agents:

```bash
# Re-derive the most recent run for this target and backend.
bin/benchmark --target <target> --backend claude --regenerate

# Re-derive one specific run.
bin/benchmark --target <target> --backend claude --regenerate \
  --run-id 20260530-142558

# Re-derive every run under output/benchmark/.
bin/benchmark --regenerate

# Rebuild only the root result pages from the surviving run reports.
bin/benchmark --rebuild-report

# Drop cached harness builds no evidence names from runs already on disk.
bin/benchmark --prune-cache
```

`--regenerate` launches no audit or discovery agents. It re-routes, validates,
scores, clusters, and renders the evidence already on disk, and recomputes
cell status, so a cell an older run marked incomplete over one pending
artifact can recover. Source-semantic validation may invoke the configured
reviewer when a current content-addressed receipt is missing or stale;
deterministic sanitizer, identity, scoring, and counting work does not.
Provider-limited and failed cells stay excluded.

`--rebuild-report` reads the surviving run state and rewrites only
`output/benchmark/benchmark-result.md` and `benchmark-result.html`. Finalized
runs come from `report.json`; unfinished runs are included provisionally from
their recorded cells. Use it after deleting or archiving run directories when
the remaining runs do not need to be replayed, rescored, or otherwise
regenerated. Per-backend `benchmark-results.md` and `benchmark-results.html`
ledgers are unchanged.

Every harness a cell's agents compiled through `bin/probe` stays in the
cell's build cache while the run is live, and the cache is what a long run
leaves behind: tens of MiB per build on a target that links statically. Once
a run is settled the runner prunes it, keeping every build that evidence
names — a probe context, a sanitizer frame, a validation receipt, a report,
or a pooled binary's debug map — and removing the rest, since they rebuild
from the harness source the cache key hashes. The cell's fuzz-activity
counts are written to `fuzz-activity.json` first, so `--regenerate` reports
what the run built rather than what the prune left. `--prune-cache` applies
the same prune to runs that finished before this existed; it narrows to
`--target` and `--run-id`, reports without deleting under `--dry-run`, skips
a run whose lock is held or whose cells are not all done, and touches no
evidence. If evidence cannot be read or the activity receipt cannot be
preserved, cleanup keeps the affected caches and logs a warning.

Regeneration cannot manufacture evidence an old cell never recorded. Missing
testcases, invocation prerequisites, build identity, source anchors, or replay
artifacts remain visible as pending or unmeasured. A fresh benchmark run is
warranted only when you need to measure discovery/recall or harness overhead
under the new code, collect prerequisites that were never saved, or publish a
comparison in which both conditions used the new audit contract. It is not
needed merely to correct deterministic severity, routing, or report metrics.

It does not substitute the current target build for the one a cell executed.
Each new cell records the content identity of the binaries and instrumented
libraries a replay would run. A regeneration that cannot match that identity
leaves the original crash evidence unchanged, records why the replay was
skipped, and keeps the verdicts the cell already settled under the build it
pinned. A rebuilt tree costs the replay, not the measurement, and what no
replay can settle stays unadjudicated rather than costing the cell its place
in the aggregate. Changes to a sanitizer build the evidence never used do not
block it. Older cells without a recorded identity can still be re-rendered,
but target-build-dependent crash replay is skipped.

It stays additive otherwise: a crash that was never bundled gets one, and
existing and hand-edited reports are left alone, whether or not replay ran. A
bundle rebuilds from source at the revision the run recorded (a run that
recorded none says `norev` rather than name the checkout's current commit),
but its build recipe is read from the target tree as it stands today, so a
recipe edited since the run is reflected in the bundle.

Any crash without a measured reproduction rate is re-run through the same
wrapper the harness uses, under exactly the runtime options its diagnostic
recorded, and only while the build artifacts that crash needs are still
available. Otherwise the pool keeps an unset `?` rather than a guess;
model-direct triage keeps unmeasured evidence under `crashes/` but withholds
its verdict, so it counts as unadjudicated rather than as a confirmed crash. A
bundle whose replay contract cannot be resolved at all (a build that is gone,
a harness nobody compiled) is held the same way; one that carries no
reproducer to run at all is left to the completeness gate instead, which holds
it pending before it rejects. Only a replay that ran and disagreed with the
report moves a crash into `findings/`.

Each pooled crash is checked against its owning cell and only its own replay
artifacts, so one changed binary does not cost unrelated crashes their rates.
A rate counts only runs that reproduced the original fault (same sanitizer,
primitive, faulting function, and normalized source path and line where both
diagnostics name them), so a replay that crashes elsewhere is not a
reproduction. Evidence whose own fault cannot be characterised claims no rate.

## How to make the result worth reading

- If both conditions report zero, inspect setup failures, unjudged artifacts,
  and actual budget spent. Zero alone cannot distinguish a difficult target,
  inadequate budget, or an ineffective approach.
- Prefer 5+ replicates before making claims. This is a practical rule of
  thumb, not a derived confidence bound; report variability rather than
  treating the count as statistically conclusive.
- Compare more than one target. A harness change that helps one parser and
  hurts another should not disappear into a single headline row.
- Read the Medium+ subset of unique crashes and top crash severity before raw
  crash count. A pile of duplicated low-value crashes is not a stronger
  benchmark result than one clean, reachable reproducer.
- Keep the target fixed while comparing harness changes. `run.json` records
  target and harness revisions so old results remain auditable.
