# Benchmarking TokenFuzz

`bin/benchmark` answers one question with evidence rather than opinion:

> For the same target, backend, model, and wall-clock budget, does
> TokenFuzz find stronger **real, reproducible** security issues than
> a direct "find vulnerabilities" prompt?

You do not need to know the harness internals to run it or read the
result. This page is for the person deciding whether the harness is
earning its overhead: a security lead comparing approaches, a backend
operator tuning model choice, or a maintainer checking whether a
triage, clustering, severity, or prompt change helped.

The important word is **evidence**. A crash does not count because an
agent claimed one in prose; it counts when sanitizer output is on disk.
A finding does not count because it sounds plausible; it goes through
the same validation and clustering machinery used by normal audits.
That is what makes a benchmark row worth reading later.

Benchmarking is for evaluating TokenFuzz itself. For routine target
work, run `bin/audit` directly.

## The experiment

Each benchmark run is a small controlled experiment:

| Condition token | Rendered label | What runs |
| --- | --- | --- |
| `model-direct` | `<model>-direct` when the model is known, otherwise `<backend>-direct` | One agent with a bare vulnerability-hunting prompt. This is the control. |
| `harness` | `tokenfuzz` | `bin/audit` as shipped: ranked work cards, strategy rotation, `bin/probe`, triage, validation, clustering, severity scoring, and reproducer bundling. |

Each cell isolates the backend from any instruction files, plugins, or skills
you have installed, using whatever per-run control that CLI provides. This keeps
an operator-installed security workflow from duplicating TokenFuzz's own
orchestration or contaminating the model-direct control. Antigravity and Grok
Build have no such one-shot control yet, so disable their installed plugins and
skills by hand before using them for benchmark claims.

The `--conditions` flag always uses the stable tokens
`model-direct` and `harness`. The rendered labels are reader-facing
names; they can include the selected model so old and new model runs
do not blur together.

Every cell gets the same per-cell wall-clock budget. With the defaults,
`bin/benchmark --target <target>` runs three `model-direct` cells and
three `harness` cells, each with a 10,800 second budget. That is six
cells, about 18 hours of audit time if run serially, plus bounded final
validation. Both conditions are told when their budget ends — the direct
prompt names a UTC deadline and a `date -u` command to check it against —
but nothing re-enters a finished session to hold it there. A baseline driven
back to work by the runner would measure the runner, so the Scoreboard
reports what each condition spent of what it was granted instead.

The benchmark keeps normal audit output separate. Cells run under
isolated `bin/audit --experiment` trees, then the benchmark pools and
scores their evidence under `output/benchmark/`.

## Why it is not a stopwatch

A useful benchmark is not "which row printed the largest number."

The direct prompt often produces more raw crash directories because it
has little structure around API misuse, duplicates, or self-inflicted
testcases. TokenFuzz spends budget on work the direct prompt does not
do: queue construction, coverage-gated probes, validation,
deduplication, severity scoring, and maintainer-ready reproducers.

That overhead is part of the comparison. The question is whether the
extra machinery buys stronger evidence by the end of the same budget.
Read the severity and uniqueness columns before the raw counts.

## Quick start

```bash
bin/benchmark --target <target>
```

The target must already exist under `targets/<target>/` and have a
usable `output/<target>/target.toml`. A target slug may be nested, such
as `samples/sample-python`, which maps to
`targets/samples/sample-python/` and `output/samples/sample-python/`.
If you have not created that yet, start with
[Add a target](../getting-started/add-a-target.md).

With all defaults, the command means:

| Setting | Default | Meaning |
| --- | --- | --- |
| `--backend` | `codex` | Agent backend. Valid values are `claude`, `codex`, `gemini`, `grok`, and `oss`. |
| `--model` | backend config default | Optional model override used by both conditions. |
| `--replicates` | `3` | Runs per condition. |
| `--budget-wall` | `10800` | Active audit seconds per cell, including housekeeping. Provider-recovery pauses are excluded. `0` is unlimited. |
| `--finalize-wall` | `0` | Start ceiling per final validation phase; crash triage and the finding drain each get their own budget, and a bounded finding group admitted before the ceiling finishes afterward. `0`, the default, is unlimited: the artifact set is frozen when the audit wall ends, so the phase runs to completion rather than publishing a partly-judged cell. |
| `--finalize-workers` | `4` | Concurrent reviewers per final validation phase, for crash triage and the finding drain alike. Independent of `--agents`, which sizes the audit itself. It also scales the find gate's admission groups, so raising it shortens the closing pass but coarsens where a finite `--finalize-wall` can cut. |
| `--conditions` | `model-direct,harness` | Run both the direct baseline and TokenFuzz. |
| `--bench-root` | `output/benchmark` | Shared benchmark artifact root. |
| `--run-id` | UTC timestamp | Run directory under `output/benchmark/<backend>/`; reuse it to resume. |

Run `bin/benchmark --help` for the full option list.

## What a run looks like

The commands below run the same target through four hosted backends, two
replicates per condition, at the default 3-hour cell budget:

```bash
bin/benchmark --target <target> --backend claude --replicates 2 --budget-wall 10800
bin/benchmark --target <target> --backend codex  --replicates 2 --budget-wall 10800
bin/benchmark --target <target> --backend gemini --replicates 2 --budget-wall 10800 --agent-security external-bypass
bin/benchmark --target <target> --backend grok   --replicates 2 --budget-wall 10800 --agent-security external-bypass
```

The Gemini and Grok rows need `--agent-security external-bypass` because the
default mode refuses those backends, and they must run inside an environment you
hardened; a row measured under a different mode is not comparable to the
others (see [agent security modes](../guides/backends.md#agent-security-modes)).

That target has to be bootstrapped first: source in
`targets/<target>/`, build artifacts where the config says they are,
and `output/<target>/target.toml` reviewed. The shortest path is the
[Add a target](../getting-started/add-a-target.md) flow.

Treat a two-replicate, three-hour run as a layout and sanity check,
not as a statistical claim. LLM runs are stochastic. For a result you would
cite, use at least five replicates and more than one target.

When a cell's timed investigation stops, it triages its crashes and finishes
validating its findings before metrics are read. That closing pass is
measurement, not extra finding time, and it is budgeted separately
(`--finalize-wall`) so a crash-heavy cell cannot starve finding validation.

The drain repeats while its unjudged remainder falls, because a review batch
that returns no keyed output leaves its ids unadjudicated even on an unlimited
budget. Cached receipts make each repeat pay only for what is still missing.

Anything still unadjudicated is handled conservatively rather than guessed at:
an unvalidated finding does not enter the finding total, and a sanitizer-backed
crash with unfinished validation remains a visible crash candidate rather than
receiving final credit or an assumed severity. A cell that could not produce a
usable measurement — provider limit, interruption before substantive evidence,
failed post-processing — is marked incomplete and kept out of the medians, but
any evidence it did produce is still reported as an observed count. A direct
backend that terminates after substantive evidence is instead retained and
counted, carrying its shorter actual wall and a replicate marker that says the
count came from a shorter experiment. A cell that finished but still
holds unjudged findings keeps its place and its evidence; its finding count
carries the remainder, and a count whose remainder outnumbers its verdicts is
marked `≥` — a lower bound on that condition, not a yield to compare.
`bin/benchmark --regenerate` finishes the
gate from cached receipts and removes the mark.

The run report also shows one compact security-decision table. A settled review
ends as **Report**, **Not reportable**, or **Rejected**; an artifact whose
review never finished, or finished without settling the claim, stays under
**Review unsettled** and receives no credit either way. Only Report enters
security yield or receives numeric severity. Not reportable preserves a real
engineering defect on disk without presenting it as a security bug, and it
states something a review established — an admitted contract violation, or
reviewers agreeing the trigger needs a control the threat model does not list.
An `Uncertain` verdict and two reviewers who disagree establish neither, so
they stay unsettled rather than being written off as out of scope: that
remainder is the reason a count can carry the `≥` floor mark. Content-addressing
reopens the review when the report, the evidence, or the prompt version changes.
Runtime signature details remain available in the linked crash and finding
indexes rather than adding another count to the benchmark headline.

The scope half of that decision — is the trigger inside `attacker_controls`? —
is not taken from the report. A report's `Trigger source` is written by whoever
found the bug, and it errs in both directions: a driver that exercises
documented entry points reads as caller-driven even when attacker bytes decide
the fault, and an unreproduced claim reads as byte-driven even when only a
caller can reach it. Left uncorrected, that penalises the condition that builds
reproducers and rewards the one that does not. The trigger-provenance reviewer
reads the source and answers the question itself, and its answer decides when
the two disagree.

Both conditions are held to the same evidence bar. The baseline's crashes are
replayed through the target's normal invocation before they count, so a
diagnostic that does not reproduce is not counted as a crash. A replay that
never ran is a different thing and is not read as a verdict: the crash keeps
its place under `crashes/`, takes no verdict, and is reported as an
unadjudicated remainder, so broken replay infrastructure can neither destroy a
real crash nor credit an unproven one. The failure is logged where the
operator sees it. On either side, a
crash that `bin/probe --confirm` reproduced 5/5 through the ordinary target
binary, faulting in the target's own code on an attacker-controlled input,
skips the trigger review it would otherwise get — the evidence already answers
the question that review asks. Everything weaker takes the normal review.

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
differ: each CLI's sandbox differs, most visibly in egress (see
[agent security modes](../guides/backends.md#agent-security-modes)). Read a
cross-backend row as two products under their own boundaries, and compare runs
only against runs that recorded the same profile.

The root `benchmark-result.html` is the cross-backend comparison. You can open
it while the run is going: it refreshes as cells finish, under a
**Provisional** banner, and a cell contributes nothing until its own triage and
validation are done. The full pooled comparison — revalidation, bundling,
clustering — is computed once at the end.

Each backend also has an append-only ledger,
`output/benchmark/<backend>/benchmark-results.html`, with one section
per run. Open the backend ledger when you want the full run narrative;
open the root crosstab when you want to compare targets, backends,
conditions, and reruns in one table.

Every pooled crash that survives triage is bundled under the run's
`pool/crashes/` tree with a `REPORT.md`, rendered `REPORT.html`, and
`reproduce.sh`.

Every cell is pinned to the same primary build. Alternate ASan builds are an
ordinary-audit feature, deliberately kept out of the benchmark so backends and
conditions are compared on one identical compiled surface.

To hand a finished run to someone else, `bin/export-benchmark` packages
it into a self-contained, path-scrubbed archive (`--format zip|tar|dir`),
taking the same `--backend` / `--target` / `--run-id` selectors as
`bin/benchmark`.

## Reading the ledger

Each run section is ordered for review:

**Verdict** gives the strongest observed crash and which condition
found it. If no sanitizer-confirmed crash exists, it says so.

**Scoreboard** is the main comparison table:

| Column | Meaning |
| --- | --- |
| `Condition` | `tokenfuzz` or the direct baseline label. |
| `Replicates` | `done/total`. Replicates that recovered from a mid-run provider pause got their full budget and fold in unmarked; a `(Np)` suffix flags N provider-limited replicates excluded from the totals (a same-run-id re-run retries them); a `(Nt)` suffix flags N counted replicates whose backend exited early, so their share of the counts came from a shorter wall than the grant. |
| `Wall (h)` | Median hours a cell spent finding things, over the hours it was granted (`0.52/5.00h`). Every cell in a run is granted the same wall, but a condition is free to stop early, so read the counts beside a short numerator as the yield of a shorter experiment. The triage and validation that follow the audit are measurement, not finding work, so they are not counted. |
| `Unique rejected findings` | FIND reports the validator rejected, after clustering merges duplicates where evidence permits. `up to N` marks an upper bound. |
| `Security findings to report` | Distinct evidence-signature clusters of reportable non-crash security findings, shown `N (M M+)`: N clusters, M scored Medium or higher. Links to the finding cluster report. |
| `Unique rejected crashes` | Crash candidates triage rejected, after stack/signature clustering merges duplicates where evidence permits. `up to N` marks an upper bound. |
| `Unique Security crashes to report` | Distinct reportable sanitizer-signature clusters with real sanitizer output on disk, shown `N (M M+)`: N clusters, M scored Medium or higher. The existing crash-cluster link includes reportable crashes at every numeric severity, including Low. |
| `Top crash severity` | Highest crash severity observed in the cell. |

A direct backend that exits nonzero after writing substantive finding or crash
evidence becomes an early terminal outcome rather than losing the entire cell.
It counts, so it carries a `(Nt)` marker in `Replicates` and its shorter actual
wall in `Wall (h)`; only independently valid cell artifacts enter the totals. A
backend exit with no substantive evidence still fails, and a cell already
excluded for a provider limit or drift keeps that stronger reason.

Reportable and rejected results go through the same deduplication, because a raw
directory tally counts matching evidence many times over and would not be
comparable with a clustered one. Signature clustering is a deterministic
deduplication proxy: one root cause can split across different sites, and
different root causes can share a sink signature. Where duplicates could not be resolved the
count is shown as `up to N` — it over-states rather than hides, so a rejected
result never quietly vanishes from the column.

The count cells are links. They point into the condition-specific
crash, finding, rejected-crash, rejected-finding, and cluster reports
that produced the number.

**Time to discovery**, below the table, plots those same numbers over time: one
row per target revision, findings and crashes side by side. Each step is one
deduplicated reportable result placed at the hour it was found, so the curve only
climbs and ends exactly on the security-report count. The chip above each
curve shows what the gate made reportable and rejected. When a result's discovery time
can't be recovered, the panel flags the timing as approximate rather than
faking precision. Reportable and rejected results are deduplicated separately, and
an `up to` rejected count is a conservative upper bound — neither figure is
*precision*, which needs the answer key described below.

**Token usage** compares what each condition actually cost. The bold row per
condition is the total, and the harness side includes everything it spends
beyond the agents themselves — preflight, triage, validation, and its other
model calls — so the comparison is not flattered by hiding overhead. Estimated
figures are marked; Gemini through the Antigravity CLI reports no usage, so its
numbers are estimates.

**Bugs by severity** lists distinct crash clusters strongest first.
The bug id links to the crash directory, and the reproducer link opens
the rendered report bundle.

**Ground truth** appears only for a target that ships an answer key
(see below). It reports measured precision and recall per condition, so
you can see not just how many crashes a run produced but how many were
the *right* ones.

## Ground truth: precision and recall

The scoreboard counts crashes by sanitizer evidence, which keeps the
count honest but cannot say *which* bug a crash is. On a real target
there is no oracle for that, so a run's precision and recall — and the
triage gate thresholds tuned to them — go unmeasured.

The **canary** target closes that gap. It is a small synthetic
record-processing program at `targets/canary/`, carrying three planted
memory-safety bugs and two deliberate false-positive traps (inputs that look
dangerous to a reviewer but are not a memory-safety fault) — enough to
exercise detection, triage, clustering, and severity scoring end to end.

The answer key is deliberately **not** in the target tree. It lives at
`output/canary/.ground-truth.json`, outside the directory handed to the
audited agents, so the score stays blind — an agent auditing the canary is
not also handed a list of which inputs are real bugs and which are traps.
The deterministic scorer reads it after the run. Each planted bug pins its
sanitizer primitive and the stack frame it crashes in; each trap declares
the benign outcome it expects. The canary is 100% synthetic, so the answer
key discloses no real project's bug.

The canary is not alone: fifteen per-language `samples/sample-*` targets are
committed the same way, each with its own answer key, so the same measurement
works for Rust, Go, Python, Java, and the rest. Everything else under
`targets/` and `output/` is a gitignored working area. See
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

`lib/benchmark.py` scores the pooled crashes against the answer key and
adds the **Ground truth** block to the ledger:

- **Recall** — the share of planted bugs confirmed at their crash site by a
  runtime sanitizer artifact. Attribution is read only from the sanitizer's
  own output file, never from an agent's `report.md`, so prose that merely
  names a planted bug cannot earn recall.
- **Precision** — the share of confirmed crashes that are real planted
  bugs. A fired trap, an unexpected crash, or a confirmed crash with no
  runtime artifact to attribute (unattributed prose) all count against it.

A healthy canary run shows high recall *and* high precision: planted issues are
confirmed and deliberate traps do not appear as accepted crashes. The direct
baseline is measured by the same rule; the result, not an expected winner, is
the point of the experiment.

The oracle grades **crashes**, because a sanitizer artifact is the only
attribution it can trust. Two consequences: a findings-only target is reported
as `not_scored: findings-only` rather than as 0% recall, and a planted bug on a
sanitizer target that can never crash (path traversal, command injection)
carries `findings_only: true` in the manifest so it stays out of the
crash-recall denominator.

Score an existing results or pool tree directly:

```bash
python3 lib/benchmark.py score output/canary/<backend>/results \
  --ground-truth output/canary/.ground-truth.json
```

This is the labelled signal to tune gate thresholds against. Tune
precision first: a change that raises recall but lets a trap through is
a regression the canary catches before it reaches a real audit.

### Measuring recall on real bugs

The same `.ground-truth.json` shape works for any target. To measure
recall against real CVEs, add a manifest at
`output/<slug>/.ground-truth.json` whose `planted_bugs` reference the real
crashing symbols and primitives, pin the target to a vulnerable revision,
and run the benchmark as usual. The scorer needs no code change — it keys
on the `(primitive, signature_symbol)` pair the clustering pipeline already
produces.

!!! warning "Keep real-bug manifests local — never commit them"
    A real-CVE manifest names actual crashing symbols and primitives, which
    discloses unreleased bug detail — exactly what the
    [neutral-fixture rule](https://github.com/tokenfuzz/tokenfuzz/blob/main/docs/development.md)
    forbids. `output/` is gitignored precisely so these stay private, so a
    real-bug `output/<slug>/.ground-truth.json` is uncommitted by default —
    leave it that way. The synthetic `canary` answer key is the one committed
    exception because it implements no real project.

## Common variations

```bash
# More replicates make the result more stable. Use 5+ for claims.
bin/benchmark --target <target> --replicates 5

# Give each cell 90 minutes instead of the default 180.
bin/benchmark --target <target> --budget-wall 5400

# Run only TokenFuzz, for example when refreshing a harness-only baseline.
bin/benchmark --target <target> --conditions harness

# Pick the backend and model explicitly.
bin/benchmark --target <target> --backend codex --model <model>

# Use more harness workers than the default of 3. The direct baseline is still launched as one agent.
bin/benchmark --target <target> --agents 5

# Start a fresh backend ledger. The previous one is archived.
bin/benchmark --reset

# Build into a private tree keyed by build inputs instead of sharing the
# target's canonical build. For recipe or configuration comparisons.
bin/benchmark --target <target> --isolate-build
```

## Running several backends at once

Backends — including multiple runs of the same backend — can benchmark one
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
   once, then records the selected runner, executable, library and build-stamp
   bytes.
2. It holds shared leases on those native build trees and any target-owned
   generic runner for the whole run, including replay, pooled triage and
   metrics.
3. A peer run whose build inputs match takes its own shared lease and uses the
   same build. Nothing has to be duplicated.
4. While any run holds the build, no `bin/setup-target`, `bin/build-configs` or
   audit preflight will replace it. They say so and leave it in place.
5. Cell startup, cell completion, resume and replay use the same exact-pin
   verifier. Cells never run freshness checks and never build.

Two things end up excluded from the headline comparison instead of silently
averaged in. Their artifacts are always kept:

- `source_drift` — the target's tracked source differs from the run pin when
  the cell ends.
- `build_drift` — the build changed since the run pinned it, which only a build
  command run outside the harness can cause.

`unowned_artifacts` records a separate provenance warning: substantive evidence
appeared in the shared target tree without a run identifier. It remains
unassigned and uncounted. Because it is never imported into the cell, it does
not invalidate evidence already written through the cell's private results
directory.

Each run also pins the *source state* it is auditing, at the checkout rather
than at the build directory. Start a run while another has pinned a different
state and it refuses immediately: sharing the live build would measure a binary
the current source did not produce, and rebuilding would corrupt that run. Use a
separate checkout, or wait. Source pinning and the single end-of-cell boundary
check read the VCS, so they cover git and Mercurial checkouts. There is no
polling thread. They compare the revision and tracked working-tree content;
untracked testcases and generated output do not invalidate a cell.

Before the first cell, build freshness remains conservative: a non-ignored
untracked file may be a real build input, so preflight converges the build
against the complete checkout once, naming the paths responsible if it must
refuse. The benchmark then pins the selected execution routes and their bytes.
Every cell receives the run's immutable `target.toml` snapshot and verifies
that it still selects those routes. It does not ask whether a hypothetical
rebuild would be fresh, so testcases and other by-products an earlier cell left
in the checkout cannot invalidate an unchanged pinned build.

A resumed `--run-id` never runs freshness and never rebuilds. It loads the
run-owned config snapshot and verifies the recorded paths, bytes and build
generation directly. A refusal names the changed route or path and tells the
operator to start a new run id or restore that generation. It also refuses if
the source state or an experiment-defining setting has moved — model, reasoning effort,
`--budget-wall`, `--agents`, or the target revision. Raising `--replicates` and
resuming a subset of `--conditions` remain the supported ways to continue a run,
because neither changes what the finished cells measured.

`--isolate-build` gives a run its own `build-asan+bench-<input-hash>/` tree,
keyed by build inputs so runs that diverge identically still share one tree, and
composed with a container's suffix when there is one. It is for comparing build
recipes or configurations over the same source — it cannot isolate a different
source revision, because both runs still read this one checkout, and the source
pin above still applies.

Isolated trees outlive their run, because `--regenerate` replays crashes against
the build they were found on. A finished run collects only the isolated trees no
run on disk still refers to; the canonical build, container-suffixed trees and
`build-asan-repro` are never candidates.

## Resuming an interrupted run

Provider quota, local interruption, or a timeout can leave cells
unfinished. Resume by re-running the same command with the run id:

```bash
bin/benchmark --target <target> --backend claude --replicates 2 \
  --run-id 20260530-142558
```

Cells already marked `done` are skipped. Incomplete cells are wiped and
run cleanly, so half-written artifacts are never folded into the
result. `--replicates` is the desired total, so you can raise it during
resume to add more cells.

A usage limit hit mid-cell does not end it. The cell pauses until the backend's
quota resets, and that wait counts against neither its budget nor its reported
`Wall (h)`. Only a backend that is still down six hours later marks the cell
provider-limited.

## Regenerating results after code changes

When you change deterministic post-processing, the cells on disk can
still be valid. Re-derive the rollups instead of launching agents:

```bash
# Re-derive the most recent run for this target and backend.
bin/benchmark --target <target> --backend codex --regenerate

# Re-derive one specific run.
bin/benchmark --target <target> --backend codex --regenerate \
  --run-id 20260530-142558

# Re-derive every run under output/benchmark/.
bin/benchmark --regenerate
```

`--regenerate` launches no audit/discovery agents. It re-routes, validates,
scores, clusters, and renders the evidence already on disk, and recomputes cell
status — so a cell an older run marked incomplete over one pending artifact can
recover. Source-semantic validation may invoke the configured reviewer when a
current content-addressed receipt is missing or stale; deterministic sanitizer,
identity, scoring, and counting work does not. Provider-limited and failed
cells stay excluded.

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
leaves the original crash evidence unchanged, marks finalization incomplete,
and reports why. Changes to a sanitizer build the evidence never used do not
block it. Older cells without a recorded identity can still be re-rendered,
but target-build-dependent crash replay is skipped.

It stays additive otherwise: a crash that was never bundled gets one, and
existing and hand-edited reports are left alone, whether or not replay ran. A
bundle rebuilds from source at the revision the run recorded — a run that
recorded none says `norev` rather than name the checkout's current commit —
but its build recipe is read from the target tree as it stands today, so a
recipe edited since the run is reflected in the bundle.

Any crash without a measured reproduction rate is re-run through the same
wrapper the harness uses, under exactly the runtime options its diagnostic
recorded, and only while the build artifacts that crash needs are still
available. Otherwise the pool keeps an unset `?` rather than a guess;
model-direct triage keeps unmeasured evidence under `crashes/` but withholds
its verdict, so it counts as unadjudicated rather than as a confirmed crash.
A bundle whose replay contract cannot be resolved at all — a build that is
gone, a harness nobody compiled — is held the same way; one that carries no
reproducer to run at all is left to the completeness gate instead, which holds
it pending before it rejects. Only a replay that ran and disagreed with the
report moves a crash into `findings/`.
Each pooled crash is checked against its owning cell and only
its own replay artifacts, so one changed binary does not cost unrelated
crashes their rates. A rate counts only runs that reproduced the original
fault — same sanitizer, primitive, faulting function, and normalized source
path and line where both diagnostics name them — so a replay that crashes
elsewhere is not a reproduction. Evidence whose own fault cannot be
characterised claims no rate.

## How to make the result worth reading

- Pick targets that can plausibly produce evidence inside the budget.
  If both rows stay at zero, you measured target hardness, not harness
  quality.
- Use 5+ replicates before making claims. Three replicates show a
  direction; they do not settle stochastic behavior.
- Compare more than one target. A harness change that helps one parser
  and hurts another should not disappear into a single headline row.
- Read the Medium+ subset of unique crashes and top crash severity before raw
  crash count.
  A pile of duplicated low-value crashes is not a stronger benchmark
  result than one clean, reachable reproducer.
- Keep the target fixed while comparing harness changes. `run.json`
  records target and harness revisions so old results remain auditable.
