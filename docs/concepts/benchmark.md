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

Each cell blocks instruction-file discovery above its launch directory using
the backend's enforceable mechanism. Claude runs in safe mode; Codex and Gemini
CLI disable parent traversal; and Antigravity and Grok Build receive a local
project boundary. Backend customizations are also disabled where the CLI
provides a per-run control: Codex disables plugins, OpenCode runs in pure mode,
and Gemini CLI disables skills and extensions. This keeps an operator-installed
security workflow from duplicating TokenFuzz's own orchestration or
contaminating the model-direct control. Antigravity and Grok Build currently
expose no equivalent one-shot plugin and skill isolation control, so disable
their installed plugins and skills before using them for benchmark claims.

The `--conditions` flag always uses the stable tokens
`model-direct` and `harness`. The rendered labels are reader-facing
names; they can include the selected model so old and new model runs
do not blur together.

Every cell gets the same per-cell wall-clock budget. With the defaults,
`bin/benchmark --target <target>` runs three `model-direct` cells and
three `harness` cells, each with a 10,800 second budget. That is six
cells, about 18 hours of audit time if run serially, plus bounded final
validation.

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
| `--finalize-wall` | `3600` | Separate wall-clock ceiling for final crash and finding validation. `0` is unlimited. |
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
bin/benchmark --target <target> --backend gemini --replicates 2 --budget-wall 10800
bin/benchmark --target <target> --backend grok   --replicates 2 --budget-wall 10800
```

That target has to be bootstrapped first: source in
`targets/<target>/`, build artifacts where the config says they are,
and `output/<target>/target.toml` reviewed. The shortest path is the
[Add a target](../getting-started/add-a-target.md) flow.

Treat a two-replicate, three-hour run as a layout and sanity check,
not as a statistical claim. LLM runs are stochastic. For a result you would
cite, use at least five replicates and more than one target.

After timed investigation stops, each cell synchronously drains the finding
quality gate before metrics are harvested. This final triage is measurement,
not additional finding time, so it gets a separate `--finalize-wall` budget.
Pending artifacts are excluded or qualified individually: an unadjudicated
finding does not enter the finding total, while a sanitizer-proved crash with
an unfinished report remains in the crash total at Unknown severity. A pending
artifact does not erase the rest of its replicate. A provider-limited run or
failed post-processing still leaves the cell incomplete.

Genuinely incomplete cells remain excluded from medians and aggregate yield. Their
confirmed on-disk yield is still shown as an observed count in the console and
run ledger, so an interrupted productive cell is not mistaken for a zero-yield
cell.

For validation, the configured benchmark target root is the product boundary.
Root-level sample or fixture labeling therefore cannot make an entire benchmark
target out of scope; ordinary non-shipping test, fuzz, example, benchmark, and
demo code below that root remains subject to the same exclusion review. The
validator also receives the target's configured `attacker_controls` from
`target.toml`.

Crash trigger review is skipped only when probe-authored evidence proves all
of the following: `bin/probe --confirm` reproduced the sanitizer crash 5/5,
the testcase and sanitizer binary still match their recorded identities, the
ordinary target binary was invoked without a custom harness or extra argv, the
first source-bearing fault frame belongs to the target tree, and the input
class is included in `attacker_controls`. Missing or stale evidence falls back
to the normal two-vote trigger review. Severity, clustering, bundling, and all
finding validation remain unchanged.

Model-direct crash evidence is additionally replayed through the configured
target invocation before it enters cell metrics. A stable 5/5 standard replay
receives the same trigger-review bypass; a clean or unexecutable replay is
preserved as a finding, and a measured 0/5 diagnostic is never counted as a
confirmed crash.

Source validators put their invariant instructions and target context before
candidate-specific facts. Repeated calls can therefore reuse the provider's
prompt-prefix cache without shortening the source-reading budget or changing
the vote contract.

Harness benchmark cells disable early-worker refills. This prevents the
configured agent count from silently expanding provider demand; standalone
`bin/audit` runs retain refills unless passed `--no-refill-workers`.

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

`run.json` records both the selected model and `resolved_effort`. Every
`logs/index.jsonl` usage event repeats `resolved_effort`, so archived runs show
the backend-native reasoning setting that was actually passed to the CLI even
when the operator's global backend settings differ.

The root `benchmark-result.html` is the cross-backend comparison. It appears
after the first cell saves metrics and refreshes after each later cell. While a
run is active, a **Provisional** banner marks the page: it shows finalized-cell
counts and cell status, while unique counts and severity remain pending. A
running cell contributes no counts until its own triage and validation finish.

The expensive pooled comparison is still rebuilt only once after the final
cell. That pass performs sanitizer revalidation, bundling, clustering, and
final report rendering; the live refresh only reads the atomic `cell.json` and
`metrics.json` files. Genuinely incomplete-cell evidence is labeled as observed
and stays excluded from medians and completed-cell totals. Artifact-level
finalization state remains available in cell metrics and linked reports without
widening the cross-run comparison table.

Each backend also has an append-only ledger,
`output/benchmark/<backend>/benchmark-results.html`, with one section
per run. Open the backend ledger when you want the full run narrative;
open the root crosstab when you want to compare targets, backends,
conditions, and reruns in one table.

Every pooled crash that survives triage is bundled under the run's
`pool/crashes/` tree with a `REPORT.md`, rendered `REPORT.html`, and
`reproduce.sh`.

Benchmark audit cells are pinned to the canonical primary build and disable
automatic sibling routing. This keeps backend and condition comparisons on one
identical compiled surface; widened-build exploration remains an ordinary-audit
feature rather than a benchmark variable.

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
| `Replicates` | `done/total`. Replicates that recovered from a mid-run provider pause got their full budget and fold in unmarked; a `(Np)` suffix flags N provider-limited replicates excluded from the totals (a same-run-id re-run retries them). |
| `Wall (h)` | Median hours a cell spent finding things. The triage and validation that follow the audit are measurement, not finding work, so they are not counted. |
| `Unique rejected findings` | FIND reports the validator rejected, after clustering merges duplicates where evidence permits. `≤ N` marks an upper bound. |
| `Unique accepted findings` | Clustered non-crash security reports an agent investigated, shown `N (M M+)`: N unique, M scored Medium or higher. Links to the finding cluster report. |
| `Unique rejected crashes` | Crash candidates triage rejected, after stack/signature clustering merges duplicates where evidence permits. `≤ N` marks an upper bound. |
| `Unique accepted crashes` | Clustered crash directories with real sanitizer output on disk, shown `N (M M+)`: N unique, M scored Medium or higher. Links to the crash cluster report. |
| `Top crash severity` | Highest crash severity observed in the cell. |

The same clusterers (`bin/cluster-findings` / `bin/cluster-crashes`) deduplicate
both sides of the gate whenever the artifacts carry clustering evidence. A raw
directory tally counts one root cause many times over, and a raw reject count
set against a clustered accept count measures two different things.

Two cases read as upper bounds rather than exact counts, both deliberately: a
legacy ledger can hold rejection rows with no directory and so no evidence to
cluster, and a clustering step that could not run reports the raw count. Both
over-state rather than hide — a rejected result never silently disappears from
the column.

The count cells are links. They point into the condition-specific
crash, finding, rejected-crash, rejected-finding, and cluster reports
that produced the number.

**Time to discovery**, below the table, plots those same numbers over time: one
row per target revision, findings and crashes side by side. Each step is one
deduplicated accepted result placed at the hour it was found, so the curve only
climbs and ends exactly on the `Unique accepted` count. The chip above each
curve shows what the gate accepted and rejected. Discovery times come from the
`finding_created` stamps in `state/events.jsonl` and the immutable filing clock
on new crash bundles. Runs recorded before those clocks existed fall back to
the artifacts' own timestamps. When a discovery time is unavailable, the panel
says the timing is approximate rather than implying an exactness it does not
have. Accepted and rejected artifacts are deduplicated separately. Because one
root with mixed gate decisions can appear on both sides, the graph reports both
counts without inferring a retention percentage. A `≤` rejected count remains
a conservative upper bound. Neither count is precision, which needs the answer
key described below.

**Token usage** appears when the backend reports usage or the harness
can estimate prompt size. The bold row per condition is the total to
compare. Harness totals include model preflight, audit agents, and
harness-owned decisions such as triage, cluster expansion, work reranking, and
peer mapping. One-shot calls without provider telemetry are estimated and
marked as such. Gemini through the Antigravity CLI may show estimated prompt
tokens instead of measured usage; Gemini through `USE_GEMINI_CLI=1` can
provide measured numbers.

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
record-processing program at `targets/canary/` — the one target tree
committed to the repo (the rest of `targets/` is a gitignored working
area). It carries a handful of distinct planted memory-safety bugs and a
couple of deliberate false-positive traps (inputs that look dangerous to a
reviewer but are not a memory-safety fault), enough to exercise detection,
triage, clustering, and severity scoring end to end.

The answer key is deliberately **not** in the target tree. It lives at
`output/canary/.ground-truth.json`, outside the directory handed to the
audited agents, so the score stays blind — an agent auditing the canary is
not also handed a list of which inputs are real bugs and which are traps.
The deterministic scorer reads it after the run. Each planted bug pins its
sanitizer primitive and the stack frame it crashes in; each trap declares
the benign outcome it expects. The canary is 100% synthetic, so the answer
key discloses no real project's bug.

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
```

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

A mid-run account/session usage limit (any backend) no longer ends a cell: the
harness pauses it until the backend's reset — that wait is excluded from the
cell's productive budget and from the reported `Wall (h)` — and marks it
provider-limited only if the backend has still not recovered after 6h.

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

`--regenerate` launches no agents and makes no API calls. It rebuilds
the pool, re-runs severity scoring and crash/finding clustering,
refreshes per-condition cluster reports, rewrites `report.json`, and
updates `benchmark-result.{md,html}` plus the backend ledger row.

It also recomputes stale cell status after post-processing succeeds. This
recovers runs written by older versions that marked a whole cell incomplete
because one artifact was pending; provider-limited and failed cells remain
excluded.

The exported reproducer bundle pass still runs, but stays additive: a
crash with no canonical bundle yet (a model-direct freeform baseline,
never bundled at audit time) gets one, while already-bundled crashes —
every harness crash, plus any hand-edited report — are left untouched,
never re-bundled or re-rendered. Re-bundling an existing report would
need live audit-session state and could overwrite hand edits, so the
pass skips anything that already carries a canonical bundle.

Reproduction rate is measured the same way for every pooled crash, so
the rate is comparable across conditions: any crash lacking a measured
rate is re-run through the same multi-run wrapper the harness path uses,
and a crash that can't be re-run keeps an unset (`?`) rate rather than a
guessed one.

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
