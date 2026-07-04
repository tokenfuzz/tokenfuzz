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
| `harness` | `tokenfuzz` | `bin/audit` as shipped: recon, ranked work cards, strategy rotation, `bin/probe`, triage, validation, clustering, severity scoring, and reproducer bundling. |

The `--conditions` flag always uses the stable tokens
`model-direct` and `harness`. The rendered labels are reader-facing
names; they can include the selected model so old and new model runs
do not blur together.

Every cell gets the same per-cell wall-clock budget. With the defaults,
`bin/benchmark --target <target>` runs three `model-direct` cells and
three `harness` cells, each with a 10,800 second budget. That is six
cells, about 18 hours of wall-clock if run serially.

The benchmark keeps normal audit output separate. Cells run under
isolated `bin/audit --experiment` trees, then the benchmark pools and
scores their evidence under `output/benchmark/`.

## Why it is not a stopwatch

A useful benchmark is not "which row printed the largest number."

The direct prompt often produces more raw crash directories because it
has little structure around API misuse, duplicates, or self-inflicted
testcases. TokenFuzz spends budget on work the direct prompt does not
do: recon, queue construction, coverage-gated probes, validation,
deduplication, severity scoring, and maintainer-ready reproducers.

That overhead is part of the comparison. The question is whether the
extra machinery buys stronger evidence by the end of the same budget.
Read the severity and uniqueness columns before the raw counts.

## Quick start

```bash
bin/benchmark --target <target>
```

The target must already exist under `targets/<target>/` and have a
usable `output/<target>/target.toml`. If you have not created that
yet, start with [Add a target](../getting-started/add-a-target.md).

With all defaults, the command means:

| Setting | Default | Meaning |
| --- | --- | --- |
| `--backend` | `codex` | Agent backend. Valid values are `claude`, `codex`, `gemini`, and `oss`. |
| `--model` | backend config default | Optional model override used by both conditions. |
| `--replicates` | `3` | Runs per condition. |
| `--budget-wall` | `10800` | Seconds allowed per cell; `0` disables the outer timeout. |
| `--conditions` | `model-direct,harness` | Run both the direct baseline and TokenFuzz. |
| `--bench-root` | `output/benchmark` | Shared benchmark artifact root. |
| `--run-id` | UTC timestamp | Run directory under `output/benchmark/<backend>/`; reuse it to resume. |

Run `bin/benchmark --help` for the full option list.

## What a run looks like

The commands below run the same target through three backends, two
replicates per condition, at the default 3-hour cell budget:

```bash
bin/benchmark --target <target> --backend claude --replicates 2 --budget-wall 10800
bin/benchmark --target <target> --backend codex  --replicates 2 --budget-wall 10800
bin/benchmark --target <target> --backend gemini --replicates 2 --budget-wall 10800
```

That target has to be bootstrapped first: source in
`targets/<target>/`, build artifacts where the config says they are,
and `output/<target>/target.toml` reviewed. The shortest path is the
[Add a target](../getting-started/add-a-target.md) flow.

Treat a two-replicate, three-hour run as a layout and sanity check,
not as a statistical claim. LLM runs are stochastic; every TokenFuzz
cell spends 10-30 minutes on cold recon before deep investigation
begins. For a result you would cite, use at least five replicates and
more than one target.

## Recon and budget

The `harness` condition is `bin/audit` as shipped, so a cold target
starts with recon. Recon is not cached or shared: every harness cell
runs its own cold recon, so each replicate is an independent product
run and all replicates carry the recon cost equally. Recon is
stochastic, so the seeded hypotheses differ across replicates — that
variance is part of what the benchmark measures.

Short budgets can therefore favor `model-direct`, since every harness
cell spends part of its budget on recon before probing. This is not a
bug in the benchmark. It is measuring whether TokenFuzz can repay its
startup cost inside the budget you gave it.

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

The root `benchmark-result.html` is the cross-backend comparison. It is
refreshed as cells complete and again at the end of each run.

Each backend also has an append-only ledger,
`output/benchmark/<backend>/benchmark-results.html`, with one section
per run. Open the backend ledger when you want the full run narrative;
open the root crosstab when you want to compare targets, backends,
conditions, and reruns in one table.

Every pooled crash that survives triage is bundled under the run's
`pool/crashes/` tree with a `REPORT.md`, rendered `REPORT.html`, and
`reproduce.sh`.

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
| `Replicates` | `done/total`, with a suffix for cells that hit provider trouble: `(Nr)` recovered after a mid-run blip, `(Np)` provider-limited, `(Nq)` quota-exhausted. |
| `Wall (h)` | Median wall-clock hours per completed cell. |
| `Rejected findings` | FIND reports rejected by the validator. |
| `Findings` | Validated non-crash security reports. |
| `Unique findings` | Clustered findings, shown `N (M M+)`: N unique, M scored Medium or higher. Links to the finding cluster report. |
| `Rejected crashes` | Crash directories rejected by triage. |
| `Crashes` | Crash directories with real sanitizer output on disk. |
| `Unique crashes` | Clustered crashes, shown `N (M M+)`: N unique, M scored Medium or higher. Links to the crash cluster report. |
| `Top crash severity` | Highest crash severity observed in the cell. |

The count cells are links. They point into the condition-specific
crash, finding, rejected-crash, rejected-finding, and cluster reports
that produced the number.

**Token usage** appears when the backend reports usage or the harness
can estimate prompt size. The bold row per condition is the total to
compare. Gemini through the Antigravity CLI may show estimated prompt
tokens instead of measured usage; Gemini through `USE_GEMINI_CLI=1`
can provide measured numbers.

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
`output/canary/ground-truth.json`, outside the directory handed to the
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

A healthy run shows `tokenfuzz` at high recall *and* high precision: it
confirms the planted bugs and the traps do not slip through as confirmed
crashes. The direct baseline typically trails on both.

Score an existing results or pool tree directly:

```bash
python3 lib/benchmark.py score output/canary/<backend>/results \
  --ground-truth output/canary/ground-truth.json
```

This is the labelled signal to tune gate thresholds against. Tune
precision first: a change that raises recall but lets a trap through is
a regression the canary catches before it reaches a real audit.

### Measuring recall on real bugs

The same `ground-truth.json` shape works for any target. To measure
recall against real CVEs, add a manifest at
`output/<slug>/ground-truth.json` whose `planted_bugs` reference the real
crashing symbols and primitives, pin the target to a vulnerable revision,
and run the benchmark as usual. The scorer needs no code change — it keys
on the `(primitive, signature_symbol)` pair the clustering pipeline already
produces.

!!! warning "Keep real-bug manifests local — never commit them"
    A real-CVE manifest names actual crashing symbols and primitives, which
    discloses unreleased bug detail — exactly what the
    [neutral-fixture rule](https://github.com/tokenfuzz/tokenfuzz/blob/main/docs/development.md)
    forbids. `output/` is gitignored precisely so these stay private, so a
    real-bug `output/<slug>/ground-truth.json` is uncommitted by default —
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
- Use enough time for recon plus investigation. For small libraries,
  the first harness cell commonly spends 10-30 minutes on recon.
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
