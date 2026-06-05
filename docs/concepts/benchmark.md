# Benchmarking TokenFuzz

`bin/benchmark` answers one question with evidence rather than opinion:

> For the same target, backend, model, and wall-clock budget, does
> TokenFuzz find stronger **real, reproducible** security issues than
> a direct "find vulnerabilities" prompt?

You do not need to know the harness internals to run it or read the
result. This page is for the person deciding whether the harness is
earning its overhead: a security lead comparing approaches, a backend
operator tuning model choice, or a maintainer checking whether a
triage, clustering, reachability, or prompt change helped.

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
| `harness` | `tokenfuzz` | `bin/audit` as shipped: recon, ranked work cards, strategy rotation, `bin/probe`, triage, validation, clustering, reachability, and reproducer bundling. |

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
not as a statistical claim. LLM runs are stochastic; the first
TokenFuzz cell may also spend 10-30 minutes on cold recon before deep
investigation begins. For a result you would cite, use at least five
replicates and more than one target.

## Recon and budget

The `harness` condition is `bin/audit` as shipped, so a cold target
starts with recon. During a benchmark run, harness cells share a
per-run recon cache keyed to the target source and backend. The first
harness cell usually pays the cold-start recon cost; later harness
cells normally reuse the cache and spend more of their budget on
investigation.

Short budgets can therefore favor `model-direct`, especially when the
first harness cell is all recon and little probing. This is not a bug
in the benchmark. It is measuring whether TokenFuzz can repay its
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

## Reading the ledger

Each run section is ordered for review:

**Verdict** gives the strongest observed crash and which condition
found it. If no sanitizer-confirmed crash exists, it says so.

**Scoreboard** is the main comparison table:

| Column | Meaning |
| --- | --- |
| `Condition` | `tokenfuzz` or the direct baseline label. |
| `Replicates` | `done/total`; `(Nq)` means N cells exhausted provider quota. |
| `Wall (h)` | Median wall-clock hours per completed cell. |
| `Rejected findings` | FIND reports rejected by the validator. |
| `Findings` | Validated non-crash security reports. |
| `Unique findings` | Findings after duplicate signatures are clustered. |
| `Rejected crashes` | Crash directories rejected by triage. |
| `Crashes` | Crash directories with real sanitizer output on disk. |
| `Unique crashes` | Crashes after duplicate signatures are clustered. |
| `Medium+ crashes` | Unique crashes scored Medium or higher by reachability. |
| `Top severity` | Highest crash severity observed in the cell. |

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

It deliberately does not rebuild each crash's exported reproducer
bundle, because that step needs live audit-session state and can
overwrite hand-edited reports.

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
- Read unique Medium+ crashes and top severity before raw crash count.
  A pile of duplicated low-value crashes is not a stronger benchmark
  result than one clean, reachable reproducer.
- Keep the target fixed while comparing harness changes. `run.json`
  records target and harness revisions so old results remain auditable.
