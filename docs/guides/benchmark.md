# Benchmark the harness

`bin/benchmark` answers one question with evidence rather than opinion:

> For the same target, backend, and time budget, does the audit harness
> find more **real, reproducible** bugs than a bare "find all
> vulnerabilities" prompt?

You do not need to know the harness internals to run it or read the
result. This page is written for any security team member who can open a
terminal and a browser tab.

## What it does

It runs two **conditions** head-to-head and compares them:

| Condition (`--conditions` token) | Shown on the page as | What it is |
| --- | --- | --- |
| `model-direct` | `<backend>-direct` (e.g. `codex-direct`) | One agent, a bare CTF prompt, no harness scaffolding. The control. |
| `harness` | `tokenfuzz` | `bin/audit` exactly as shipped. |

The `--conditions` flag always takes the stable tokens `model-direct` and
`harness`; the results page labels them with product-facing names — the
baseline after the backend that ran it, the harness as `tokenfuzz`.

Each condition is run multiple times (LLM runs are stochastic, so one
run proves nothing) under an identical wall-clock budget. A crash is
counted **only when an AddressSanitizer report is on disk** — never
because an agent claimed it in prose. That is what makes the number
trustworthy.

## Quick start

```bash
bin/benchmark --target pcre2
```

With all defaults, that command runs:

| Setting | Default | Meaning |
| --- | --- | --- |
| `--backend` | _(see below)_ | Agent backend, one of: `claude`, `codex`, `gemini`, `oss`. |
| `--replicates` | `3` | How many times each condition is run. |
| `--budget-wall` | `10800` | Seconds each run is allowed (180 minutes / 3 hours). |
| `--conditions` | `model-direct,harness` | Both conditions. |
| `--bench-root` | `output/benchmark` | Where all results are stored. |
| `--run-id` | _(UTC timestamp)_ | Name of the run directory. Re-use a prior id to resume an interrupted run. |

So `bin/benchmark --target pcre2` is: **the default backend, 3 runs
each of model-direct and harness, 180 minutes per run** — six runs,
about eighteen hours of wall-clock. Run `bin/benchmark --help` to see every
option and the exact default backend.

!!! note "Budget for the harness's recon pass"
    `harness` is `bin/audit` exactly as shipped, with one benchmark
    optimization: every harness cell in the same benchmark run shares a
    per-run recon cache keyed on the same target source and backend. The
    first harness cell that sees a target's source typically spends
    10–30 minutes on a breadth-first **recon** pass before deep
    investigation begins; later harness cells normally get a cache hit
    and spend their budget on investigation. A short first harness cell
    can be eaten almost entirely by recon — which is why the default is
    180 minutes (3 hours). For a meaningful comparison, give each cell
    well over one hour.

!!! tip "Try it first with no API cost"
    `bin/benchmark --target pcre2 --dry-run` runs the whole pipeline
    with synthetic data and no LLM calls. Use it to see the output shape
    before spending a real budget.

## What a run looks like

The example below is one illustrative run on `cjson` with three
backends, two replicates each, at the default 3-hour budget — the
same commands you can reproduce locally:

```bash
bin/benchmark --target cjson --backend claude --replicates 2 --budget-wall 10800
bin/benchmark --target cjson --backend codex  --replicates 2 --budget-wall 10800
bin/benchmark --target cjson --backend gemini --replicates 2 --budget-wall 10800
```

_Benchmark comparison screenshot — pending._

It is a demo of the output shape, not a statistical comparison. LLM
runs are stochastic and a two-replicate, three-hour cell can swing either
way across reruns; the first harness cell also pays the recon cost.
For a defensible head-to-head, push `--replicates` to 5+ and
`--budget-wall` well past the first harness cell's recon cost, across
more than one target.

## Reading the results

Results append to one backend ledger, for example
`output/benchmark/codex/benchmark-results.md`, with a styled
`benchmark-results.html` rendered next to it. The cross-backend
aggregate lives at `output/benchmark/benchmark-result.md` (and `.html`)
and folds in the latest run for each backend/target pair.

Each run adds three blocks in the order you need them:

**Verdict** — one sentence: which condition found the strongest bug,
and the per-condition spread. Read this first.

**Scoreboard** — the headline table. Columns are grouped by *evidence
type* (findings vs. crashes) and a *severity tail* that scores both
conditions on the same scale:

| Column | Meaning |
| --- | --- |
| `Condition` | `tokenfuzz` (the harness) or `<backend>-direct` (the bare baseline). |
| `Replicates` | `done/total`; a `(Nq)` suffix means N replicates hit a provider quota — treat as upper-bounded effort, not a failure. |
| `Wall (h)` | Median per-replicate wall-clock, in decimal hours. |
| `Rejected findings` | FIND reports an independent validator agent threw out (false positives, misreadings, sanitizer-already-catches). Links to `REJECTED-FINDINGS`. |
| `Findings` | FIND reports that survived the validator gate but produced no crash artifact — leads, not yet bugs. |
| `Unique findings` | Findings after `bin/cluster-findings` merges duplicate signatures. Each row in `FINDING-CLUSTERS` is a unique root cause; the `Members` column links every FIND-* report sharing the signature. |
| `Rejected crashes` | Crash directories triage discarded (not reproducible, harness artefact, known issue). Links to `REJECTED-CRASHES`. |
| `Crashes` | Crash directories that survived triage. Reproducible ASan reports with stack frames on disk. |
| `Unique crashes` | Crashes after `bin/cluster-crashes` merges duplicate signatures. |
| `Medium+ crashes` | Unique crashes scored Medium or higher by `bin/reachability`. The headline impact metric — low-severity noise inflates `Crashes` without moving this. |
| `Top severity` | Highest tier observed in the cell (`Low` / `Medium` / `High` / `Critical`, or `—` if nothing triaged). |

!!! note "Why a big crash count can still lose"
    The `<backend>-direct` row is the un-triaged floor — a bare CTF
    prompt with no scaffolding. It often produces *more* raw crashes,
    because nothing filters API-misuse or self-inflicted crashes.
    `tokenfuzz` ships the triage + reachability + reproducer pipeline,
    so its crashes are reach-assessed and bundled. The **severity**
    columns, not the raw crash count, are what the comparison turns on.

**Finding Clusters** (`FINDING-CLUSTERS.html`) — every unique root cause,
sorted strongest-first. The columns mirror the scoreboard's evidence
grouping at the per-cluster level:

| Column | Meaning |
| --- | --- |
| `Severity` | `Critical` / `High` / `Medium` / `Low` / `—`, scored by `bin/reachability`. |
| `Cluster` | Stable id (`FCL-<hash>`) for the root cause. |
| `Size` | Number of FIND reports merged into this cluster. |
| `Class` | Bug family (e.g. `memory-safety`, `dos`, `logic`, `input-validation`). |
| `Strategy` | Which audit strategy (`S5`, `S7`, …) produced the canonical report; `—` for findings from other sources. |
| `Signature kind` | How the signature was derived: `llm` (semantic), `loc` (file:function). |
| `Signature` | The neutral signature string that clustered these reports. |
| `Canonical` | The representative FIND-* (highest severity / smallest id). |
| `Members` | Every FIND-* in the cluster; canonical is **bold**. |
| `Status` | `OK`, or a marker noting why a member was excluded. |

**Bugs by severity** — every distinct crash, sorted strongest-first,
with a `Found by` column and a link to its reproducer bundle.

Every pooled crash — both conditions — is bundled into a `REPORT.md`
+ `REPORT.html` + `reproduce.sh` under
`output/benchmark/<backend>/<runid>/pool/crashes/`, so you can open any bug and
see exactly why it scored the way it did.

## Common variations

```bash
# More replicates = a more trustworthy result (5+ recommended for claims).
bin/benchmark --target pcre2 --replicates 5

# Give each run 90 minutes instead of the default 180.
bin/benchmark --target pcre2 --budget-wall 5400

# Only run the harness condition (skip the model-direct baseline).
bin/benchmark --target pcre2 --conditions harness

# Pick the agent backend (one of: claude, codex, gemini, oss).
bin/benchmark --target libxml2 --backend <backend>

# Start a fresh ledger (the previous one is archived, not deleted).
bin/benchmark --reset
```

## Resuming an interrupted run

A run can stop partway — most often when the provider's quota or rate limit
is hit mid-sweep, leaving some replicates `failed`, `quota_exhausted`, or
unfinished. To finish it, wait for quota to return and re-run **the same
command with the run's `--run-id`** — the run directory name under
`output/benchmark/<backend>/`, a UTC timestamp like `20260530-142558`:

```bash
bin/benchmark --target cjson --backend claude --replicates 2 \
  --run-id 20260530-142558
```

Resume is per replicate and covers both conditions: cells already marked
`done` are kept and skipped, and every incomplete cell — in model-direct
*and* harness — is wiped clean and re-run, so a half-finished replicate's
artifacts are never folded into the result. `--replicates` is the target
total, so you can raise it on resume to add more replicates; pass the same
`--conditions` you started with.

## Regenerating results after a code change

When you change a *post-processing* algorithm — how severity is scored, how
crashes or findings are clustered, how the rollup tables render — the cells
already on disk are still valid; only the derived results are stale. Re-run
just the deterministic post-processing with `--regenerate`:

```bash
# Re-derive the most recent run for this target + backend.
bin/benchmark --target pcre2 --backend codex --regenerate

# Or target a specific run by id.
bin/benchmark --target pcre2 --backend codex --regenerate \
  --run-id 20260530-142558

# Re-derive EVERY run under the bench root — all targets and backends —
# and rebuild the full cross-backend page in one go.
bin/benchmark --regenerate
```

With no `--target`, `--regenerate` walks every `<backend>/<runid>/` under the
bench root, reads each run's target and backend from its `run.json`, re-derives
it, then rebuilds the cross-backend `benchmark-result.{md,html}` so the whole
page reflects every config you have run there.

`--regenerate` launches no agents and makes no API calls. It re-pools the
run's crash and finding directories, then re-runs `bin/reachability`
(severity), `bin/cluster-crashes`, and `bin/cluster-findings` over the pool,
and rebuilds `report.json`, the ledger row, and
`benchmark-result.{md,html}` — the unique-bug counts, severity, and dedup
columns all refresh.

It deliberately **does not** rebuild each crash's `export-repro` `REPORT.md`
bundle. That rebuild needs the live audit session a re-derivation no longer
has, and would overwrite any hand-edits to a report — so regeneration leaves
the individual reports alone and only refreshes the cluster tables and
rollups. The original `run.json` metadata (replicates, budget, the target and
harness SHAs at audit time) is preserved untouched.

## Things to know

- **Pick a target the harness can crack.** If both conditions score
  zero, the run tells you nothing. `libxml2` is a reliable producer; a
  hardened or already-audited target may not crash inside a two-hour
  budget.
- **Recon eats into the first harness budget.** The first `harness`
  cell for a benchmark run pays the cold-start recon cost for the
  current target source and backend. Later harness cells reuse the
  per-run recon cache via `AUDIT_RECON_CACHE_DIR` and normally start
  investigation sooner. The model-direct condition has no such startup
  cost, which is part of what the budget comparison measures: short
  budgets can favour model-direct, especially on the first harness
  cell.
- **Replication is part of the result.** LLM runs are stochastic. Three
  replicates give you a ranking, not a statistically significant claim
  — use 5+ replicates and more than one target before drawing
  conclusions.
- **Your real audit output is untouched.** Every run is isolated under
  `output/<target>-bench-…/` via `bin/audit --experiment`.
- **Token usage is reported per experiment.** Each ledger section
  includes a **Token usage** table keyed by the cell's `--experiment`
  name, with input, cached-input, output, and prompt-estimate columns.
- **Some backends only estimate cost.** A backend whose CLI reports
  token usage gets real numbers; the `gemini` backend's `agy` CLI does
  not, so its cells show a character-count or prompt-estimate row
  flagged `estimated` in the ledger. Missing Codex/Claude usage is
  treated as unknown/zero, not estimated from error text.
