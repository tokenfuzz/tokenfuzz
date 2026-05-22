# Benchmark the harness

`bin/benchmark` answers one question with evidence instead of opinion:

> For the same target, backend, and time budget, does the audit harness
> find more **real, reproducible** bugs than a bare "find all
> vulnerabilities" prompt?

You do not need to understand the harness internals to run it. This page
is written for any security team member who can open a terminal.

## What it does

It runs two **conditions** and compares them:

| Condition (`--conditions` token) | Shown on the page as | What it is |
| --- | --- | --- |
| `model-direct` | `<backend>-direct` (e.g. `codex-direct`) | One agent, a bare CTF prompt, no harness scaffolding. The control. |
| `harness` | `tokenfuzz` | `bin/audit` exactly as shipped. |

The `--conditions` flag always takes the stable tokens `model-direct` and
`harness`; the results page labels them with product-facing names — the
baseline after the backend that ran it, the harness as `tokenfuzz`.

Each condition is run several times (LLM runs vary, so one run proves
nothing), under an identical wall-clock budget. Every crash is counted
**only when AddressSanitizer output is on disk** — never because an agent
claimed it. That is what makes the number trustworthy.

## Quick start

```bash
bin/benchmark --target pcre2
```

That single command runs, with all defaults:

| Setting | Default | Meaning |
| --- | --- | --- |
| `--backend` | _(see below)_ | Agent backend, one of: `claude`, `codex`, `gemini`, `oss`. |
| `--replicates` | `3` | How many times each condition is run. |
| `--budget-wall` | `3600` | Seconds each run is allowed (60 minutes). |
| `--conditions` | `model-direct,harness` | Both conditions. |
| `--bench-root` | `output/benchmark` | Where all results are stored. |

So `bin/benchmark --target pcre2` is: **the default backend, 3 runs each
of model-direct and harness, 60 minutes per run** — six runs, about six
hours of wall-clock. Run `bin/benchmark --help` to see every option and
the exact default backend.

!!! note "Budget for the harness's recon pass"
    `harness` is `bin/audit` exactly as shipped, with one benchmark
    optimization: every harness cell in the same benchmark run shares a
    per-run recon cache for the same target source and backend. The first
    harness cell that sees a target's source may spend 10-30 minutes on
    breadth-first **recon** before deep investigation begins; later
    harness cells normally get a cache hit and spend their budget on
    investigation. A 30-minute first harness cell can still be eaten
    almost entirely by recon — which is why the default is 60 minutes.
    For a meaningful comparison, give each cell well over an hour.

!!! tip "Try it first with no API cost"
    `bin/benchmark --target pcre2 --dry-run` runs the whole pipeline with
    synthetic data and no LLM calls. Use it to see the output shape
    before spending a real budget.

## Reading the results

Results append to one backend ledger, for example
`output/benchmark/codex/benchmark-results.md`, with a styled
`benchmark-results.html` next to it. The root aggregate lives at
`output/benchmark/benchmark-result.md` and `.html`, and includes the latest
run for each backend/target pair.

Each run adds a section with three blocks, in the order you need them:

**Verdict** — one sentence: which condition found the strongest bug, and
the per-condition spread. Read this first.

**Scoreboard** — the headline table:

| Condition | Crashes | Unique bugs | Findings | Top severity | Medium+ bugs |
| --- | --: | --: | --: | :--: | --: |
| `tokenfuzz` | 2 | 1 | 2 | 🟡 Medium | 1 |
| `codex-direct` | 24 | 7 | 0 | ⬜ Low | 0 |

- **Crashes** — every AddressSanitizer-confirmed crash, all replicates.
- **Unique bugs** — crashes deduplicated by `bin/cluster-crashes`, so the
  same bug found 17 times counts once.
- **Top severity / Medium+ bugs** — severity is scored by
  `bin/reachability`, the *same lens applied to every crash of both
  conditions*. A high crash count at `Low` severity is not a win.

**Bugs by severity** — every distinct bug, sorted strongest-first, with a
`Found by` column and a link to its reproducer bundle.

!!! note "Why a big crash count can still lose"
    The `<backend>-direct` row is the un-triaged floor — a bare CTF prompt
    with no scaffolding. It often produces *more* raw crashes, because
    nothing filters API-misuse or self-inflicted crashes. `tokenfuzz` ships
    the triage + reachability + reproducer pipeline, so its crashes are
    reach-assessed and bundled. The **severity** columns, not the crash
    count, are what the comparison turns on.

Every pooled crash — both conditions — is bundled into a `REPORT.md` +
`REPORT.html` + `reproduce.sh` under `output/benchmark/<runid>/pool/crashes/`,
so you can open any bug and see exactly why it scored the way it did.

## Common variations

```bash
# More replicates = a more trustworthy result (5+ recommended for claims).
bin/benchmark --target pcre2 --replicates 5

# Give each run 90 minutes instead of the default 60.
bin/benchmark --target pcre2 --budget-wall 5400

# Only run the harness condition (skip the model-direct baseline).
bin/benchmark --target pcre2 --conditions harness

# Pick the agent backend (one of: claude, codex, gemini, oss).
bin/benchmark --target libxml2 --backend <backend>

# Start a fresh ledger (the previous one is archived, not deleted).
bin/benchmark --reset
```

## Things to know

- **Pick a target the harness can crack.** If both conditions score zero,
  the run tells you nothing. `libxml2` is a reliable producer; a hardened
  or already-audited target may not crash inside a one-hour budget.
- **Recon eats into the first harness budget.** The first `harness`
  cell for a benchmark run pays the cold-start recon cost for the current
  target source and backend. Later harness cells reuse the per-run recon
  cache via `AUDIT_RECON_CACHE_DIR` and normally start investigation
  sooner. The model-direct condition has no such startup cost, which is
  part of what the budget comparison measures: short budgets can favour
  model-direct, especially on the first harness cell.
- **Replication is part of the result.** LLM runs are stochastic. With 3
  replicates you get a ranking, not a statistically significant claim —
  use 5+ replicates and more than one target before drawing conclusions.
- **Your real audit output is untouched.** Every run is isolated under
  `output/<target>-bench-…/` via `bin/audit --experiment`.
- **Token usage is shown per experiment.** Each ledger section includes a
  **Token usage** table keyed by the cell's `--experiment` name, with
  input, cached-input, output, and prompt-estimate columns.
- **Some backends only estimate cost.** A backend whose CLI reports token
  usage gets real numbers; the `gemini` backend's `agy` CLI does not
  report usage, so its cells show a character-count or prompt-estimate
  row flagged `estimated` in the ledger. Missing Codex/Claude usage is
  treated as unknown/zero, not estimated from error text.
