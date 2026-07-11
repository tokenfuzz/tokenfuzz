# Recon discovery

Recon is a bounded, breadth-first review pass over target source. It runs before
deep agents on a cold multi-iteration audit and can also run independently with
`bin/audit-recon`. A one-iteration smoke test skips it.

What recon is for, in one line:

> Surface the suspicious-looking spots in the codebase as a starting
> list, before the deep agents start writing testcases.

For comparison, a full audit can continue for hours and execute testcases.
Recon is a bounded source-reading pass: it writes candidate locations for the
deep audit to investigate.

## When recon runs

You normally never invoke it directly. It runs automatically at the
start of an audit, then its findings become work cards that the deep
agents pick up.

```bash
bin/audit --target curl --backend <backend>  # runs recon, then the audit
```

On the first multi-iteration run for a target revision, recon spends its
configured per-agent time budget. Later runs against the same revision reuse
the cached result. Update the source and recon runs again for the new revision.

You can also call it on its own to look at the candidate list before
starting an audit:

```bash
export TARGET=curl
export BACKEND="<backend>"     # one of: claude, codex, gemini, grok, oss
bin/audit-recon --target "$TARGET" --backend "$BACKEND"
ls "output/$TARGET/$BACKEND/results/recon-findings.md"
```

The standalone command writes the same two files the auto-run does:

- `output/<target>/<backend>/results/recon-findings.md` — human read.
- `output/<target>/<backend>/results/recon-hypotheses.jsonl` —
  machine read, also the source the audit's work queue is seeded from.

## What recon does, step by step

1. **Looks at the source tree.** No sanitizer, no testcase yet — just
   the code.
2. **Splits the work across several agents.** The slicer partitions the
   in-scope source files into N groups and runs one agent per group.
   Grouping follows the directory tree — a directory is the project
   author's own functional decomposition — and slices are balanced by
   **lines of code**, not file count, so no agent draws a slice many
   times heavier than its peers. Every file lands in exactly one slice.
   A flat source tree (no subdirectories) has no structure to exploit,
   so it falls back to LOC-balanced contiguous chunks.
3. **Each agent reads code looking for vulnerabilities.** The prompt
   is the same on every agent: a broad instruction to surface potential
   security issues without pre-filtering — guard gaps,
   suspicious arithmetic, unchecked input, lifetime patterns,
   protocol-state quirks. The agent is asked for **recall, not
   precision**; it is told *not* to pre-filter.
4. **A validator gate votes the candidates.** After the sweep, near-duplicate
   emissions are collapsed to one representative each (so the same defect
   spotted from several slices is judged once), a triage pass votes each
   representative Promote, Reject, or Uncertain, and the strongest survivors
   get a deeper independent second look. That deep pass is bounded, so a
   thousand-candidate emission cannot blow up validation cost — anything past
   the cap keeps its triage verdict, marked Uncertain. Promoted candidates
   move to the front of the audit queue; rejected and uncertain ones are
   demoted but retained, so later sanitizer evidence can still overturn the
   vote. The verdict is recorded on the work card — the validator does not
   keep re-ranking the queue during the audit.
5. **Candidates become work cards for `bin/audit`.** When the audit
   starts, the deep agents pick up recon-derived cards before falling
   back to their own ranked queue. If the target enables multiple
   sanitizers, one recon candidate may create multiple cards so each
   enabled runner gets a proof attempt.

## Why two stages — recon and audit — and not one big run?

Recon answers "where might there be bugs?"; the audit answers "is this
specific bug real, and can we trigger it under a sanitizer?". One is a
fast breadth-first survey, the other a deep serial investigation.
Splitting them lets recon front-load the candidate list so the deep
agents start on the right files instead of discovering them through
the much slower ranked-queue scan.

## Scope: how recon stays bounded on big codebases

A whole-tree recall sweep of a small library is cheap. The same sweep
of a large codebase is not — it is unbounded, potentially many hours of
agent time, and most of that time is spent re-reading stable code that
fuzzers and upstream review have already pounded. So recon **scopes**
the file set before slicing it. `--scope` controls this:

| Scope | What it audits | When `auto` picks it |
| --- | --- | --- |
| `all` | Every source file in the tree. | Small trees (≤500 source files). |
| `since` | Only files changed within the lookback window — the bounded, change-driven scope. | Large trees (>500 source files). |
| `path` | One subtree (`--path <subdir>`). | Never auto-selected; ask for it explicitly. |

`auto` is the default and is correct for almost everyone: small targets
get whole-tree coverage, large targets get change-driven coverage.

### Why `since` has a lookback limit

`--scope since` audits files changed in a git window. Without a bound,
"changed" could reach back across the entire history of the repository
— on a large, long-lived codebase that is thousands of files and, again,
many hours of recon for a single cold start. `--recon-lookback` caps
that window. It **defaults to 365 days**: a year of churn is a
generous, still-bounded audit surface. Raise it to widen coverage at
proportionally higher cost (`--recon-lookback 730`), or lower it for a
faster incremental pass.

Recon also records a per-target **checkpoint** — the commit it last ran
at. A later `since` run audits forward from that checkpoint instead of
re-scanning the full window, so repeated runs only re-audit genuinely
new changes. The checkpoint never reaches back further than the
lookback window, so the 365-day bound is always the worst case.

To audit a specific subsystem regardless of churn, use `--path` — e.g.
`bin/audit-recon --target firefox --backend <backend> --path netwerk`.

## What happens when recon misses

Recon is one sample. The same model on the same source can produce
6 substantive findings on one run and 0 on the next — that variance
is real on a single recon roll.

Two safety nets:

- **Auto re-roll.** If every agent in the first pass returned
  AUDIT-CLEAN with nothing substantive, the recon re-shuffles the
  slice partition and runs once more. Triggered only on the
  pathological case; doubles the cost only when it fires. Disable
  with `--no-reroll` if you want strict single-pass cost control
  (e.g. on CI).
- **The deep audit still runs.** Recon-seeded cards are at the top
  of the queue, but the audit's regular ranked queue (recent fixes,
  coverage gaps, peer projects) is still there underneath. A
  zero-recon run is not a zero-audit run.

## Calibration: recall first, then precision

The first stage emits broadly, including patterns that turn out to have an
upstream guard or downstream bound. That is expected. Validator votes order the
queue so stronger candidates are investigated first; weaker candidates remain
available for later evidence rather than disappearing.

## Tuning, if you need it

The defaults are tuned for normal use. The knobs that matter:

| Flag | Default | When to push it |
| --- | --- | --- |
| `--timeout N` | 1800 seconds per agent | Bigger files or a denser callgraph. 2700–3600 is fine. Lower than 1200 risks recall on subtle bugs. |
| `--no-reroll` | off (re-roll is on) | Disable the variance re-roll. Useful on CI; not recommended for ad-hoc audits. |
| `--concurrency N` | 4 | Number of parallel recon agents. Raise it for finer-grained coverage; each unit is one more parallel recon agent. |
| `--scope S` | `auto` | Force `all`, `since`, or `path` instead of the size-based default. |
| `--path <subdir>` | — | Audit one subtree; implies `--scope path`. |
| `--recon-lookback N` | 365 days | Widen or narrow the `--scope since` change window. |
| `--validate <mode>` | `all` | Validator pass over candidates: `off` skips it, `confirmed` is a cost-saving mode that validates only candidates the recon agent already marked confirmed, `all` validates every candidate. |

You can also pick a backend explicitly:

```bash
bin/audit-recon --target curl --backend <backend>
```

Pick the backend you plan to use for the audit run. Recon output is
stored under that backend's result tree, so using the same backend
keeps the survey and follow-up audit artifacts together.

## What recon will not do

- It does **not** produce sanitizer-reproducible crashes. Its outputs are
  unverified candidates and work cards, not accepted findings or crashes.
- It does **not** file anything upstream. Every artifact stays in
  your local results directory until you review it.
- It does **not** wander across the slice boundary by design. Each
  agent stays in its file group (it may read one level of caller to
  trace a finding); a bug that needs cross-slice reasoning is a job for
  the audit's deep loop, not recon.

## See also

- [Audit lifecycle](../concepts/audit-lifecycle.md) — recon's place
  in the end-to-end run.
- [System architecture](../concepts/system-architecture.md) — how
  recon's outputs become work cards.
- [Backends and ensembling](backends.md) — running the same target
  with multiple backends and merging results.
- [Cost model](../concepts/cost-model.md) — what scales with the
  recon stage and how to keep it under control.
