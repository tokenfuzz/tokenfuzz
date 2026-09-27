# Artifact layout

Where TokenFuzz writes a target's configuration, evidence, structured state,
review pages, and logs. Paths are relative to the repository root. The
examples use:

```bash
export TARGET="<target>"
export BACKEND=claude             # or codex, gemini, grok, oss
export RESULTS="output/$TARGET/$BACKEND/results"
```

Start with the generated HTML pages, each rendered from the Markdown beside
it:

| Page | Shows |
| --- | --- |
| `$RESULTS/crashes/crash-clusters.html`, `$RESULTS/findings/finding-clusters.html` | Cluster indexes: matching evidence with discovery time, subsystem, strategy, and member reports. A cluster groups evidence; it does not prove one root cause ([Deduplication](../concepts/deduplication.md)). |
| `$RESULTS/crashes-rejected/rejected-crashes.html`, `$RESULTS/findings-rejected/rejected-findings.html` | Rejected artifacts, grouped by gate and reason. |
| `$RESULTS/crashes/CRASH-*/report.html`, `$RESULTS/findings/FIND-*/report.html` | One claim: source location, suggested fix, reproduction, review receipt, severity, and bundle files. |

Empty `crashes/` and `findings/` after a short run do not mean the run
failed; check the rejected indexes for candidates that were filed and
rejected. Read `logs/` only to debug orchestration, backend authentication,
or wrapper failures.

!!! example "A real tree to browse"
    The handbook ships a benchmark pool from a sample target:
    [crash clusters](../assets/examples/benchmark-sample-c/claude/20260916-141941/pool/crashes/crash-clusters.html),
    [a crash report](../assets/examples/benchmark-sample-c/claude/20260916-141941/pool/crashes/CRASH-0001/report.html),
    and [a finding report](../assets/examples/benchmark-sample-c/claude/20260916-141941/pool/findings/FIND-0001/report.html).
    Pools renumber artifacts as `CRASH-0001` and `FIND-0001`; an audit tree
    uses the names described below.

## Overview

```text
targets/<target>/                   source checkout, or a symlink to a local tree
  .audit/                           harness recipes, leases, logs, and caches
  build-<san>/, build-asan+cov/, …  sanitizer builds
output/<target>/
  target.toml                       the target's configuration
  crash-clusters.md, .html          cross-backend crash rollup
  finding-clusters.md, .html        cross-backend finding rollup
  <backend>/
    results/                        evidence, structured state, review pages
    logs/                           orchestration logs and transcripts
output/benchmark/                   benchmark runs
```

## Target root

`targets/<target>/` is the audited source: a clone, or a symlink to a local
plain source tree whose build output then lands in that tree (see
[Set up a target](commands.md#set-up-a-target)). When `target.toml` sets
`source_subdir`, the entries below live in that subdirectory.

| Path | What it is |
| --- | --- |
| `build-<san>/` | Sanitizer build for `asan`, `ubsan`, `msan`, or `tsan`. A tree the harness built carries an `.audit-build-stamp` with the revision, source signature, and recipe digest it was built from. |
| `build-asan+cov/` | Coverage sibling that `bin/hits` replays native testcases in. |
| `build-<san>+fuzz/` | Sibling with libFuzzer coverage feedback, linked by `bin/fuzz`. |
| `build-asan+cfg-<id>/` | Alternate ASan build configuration from `bin/build-configs`. |
| `.audit/build.sh`, `.audit/build-<san>.sh` | Canonical build recipes: `build.sh` for ASan, `build-<san>.sh` for the others. `bin/cleanup_state` keeps these. |
| `.audit/configs/<id>.asan.sh` | Recipes for alternate configurations. |
| `.audit/build-locks/`, `.audit/source-pins/` | Leases and source pins that stop one run rebuilding a tree another run is reading. |
| `.audit/build-materialize-<san>*.log` | Build logs. |
| `.audit/python-runner-asan` | Generated ASan-first Python host for a Python extension with no CLI. |

The rest of `.audit/` is toolchain caches, bootstrap stamps, and build
scratch, none of it audited source.

## Target output root

| Path under `output/<target>/` | What it is |
| --- | --- |
| `target.toml` | The generated configuration you review; see the [target config reference](target-toml.md). |
| `.ground-truth.json` | Sample targets only: the answer key for benchmark scoring. An input; `bin/cleanup_state` never removes it. |
| `crash-clusters.md`, `.html`; `finding-clusters.md`, `.html` | Cross-backend rollups over every `<backend>/results/` tree. The audit keeps them current; `bin/cluster-crashes output/<target>` and `bin/cluster-findings output/<target>` rebuild them. Rejected artifacts have no rollup. |
| `<backend>/` | One tree per backend; see below. |

A nested slug keeps its path: `samples/sample-c` lives in
`output/samples/sample-c/`. `bin/audit --experiment <name>` writes to
`output/<target>-<name>/` instead, so trial runs never mix with the main
audit. A `--target-path` run outside `targets/` is named after the
directory's basename.

## Backend directory

`output/<target>/<backend>/` holds `results/` and `logs/`. Each backend
(`claude`, `codex`, `gemini`, `grok`, or `oss`) gets its own tree, so runs
from different providers never overwrite each other's state.

## Results directory

| Path | What it is |
| --- | --- |
| `crashes/` | Crash candidates, `CRASH-<NNN>-<agent>/`, plus `crash-clusters.md` and `.html` for this backend. `.probe-filed-<agent>.tsv` is the index `bin/probe` uses to avoid filing a crash state twice; `.duplicates/` holds bundles triage folded into an already-reportable crash. |
| `crashes-rejected/` | Rejected crash directories, each with a `rejection.md`, plus `rejected-crashes.md` and `.html`. |
| `findings/` | Finding candidates, `FIND-*/`, of any class, with or without a reproducer, plus `finding-clusters.md` and `.html`. |
| `findings-rejected/` | Findings that failed substance, source, or publication review, or whose scope stayed unsettled after review completed, each with a `rejection.md`, plus `rejected-findings.md` and `.html`. |
| `scratch-<N>/` | Agent `N`'s working testcases and their output. |
| `corpus/` | Seeds: inputs that reached new coverage in a clean run. `COVER-<NNN>-<agent>/` holds the input, its run output, and `metadata.md`; `corpus/index.md` lists them. Duplicate content is dropped. |
| `coverage/edges-agent-<N>.journal` | Coverage edges first seen by agent `N`'s `bin/hits` replays, as `function|target-relative path`. Read by `bin/coverage-summary` and `bin/rank-work`. |
| `hits-<N>.log` | One `HIT`, `MISSED`, or `COVERAGE_UNAVAILABLE` line per coverage replay by agent `N`. |
| `tried-inputs-<N>.log` | One line per sanitizer run set by agent `N`: verdict, input hash, hypothesis, closest frame. Read by `bin/state recent-tried`. |
| `fuzz/` | The S4 fuzzing campaign; see [below](#fuzzing-campaign). |
| `fuzz-leads.md` | Non-noise libFuzzer artifacts summarised as leads by `bin/triage-fuzz-crashes`. |
| `fuzz-crashes/` | Artifacts from a sanitizer runner's `fuzz` mode; `shutdown-noise/` holds moved infrastructure noise. |
| `work-cards.jsonl` | The ranked work-card queue, replaced on each refresh. |
| `patch-cards.jsonl`, `s6-peer-cards.jsonl` | S1 prior-fix and S6 peer-fix cards merged into the queue. |
| `state/` | Structured ledgers; see [below](#structured-progress). |
| `.session-env` | The session's `RESULTS_DIR`, `TARGET_ROOT`, `TARGET_SLUG`, `TARGET_REV`, `TARGET_REPO_TYPE`, `LOGDIR`, and `SESSION_STARTED`, plus `TARGET_CONFIG_SHA256` once preflight pins the config. `bin/probe` and the other session tools find their session by walking up to this file. |
| `.target.toml` | The post-preflight `target.toml` snapshot the session runs against, pinned by `TARGET_CONFIG_SHA256`. Session tools read it, not `output/<target>/target.toml`; editing or removing it makes them fail rather than fall back. |

Other dot-files at the results root (`.session_seed_<N>.md`,
`.housekeeping-cache`, and similar) are harness bookkeeping.

In a scratch directory, `bin/probe` writes each run's output to
`<stem>.run-<pid>-<ns>.asan.txt`, never rewritten, and points
`<stem>.asan.txt` at the newest finished run. `<stem>` is the testcase name
without its final extension: `testcase.html` gives `testcase.asan.txt`.

### Structured progress

`state/` lets a run resume without reading logs. Claims, runs, notes, and
events are append-only ledgers; `hypotheses.jsonl` is rewritten atomically
when a status changes.

| File | What it holds |
| --- | --- |
| `claims.jsonl` | Card claim and release events. Each row records the card's target-relative `file`, `queue_rank`, `queue_size`, and `score` when offered, and the claiming lane's `strategy`, which can differ from the card's. `bin/state card-yield` replays them. |
| `hypotheses.jsonl` | Current hypothesis rows. |
| `runs.jsonl` | One row per `bin/probe` run that names a hypothesis: verdict, sanitizer, run count, duration, testcase and hash, `asan_output` (that run's own output file), and, after a coverage replay, `coverage` (`HIT`, `MISSED`, `UNAVAILABLE`, …) with the `closest` frame. An `EXEC_FAIL` row carries `execution_failure_class`. A row can record `NO_EXEC`, so the row count alone does not prove target code ran. |
| `notes.jsonl` | Compact supporting notes. |
| `events.jsonl` | Audit events. A `lane_stop` row marks a pinned strategy with no applicable work (`outcome: unavailable`) or no cards left (`outcome: exhausted`). An unavailable lane can exit successfully without a session: count it as skipped, not completed. |
| `run-config.json` | Worker counts, backend, model, effort, security profile, and delta. |
| `unreachable-routes.jsonl` | Anchored disproofs and out-of-model triggers that later cards render. |
| `manifest.jsonl` | Every auditable file the ranker enumerated, with its content identity and whether it was offered. Rewritten with each queue; read by `bin/state coverage` ([Review coverage](../concepts/coverage.md)). |
| `receipts.jsonl` | Line ranges a session attested reading, pinned to content hash. |
| `reads.jsonl` | Read requests observed in transcripts, pinned to content hash. |
| `sweep.json` | The budgeted sweep's spend, counts, and why it stopped. |
| `callgraph.json` | Optional call-neighbourhood context; see below. |
| `strategy-<N>`, `fixed-strategy`, `build-config-<N>` | Per-agent assignments. |

`callgraph.json` exists only when the optional
[call-neighbourhood analysis](../getting-started/prerequisites.md#experimental-call-neighbourhood-context)
is installed. It holds the per-file call maps work-card prompts quote and
each file's function definitions with line ranges, or only a `skipped`
reason when the tree was too large or failed to parse. Until the next
`bin/rank-work` rebuilds a deleted copy, prompts lose that context,
`mark-examined --functions` stops working (`--lines` still works), and the
sweep loses per-function units.

### Fuzzing campaign

```text
fuzz/
  src/                      harness sources (bin/fuzz template)
  bin/                      built harnesses, build logs, *.manifest.json
  corpus/<harness>/         persistent corpora
  artifacts/<harness>/      crashing and slow inputs libFuzzer saved
  logs/<harness>/slice-<NNNN>.log
  campaign.jsonl            one row per campaign slice
  state.json                resumable per-harness state
```

A harness manifest (`bin/*.manifest.json`, schema 2) binds one binary to its
source digest, sanitizer, linked library or tree, and a source-grounding
`receipt`, empty when the harness has none. `state.json` keeps each
harness's `first_slice` apart from later totals; `bin/fuzz status` joins
both. These are agent diagnostics, not maintainer fields.

## Crash directory

A crash is `crashes/CRASH-<NNN>-<agent>/`, for example `CRASH-001-1`. It
passes through three shapes.

**As filed.** A confirmed `bin/probe` run creates:

```text
CRASH-001-1/
  <testcase>              the input, under its scratch name
  <harness source>        only when the crash came through an API harness
  sanitizer.txt           the confirmed diagnostic
  report.md               a skeleton with TODO sections the agent completes
  repro.cmd               replay arguments, when the route needs any
  .probe-context.json     the exact probe route, binary identity, and hypothesis
```

It also holds `.crash-created-at` and `.probe-identity`, and, for a crash on
an alternate build, `.build-config.json`, `.build-config-recipe.sh`, and the
`.primary-build-*` result of re-running it on the regular build. The agent
adds the narrative and may add `patch.diff`.

**Pending promotion.** A crash triage accepted but has not yet bundled
carries `.promotion_pending`, listing the missing artifacts one per line,
until the export bundle is complete. After ten passes with the same
artifacts missing (`CRASH_PROMOTION_PENDING_MAX`), the directory moves to
`crashes-rejected/` with those artifacts named in its `rejection.md`.
`bin/state resume` puts an unfinished bundle ahead of new work. See
[Crash review](../guides/triage-results.md#crash-review).

**Exported bundle.** `bin/export-repro`, which triage runs for you, turns
the directory into the maintainer bundle:

```text
CRASH-001-1/
  report.md               the maintainer report
  report.html             rendered from report.md on each triage pass
  reproduce.sh            ./reproduce.sh [/path/to/checkout]
  input.<ext>             the testcase bytes
  harness.c               or .cc, .cpp, .cxx; only when the crash needs a harness
  repro.cmd               replay arguments, when the route needs any
  sanitizer.txt           the filed diagnostic
  patch.diff              optional candidate fix
  validation.json         publication receipt
  severity.json           only when a current reportable score exists
  .audit/                 the agent's draft report, filed originals, export log
```

Without a checkout path, `reproduce.sh` uses the in-place local source of a
target with no upstream URL, found by searching up from the script, and
otherwise clones the recorded upstream at the audited revision next to
itself. A local-only bundle moved to another machine needs the path. When no
runnable route (testcase, harness, or wrapper) was captured, `reproduce.sh`
is a stub that explains what is missing and exits 2. See
[Reproduce a crash](../guides/reproduce-a-crash.md).

**Editing an exported report.** Export titles `report.md` as
`# CRASH-001-1: <primitive> in <function>` (indexes show it without the id)
and demotes the agent's own title to a subheading. The narrative's source is
the agent's draft, `.audit/report.md`: a re-export rebuilds the root
`report.md` from it and carries over only the field values, and triage
re-exports whenever the draft is newer. So edit `.audit/report.md` to change
the narrative, and the root `report.md` to change a field. Keep `.audit/`:
the receipt binds evidence stored there.

`report.md` also carries a `Cluster: <ID> (<N> reports: …)` or
`Cluster: <ID> (singleton)` line and a `Dedup frames:` line with the frames
that decided the cluster.

A memory-safety finding filed at the crash's exact target-relative path and
line moves under the crash as `.companion/<FIND-id>/`, so one verdict covers
both. Other dot-files (`.promotion_pending.*`, vote and gate caches, timing
markers) are harness internals.

## Finding directory

```text
FIND-<NNN>-<slug>/
  report.md               the narrative; hand-edit this
  report.html             rendered from report.md on each triage pass
  validation.json         publication receipt
  severity.json           only when a current reportable score exists
  patch.diff              optional candidate fix
  <evidence>              optional testcase, sanitizer output, harness, affected-files.txt
  .dup-of                 only on non-canonical cluster members: the canonical FIND
  .needs-content          no report file yet
  .pending-drop           reject votes below quorum, with the count and reason
  .reviewed or .keep      a human pin you create
```

Agents name findings `FIND-<NNN>-<slug>`; a crash triage demotes as
runtime-only becomes `FIND-<NNN>-<agent>` with a `## Triage disposition`
section saying why. The report file is the first of `report.md`,
`description.md`, `analysis.md`, and `README.md` that exists.

A finding may be any concrete security issue and needs no sanitizer
reproducer, but it needs a substantive report: a concrete location
(`file:function:line`, an endpoint, a config key), what is wrong from a
security standpoint, and a rationale a reviewer can act on. Evidence files
are optional; once present, the testcase, sanitizer output, and harness are
bound into the receipt, so changing them re-opens review. `patch.diff` is
inlined into the report's `## Patch` section.

`report.md` carries a `Cluster:` line, marked `(canonical)` or
`(duplicate of <FIND>)` in a multi-member cluster, and usually a
`Dedup key:` line. A directory without a report shows as `NEEDS CONTENT` in
`finding-clusters.html`.

**Rejection and pins.** Reject votes below quorum leave `.pending-drop`.
Editing the report to address them discards the saved quality votes, so the
revision gets a fresh quorum. At quorum the directory moves to
`findings-rejected/`; it is never deleted. `touch .reviewed` (or `.keep`)
requests a human override: creating the marker re-opens review, and the
report still needs complete boundary and trigger fields before the harness
writes a final receipt. Editing the report's substance re-opens review;
harness annotations (severity, patch, enrichment, cluster lines) do not.

## Publication receipts

Every adjudicated crash and finding has a content-addressed
`validation.json` with one state: `reportable`, `pending`, `rejected`, or,
for a human-pinned finding (or a tree written by an older version),
`not-reportable`. Only a current `reportable` receipt counts toward the
benchmark total or receives a numeric severity.
[Publication state](../guides/triage-results.md#publication-state) explains
each state and its fields.

The receipt binds the report, the testcase, harness, sanitizer diagnostic,
invocation evidence (`repro.cmd`, `reproduce.sh`, probe context), pin
markers, cited source (`source_attestations`), the target revision and
config, the attacker controls, and the review evidence. Changing any of them
invalidates the receipt and returns the artifact to review; see
[Receipts and re-review](../guides/triage-results.md#receipts-and-re-review).

`severity.json` records the published level, score, and CVSS vector with the
scorer version and a hash of the report content they came from, so a score
from an older report is re-derived, never credited as it stands. In
`findings/` and `crashes/`, `bin/severity` writes it only for a current
`reportable` receipt and removes it otherwise.

A rejected directory keeps its evidence and gains `rejection.md`
(`Reason: …`); its receipt's state is `rejected`.

## Report narrative

Crash and finding reports share one narrative shape, so a reviewer reads
every backend's output the same way. The contract is
`lib/prompts/report_prose.md.j2`, rendered into both the harness session
prompt and the benchmark's model-direct baseline.

The report opens with one `# <title>` line: the defect in at most ten plain
words, with no symbol names or artifact id. Indexes and the benchmark page
label the report by it; without one, they use the first sentence of the
Summary. (An exported crash gets a harness title instead; see
[Crash directory](#crash-directory).) Before the headings comes one bare
`Location: path/to/file.ext:function:line` naming the root-cause operation,
or an endpoint, config key, or protocol step when no source location
exists. Never give a list or range: finding clustering uses this line as its
primary source identity.

| Section | Budget | Answers |
| --- | --- | --- |
| `## Summary` | 60–90 words | What the component does, what goes wrong, what the attacker gets |
| `## Root Cause` | 120–200 words | The invariant the code assumed and the input that breaks it |
| `## Data Flow` | one sentence, then ≤ 8 bullets | The path, as `step: func (path/file.c:NN) — sentence` |
| `## Impact` | 40–70 words | Who is exposed and what they lose |
| `## Fix Direction` | 30–60 words | Where the fix goes and what changes; a sibling `patch.diff` replaces it |

`## Summary` is required: the reviewer TL;DR is built from it and Fix
Direction. Omit any other section you have no evidence for rather than
filling it; an invented Impact paragraph can invalidate a real finding.

The harness writes these sections itself: `## Fields`, `## Patch`,
`## Severity rationale`, `## Classification`, `## Reproduce`,
`## Expected sanitizer output`, `## Contract concern`, and
`## Triage disposition`, plus the TL;DR block.

## Logs

```text
output/<target>/<backend>/logs/
  README.md
  index.log
  index.jsonl
  session_<TS>_<launch>-<n>.log
  llm-decisions.log
  setup-build.log
  sweep.log
  .raw/
    session_<TS>_<launch>-<n>.log.raw
    session_<TS>_<launch>-<n>.prompt.md
```

| File | What it is |
| --- | --- |
| `README.md` | A short tour of this directory. |
| `index.log` | Timeline of launches, promotions, rejections, and sessions. Start here. |
| `index.jsonl` | The same sessions as structured rows, with usage. |
| `session_*.log` | Readable transcript of one agent session. `<TS>` is the local launch time (`YYYYMMDD_HHMMSS_ffffff`), `<launch>` is `cold-start` or `deep_investigation`, and `<n>` is the agent number. |
| `llm-decisions.log` | One line per one-shot model decision, such as queue reranking and review gates. |
| `setup-build.log` | Preflight's rebuilds through `bin/setup-target --build`. |
| `sweep.log` | The background sweep's output. |
| `.raw/*.log.raw` | Full backend transcripts, kept aside because they are large. |
| `.raw/*.prompt.md` | The exact rendered prompt for each session. |

`.instance.lock.d/` is the one-instance lock `bin/audit` holds. Other
dot-files are counters and caches.

To debug, read `index.log`, then open the `session_*.log` it names.
`index.jsonl` rows add, per session:

| Field | Meaning |
| --- | --- |
| `probes`, `probe_seconds`, `probe_diagnostics` | `bin/probe` runs the session recorded, the wall they took, and how many produced a diagnostic. |
| `first_probe_seconds` | Time until the first probe completed and wrote its run row, when the session probed at all. |
| `delegation_events` | Subagent spawns the transcript shows, one per call id. |
| `spend_lower_bound: true` | Delegated work ran where the row's usage cannot see it. |
| `delegation_observable: false` | The backend cannot show its fan-out at all. |
| `served_model` | The model the provider billed, when it differs from the one requested. |

The [benchmark page](../concepts/benchmark.md) explains how the report reads
them.

## Benchmark output

```text
output/benchmark/
  benchmark-result.md, .html        cross-run comparison
  <backend>/
    benchmark-results.md, .html     per-backend ledger, one section per run
    <run-id>/
      run.json                      model, effort, and security profile used
      report.json
      cells/                        one audit tree per condition and replicate
      pool/                         pooled, renumbered artifacts
```

`--bench-root` moves the root. See [Benchmarking](../concepts/benchmark.md)
for what each file holds.
