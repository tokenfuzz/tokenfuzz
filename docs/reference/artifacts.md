# Artifact Layout

This page describes the files and directories TokenFuzz creates
while an audit is running. It also shows where to look first when
you want to understand the result of a run.

Set the active result directory once when you start inspecting:

```bash
export TARGET=<your-target>
export BACKEND="<backend>"        # one of: claude, codex, gemini, grok, oss
# Optional convenience path for inspecting results.
export RESULTS="output/$TARGET/$BACKEND/results"
```

Open the generated HTML pages first:

```text
$RESULTS/crashes/CRASH-CLUSTERS.html
$RESULTS/findings/FINDING-CLUSTERS.html
$RESULTS/crashes-rejected/REJECTED-CRASHES.html
$RESULTS/crashes/CRASH-*/REPORT.html   # report.html before export-repro runs
$RESULTS/findings/FIND-*/report.html
```

Where to look for what:

- `results/` — audit evidence and progress.
- `logs/` — debugging orchestration, backend authentication, or
  wrapper failures.

The result tree is designed to surface which security results are
ready for review, even when they are not sanitizer crashes.

## Target root

```text
targets/<target>/
```

This is the upstream source checkout. Build artifacts may also
live here when the target's build system writes them under the
source tree.

## Target output root

```text
output/<target>/
  target.toml
  CRASH-CLUSTERS.md
  CRASH-CLUSTERS.html
  FINDING-CLUSTERS.md
  FINDING-CLUSTERS.html
  <backend>/
```

What each file is:

- `target.toml` — the generated static configuration you review
  when inference leaves placeholders or target-specific values.
- `CRASH-CLUSTERS.html` and `FINDING-CLUSTERS.html` — cross-backend
  aggregate review tables for every backend under this target. The
  `.md` siblings are the source files used to generate them.

## Backend directory

```text
output/<target>/<backend>/
  results/
  logs/
```

Backends get their own subdirectories so runs from different model
providers do not overwrite each other's state.

- If you ran `--backend <backend>`, inspect
  `output/<target>/<backend>/results/`, where `<backend>` is one of
  `claude`, `codex`, `gemini`, `grok`, or `oss`.

## Results directory

The paths an operator inspects after a run:

| Path | Purpose |
| --- | --- |
| `crashes/` | Crash candidates, including final and pending artifacts. |
| `crashes-rejected/` | Rejected crash artifacts and `REJECTED-CRASHES.html` / `REJECTED-CRASHES.md`. |
| `findings/` | Security finding candidates — any class, with or without a reproducer. See note below. |
| `findings-rejected/` | FIND directories rejected by the LLM substance gate at quorum. |
| `corpus/` | Inputs that reached new coverage, saved after each iteration for reuse as seeds. Deduplicated by content. |
| `scratch-N/` | Active testcase work for agent `N`. |
| `.session-env` | Active backend-local `RESULTS_DIR`, `TARGET_ROOT`, `TARGET_SLUG`, `TARGET_REV`, `TARGET_REPO_TYPE`, `LOGDIR`, `SESSION_STARTED`, and `TARGET_CONFIG_SHA256` values read by `bin/probe`. |
| `.target.toml` | The post-preflight `target.toml` snapshot this session runs against, pinned by the `TARGET_CONFIG_SHA256` digest above. Every config consumer in the session reads it instead of the shared `output/<target>/target.toml`. Editing or removing it fails the run loud. |

The tree also holds the work queue and structured state the harness
manages itself. One file is worth knowing: `state/runs.jsonl` has one
row per `bin/probe` invocation, so `wc -l` on it answers "did anything
actually run?". `state/callgraph.json` is present only with the optional
[call-neighbourhood analysis](../getting-started/prerequisites.md#experimental-call-neighbourhood-context)
installed; it holds the per-file call maps work-card prompts quote, and
deleting it costs prompt context and nothing else. The rest is internal
bookkeeping.

FIND directories without a report get a `.needs-content` marker and
surface as `NEEDS CONTENT` in `FINDING-CLUSTERS.html`. A gate pass with
Reject votes below quorum leaves `.pending-drop`; reaching quorum moves
the directory to `findings-rejected/` rather than deleting it. `touch
.reviewed` (or `.keep`) inside a FIND directory requests a human override; the
report must still contain complete boundary and trigger fields before the
harness writes a final receipt. Editing the report's substance re-opens its
review; mechanical severity, patch, enrichment, and cluster annotations do not.

Every adjudicated artifact has a content-addressed `validation.json`. It binds
the publication state to the report, saved evidence, target revision/config,
and threat model. Its states are `reportable`, `not-reportable`, `pending`, and
`rejected`. Pending and legacy artifacts remain visible on disk. Only a current
`reportable` receipt enters the security benchmark total or receives numeric
severity. `not-reportable` is a final retained engineering defect, not a
security report; `pending` is an artifact no review settled, which is neither
credited nor written off.
Changing the report, testcase, harness, sanitizer diagnostic, invocation
evidence, target/config identity, or review evidence invalidates the receipt
and returns the artifact to review.

A short run may leave `crashes/` and `findings/` empty — that is
not a failed run by itself. Check the rejected indexes first to
see whether the agent produced candidates that triage rejected.

## Crash directory

Before export, a crash directory commonly includes:

```text
CRASH-001-1/
  testcase.<ext>        # .html, .js, .py, .dat, … depending on the target
  sanitizer.txt         # saved sanitizer output
  report.md             # agent-authored narrative + fields
  patch.diff            # optional agent-suggested fix
```

A crash that triage has accepted but not finished promoting carries a
`.promotion_pending` marker naming what is still missing. It clears once the
export bundle below is complete. A directory still missing the same artifacts
after ten triage passes is moved to `crashes-rejected/`, with those artifacts
named in its rejection report.

Pending promotion is resumable work. `bin/state resume --agent N` presents an
unfinished bundle before active hypotheses or new work cards. Its sanitizer
proof remains countable in benchmark crash totals, but severity stays Unknown
until the report is complete.

After export, the maintainer-facing bundle has:

```text
CRASH-001-1/
  REPORT.md             # field table + sanitizer summary; hand-edit this
  REPORT.html           # auto-generated sibling of REPORT.md
  reproduce.sh          # ./reproduce.sh /path/to/source
  input.<ext>           # the testcase bytes
  harness.{c,cc,cpp,cxx} # present iff the bug uses a C/C++ harness
  sanitizer.txt         # original sanitizer output
  patch.diff            # optional: candidate fix
  validation.json       # current publication state + evidence identity
  severity.json         # the published score, bound to the report it came from
  .audit/
  .dup-of               # only on non-canonical cluster members
```

Accepted crashes may carry other dot-files the triage gates leave behind
(vote caches, timing and scoring markers, and the like). All of them are
harness internals — safe to ignore when reviewing.

`REPORT.md` carries a `Cluster: <ID>` line. Non-canonical cluster
members also have a `.dup-of` file naming the canonical CRASH. The
auto-generated `REPORT.html` is regenerated on every triage pass;
edit `REPORT.md` only. See
[Triage results](../guides/triage-results.md#clusters-and-duplicates)
for the cluster model.

Audit-side originals (operator's `report.md`, intermediate scratch
artifacts) are kept under `.audit/` as an internal triage cache —
not needed to reproduce or review the crash.

Crash directories are intentionally narrow. They should contain
the evidence needed to rerun and prioritise a crash. Broader
security observations belong in `findings/`.

`crashes/` also contains `CRASH-CLUSTERS.md` and
`CRASH-CLUSTERS.html` — the generated
review table for crashes in this backend's `results/` tree. The
cross-backend aggregate lives at
`output/<target>/CRASH-CLUSTERS.md` and
`output/<target>/CRASH-CLUSTERS.html`.

## Finding directory

Findings use:

```text
FIND-001/
  report.md              # the narrative; hand-edit this (description.md also accepted)
  report.html            # auto-generated sibling of report.md (open in browser)
  validation.json        # current publication state + evidence identity
  severity.json          # the published score, bound to the report it came from
  affected-files.txt     # optional, operator-authored — the harness does not generate it
  .dup-of                # only on non-canonical cluster members
  .needs-content         # marker added when report.md is missing
```

`report.md` carries `Cluster: <ID>` and `Dedup key:` lines.
`report.html` is regenerated on every triage pass; hand-edit only
`report.md`.

`findings/` also contains `FINDING-CLUSTERS.md` and
`FINDING-CLUSTERS.html` — the review table grouping reports that share
a root cause. The cross-backend aggregate lives at
`output/<target>/FINDING-CLUSTERS.md` and
`output/<target>/FINDING-CLUSTERS.html`.

See
[Triage results](../guides/triage-results.md#clusters-and-duplicates)
for how cluster membership and `.dup-of` markers are used during
review.

`findings/` accepts any concrete security issue — memory safety,
logic, auth bypass, injection, info disclosure, crypto, races,
boundary violations, and so on. A sanitizer reproducer or runnable
testcase is **not** required — a substantive report is. Each report
needs:

- a concrete location (`file:function:line`, an endpoint, a config
  key, …);
- what is wrong from a security standpoint;
- a rationale a reviewer can act on.

Vacuous candidates are not moved out of `findings/` below reject
quorum. The harness drops a `.pending-drop` marker in the FIND directory.
Edit the report to address the marker, or `touch .reviewed` / `.keep` to
override. Editing the report also invalidates saved quality votes so the
revised content receives a fresh quorum. At quorum, the directory is moved
to `findings-rejected/`.

The severity scorer writes `severity.json` and updates severity text only
after a current final-state validation receipt exists. A pending FIND remains
available for review without being silently interpreted as a low-severity
security bug.

`severity.json` records the published level, score, and vector together with
the scorer version and a hash of the report content they were derived from.
Later passes rewrite reports — reach-field fills, enrichment, pool copies — so
that binding is what distinguishes a current score from one an earlier scorer
left behind. A score whose binding no longer matches is re-derived, never
credited as-is.

## Report narrative

Crash and finding reports share one narrative shape, so a reviewer reads
every backend's output the same way. In order:

| Section | Budget | Answers |
| --- | --- | --- |
| `## Summary` | 60–90 words | What the component does, what goes wrong, what the attacker gets |
| `## Root Cause` | 120–200 words | The invariant the code assumed and the input that breaks it |
| `## Data Flow` | ≤ 8 bullets | The path, as `step: func (path/file.c:NN) — sentence` |
| `## Impact` | 40–70 words | Who is exposed and what they lose |
| `## Fix Direction` | 30–60 words | Where the fix goes and what changes |

`## Summary` is required because it feeds the reviewer TL;DR. Any other
section with no evidence behind it is omitted rather than filled — an
unevidenced Impact paragraph costs more than a missing one. Sections outside
this set are written by the harness (`## Fields`, `## Patch`, `## Severity
rationale`, `## Classification`, `## Reproduce`), not by the report author.

The contract lives in `lib/prompts/report_prose.md.j2` and is rendered into
both the harness session prompt and the model-direct baseline, so prose shape
is never a difference between benchmark conditions.

## Logs

```text
output/<target>/<backend>/logs/
  README.md
  index.log
  index.jsonl
  llm-decisions.log
  session_<TS>_<launch>-<n>.log
  .raw/
    session_<TS>_<launch>-<n>.log.raw
    session_<TS>_<launch>-<n>.prompt.md
```

In the per-session filenames, `<TS>` is the launch timestamp, `<launch>`
is `cold-start` or `deep_investigation`, and `<n>` is the agent number.

Logs are useful for:

- backend CLI failures;
- orchestrator launch problems;
- unexpected wrapper behaviour.

For normal audit progress, prefer the generated HTML:

- `crashes/CRASH-CLUSTERS.html`;
- `findings/FINDING-CLUSTERS.html`;
- `crashes-rejected/REJECTED-CRASHES.html`;
- per-result `REPORT.html` / `report.html`.

For debugging a run, start with `logs/README.md`, then `index.log`.
Open the matching `session_*.log` for the session named in the timeline.
Use `index.jsonl` when you want the same session data in a scriptable
form. Full backend transcripts and exact prompt dumps live under
`logs/.raw/`; they are intentionally out of the way because they can be
large and are rarely the first artifact you need.
