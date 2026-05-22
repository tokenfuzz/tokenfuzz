# Artifact Layout

This page describes the files and directories TokenFuzz creates
while an audit is running. It also shows where to look first when
you want to understand the result of a run.

Set the active result directory once when you start inspecting:

```bash
export TARGET=<your-target>
export BACKEND="<backend>"        # one of: claude, codex, gemini, oss
# Optional convenience path for inspecting results.
export RESULTS="output/$TARGET/$BACKEND/results"
```

Open the generated HTML pages first:

```text
$RESULTS/crashes/CRASH-CLUSTERS.html
$RESULTS/findings/FINDING-CLUSTERS.html
$RESULTS/crashes-rejected/INDEX.html
$RESULTS/crashes/CRASH-*/REPORT.html
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
  `claude`, `codex`, `gemini`, or `oss`.

## Results directory

The paths an operator inspects after a run:

| Path | Purpose |
| --- | --- |
| `crashes/` | Accepted or pending crash artifacts. |
| `crashes-rejected/` | Rejected crash artifacts and `INDEX.html` / `INDEX.md`. |
| `findings/` | All security findings — any class, with or without a reproducer. See note below. |
| `findings-rejected/` | FIND directories rejected by the LLM substance gate at quorum. |
| `recon/` | One `RECON-*` directory per breadth-first recon candidate — an **unverified** raw claim. Holds `finding.json`, `validator-vote-*.json`, and a human-readable `REPORT.md`/`REPORT.html`. A sibling of `findings/`, not part of it. |
| `corpus/` | Promoted inputs useful for future work. |
| `scratch-N/` | Active testcase work for agent `N`. |
| `.session-env` | Active backend-local `RESULTS_DIR`, `TARGET_ROOT`, `TARGET_REV`, and `LOGDIR` values read by `bin/probe`. |

The result tree also holds the queue files, structured state, and
per-agent hit/tried-input logs the harness reads and writes itself.
You rarely need to open these directly; the two worth knowing are:

- `state/runs.jsonl` — one row per `bin/probe` invocation. `wc -l` on
  it is the fastest "did anything actually run?" check.
- `crashes-needs-review/` — borderline LLM-rejections held for one
  more pass before final demotion to `crashes-rejected/`.

Everything else (`work-cards.jsonl`, `patch-cards.jsonl`, the recon
survey files, the other `state/*.jsonl` streams, per-agent
`hits-N.log` / `tried-inputs-N.log`, `.static-prompt-rules.md`) is
harness internals. The recon outputs are explained in
[Recon discovery](../guides/recon-discovery.md).

FIND directories without a report get a `.needs-content` marker and
surface as `NEEDS CONTENT` in `FINDING-CLUSTERS.html`. Vacuous
reports can get `.needs-attention` or `.pending-drop` while they wait
for review or a second verdict. FINDs the LLM substance gate rejects
at quorum are moved to `findings-rejected/` (not deleted).

A short run may leave `crashes/` and `findings/` empty — that is
not a failed run by itself. Check the rejected indexes first to
see whether the agent produced candidates that triage rejected.

## Crash directory

Before export, a crash directory commonly includes:

```text
CRASH-001-1/
  testcase.html
  asan.txt              # sanitizer output sidecar; non-ASan logs may also appear
  report.md
  reproducer.sh
```

After export, the maintainer-facing bundle has:

```text
CRASH-001-1/
  REPORT.md             # field table + ASan summary; hand-edit this
  REPORT.html           # auto-generated sibling of REPORT.md
  reproduce.sh          # ./reproduce.sh /path/to/source
  input.html
  sanitizer.txt         # original sanitizer output
  .audit/
  .dup-of               # only on non-canonical cluster members
```

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
  reachability.json      # caller / severity hints (when reachability analysis ran)
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

Vacuous candidates are not moved out of `findings/` after a single
reject. The harness drops a `.needs-attention` or `.pending-drop`
marker visible in the `Status` column of
`findings/FINDING-CLUSTERS.html`. Edit the report to address the
marker, or `touch .reviewed` / `.keep` to override. If the reject
quorum is reached, the directory is quarantined under
`findings-rejected/`.

Reachability can also write `reachability.json` and update
severity text for a FIND. That is useful context, not a
requirement for the finding to exist.

## Logs

```text
output/<target>/<backend>/logs/
  README.md
  index.log
  index.jsonl
  llm-decisions.log
  session_<TS>_<role>-<n>-<mode>.log
  session_<TS>_<role>-<n>-<mode>.summary.md
  .raw/
```

Logs are useful for:

- backend CLI failures;
- orchestrator launch problems;
- unexpected wrapper behaviour.

For normal audit progress, prefer the generated HTML:

- `crashes/CRASH-CLUSTERS.html`;
- `findings/FINDING-CLUSTERS.html`;
- `crashes-rejected/INDEX.html`;
- per-result `REPORT.html` / `report.html`.

For debugging a run, start with `logs/README.md`, then `index.log`.
Use `index.jsonl` when you want the same session data in a scriptable
form. Full backend transcripts live under `logs/.raw/`; they are
intentionally out of the way because they can be large.
