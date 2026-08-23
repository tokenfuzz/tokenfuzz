# Audit Lifecycle

[![Audit lifecycle: set up the target, run the audit, agents investigate, probe runs the testcase, triage decides outcome](../assets/audit-lifecycle.svg)](../assets/audit-lifecycle.svg){target="_blank" title="Open full-size diagram in a new tab"}

This page follows a run from "I have source I'm allowed to audit" to
"a reviewer is looking at a finding". Every other page in the handbook
expands on one piece of it.

A run has two successful endings:

- **A written finding.** Any concrete security issue lands in
  `findings/` as a substantive report a reviewer must manually
  verify. With or without a reproducer. This is the primary surface.
- **A runnable crash.** When the testcase reproduces under a
  sanitizer, the same issue also lands in `crashes/` with the trace,
  the input, and a ready-to-run `reproduce.sh`.

Every accepted crash is automatically converted to a maintainer bundle
(`REPORT.md` + `reproduce.sh` + sanitizer output + the input) as part
of triage; you do not have to run any extra step to get that.

## 1. Set up the target

Setup creates two things:

```text
targets/<target>/                   upstream source + sanitizer build
output/<target>/target.toml         generated config + threat model
```

The source checkout belongs to the upstream project. The harness
reads it, builds against it, and records its revision, but audit
output stays under `output/`.

If `target.toml` is missing, `bin/audit --target <slug>` seeds a
starter config automatically before loading it. You can also seed or
refresh it explicitly with `bin/setup-target <slug>` (or use
`bin/audit --new-target <slug>` to generate the file and exit).

## 2. Build the sanitizer artifact

For native C/C++ targets, the harness needs a sanitizer build. The default
location is `targets/<target>/build-asan/`, and `target.toml` points
the harness at the binary inside it (`asan_bin`, `asan_lib`). The same
layout is used for browsers and generic CLI/library targets.

- ASan is the only sanitizer enabled by default.
- UBSan, MSan, TSan, and Go's race detector are opt-in per target.
- MSan is recommended for self-contained libraries.
- UBSan and TSan are useful but need triage of their false positives.

See
[Configure a target](../guides/configure-target.md#sanitizer-policy)
for the recommended posture.

Targets with `[sanitizer].enabled = []` (typical for interpreted
runtimes like Python, Ruby, Node, Java, PHP, but valid for anything
without an ASan build) skip the sanitizer entirely and run in
findings-only mode — runtime panics and tracebacks land under
`findings/` instead of `crashes/`. Go is a hybrid: when
`[sanitizer].enabled = ["race"]` and `[runner].args` includes
`-race`, the runtime race detector still routes data-race reports
into `crashes/`.

Audit preflight can create or refresh ordinary non-browser native sanitizer
builds. Browser builds use their project tooling; registered language package
builds run explicitly through `bin/setup-target <target> --build`. After the
required build exists, refresh the generated config and review only unresolved
or incorrect values.

For ordinary native targets the regular `build-asan` stays the control, while a
second build with the project's optional features turned on takes a minority of
the audit's effort — a bug behind a non-default feature is still a bug. A crash
found there is replayed against the regular build and triaged with both
results. Set `build_widening = false` in `target.toml` to skip it.

## 3. Run the audit

`bin/audit --target <slug> --backend <backend>` starts a session. It
reads `target.toml`, detects the source revision, creates per-backend
result and log directories, and launches one or more agents. The
optional iteration count limits the run; omit it (or pass `0`) to run
continuously.

Each agent is assigned a role and a strategy. Subsystem and starting
point come from the work queue when the agent claims its first piece
of source. Claims, hypotheses, notes, and probe verdicts are written
as append-only rows under `state/`. That structured state — not the
agent's transcript — is the source of truth across resume, compaction,
and crash recovery.

## 4. Agents investigate

Each agent works on **one hypothesis at a time**:

1. Take an assigned piece of source from the work queue.
2. Pick or refine a hypothesis (a file, a function, a line, an input
   shape, an expected diagnostic).
3. Read a small region of the source.
4. Find an existing seed input, or write a testcase from scratch.
5. Run the testcase. If it doesn't reach the right code through the
   configured sanitizer or runner, revise the input and try again.
6. If it does, confirm the result and move it through triage.

Investigation depth follows evidence. A deterministic bug can be dismissed
after one clean probe that hit its exact trigger, but timing-, race-, GC-, and
state-dependent triggers need repetition or different inputs before the harness
will discard a work card — so a flaky bug is not written off on a single quiet
run. A surface that no configured build or mode can even execute is marked
blocked rather than counted as clean evidence.

Work cards are leased so two agents don't step on each other; after a context
compaction, the next iteration tells the agent which regions it has already
read so it doesn't re-cover the same ground.

When an agent confirms a crash or finding in a subsystem, the queue
relaxes the usual subsystem-diversity rule for that agent.
Neighbouring cards are cheaper and more valuable once the agent has
working data-flow context for the area.

## 5. Run the testcase

Every testcase runs through one execution gate: `bin/probe`. It reads
the testcase header, picks the right runner (browser, JS shell,
generic CLI, C/C++ or language harness, or the configured `[runner]`),
captures output, and records the verdict in
`state/runs.jsonl`.

Common outcomes:

| Outcome | Meaning | Action |
| --- | --- | --- |
| Did not execute | Syntax error, missing binary, runner refused. | Fix the testcase. This doesn't count against the sanitizer budget. |
| Missed the target code (browser/JS only) | A coverage-gated probe didn't reach the named function. | Revise the input. |
| Clean hit | The code ran but the sanitizer was quiet. | Mutate input shape, state, timing, or allocator layout. |
| Sanitizer diagnostic | The input might be a crash candidate. | Confirm by re-running, minimise, and file under `crashes/`. |

Coverage gating only fires in browser and JS modes. Generic CLI
targets always run the sanitizer directly.

Probe output is a contract, not a log. Crash promotion requires saved
sanitizer output; report-only FINDs go
through FIND validation instead.

## 6. Triage

Triage decides whether an artifact is useful and in scope.

**For crashes, the gates are strict:**

- there is a runnable testcase;
- sanitizer output is saved;
- the report fields are complete;
- the result is not an auto-quarantined low-value class — null
  dereference (`0x0` SEGV), OOM, assertion-only abort (ABRT with no
  sanitizer error), `MOZ_CRASH`/panic, timeout-only, or a plain
  stack overflow.

A trigger source outside the target's declared attacker surface is not a
rejection: the crash stays in `crashes/`, and when the source reviewer agrees
the fault needs something outside those controls, it ends `not-reportable` —
no numeric CVSS score, no security yield.

Those checks are mechanical. On top of them, a reviewer reads the source and can
still throw out a sanitizer-confirmed crash — but only on two independent
rejections that each carry a concrete disproof. Silence or uncertainty keeps
the crash. An inconclusive or split review receives the same focused resolution
pass as a finding; one resolver Reject still cannot replace the two-Reject bar.

**For findings, the gates are about substance:**

- there is a report file at the FIND root;
- the report is substantive — a concrete location, an explicit issue
  class, and a rationale a reviewer can act on. A sanitizer
  reproducer is *not* required.

Because no sanitizer vouches for a finding, each report is read
independently — with none of the filing agent's context — and voted
accept or reject. Two accepts promote it; two rejects move it to
`findings-rejected/`. A promoted finding then receives source review of its
trigger and exact claimed security consequence. It is quarantined only when
two anchored reviewers agree on a concrete disproof; missing or ambiguous
evidence fails open. An inconclusive first review or a split receives one
focused resolution pass carrying the prior evidence; genuine remaining
uncertainty stays visible and unjudged.

What happens to each artifact:

- Accepted crashes stay under `crashes/`.
- Hard rejections move to `crashes-rejected/` with a reason rendered in
  `REJECTED-CRASHES.html`.
- Runtime-diagnostic crashes from findings-only targets are demoted
  to `findings/` rather than promoted as sanitizer crashes.
- Findings with no report get a `.needs-content` marker and surface
  as `NEEDS CONTENT` in `findings/FINDING-CLUSTERS.html`.
- Findings rejected twice by the substance gate are quarantined to
  `findings-rejected/` — they are not deleted, so you can review the
  reasoning.

### Rejections are kept as reusable knowledge

Building a reproducer is the expensive half of an audit, so a disproof is
worth as much as a finding. When a reviewer rejects an artifact because its
triggering state is not attacker-reachable, the anchored reason is appended to
`state/unreachable-routes.jsonl`, and a later work card on any file that
disproof names renders it, newest first. Without this, each session re-derives
the same disproof on the same file — in one measured run, over half of all
trigger rejections landed on a file that had already produced one.

Two properties keep the note honest:

- **It rules out a route, not a file.** The card is still assigned, and
  reaching the same code through a different attacker-controlled path still
  counts.
- **It lives exactly as long as the rejection does.** A rejected artifact is
  the record of its own rejection, so when the gate requeues one whose verdict
  went stale, the directory leaves `findings-rejected/` and its route row is
  retired before that path can be reused. Resumed runs reconcile stale trigger
  rejections before launching their first agents, so an obsolete note cannot
  survive even one cohort. No tombstone, and no second copy of the gate's
  validity rules to drift out of step.

Severity annotation is best-effort post-processing on top of all this. A failed
scoring run does not remove an otherwise complete crash or finding.

## 7. Export to a maintainer bundle

Triage automatically runs `bin/export-repro` on every accepted crash.
After bundling, each `crashes/CRASH-*` directory contains:

```text
REPORT.md          one-page summary
REPORT.html        generated sibling
reproduce.sh       single command, no env vars
input.<ext>        the testcase bytes
harness.{c,cc,cpp,cxx} present iff the bug uses a C/C++ harness
sanitizer.txt      full sanitizer output
patch.diff         optional candidate fix
validation.json    the publication decision, bound to this evidence
severity.json      the published score, bound to the report it came from
.audit/            original agent-authored files, kept for provenance
```

A maintainer runs:

```bash
./reproduce.sh /path/to/source
```

and sees the same sanitizer output against a clean checkout. You can
re-run `bin/export-repro <crash-id> --slug <target>` manually after
editing files in the bundle, but the first export happens during
triage without operator action.

## 8. Where to look

The paths worth knowing during a session:

```text
output/<target>/CRASH-CLUSTERS.html
output/<target>/FINDING-CLUSTERS.html
output/<target>/<backend>/results/crashes/
output/<target>/<backend>/results/findings/
output/<target>/<backend>/results/crashes-rejected/REJECTED-CRASHES.html
```

See [Artifact layout](../reference/artifacts.md) and
[Commands](../reference/commands.md) for the full inspection toolkit.
