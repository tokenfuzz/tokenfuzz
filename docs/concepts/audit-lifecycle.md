# Audit Lifecycle

[![Audit lifecycle: setup and preflight, source-only finding or probe path, lane-specific validation, preserved outcomes, and crash bundle export](../assets/audit-lifecycle.svg)](../assets/audit-lifecycle.svg){target="_blank" title="Open full-size diagram in a new tab"}

This page follows a run from "I have source I'm allowed to audit" to
"a reviewer is looking at evidence." It is the operational narrative; the
other concept pages explain individual components and design choices.

A useful run can end in either evidence lane:

- **A written finding.** A concrete security issue that does not depend on a
  sanitizer-class crash lands in `findings/` as a substantive report for
  independent review. A reproducer is useful, but optional.
- **A confirmed crash.** When the testcase reproduces under a
  configured sanitizer or race detector, it lands in `crashes/` with the
  trace, input, and a `reproduce.sh` that rebuilds and re-runs it.

These are parallel lanes, not two copies of every issue. Managed-runtime
panics and tracebacks normally become findings; sanitizer-class diagnostics
and enabled race-detector reports become crashes.

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

For native C/C++ targets, the harness needs a sanitizer build. Outside a
container the default location is `targets/<target>/build-asan/`; container
runs add `${AUDIT_BUILD_SUFFIX}` so incompatible images use separate build
trees. `target.toml` points
the harness at the binary inside it (`asan_bin`, `asan_lib`). The same
layout is used for browsers and generic CLI/library targets.

- ASan is the only sanitizer enabled by default.
- UBSan, MSan, TSan, and Go's race detector are opt-in per target.
- MSan is recommended for self-contained libraries.
- UBSan and TSan are useful but need triage of their false positives.

See
[Sanitizer policy](../guides/configure-target.md#sanitizer-policy)
for the recommended posture.

Targets with `[sanitizer].enabled = []` (typical for interpreted or managed
runtimes) skip sanitizer execution and ordinarily use the findings lane.
Runtime panics and tracebacks are report evidence, not sanitizer crashes. Go
is a hybrid: when `[sanitizer].enabled = ["race"]` and the configured command
emits `WARNING: DATA RACE`, the race report goes to `crashes/`.

Audit preflight can create or refresh ordinary non-browser native sanitizer
builds. Browser builds use their project tooling; registered language package
builds run explicitly through `bin/setup-target <target> --build`. After the
required build exists, refresh the generated config and review only unresolved
or incorrect values.

For ordinary native targets the regular sanitizer build stays the control,
while optional widened configurations take a minority of the audit's effort —
a bug behind a non-default feature is still a bug. A crash found there is
replayed against the regular build and triaged with both results. Set
`build_widening = false` in `target.toml` to skip this work.

## 3. Run the audit

`bin/audit --target <slug> --backend <backend>` starts a session. It
reads `target.toml`, detects the source revision, creates per-backend
result and log directories, and launches one or more agents. The
optional iteration count limits the run; omit it (or pass `0`) to run
continuously.

At preflight, the session copies the reviewed target configuration into its
result tree. That snapshot is immutable for the run: change the source config
for a future session rather than retargeting live agents underneath their
recorded evidence.

Each agent is assigned a role and a strategy. Subsystem and starting
point come from the work queue when the agent claims its first piece
of source. Claims, notes, probe verdicts, and events append under `state/`;
the current hypothesis table is updated atomically, and `work-cards.jsonl` is
rewritten when the ranked queue refreshes. That structured state — not the
agent's transcript — is the source of truth across resume, compaction, and
crash recovery.

`bin/audit --since <rev>` runs a **delta audit**: the work cards cover
only the files changed in `<rev>..HEAD`, the files that call them (one
hop over the call-neighbourhood graph's certain edges — with no graph,
the run says so and covers the changed files alone), and one S1 card
per commit in the range. The window is the delta: no diversity floor,
no expansion. The tree records the base revision and changed-file set
in `state/run-config.json`, and a resumed run must keep the same `HEAD` and pass the same
`--since`; a revision the checkout cannot resolve — a shallow clone, a
typo — stops the run rather than silently widening it to a full audit. The
tracked working tree must match `HEAD`, because uncommitted code is outside the
recorded `<rev>..HEAD` range. An empty or exhausted delta stops instead of
opening the primary agent's ordinary whole-tree discovery slot.

## 4. Agents investigate

Each agent keeps **one active investigation at a time**, with other candidate
hypotheses parked in its compact state:

1. Take an assigned piece of source from the work queue.
2. Pick or refine a hypothesis (a file, a function, a line, an input
   shape, an expected diagnostic).
3. Read a small region of the source.
4. If the source already establishes a concrete security issue, file the FIND
   now; a reproducer strengthens it but is not a precondition.
5. Find a seed or write one testcase and run it immediately. If it does not
   reach the right code through the configured sanitizer or runner, revise the
   input and try again.
6. Confirm a diagnostic before crash promotion, then move the artifact through
   its lane-specific validation.

Investigation depth follows evidence. One clean probe that instantiates every
named boundary or call step can close a deterministic hypothesis. Timing-,
race-, scheduler-, GC-, allocator-, re-entrancy-, and state-dependent triggers
cannot:
they need repetition or different input shapes.

Closing one hypothesis does not retire its card. A dry card needs at least
three clean probes across at least two distinct input shapes before it can be
discarded — a minimum per card, not a quota per hypothesis.

That conclusion retires a concrete patch or site card. A broad whole-file card
instead yields to fresher work and stays reofferable, because finite probes
cannot prove its unexamined functions exhausted. A surface that no configured
build or mode can execute at all is marked blocked rather than counted as clean
evidence.

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
| `NO_EXEC` | Nothing ran: the testcase is missing, the probe refused the route, or the per-iteration sanitizer launch budget is exhausted (`budget-exhausted`). | Fix the prerequisite, or wait for the next iteration. Not clean evidence; never a reason to discard a hypothesis. |
| `EXEC_FAIL` | The command started but produced no valid result. The recorded reason names the class — `loader`, `usage`, `input-rejected`, `aborted`, `unverified-exit`, or `exit` — and the repair it implies. | Fix what the class names: the route, the argv, the harness, or the input. The launch still counts against the sanitizer budget. |
| Missed the target code | The coverage replay did not reach the named function. Browser and JS modes skip the sanitizer; a native target still runs it and records the miss beside the verdict. | Revise the input around the closest reached frame. |
| Clean hit | The code ran but the sanitizer was quiet. | Mutate input shape, state, timing, or allocator layout. |
| Sanitizer diagnostic | The input might be a crash candidate. | Confirm by re-running, minimise, and file under `crashes/`. |

Browser and JS modes use their configured coverage artifacts. A native target
is measured in the `build-asan+fuzz` sibling that `bin/setup-target --build`
and audit preflight build from the target's ASan recipe — the configured CLI,
or a coverage twin of the testcase's `// HARNESS:`. If that sibling is absent,
coverage is reported unavailable and the sanitizer run proceeds; it is never
counted as a miss.

Probe output is a contract, not a log: crash promotion requires saved
sanitizer output on disk. Report-only FINDs go through FIND validation
instead.

## 6. Triage

Triage decides whether an artifact is useful and in scope.

It runs at the end of every iteration over the whole results tree, and it
also runs earlier: while agent slots are still busy, a background sweep
adjudicates the artifacts no live session can still write — a crash bundle
once the slot that filed it has ended its session, a finding once every
session still running started after it was filed. A turn-capped session's
continuation counts as the same session. The end-of-iteration pass repeats
the work over everything, reusing the cached verdicts, so what the sweep
settled costs no further review and what it could not reach is judged there.

**For crashes, the gates are strict:**

- there is a runnable testcase;
- sanitizer output is saved;
- the report fields are complete;
- the result is not an auto-quarantined low-value class — null
  dereference (`0x0` SEGV), OOM, assertion-only abort (ABRT with no
  sanitizer error), `MOZ_CRASH`/panic, or a plain stack overflow.

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
- Runtime panics and tracebacks from findings-only targets remain report
  evidence under `findings/`; they are not sanitizer crashes in the first
  place.
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
disproof names renders it, newest first. Without this, later sessions can spend
time re-deriving the same disproved route on the same source.

Two properties keep the note honest:

- **It rules out a route, not a file.** The card is still assigned, and
  reaching the same code through a different attacker-controlled path still
  counts.
- **It lives exactly as long as the rejection does.** A rejected artifact is
  the record of its own rejection, so when the gate requeues one whose verdict
  went stale, the directory leaves `findings-rejected/` and its route row is
  retired before that path can be reused. A new source revision alone does
  not make a rejection stale: the disproof is re-read against the lines it
  cites and stands while they still match byte for byte, so a pin change
  spends no review — and loses no advice — on a rejection the source still
  supports. Once an anchored line moves, the artifact is requeued and the
  note goes with it. Resumed runs reconcile stale trigger
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
reproduce.sh       ./reproduce.sh /path/to/source
input.<ext>        the testcase bytes
harness.{c,cc,cpp,cxx} only when the bug uses a C/C++ harness
sanitizer.txt      saved sanitizer output
patch.diff         optional candidate fix
validation.json    the publication decision, bound to this evidence
severity.json      only when a current reportable score exists
.audit/            original agent-authored files, kept for provenance
```

A maintainer runs:

```bash
./reproduce.sh /path/to/source
```

and sees the same sanitizer output against a clean checkout. The first export
happens during triage without operator action;
[Maintenance commands](../guides/triage-results.md#maintenance-commands) shows
how to re-run it after editing a bundle.

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
