# Audit Lifecycle

[![Audit lifecycle: set up the target, run the audit, recon surveys the code, agents investigate, probe runs the testcase, triage decides outcome](../assets/audit-lifecycle.svg)](../assets/audit-lifecycle.svg){target="_blank" title="Open full-size diagram in a new tab"}

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

For C/C++ targets, the harness needs a sanitizer build. The default
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

After the build exists, refresh the generated config and review only
unresolved or incorrect values.

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

At startup the harness also runs a quick, fail-open **build-feature
probe**: when object files are available, it inspects them to learn
which translation units the current sanitizer build actually compiled.
The result lives in `state/features.json` and blocks work cards whose
source was stubbed out of the build — agents do not burn hours probing
code the binary cannot reach.

## 4. Breadth-first recon (cold start only)

The first time `bin/audit` sees a given commit of the target source,
it pauses before the deep agents and runs a **breadth-first recon
pass**: several agents sweep the in-scope source set for suspicious
spots (no sanitizer, no testcases), and a second model votes each
emission Promote / Reject / Uncertain. The result is a prioritized
list of *where bugs might be* — work cards the deep agents pick up
first, not a verified bug list.

Promoted recon cards get the strongest priority: if no agent is
already on one, the next eligible claim is steered there even when
the agent's current strategy filter would normally skip it. Rejected
candidates are demoted rather than deleted, so a later sanitizer
verdict can still overturn the validator.

Recon takes 10–30 minutes on a small library, up to an hour on a
browser-sized tree, and is cached on the target source SHA so later
audits against the same commit skip it. If recon fails, the audit
continues on its regular ranked queue. See
[Recon discovery](../guides/recon-discovery.md) for the full picture.

## 5. Agents investigate

Each agent works on **one hypothesis at a time**:

1. Take an assigned piece of source from the work queue.
2. Pick or refine a hypothesis (a file, a function, a line, an input
   shape, an expected diagnostic).
3. Read a small region of the source.
4. Find an existing seed input, or write a testcase from scratch.
5. Run the testcase. If it doesn't reach the right code under the
   sanitizer, revise the input and try again.
6. If it does, confirm the result and move it through triage.

The harness deliberately favours **a few deep hypotheses over many
shallow notes** — agents are told to commit at least 15 tool calls
and a few testcase variants per hypothesis before discarding. Work
cards are leased so two agents don't step on each other; after a
context compaction, the next iteration tells the agent which regions
it has already read so it doesn't re-cover the same ground.

When an agent confirms a crash or finding in a subsystem, the queue
relaxes the usual subsystem-diversity rule for that agent.
Neighbouring cards are cheaper and more valuable once the agent has
working data-flow context for the area.

## 6. Run the testcase

Every testcase runs through one execution gate: `bin/probe`. It reads
the testcase header, picks the right runner (browser, JS shell,
generic CLI, C/C++ or language harness, differential, or the
configured `[runner]`), captures output, and records the verdict in
`state/runs.jsonl`.

Common outcomes:

| Outcome | Meaning | Action |
| --- | --- | --- |
| Did not execute | Syntax error, missing binary, runner refused. | Fix the testcase. This doesn't count against the sanitizer budget. |
| Missed the target code (browser/JS only) | A coverage-gated probe didn't reach the named function. | Revise the input. |
| Clean hit | The code ran but the sanitizer was quiet. | Mutate input shape, state, timing, or allocator layout. |
| Sanitizer diagnostic | The input might be a crash candidate. | Confirm by re-running, minimise, and file under `crashes/`. |
| Differential divergence (JS only) | Two JS modes disagreed on output. | Save both outputs and file as a finding — no sanitizer crash needed. |

Coverage gating only fires in browser and JS modes. Generic CLI
targets always run the sanitizer directly.

Probe output is a contract, not a log. Crash promotion requires a
saved sanitizer or differential output file; report-only FINDs go
through FIND validation instead.

## 7. Triage

Triage decides whether an artifact is useful and in scope.

**For crashes, the gates are strict:**

- there is a runnable testcase;
- sanitizer or differential output is saved;
- the report fields are complete;
- the result is not a low-value class such as OOM, assertion-only
  abort, or a plain null dereference without memory-safety impact.

A trigger source outside the target's declared attacker surface is
*not* a rejection: the crash stays in `crashes/` with a contract
concern noted and its severity downgraded (×0.7), because the
threat-model fit is a scoring question, not a filing question.

The LLM-backed crash gates (trace validity, report completeness,
legitimacy) are **multi-vote**: a single keep vote keeps the crash,
while a rejection only sticks once independent negative votes reach
quorum (two by default). The gates fail open — an undecided crash is
kept rather than dropped.

**For findings, the gates are about substance:**

- there is a report file at the FIND root;
- the report is substantive — a concrete location, an explicit issue
  class, and a rationale a reviewer can act on. A sanitizer
  reproducer is *not* required.

Because no sanitizer vouches for a finding, an independent validator
votes each one Promote / Reject / Uncertain. Two Promote votes
promote it; a single Reject is fatal; an Uncertain vote triggers a
skeptical tiebreak.

What happens to each artifact:

- Accepted crashes stay under `crashes/`.
- Borderline rejections sit in `crashes-needs-review/` for one more
  pass before final demotion.
- Hard rejections move to `crashes-rejected/` with a reason rendered in
  `INDEX.html`.
- Runtime-diagnostic crashes from findings-only targets are demoted
  to `findings/` rather than promoted as sanitizer crashes.
- Findings with no report get a `.needs-content` marker and surface
  as `NEEDS CONTENT` in `findings/FINDING-CLUSTERS.html`.
- Findings rejected twice by the substance gate are quarantined to
  `findings-rejected/` — they are not deleted, so you can review the
  reasoning.

Reachability and severity annotations are best-effort post-processing.
A failed external-caller lookup does not remove an otherwise complete
crash or finding.

## 8. Export to a maintainer bundle

Triage automatically runs `bin/export-repro` on every accepted crash.
After bundling, each `crashes/CRASH-*` directory contains:

```text
REPORT.md          one-page summary
REPORT.html        generated sibling
reproduce.sh       single command, no env vars
input.<ext>        the testcase bytes
harness.{c,cc,cpp,cxx} present iff the bug uses a C/C++ harness
sanitizer.txt      full sanitizer output
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

## 9. Where to look

The paths worth knowing during a session:

```text
output/<target>/CRASH-CLUSTERS.html
output/<target>/FINDING-CLUSTERS.html
output/<target>/<backend>/results/crashes/
output/<target>/<backend>/results/findings/
output/<target>/<backend>/results/crashes-rejected/INDEX.html
```

See [Artifact layout](../reference/artifacts.md) and
[Commands](../reference/commands.md) for the full inspection toolkit.
