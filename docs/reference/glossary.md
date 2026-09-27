# Glossary

Short definitions for terms used in the handbook, logs, reports, and agent
prompts. Terms are grouped by the part of the system they describe and
sorted alphabetically within each group. Most entries link to the page that
explains the idea in full.

## Audit runs

**Agent role.** What a slot is asked to do. `reproduce` agents write
testcases and run them through `bin/probe`; an `analysis` agent traces
source and hands leads that need a testcase to reproduce agents. With more
than one slot, the last is `analysis` by default; `AGENT_ROLES` overrides
this. See [Agents](../concepts/system-architecture.md#agents).

**Audit run.** One invocation of `bin/audit` against one target and
backend, spanning many iterations and sessions. See
[Audit lifecycle](../concepts/audit-lifecycle.md).

**Cohort.** The schedule of pinned-strategy (`--strategy`), delta
(`--since`), ensemble, and `--no-refill-workers` runs: a pool of sessions
launched together, waited for at a barrier, and triaged before the next
iteration. See
[How slots are scheduled](../concepts/audit-lifecycle.md#how-slots-are-scheduled).

**Cold start.** A launch made before any agent in the results tree has
structured state or card activity, typically the first on a fresh target.
Its log is `session_<TS>_cold-start-<n>.log`; later launches say
`deep_investigation` instead.

**Compaction.** The backend's own shortening of a conversation near its
context limit. The agent then runs `bin/state resume` and does not re-read
its session seed ranges.

**Continuous run.** The default schedule: each slot relaunches as soon as
its session ends while work remains, steering happens at steward ticks
without stopping anyone, and one final barrier runs after the last slot
drains. See
[How slots are scheduled](../concepts/audit-lifecycle.md#how-slots-are-scheduled).

**Delta audit.** `bin/audit --since <rev>`: a run scoped to the files
changed in `<rev>..HEAD`, their one-hop callers, and S1 cards for those
commits. A resume must pass the same `--since`. See
[Delta audits](../concepts/audit-lifecycle.md#delta-audits).

**Generation.** In a continuous run, the span between two steward ticks.
Strategy rotation and the dry-streak stop count generations, and `index.log`
numbers them as iterations.

**Iteration.** One outer pass of the audit loop, logged as
`Iteration <n> starting`: a generation in a continuous run, one pool of
sessions in a cohort run. The optional `max_iterations` argument of
`bin/audit` caps it; `1` is a one-worker smoke test.

**Preflight.** The checks `bin/audit` runs before the first agent: the
runner starts, the model can act in the target tree, the sanitizer builds
are current, and, for a browser target, a canary page runs. A failure prints
`FATAL:` and starts nothing. See
[Troubleshooting](troubleshooting.md#preflight-fails).

**Resume.** Continuing from structured state rather than from a transcript.
Rerunning the same `bin/audit` command resumes the run, and each session
starts from `bin/state resume --agent <n>`.

**Session.** One backend process working one slot, from launch to exit,
hard-stopped at `AGENT_TIMEOUT` (default 7200 seconds).

**Session seed.** A digest of what a slot's previous session read, searched,
and wrote, embedded in the next prompt under `PRIOR SESSION SEED` so the
agent does not repeat that work. The oldest reads and searches are trimmed
toward 2 KiB; written testcases are always kept. See
[Session seeds](../concepts/cost-model.md#session-seeds).

**Slot.** One of a run's numbered agent positions (`AGENT_NUM`), with its
own `scratch-<n>/` directory and sanitizer budget. A run has three by
default; see [Worker pool](environment.md#worker-pool).

**Steward tick.** In a continuous run, the pass every
`STEWARD_INTERVAL_SECS` (default 300) that scores the generation, rotates
starved strategy lanes, and re-ranks the queue without stopping any session.

**Turn cap.** `TURN_SOFT_CAP` (default 128 turns or tool calls, depending on
the backend): the point where a session is checkpointed and a fresh one
continues from structured state. `index.log` says
`turn-capped; continuing from state`.

## Work queue and structured state

**Claim.** An agent's lease on a work card, in `state/claims.jsonl`. A claim
with no active hypothesis is released at the next iteration, and every claim
expires after `WORK_CARD_CLAIM_TTL_SECONDS` (default 30 minutes), so a
killed agent does not strand its card.

**ENV-BLOCKED.** A hypothesis status: the configured target cannot execute
the card's route, for example because runner or build metadata is wrong.
The agent records proof for the operator instead of manufacturing clean
runs.

**Hypothesis.** A narrow, falsifiable claim about one `file:function:line`:
the input that reaches it, the guard gap it relies on, and the diagnostic
expected. The unit of agent work, recorded in `state/hypotheses.jsonl` as
`PENDING`, `INVESTIGATING`, `NEEDS_TESTCASE`, `ENV-BLOCKED`, `DISCARDED`, or
the `CRASH-*` or `FIND-*` it produced. See
[A good hypothesis](../concepts/strategy-model.md#a-good-hypothesis).

**Ranked window.** The top-ranked source files that get work cards when the
queue is refreshed. See
[The ranked queue](../concepts/system-architecture.md#the-ranked-queue).

**Structured state.** The JSONL files under `results/state/` plus
`results/work-cards.jsonl`. A resumed run reads these, never a model
transcript. See
[Work queue and structured state](../concepts/system-architecture.md#work-queue-and-structured-state).

**Subsystem.** The leading directories of a source file (`parser/xml`,
`crypto/aes`), never its file name. Ranking avoids putting two agents in one
subsystem at once, so a run spreads across the tree.

**Work card.** One unit of queued work in `results/work-cards.jsonl`,
pairing source with a strategy. Agents take them with `bin/state next-card`.
See [Strategy model](../concepts/strategy-model.md).

## Review coverage

**Budgeted sweep.** An optional breadth pass enabled by
`[sweep] token_budget`: one tool-less model decision per unreceipted source
unit, stopping at the budget. It writes receipts and leads but never probes
or files; its leads become hypotheses owned by agent `sweep`. See
[The budgeted sweep](../concepts/coverage.md#the-budgeted-sweep).

**Call-edge card.** The cross-file second pass: once every parsed function of
a file carries a receipt, one S3 card for the file's resolved callers. See
[The second pass](../concepts/coverage.md#the-second-pass).

**Manifest (`state/manifest.jsonl`).** Every auditable file a ranking pass
enumerated, with its content hash and whether it ever entered the ranked
window. The coverage report measures against it. See
[The manifest](../concepts/coverage.md#the-manifest).

**Receipt (`state/receipts.jsonl`).** A record, written by
`bin/state mark-examined` or the sweep, that specific line ranges or
functions were examined, pinned to the file's content hash; it stops
counting once the file changes. Not the same as a validation
receipt (`validation.json`). See [Receipts](../concepts/coverage.md#receipts).

**Transcript read (`state/reads.jsonl`).** A file read a session's backend
transcript shows, recorded after the session ends. Supporting evidence
beside receipts, never a gate. See [Review coverage](../concepts/coverage.md).

## Strategies

**Guard chain.** Several hypotheses dying to the same input guard. After
three or more, an agent finds a path past the guard or rotates, and records
the guard string with `bin/state add-note --kind guard`.

**REF.** The pattern-search reference: grep recipes used alongside the
assigned strategy. Not a strategy itself.

**Rotation.** Moving an agent to another strategy after a run of dry
iterations on its current one, once structured state shows the strategy was
actually worked. A pinned `--strategy` suspends it. See
[Strategy rotation](../concepts/strategy-model.md#strategy-rotation).

**Strategy (S1 through S8).** A named investigation recipe carried by a work
card: prior-fix variants (S1), invariant negation (S2), spec versus
implementation (S3), boundary-directed fuzzing (S4), lifetime and state
(S5), cross-project variants (S6), adversarial input (S7), and
property-based oracles (S8). See
[Strategy model](../concepts/strategy-model.md).

## Probe and execution

**Alternate build configuration.** A content-addressed ASan sibling of the
canonical `build-asan` tree that reaches optional features. It never
replaces the primary build; `PROBE_BUILD_CONFIG` selects one for a probe.
See [Build configurations](target-toml.md#build-configurations).

**Confirm run.** `bin/probe --confirm`: five sanitizer runs of one testcase.
A sanitizer `CRASH` from two or more runs files a `crashes/CRASH-*` bundle;
a single exploratory run never does.

**Coverage gate.** A replay on a coverage-instrumented build that checks
whether a testcase reaches the code its `TARGET` header names (`HIT` or
`MISSED`). On native routes a miss is feedback and the sanitizer still runs;
on browser and JavaScript-shell routes it skips the sanitizer run. When it
cannot measure, the probe records why (`COVERAGE_UNAVAILABLE`,
`COVERAGE_ENV_FAIL`, and similar) and runs ungated.

**Execution failure class.** The reason attached to an `EXEC_FAIL`:
`loader`, `usage`, `input-rejected`, `aborted`, `unverified-exit`, or
`exit`. It narrows where to look and never changes the verdict. See
[Troubleshooting](troubleshooting.md#every-probe-reports-exec_fail).

**Harness.** A source file beside a testcase, named by its `HARNESS:`
header, that `bin/probe` compiles or interprets to drive the target's API.
The word also names TokenFuzz itself, as in the `harness` benchmark
condition.

**Probe (`bin/probe`).** The only execution path for testcases. It reads the
testcase headers, picks the runner and sanitizer, runs the coverage gate
where one applies, executes the target, and records the run in
`state/runs.jsonl`. See [Commands](commands.md#run-a-testcase).

**Probe verdict.** The result recorded for each probe run:

- `CLEAN`: execution completed without a recognised diagnostic.
- `EXEC_FAIL`: the runner was reached but did not complete cleanly.
- `NO_EXEC`: no target execution was established, for example a launch the
  sanitizer budget refused (`budget-exhausted`) or a route that crashes
  identically on an empty input (`input-independent`).
- `TIMEOUT`: the runner hit its deadline. Unresolved evidence, never clean.
- `CRASH`: a configured sanitizer or runner diagnostic was observed.
- `PROPERTY`: an S8 oracle reported a counterexample to its property.

Coverage (`HIT`, `MISSED`) is recorded separately and says nothing about
whether a sanitizer fired.

**Sanitizer run budget.** Sanitizer launches one agent may make per
iteration: `SHELL_SANITIZER_RUN_BUDGET` (default 60) or
`BROWSER_SANITIZER_RUN_BUDGET` (default 25). A launch past it is `NO_EXEC`
with class `budget-exhausted`. See
[Per-agent sanitizer budget](../concepts/cost-model.md#per-agent-sanitizer-budget).

**Scratch directory (`scratch-<n>/`).** Agent `<n>`'s working directory.
`bin/probe` runs only testcases stored there, and anything in it is
provisional until a probe run records evidence.

## Artifacts

**Bug class.** The canonical token a finding's `Class` field carries, such
as `heap-buffer-overflow` or `ssrf`. Each class belongs to a family, and
finding clusters key on the family. See [Bug classes](bug-classes.md).

**Cluster file (`crash-clusters.html`, `finding-clusters.html`).** A
summary grouping reports that share a deterministic evidence signature: a
deduplication aid, not proof of one root cause per cluster. See
[Deduplication](../concepts/deduplication.md).

**Cluster id.** `CL-<8 hex>` for a crash cluster, `FCL-<8 hex>` for a
finding cluster. Deterministic for unchanged inputs, but not a permanent
root-cause identifier: it changes when the cluster's canonical member does.

**Crash (`crashes/CRASH-*`).** A reproducible sanitizer diagnostic with its
saved input, output, and report, filed by `bin/probe` as
`CRASH-<nnn>-<agent>`. It is reportable only when its trigger is inside
`attacker_controls`. See
[Triage and review](../guides/triage-results.md).

**Crash state.** The identity of one sanitizer report: the fault primitive
plus the line-exact frames of the faulting stack (the "freed by" stack for a
lifetime bug). A bundle whose crash state and probe route match an already
reportable bundle moves to `crashes/.duplicates/`. Crash clustering uses a
coarser state; see [Deduplication](../concepts/deduplication.md).

**Export bundle.** The maintainer-facing form of a crash from
`bin/export-repro`: `report.md`, `reproduce.sh`, `input.<ext>`, an optional
`harness.*`, and `sanitizer.txt`. When no runnable route was captured,
`reproduce.sh` is a stub that says so and exits 2. See
[Reproduce a crash](../guides/reproduce-a-crash.md).

**Finding (`findings/FIND-*`).** A filed security report naming a concrete
location, issue class, and reviewer-actionable rationale, with or without a
reproducer. Review decides whether it becomes reportable.

**Rejected crash (`crashes-rejected/`).** A crash candidate that failed
triage, kept with a `rejection.md` and indexed in `rejected-crashes.html`,
so later sessions do not refile it.

**Rejected finding (`findings-rejected/`).** A FIND that failed review or
fell outside the threat model, kept and indexed in `rejected-findings.html`
with its reason.

## Review and publication

**Admitted.** Cleared the first gate (the substance gate for a finding, the
mechanical evidence checks for a crash) and moved on to source review. Not
publication.

**Filed.** Written to disk by an agent. Says nothing yet about review.

**Not reportable.** A real defect that crosses no security boundary. Current
triage writes a `not-reportable` receipt only for a human-pinned finding;
older trees may also carry one. Review-settled out-of-model results are
rejected with a `threat-model:` reason instead. Neither earns security credit
or a numeric severity. See
[Publication state](../guides/triage-results.md#publication-state).

**Pending.** Required content or review is incomplete. The artifact stays
visible without credit, and a benchmark counts it as unjudged. Completed
review that cannot establish scope ends in rejection, not pending.

**Promotion pending (`.promotion_pending`).** A crash held in `crashes/`
because its bundle is incomplete; the file lists what is missing. After ten
triage passes with the same items missing, it is rejected. See
[Troubleshooting](troubleshooting.md#triage-rejects-a-crash).

**Rejected.** A final state: the claim failed a gate, fell outside the
threat model, or could not be placed in scope after completed review. The
artifact moves to a rejected tree with its evidence and reason.

**Reportable.** Settled review found real security impact inside the
declared attacker surface. Only this state earns a numeric CVSS score and
counts toward security yield.

**Security yield.** The count of reportable results. See
[Publication state](../guides/triage-results.md#publication-state).

**Substance gate.** The first review a FIND faces: independent reviewers,
without the filing agent's context, vote on whether it states concrete
security substance. By default two accepts admit it and two rejects move it
to `findings-rejected/`; a reject short of quorum leaves a `.pending-drop`
marker.

**Trigger reviewer.** The source-reading review of a crash or admitted
finding. It judges whether the trigger is attacker-reachable and the
consequence holds, votes `Promote`, `Reject`, or `Uncertain`, and must anchor
a Reject in named source. A vote is a triage signal, not proof. See
[How automated review works](../guides/triage-results.md#how-automated-review-works).

**Unsettled scope.** A rejection with an `unsettled-scope:` reason: every
required review answered, but none established that the trigger is inside
the threat model. Terminal, and distinct from a source disproof.

**`validation.json`.** The content-addressed receipt recording an
artifact's [publication state](../guides/triage-results.md#publication-state)
(`reportable`, `pending`, `rejected`, or `not-reportable`), bound to the
report, its evidence, the target revision and config, and the threat model.
Changing any of those returns the artifact to review.

## Target configuration

**Attacker controls.** `[threat_model].attacker_controls`: what an external
caller can legitimately control. Tokens are `bytes`, `call-sequence` (alias
`call-order`), `timing`, `race`, `env`, `protocol-state`, and `fs-state`; an
empty list means `bytes`. A trigger that source review places outside this
set is rejected with a `threat-model:` reason. See
[Threat model](target-toml.md#threat-model).

**Config snapshot (`.target.toml`).** The copy of `target.toml` that
`bin/audit` pins into the results tree after preflight. Probes and gates
read the snapshot, so editing `target.toml` mid-run cannot change the
runner, build, or threat model behind recorded evidence.

**Findings-only mode.** `[sanitizer].enabled = []`, typical for interpreted
or managed-runtime targets. A runtime-only diagnostic is demoted from
`crashes/` into `findings/` and needs a substantive security report. See
[Findings-only mode](target-toml.md#findings-only-mode-no-sanitizer).

**Runner.** The command that carries a testcase into the target: a native
executable, an interpreter, or a project-specific driver, configured under
`[runner]`. See [Language runner](target-toml.md#language-runner).

**Sanitizer.** Runtime instrumentation that reports classes of invalid
execution. TokenFuzz knows `asan` (the default), `ubsan`, `msan`, `tsan`,
and `race`. A clean run means only that the selected detector reported
nothing in that execution.

**`.session-env`.** Per-run paths and identifiers (`RESULTS_DIR`,
`TARGET_SLUG`, `TARGET_REV`, `TARGET_CONFIG_SHA256`, and others) that
`bin/audit` writes to `output/<target>/<backend>/results/.session-env`.
`bin/probe` finds it by walking up from the testcase path.

**Target.** The project being reviewed, identified by a slug that may
contain path components, such as `samples/sample-python`. Its source is
normally `targets/<slug>/` and its configuration
`output/<slug>/target.toml`.

**`target.toml`.** The per-target configuration: source metadata, build
system, sanitizer artifacts, runner, and threat model. Setup generates it
and you review it. See the [target config reference](target-toml.md).

## Backends

**Agent security mode.** The boundary an agent launch runs under:
`sandboxed` (the CLI's own OS sandbox, the default except for `oss`) or
`external-bypass` (a container or VM you administer, asserted with
`IS_SANDBOX=1`). See
[Agent security modes](../guides/backends.md#agent-security-modes).

**Backend.** The LLM CLI driving the agent loop: `claude`, `codex`,
`gemini`, `grok`, or `oss`. `gemini` runs Antigravity (`agy`) unless
`USE_GEMINI_CLI=1` selects Google Gemini CLI; `oss` runs OpenCode against a
configured provider or local endpoint. See
[Backends and isolation](../guides/backends.md).

**Cyber-access program.** Provider-side trusted-access registration
(OpenAI's Trusted Access for Cyber, Anthropic's Cyber Verification Program)
that reduces false-positive policy interruptions during authorised defensive
research. See
[Cyber access](../getting-started/prerequisites.md#cyber-access-for-security-research).

**Ensemble mode.** `--backend all`, the default when neither `--backend`
nor `AUDIT_BACKEND` is set: it rotates the installed hosted backends across
iterations, with one results tree per backend. See
[Ensemble mode](../guides/backends.md#ensemble-mode).

## Builds and benchmarking

**Build lease.** A kernel-held reader/writer lock on a build tree. Every run
holds a shared lease on the builds it uses and a rebuild needs the exclusive
one, so a live run's build is never replaced under it. See
[Troubleshooting](troubleshooting.md#a-build-was-not-replaced-or-a-cell-refuses-to-start).

**Build pin.** The exact build artifacts (paths, sizes, and hashes) a
benchmark run records when it starts. Its cells and resumes verify against
the pin and never rebuild.

**Cell.** One audit run of one condition in a benchmark, with its own
results tree under the run's `cells/` directory.

**Closing pass.** The review of a cell's artifacts after its wall ends. It
cannot add findings, and its time is not counted in the cell's wall. See
[The closing pass](../concepts/benchmark.md#the-closing-pass).

**Condition.** One side of the benchmark comparison: `harness` (TokenFuzz)
or `model-direct` (the same model prompted directly with the same budget).
See [Benchmarking](../concepts/benchmark.md).

**Replicate.** One repetition of a condition. `--replicates` (default 3)
sets how many cells each condition gets.

**Unjudged.** A benchmark artifact that never reached a verdict. It earns no
credit, and a result count carries it as a `K unjudged` term.

**Wall budget.** The productive time a run may spend:
`AUDIT_WALL_BUDGET_SECS` for an audit (off by default) and `--budget-wall`
for a benchmark cell (default 10,800 seconds). Housekeeping counts against
it; provider pauses do not.
