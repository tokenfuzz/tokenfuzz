# Glossary

One-line definitions for the vocabulary used throughout the
harness, the docs, and the agent prompts. Terms are grouped by
topic; within a group, they are listed alphabetically. The
operator-facing groups come first; the
[Harness internals](#harness-internals) section at the end covers
vocabulary you only need when extending the harness or reading raw
state.

## Audit lifecycle

**Audit run.** One invocation of `bin/audit`. May contain many
iterations and many agents.

**Iteration.** One outer pass of the audit loop. Each iteration
builds work cards, assigns roles, launches agents, and waits for
them to exit.

**Session.** Operator-facing concept. A continuous stretch of
audit iterations against the same target and backend, normally
rooted in the same `output/<target>/<backend>/` tree.

**Cold start.** An iteration where no agent has a state file yet
— typically the first iteration of a fresh target. Cold start
also runs the recon survey before the deep agents launch.

**Recon.** A short breadth-first review pass over the in-scope
source set. Runs at the start of an audit (or via
`bin/audit-recon` on its own), surveys the code for candidate
bugs with one model, gates them with an independent second
model, and seeds the work queue with prioritized candidates.
Cached on the target source SHA. See
[Recon discovery](../guides/recon-discovery.md).

**Recon-hypothesis card.** A work card derived from a recon
finding (`kind: "recon-hypothesis"` in `work-cards.jsonl`).
High-confidence cards are tried before the regular queue;
validator-rejected cards are kept at lower priority rather than
deleted.

**Validator.** The second-opinion model run on every recon
emission. Reads the same source independently, votes Promote /
Reject / Uncertain, and ranks what reaches the audit's work
queue. The validator vote is a triage signal, not proof.

**Resume.** An iteration where the agent reads structured state
to continue prior hypotheses. Recon is skipped on resume — the
cache from cold start is re-used.

**Compaction.** The backend's automatic shortening of the
conversation when it nears the context limit. The harness emits
a checkpoint warning before compaction so the agent can save
findings to its state file.

**Session seed.** A small set of `PRIOR SESSION SEED` ranges
(files + line windows) the agent already covered. The prompt
tells the agent not to re-read those ranges after compaction.

## Strategies

**Strategy (S1–S8).** A named recipe an agent follows: how to
pick a hypothesis, find an input, mutate it, and decide what the
result means. See
[Strategy model](../concepts/strategy-model.md).

**REF.** Shared grep recipes used alongside any strategy. Not
itself a strategy.

**Rotation.** Switching an agent's current strategy after
sustained dry effort. Effort-gated, not iteration-gated.

**Guard chain.** A repeating upstream error string ("Error:
regexp too big", `NS_ERROR_…`) that blocks a run of testcases in
one subsystem.

**GUARD-… card.** A synthetic work card the harness appends when
a guard chain saturates, asking the agent for a path past the
guard.

## Probe and execution

**Probe (`bin/probe`).** The only execution gate for testcases.
Reads headers, picks the right runner, coverage-gates, runs the
sanitizer, and records `state/runs.jsonl`.

**Coverage gate.** A pre-run on a sancov-instrumented build that
confirms the testcase reaches the named target code before
spending a sanitizer-run budget.

**HIT / MISSED / CLEAN.** Probe verdicts.

- `MISSED` — the testcase did not reach the target code.
- `HIT` — it did.
- `CLEAN` — it ran without sanitizer output.

**Confirm run.** A 5-times re-run of a candidate crash
(`bin/probe --confirm`) before promotion, to filter flaky
single-run results.

**Harness (testcase `HARNESS:` header).** A sibling source file
(`harness.c`, `harness.cc`, `harness.cpp`, `harness.cxx`,
`harness.C`, or a language-specific runner) that `bin/probe`
compiles and links against the target library to exercise an API.

**Scratch dir (`scratch-N/`).** In-progress testcase work for
agent `N`. Anything here is provisional until probe confirms it.

## Artifacts

**Crash (`crashes/CRASH-*`).** A sanitizer-confirmed reproducer
with a saved trace, an input, and a report. Promotion requires
a memory-safety or explicit boundary violation reachable through
the target's documented input boundary.

**Finding (`findings/FIND-*`).** A concrete security issue with
a written report naming `file:function:line`, an issue class,
and a reviewer-actionable rationale. May or may not have a
reproducer.

**Rejected crash (`crashes-rejected/`).** A candidate that
failed triage, indexed with a reason so future sessions do not
refile it.

**Cluster file (`CRASH-CLUSTERS.html`, `FINDING-CLUSTERS.html`).** A
browser-readable summary grouping reports that share a root cause.
Per-backend at the result tree; cross-backend at the target root. The
`.md` siblings are the generated markdown source.

**Export bundle.** The maintainer-facing form of a crash,
produced by `bin/export-repro`: `REPORT.md`, `reproduce.sh`,
`input.<ext>`, optional `harness.*`, `sanitizer.txt`. See
[Reproduce a crash](../guides/reproduce-a-crash.md).

## Configuration

**`target.toml`.** Per-target generated config: source metadata,
sanitizer binaries, build system, threat model. Lives at
`output/<target>/target.toml`. See
[Target config reference](target-toml.md).

**Attacker controls.** `[threat_model].attacker_controls` — the
tokens describing what an external caller can legitimately
control. Valid tokens are `bytes`, `call-sequence`, `timing`,
`race`, `env`, `protocol-state`, and `fs-state`. A crash whose
trigger source falls outside this set stays in `crashes/` but is
flagged with a contract concern, which sets CVSS **MAT:P** (Modified
Attack Requirements: present) in the CVSS-BTE score — threat-model fit
is a scoring question, not a filing one.

**Findings-only mode.** `[sanitizer].enabled = []`. Typical for
interpreted / managed-runtime targets (Python, Ruby, Node, Java,
PHP) but valid for any project without an ASan build. Runtime
diagnostics are filed under `findings/`, not `crashes/`.

**`.session-env`.** Dynamic per-run paths and identifiers
(`RESULTS_DIR`, `TARGET_ROOT`, `TARGET_REV`, `TARGET_SLUG`,
`LOGDIR`, `SESSION_STARTED`) written by `bin/audit` at startup
into `output/<target>/<backend>/results/.session-env`. `bin/probe`
discovers it by walking up from the testcase path, so no env vars need
to be exported by hand.

## Backends

**Backend.** The LLM CLI driving the agent loop — `claude`,
`codex`, `gemini`, or `oss` (local Ollama via Codex).

**Ensemble mode.** `--backend all` (or omitted) — cycles
installed hosted backends across iterations, writing
per-backend result trees.

**Cyber-access program.** Provider-side trusted-access
registration (OpenAI's Trusted Access for Cyber, Anthropic's
Cyber Verification Program) that reduces false-positive policy
interruptions during authorised defensive research.

## Harness internals

Vocabulary for the queue, structured state, and cost machinery.
You only need these when extending the harness or reading raw
state files directly.

### Work-card pipeline

**Work card.** A single unit of audit work — one source file ×
strategy, or one prior fix, or a synthetic GUARD-… task. Lives
in `work-cards.jsonl` / `patch-cards.jsonl`.

**Patch card.** A prior-fix work card (strategy S1), built by
`bin/patch-cards` from the target's VCS history.

**Companion card.** A second work card for the same file with a
different strategy, emitted when a file fires more than one
code-feature signal.

**Ranker (`bin/rank-work`).** The deterministic scorer that
walks the source tree, applies `CODE_PATTERNS`, structural and
coverage signals, and emits the ranked queue.

**Claim.** The lease an agent takes on a card when it adopts the
card into a hypothesis. Recorded in `claims.jsonl`. Expires
after 30 minutes by default.

**Work surface.** The dedupe key the work queue uses to prevent
duplicate claims. Surface-card cards key on `file:function`
(file-scoped cards use `file:S<n>` where `n` is the strategy
number). A separate diversity gate prevents two agents from
sharing a subsystem at the same time.

**Subsystem.** The first one to five path components of a source
file (`parser/xml`, `crypto/aes`, …). Used for blocklisting,
ownership, and guard-saturation tracking. Depth is auto-picked
at startup.

**Dry streak.** Consecutive iterations on the same strategy with
no confirmed result. Tracked per agent in
`.agent_strategy_streak_<n>`.

### State

**`state/*.jsonl`.** Structured append-only records:
`hypotheses.jsonl`, `claims.jsonl`, `runs.jsonl`, `notes.jsonl`.

**Hypothesis.** A narrow, falsifiable claim about a specific
`file:function:line` with a named input shape, guard gap, and
expected diagnostic. The unit of agent work.

**Status.** A hypothesis lifecycle marker: `PENDING`,
`INVESTIGATING`, `NEEDS_TESTCASE`, `NEEDS_DEEPER_PROBE`,
`ENV-BLOCKED`, `DISCARDED`, `CRASH-XXX`, `FIND-XXX`.

### Cost levers

See [Cost model](../concepts/cost-model.md) for full context.

**Prompt cache.** Cached cross-agent prompt fragments built
once per iteration into `.static-prompt-rules.md`.

**Capping wrappers.** `bin/rg-safe`, `bin/peek`,
`bin/show-patch`, `bin/scratch-search` — enforce per-call
byte / line ceilings so agents cannot dump raw source into
context.

**ASan budget.** Per-agent per-iteration sanitizer-run budget
(25 for browser agents, 60 for shell agents). Coverage-gate runs
do not count against it.

**Tried-inputs / hits log.** `tried-inputs-N.log` and
`hits-N.log` — per-agent memory of testcase shapes and reached
coverage edges, so the next session does not repeat them.
