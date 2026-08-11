# Glossary

One-line definitions for the vocabulary used across the handbook,
the reports, and the agent prompts.

## Audit lifecycle

**Audit run.** One invocation of `bin/audit`. May contain many
iterations and many agents.

**Iteration.** One outer pass of the audit loop. Each iteration
builds work cards, assigns roles, launches agents, and waits for
them to exit.

**Session.** Operator-facing concept. A continuous stretch of
audit iterations against the same target and backend, normally
rooted in the same `output/<target>/<backend>/` tree.

**Cold start.** An iteration where no agent has structured state yet—typically
the first working iteration of a fresh target.

**Validator.** The second-opinion model run on a filed finding.
Reads the same source independently, votes Promote / Reject /
Uncertain, and ranks what reaches the audit's work queue. The
validator vote is a triage signal, not proof.

**Resume.** An iteration where the agent reads structured state
to continue prior hypotheses.

**Compaction.** The backend's automatic shortening of the
conversation when it nears the context limit. The harness emits
a checkpoint warning before compaction so the agent can save
progress to structured state.

**Session seed.** A small set of `PRIOR SESSION SEED` ranges
(files + line windows) the agent already covered. The prompt
tells the agent not to re-read those ranges after compaction.

## Strategies

**Strategy (S1, S2, S3, S5, S6, S7, or S8).** A named recipe an agent follows: how to
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
browser-readable summary grouping reports that share a deterministic evidence
signature. It is a deduplication proxy, not proof of one root cause per cluster.
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
trigger source falls outside this set, and whose source reviewer agrees that it
does, stays in `crashes/` as `not-reportable`: no security report, no security
yield, no numeric CVSS.

**Findings-only mode.** `[sanitizer].enabled = []`. Typical for
interpreted / managed-runtime targets (Python, Ruby, Node, Java,
PHP) but valid for any project without an ASan build. Runtime
diagnostics are filed under `findings/`, not `crashes/`.

**`.session-env`.** Dynamic per-run paths and identifiers
(`RESULTS_DIR`, `TARGET_ROOT`, `TARGET_REV`, `TARGET_REPO_TYPE`, `TARGET_SLUG`,
`LOGDIR`, `SESSION_STARTED`) written by `bin/audit` at startup
into `output/<target>/<backend>/results/.session-env`. `bin/probe`
discovers it by walking up from the testcase path, so no env vars need
to be exported by hand.

## Backends

**Backend.** The LLM CLI driving the agent loop — `claude`,
`codex`, `gemini`, `grok`, or `oss` (OpenCode against a local vLLM or Ollama
server).

**Ensemble mode.** `--backend all` (or omitted) — cycles
installed hosted backends across iterations, writing
per-backend result trees.

**Cyber-access program.** Provider-side trusted-access
registration (OpenAI's Trusted Access for Cyber, Anthropic's
Cyber Verification Program) that reduces false-positive policy
interruptions during authorised defensive research.

## Work queue and state

**Work card.** One unit of audit work — a source file paired with a
strategy, a prior fix, or a peer-project fix. Agents claim cards from
the ranked queue in `work-cards.jsonl`.

**Claim.** The lease an agent holds on a card while it works the
hypothesis. Expires after 30 minutes so a killed agent does not
strand its card.

**Subsystem.** The leading directories of a source file (`parser/xml`,
`crypto/aes`, …) — never the file name, or a tree only that deep would
give every file a subsystem of its own. Two agents are kept out of the
same subsystem at once, so a run spreads across the tree.

**Hypothesis.** A narrow, falsifiable claim about a specific
`file:function:line` — the input shape that reaches it, the guard it
should violate, and the diagnostic expected. The unit of agent work,
recorded with its outcome in `state/hypotheses.jsonl`.

**`state/*.jsonl`.** Append-only records of claims, hypotheses, probe
runs, and notes. This — not the model transcript — is what a resumed
run reads.
