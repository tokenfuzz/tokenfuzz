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

**Cold start.** An iteration where no agent has structured state yet — typically
the first working iteration of a fresh target.

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

**Strategy (S1 through S8).** A named recipe an agent follows: how to
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
spending a sanitizer-run budget. When no route-equivalent coverage artifact
exists, the sanitizer run proceeds ungated rather than being labelled a miss.

**Probe verdicts.** The execution result recorded in `state/runs.jsonl`.

- `MISSED` — the testcase did not reach the target code.
- `HIT` — it did.
- `CLEAN` — it ran without sanitizer output.
- `EXEC_FAIL` — it reached the configured runner but did not complete cleanly.
- `NO_EXEC` — no target-execution evidence was established.
- `TIMEOUT` — the runner reached its reserved wall-clock deadline; this is
  unresolved evidence, never a clean run.
- `CRASH` — a configured sanitizer or runner diagnostic was observed.
- `PROPERTY` — an S8 oracle reported a declared property counterexample.

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

**Crash (`crashes/CRASH-*`).** A sanitizer-confirmed reproducer with a saved
trace, an input, and a report. Promotion requires a memory-safety or explicit
boundary violation — not attacker reachability, which decides *reportability*
instead: a crash whose trigger needs a control outside `attacker_controls`
stays here as `not-reportable`.

**Finding (`findings/FIND-*`).** A filed security report naming a concrete
location, issue class, and reviewer-actionable rationale. It may or may not
have a reproducer; validation determines whether the filed report becomes a
reportable result.

**Rejected crash (`crashes-rejected/`).** A crash candidate that failed
triage, kept on disk and indexed in `REJECTED-CRASHES.html` with a reason, so
future sessions do not refile it.

**Rejected finding (`findings-rejected/`).** A FIND that lost at quorum — the
substance gate, an unreachable trigger, or a source-disproved consequence.
Kept on disk and indexed in `REJECTED-FINDINGS.html`. Quarantined, never
deleted, so a false reject can be reviewed and recovered.

**Cluster file (`CRASH-CLUSTERS.html`, `FINDING-CLUSTERS.html`).** A
browser-readable summary grouping reports that share a deterministic evidence
signature. It is a deduplication proxy, not proof of one root cause per cluster.
Per-backend at the result tree; cross-backend at the target root. The
`.md` siblings are the generated markdown source.

**Export bundle.** The maintainer-facing form of a crash,
produced by `bin/export-repro`: `REPORT.md`, `reproduce.sh`,
`input.<ext>`, optional `harness.*`, `sanitizer.txt`. See
[Reproduce a crash](../guides/reproduce-a-crash.md).

**Cluster id.** The hash naming a cluster — `CL-<8 hex>` for crashes,
`FCL-<8 hex>` for findings. Derived from the cluster's signature, not from its
membership, so it is stable across reruns.

## Triage verdicts

**Substance gate.** The first review a FIND faces: two independent readers,
with none of the filing agent's context, vote accept or reject on whether the
report contains concrete security substance. Two accepts confirm; two rejects
quarantine.

**Trigger reviewer.** The source-reading second opinion on a crash or an
accepted finding. It answers whether the trigger is attacker-reachable and
whether the claimed consequence holds, votes Promote / Reject / Uncertain, and
must anchor a Reject in named source. It fails open: missing or inconclusive
output keeps the artifact. Its vote is a triage signal, not proof.

**`validation.json`.** The content-addressed receipt recording an artifact's
publication state, bound to the report, its evidence, the target revision and
config, and the threat model. Change any of those and the artifact returns to
review.

**Reportable.** A settled review found real security impact inside the declared
attacker surface. Only this state earns a numeric CVSS score and counts toward
security yield.

**Not reportable.** A settled review found a real *engineering* defect that
crosses no security boundary — commonly a trigger needing a control
`attacker_controls` does not list. Final, kept on disk, never scored, never
counted as yield.

**Pending.** No review settled the artifact. Neither credited nor written off;
it is reported as part of the unjudged remainder.

**Filed.** An agent wrote the required artifact to disk. This says nothing yet
about independent review.

**Admitted.** The artifact cleared its first evidence or substance gate and can
proceed to source review. Admission is not publication.

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
(`RESULTS_DIR`, `TARGET_ROOT`, `TARGET_SLUG`, `TARGET_REV`,
`TARGET_REPO_TYPE`, `LOGDIR`, `SESSION_STARTED`, `TARGET_CONFIG_SHA256`)
written by `bin/audit` at startup into
`output/<target>/<backend>/results/.session-env`. `bin/probe` discovers it by
walking up from the testcase path, so no env vars need to be exported by
hand.

## Backends

**Backend.** The LLM CLI driving the agent loop — `claude`, `codex`, `gemini`,
`grok`, or `oss`. The `oss` route uses OpenCode with either a configured
provider or an OpenAI-compatible local endpoint such as vLLM or Ollama.

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
