# Glossary

Definitions for terms used in the handbook, generated reports, and agent
prompts. Entries are grouped by the part of the system they describe.

## Audit lifecycle

**Audit run.** One invocation of `bin/audit`. May contain many iterations and
many agents.

**Iteration.** One outer pass of the audit loop. In an ordinary continuous run
an iteration is a steward tick; in cohort mode (fixed-lane, delta, ensemble,
and `--no-refill-workers` runs) it is one pool of agents launched together and
waited for.

**Session.** One backend process working one agent slot, from launch to exit.
A turn-capped session's continuation counts as the same session.

**Cold start.** A session for an agent that has no structured state yet,
typically the first working iteration of a fresh target.

**Resume.** A session that reads structured state to continue prior
hypotheses.

**Compaction.** The backend's automatic shortening of the conversation when it
nears the context limit. The harness emits a checkpoint warning before
compaction so the agent can save progress to structured state.

**Session seed.** A small set of `PRIOR SESSION SEED` ranges (files plus line
windows) the agent already covered. The prompt tells the agent not to re-read
those ranges after compaction.

**Steward tick.** In a continuous run, the timer-driven pass (every
`STEWARD_INTERVAL_SECS`) that scores the generation, rotates starved
strategies, and re-ranks the queue without stopping any live slot.

**Delta audit.** `bin/audit --since <rev>`: a run scoped to the files changed
in `<rev>..HEAD`, their one-hop callers, and one S1 card per commit in the
range.

## Strategies

**Strategy (S1 through S8).** A named recipe an agent follows: how to pick a
hypothesis, find an input, mutate it, and decide what the result means. See
[Strategy model](../concepts/strategy-model.md).

**REF.** Shared grep recipes used alongside any strategy. Not itself a
strategy.

**Rotation.** Switching an agent's current strategy after a run of dry
iterations on it, once its notes show the strategy was worked.

**Guard chain.** A repeating upstream error string ("Error: regexp too big",
`NS_ERROR_…`) that blocks a run of testcases in one subsystem.

## Probe and execution

**Probe (`bin/probe`).** The only execution gate for testcases. Reads headers,
picks the right runner, performs a coverage check where supported, runs the
sanitizer or configured runner, and records `state/runs.jsonl`.

**Coverage gate.** A pre-run on a sancov-instrumented build that checks whether
a testcase reaches the named target code. Browser and JavaScript routes treat
a miss as a hard gate and skip the sanitizer run; native routes record the
miss as feedback and run the sanitizer anyway. When no route-equivalent
coverage build exists or the check cannot run, the probe records why
(`COVERAGE_UNAVAILABLE`, `COVERAGE_ENV_FAIL`) and proceeds ungated.

**Probe verdicts.** Execution results recorded in `state/runs.jsonl`.
Coverage is a separate measurement: `HIT` means the named code was reached;
`MISSED` means the coverage replay did not reach it. Neither says whether a
sanitizer found an error.

- `CLEAN`: execution completed without a recognized diagnostic.
- `EXEC_FAIL`: it reached the configured runner but did not complete cleanly.
  The row carries an `execution_failure_class` (`loader`, `usage`,
  `input-rejected`, `aborted`, `unverified-exit`, or `exit`).
- `NO_EXEC`: no target-execution evidence was established, including a launch
  the sanitizer budget refused (`budget-exhausted`).
- `TIMEOUT`: the runner reached its reserved wall-clock deadline; this is
  unresolved evidence, never a clean run.
- `CRASH`: a configured sanitizer or runner diagnostic was observed.
- `PROPERTY`: an S8 oracle reported a declared property counterexample.

**Confirm run.** A five-times re-run of a candidate crash
(`bin/probe --confirm`) before promotion, to filter flaky single-run results.

**Harness (testcase `HARNESS:` header).** A sibling source file (`harness.c`,
`harness.cc`, `harness.cpp`, `harness.cxx`, `harness.C`, or a
language-specific runner) that `bin/probe` compiles or interprets to exercise
an API.

**Scratch dir (`scratch-N/`).** In-progress testcase work for agent `N`.
Anything here is provisional until probe confirms it.

## Artifacts

**Crash (`crashes/CRASH-*`).** A sanitizer-confirmed reproducer with a saved
trace, an input, and a report. Promotion requires a memory-safety or explicit
boundary violation, not attacker reachability, which decides *reportability*
instead: a crash whose trigger needs a control outside `attacker_controls`
is rejected with a `threat-model:` reason.

**Bug class.** The canonical token a finding's `Class` field carries, from
the [bug class reference](bug-classes.md): the vocabulary public disclosure
ledgers use (`heap-buffer-overflow`, `auth-bypass`, `ssrf`, …) plus a few
harness-native classes. Each class belongs to one *family*, which is what
finding clusters key on.

**Finding (`findings/FIND-*`).** A filed security report naming a concrete
location, issue class, and reviewer-actionable rationale. It may or may not
have a reproducer; validation determines whether the filed report becomes a
reportable result.

**Rejected crash (`crashes-rejected/`).** A crash candidate that failed
triage, kept on disk and indexed in `REJECTED-CRASHES.html` with a reason, so
future sessions do not refile it.

**Rejected finding (`findings-rejected/`).** A FIND that failed substance or
source review, fell outside the threat model, or remained out of established
scope after completed review. Kept on disk and indexed in
`REJECTED-FINDINGS.html` with its reason, so the decision can be reviewed.

**Cluster file (`CRASH-CLUSTERS.html`, `FINDING-CLUSTERS.html`).** A
browser-readable summary grouping reports that share a deterministic evidence
signature. It is a deduplication proxy, not proof of one root cause per
cluster. Per-backend at the result tree; cross-backend at the target root. The
`.md` siblings are the generated markdown source.

**Export bundle.** The maintainer-facing form of a crash, produced by
`bin/export-repro`: `REPORT.md`, `reproduce.sh`, `input.<ext>`, optional
`harness.*`, and `sanitizer.txt`. When no runnable route was captured,
`reproduce.sh` is a stub that says so and exits 2. See
[Reproduce a crash](../guides/reproduce-a-crash.md).

**Cluster id.** The hash naming a cluster: `CL-<8 hex>` for crashes,
`FCL-<8 hex>` for findings. Crash ids depend on the encounter-order
representative's signature; finding ids also include the canonical finding id.
They are deterministic for
unchanged inputs and ordering, but can change when the representative or
canonical member changes. They are not permanent root-cause identifiers.

## Triage verdicts

**Substance gate.** The first review a FIND faces: two independent readers,
with none of the filing agent's context, vote accept or reject on whether the
report contains concrete security substance. Two accepts confirm; two rejects
quarantine.

**Trigger reviewer.** The source-reading second opinion on a crash or an
accepted finding. It answers whether the trigger is attacker-reachable and
whether the claimed consequence holds, votes Promote / Reject / Uncertain, and
must anchor a Reject in named source. Missing required output keeps the
artifact pending. Completed review that cannot establish scope leads to an
`unsettled-scope:` rejection with the evidence preserved. A review vote is a
triage signal, not proof.

**`validation.json`.** The content-addressed receipt recording an artifact's
publication state, bound to the report, its evidence, the target revision and
config, and the threat model. Change any of those and the artifact returns to
review.

**Reportable.** A settled review found real security impact inside the
declared attacker surface. Only this state earns a numeric CVSS score and
counts toward security yield.

**Not reportable.** A real engineering defect outside the security boundary.
Current triage normally rejects it with a `threat-model:` reason while keeping
the evidence. Human-pinned and older artifacts can retain the
`not-reportable` receipt in place. Neither form receives security credit or
numeric severity.

**Pending.** Required content or review is incomplete. The artifact stays
available without security credit and contributes to the unjudged remainder.
Completed review that cannot establish scope is rejected, not left pending.

**Filed.** An agent wrote the required artifact to disk. This says nothing yet
about independent review.

**Admitted.** The artifact cleared its first evidence or substance gate and
can proceed to source review. Admission is not publication.

## Configuration

**Target.** The project being reviewed, identified by a slug and a configured
source root. A slug such as `samples/sample-python` can contain path components.
Its configuration normally lives at `output/<slug>/target.toml`.

**Runner.** The command that carries a testcase into the target. It can be a
native executable, an interpreter, or a project-specific driver. `[runner]`
defines its arguments and environment where that route is used.

**Sanitizer.** Runtime instrumentation that reports particular classes of
invalid execution, such as an out-of-range memory access. A clean run means
that the selected detector did not report a problem in that execution; it is
not proof that the project is safe.

**`target.toml`.** Per-target generated config: source metadata, sanitizer
binaries, build system, threat model. Lives at `output/<target>/target.toml`.
See [Target config reference](target-toml.md).

**Attacker controls.** `[threat_model].attacker_controls`: the tokens
describing what an external caller can legitimately control. Valid tokens are
`bytes`, `call-sequence`, `timing`, `race`, `env`, `protocol-state`, and
`fs-state`. A crash whose trigger source falls outside this set, and whose
source reviewer agrees that it does, is rejected with a `threat-model:`
reason: the evidence moves to `crashes-rejected/`, no security yield, no
numeric CVSS.

**Findings-only mode.** `[sanitizer].enabled = []`. Typical for interpreted
or managed-runtime targets (Python, Ruby, Node, Java, PHP) but valid for any
project without a sanitizer build. Runtime diagnostics guide investigation;
a runtime-only diagnostic is demoted from `crashes/` into `findings/` as a
candidate, and a substantive security report is required for it to be admitted.

**`.session-env`.** Dynamic per-run paths and identifiers (`RESULTS_DIR`,
`TARGET_ROOT`, `TARGET_SLUG`, `TARGET_REV`, `TARGET_REPO_TYPE`, `LOGDIR`,
`SESSION_STARTED`, `TARGET_CONFIG_SHA256`) written by `bin/audit` at startup
into `output/<target>/<backend>/results/.session-env`. `bin/probe` discovers
it by walking up from the testcase path, so no env vars need to be exported by
hand.

## Backends

**Backend.** The LLM CLI driving the agent loop: `claude`, `codex`, `gemini`,
`grok`, or `oss`. The `oss` route uses OpenCode with either a configured
provider or an OpenAI-compatible local endpoint such as vLLM or Ollama.

**Ensemble mode.** `--backend all` (or omitted): cycles installed hosted
backends across iterations, writing per-backend result trees.

**Agent security mode.** The execution boundary an agent launch runs under:
`sandboxed` (the CLI's own OS sandbox) or `external-bypass` (a container or VM
you administer, announced with `IS_SANDBOX=1`).

**Cyber-access program.** Provider-side trusted-access registration (OpenAI's
Trusted Access for Cyber, Anthropic's Cyber Verification Program) that reduces
false-positive policy interruptions during authorised defensive research.

## Work queue and state

**Work card.** One unit of audit work: a source file paired with a strategy, a
prior fix, or a peer-project fix. Agents claim cards from the ranked queue in
`work-cards.jsonl`.

**Claim.** The lease an agent holds on a card while it works the hypothesis.
Expires after 30 minutes so a killed agent does not strand its card.

**Subsystem.** The leading directories of a source file (`parser/xml`,
`crypto/aes`, and so on), never the file name, or a tree only that deep would
give every file a subsystem of its own. Ranking prefers not to put two agents
in the same subsystem at once, so a run spreads across the tree.

**Hypothesis.** A narrow, falsifiable claim about a specific
`file:function:line`: the input shape that reaches it, the guard it should
violate, and the diagnostic expected. The unit of agent work, recorded with
its outcome in `state/hypotheses.jsonl`.

**Structured state (`state/*.jsonl`).** Durable claims, hypotheses, probe
runs, notes, and events. Claims, runs, notes, and events are append-only
ledgers; hypothesis status is maintained by an atomic rewrite. This, not the
model transcript, is what a resumed run reads.
