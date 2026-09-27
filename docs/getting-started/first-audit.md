# First audit

Run one bounded audit before you commit time or model budget to a longer
session. The smoke test checks the target config, build preflight, backend,
state store, and output layout together. An empty findings directory is a
normal outcome.

You need the [prerequisites](prerequisites.md) and a configured target:
a [sample target](sample-targets.md) or one you [added](add-a-target.md).

## Where to run the audit

Target builds and agent-driven testcases execute code from the audited tree,
so run in a container or on an isolated host without long-lived credentials.
The recommended default is `bin/audit-container-shell`. It isolates target
build scripts and agent tool use from most of the host filesystem while
keeping the checkout and output in the mounted repository:

```bash
bin/audit-container-shell --rebuild   # first use: build the image
bin/audit-container-shell             # later uses
```

The helper opens a shell at `/root/work` with the backend CLIs installed. It
does not start the audit, and it does not mount host CLI credential
directories: log in inside the shell, or pass `--forward-credentials`. If the
backend's own sandbox cannot start inside the container, run with
`--agent-security external-bypass`; the container is then your boundary.
[Container runtime](prerequisites.md#container-runtime-recommended) covers
Docker, gVisor, and the trust boundary.

## 1. Run one iteration

In the shell you will audit from, set variables for the commands on this
page, naming the backend so the output path is predictable:

```bash
TARGET=samples/sample-python        # or your own target slug
BACKEND=claude                      # or codex, gemini, grok, oss
RESULTS="output/$TARGET/$BACKEND/results"
LOGS="output/$TARGET/$BACKEND/logs"
```

Do not `export` them: several TokenFuzz tools read an exported `BACKEND` as a
backend choice. Then run:

```bash
bin/audit --target "$TARGET" --backend "$BACKEND" 1
```

The trailing `1` makes this a smoke test: one worker launches, whatever the
normal pool size (3 by default; see
[Worker pool](../reference/environment.md#worker-pool)), and claims ranked
work for one iteration. Result and log directories stay in place for the next
run.

Add these when they apply:

- `--model <id>`: required for `oss`, on this and every later audit command.
  For a hosted backend, pass it when reproducibility matters; otherwise the
  default model and reasoning effort come from `config/models.toml`
  ([overrides](../reference/environment.md#model-selection)).
- `--agent-security external-bypass`: required for `gemini` and `grok`, which
  cannot run inside their own CLI sandbox. Run them in a container or VM you
  administer; see [Agent security modes](../guides/backends.md#agent-security-modes).
- `--strategy S1` (or any of `S2` through `S8`): pins that strategy and
  suspends normal rotation, for a focused plumbing test.

Without `--backend`, `bin/audit` uses `AUDIT_BACKEND`, or rotates every
installed and configured hosted backend.

### What happens before the agent starts

In order, the audit:

1. checks that the configured `[runner].bin` starts and reaches the audited
   tree, when the target has a runner;
2. sends a small model preflight and stops if the provider refuses or serves
   a different model;
3. builds or refreshes stale sanitizer trees, continuing with a warning if a
   build fails;
4. pins the reviewed config for the session.

!!! warning "Do not edit the live session snapshot"
    Preflight copies the reviewed config to `$RESULTS/.target.toml` and binds
    it, with the target path and revision, in `$RESULTS/.session-env`. Every
    probe in the session reads that copy. Edit `output/$TARGET/target.toml`
    only between runs; never edit or remove the snapshot.

### What success looks like

The startup timeline goes to `$LOGS/index.log`. Look for these lines:

```text
Model preflight passed: backend=<backend> model=<model>
LLM backend: provider=<backend> model=<model>
Target: slug=<target> path=<source path>
Output: results=<results dir> logs=<logs dir>
Iteration 1 starting: agents=1 ...
Agent 1 cold-start finished rc=0 ... log=session_<stamp>_cold-start-1.log
```

The result tree should contain at least:

```text
results/
  .session-env
  .target.toml
  work-cards.jsonl
  state/
  scratch-1/
  findings/
  crashes/
  findings-rejected/
  crashes-rejected/
```

`state/hypotheses.jsonl`, `state/runs.jsonl`, and testcases appear only if the
agent got that far. Their absence is a reason to read the log, not proof that
setup failed. [Artifacts](../reference/artifacts.md) describes every file.

Press Ctrl-C to stop a longer run. The orchestrator terminates the active
backend process tree and leaves structured state for the next invocation.

## 2. Inspect the run

Start with the compact state view:

```bash
bin/state --results-dir "$RESULTS" show-recent --agent 1
```

Then open the generated review pages:

| Path | What it shows |
| --- | --- |
| `$RESULTS/findings/finding-clusters.html` | Concrete security findings, including reports without a reproducer. |
| `$RESULTS/crashes/crash-clusters.html` | Confirmed crash clusters and maintainer bundles. |
| `$RESULTS/crashes-rejected/rejected-crashes.html` | Rejected crash candidates with reasons. |
| `$RESULTS/findings-rejected/rejected-findings.html` | Rejected findings with reasons. |
| `output/$TARGET/finding-clusters.html` | Finding summary across backends. |
| `output/$TARGET/crash-clusters.html` | Crash summary across backends. |

An empty `findings/` or `crashes/` after one iteration is normal. A filed FIND
is not automatically a confirmed security result: read its Status column and
its `validation.json`, and see [Triage and review](../guides/triage-results.md).

To tell an uneventful iteration from a failed one, read in this order:

1. `$LOGS/index.log`, for preflight or backend failures.
2. The `show-recent` view above, for claims and hypotheses.
3. `$RESULTS/state/runs.jsonl`, for recorded probe executions, if it exists.
4. The two rejected pages, for candidates that reached triage but did not
   meet the bar.
5. The trimmed session log that `index.log` names (`$LOGS/session_*.log`), and
   only as a last resort the raw backend transcripts under `$LOGS/.raw/`.

To see what the iteration never looked at:

```bash
bin/state --results-dir "$RESULTS" coverage
```

It compares auditable files per directory with those offered to a session,
claimed, requested in a transcript, and verifiably examined, and lists the
largest files never offered. A clean run over a mostly unread tree is a budget
statement, not a security result; [Review coverage](../concepts/coverage.md)
explains the columns.

## 3. Continue or reset

```bash
bin/audit --target "$TARGET" --backend "$BACKEND" 10   # a bounded session
bin/audit --target "$TARGET" --backend "$BACKEND"      # run until stopped
```

Both use the configured worker pool and normal strategy rotation, and resume
from the structured state already in `$RESULTS`.

To see what a cleanup would remove before starting over:

```bash
bin/cleanup_state --target "$TARGET" --backend "$BACKEND" --dry-run
bin/cleanup_logs --target "$TARGET" --backend "$BACKEND" --dry-run
```

Remove `--dry-run` only after checking the printed paths. Always pass
`--target`: without it, both commands act on every target under `output/`.
Without `--backend`, `bin/cleanup_state` resets every backend and aggregate
result for the target, and also removes its generated sanitizer build trees
and transient `.audit/` state from the target source. It keeps `target.toml`,
`.ground-truth.json`, and the `.audit/build.sh` and
`.audit/build-<sanitizer>.sh` recipes. A backend-scoped cleanup leaves the
shared source builds intact.

## What's next

- [Triage and review](../guides/triage-results.md) explains what is ready for
  maintainer review.
- [Sanitizer policy](../guides/configure-target.md#sanitizer-policy) explains
  how to audit with UBSan, MSan, or TSan instead of ASan.
- [Backends and isolation](../guides/backends.md) covers hosted rotation and
  local models.
- [Audit lifecycle](../concepts/audit-lifecycle.md) connects setup, agents,
  probing, triage, and export.
