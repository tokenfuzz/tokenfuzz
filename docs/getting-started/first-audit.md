# First Audit

Run one bounded audit before committing time or model budget to a continuous
session. The smoke test verifies the target config, build preflight, backend,
state store, and output layout. It is not expected to find a vulnerability.

Complete [Prerequisites](prerequisites.md) and
[Add a target](add-a-target.md) first. Run the audit in a container or on an
isolated host without long-lived credentials; target builds and agent-driven
testcases execute code from the audited tree.

Set short shell variables for the commands on this page. Use an explicit
backend so the output path is predictable:

```bash
export TARGET=<target>
export BACKEND=claude               # or codex, gemini, grok, oss
export RESULTS="output/$TARGET/$BACKEND/results"
export LOGS="output/$TARGET/$BACKEND/logs"
```

## 1. Run one iteration

```bash
bin/audit --target "$TARGET" --backend "$BACKEND" 1
```

The `oss` backend has no default model: add `--model <id>` here and on every
later audit command.

The trailing `1` has special smoke-test behavior:

- one worker launches, regardless of the normal pool size;
- the worker claims ranked work and investigates for one iteration;
- result and log directories remain available for the next run.

For a hosted backend, choose a model explicitly with `--model <name>` when
reproducibility matters. Otherwise its default model and reasoning effort come
from `config/models.toml`; per-shell model overrides are listed under
[Model selection](../reference/environment.md#model-selection).

For a focused plumbing test, add `--strategy S1` (or S2–S8). This pins the
strategy and suspends normal rotation for the run.

!!! warning "Do not edit the live session snapshot"
    Preflight copies the reviewed config to `$RESULTS/.target.toml` and binds
    it to `$RESULTS/.session-env`. Every probe in that session reads the pinned
    copy. Edit `output/$TARGET/target.toml` only between runs; never edit or
    remove the backend-local snapshot.

### What success looks like

The startup timeline is written to:

```text
output/<target>/<backend>/logs/index.log
```

It should identify the backend/model, target source and revision, worker pool,
and result/log roots. The result tree should contain at least:

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

Whether `state/hypotheses.jsonl`, `state/runs.jsonl`, or a testcase appears
depends on how far the agents get. Their absence is a reason to inspect
the log, not proof that directory setup failed.

Press Ctrl-C to stop a longer run. The orchestrator terminates the active
backend process tree and leaves structured state for the next invocation.

## 2. Inspect the run

Start with the compact state view:

```bash
bin/state --results-dir "$RESULTS" show-recent --agent 1
```

Then check the generated review pages:

| Path | What it shows |
| --- | --- |
| `$RESULTS/findings/FINDING-CLUSTERS.html` | Concrete security findings, including reports without a reproducer. |
| `$RESULTS/crashes/CRASH-CLUSTERS.html` | Confirmed crash clusters and maintainer bundles. |
| `$RESULTS/crashes-rejected/REJECTED-CRASHES.html` | Rejected crash candidates with reasons. |
| `$RESULTS/findings-rejected/REJECTED-FINDINGS.html` | Rejected findings with reasons. |
| `output/$TARGET/FINDING-CLUSTERS.html` | Cross-backend finding summary. |
| `output/$TARGET/CRASH-CLUSTERS.html` | Cross-backend crash summary. |

An empty `findings/` or `crashes/` after one iteration is normal. A filed FIND
is also not automatically a confirmed security result: read its Status and
`validation.json`. To distinguish
an uneventful iteration from a failed one, inspect in this order:

1. `$LOGS/index.log` for preflight or backend failures.
2. `bin/state --results-dir "$RESULTS" show-recent --agent 1` for claims and
   hypotheses.
3. `$RESULTS/state/runs.jsonl` for recorded probe executions, if the file
   exists.
4. The two rejected pages, for candidates that reached triage but did not meet
   the bar.

Use the trimmed session log named by `index.log` only when the structured views
do not explain the run. Raw backend transcripts under `$LOGS/.raw/` are the
last resort.

## 3. Continue or reset

Run a bounded working session:

```bash
bin/audit --target "$TARGET" --backend "$BACKEND" 10
```

Or run continuously:

```bash
bin/audit --target "$TARGET" --backend "$BACKEND"
```

Multi-iteration and continuous runs use the configured worker pool and normal
strategy rotation.

To inspect cleanup before starting over:

```bash
bin/cleanup_state --target "$TARGET" --backend "$BACKEND" --dry-run
bin/cleanup_logs --target "$TARGET" --backend "$BACKEND" --dry-run
```

Remove `--dry-run` only after checking the printed paths. Cleanup does not
delete source under `targets/`. Omitting `--backend` from `bin/cleanup_state`
selects every backend and aggregate result under that target, so use it only
when you intend a target-wide reset.

## Auditing with UBSan, MSan, or TSan

ASan is the default native sanitizer. To make another sanitizer part of the
target's persistent execution contract:

1. Add it to `[sanitizer].enabled` in `output/<target>/target.toml`.
2. Put it first in the list, because `bin/probe` selects the first enabled
   sanitizer by default.
3. Set the matching `<name>_bin` and, for compiled API harnesses,
   `<name>_lib` when generation cannot infer them.

```toml
[sanitizer]
enabled = ["ubsan", "asan"]
ubsan_bin = "build-ubsan/path/to/binary"
ubsan_lib = "build-ubsan/path/to/library.a"
```

Build up front or let audit preflight refresh stale artifacts:

```bash
bin/setup-target "$TARGET" --build
bin/audit --target "$TARGET" --backend "$BACKEND" 1
```

For one deliberate probe without changing list order:

```bash
PROBE_SANITIZER=ubsan bin/probe "$RESULTS/scratch-1/testcase"
```

The environment override affects that probe only; it does not change the
session snapshot or future runs. See
[Sanitizer policy](../guides/configure-target.md#sanitizer-policy) for
tradeoffs and
[Target config reference](../reference/target-toml.md#sanitizers) for exact
fields. Go's `race` detector uses the configured language runner rather than a
`race_bin` or `race_lib`.

## Where to run the audit

The recommended default is `bin/audit-container-shell`. It isolates target
build scripts and agent tool use from most of the host filesystem while keeping
the checkout and output in the mounted repository.

```bash
bin/audit-container-shell --rebuild   # first use
bin/audit-container-shell             # later uses
```

The helper installs backend CLIs into a Docker image and opens `/root/work`; it
does not start the audit. It does not mount host CLI credential directories.
Authenticate inside the disposable shell, or use `--forward-credentials` when
you explicitly want supported credential variables forwarded.

For Docker installation, gVisor, and the container trust boundary, see
[Container runtime](prerequisites.md#container-runtime-recommended). For all
helper flags, run `bin/audit-container-shell --help`.

## What's next

- [Triage and review](../guides/triage-results.md) explains what is ready for
  maintainer review.
- [Backends and isolation](../guides/backends.md) covers hosted rotation and
  local models.
- [Audit lifecycle](../concepts/audit-lifecycle.md) connects setup, agents,
  probing, triage, and export.
