# Command Reference

Run commands from the repository root. This page documents the public operator
workflow; each command's `--help` output is the source for rarely used flags.

For examples below:

```bash
export TARGET=<target>
export BACKEND=<claude|codex|gemini|grok|oss>
export RESULTS="output/$TARGET/$BACKEND/results"
```

## Set up a target

```bash
bin/setup-target <target> <repo-url>
bin/setup-target <target> <repo-url> --ref <branch-or-revision>
bin/setup-target <target> <repo-url> --repo-type hg
bin/setup-target <target> /path/to/local/source
bin/setup-target <target>
```

`bin/setup-target` creates or updates `targets/<target>/` and generates
`output/<target>/target.toml`. With no source argument it re-inspects an
existing checkout and refreshes unresolved generated fields.

Useful flags:

| Flag | Meaning |
| --- | --- |
| `--build` | For native targets, build now instead of waiting for audit preflight. The command fails if the requested build cannot be materialized. For supported language targets, explicitly run the ecosystem build step (audit preflight does not run it automatically). |
| `--browser` / `--no-browser` | Select browser execution mode explicitly. A browser-specific driver such as `mach` is inferred when neither flag is present; shared build systems such as GN require an explicit choice. |
| `--pull` | Update an existing VCS checkout to the latest upstream source without re-passing its repo URL. Tracked local edits leave the checkout untouched; untracked build trees, `.audit/` overlays, and run leftovers do not block the update. |
| `--no-update` | Do not pull or fetch an existing VCS checkout. |
| `--force` | Without `--build`, regenerate generated config, including suggested threat-model and peer sections. With `--build`, preserve reviewed config and recipes but rematerialize their build output from a clean tree. |
| `--no-llm-config` | Skip best-effort model suggestions for the threat model and S6 peers. |

The suggestion steps can also be rerun independently:

```bash
bin/suggest-threat-model "$TARGET" --apply --force   # re-derive attacker_controls
bin/suggest-peers "$TARGET" --apply --force          # re-derive [s6_peers]
bin/suggest-runner "$TARGET" --apply --force         # pick a CLI and its testcase argv
```

All three take a target slug and print the suggestion; `--apply` writes it into
`output/<target>/target.toml` and `--force` overwrites an existing section.
They ask the model once, except that `bin/suggest-runner` permits one revision
after launch validation rejects a proposal. It reads the `--help` output of a
bounded set of instrumented CLIs the build declares, picks the one that parses
input files, and proposes the matching `[runner]` invocation. When that is not
the binary detection guessed, it retargets `<san>_bin` too — a build tree holds
a project's tools next to its test drivers, and only the launch it validates
proves which is which. Matching instrumented programs in other enabled
sanitizer builds are retargeted at the same time so the shared runner arguments
keep their meaning; if a configured sibling build has no such program, the
helper refuses the update instead of applying arguments to a different CLI.
Nothing is written until the proposed invocation passes input-dependence
validation with a disposable testcase.

See [Add a target](../getting-started/add-a-target.md) for the workflow and
[Target config](target-toml.md) for field definitions.

### Prepare alternate build configurations

```bash
bin/build-configs --target "$TARGET" --all --backend "$BACKEND"
bin/build-configs --target "$TARGET" --config compact
```

Setup and audit preflight run this for you. Use it directly to inspect or retry
one configuration. Alternate builds are cached ASan siblings — a failure never
costs you the canonical `build-asan` control.

Preflight gives alternates ten minutes and then starts the audit on the primary
build, so a large target may need `bin/build-configs` run by hand up front. The
`--backend` is used only for a model-guided `widen = true` row; configurations
that declare their own `flags` do not need a model at all. After fixing a
transient toolchain problem, retry with `--force` to bypass the cached failure.

## Run an audit

```bash
bin/audit --target "$TARGET" --backend "$BACKEND" 1
bin/audit --target "$TARGET" --backend "$BACKEND" 10
bin/audit --target "$TARGET" --backend "$BACKEND"
```

The optional final number is the iteration limit. `1` is a smoke test with one
worker. Omit the number, or pass `0`, for a continuous run.

Common flags:

| Flag | Meaning |
| --- | --- |
| `--model <name>` | Override the backend's configured model. Required for `oss`. |
| `--strategy S1|S2|S3|S5|S6|S7|S8` | Pin one investigation strategy and suspend rotation. S4 is reserved. |
| `--no-refill-workers` | Leave a slot idle once its agent finishes, instead of relaunching it while a peer's initial session is still running. |
| `--enable-memory` | Allow the backend's cross-run learned memory. It is disabled by default to prevent stale conclusions from steering later audits. |
| `--agent-security sandboxed|external-bypass` | Select the agent execution boundary. `sandboxed` is the default and refuses backends whose sandbox cannot host an audit; the bypass mode requires an asserted outer sandbox. |
| `--new-target <slug>` | Generate starter config and exit without starting an audit. |

One audit at a time owns a result tree: a second run on the same target and
backend exits with `another bin/audit instance is writing to …`. A lock left by
a killed run is reclaimed automatically — there is nothing to clean up.

Omitting `--backend`, or using `--backend all`, cycles installed hosted
backends in `claude → codex → gemini → grok` order, skipping any the selected
`--agent-security` mode cannot launch. Each writes its own result tree. Use
an explicit backend and model in reproducibility notes.

Turning off learned memory does not make an agent forgetful: the audit contract
and the run's own structured state still apply. It only stops conclusions from
one target's run leaking into the next. Benchmarks always keep it off.

### Container shell

```bash
bin/audit-container-shell --rebuild       # first use or image refresh
bin/audit-container-shell                 # reuse the existing image
bin/audit-container-shell --gvisor        # use runsc on a configured Linux host
bin/audit-container-shell --forward-credentials
```

The helper opens an interactive Docker shell with supported backend CLIs and
the repository mounted at `/root/work`. It does not start an audit. Credential
directories are not mounted; log in inside the disposable container or
explicitly forward supported credential variables.

## Run a testcase

```bash
bin/probe "$RESULTS/scratch-1/testcase.html"
bin/probe --confirm "$RESULTS/scratch-1/testcase.html"
bin/probe --dry-run "$RESULTS/scratch-1/testcase.dat"
```

`bin/probe` is the execution gate for agent-authored testcases. It walks up
from the testcase to `.session-env`, loads `target.toml`, selects the browser,
JS, generic, harness, or language runner, writes diagnostic output beside the
testcase, and records the verdict in `state/runs.jsonl`.

- Use the ordinary command for exploration.
- Use `--confirm` after a first diagnostic: it re-runs the testcase five times
  and can file a stable crash bundle.
- Use `--dry-run` to inspect mode, sanitizer, output path, and resolved command
  without executing target code.
- Use `--mode browser|js|generic` only when automatic mode detection is wrong.
- Compiled C/C++ harnesses that set `LD_PRELOAD` or
  `DYLD_INSERT_LIBRARIES` and then launch a process are refused before
  compilation. Injected process state is not a testcase-derived public
  boundary; ordinary linked API and file/protocol launcher harnesses remain
  supported.
- A confirmed crash is filed only when the diagnostic came from the binary
  `bin/probe` built. If the sanitizer names a module under the agent's scratch
  tree that probe did not compile, or gives an absolute path for the crashing
  process's `main` in a scratch source that is not the harness, the crash
  describes a separately built binary and no bundle could ship it, so it is
  not filed. Bare source names are not guessed. Harnesses that drive the
  target's own executable are unaffected.

Run `bin/probe --help` for the rest.

When a target has alternate ASan builds, most of the audit stays on the regular
build and a minority slot explores the alternates. A crash confirmed on an
alternate is automatically re-confirmed against the regular build, and the
report records both results — a bug in a supported optional feature is still a
bug, it just carries the build it needs. Use `PROBE_BUILD_CONFIG=<name>` (or
`primary`) for a deliberate one-off comparison.

Every testcase begins with native-comment headers:

```text
TARGET: path/to/file.c:Function:123
HYPOTHESIS-ID: H1
CATEGORY: bounds
MODE: generic          # optional: auto|browser|js|generic
HARNESS: harness.c     # optional sibling API harness
```

The valid categories are `bounds`, `lifetime`, `type`, `size`, `uninit`, and
`state`. See [Reproduce a crash](../guides/reproduce-a-crash.md) for the
maintainer-side bundle flow.

### Testcase helpers

```bash
TARGET_ROOT="targets/$TARGET" RESULTS_DIR="$RESULTS" \
  bin/find-seed <file>[:<Function>]
bin/scratch-status "$RESULTS/scratch-1"
RESULTS_DIR="$RESULTS" bin/scratch-search <pattern>
bin/probe-history --results-dir "$RESULTS" --hypothesis-id H1
```

| Command | Purpose |
| --- | --- |
| `bin/find-seed` | Find nearby tests, samples, and corpus inputs before writing a format from scratch. |
| `bin/scratch-status` | Show testcase/output pairs and unrun testcases in one scratch directory. |
| `bin/scratch-search` | Search prior scratch, corpus, and crash artifacts without scanning raw logs. |
| `bin/probe-history` | Read prior verdicts from structured run state. |

Coverage diagnostics for supported browser and JS builds:

```bash
bin/hits --testcase "$RESULTS/scratch-1/testcase.js" \
  --want <symbol-regex> --mode js
bin/coverage-summary --results-dir "$RESULTS"
```

## Inspect a running audit

Use structured state instead of raw transcripts:

```bash
bin/state --results-dir "$RESULTS" show-recent --agent 1
bin/state --results-dir "$RESULTS" resume --agent 1
bin/state --results-dir "$RESULTS" list-cards
bin/state --results-dir "$RESULTS" list-crashes
bin/state --results-dir "$RESULTS" list-findings
bin/state --results-dir "$RESULTS" explain-queue
```

`show-recent` is the best general checkpoint: it combines recent claims,
hypotheses, and probe runs for one worker. The `list-*` commands emit compact
JSONL suitable for scripts. Use `show-card`, `show-crash`, or `show-finding`
with an ID for one full compact record. Run `bin/state --help` and
`bin/state <subcommand> --help` for filters and state-mutating commands used by
agents.

An agent cannot retire a piece of work on an opinion: closing a card as
uninteresting requires probe runs on disk that actually executed the code and
came back clean. That is why `list-cards` can show cards still open after an
agent has looked at them.

## Review results

Open the generated HTML before reading logs:

```text
output/<target>/FINDING-CLUSTERS.html
output/<target>/CRASH-CLUSTERS.html
output/<target>/<backend>/results/findings/FINDING-CLUSTERS.html
output/<target>/<backend>/results/crashes/CRASH-CLUSTERS.html
output/<target>/<backend>/results/crashes-rejected/REJECTED-CRASHES.html
```

Target-level pages combine all backends. Backend-level pages show one result
tree. Follow a cluster to `report.html` or `REPORT.html`; edit only the Markdown
source.

Normal triage performs export, severity, validation, and clustering
automatically. These commands are for deliberate regeneration after a manual
edit:

```bash
bin/export-repro CRASH-001-1 --slug "$TARGET"
bin/severity --report "$RESULTS/crashes/CRASH-001-1"
bin/severity --batch "$RESULTS"
bin/cluster-crashes "$RESULTS"
bin/cluster-findings "$RESULTS"
bin/show-exclusions "$RESULTS"
```

`export-repro` normally gets the audited checkout and revision from the
session. Maintenance code rebuilding an older pool passes both explicitly:

```bash
bin/export-repro CRASH-001-1 --slug "$TARGET" \
  --target-root /path/to/audited-checkout --target-rev <commit>
```

Use the pair together for detached artifacts. It prevents an unrelated live
session for the same slug from supplying either the revision or build recipe.

`bin/severity --batch` scores accepted crashes and findings together in one
offline process.

See [Triage results](../guides/triage-results.md) before overriding or
regenerating an artifact.

## Maintain TokenFuzz and local output

```bash
bash tests/run-tests.sh
bin/docs build
bin/docs serve

bin/cleanup_state --target "$TARGET" --dry-run
bin/cleanup_logs --target "$TARGET" --backend "$BACKEND" --dry-run
```

Remove `--dry-run` only after reviewing the paths. Both cleanup commands can
sweep multiple targets, so prefer explicit `--target` and `--backend` values.

`bin/benchmark` evaluates TokenFuzz itself against a direct-prompt baseline; it
is not part of routine target auditing:

```bash
bin/benchmark --target "$TARGET" --backend "$BACKEND"
bin/benchmark --target "$TARGET" --backend "$BACKEND" --agent-security sandboxed
bin/export-benchmark --target "$TARGET" --backend "$BACKEND" --format zip
```

See [Benchmarking](../concepts/benchmark.md) for experiment design, resumption,
and regeneration.

## Everything else in `bin/`

The rest of `bin/` is orchestration the audit runs for you: ranking, card
building, sanitizer runners, report enrichment, validation, and rendering. They
are not an operator workflow and their interfaces are not stable. If you need
one for development or diagnosis, read the command source and its tests first.
