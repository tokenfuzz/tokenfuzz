# Command Reference

Run commands from the repository root. This page documents the public operator
workflow; each command's `--help` output is the source for rarely used flags.

For examples below:

```bash
export TARGET=<target>
export BACKEND=claude               # or codex, gemini, grok, oss
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
| `--no-alternates` | Build only the canonical sanitizer trees, skipping the cached alternate ASan configurations described below. |
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
| `--strategy S1|S2|S3|S4|S5|S6|S7|S8` | Pin one investigation strategy and suspend rotation. |
| `--since <rev>` | Delta mode: audit only what changed in `<rev>..HEAD` — the changed files, their one-hop callers from the call-neighbourhood graph, and S1 cards for exactly those commits. The results tree records both ends of the delta, so a resumed run must keep the same `HEAD` and pass the same `--since` (or use `--experiment` for a separate tree). An unresolvable revision or tracked working-tree change stops the run rather than widening or measuring code outside that range; an empty or exhausted range exits without a whole-tree discovery slot. |
| `--no-refill-workers` | Leave a slot idle once its agent finishes, instead of relaunching it while a peer is still running. |
| `--enable-memory` | Allow the backend's cross-run learned memory. It is disabled by default to prevent stale conclusions from steering later audits. |
| `--agent-security sandboxed|external-bypass` | Select the agent execution boundary. Each backend defaults to the strongest mode it can run under; see [Agent security modes](../guides/backends.md#agent-security-modes). |
| `--new-target <slug>` | Generate starter config and exit without starting an audit. |
| `--allow-concurrent` | Skip the one-instance lock below. Two runs then append to one state tree; use it only when you know why you want that. |

One audit at a time owns a result tree: a second run on the same target and
backend exits with `another bin/audit instance is writing to …`. A lock left by
a killed run is reclaimed automatically — there is nothing to clean up. To run
several backends at once, give each its own `--backend`; they already write
separate trees.

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
  and can file a stable crash bundle. `--sanitizer-runs N` sets an explicit
  count instead.
- Use `--dry-run` to inspect mode, sanitizer, output path, and resolved command
  without executing target code.
- Use `--mode browser|js|generic` only when automatic mode detection is wrong.
- Use `--hypothesis-id H1` for an opaque binary input that cannot carry a
  comment header. An opaque S8 input also uses `--property <kind>`. Use
  `--want <symbol-regex>` to name the code a coverage-gated browser or JS probe
  must reach.
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

Every testcase begins with native-comment headers — `//`, `#`, `<!-- … -->`,
whatever the file's own language uses:

```text
TARGET: path/to/file.c:Function:123
HYPOTHESIS-ID: H1
CATEGORY: bounds
MODE: generic          # optional: auto|browser|js|generic
HARNESS: harness.c     # optional sibling API harness
CARD-ID: <id>          # optional: the work card this came from
PROPERTY: inverse      # required under S8; the oracle kind
```

The valid categories are `bounds`, `lifetime`, `type`, `size`, `uninit`, and
`state`. The valid properties are `inverse`, `idempotence`, `injectivity`,
`domain`, `format`, and `equivalence`. An opaque byte input that cannot carry a
comment supplies the same values as flags instead. See
[Reproduce a crash](../guides/reproduce-a-crash.md) for the maintainer-side
bundle flow.

### Testcase helpers

```bash
TARGET_ROOT="targets/$TARGET" RESULTS_DIR="$RESULTS" \
  bin/find-seed <file>[:<Function>]
bin/scratch-status "$RESULTS/scratch-1"
RESULTS_DIR="$RESULTS" bin/scratch-search <pattern>
bin/probe-history --results-dir "$RESULTS" --hypothesis-id H1
bin/symbolize "$RESULTS/crashes/CRASH-001/sanitizer.txt"
```

| Command | Purpose |
| --- | --- |
| `bin/find-seed` | Find nearby tests, samples, and corpus inputs before writing a format from scratch. |
| `bin/scratch-status` | Show testcase/output pairs and unrun testcases in one scratch directory. |
| `bin/scratch-search` | Search prior scratch, corpus, and crash artifacts without scanning raw logs. |
| `bin/probe-history` | Read prior verdicts from structured run state. |
| `bin/symbolize` | Resolve `module+offset` frames in a report produced outside the runners. |

The runners symbolize what they run. `bin/symbolize` is for a report that did
not come from one — a sandboxed backend that drove the instrumented binary
itself, where the sanitizer runtime is denied the process spawn its own
symbolizer needs. It exits non-zero, and says why, when a frame stays raw.

### Boundary-directed fuzzing (S4)

```bash
bin/fuzz inventory                    # harnesses the target already has
bin/fuzz candidates                   # APIs that earn one, ranked
bin/fuzz template <symbol>            # skeleton under $RESULTS/fuzz/src/
bin/fuzz build                        # compile out of tree
bin/fuzz run --budget-seconds 300     # bounded campaign
bin/fuzz status
bin/fuzz doctor                       # prove the shared build is unaffected
```

| Command | Purpose |
| --- | --- |
| `bin/fuzz inventory` | List existing fuzz harnesses (libFuzzer, cargo-fuzz, Go, Atheris, Jazzer), what each drives, and its structural gaps. |
| `bin/fuzz candidates` | Run every exported symbol through the admission gate; report the reason each rejection failed. |
| `bin/fuzz template` | Write a dual-entry harness skeleton for one admitted symbol. |
| `bin/fuzz build` | Compile a harness out of tree; refuses in-tree sources and unfaithful harnesses. |
| `bin/fuzz run` | Spend a budget across harnesses, quarantine those that stop paying, replay artifacts through `bin/probe`. |
| `bin/fuzz status` | What each harness did and why it stopped. |
| `bin/fuzz doctor` | Report the linked build, coverage feedback, lease state, and isolation. |

See [Boundary-directed fuzzing](../guides/directed-fuzzing.md) for the workflow
and the build-isolation rules.

Coverage diagnostics for browser, JS, and generic CLI builds. `--mode generic`
replays a native testcase against the configured ASan CLI in an instrumented sibling
tree (`build-asan+fuzz` or `build-asan+cov`) and reports the source files it
reached. The sibling is used only when the sanitizer selected that configured
CLI route; API harnesses and alternate runners have no route-equivalent sibling,
so they print `COVERAGE_UNAVAILABLE` and proceed ungated instead of gating on
the wrong program. A missing sibling behaves the same way.

```bash
bin/hits --testcase "$RESULTS/scratch-1/testcase.js" \
  --want <symbol-regex> --mode js
bin/hits --testcase "$RESULTS/scratch-1/input.dat" \
  --want <symbol-regex> --mode generic
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

An agent cannot conclude a piece of work on an opinion: marking a card
uninteresting requires probe runs on disk that actually executed the code and
came back clean. That retires a concrete patch/site card. A broad whole-file
card instead records the dry pass and yields to fresher work; it may be
reoffered with its history because finite probes cannot prove its unexamined
functions exhausted. That is why `list-cards` can show cards still open after
an agent has looked at them.

## Review results

Open the generated HTML before reading logs:

```text
output/<target>/FINDING-CLUSTERS.html
output/<target>/CRASH-CLUSTERS.html
output/<target>/<backend>/results/findings/FINDING-CLUSTERS.html
output/<target>/<backend>/results/crashes/CRASH-CLUSTERS.html
output/<target>/<backend>/results/crashes-rejected/REJECTED-CRASHES.html
output/<target>/<backend>/results/findings-rejected/REJECTED-FINDINGS.html
```

Target-level pages combine all backends; backend-level pages show one result
tree. The two rejected indexes are per-backend only — there is no cross-backend
rollup of rejections. Follow a cluster to `report.html` or `REPORT.html`, and
edit only the Markdown source.

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

`bin/severity --batch` scores reportable crashes and findings together in one
offline process; `not-reportable` artifacts remain unscored.

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

The rest of `bin/` is machinery the audit drives for you. It is listed here so
you can find the right file when diagnosing a run or changing the harness —
**not** as an operator workflow. These interfaces are not stable; read the
command's source and its tests before depending on one.

| Command | What it does |
| --- | --- |
| `bin/rank-work` | Builds the ranked work-card queue for an iteration; `--since <rev>` restricts it to the delta's files and callers. |
| `bin/patch-cards` | Derives S1 prior-fix cards from the target's own history; `--since <rev>` emits one per commit in the range. |
| `bin/peer-fix-cards` | Derives S6 cards from the projects in `[s6_peers]`. |
| `bin/callgraph` | Extracts the optional per-file call neighbourhood a card prompt quotes. |
| `bin/auto-build-script` | Converges a sanitizer build recipe into `.audit/build*.sh`. |
| `bin/auto-repair-target-toml` | Proposes an additive `target.toml` repair after repeated harness build failures. |
| `bin/run-asan`, `bin/run-ubsan`, `bin/run-msan`, `bin/run-tsan` | Per-sanitizer execution wrappers. `bin/probe` selects and invokes these. |
| `bin/run-sanitizer-multi` | Repeats a sanitizer runner and reduces the results to one verdict — the `--confirm` path. |
| `bin/triage-fuzz-crashes` | Summarises non-noise libFuzzer artifacts from an S4 campaign. |
| `bin/validate-finding` | Runs one independent source-reading review over a single FIND. |
| `bin/enrich-report` | Inlines source snippets and writes the `## Patch` section. The only writer of that section. |
| `bin/severity-sweep` | Re-scores the cluster representatives of a results pool. |
| `bin/render-md` | Generates the `.html` sibling of a report or cluster table. |
| `bin/find-crash-testcase` | Resolves the testcase path for a `CRASH-*` directory. |
| `bin/peek`, `bin/rg-safe`, `bin/show-patch` | Bounded source read, search, and diff wrappers — the caps that keep agent prompts small. |
