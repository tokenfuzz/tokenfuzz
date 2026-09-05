# Command Reference

Run commands from the repository root. This page documents the public operator
workflow; each command's `--help` output is the source for rarely used flags.

| Task | Start with |
| --- | --- |
| Add or refresh a target | `bin/setup-target` |
| Run or resume an audit | `bin/audit` |
| Execute one testcase | `bin/probe` |
| Inspect structured progress | `bin/state` |
| Review results | Generated cluster HTML |
| Rebuild derived reports | `bin/export-repro`, `bin/severity`, and the cluster commands |
| Test TokenFuzz itself | `bash tests/run-tests.sh` and `bin/docs build` |

For the examples below:

```bash
export TARGET=<target>
export BACKEND=claude               # or codex, gemini, grok, oss
export RESULTS="output/$TARGET/$BACKEND/results"
```

The `oss` backend has no default model. When `BACKEND=oss`, add `--model <id>`
to every command below that launches one.

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
| `--build` | Build now instead of waiting for audit preflight; fails if the requested build cannot be produced. Language targets run their ecosystem bootstrap here, and preflight repeats it later only for a target with a `.audit/build.sh` recipe or an already-stamped build that went stale. |
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

All three take a target slug and print the suggestion; `--apply` writes it
into `output/<target>/target.toml` and `--force` overwrites an existing
section. They ask the model once, except that `bin/suggest-runner` permits one
revision after launch validation rejects a proposal.

`bin/suggest-runner` reads the `--help` output of a bounded set of
instrumented CLIs the build declares, picks the one that parses input files,
and proposes the matching `[runner]` invocation. When that is not the binary
detection guessed, it retargets `<san>_bin` too: a build tree holds a
project's tools next to its test drivers, and only the launch it validates
proves which is which. Matching instrumented programs in other enabled
sanitizer builds are retargeted at the same time so the shared runner
arguments keep their meaning; if a configured sibling build has no such
program, the helper refuses the update instead of applying arguments to a
different CLI. Nothing is written until the proposed invocation passes
input-dependence validation with a disposable testcase. That same validation
records `[runner].success_codes`: a zero exit is accepted deterministically,
while a nonzero exit is added only when the bounded review confirms the
program opened and rejected the disposable input rather than failing in
argument parsing or startup. `bin/setup-target` also calibrates an older
`[runner].args` block once when it has no explicit `success_codes`; it keeps
the existing argv and does not ask the model to choose it again.

See [Add a target](../getting-started/add-a-target.md) for the workflow and
the [target config reference](target-toml.md) for field definitions.

### Prepare alternate build configurations

```bash
bin/build-configs --target "$TARGET" --all --backend "$BACKEND"
bin/build-configs --target "$TARGET" --config compact
```

Setup and audit preflight run this for you. Use it directly to inspect or
retry one configuration. Alternate builds are cached ASan siblings; a failure
never costs you the canonical `build-asan` control.

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
| `--since <rev>` | Delta mode: audit only what changed in `<rev>..HEAD`, meaning the changed files, their one-hop callers from the call-neighbourhood graph, and S1 cards for exactly those commits. The results tree records both ends of the delta, so a resumed run must keep the same `HEAD` and pass the same `--since` (or use `--experiment` for a separate tree). An unresolvable revision or a tracked working-tree change stops the run rather than widening or measuring code outside that range; an empty or exhausted range exits without a whole-tree discovery slot. |
| `--experiment <name>` | Write results and logs under `output/<target>-<name>/<backend>/` instead of the target's normal tree. The benchmark uses this for its cells; use it yourself to keep a trial run's state apart from the main audit. |
| `--target-path <dir>` | Audit a source tree at that path instead of `targets/<target>/`. The output tree is then named after the directory's basename (`output/<basename>/`), not after `--target`. |
| `--no-refill-workers` | Leave a slot idle once its agent finishes, instead of relaunching it while a peer is still running. This also switches the run to the older cohort scheduler. |
| `--enable-memory` | Allow the backend's cross-run learned memory. It is disabled by default to prevent stale conclusions from steering later audits, except on Antigravity (`agy`), which has no memory switch; see [the isolation policy](../guides/backends.md#one-isolation-policy-for-every-launch). |
| `--agent-security sandboxed|external-bypass` | Select the agent execution boundary. Each backend defaults to the strongest mode it can run under; see [Agent security modes](../guides/backends.md#agent-security-modes). |
| `--new-target <slug>` | Generate starter config and exit without starting an audit. |
| `--allow-concurrent` | Skip the one-instance lock below. Two runs then append to one state tree; use it only when you know why you want that. |
| `--claude-bin`, `--codex-bin`, `--gemini-bin`, `--grok-bin` | Point at a backend executable outside `PATH` for this run. The `*_BIN` environment variables do the same for a shell. |

One audit at a time owns a result tree: a second run on the same target and
backend exits with `another bin/audit instance is writing to …`. A lock left
by a killed run is reclaimed automatically; there is nothing to clean up. To
run several backends at once, give each its own `--backend`; they already
write separate trees.

Omitting `--backend`, or using `--backend all`, cycles installed hosted
backends in `claude → codex → gemini → grok` order, skipping any the selected
`--agent-security` mode cannot launch. Each writes its own result tree. Use an
explicit backend and model in reproducibility notes.

Turning off learned memory does not make an agent forgetful: the audit
contract and the run's own structured state still apply. It only stops
conclusions from one target's run leaking into the next. Benchmarks always
keep it off.

### Container shell

```bash
bin/audit-container-shell --rebuild       # first use or image refresh
bin/audit-container-shell                 # reuse the existing image
bin/audit-container-shell --gvisor        # use runsc on a configured Linux host
bin/audit-container-shell --forward-credentials
```

The helper opens an interactive Docker shell with the supported backend CLIs
and the repository mounted at `/root/work`. It does not start an audit.
Credential directories are not mounted; log in inside the disposable container
or explicitly forward supported credential variables.

## Run a testcase

```bash
bin/probe "$RESULTS/scratch-1/testcase.html"
bin/probe --confirm "$RESULTS/scratch-1/testcase.html"
bin/probe --dry-run "$RESULTS/scratch-1/testcase.dat"
```

`bin/probe` is the execution gate for agent-authored testcases. It walks up
from the testcase to `.session-env`, loads the pinned `target.toml`, selects
the browser, JS, generic, harness, or language runner, writes diagnostic
output beside the testcase, and records the verdict in `state/runs.jsonl`.

- Use the ordinary command for exploration.
- Use `--confirm` after a first diagnostic: it re-runs the testcase five times
  and can file a stable crash bundle. `--sanitizer-runs N` sets an explicit
  count instead.
- Use `--dry-run` to inspect the mode, sanitizer, output path, and resolved
  command without executing target code.
- Use `--mode browser|js|generic` only when automatic mode detection is wrong.
- Use `--hypothesis-id H-…` for an opaque binary input that cannot carry a
  comment header. An opaque S8 input also needs `--property <kind>`, and a
  fuzz artifact replayed against the harness that produced it needs
  `--harness <name>`. Use `--want <symbol-regex>` to name the code a
  coverage-gated browser or JS probe must reach.
- Arguments after `--` go to the harness.
- Compiled C/C++ harnesses that set `LD_PRELOAD` or `DYLD_INSERT_LIBRARIES`
  and then launch a process are refused before compilation. Injected process
  state is not a testcase-derived public boundary; ordinary linked API and
  file/protocol launcher harnesses remain supported.
- A confirmed crash is filed only when the diagnostic came from the binary
  `bin/probe` built. If the sanitizer names a module under the agent's scratch
  tree that probe did not compile, or gives an absolute path for the crashing
  process's `main` in a scratch source that is not the harness, the crash
  describes a separately built binary that no bundle could ship, so it is not
  filed. Bare source names are not guessed. Harnesses that drive the target's
  own executable are unaffected.

Run `bin/probe --help` for the rest.

When a target has alternate ASan builds, most of the audit stays on the regular
build and a minority slot explores the alternates. A crash confirmed on an
alternate is automatically re-confirmed against the regular build, and the
report records both results: a bug in a supported optional feature is still a
bug, it just carries the build it needs. Use `PROBE_BUILD_CONFIG=<name>` (or
`primary`) for a deliberate one-off comparison.

Every testcase begins with native-comment headers (`//`, `#`, `<!-- … -->`,
whatever the file's own language uses):

```text
TARGET: path/to/file.c:Function:123
HYPOTHESIS-ID: H-…
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
bin/probe-history --results-dir "$RESULTS" --hypothesis-id H-…
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
not come from one: a sandboxed backend that drove the instrumented binary
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
| `bin/fuzz template` | Write a dual-entry harness skeleton for one admitted symbol, with at most two target-local caller locations and a source-grounding receipt. |
| `bin/fuzz build` | Compile a harness out of tree; refuses in-tree sources and unfaithful harnesses. |
| `bin/fuzz run` | Spend a budget across harnesses, quarantine those that stop paying, and replay artifacts through `bin/probe`. |
| `bin/fuzz status` | Join the current build/grounding receipt with first-slice and campaign state; report what to resolve or try next. `--json` includes `build`, `receipt`, `receipt_warnings`, `first_slice`, `coverage`, `compatible_apis`, and `next` per harness. |
| `bin/fuzz doctor` | Report the linked build, coverage feedback, lease state, and isolation. |

All subcommands accept `--results-dir` in place of the `RESULTS_DIR` variable.
See [Boundary-directed fuzzing](../guides/directed-fuzzing.md) for the
workflow and the build-isolation rules.

`bin/hits` provides coverage diagnostics for browser, JS, and generic CLI
builds. `--mode generic` replays a native testcase in an instrumented ASan
sibling (`build-asan+fuzz`, produced by `bin/setup-target --build` or audit
preflight from the target's own recipe, or a compatible hand-built
`build-asan+cov`) and reports the source files it reached. The configured ASan
CLI is replayed from the sibling directly. A `// HARNESS:` route instead uses
a coverage twin of that harness, linked against the sibling's `asan_lib`.

The coverage route must describe the same program and source generation as the
primary ASan route. Otherwise `bin/hits` reports `COVERAGE_UNAVAILABLE` and the
sanitizer run proceeds. Interpreter and wrapper routes behave the same way
because they have no route-equivalent native sibling. In generic mode,
coverage is feedback: even a `MISSED` continues to the sanitizer run. Browser
and JavaScript routes can use it as a hard pre-run gate.

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
bin/state --results-dir "$RESULTS" card-yield
bin/state --results-dir "$RESULTS" strategy-yield
```

`show-recent` is the best general checkpoint: it combines recent claims,
hypotheses, and probe runs for one worker, each run with its `coverage`
outcome and `closest` frame. The `recent-hyps`, `recent-runs`,
`recent-notes`, `recent-claims`, and `recent-tried` subcommands print one
ledger each with filters. `card-yield` replays the queue: claims, probed
cards, runs, and diagnostics per rank bucket, and the share of the queue that
was ever touched, so a ranking change is judged by conversion rather than
taste. `strategy-yield` reports per-strategy runs, seconds, and diagnostics.
The `list-*` commands emit compact JSONL suitable for scripts. Use
`show-card`, `show-crash`, or `show-finding` with an id for one full compact
record. Run `bin/state --help` and `bin/state <subcommand> --help` for filters
and the state-mutating commands agents use.

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
tree. The two rejected indexes are per-backend only; there is no
cross-backend rollup of rejections. Follow a cluster to `report.html` or
`REPORT.html`, and edit only the Markdown source.

Normal triage performs export, severity, validation, and clustering
automatically. These commands are for deliberate regeneration after a manual
edit:

```bash
TOKENFUZZ_ROOT=$PWD
(cd "$RESULTS" && "$TOKENFUZZ_ROOT/bin/export-repro" CRASH-001-1)
bin/severity --report "$RESULTS/crashes/CRASH-001-1"
bin/severity --batch "$RESULTS"
bin/cluster-crashes "$RESULTS"
bin/cluster-findings "$RESULTS"
bin/show-exclusions "$RESULTS"
```

`export-repro` reads the nearest `.session-env` above its working directory,
so run it from inside the result tree; `--slug` alone picks the first backend
alphabetically, which may not be the one you mean. For a detached artifact,
name the crash, checkout, and revision explicitly:

```bash
bin/export-repro CRASH-001-1 --slug "$TARGET" \
  --crash-dir "$RESULTS/crashes/CRASH-001-1" \
  --target-root /path/to/audited-checkout --target-rev <commit>
```

`bin/severity --batch` scores reportable crashes and findings together in one
offline process; `not-reportable` artifacts remain unscored.

See [Triage and review](../guides/triage-results.md) before overriding or
regenerating an artifact.

## Maintain TokenFuzz and local output

```bash
bash tests/run-tests.sh
bash tests/run-tests.sh --image ubuntu:24.04   # the CI container lane
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
bin/benchmark score "$RESULTS" --ground-truth "output/$TARGET/.ground-truth.json"
```

`bin/benchmark score` runs the answer-key scorer over an existing results or
pool tree and launches nothing; it needs a `.ground-truth.json` manifest, which
every shipped sample target has.

See [Benchmarking](../concepts/benchmark.md) for experiment design,
resumption, and regeneration.

## Everything else in `bin/`

The rest of `bin/` is machinery the audit drives for you. It is listed here so
you can find the right file when diagnosing a run or changing the harness,
**not** as an operator workflow. These interfaces are not stable; read the
command's source and its tests before depending on one.

| Command | What it does |
| --- | --- |
| `bin/rank-work` | Builds the ranked work-card queue for an iteration; `--since <rev>` restricts it to the delta's files and callers. |
| `bin/patch-cards` | Derives S1 prior-fix cards from the target's own history; `--since <rev>` emits one per commit in the range. |
| `bin/peer-fix-cards` | Derives S6 cards from the projects in `[s6_peers]`. Fetching patch excerpts is bounded to 120 s per refresh; a card whose excerpt did not arrive in time stays a discovery lead. |
| `bin/callgraph` | Extracts the optional per-file call neighbourhood a card prompt quotes; `--probe` reports whether the analysis can run here. |
| `bin/auto-build-script` | Converges a sanitizer build recipe into `.audit/build*.sh`. |
| `bin/auto-repair-target-toml` | Proposes an additive `target.toml` repair after repeated harness build failures. |
| `bin/run-asan`, `bin/run-ubsan`, `bin/run-msan`, `bin/run-tsan` | Per-sanitizer execution wrappers. `bin/probe` selects and invokes these. |
| `bin/run-sanitizer-multi` | Repeats a sanitizer runner and reduces the results to one verdict; the `--confirm` path. |
| `bin/triage-fuzz-crashes` | Summarises non-noise libFuzzer artifacts from an S4 campaign. |
| `bin/validate-finding` | Runs one independent source-reading review over a single FIND. |
| `bin/enrich-report` | Inlines source snippets and writes the `## Patch` section. The only writer of that section. |
| `bin/severity-sweep` | Re-scores the cluster representatives of a results pool. |
| `bin/render-md` | Generates the `.html` sibling of a report or cluster table. |
| `bin/find-crash-testcase` | Resolves the testcase path for a `CRASH-*` directory. |
| `bin/peek`, `bin/rg-safe`, `bin/show-patch` | Bounded source read, search, and diff wrappers: the caps that keep agent prompts small. |
