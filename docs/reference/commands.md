# Command reference

Every executable in `bin/`, grouped by task. Run commands from the repository
root. Replace `<placeholders>`; square brackets mark optional arguments.
Most commands print their options and defaults under `--help`.

| Task | Command | Section |
| --- | --- | --- |
| Add or refresh a target | `bin/setup-target` | [Set up a target](#set-up-a-target) |
| Run or resume an audit | `bin/audit` | [Run an audit](#run-an-audit) |
| Inspect progress | `bin/state`, `bin/sweep` | [Inspect a running audit](#inspect-a-running-audit) |
| Review and regenerate results | cluster HTML, `bin/cluster-*`, `bin/severity`, `bin/export-repro` | [Review results](#review-results) |
| Replay one testcase | `bin/probe`, `bin/hits` | [Run a testcase](#run-a-testcase) |
| Measure TokenFuzz itself | `bin/benchmark`, `bin/export-benchmark` | [Benchmark TokenFuzz](#benchmark-tokenfuzz) |
| Test, build docs, clean up | `tests/run-tests.sh`, `bin/docs`, `bin/cleanup_*` | [Maintain TokenFuzz and local output](#maintain-tokenfuzz-and-local-output) |
| Tools agents call in a session | `bin/peek`, `bin/rg-safe`, `bin/fuzz`, … | [Agent tools](#agent-tools) |
| Pipeline stages the audit runs | `bin/rank-work`, `bin/run-asan`, … | [Harness internals](#harness-internals) |

The examples use these variables:

```bash
export TARGET="<target>"            # a slug under targets/, e.g. samples/sample-c
export BACKEND=claude               # or codex, gemini, grok, oss
export RESULTS="output/$TARGET/$BACKEND/results"
```

The `oss` backend has no default model. Pass `--model <id>` to `bin/audit`,
`bin/benchmark`, and `bin/sweep`. Setup and the configuration helpers have
no `--model` flag; they read `MODEL=<id>` from the environment.

## Set up a target

Clone or update `targets/<target>/` and write `output/<target>/target.toml`,
then print the next steps: review the config and run a one-iteration smoke
test.

```bash
bin/setup-target <target> <repo-url>
bin/setup-target <target> <repo-url> --ref <branch-or-revision>
bin/setup-target <target> <repo-url> --repo-type hg
bin/setup-target <target> /path/to/local/source
bin/setup-target <target>                     # re-inspect the existing checkout
bin/setup-target <target> --build             # build now instead of at preflight
```

| Argument or flag | Meaning |
| --- | --- |
| `<target>` | Target slug. Nested slugs such as `samples/sample-c` are allowed. |
| `<source>` | Repository URL or local directory. A local Git or Mercurial repository is cloned; a plain directory is symlinked, not copied (see below). Omit it to re-inspect an existing checkout. |
| `--repo-type auto|git|hg` | Version control of `<source>`. Default `auto`. |
| `--ref <ref>` | Branch, tag, or revision. Default: the clone's default branch, or the existing checkout's current branch. |
| `--pull` | Update an existing checkout to the latest upstream without re-passing its URL. |
| `--no-update` | Never fetch or pull an existing checkout. Cannot be combined with `--pull`. |
| `--build` | Build now instead of at audit preflight, and fail if the build cannot be produced. Language targets also run their ecosystem bootstrap. |
| `--force` | Regenerate the inferred config, including the threat model and S6 peers. With `--build`, rebuild afterwards, keeping the target's build recipe. |
| `--browser` / `--no-browser` | Choose browser execution mode. A browser-specific driver such as `mach` is inferred; a shared build system such as GN needs the flag. |
| `--no-alternates` | Build only the canonical sanitizer trees, skipping alternate ASan configurations. |
| `--no-llm-config` | Skip the model suggestions for threat model, S6 peers, and runner. It does not disable network access, and a missing native build recipe is still generated deterministically. |

**Rerunning setup.** An existing checkout is fetched only when you pass a
source URL, `--ref`, or `--pull`, and never with `--no-update`. Tracked
local edits skip the update; untracked build trees, `.audit/` overlays, and
run leftovers do not.

**When `target.toml` is rewritten.** A reviewed file is kept unless you pass
`--force`; one that still has placeholders is refreshed, except under
`--build` alone. After `--force`, the model helpers re-derive the threat
model and peers unless you add `--no-llm-config` or no backend answers. See
[When setup rewrites the file](target-toml.md#when-setup-rewrites-the-file)
for what is carried over.

**Symlinked local trees.** Builds and `.audit/` are written into the linked
directory. `bin/audit` follows the symlink and keeps the output tree under
the slug, but does not rebuild the linked tree at preflight: rerun
`bin/setup-target <target> --build` after source changes.

**Source layout.** With `--build`, Git submodules are synced and initialised
recursively first. A checkout root with no build manifest uses one child
directory as `source_subdir`: the one named like the target, else the only
buildable one; several unmatched candidates stop setup.

**Host checks.** Setup and audit preflight
[prove `[runner].bin`](../guides/multi-language.md#how-the-runner-is-proved)
before spending model budget. A sanitizer the host compiler cannot build
(MSan on macOS) is reported as `unsupported by the host toolchain` and
skipped; `--build` fails on it, and `bin/benchmark` exits 3. A CMake- or
Meson-built Python extension with no CLI gets an ASan-first host,
`.audit/python-runner-asan`, as its `[runner].bin` under `--build`.

See [Add a target](../getting-started/add-a-target.md) for the workflow and
[Configure a target](../guides/configure-target.md) for tuning.

### Rerun the configuration helpers

Ask a model for one `target.toml` section, and write it with `--apply`.

```bash
bin/suggest-threat-model "$TARGET" --apply --force   # [threat_model].attacker_controls
bin/suggest-peers "$TARGET" --apply --force          # [s6_peers]
bin/suggest-runner "$TARGET" --apply --force         # [runner] args and success_codes
```

| Flag | Meaning |
| --- | --- |
| `<slug>` | Target whose `output/<slug>/target.toml` is read. |
| `--apply` | Write the suggestion into `target.toml` instead of printing it. |
| `--force` | Replace a section already set: a threat model other than the seeded `["bytes"]`, an existing `[s6_peers]` (these two are checked only with `--apply`), or a `[runner]` with both `args` and `success_codes`. Without it the helper keeps the section and exits 4. |
| `--timeout <s>` | Seconds per model call and, for the runner, per validation launch. Default 120. |

Exit status: 0 success, 1 target or config unusable, 2 model call failed,
3 proposal failed validation, 4 existing section kept.

**Model use.** Each helper asks the model once. `bin/suggest-runner` may
revise once after launch validation rejects its proposal, and writes nothing
until the invocation passes an input-dependence check
([how it picks a CLI](../guides/configure-target.md)).

**Inside setup.** The threat-model and peer helpers run only when setup
writes a fresh config (missing, unparseable, re-detected, or `--force`); the
runner helper runs for a native, non-browser target whose `[runner]` is not
calibrated. A backend in `ACTIVE_BACKEND`, `BACKEND`, or `AUDIT_BACKEND`
(anything but `all`) is pinned and never falls back; the `BACKEND` exported
above counts. Unpinned, setup tries `claude → codex → gemini → grok`, then
`oss` when `MODEL` is set, moving on when a call fails or its answer does
not validate. A problem with the target itself, such as a CLI with no
readable help, is not retried elsewhere.

### Prepare alternate build configurations

Build cached alternate ASan configurations beside `build-asan`. Setup and
audit preflight run this for you; use it to inspect or retry one.

```bash
bin/build-configs --target "$TARGET" --all --backend "$BACKEND"
bin/build-configs --target "$TARGET" --config <name> --force
```

| Flag | Meaning |
| --- | --- |
| `--target <slug>` | Target under `targets/` and `output/`. Required unless both `--target-path` and `--target-toml` are given. |
| `--target-path <dir>` | Source checkout to build. Default `targets/<target>`. |
| `--target-toml <file>` | Config listing the configurations. Default `output/<target>/target.toml`. |
| `--config <name>` | Build one configuration by name or id. Repeatable. |
| `--all` | Build every configuration and prune orphaned alternate trees. One of `--config` or `--all` is required. |
| `--force` | Rebuild even when the cached tree is fresh or marked unavailable, for example after fixing a transient toolchain problem. |
| `--backend <backend>` | Model backend for a `widen = true` configuration. Default: `BACKEND`, else `ACTIVE_BACKEND`. Configurations that declare their own flags need no model. |
| `--timeout-seconds <s>` | Seconds for each configuration's recipe run. Default 900. |

A failed alternate never costs you the `build-asan` control build.
Preflight gives alternates ten minutes, then starts on the primary build, so
build a large target's alternates by hand first.

### Repair harness include and link settings

Propose additive `includes`, `link_libs`, or `defines` edits from a failing
C/C++ harness build log. Nothing in an audit runs it for you.

```bash
bin/auto-repair-target-toml --toml "output/$TARGET/target.toml" \
  --build-log <harness.build.log> --dry-run
```

| Flag | Meaning |
| --- | --- |
| `--toml <file>` | Config to repair. Required. |
| `--build-log <file>` | Failing harness build log. Required. |
| `--harness <file>` | Failing harness source, as extra context. |
| `--logdir <dir>` | Where the decision is logged. |
| `--dry-run` | Print the proposed TOML without writing it. Without it, a timestamped backup is saved beside the config. |

Read [Configure a target](../guides/configure-target.md) before accepting a
repair.

## Run an audit

Start or resume audit agents against one target.

```bash
bin/audit --target "$TARGET" --backend "$BACKEND" 1    # smoke test: one worker
bin/audit --target "$TARGET" --backend "$BACKEND" 10   # stop after ten iterations
bin/audit --target "$TARGET" --backend "$BACKEND"      # run until stopped
```

The optional final number is the iteration limit: default `0` runs until you
stop it, and `1` is a one-worker smoke test. Otherwise the pool is three
workers ([Environment variables](environment.md)). Rerunning the same
command resumes from structured state. With no arguments, `bin/audit`
prints its help.

| Flag | Meaning |
| --- | --- |
| `--target <slug>` | Target under `targets/`, such as `samples/sample-python`. This or `--target-path` is required. |
| `--target-path <dir>` | Audit this source tree instead of `targets/<target>/`. The output tree is named after its path below `targets/`, or after its basename when it lies elsewhere (lowercased; other characters become `-`). Preflight does not rebuild a tree outside `targets/`; run its build recipe yourself. |
| `--backend <name>` | `claude`, `codex`, `gemini`, `grok`, `oss`, or `all`. Default: `AUDIT_BACKEND`, else `all`. |
| `--model <name>` | Override the backend's configured model. Required for `oss`; refused with `all`. |
| `--agent-security sandboxed|external-bypass` | The agent execution boundary. Default `sandboxed`, except `oss`, which defaults to `external-bypass`. Gemini and Grok refuse `sandboxed`; run them with `external-bypass` inside a boundary you administer. See [Agent security modes](../guides/backends.md#agent-security-modes). |
| `--strategy S1|…|S8` | Pin one investigation strategy and suspend rotation. |
| `--since <rev>` | Delta mode: audit only the files changed in `<rev>..HEAD`, their one-hop callers, and S1 cards for exactly those commits. |
| `--experiment <name>` | Write results and logs under `output/<target>-<name>/` instead. The name is lowercased; other characters become `-`. The benchmark uses this for its cells. |
| `--enable-memory` | Allow the backend's cross-run learned memory. It is off by default so one run's conclusions cannot steer the next, except on Antigravity (`agy`), which has no switch for it. Benchmarks always keep it off. See [the isolation policy](../guides/backends.md#one-isolation-policy-for-every-launch). |
| `--no-refill-workers` | Leave a finished worker's slot idle while its peers run. This also selects the cohort scheduler, which `--strategy` and `--since` runs use anyway. |
| `--allow-concurrent` | Skip the one-instance lock. Two runs then append to one state tree. |

**One audit per result tree.** A second run on the same target and backend
exits with `another bin/audit instance is writing to …`; a dead owner's lock
is reclaimed automatically. Different backends write separate trees and can
run at once.

**`--backend all`.** Rotates iterations across the installed, authenticated
hosted backends in `claude → codex → gemini → grok` order, skipping any the
`--agent-security` mode cannot launch: under the default `sandboxed`, only
Claude and Codex run. A positive iteration limit also caps how many backends
take part. Name an explicit backend and model in reproducibility notes.

**Delta mode.** `--since` needs a Git or Mercurial checkout. The results tree
records both ends of the delta, so a resumed run must keep the same `HEAD`
and pass the same `--since`, or use `--experiment` for a separate tree. An
unresolvable revision or a tracked working-tree change stops the run, and an
empty or exhausted range exits; neither falls back to a whole-tree audit.

**Preflight.** Before any agent starts, the audit checks the runner and, for
a tree under `targets/`, rebuilds missing or stale sanitizer builds with
`bin/setup-target <target> --build` (log: `logs/setup-build.log`).

### Container shell

Open an interactive Docker shell with the supported backend CLIs installed
and this repository mounted at `/root/work`. It does not start an audit.

```bash
bin/audit-container-shell --rebuild               # first use or image refresh
bin/audit-container-shell                         # reuse the existing image
bin/audit-container-shell --gvisor                # run under gVisor (runsc)
```

| Flag | Default | Meaning |
| --- | --- | --- |
| `--image <image>` | `node:lts-bookworm` | Base image for `--rebuild`; `ubuntu` and `fedora` expand to `:latest`. |
| `--tag <name>` | `audit-cli-shell:latest` | Image tag to build and run. |
| `--runtime <name>` | `CONTAINER_RUNTIME`, else `docker` | Container CLI; only Docker is supported. |
| `--gvisor` | off | Shorthand for `--docker-runtime runsc`. |
| `--docker-runtime <name>` | `AUDIT_DOCKER_RUNTIME`, else the daemon default | OCI runtime passed to `docker run --runtime`. |
| `--workdir <path>` | `/root/work` | Where the repository is mounted and the shell starts. |
| `--env-file <path>` | none | Passed to `docker run --env-file`. |
| `--forward-credentials` | on when `AUDIT_FORWARD_CREDENTIALS=1` | Forward host credential variables and mount the Google Cloud config read-only. |
| `--rebuild` | off | Build or refresh the image first. |
| `--dry-run` | off | Print the build and run commands without executing them. |

Host credential directories are never mounted: log in inside the disposable
container, or pass `--forward-credentials`. The container sets
`IS_SANDBOX=1`, the boundary assertion `--agent-security external-bypass`
expects. See
[Containerised backend shell](../guides/backends.md#containerised-backend-shell).

## Inspect a running audit

Read structured state instead of raw transcripts. `bin/state` and
`bin/sweep` share these global options, which go before a `bin/state`
subcommand:

| Option | Default |
| --- | --- |
| `--results-dir <dir>` | `RESULTS_DIR`, else `output/<target>/results`. That derived path has no backend component and is not the audit's tree, so always pass this. |
| `--target <slug>` | `TARGET_NAME`. Pass it too, so commands that consult the source tree read the right one. |
| `--target-path <dir>` | `TARGET_ROOT`. Use instead of `--target` for a tree outside `targets/`. |
| `--target-slug <name>` | `TARGET_SLUG`. The output tree name, when it differs from the target's slug. |
| `--script-root <dir>` | `SCRIPT_ROOT`, else this checkout. |

### `bin/state`

```bash
bin/state --target "$TARGET" --results-dir "$RESULTS" show-recent --agent 1
bin/state --target "$TARGET" --results-dir "$RESULTS" resume --agent 1 --peek
bin/state --target "$TARGET" --results-dir "$RESULTS" explain-queue
```

!!! warning "`resume` and `next-card` claim work"
    Without `--peek`, `bin/state resume --agent N` and
    `bin/state next-card --agent N` claim the next eligible card for agent
    `N`, exactly as a starting agent does. Add `--peek` to look without
    changing the queue.

Read-only subcommands:

| Subcommand | Shows |
| --- | --- |
| `show-recent [--agent N]` | The best first look: recent claims, hypotheses, and probe runs with their `coverage` outcome and `closest` frame. `--hyps`, `--runs`, `--claims` default to 10 rows; `--notes` to 0. |
| `resume --agent N --peek` | The startup brief an agent would get, without claiming a card. |
| `list-cards`, `list-crashes`, `list-findings` | Compact JSONL, 20 rows by default (`--limit 0` for all). `list-cards` filters by `--status`, `--strategy`, `--subsystem`, `--contains`. |
| `show-card <id>`, `show-crash <id>`, `show-finding <id>` | One full compact record. |
| `explain-queue` | Why cards are or are not eligible, aggregated by reason (top 8 by default; `--all` for one row per card). |
| `card-yield` | Claims, probed cards, runs, and diagnostics per queue-rank bucket, and the share of the queue ever touched. |
| `coverage` | Auditable files enumerated versus offered, claimed, and receipted, per directory (`--depth`, default 2; `--format md|json`). See [Review coverage](../concepts/coverage.md). |
| `strategy-yield` | Per-strategy probe runs, verdict counts, seconds, and crash yield. |
| `strategy-status` | The strategy-completion evidence the rotation gate reads. |
| `agent-counts` | A status histogram for one agent. |
| `recent-hyps`, `recent-runs`, `recent-notes`, `recent-claims`, `recent-tried` | One slim ledger each, with filters. |

Run `bin/state <subcommand> --help` for each subcommand's filters. The
state-changing subcommands are listed under [Agent tools](#agent-tools).

A card that stays open after an agent examined it is expected; see
[how cards close](../concepts/strategy-model.md#how-a-card-gets-to-an-agent).

### `bin/sweep`

Run the budgeted breadth pass by hand, for example
`bin/sweep --target "$TARGET" --results-dir "$RESULTS" --dry-run`. An audit
starts it in the background when `[sweep] token_budget` is set, except in
`--since` and `--strategy` runs, and logs to `logs/sweep.log`.

| Flag | Meaning |
| --- | --- |
| `--dry-run` | List the unreceipted units in sweep order, and exit. |
| `--token-budget <n>` | Estimated prompt-plus-reply budget. Default `[sweep] token_budget`; with neither, a sweep other than `--dry-run` exits 2. Spend accumulates in `state/sweep.json` across invocations, so topping up a finished sweep needs a larger number. The sweep stops before a prompt that would exceed the budget; the last reply can take the total past it. |
| `--max-units <n>` | Stop after this many units. Default 0, no cap. |
| `--unit-lines <n>` | Largest unit in source lines. Default `[sweep] unit_lines`. |
| `--model <name>` | Model for the decisions. Default `[sweep] model`, else the backend default. |

See [The budgeted sweep](../concepts/coverage.md#the-budgeted-sweep) for how
it chooses units.

### `bin/coverage-summary`

`bin/coverage-summary --results-dir "$RESULTS"` groups the coverage edges
`bin/hits` recorded into a per-subsystem table.

| Flag | Meaning |
| --- | --- |
| `--results-dir <dir>` | Results tree to read; skips the slug lookup. |
| `--slug <slug>` | Target slug. Default `TARGET_SLUG`. |
| `--depth <n>` | Path components to group by. Default 2. |
| `--min-edges <n>` | Drop subsystems with fewer edges. Default 1. |
| `--format md|tsv|json` | Output format. Default `md`. |
| `--out <file>` | Write here instead of stdout. |

## Review results

Open the HTML indexes before logs: `output/<target>/crash-clusters.html` and
`finding-clusters.html` cover every backend; cluster and rejected indexes
per backend are listed in [Artifact layout](artifacts.md). Follow a cluster
to the artifact's `report.html`, and edit only its Markdown source.
[Triage and review](../guides/triage-results.md) explains the review states.

The audit runs export, severity, validation, and clustering for you; use
these commands to regenerate a view after a deliberate manual edit.

### `bin/export-repro`

Rebuild a crash's maintainer bundle (`reproduce.sh`, report, and staged
evidence) in place.

```bash
bin/export-repro CRASH-001-1 --crash-dir "$RESULTS/crashes/CRASH-001-1"
```

| Flag | Meaning |
| --- | --- |
| `--crash-dir <dir>` | Crash directory to export; the safest way to name a crash, because its nearest `.session-env` supplies the results tree, checkout, and revision. Default `<results>/crashes/<CRASH-id>`. |
| `--slug <slug>` | Take the session from `output/<slug>/` when the crash directory has none. With several backend trees this may pick another backend's session. |
| `--target-root <dir>` | Checkout that owns the build recipe; outranks the session's. |
| `--target-rev <rev>` | Revision the crash was found at. Default: the session's audited revision, or the `--target-root` checkout's revision when that flag is given. |
| `--out <dir>` | Write the bundle elsewhere. The directory's previous content is replaced. |
| `--symbolize-budget <s>` | Wall for the one symbolization pass a raw-frame diagnostic gets. Default 600. |

With neither `--crash-dir` nor `--slug`, export uses the nearest
`.session-env` above the current directory. For a crash copied out of its
results tree, name the checkout and revision explicitly:

```bash
bin/export-repro CRASH-001-1 --slug "$TARGET" \
  --crash-dir /path/to/CRASH-001-1 \
  --target-root /path/to/audited-checkout --target-rev <commit>
```

Export rebuilds the narrative from the agent's draft, `.audit/report.md`,
and keeps only the field values from the root `report.md`. Edit the draft to
change the narrative durably; see [Crash directory](artifacts.md#crash-directory).

### `bin/severity`

The offline CVSS v4.0 scorer, for example `bin/severity --batch "$RESULTS"`.
No network access.

| Flag | Meaning |
| --- | --- |
| `--report <dir>` | Score one artifact: rewrite its severity fields and write `severity.json`. |
| `--batch <results>` | Score every `findings/FIND-*` and `crashes/CRASH-*` directory. |
| `--json` | Print JSON instead of a summary. |
| `--harness-rooted-check` | With `--report`, read-only: print `1` and exit 0 when the crash faults entirely inside the audit harness, else print `0` and exit 1. No scoring. |

In a results tree's `findings/` or `crashes/`, only an artifact with a
current `reportable` receipt gets a numeric score. The rest are marked
`Not a security report` (`not-reportable`) or `Unknown` (pending or stale
validation).

### `bin/cluster-crashes` and `bin/cluster-findings`

Regroup artifacts and rewrite the cluster indexes and each report's
`Cluster:` line. Each takes a results directory, its `crashes/` or
`findings/` directory, or `output/<target>/` for the cross-backend rollup.

```bash
bin/cluster-crashes "$RESULTS"
bin/cluster-findings "output/$TARGET"     # rebuild the cross-backend rollup
```

| Flag | Meaning |
| --- | --- |
| `--dry-run` | Write nothing; print the plan. |
| `--json` | Print the clusters as JSON. |
| `--json-out <file>` | Save the clusters as JSON and still update the reports. |
| `--only <name>` | With `--json`, cluster only the named artifacts; repeat it per name. A running audit uses it to count root causes from admitted artifacts alone. |
| `--target-root <dir>` | `bin/cluster-findings` only: strip this prefix from absolute paths in report text. |

[Deduplication](../concepts/deduplication.md) explains the signatures.

### `bin/show-exclusions`

`bin/show-exclusions <results>` prints a read-only listing of the `CRASH-*`
and `FIND-*` directories present, rejected crashes with the reason from
their `rejection.md`, and fuzz shutdown noise. It reads no receipts: its
"Confirmed findings" heading means "present in `findings/`", and rejected
findings are not listed.

## Run a testcase

Run one harness-authored testcase. `bin/probe` is the only execution gate for
such testcases.

```bash
bin/probe "$RESULTS/scratch-1/testcase.html"
bin/probe --confirm "$RESULTS/scratch-1/testcase.html"
bin/probe --dry-run "$RESULTS/scratch-1/testcase.dat"
```

It finds the session by walking up to the result tree's `.session-env`,
selects the browser, JS, generic, harness, or language runner from the
pinned config, and writes diagnostic output beside the testcase. A verdict
for a named hypothesis is recorded in `state/runs.jsonl`. Exit status 2
means a usage or setup error.

!!! warning "Probing writes into the live result tree"
    The testcase must sit under `<results>/scratch-<N>/`, and `bin/probe`
    records its runs and notes as agent `N`. A confirmed crash is filed in
    `crashes/` and triaged like any other. Use `--dry-run` to inspect a
    route without running it.

| Flag | Meaning |
| --- | --- |
| `--confirm` | Run five times. |
| `--sanitizer-runs <n>` | Run `n` times instead. Default one run, or `SANITIZER_RUNS`. Cannot be combined with `--confirm`. |
| `--dry-run` | Print the resolved mode, sanitizer, build configuration, output path, and command without running it. |
| `--mode auto|browser|js|generic` | Default `auto`: the `MODE` header, else the mode `target.toml` configures. Set it only when detection is wrong. |
| `--hypothesis-id <H-…>` | For an opaque binary input that cannot carry headers; `TARGET` and `CARD-ID` come from that hypothesis. |
| `--property <kind>` | The `PROPERTY` header for an opaque S8 input. |
| `--harness <name>` | The `HARNESS` header, for a fuzz artifact replayed against the harness that produced it. |
| `--want <regex>` | The symbol a coverage-gated browser or JS probe must reach. Default: derived from the `TARGET` header. |
| `-- <args>` | Arguments passed to the harness. |

`PROBE_SANITIZER=asan|ubsan|msan|tsan|race|runner` overrides the sanitizer
`target.toml` selects.

**When a crash is filed.** A `CRASH` verdict from two or more runs
(`--confirm`, or `--sanitizer-runs 2` and up) is filed as
`crashes/CRASH-<NNN>-<agent>/` with the testcase, `sanitizer.txt`, and a
skeleton `report.md`. It is not filed when:

- the same crash state through the same route is already filed
  ([filing-time refusal](../concepts/deduplication.md#filing-time-refusal));
- the `runner` sanitizer produced it;
- the harness is interpreted rather than compiled; or
- the diagnostic describes a binary `bin/probe` did not build: a module
  under the agent's scratch tree that probe did not compile, or a crashing
  `main` in a scratch source other than the harness. Harnesses that drive
  the target's own executable are unaffected.

**Refused harnesses.** A compiled C/C++ harness that sets `LD_PRELOAD` or
`DYLD_INSERT_LIBRARIES` and then launches a process is refused before
compilation. Linked API harnesses and file or protocol launchers are fine.

**Alternate builds.** A crash confirmed on an alternate
[build configuration](target-toml.md#build-configurations) is re-run on the
regular build, with the result saved beside it, and its `reproduce.sh`
rebuilds the captured alternate recipe. `PROBE_BUILD_CONFIG=<name>` (or
`primary`) pins one probe; the configuration id and its `cfg-<id>` spelling
also work. Alternates are ASan-only.

### Testcase headers

Every testcase begins with headers in the file's native comment syntax
(`//`, `#`, `<!-- … -->`):

```text
TARGET: path/to/file.c:Function:123   # required: file[:function[:line]]
HYPOTHESIS-ID: H-…                    # required: a hypothesis recorded with bin/state
CATEGORY: bounds                      # required
MODE: generic                         # optional: auto|browser|js|generic
HARNESS: harness.c                    # optional sibling API harness
CARD-ID: <id>                         # optional: the work card this came from
PROPERTY: inverse                     # required under S8: the oracle kind
```

Categories are `bounds`, `lifetime`, `type`, `size`, `uninit`, and `state`.
Properties are `inverse`, `idempotence`, `injectivity`, `domain`, `format`,
and `equivalence`. See [Reproduce a crash](../guides/reproduce-a-crash.md) for
the maintainer-side bundle flow.

### Coverage replay

Run a testcase under SanitizerCoverage and report whether a covered symbol or
`file:line` matches `--want`: `HIT`, `MISSED` with the closest frame
reached, or `COVERAGE_UNAVAILABLE`. `bin/probe` runs it for you.

```bash
bin/hits --testcase "$RESULTS/scratch-1/testcase.js" --want <symbol-regex> --mode js
bin/hits --testcase "$RESULTS/scratch-1/input.dat" --want <symbol-regex> --mode generic
```

| Flag | Meaning |
| --- | --- |
| `--testcase <file>` | Testcase to run. Required. |
| `--want <regex>` | Pattern a covered symbol or `file:line` must match for a `HIT`. Required. |
| `--mode browser|js|generic` | Launch route. Default `browser`, so pass it for anything else. |
| `--timeout <s>` | Seconds before the instrumented run is killed. Default 20. |
| `--save <file>` | Keep the symbolized hit list. |
| `--log <file>` | Append the one-line verdict. |
| `--slug`, `--agent` | Label recorded edges. Defaults `TARGET_SLUG` and `AUDIT_AGENT_NUM` or `AGENT_NUM`. |
| `-- <args>` | Arguments for the launched program. |

`--route-binary`, `--harness-source`, and `--generic-skip-testcase` are set
by `bin/probe`.

- **Generic mode** replays in `build-asan+cov`, the ASan coverage sibling
  built from the target's recipe; a `HARNESS` route replays a coverage twin
  linked against its `asan_lib`. Coverage is feedback only: even `MISSED`
  continues to the sanitizer run.
- **Browser and JS modes** can use it as a hard gate before the sanitizer.
- **`COVERAGE_UNAVAILABLE`** means the coverage route cannot describe the
  same program and source generation as the ASan route, as with interpreter
  and wrapper routes. The sanitizer run still proceeds.
- **Alternate builds** replay on the control build's twin: a `HIT` is
  labelled control-build coverage, and a miss is `COVERAGE_UNAVAILABLE`.

## Benchmark TokenFuzz

Compare TokenFuzz with the same model prompted directly. It is not part of
routine auditing; see [Benchmarking](../concepts/benchmark.md) for the
design.

```bash
bin/benchmark --target "$TARGET" --backend "$BACKEND"
bin/benchmark --target "$TARGET" --backend gemini --agent-security external-bypass
bin/benchmark --target "$TARGET" --backend "$BACKEND" --run-id <run-id>   # resume
bin/benchmark --rebuild-report
bin/benchmark score "$RESULTS" --ground-truth "output/$TARGET/.ground-truth.json"
bin/export-benchmark --target "$TARGET" --backend "$BACKEND" --format zip
```

| Flag | Default | Meaning |
| --- | --- | --- |
| `--target <slug>[,<slug>…]` | required | Target to benchmark; a list runs each target as its own run. Not needed with `--reset`, `--regenerate`, `--rebuild-report`, or `--prune-cache`. |
| `--backend <name>` | `codex` | Backend for both conditions: `claude`, `codex`, `gemini`, `grok`, or `oss`. |
| `--model <name>` | backend default | Model for both conditions; required for `oss`. |
| `--agent-security <mode>` | as for `bin/audit` | Boundary for both conditions. |
| `--replicates <n>` | 3 | Runs per condition. |
| `--budget-wall <s>` | 10800 | Active audit seconds per cell; provider-recovery pauses are excluded. `0` is unlimited. |
| `--finalize-wall <s>` | 0 | Ceiling per final validation phase. `0` is unlimited. |
| `--finalize-workers <n>` | 4 | Concurrent reviewers per final validation phase. |
| `--agents <n>` | the audit's pool, normally 3 | Harness workers per cell; the direct baseline is one launch. |
| `--conditions <list>` | `model-direct,harness` | Conditions to run. |
| `--hold-direct` | off | Re-enter a direct session that ends early, until the wall. |
| `--bench-root <dir>` | `benchmark` | Artifact root; a relative path lives under `output/`. |
| `--run-id <id>` | UTC timestamp | Run directory under `<bench-root>/<backend>/`; reuse it to resume. |
| `--isolate-build` | off | Build into a private tree keyed by build inputs instead of sharing the canonical build. |
| `--no-validate-findings` | off | Skip the post-cell finding review; filed findings stay unconfirmed. `--validate-findings` is the default. |
| `--dry-run` | off | Launch no backend; write synthetic cells instead. They are still scored and published to the ledger and result page under the bench root, so point `--bench-root` at a scratch location. With `--regenerate`, pools are rebuilt without model decisions; with `--prune-cache`, it only lists what would be removed. |
| `--regenerate` | off | Rebuild scores, ledger, and pages without new cells; may replay artifacts and invoke reviewers. Without `--target`, every recorded run. |
| `--rebuild-report` | off | Rebuild `benchmark-result.md`/`.html` from existing run state only. |
| `--prune-cache` | off | Drop cached harness builds that no run on disk names. |
| `--reset` | off | Archive the backend's `benchmark-results.md` ledger and exit. |

A target whose enabled sanitizer the host compiler cannot build is refused
before any cell starts, with exit code 3 (distinct from a fixable build).

### `bin/benchmark score`

Score an existing `crashes/`, results, or pool tree against a target's
answer key. It launches nothing. Every shipped sample target has a
`.ground-truth.json`, and a benchmark run on such a target also gets an
**Answer key** section in `benchmark-result.md`.

| Flag | Meaning |
| --- | --- |
| `<dir>` | A `crashes/` directory, or a results or pool directory holding one. |
| `--ground-truth <file>` | The target's answer key, `output/<target>/.ground-truth.json` for a sample. Required. |
| `--findings-dir <dir>` | Findings to score. Default: the `findings/` beside the crashes. |
| `--members <file>` | A `pool-members.json`, for per-condition scores. |
| `--conditions <list>` | Conditions that each get a row, even with zero crashes. |
| `--out <file>` | Write the scoring JSON here. Default stdout. |

### `bin/export-benchmark`

Package benchmark results into a self-contained archive.

| Flag | Meaning |
| --- | --- |
| `--format zip|tar|dir` | Archive type. Default `zip`. |
| `--backend <name>` | Only this backend's runs. |
| `--target <slug>` | Only runs of this target. |
| `--run-id <id>` | Only this run. Needs `--backend`. |
| `--bench-root <dir>` | As for `bin/benchmark`. |
| `--out <path>` | Default `<bench-root>/benchmark-share[-<backend>][-<target>][-<run-id>].<ext>`. |

## Maintain TokenFuzz and local output

```bash
bash tests/run-tests.sh
bash tests/run-tests.sh --image ubuntu:24.04   # the CI container lane
bin/docs build                                 # strict build into site/
bin/docs serve                                 # local preview

bin/cleanup_state --target "$TARGET" --dry-run
bin/cleanup_state --target "$TARGET" --backend "$BACKEND" --dry-run
bin/cleanup_logs --target "$TARGET" --backend "$BACKEND" --dry-run
```

See [Development](../development.md) for the test-suite options.
`bin/docs install` only installs the docs dependencies, and
`bin/docs mkdocs <args>` passes through to MkDocs.

### `bin/cleanup_state` and `bin/cleanup_logs`

!!! warning "Cleanup defaults to every target"
    Without `--target`, both commands act on every target under `output/`.
    Pass `--target` and review the `--dry-run` list before removing
    anything. Neither command checks for a running audit, and
    `bin/cleanup_logs` also removes the audit's instance lock, so stop the
    audit first.

| Flag | Meaning |
| --- | --- |
| `--target <slug>` | Target to clean. Repeatable. Default: every target. |
| `--backend <a,b>` / `--backends` | Only these backend directories. |
| `-n`, `--dry-run` | List (`cleanup_state`) or count (`cleanup_logs`) what would be removed. |
| `-q`, `--quiet` | Print only errors. |
| `--output-root <dir>` | Default `output/`. |
| `--keep <name>` | `cleanup_state` only: another entry to preserve in each target directory. Repeatable. |
| `--keep-only <a,b>` | `cleanup_state` only: replaces the `--keep` list. |

**`bin/cleanup_state`** resets `output/<target>/`, always keeping
`target.toml` and `.ground-truth.json`. A whole-target reset also removes
the target's generated `build-<sanitizer>*` trees and everything under its
`.audit/` except the canonical recipes `.audit/build.sh` and
`.audit/build-<sanitizer>.sh`. With `--backend`, it removes only those
backend directories and leaves the source builds alone. It finds the source
checkout from the backend sessions' recorded `TARGET_ROOT`, else
`targets/<slug>` beside the output root.

**`bin/cleanup_logs`** empties `output/<target>/<backend>/logs/` for the
selected backends (default all five), keeping the directories and their
`.gitkeep` files.

## Agent tools

Audit agents call these during a session; the prompts teach them. You can
run them by hand when diagnosing a run. Most read `RESULTS_DIR` and
`TARGET_ROOT` from the environment the audit sets, so export those first.

| Command | What it does |
| --- | --- |
| `bin/peek <file>[:<start>[-<end>]]` | Bounded source read (about 50 KiB). `bin/peek [grep flags] <pattern> <file>…` greps with context clamped to `PEEK_GREP_AFTER` (30) and `PEEK_GREP_BEFORE` (8) lines. `--no-cap` disables clamping. |
| `bin/rg-safe [rg args]` | ripgrep with a 20 KiB output cap and a per-file hit digest when it truncates. A relative path that is missing from the working directory is searched under the target or results tree instead. Skips `.git/`, `.hg/`, and `output/**/logs/`; `--cap-bytes <n>`, `--no-cap`, `--include-logs`. |
| `bin/show-patch <commit> [<path>…] [git show flags]` | Bounded, memoized `git show` of one commit, `--unified=10` by default (`PATCH_CONTEXT`). |
| `bin/find-seed <file>[:<function>] [max]` | In-tree tests, samples, and corpus inputs likely to exercise that code, best first (default 15). Needs `TARGET_ROOT`. |
| `bin/scratch-status [dir…]` | Digest of scratch directories: testcase/output pairs and unrun testcases. Default: every `scratch-*` under `RESULTS_DIR`. `--agent N`, `--terse`, `--files [N]`. |
| `bin/scratch-search [options] <pattern>` | Search scratch, corpus, crash, and finding artifacts under `RESULTS_DIR`, capped per section. Sanitizer sidecars and logs are excluded unless `--include-asan` / `--include-logs`. |
| `bin/probe-history <testcase>` | Prior `bin/probe` verdicts for a testcase, by path and content hash; or `--sha1`, `--hypothesis-id`, `--card-id`, `--all`. `--results-dir` overrides `RESULTS_DIR`. Exits 1 when nothing matched. |
| `bin/symbolize <sanitizer.txt>…` | Resolve `module+offset` frames in place in a report produced outside the runners, for example by a sandboxed backend that drove the binary itself. Exits non-zero, and says why, when a frame stays raw. |
| `bin/find-crash-testcase <CRASH-dir>` | Print the testcase path of a crash directory (`.audit/` first). Exits 1 when none is found. |
| `bin/triage-fuzz-crashes <results> [max_leads]` | Summarise non-noise libFuzzer artifacts from an S4 campaign as leads. |
| `bin/state` (writing subcommands) | `init`, `next-card` and `resume` without `--peek`, `add-hyp`, `update-hyp`, `update-card`, `add-run` (normally written by `bin/probe`), `mark-examined`, `add-note`, and `release-stale-claims`. They change the live queue; do not run them against an audit you are only watching. |

### Boundary-directed fuzzing (S4)

```bash
bin/fuzz --results-dir "$RESULTS" inventory               # harnesses the target already has
bin/fuzz --results-dir "$RESULTS" candidates              # APIs that earn one
bin/fuzz --results-dir "$RESULTS" template <symbol>       # skeleton under fuzz/src/
bin/fuzz --results-dir "$RESULTS" build                   # compile out of tree
bin/fuzz --results-dir "$RESULTS" run --budget-seconds 300
bin/fuzz --results-dir "$RESULTS" --json status
bin/fuzz --results-dir "$RESULTS" doctor                  # prove the shared build is unaffected
```

The global options `--results-dir` (default `RESULTS_DIR`, else walk up from
the current directory), `--sanitizer` (default: the first enabled native
sanitizer), and `--json` go before the subcommand.

| Subcommand | Purpose |
| --- | --- |
| `inventory` | Existing harnesses (libFuzzer, cargo-fuzz, Go, Atheris, Jazzer), what each drives, and what each cannot reach. |
| `candidates [--limit N]` | Exported APIs through the admission gate, with each rejection's reason. Default 25. |
| `template <symbol>` | A dual-entry skeleton (libFuzzer target and standalone driver `bin/probe` can replay) with a source-grounding receipt from at most two target-local callers. `--output`, `--target`, `--hypothesis-id`, `--force`. |
| `build [source…]` | Compile harnesses out of tree against the shared sanitizer build. Refuses in-tree sources and unfaithful harnesses. |
| `run` | Spend `--budget-seconds` (default 300) across built harnesses in `--slice-seconds` slices (default 60), quarantine those that stop paying, and replay artifacts through `bin/probe`. `--agent` (default `AGENT_NUM`, else 1) owns the campaign state. |
| `status` | Build and grounding receipt, first-slice and campaign state, and the next step per harness. |
| `doctor` | Linked build, coverage feedback, lease state, and isolation; exits 1 when an untracked harness or the campaign itself sits inside the target checkout. |

See [Boundary-directed fuzzing](../guides/directed-fuzzing.md) for the
workflow and the build-isolation rules.

## Harness internals

The audit runs these stages for you. They are listed so you can find the
right file when diagnosing a run or changing the harness; their interfaces
are not stable, so read the source and its tests before depending on one.

| Command | What it does |
| --- | --- |
| `bin/rank-work` | Builds the ranked work-card queue (`work-cards.jsonl`); `--since <rev>` restricts it to the delta's files and callers. |
| `bin/patch-cards` | Derives S1 prior-fix cards from the target's history (`patch-cards.jsonl`); `--since <rev>` emits one per commit in the range. |
| `bin/peer-fix-cards` | Derives S6 cards from `[s6_peers]` (`s6-peer-cards.jsonl`). Patch-excerpt fetching is bounded to 120 s per refresh; a card whose excerpt did not arrive stays a discovery lead. |
| `bin/callgraph` | Writes the optional per-file call neighbourhood card prompts quote; `--probe` reports whether the analysis can run here. |
| `bin/auto-build-script` | Converges a sanitizer build recipe into `.audit/build*.sh`, with model help. |
| `bin/run-asan`, `bin/run-ubsan`, `bin/run-msan`, `bin/run-tsan` | Per-sanitizer execution wrappers, `bin/run-<san> <mode> <testcase> [args…]`. `bin/probe` selects and invokes them. |
| `bin/run-sanitizer-multi` | Repeats a sanitizer runner, runs the coverage gate, and reduces the results to one verdict. |
| `bin/validate-finding` | One independent source-reading review of a single finding, under the threat model its results tree pinned. |
| `bin/enrich-report` | Inlines source snippets and the TL;DR, and writes the `## Patch` section from `patch.diff`. |
| `bin/render-md` | Pads Markdown tables and renders a report's or index's `.html` sibling in the evidence-page shell. |
| `bin/severity-sweep` | Re-scores the cluster representatives of results or benchmark pools and prints CSV. It runs `bin/severity --report` on each, which rewrites their severity fields and `severity.json`, so do not run it on a live tree. |
