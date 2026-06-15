# Commands

This is the operator command reference. It is organised by the
order you reach for things:

- target setup;
- audit execution;
- testcase development;
- mid-run checkpoint;
- result review;
- maintenance.

Examples assume you are at the repository root.

The commands you reach for most:

```bash
bin/audit --target <slug> --backend <backend> 1          # one bounded iteration
bin/state --results-dir "$RESULTS" show-recent --agent 1 # mid-run check
open "$RESULTS"/crashes/CRASH-CLUSTERS.html              # review results
```

Everything below expands on those three.

To keep the examples consistent, set the target slug and backend
once:

```bash
export TARGET=<your-target>
export BACKEND="<backend>"        # one of: claude, codex, gemini, oss
# Optional convenience path for inspecting results.
export RESULTS="output/$TARGET/$BACKEND/results"
```

## Target setup

```bash
bin/setup-target "$TARGET" <repo-url>
bin/setup-target "$TARGET"
bin/setup-target "$TARGET" <repo-url> --ref <branch-or-revision>
bin/setup-target "$TARGET" <repo-url> --repo-type hg
```

This creates or updates:

```text
targets/<target>/
output/<target>/target.toml
```

Run twice for a normal ASan-first setup:

1. **Before the sanitizer build, with a repository URL** — creates
   or updates `targets/<target>/` and seeds
   `output/<target>/target.toml`.
2. **After the sanitizer build, without a repository URL** —
   re-inspects build outputs and fills values that could not be
   inferred earlier.

With no repo URL or ref, `bin/setup-target <target>` re-inspects
`build-asan/` and refreshes generated fields in `target.toml`.

Advanced flags:

```bash
bin/setup-target <target> <repo-url> --no-update
bin/setup-target <target> --force-config
bin/setup-target <target> --bootstrap
bin/setup-target <target> --no-llm-config
```

What each flag does:

- `--no-update` — skip the pull when passing a repo URL or ref.
- `--force-config` — explicitly regenerate `target.toml` and overwrite
  LLM-suggested `[threat_model]` / `[s6_peers]` sections.
- `--bootstrap` — run an optional language build step for non-C/C++
  targets (Python C extensions, `npm install`, `composer install`,
  …). See [Add a target](../getting-started/add-a-target.md).
- `--no-llm-config` — skip the best-effort threat-model and S6 lookalike project
  suggestions. Not recommended unless you have a specific reason to
  stay offline; the LLM-suggested values are usually a better starting
  point than the conservative defaults.

LLM-backed config helpers can be run explicitly after setup:

```bash
bin/suggest-threat-model "$TARGET" --apply --force-config
bin/suggest-peers "$TARGET" --apply --force-config
```

Use these when the deterministic seed is too conservative and you want
to refresh `[threat_model]` or `[s6_peers]` without recreating the rest
of `target.toml`.

## Audit runs

```bash
bin/audit --backend <backend> --target <target-name> [--model <model>]
bin/audit --target "$TARGET" --backend "$BACKEND" 1
bin/audit --target "$TARGET" --backend "$BACKEND" 10
bin/audit --target "$TARGET" --backend "$BACKEND" --strategy S3 1
```

Notes:

- The optional final argument limits iterations. Omit it, or pass
  `0`, to run continuously.
- `<backend>` is one of `claude`, `codex`, `gemini`, or `oss`.
- Start with `1` to verify target config, backend CLI, results
  directory, and state writer before committing to a long run.
- Use `--model` with the `claude` or `codex` backend. The harness
  forwards it to that backend's native model flag. For `oss`,
  `--model` is required and names an already-pulled Ollama model. The
  `gemini` backend uses Antigravity CLI (`agy`) by default, which has no
  launch-time model selector; use `agy`'s interactive `/model` command.
  Set `USE_GEMINI_CLI=1` to use Google Gemini CLI instead; then
  `--model` is forwarded to `gemini`.

### Cross-run memory is off by default

Every supported backend can build up its own *cross-run memory* — notes it
saves from one run and silently reloads into later ones. That is dangerous for
an audit: the memory is cumulative, so one wrong note ("this code is already
saturated", "not reachable") quietly steers **every future run** on that
target. Exactly that has happened — a stale "saturated" note walked an audit
straight past a real, reproducible bug. The danger is two-sided: a backend
*reads* its prior notes into context, and *writes* new ones — so a real off
switch has to close both directions.

So the harness turns cross-run memory **off by default**. There is one control,
a single flag — no environment variables to set:

```bash
bin/audit --target "$TARGET" --backend "$BACKEND" --enable-memory
```

`--enable-memory` opts back in (for cumulative learning across runs). Otherwise
the harness applies the right per-backend "off" control for you:

| Backend | Cross-run memory it keeps | What the harness does by default |
| --- | --- | --- |
| `claude` | `MEMORY.md` + `memory/*.md`, auto-recalled into context and auto-saved mid-run | sets `CLAUDE_CODE_DISABLE_AUTO_MEMORY=1` (Claude Code's own off switch) |
| `codex` / `oss` | learned memories under `~/.codex/memories/`, reloaded into context and regenerated | passes `-c features.memories=false -c memories.use_memories=false -c memories.generate_memories=false` |
| `gemini` with `USE_GEMINI_CLI=1` (Google Gemini CLI) | global `~/.gemini/GEMINI.md` plus private project memory under Gemini's user storage, loaded into later sessions and writable by memory commands or direct file edits | runs the CLI under a clean, **empty** per-run `GEMINI_CLI_HOME` (staged at `$LOGDIR/.gemini-home`, no `GEMINI.md`, no state, no credential files) so nothing is read or written; auth rides on the `GEMINI_API_KEY` the harness forwards. An `--admin-policy` denying `save_memory` stays as a backstop |
| `gemini` default (`agy` / Antigravity CLI) | persistent Antigravity CLI state under `~/.gemini/antigravity-cli` (`brain/`, `implicit/`, conversations, logs) | nothing automatic — `agy` exposes no documented memory-off flag or auth-preserving isolated home/profile switch in headless `-p`; naive `HOME` relocation creates fresh state but breaks auth (a false "successful" empty run). Use `USE_GEMINI_CLI=1` when strict Gemini memory isolation is required |

Every row was confirmed by **running the CLI**, not just reading its docs: with
memory on, the model recalls a planted fact; with the harness's control
applied, it does not. For Gemini CLI in particular, denying `save_memory` alone
was *not* enough — the global memory is loaded regardless of tool policy and the
model can write it directly, and no flag or setting disables that load. So the
harness relocates the home to an empty per-run directory: a planted fact in the
real `~/.gemini/GEMINI.md` is then not recalled, while the forwarded
`GEMINI_API_KEY` keeps the empty home authenticated. Because the empty home has
no credential files, an API key is the only way it can authenticate, so the
harness checks for one up front: with `USE_GEMINI_CLI=1` and memory off, a run
that has neither `GEMINI_API_KEY` nor `GOOGLE_API_KEY` set **fails immediately**
with a clear message rather than silently falling back to the operator's global
home. Operators who use file-based (OAuth) Gemini CLI auth must export an API
key for memory-off runs, use the default `agy` backend, or pass
`--enable-memory` to opt back in.

This affects only the *learned, cross-run* channel. Your project instructions —
`AGENTS.md` and a project `GEMINI.md` — are the intended audit contract and are
never touched.

If you turn memory back on, **watch the memory files and prune stale entries**:
Claude Code stores them under `~/.claude/projects/<slugified-cwd>/memory/` (one
fact per file, indexed by `MEMORY.md`) and Codex under `~/.codex/memories/`.
Delete any note claiming a target is "clean", "saturated", or "not reachable"
unless you have re-confirmed it — those are the ones that suppress future
findings.

`bin/benchmark` always keeps memory off (so backends compare from a clean
slate) and has no opt-in. Gemini CLI memory-off runs without an env API key fail
early as described above; otherwise the effect is only the memory default.

Results are written under:

```bash
# Optional convenience paths for inspecting results.
export RESULTS="output/$TARGET/$BACKEND/results"
export LOGS="output/$TARGET/$BACKEND/logs"
```

- Use `results/` for audit progress and evidence.
- Use `logs/` when startup, backend authentication, or wrapper
  behaviour needs debugging.

Supported single backends: `claude`, `codex`, `gemini`, `oss`.
Use `--backend all`, or omit `--backend`, to cycle installed hosted
backends across iterations. Use the same explicit backend when
comparing runs — backend names are part of the output path, so each
writes to its own result tree.

### Container shell

```bash
bin/audit-container-shell
bin/audit-container-shell --forward-credentials
```

This opens an interactive Docker shell with the supported backend CLIs
installed and the repository mounted. Use it when you want a reproducible
Linux audit environment or to run the image-mode test suite. Credentials
are not forwarded unless you pass `--forward-credentials`.

### `bin/probe` — run one testcase

```bash
bin/probe "$RESULTS/scratch-1/testcase.html"
bin/probe --confirm "$RESULTS/scratch-1/testcase.html"
bin/probe --dry-run "$RESULTS/scratch-1/testcase.dat"
PROBE_SANITIZER=ubsan bin/probe "$RESULTS/scratch-1/testcase.dat"
```

`bin/probe` is the execution gate for testcases. It discovers the active
target by walking up from the testcase to
`output/<slug>/<backend>/results/.session-env`, reads `target.toml`,
chooses the right browser / JS / generic runner, and saves sanitizer or
runner output beside the testcase as
`<testcase>.asan.txt`.

Use `--dry-run` first when checking a new target config or `HARNESS:`
setup; it prints the resolved mode, sanitizer, output path, and command
without executing the testcase. Use `--confirm` only after an initial
crash or diagnostic, when you need the 5-run reproducibility check.

Testcase headers provide the audit linkage:

```text
TARGET: path/to/file.c:Function:123
HYPOTHESIS-ID: H1
CATEGORY: bounds
MODE: generic          # optional; auto/browser/js/generic/js-diff
HARNESS: harness.c     # optional sibling API harness
```

The default sanitizer is the first entry in `[sanitizer].enabled`, or
`runner` when the target is findings-only with `enabled = []`. Override a
single run with `PROBE_SANITIZER=asan|ubsan|msan|tsan|race|runner`.
Advanced probe escape hatches are listed in
[Environment](environment.md#probe-selection).

## Testcase development

These commands help an operator or agent avoid duplicate work, seed a
testcase from existing inputs, and inspect probe history without opening
large scratch directories.

```bash
TARGET_ROOT="targets/$TARGET" RESULTS_DIR="$RESULTS" bin/find-seed <path.ext>[:<Function>] [max_results]
bin/scratch-status "$RESULTS/scratch-1"
RESULTS_DIR="$RESULTS" bin/scratch-search <pattern>
bin/probe-history --results-dir "$RESULTS" scratch-1/testcase.html
bin/probe-history --results-dir "$RESULTS" --hypothesis-id H1
```

- `bin/find-seed` searches the target tree for in-tree tests or sample
  inputs likely to exercise a file or function.
- `bin/scratch-status` summarizes testcase/output pairs in one scratch
  directory and flags orphan testcases that have not been probed.
- `bin/scratch-search` searches audit scratch/corpus/crash artifacts for
  prior attempts, hypothesis IDs, harness names, or symbols.
- `bin/probe-history` reads `state/runs.jsonl` and shows prior verdicts
  for a testcase, hypothesis, card, agent, or verdict.

Coverage helpers are useful when you need to debug why a testcase is
missing the intended code:

```bash
bin/hits --testcase "$RESULTS/scratch-1/testcase.html" --want <symbol-regex> --mode browser
bin/hits --testcase "$RESULTS/scratch-1/testcase.js" --want <symbol-regex> --mode js
bin/coverage-summary --results-dir "$RESULTS"
```

- `bin/hits` runs a testcase against the coverage-instrumented ASan build
  and reports whether the requested symbol was reached.
- `bin/coverage-summary` aggregates per-agent edge journals into a
  subsystem coverage summary. It is only useful after coverage data
  exists for the run.

### Capped source-reading wrappers

Agents read source through wrappers that cap output size so a single
search cannot flood a prompt. They are plain CLI tools, and they are
just as useful to an operator poking at a large target tree:

```bash
bin/rg-safe <pattern> targets/$TARGET/src     # rg with line + byte caps
bin/peek targets/$TARGET/src/parser.c 200 260 # clamped line-range view
bin/peek <pattern> targets/$TARGET/src/file.c # clamped grep-with-context
bin/show-patch <commit> [paths...]            # git show with narrow context + caps
```

Each prints a footer when a cap fires, so truncation is visible
rather than silent. The caps are tunable — see
[Environment](environment.md#context-and-ranking-budgets).

### `bin/audit-recon` — breadth-first survey of the source tree

`bin/audit` runs this automatically on the first audit of a given
target commit; the results are cached and re-used until the source
changes. You only need to invoke it directly if you want a survey
without launching a deep audit, or to refresh recon on demand.

```bash
bin/audit-recon --target "$TARGET" --backend "$BACKEND"
bin/audit-recon --target "$TARGET" --backend "$BACKEND" --timeout 2700
```

Outputs:

- `output/$TARGET/$BACKEND/results/recon-findings.md` — human read.
- `output/$TARGET/$BACKEND/results/recon-hypotheses.jsonl` — the
  candidate findings (validator votes merged in). Seeds `bin/audit`'s
  work queue at cold start.

See [Recon discovery](../guides/recon-discovery.md) for the recon
shape, validator gate, and auto re-roll on all-AUDIT-CLEAN runs.

For focused strategy smoke validation, pass `--strategy S1` through
`--strategy S8` to `bin/audit`, not to `bin/audit-recon`. Recon has
its own scoping flags (`--scope`, `--path`, `--concurrency`,
`--validate`, and `--no-reroll`) and always emits work cards for the
later deep audit.

## Mid-run checkpoint

`bin/state` exposes a number of slim views into the structured
state. The single most useful is `show-recent` — it bundles the
agent's recent claims, hypotheses, and probe runs in one call:

```bash
bin/state --results-dir "$RESULTS" show-recent --agent 1
```

The narrower views are also available:

```bash
bin/state --results-dir "$RESULTS" recent-runs    --agent 1
bin/state --results-dir "$RESULTS" recent-claims  --agent 1
bin/state --results-dir "$RESULTS" recent-notes   --agent 1
bin/state --results-dir "$RESULTS" resume         --agent 1
bin/state --results-dir "$RESULTS" list-cards
bin/state --results-dir "$RESULTS" list-crashes
bin/state --results-dir "$RESULTS" list-findings
bin/state --results-dir "$RESULTS" explain-queue
bin/state --results-dir "$RESULTS" show-card     <id>
bin/state --results-dir "$RESULTS" show-crash    <id>
bin/state --results-dir "$RESULTS" show-finding  <id>
```

What each one shows:

- `show-recent` — agent's recent claims + hypotheses + probe runs.
- `recent-runs` — one pipe-delimited row per recent testcase verdict.
- `recent-claims` / `recent-notes` — narrower listings of those streams.
- `resume` — the compact next-iteration brief for one agent.
- `list-cards` / `list-crashes` / `list-findings` — slim JSONL listings.
- `explain-queue` — why the top-N cards in the queue scored where they did.
- `show-card` / `show-crash` / `show-finding` — full compact JSON for one item.

## Result review

Open the generated HTML artifacts in a browser. Start with the
highest-level page that exists for the scope you are reviewing:

```text
output/$TARGET/CRASH-CLUSTERS.html
output/$TARGET/FINDING-CLUSTERS.html
$RESULTS/crashes/CRASH-CLUSTERS.html
$RESULTS/findings/FINDING-CLUSTERS.html
$RESULTS/crashes-rejected/INDEX.html
```

Then follow the linked cluster member to the report:

```text
$RESULTS/crashes/CRASH-*/REPORT.html
$RESULTS/findings/FIND-*/report.html
```

Use the target-level cluster HTML files when comparing multiple
backends. Use the backend-local cluster HTML files when reviewing one
run. `crashes-rejected/INDEX.html` explains rejected crash candidates
so the next operator does not repeat already-triaged work.

These commands are for regenerating or enriching artifacts, not for
reading the normal review output:

```bash
bin/export-repro CRASH-001-1 --slug "$TARGET"
bin/reachability --report "$RESULTS/crashes/CRASH-001-1/" --severity-only
bin/validate-finding --finding "$RESULTS/findings/FIND-001" --target-path "targets/$TARGET" --backend "$BACKEND"
bin/enrich-report "$RESULTS/crashes/CRASH-001-1/report.md" --slug "$TARGET"
bin/find-crash-testcase "$RESULTS/crashes/CRASH-001-1"
bin/cluster-crashes "$RESULTS"
bin/cluster-findings "$RESULTS"
```

- `bin/export-repro` creates the maintainer bundle for an accepted
  crash.
- `bin/reachability --severity-only` recomputes severity without
  external queries. Omit `--severity-only` only when public caller
  search is intended. The caller search filters by the target's
  language (derived from the target tree; override with `--language`,
  or `--language none` to disable the filter).
- `bin/validate-finding` — re-runs the finding substance gate on a
  candidate report or recon row.
- `bin/enrich-report` — inlines source snippets, patch excerpts, and
  report metadata into a crash/finding report. `--source-root`,
  `--upstream-url`, and `--pinned-rev` override the snippet source and
  source-link rewrites; `--quiet` suppresses the changed/unchanged
  line.
- `bin/find-crash-testcase` — prints the testcase path selected from a
  crash directory, useful when an old artifact layout is ambiguous.
- `bin/cluster-crashes` / `bin/cluster-findings` — group reports that
  share a root cause, write the `CRASH-CLUSTERS` /
  `FINDING-CLUSTERS` summaries, and stamp `Cluster:` lines into each
  member report. Both run automatically during triage; rerun them
  after manually editing reports or moving artifacts. Pass a backend
  results dir for one run, or `output/<target>` for the cross-backend
  rollup.
- `bin/show-exclusions "$RESULTS"` — one read-only view of what was
  kept vs. excluded and why: active crashes, confirmed findings,
  rejected candidates with reasons, and fuzz-crash noise.

An empty `crashes/` directory is normal after a short smoke run. A
rejected index with clear reasons is useful output too — it tells
the next operator what has already been evaluated.

Always inspect `findings/FINDING-CLUSTERS.html` as well. A run may
produce a concrete security finding without producing a sanitizer
crash.

## Maintenance

```bash
bash tests/run-tests.sh
bash tests/run-tests.sh --image ubuntu:24.04
bash tests/run-tests.sh --image fedora:latest

bin/docs build
bin/docs serve

# Wipe state, logs, or both for a clean restart on the same target.
bin/cleanup_state --target "$TARGET" --backend "$BACKEND"
bin/cleanup_logs  --target "$TARGET" --backend "$BACKEND"
```

Both cleanup helpers accept `--backend NAME` for one backend or
`--backends a,b,c` for a comma-separated set, and `--dry-run` to
print what would be removed without touching anything. With no
`--target` they sweep every target under `output/`, so prefer an
explicit target. `cleanup_state` preserves every crash, finding,
rejected artifact, corpus seed, and cross-session memory file by
default — it removes the transient queue and scratch state only.
To adjust what survives, `--keep <name>` (repeatable) protects an
extra directory or file, `--keep-only <csv>` replaces the default
preserve list outright, and `--output-root <path>` points both
helpers at a non-default output root.

Run the test suite before merging changes to the harness or to
docs that describe its behaviour. Use image mode for Linux
portability checks: it mounts the repository in a clean container,
installs the baseline dependencies for apt, dnf, or microdnf/yum
images, and runs the same suite under Docker (see
[Prerequisites](../getting-started/prerequisites.md#4-verify-the-harness)).

Use `bin/docs build` for the same strict MkDocs build CI expects, and
`bin/docs serve` for a local preview.

Benchmarking is a separate operator workflow:

```bash
bin/benchmark --target "$TARGET" --backend "$BACKEND"
```

It compares the shipped harness against a direct-prompt baseline under
isolated `--experiment` output directories. Use it for harness
evaluation, not routine target auditing.

After changing a severity or clustering algorithm, re-derive an existing
run's results — severity, crash/finding dedup, and the rollup tables —
without re-auditing or any API calls:

```bash
bin/benchmark --target "$TARGET" --backend "$BACKEND" --regenerate
```

With `--target`, `--regenerate` reuses `--run-id` / `BENCHMARK_RUNID` (or the
most recent run when neither is set). With no `--target` it re-derives every
run under the bench root — all targets and backends — and rebuilds the full
cross-backend page. Either way it refreshes `benchmark-result.{md,html}` and
the cluster reports and does not rebuild each crash's `export-repro` report
bundle. See [Benchmarking](../concepts/benchmark.md#regenerating-results-after-code-changes).

## Helpers the harness runs for you

The remaining commands in `bin/` are invoked by the harness itself.
You rarely run them by hand, but knowing what each one is keeps a
directory listing from being mysterious:

| Command | Invoked by | What it does |
| --- | --- | --- |
| `bin/auto-build-script` | `setup-target --bootstrap` | Converges on a working sanitizer build recipe via an LLM and writes it to `targets/<target>/.audit/build.sh`. |
| `bin/auto-repair-target-toml` | triage, after repeated C/C++ harness build failures | Proposes a conservative additive repair to `includes` / `defines` / `link_libs`, with a `target.toml.bak.<timestamp>` backup. Disable with `TARGET_TOML_AUTO_REPAIR=0`. |
| `bin/rank-work` | `bin/audit` | Builds and ranks the concrete work cards agents claim. |
| `bin/patch-cards` | `bin/audit` | Builds S1 prior-fix cards from the target's recent fix commits. |
| `bin/peer-fix-cards` | `bin/audit` | Builds S6 cards from the `[s6_peers]` projects in `target.toml`. |
| `bin/run-asan`, `bin/run-ubsan`, `bin/run-msan`, `bin/run-tsan` | `bin/probe` | Per-sanitizer single-shot execution wrappers (browser, JS, generic, and fuzz modes). |
| `bin/run-sanitizer-multi` | `bin/probe --confirm`, `export-repro` | Multi-run normalizer (default 5 runs, `SANITIZER_RUNS` overrides) that measures the reproduction rate. `bin/run-asan-multi` is a compatibility shim forwarding to it. |
| `bin/triage-fuzz-crashes` | triage | Triages libFuzzer artifacts under `fuzz-crashes/` into a single `fuzz-leads.md` agents can pick leads from. |
| `bin/render-md` | triage, clustering, benchmark | Renders a markdown report or index to its styled `.html` sibling. |
