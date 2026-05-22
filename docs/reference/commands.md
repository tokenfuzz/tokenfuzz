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
Pass `--no-llm-config` to keep the deterministic seed and skip
LLM-backed `[threat_model]` / `[s6_peers]` enrichment.

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
  suggestions.

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
  `--model` is required for `oss`, optional for `claude` and `codex`,
  and supported for `gemini` only when `USE_GEMINI_CLI=1`.
- Start with `1` to verify target config, backend CLI, results
  directory, and state writer before committing to a long run.
- Use `--model` with the `claude` or `codex` backend. The harness
  forwards it to that backend's native model flag. For `oss`,
  `--model` is required and names an already-pulled Ollama model. The
  `gemini` backend uses Antigravity CLI (`agy`) by default, which has no
  launch-time model selector; use `agy`'s interactive `/model` command.
  Set `USE_GEMINI_CLI=1` to use Google Gemini CLI instead; then
  `--model` is forwarded to `gemini`.

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
bin/probe scratch-1/testcase.html
bin/probe --confirm scratch-1/testcase.html
bin/probe --dry-run scratch-1/testcase.dat
PROBE_SANITIZER=ubsan bin/probe scratch-1/testcase.dat
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
bin/hits --testcase scratch-1/testcase.html --want <symbol-regex> --mode browser
bin/hits --testcase scratch-1/testcase.js --want <symbol-regex> --mode js
bin/coverage-summary --results-dir "$RESULTS"
```

- `bin/hits` runs a testcase against the coverage-instrumented ASan build
  and reports whether the requested symbol was reached.
- `bin/coverage-summary` aggregates per-agent edge journals into a
  subsystem coverage summary. It is only useful after coverage data
  exists for the run.

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
- `resume` — the compact context the next agent iteration will pick up.
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
```

- `bin/export-repro` creates the maintainer bundle for an accepted
  crash.
- `bin/reachability --severity-only` recomputes severity without
  external queries. Omit `--severity-only` only when public caller
  search is intended.
- `bin/validate-finding` — re-runs the finding substance gate on a
  candidate report or recon row.
- `bin/enrich-report` — inlines source snippets, patch excerpts, and
  report metadata into a crash/finding report.
- `bin/find-crash-testcase` — prints the testcase path selected from a
  crash directory, useful when an old artifact layout is ambiguous.

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
`--backends a,b,c` for a comma-separated set.

Run the test suite before merging changes to the harness or to
docs that describe its behaviour. Use image mode for Linux
portability checks. It:

- mounts the repository at `/work`;
- installs dependencies for apt, dnf, or microdnf/yum images;
- runs the same suite with Docker.

For Debian / Ubuntu images, the apt dependency set includes the
normal shell, Python, Perl, Git, jq, ripgrep, Mercurial, procps,
`file`, LLVM, and compiler tools, plus `libclang-rt-dev`. On
images with a non-default LLVM major version, install the matching
`libclang-rt-<N>-dev` package before using `--no-install-deps`.

Use `bin/docs build` for the same strict MkDocs build CI expects, and
`bin/docs serve` for a local preview.

Benchmarking is a separate operator workflow:

```bash
bin/benchmark --target "$TARGET" --backend "$BACKEND"
```

It compares the shipped harness against a direct-prompt baseline under
isolated `--experiment` output directories. Use it for harness
evaluation, not routine target auditing.
