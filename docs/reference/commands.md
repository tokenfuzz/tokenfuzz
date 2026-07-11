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
| `--build` | For native targets, build now instead of waiting for audit preflight. For supported language targets, explicitly run the ecosystem build step (audit preflight does not run it automatically). |
| `--no-update` | Do not pull or fetch an existing VCS checkout. |
| `--force` | Regenerate generated config, including suggested threat-model and peer sections. Review local edits first. |
| `--no-llm-config` | Skip best-effort model suggestions for the threat model and S6 peers. |

The suggestion steps can also be rerun independently:

```bash
bin/suggest-threat-model "$TARGET" --apply --force
bin/suggest-peers "$TARGET" --apply --force
```

See [Add a target](../getting-started/add-a-target.md) for the workflow and
[Target config](target-toml.md) for field definitions.

## Run an audit

```bash
bin/audit --target "$TARGET" --backend "$BACKEND" 1
bin/audit --target "$TARGET" --backend "$BACKEND" 10
bin/audit --target "$TARGET" --backend "$BACKEND"
```

The optional final number is the iteration limit. `1` is a smoke test with one
worker and no recon seeding. Omit the number, or pass `0`, for a continuous run.

Common flags:

| Flag | Meaning |
| --- | --- |
| `--model <name>` | Override the backend's configured model. Required for `oss`. |
| `--strategy S1` … `--strategy S8` | Pin one investigation strategy and suspend rotation. |
| `--skip-recon` | Skip cold-start recon for this run. |
| `--enable-memory` | Allow the backend's cross-run learned memory. It is disabled by default to prevent stale conclusions from steering later audits. |
| `--new-target <slug>` | Generate starter config and exit without starting an audit. |

Omitting `--backend`, or using `--backend all`, cycles installed hosted
backends in `claude → codex → gemini → grok` order. Each writes its own result
tree. Use an explicit backend and model in reproducibility notes.

Cross-run learned memory is deliberately different from project instructions
and TokenFuzz state. `AGENTS.md`, the prompt, and `state/*.jsonl` still apply
when learned memory is off. Benchmarks always keep learned memory off.

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
- Use `--confirm` only after the first diagnostic; it performs the multi-run
  reproduction check and can file a stable crash bundle.
- Use `--dry-run` to inspect mode, sanitizer, output path, and resolved command
  without executing target code.
- Use `--mode browser|js|generic|js-diff` only when automatic mode detection is
  wrong or the testcase deliberately requests differential execution.

Every testcase begins with native-comment headers:

```text
TARGET: path/to/file.c:Function:123
HYPOTHESIS-ID: H1
CATEGORY: bounds
MODE: generic          # optional
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

## Run recon separately

```bash
bin/audit-recon --target "$TARGET" --backend "$BACKEND"
bin/audit-recon --target "$TARGET" --backend "$BACKEND" \
  --scope path --path src/parser
```

`bin/audit` normally runs recon automatically once per target revision. Invoke
`bin/audit-recon` directly to inspect a breadth-first survey without launching
the deep audit, or to choose an explicit scope. Its main outputs are
`recon-findings.md`, `recon-hypotheses.jsonl`, and candidate directories under
`recon/`. They are leads, not verified findings. See
[Recon discovery](../guides/recon-discovery.md).

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
bin/export-benchmark --target "$TARGET" --backend "$BACKEND" --format zip
```

See [Benchmarking](../concepts/benchmark.md) for experiment design, resumption,
and regeneration.

## Internal entry points

Commands such as `bin/rank-work`, `bin/patch-cards`, `bin/peer-fix-cards`,
`bin/run-asan`, `bin/run-sanitizer-multi`, `bin/triage-fuzz-crashes`, and
`bin/render-md` are orchestration components. Normal audits invoke them for
you. Their CLI remains available for development and diagnosis, but it is not a
stable operator workflow; read the command source and tests before calling one
directly.
