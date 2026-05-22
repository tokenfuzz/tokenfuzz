# Environment Variables

Most users can run TokenFuzz without setting any environment
variables. The defaults are tuned for everyday use.

Reach for the knobs below when you need a predictable agent mix, a
different timeout policy, a specific LLVM path, or a particular model.
The [Advanced / internal tuning](#advanced-internal-tuning) section at the end collects the
internal knobs you should not normally touch.

## Agent counts

| Variable | Default | Purpose |
| --- | --- | --- |
| `NUM_AGENTS` | auto (`3`) | Flat worker count for generic targets. On browser targets, setting it overrides the browser/shell split. |
| `BROWSER_AGENTS` | `1` | Number of browser-mode agents for browser targets. |
| `SHELL_AGENTS` | `2` | Number of JS shell agents for browser targets. |

`auto` means three workers in the normal case:

- generic targets: `NUM_AGENTS=3`, a flat pool of three shell-mode
  workers;
- browser targets: `BROWSER_AGENTS=1` and `SHELL_AGENTS=2`, for three
  workers total.

When `NUM_AGENTS` is not set, the orchestrator can reduce the
agent pool if it detects low memory or another audit process.
That keeps unattended sessions from failing because the host is
overloaded.

Set `NUM_AGENTS=N` when you want a generic target to run exactly `N`
parallel workers. For browser targets, prefer `BROWSER_AGENTS` and
`SHELL_AGENTS` when you care about the browser-vs-shell mix.

## Timeouts

| Variable | Default | Purpose |
| --- | --- | --- |
| `ASAN_TIMEOUT` | browser/generic/xpcshell `15`; JS `10` | ASan timeout for normal runs. |
| `FUZZ_ASAN_TIMEOUT` | `600` | ASan timeout for fuzz-mode runs. |

UBSan, MSan, and TSan have the same pair of knobs under their own
prefixes (`UBSAN_TIMEOUT`, `FUZZ_MSAN_TIMEOUT`, …), plus a
`<NAME>_FUZZ_REPRO_TIMEOUT` for fuzz-repro runs. The full matrix is in
[Advanced / internal tuning](#advanced-internal-tuning).

Do not use shell `timeout` directly in audit workflows. The
harness timeout helpers keep behaviour consistent across macOS
and Linux.

## LLVM

| Variable | Default | Purpose |
| --- | --- | --- |
| `LLVM_PREFIX` | auto | Path to LLVM tools such as `clang`, `llvm-symbolizer`, and `sancov`. |

Set this when multiple LLVM installations exist and the harness
picks the wrong one.

Defaults by platform:

- **macOS** — Homebrew LLVM is auto-detected at
  `/opt/homebrew/opt/llvm` and `/usr/local/opt/llvm`.
- **Linux** — the harness searches `LLVM_PREFIX`, common
  `/usr/lib/llvm-*` prefixes, and then `PATH`.

## Probe budgets

| Variable | Default | Purpose |
| --- | --- | --- |
| `BROWSER_ASAN_RUN_BUDGET` | `25` | Maximum ASan invocations per browser agent per iteration. |
| `SHELL_ASAN_RUN_BUDGET` | `60` | Maximum ASan invocations per shell agent per iteration. |

These budgets protect long sessions from spending too much ASan
time on a single agent iteration. UBSan, MSan, and TSan runners
use their own timeout knobs and are normally invoked for targeted
follow-up rather than the default probe budget.

## Model selection

| Variable | Default | Purpose |
| --- | --- | --- |
| `CLAUDE_MODEL_DEFAULT` | `claude-opus-4-7` | Default model name passed to the `claude` CLI when `--model` is omitted. |
| `CODEX_MODEL_DEFAULT` | `gpt-5.5` | Default model name passed to the `codex` CLI when `--model` is omitted. |
| `GEMINI_MODEL_DEFAULT` | `gemini-3.1-pro-preview` | Default model for the `gemini` backend. With `USE_GEMINI_CLI=1`, it is passed to Google Gemini CLI. With the default Antigravity CLI (`agy`), launch-time model flags are not supported; change the actual selected model with `agy`'s interactive `/model` command. |
| `CODEX_OSS_MODEL_DEFAULT` | (empty) | Default for lower-level `oss` backend helpers. Normal `bin/audit --backend oss` runs should pass `--model <ollama-model>` explicitly. |
| `AUDIT_MODEL_PREFLIGHT_OPTIONAL` | `0` | Keep the backend litmus test fail-fast by default. Set to `1` only when a scheduled run should warn and continue after a transient preflight failure. |
| `AUDIT_BACKEND` | (none) | Alternative to `--backend`. Same accepted values: `all`, `claude`, `codex`, `gemini`, `oss`. |

`--model` on the command line wins over hosted/backend-local model
defaults for backends that accept a launch-time model. For `gemini`, it
is supported only with `USE_GEMINI_CLI=1`; the default Antigravity CLI
(`agy`) keeps model selection in its interactive `/model` setting.

## Where to put overrides

For one command:

```bash
ASAN_TIMEOUT=30 bin/audit --target <target> --backend <backend> 1
```

For a shell session:

```bash
export LLVM_PREFIX=/opt/homebrew/opt/llvm
bin/audit --target <target> --backend <backend>
```

Record non-default values in reports or run notes when they
affect reproduction.

## Advanced / internal tuning

The knobs below change harness internals. Most maintainers can ignore
them. Use them only for a specific debugging command, not for routine
agent sessions.

### Full timeout matrix

| Variable | Default | Purpose |
| --- | --- | --- |
| `ASAN_FUZZ_REPRO_TIMEOUT` | `20` | ASan timeout for fuzz-repro runs. |
| `UBSAN_TIMEOUT` | browser/generic `15`; JS `10`; fuzz `600` when unset | UBSan timeout. |
| `UBSAN_FUZZ_REPRO_TIMEOUT` | `20` | UBSan timeout for fuzz-repro runs. |
| `MSAN_TIMEOUT` | generic `15`; JS `10` | MSan timeout for normal runs. |
| `FUZZ_MSAN_TIMEOUT` | `600` | MSan timeout for fuzz-mode runs. |
| `MSAN_FUZZ_REPRO_TIMEOUT` | `20` | MSan timeout for fuzz-repro runs. |
| `TSAN_TIMEOUT` | generic `15`; JS `10` | TSan timeout for normal runs. |
| `FUZZ_TSAN_TIMEOUT` | `600` | TSan timeout for fuzz-mode runs. |
| `TSAN_FUZZ_REPRO_TIMEOUT` | `20` | TSan timeout for fuzz-repro runs. |

### Probe selection

| Variable | Default | Purpose |
| --- | --- | --- |
| `PROBE_SANITIZER` | first enabled sanitizer, or `runner` when `enabled = []` | Force one probe to use `asan`, `ubsan`, `msan`, `tsan`, `race`, or `runner`. |
| `PROBE_ALLOW_DISABLED_SANITIZER` | `0` | Allow `bin/probe` to run a sanitizer not listed in `target.toml`. Use only for trusted local experiments. |
| `PROBE_ALLOW_EXTERNAL_TESTCASE` | `0` | Allow testcase paths outside `RESULTS_DIR/scratch-N/`. |
| `PROBE_ALLOW_EXTERNAL_HARNESS` | `0` | Allow `HARNESS:` paths outside the testcase directory. |

### Context and ranking budgets

| Variable | Default | Purpose |
| --- | --- | --- |
| `RG_CAP` | `200` | Line cap used by `bin/rg-safe`. |
| `RG_BYTES` | `131072` | Byte cap used by `bin/rg-safe`. |
| `PEEK_MAX_LINES` | `200` | Maximum range shown by `bin/peek` range mode. |
| `PEEK_GREP_AFTER` | `30` | Clamp for `bin/peek -A`. |
| `PEEK_GREP_BEFORE` | `8` | Clamp for `bin/peek -B`. |
| `RANK_WORK_LIMIT` | `120` | Number of work cards produced by the ranker. |
| `STATE_RESUME_RECENT_LIMIT` | `5` | Recent rows included in compact resume output. |
| `LLM_DECIDE_MAX_CALLS` | `120` | Per-session/per-agent cap for optional one-shot LLM decisions. `0` disables the cap. Applies only when `LOGDIR` or `LLM_DECIDE_COUNTER_FILE` is set. |
| `LLM_DECIDE_COUNTER_FILE` | derived from `LOGDIR` | Counter path for `LLM_DECIDE_MAX_CALLS`; use this only when you need a custom session scope. |

These defaults are intentionally conservative. Widen them for a
specific debugging command, not for normal agent sessions.

### New-target bootstrap

`bin/setup-target <slug>` and `bin/audit --new-target <slug>` write a
deterministic seed `target.toml`, then run `bin/suggest-threat-model` and
`bin/suggest-peers` to replace the conservative defaults with LLM-suggested
`[threat_model]` / `[s6_peers]` sections. Use
`bin/setup-target <slug> --no-llm-config` when you need the offline path.

| Variable | Default | Purpose |
| --- | --- | --- |
| `AUDIT_NEW_TARGET_BOOTSTRAP` | `1` | Set to `0` to skip the LLM bootstrap and seed offline only. |

Set `AUDIT_NEW_TARGET_BOOTSTRAP=0`, `LLM_DECIDE_DISABLE=1`, or pass
`--no-llm-config` to `bin/setup-target` to keep the deterministic seed and
skip LLM enrichment.

### Container build directories

| Variable | Default | Purpose |
| --- | --- | --- |
| `AUDIT_BUILD_SUFFIX` | empty outside `bin/audit-container-shell`; image-derived inside it | Suffix appended to sanitizer build directories such as `build-asan`, `build-ubsan`, `build-msan`, and `build-tsan`. |

`bin/audit-container-shell` sets this to a short image-derived suffix
so different container images do not share sanitizer build trees.
Relative `target.toml` paths whose first segment is `build-asan`,
`build-ubsan`, `build-msan`, or `build-tsan` resolve through that
suffix. Absolute paths and already-distinct directories such as
`build-asan-other/` are left literal.

### Peer mining (S6)

The S6 strategy mines peer projects' VCS history for security-shaped fix
commits. Commits larger than these bounds are skipped as
refactors/features. The defaults are deliberately generous — a real fix
usually also carries a regression test, header change, and changelog
entry, and `git --shortstat` counts all of it; too tight a bound silently
drops genuine fixes (a false negative). Candidate *volume* is capped
separately, so widening these does not multiply LLM-call count.

| Variable | Default | Purpose |
| --- | --- | --- |
| `PEER_VCS_MAX_FILES` | `10` | Maximum files changed for a commit to count as a fix candidate. |
| `PEER_VCS_MAX_LINES` | `400` | Maximum insertions + deletions for a fix candidate. |

Raise these when a target's real upstream fixes land in larger commits
(e.g. `PEER_VCS_MAX_LINES=1000` for projects with bulky test-data files);
set them very high to effectively disable the size filter.

### Triage knobs

These change what triage does with the artifacts an agent produces.
Defaults are tuned for everyday use — leave them alone unless you
have a specific reason to deviate.

| Variable | Use |
| --- | --- |
| `ASAN_NO_DIGEST=1` | Print full sanitizer output instead of the shortened digest. |
| `REACHABILITY_AUTO=0` | Skip automatic reachability / severity post-processing during triage. |
| `REACHABILITY_AUTO=external` | Opt automatic triage into public caller search — see note below. |
| `CRASH_CONFIRM_AUTO=0` | Bypass LLM confirmation gates during triage. |
| `INDEX_HTML_AUTO=0` | Skip automatic HTML rendering of indexes and reports. |
| `STATE_RESUME_INCLUDE_TRIED=1` | Include recent tried inputs in `bin/state resume`. |
| `TARGET_TOML_AUTO_REPAIR=0` | Disable additive `target.toml` repair after repeated C/C++ harness build failures. |
| `TARGET_TOML_LENIENT=1` | Allow invalid `target.toml` section headers during one-off migration. Strict by default. |
| `REACHABILITY_CACHE_DIR=<path>` | Override public code-search cache location. |

Default automatic triage uses `--severity-only` and does not send
target symbols to public services. Setting
`REACHABILITY_AUTO=external` opts in to public Sourcegraph / GitHub
caller search during automatic triage.
