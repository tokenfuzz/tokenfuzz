# Environment Variables

Most users can run TokenFuzz without setting any environment
variables. The defaults are tuned for everyday use.

Reach for the knobs below when you need a predictable agent mix, a
different timeout policy, a specific LLVM path, or a particular model.
The harness has more internal toggles than these — they cover one-off
migration, harness debugging, and display formatting, and are not
listed here on purpose. If you find yourself wanting one, read the
source.

## Agent counts

| Variable | Default | Purpose |
| --- | --- | --- |
| `NUM_AGENTS` | auto (`3`) | Flat worker count for generic targets. On browser targets, setting it overrides the browser/shell split. |
| `BROWSER_AGENTS` | `1` | Number of browser-mode agents for browser targets. |
| `SHELL_AGENTS` | `2` | Number of JS shell agents for browser targets. |

`auto` means three workers in the normal case:

- generic targets: `NUM_AGENTS=3`, a flat pool of three generic
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

Do not use shell `timeout` directly in audit workflows. The
harness timeout helpers keep behaviour consistent across macOS
and Linux.

## Per-sanitizer timeouts

UBSan, MSan, and TSan have their own equivalents of `ASAN_TIMEOUT` /
`FUZZ_ASAN_TIMEOUT` plus a third knob for fuzz-repro runs. Reach for
these when one sanitizer is dramatically slower or faster than ASan
on your target.

| Variable | Default | Purpose |
| --- | --- | --- |
| `ASAN_FUZZ_REPRO_TIMEOUT` | `20` | ASan timeout for fuzz-repro runs. |
| `UBSAN_TIMEOUT` | browser/generic `15`; JS `10` | UBSan timeout for normal runs. |
| `UBSAN_TIMEOUT` (fuzz mode) | `600` | UBSan fuzz-mode timeout. Unlike ASan/MSan/TSan there is no `FUZZ_UBSAN_TIMEOUT`; fuzz-mode reuses `UBSAN_TIMEOUT` (default `600` here). |
| `UBSAN_FUZZ_REPRO_TIMEOUT` | `20` | UBSan timeout for fuzz-repro runs. |
| `MSAN_TIMEOUT` | generic `15`; JS `10` | MSan timeout for normal runs. |
| `FUZZ_MSAN_TIMEOUT` | `600` | MSan timeout for fuzz-mode runs. |
| `MSAN_FUZZ_REPRO_TIMEOUT` | `20` | MSan timeout for fuzz-repro runs. |
| `TSAN_TIMEOUT` | generic `15`; JS `10` | TSan timeout for normal runs. |
| `FUZZ_TSAN_TIMEOUT` | `600` | TSan timeout for fuzz-mode runs. |
| `TSAN_FUZZ_REPRO_TIMEOUT` | `20` | TSan timeout for fuzz-repro runs. |

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
| `CLAUDE_MODEL_DEFAULT` | `claude-opus-4-8` | Default model name passed to the `claude` CLI when `--model` is omitted. |
| `CODEX_MODEL_DEFAULT` | `gpt-5.5` | Default model name passed to the `codex` CLI when `--model` is omitted. |
| `GEMINI_MODEL_DEFAULT` | `gemini-3.1-pro-preview` | Default model for the `gemini` backend. Only consulted with `USE_GEMINI_CLI=1`; the default Antigravity CLI (`agy`) has no launch-time model flag. |
| `CODEX_OSS_MODEL_DEFAULT` | (empty) | Default for lower-level `oss` backend helpers. Normal `bin/audit --backend oss` runs should pass `--model <ollama-model>` explicitly. |
| `AUDIT_BACKEND` | (none) | Alternative to `--backend`. Same accepted values: `all`, `claude`, `codex`, `gemini`, `oss`. |
| `USE_GEMINI_CLI` | `0` | Set to `1` to drive the `gemini` backend through Google Gemini CLI (`gemini`) instead of the default Antigravity CLI (`agy`). |

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

## Probe selection

| Variable | Default | Purpose |
| --- | --- | --- |
| `PROBE_SANITIZER` | first enabled sanitizer, or `runner` when `enabled = []` | Force one probe to use `asan`, `ubsan`, `msan`, `tsan`, `race`, or `runner`. |

## Context and ranking budgets

Caps on how much source the agent and the ranker can pull into one
turn. Raise them when a target's real-world functions or queue depth
genuinely need more room; they exist to keep prompts and queues
bounded by default.

| Variable | Default | Purpose |
| --- | --- | --- |
| `RG_CAP` | `200` | Line cap used by `bin/rg-safe`. |
| `RG_BYTES` | `131072` | Byte cap used by `bin/rg-safe`. |
| `PEEK_MAX_LINES` | `200` | Maximum range shown by `bin/peek` range mode. |
| `PEEK_GREP_AFTER` | `30` | Clamp for `bin/peek -A`. |
| `PEEK_GREP_BEFORE` | `8` | Clamp for `bin/peek -B`. |
| `RANK_WORK_LIMIT` | `120` | Number of work cards produced by the ranker. |
| `STATE_RESUME_RECENT_LIMIT` | `5` | Recent rows included in compact resume output. |

## Container build directories

| Variable | Default | Purpose |
| --- | --- | --- |
| `AUDIT_BUILD_SUFFIX` | empty outside `bin/audit-container-shell`; image-derived inside it | Suffix appended to sanitizer build directories (`build-asan`, `build-ubsan`, `build-msan`, `build-tsan`) so per-image builds don't share trees. |

`bin/audit-container-shell` sets this automatically. Relative
`target.toml` paths whose first segment is one of those four resolve
through the suffix; absolute paths and already-distinct directories
like `build-asan-other/` are left literal.

## Peer mining (S6)

The S6 strategy mines peer projects' VCS history for security-shaped
fix commits. Commits larger than these bounds are skipped as
refactors/features.

| Variable | Default | Purpose |
| --- | --- | --- |
| `PEER_VCS_MAX_FILES` | `10` | Maximum files changed for a commit to count as a fix candidate. |
| `PEER_VCS_MAX_LINES` | `400` | Maximum insertions + deletions for a fix candidate. |

The defaults are deliberately generous — a real fix usually also
carries a regression test, header change, and changelog entry, and
`git --shortstat` counts all of it. Too tight a bound silently drops
genuine fixes. Candidate volume is capped separately, so widening
these does not multiply LLM-call count. Raise them when a target's
upstream fixes land in larger commits (e.g. `PEER_VCS_MAX_LINES=1000`
for projects with bulky test-data files); set them very high to
disable the size filter entirely.

## Triage

| Variable | Default | Purpose |
| --- | --- | --- |
| `REACHABILITY_AUTO` | `1` | Controls post-crash reachability/severity processing. The default (`1`, alias `external`) runs **full** reachability, which queries public Sourcegraph / GitHub for callers — target symbol names leave the host. Set `local` or `severity-only` to recompute severity from cached `reachability.json` only, with no external network calls. `0` disables reachability/severity post-processing entirely. |
