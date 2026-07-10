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
| `AGENT_ROLES` | auto | Comma-separated per-agent role list (e.g. `analysis,reproduce,analysis`) that overrides the automatic role split. Its length must match the agent count. |

`auto` means three workers in the normal case:

- generic targets: `NUM_AGENTS=3`, a flat pool of three generic
  workers;
- browser targets: `BROWSER_AGENTS=1` and `SHELL_AGENTS=2`, for three
  workers total.

Set `NUM_AGENTS=N` when you want a generic target to run exactly `N`
parallel workers. For browser targets, prefer `BROWSER_AGENTS` and
`SHELL_AGENTS` when you care about the browser-vs-shell mix.

## Session length and loop control

| Variable | Default | Purpose |
| --- | --- | --- |
| `AGENT_TIMEOUT` | `7200` | Per-agent session wall-clock ceiling in seconds (120 min). A runaway guard — a healthy agent finishes its iteration well before this. |
| `MAX_DRY_SESSIONS` | `10` | Stop a continuous (no iteration count) run after this many consecutive iterations with no new confirmed result. Auto-clamped upward if it is too low to give per-agent strategy rotation a fair chance. |

Cross-run agent memory is a separate control. It is **off by default**;
opt back in with the `--enable-memory` flag (or `TOKENFUZZ_MEMORY_ENABLED=1`).
See [Cross-run memory is off by default](commands.md#cross-run-memory-is-off-by-default)
for why, and the per-backend mechanics.

## Timeouts

| Variable | Default | Purpose |
| --- | --- | --- |
| `ASAN_TIMEOUT` | browser/generic/xpcshell `15`; JS `10` | ASan timeout for normal runs. |
| `FUZZ_ASAN_TIMEOUT` | `600` | ASan timeout for fuzz-mode runs. |

UBSan, MSan, and TSan follow the same pattern when one sanitizer is
dramatically slower or faster than ASan on your target:
`UBSAN_TIMEOUT`, `MSAN_TIMEOUT`, and `TSAN_TIMEOUT` mirror
`ASAN_TIMEOUT`, and `FUZZ_MSAN_TIMEOUT` / `FUZZ_TSAN_TIMEOUT` mirror
`FUZZ_ASAN_TIMEOUT` (UBSan reuses `UBSAN_TIMEOUT` for fuzz mode).
Most runs never need any of them.

Do not use a platform `timeout` executable directly in audit workflows.
`lib/timeout.py` keeps process-group termination and RSS limits consistent
across macOS and Linux.

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
| `BROWSER_SANITIZER_RUN_BUDGET` | `25` | Maximum sanitizer invocations per browser agent per iteration. |
| `SHELL_SANITIZER_RUN_BUDGET` | `60` | Maximum sanitizer invocations per shell agent per iteration. |
| `SANITIZER_RUN_BUDGET_PER_ITERATION` | (unset) | Convenience override that sets **both** budgets above to one value. |
| `SANITIZER_RUNS` | `5` | Number of runs `bin/run-sanitizer-multi` uses for `bin/probe --confirm` and export, to measure the reproduction rate. |
| `SANITIZER_DIGEST_HEAD` | `80` | Clean-run lines retained from the start of sanitizer output. Set `0` to disable clean-run truncation. |
| `SANITIZER_DIGEST_TAIL` | `120` | Clean-run lines retained from the end of sanitizer output. Set `0` to disable clean-run truncation. |
| `SANITIZER_NO_DIGEST` | unset | Preserve complete sanitizer output in the agent transcript for one probe. Full output is always preserved in the diagnostic file. |

The budget controls protect long sessions from spending too much sanitizer
time on a single agent iteration. The individual runners
use their own timeout knobs and are normally invoked for targeted
follow-up rather than the default probe budget.

## Model selection

| Variable | Default | Purpose |
| --- | --- | --- |
| `CLAUDE_MODEL_DEFAULT` | `claude-opus-4-8` | Default model name passed to the `claude` CLI when `--model` is omitted. |
| `CODEX_MODEL_DEFAULT` | `gpt-5.5` | Default model name passed to the `codex` CLI when `--model` is omitted. |
| `GEMINI_MODEL_DEFAULT` | `gemini-3.1-pro-preview` | Default model for the `gemini` backend. Used by both the default Antigravity CLI (`agy`, mapped to its `agy models` label) and Google Gemini CLI (`USE_GEMINI_CLI=1`). |
| `GROK_MODEL_DEFAULT` | `grok-build-0.1` | Default model name passed to the Grok Build CLI when `--model` is omitted. |
| `AUDIT_BACKEND` | (none) | Alternative to `--backend`. Same accepted values: `all`, `claude`, `codex`, `gemini`, `grok`, `oss`. |
| `USE_GEMINI_CLI` | `0` | Set to `1` to drive the `gemini` backend through Google Gemini CLI (`gemini`) instead of the default Antigravity CLI (`agy`). |
| `GEMINI_API_KEY` / `GOOGLE_API_KEY` | (none) | Required for the `USE_GEMINI_CLI=1` path when memory is off; the harness fails fast if neither is set. Not needed for the default `agy` path, which uses its own login. |
| `XAI_API_KEY` | (none) | API key used by the Grok Build CLI. `bin/audit-container-shell --forward-credentials` forwards it into the container. |
| `GROK_BIN` | `grok` | Grok Build binary used by `--backend grok` when it is not on `PATH` under the default name. |
| `AUDIT_LOCAL_BASE_URL` | `http://127.0.0.1:8000/v1` | OpenAI-compatible endpoint for `--backend oss`. `/v1` is appended automatically when omitted. Set this to `http://127.0.0.1:11434/v1` for Ollama. |
| `AUDIT_LOCAL_API_KEY` | `EMPTY` | API key sent to the local OpenAI-compatible endpoint. Set it only if your server requires a token. |
| `OPENCODE_BIN` | `opencode` | OpenCode binary used by `--backend oss` when it is not on `PATH` under the default name. |

The hosted model default chain is: `--model` on the command line, then
the matching `*_MODEL_DEFAULT` environment variable, then
`config/models.toml`. The table above shows the shipped
`config/models.toml` values.
`--model` wins over hosted/backend-local model
defaults for backends that accept a launch-time model. For `oss`, pass
`--model` every time so the harness can match the exact served model id
from the local provider's `/v1/models` endpoint. For `gemini` on the
default Antigravity CLI (`agy`), `--model` takes a config slug or an
exact `agy models` label, which the harness maps and a preflight
validates; under `USE_GEMINI_CLI=1` it is forwarded to the Google Gemini
CLI directly.

### Gemini health checks

The Gemini backend watches live output for sustained quota failures. The
default Antigravity CLI path also detects its two known post-generation stall
states. These limits normally need no adjustment.

| Variable | Default | Purpose |
| --- | --- | --- |
| `GEMINI_WATCHDOG_POLL_SECS` | `10` | Seconds between backend-health checks. |
| `GEMINI_QUOTA_WINDOW_LINES` | `400` | Recent raw-log lines inspected for a quota-dominated retry loop. |
| `GEMINI_QUOTA_MIN_429` | `10` | HTTP 429 retry lines, with no assistant progress, required before the run is stopped as quota-exhausted. |
| `AGY_DRIP_GRACE_SECS` | `60` | Grace period after Antigravity reports that output streaming stopped. Set `0` to disable this check. |
| `AGY_IDLE_WINDOW_SECS` | `600` | Recent Antigravity log window checked for heartbeat-only activity. |
| `AGY_IDLE_CONFIRM_POLLS` | `2` | Consecutive heartbeat-only checks required before termination. Set `0` to disable this check. |

On a quota stop, the harness writes `.quota-exhausted` in the agent scratch
directory or benchmark cell. The outer audit/benchmark loop uses the raw
provider status and this marker to classify the interrupted run.

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
| `RG_BYTES` | `51200` | Byte threshold for `bin/rg-safe` head/tail output. Set `0` to disable clipping. |
| `PEEK_GREP_AFTER` | `30` | Clamp for `bin/peek -A`. |
| `PEEK_GREP_BEFORE` | `8` | Clamp for `bin/peek -B`. |
| `RANK_WORK_LIMIT` | `120` | Number of work cards produced by the ranker. |

## Container build directories

| Variable | Default | Purpose |
| --- | --- | --- |
| `AUDIT_BUILD_SUFFIX` | empty outside `bin/audit-container-shell`; image-derived inside it | Suffix appended to sanitizer build directories (`build-asan`, `build-ubsan`, `build-msan`, `build-tsan`) so per-image builds don't share trees. |

`bin/audit-container-shell` sets this automatically. Relative
`target.toml` paths whose first segment is one of those four resolve
through the suffix; absolute paths and already-distinct directories
like `build-asan-other/` are left literal.

The container helper also honours two runtime overrides, both with flag
equivalents:

| Variable | Default | Purpose |
| --- | --- | --- |
| `CONTAINER_RUNTIME` | `docker` | Container engine `bin/audit-container-shell` invokes (e.g. `podman`). |
| `AUDIT_DOCKER_RUNTIME` | (unset) | OCI runtime passed to `docker run` (e.g. `runsc` for gVisor). Same as `--docker-runtime`; `--gvisor` is shorthand for `runsc`. |

## Peer mining (S6)

The S6 strategy mines peer projects' VCS history for security-shaped
fix commits. Commits larger than these bounds are skipped as
refactors/features.

| Variable | Default | Purpose |
| --- | --- | --- |
| `PEER_VCS_MAX_FILES` | `10` | Maximum files changed for a commit to count as a fix candidate. |
| `PEER_VCS_MAX_LINES` | `400` | Maximum insertions + deletions for a fix candidate. |

The defaults are deliberately generous — a real fix usually also
carries a regression test and changelog entry. Raise them when a
target's upstream fixes land in larger commits; widening them does
not multiply LLM-call count, since candidate volume is capped
separately.

## Triage

| Variable | Default | Purpose |
| --- | --- | --- |
| `CRASH_PROMOTION_PENDING_MAX` | `10` | Consecutive triage passes allowed for an incomplete crash or failed maintainer-bundle export. On expiry, the preserved directory moves to `crashes-rejected/` with a possible-false-negative warning. Set `0` for immediate rejection. |
| `CRASH_TRIGGER_GATE` | `1` | Run the source-grounded trigger-provenance gate before promotion. Set `0` only to bypass it; rejection normally requires two independent disproof-backed votes. |
| `REPORT_GATE_MAX_BYTES` | `262144` | Maximum report bytes sent to one LLM triage gate. Oversize reports use a visible head-and-tail slice and emit a possible-false-negative warning. |
| `FIND_GATE_MAX_PAUSES` | `12` | Maximum provider-limit pauses while draining finding validation at the end of a benchmark cell. |
| `FIND_GATE_PAUSE_MAX_TOTAL` | `21600` | Maximum total seconds a benchmark cell may pause for finding validation. |
| `FIND_GATE_PAUSE_CHUNK` | `1800` | Retry delay when the provider does not report an exact reset time. |
