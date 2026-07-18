# Environment Variables

TokenFuzz is designed to run without a large environment file. Prefer command
flags for choices that belong to one run (`--target`, `--backend`, `--model`,
`--strategy`) and `target.toml` for choices that belong to one target.

The variables below are the operator-facing exceptions: machine capacity,
backend executable locations, local-model connectivity, and toolchain paths.
Variables used only by tests, internal gates, prompt formatting, or migration
code are intentionally not part of the public interface.

## Worker pool

| Variable | Default | Use it for |
| --- | --- | --- |
| `NUM_AGENTS` | unset | Force a flat pool of `N` workers. On a browser target this replaces the browser/shell split. |
| `BROWSER_AGENTS` | `1` | Browser-mode workers when `is_browser = "1"`. |
| `SHELL_AGENTS` | `2` for browsers, `3` otherwise | Shell/generic workers when `NUM_AGENTS` is unset. |
| `AGENT_ROLES` | automatic | Comma-separated `analysis` and `reproduce` roles, one entry per worker. |

A one-iteration smoke test always launches one worker, regardless of these
settings. For a normal browser run, change `BROWSER_AGENTS` and `SHELL_AGENTS`
when the mix matters. Use `NUM_AGENTS` for a simple fixed-size pool:

```bash
NUM_AGENTS=4 bin/audit --target <target> --backend <backend>
```

## Run limits

| Variable | Default | Use it for |
| --- | --- | --- |
| `AGENT_TIMEOUT` | `7200` seconds | Hard wall-clock ceiling for one agent launch. |
| `TURN_SOFT_CAP` | `75` completed commands | Restart a Codex audit session with fresh context after this many shell commands. A newly confirmed crash gets a bounded report-enrichment tail and resumes first if still unfinished. Set `0` to disable. |
| `MAX_DRY_SESSIONS` | `10` | Stop a continuous run after this many dry iterations; the harness may raise a value that would prevent fair strategy rotation. |
| `ASAN_AUTOENFORCE_MAX` | `3` | Maximum orphan testcases the post-iteration pass probes automatically. Set `0` to report them without running them. |
| `ASAN_AUTOENFORCE_TIMEOUT` | `30` seconds | Per-testcase ceiling for the orphan enforcement probe. |

The positional iteration count is the clearer way to bound an ordinary run:

```bash
bin/audit --target <target> --backend <backend> 10
```

## Model selection

Use `--backend` and `--model` for reproducible commands. Environment overrides
are most useful in a shared shell or when a backend binary is outside `PATH`.

| Variable | Default | Use it for |
| --- | --- | --- |
| `AUDIT_BACKEND` | `all` | Backend used when `--backend` is omitted. |
| `CLAUDE_MODEL_DEFAULT` | `config/models.toml` | Default Claude model. |
| `CODEX_MODEL_DEFAULT` | `config/models.toml` | Default Codex model. |
| `GEMINI_MODEL_DEFAULT` | `config/models.toml` | Default Gemini model. |
| `GROK_MODEL_DEFAULT` | `config/models.toml` | Default Grok model. |
| `CLAUDE_BIN` | `claude` | Claude CLI executable. |
| `CODEX_BIN` | `codex` | Codex CLI executable. |
| `GEMINI_BIN` | `agy` or `gemini` | Gemini backend executable. |
| `GROK_BIN` | `grok` | Grok Build executable. |
| `OPENCODE_BIN` | `opencode` | OpenCode executable for `--backend oss`. |
| `USE_GEMINI_CLI` | `0` | Use Google Gemini CLI instead of the default Antigravity CLI. |
| `AUDIT_MODEL_PREFLIGHT` | `1` | Launch the selected model once through the real agent path before starting. Set `0` only for an intentionally offline/mock run. |
| `AUDIT_MODEL_PREFLIGHT_TIMEOUT` | `60` seconds | Ceiling for each model preflight attempt. |
| `AUDIT_MODEL_PREFLIGHT_ATTEMPTS` | `3` | Number of model preflight attempts. |
| `LLM_DECISION_TIMEOUT` | `45` seconds | Override the per-decision ceiling for focused triage and validation LLM calls. |

The model precedence is `--model`, then the matching
`*_MODEL_DEFAULT`, then `config/models.toml`. The `oss` backend has no model
default: always pass the exact served model name with `--model`.

Authentication variables such as `GEMINI_API_KEY`, `GOOGLE_API_KEY`, and
`XAI_API_KEY` belong to the backend CLI. TokenFuzz forwards selected credentials
only when `bin/audit-container-shell --forward-credentials` is used. Keep keys
out of `target.toml`, reports, and committed shell files.

## Local model endpoint

| Variable | Default | Use it for |
| --- | --- | --- |
| `AUDIT_LOCAL_BASE_URL` | `http://127.0.0.1:8000/v1` | OpenAI-compatible endpoint used by `--backend oss`. TokenFuzz appends `/v1` when omitted. |
| `AUDIT_LOCAL_API_KEY` | `EMPTY` | Token sent to a local endpoint that requires authentication. |

For Ollama:

```bash
export AUDIT_LOCAL_BASE_URL=http://127.0.0.1:11434/v1
bin/audit --target <target> --backend oss --model <served-model>
```

## LLVM selection

| Variable | Default | Use it for |
| --- | --- | --- |
| `LLVM_PREFIX` | auto-detected | Select an LLVM installation when the wrong `clang`, `llvm-symbolizer`, or `sancov` would otherwise be used. |

Homebrew LLVM and common Linux LLVM prefixes are detected automatically. Set
this only on hosts with multiple installations:

```bash
LLVM_PREFIX=/opt/homebrew/opt/llvm bin/audit --target <target> --backend <backend> 1
```

## Container runtime

The container helper has flags for its normal choices; flags are preferred in
scripts because they are visible in the command being reviewed.

| Variable | Flag equivalent | Purpose |
| --- | --- | --- |
| `CONTAINER_RUNTIME` | `--runtime` | Container CLI. The current helper accepts Docker. |
| `AUDIT_DOCKER_RUNTIME` | `--docker-runtime` | OCI runtime passed to `docker run`; `--gvisor` selects `runsc`. |

`AUDIT_BUILD_SUFFIX` is written by `bin/audit-container-shell` to isolate
sanitizer build directories by image. It is runtime state, not an operator
setting. Do not put it in shell profiles or reports.

## One-off probe selection

`bin/probe` normally selects the first enabled sanitizer from `target.toml`.
For a deliberate one-off comparison, set `PROBE_SANITIZER` to `asan`, `ubsan`,
`msan`, `tsan`, `race`, or `runner`:

```bash
PROBE_SANITIZER=msan bin/probe output/<target>/<backend>/results/scratch-1/testcase
```

The selected sanitizer must be enabled for the target. Persistent sanitizer
policy belongs in `[sanitizer].enabled`, not in the environment.

For an explicit ASan build comparison, select a ready named configuration from
`target.toml`, or force the canonical control:

```bash
PROBE_BUILD_CONFIG=compact bin/probe output/<target>/<backend>/results/scratch-1/testcase
PROBE_BUILD_CONFIG=primary bin/probe output/<target>/<backend>/results/scratch-1/testcase
```

Normal audits assign this automatically. `PROBE_BUILD_CONFIG` is a one-off
probe override, not persistent configuration policy. Confirmed crashes from an
alternate are automatically compared with the primary build; no extra override
is needed.
