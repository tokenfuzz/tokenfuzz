# Environment Variables

TokenFuzz is designed to run without an environment file. Prefer command flags
for choices that belong to one run (`--target`, `--backend`, `--model`,
`--strategy`) and `target.toml` for choices that belong to one target.

The variables below are the operator-facing exceptions. Each one is here for
the same reason: its default can produce something you would otherwise have to
diagnose — a run that stops by itself, a session that restarts mid-thought, a
local model that never finishes a decision. The harness reads other variables
internally; those are not a supported interface and you should not need them.

## Worker pool

| Variable | Default | Use it for |
| --- | --- | --- |
| `NUM_AGENTS` | unset | A flat pool of `N` workers. On a browser target this replaces the browser/shell split. |
| `BROWSER_AGENTS` | `1` | Browser-mode workers when `is_browser = "1"`. |
| `SHELL_AGENTS` | `2` for browsers, `3` otherwise | Shell/generic workers when `NUM_AGENTS` is unset. |

A one-iteration smoke test always launches one worker, whatever these say.

```bash
NUM_AGENTS=4 bin/audit --target <target> --backend <backend>
```

## Spend and time ceilings

| Variable | Default | Use it for |
| --- | --- | --- |
| `AUDIT_WALL_BUDGET_SECS` | `0` (off) | Wall-clock ceiling for a continuous run. The loop stops launching new iterations once it is spent — the simplest way to leave an overnight audit running with a hard stop. Provider quota pauses do not count against it. |
| `AGENT_TIMEOUT` | `7200` seconds | Hard ceiling for one agent launch. |
| `SHELL_SANITIZER_RUN_BUDGET` | `60` | Sanitizer runs one shell/generic agent may spend per iteration. |
| `BROWSER_SANITIZER_RUN_BUDGET` | `25` | The same budget for browser-mode agents. |

To bound an ordinary run, the positional iteration count is clearer than any of
these:

```bash
bin/audit --target <target> --backend <backend> 10
```

## When a run stops or restarts by itself

Two defaults end something on their own. Both announce themselves in the log,
so this section is mostly here to explain what you are reading.

| Variable | Default | What it controls |
| --- | --- | --- |
| `MAX_DRY_SESSIONS` | `10` | A continuous run stops once this many iterations in a row produce nothing *and* no hypothesis is still open, logging `STALL_STOP`. Raise it for a hard target you expect to be slow; the harness ignores a value low enough to prevent fair strategy rotation. |
| `TURN_SOFT_CAP` | `75` completed commands | A long Codex session is checkpointed and continued with fresh context instead of dragging hundreds of tool calls forward. The log says `TURN_SOFT_CAP reached …; session checkpointed for a fresh continuation`. Set `0` to disable. |

Neither loses work: both stop at a point where the next iteration resumes from
saved state.

## Model selection

Use `--backend` and `--model` for reproducible commands. These overrides are
for a shared shell, or a backend binary outside `PATH`.

| Variable | Default | Use it for |
| --- | --- | --- |
| `AUDIT_BACKEND` | `all` | Backend used when `--backend` is omitted. |
| `CLAUDE_MODEL_DEFAULT` | `config/models.toml` | Default Claude model. |
| `CODEX_MODEL_DEFAULT` | `config/models.toml` | Default Codex model. |
| `GEMINI_MODEL_DEFAULT` | `config/models.toml` | Default Gemini model. |
| `GROK_MODEL_DEFAULT` | `config/models.toml` | Default Grok model. |
| `CLAUDE_BIN` / `CODEX_BIN` / `GEMINI_BIN` / `GROK_BIN` / `OPENCODE_BIN` | the CLI's own name (`agy` for Gemini) | Backend executable outside `PATH`. |
| `USE_GEMINI_CLI` | `0` | Use Google Gemini CLI instead of the default Antigravity CLI. |
| `AUDIT_MODEL_PREFLIGHT` | `1` | Launch the selected model once through the real agent path before starting. Set `0` only for an intentionally offline or mock run. |

Model precedence is `--model`, then the matching `*_MODEL_DEFAULT`, then
`config/models.toml`. The `oss` backend has no default: always pass the exact
served model name with `--model`.

Authentication variables such as `GEMINI_API_KEY`, `GOOGLE_API_KEY`, and
`XAI_API_KEY` belong to the backend CLI. TokenFuzz forwards selected
credentials only when `bin/audit-container-shell --forward-credentials` is
used. Keep keys out of `target.toml`, reports, and committed shell files.

## Local model endpoint

| Variable | Default | Use it for |
| --- | --- | --- |
| `AUDIT_LOCAL_BASE_URL` | `http://127.0.0.1:8000/v1` | OpenAI-compatible endpoint used by `--backend oss`. TokenFuzz appends `/v1` when omitted. |
| `AUDIT_LOCAL_API_KEY` | `EMPTY` | Token for a local endpoint that requires authentication. |
| `LLM_DECISION_TIMEOUT` | `180` seconds for `oss`, `45` hosted | Ceiling on each audit-time ranking, peer-mapping, triage, and validation decision. Setting it applies to *every* decision, including the two below. Stage deadlines may shorten it. |
| `RANK_WORK_LLM_TIMEOUT` | unset | Override `LLM_DECISION_TIMEOUT` for work-card reranking only. The `bin/rank-work --llm-timeout` flag takes precedence over both. |

Every decision launches a full agent CLI rather than a single chat completion,
so its floor is a process launch plus a reasoning turn. A few decisions have
been observed to complete well past the ceiling above and get a longer built-in
default, scaled by the same hosted→`oss` ratio so a slow local-inference host
gets proportionally more room. Setting `LLM_DECISION_TIMEOUT` replaces those
defaults too.

For Ollama:

```bash
export AUDIT_LOCAL_BASE_URL=http://127.0.0.1:11434/v1
bin/audit --target <target> --backend oss --model <served-model>
```

A slow local model is where these bite. If the audit never gets past startup,
the model is losing the launch probe — raise `AUDIT_MODEL_PREFLIGHT_TIMEOUT`
(60s by default). If agents work but findings sit unvalidated, decisions are
timing out — raise `LLM_DECISION_TIMEOUT`. Both are normal on CPU inference or
a large model on modest hardware, and neither means the model is misconfigured.

## LLVM selection

| Variable | Default | Use it for |
| --- | --- | --- |
| `LLVM_PREFIX` | auto-detected | Select an LLVM installation when the wrong `clang`, `llvm-symbolizer`, or `sancov` would otherwise be used. |

Homebrew LLVM and common Linux prefixes are detected automatically. Set this
only on hosts with several installations:

```bash
LLVM_PREFIX=/opt/homebrew/opt/llvm bin/audit --target <target> --backend <backend> 1
```

## Container runtime

`bin/audit-container-shell` has flags for its normal choices, and flags are
better in scripts because they are visible in the command under review.

| Variable | Flag equivalent | Purpose |
| --- | --- | --- |
| `CONTAINER_RUNTIME` | `--runtime` | Container CLI. The current helper accepts Docker. |
| `AUDIT_DOCKER_RUNTIME` | `--docker-runtime` | OCI runtime passed to `docker run`; `--gvisor` selects `runsc`. |

Inside the container helper, `AUDIT_BUILD_SUFFIX` is set for you so each image
gets its own `build-asan-<image-id>/` tree. It is runtime state — do not set it
by hand.

## One-off probe selection

`bin/probe` normally uses the first enabled sanitizer in `target.toml`. For a
deliberate one-off comparison:

```bash
PROBE_SANITIZER=msan bin/probe output/<target>/<backend>/results/scratch-1/testcase
```

Valid values are `asan`, `ubsan`, `msan`, `tsan`, `race`, and `runner`, and the
sanitizer must be enabled for the target. Persistent policy belongs in
`[sanitizer].enabled`, not in the environment.

To compare ASan build configurations, select a ready named configuration or
force the canonical control:

```bash
PROBE_BUILD_CONFIG=compact bin/probe .../scratch-1/testcase
PROBE_BUILD_CONFIG=primary bin/probe .../scratch-1/testcase
```

Normal audits assign this automatically, and a confirmed crash from an
alternate build is compared against the primary without any override.
