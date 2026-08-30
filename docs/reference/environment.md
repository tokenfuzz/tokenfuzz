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
| `BROWSER_AGENTS` | `1` | Browser-mode workers. Only applies when `[runner].args` declares a `{PROFILE}` page route; a browser-mode script engine gets shell workers only. |
| `SHELL_AGENTS` | `2` beside browser workers, `3` otherwise | Shell/generic workers when `NUM_AGENTS` is unset. |

A one-iteration smoke test always launches one worker, whatever these say.

```bash
NUM_AGENTS=4 bin/audit --target <target> --backend <backend>
```

## Spend and time ceilings

| Variable | Default | Use it for |
| --- | --- | --- |
| `AUDIT_WALL_BUDGET_SECS` | `0` (off) | Wall-clock ceiling for a continuous run. The loop stops launching new iterations once it is spent — the simplest way to leave an overnight audit running with a hard stop. Provider quota pauses do not count against it. |
| `AGENT_TIMEOUT` | `7200` seconds | Hard ceiling for one agent launch, and for one iteration's pool of them. An early-finished slot is relaunched while a cohort-era peer is still running (one overtime session per slot), so this also bounds how far those replacements can push post-iteration triage out: every session in the iteration is clamped to what remains of the ceiling measured from when the iteration's first sessions started. |
| `POOL_OVERTIME` | `cohort-era` | Which in-flight peer lets a slot that finished after the initial cohort drained take its one extra session. `cohort-era`: only an initial session or a refill launched beside one, so an overtime session never justifies another. `any-peer`: any peer, including another slot's overtime — the per-slot cap and the `AGENT_TIMEOUT` clamp still bound the iteration at one extra session per slot. Measure it with the benchmark's Efficiency table (occupancy against confirmed per seat-hour) before making it a default. Any other value is refused. |
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
| `TURN_SOFT_CAP` | `128` agent/tool turns | Rollover target for a long audit session. Claude, Grok, and current Google Gemini CLI versions use native turn limits; Gemini retains a completed-tool fallback for older versions. Codex and OpenCode use completed tool events as the safe termination boundary. Antigravity (`agy`) has neither a native turn flag nor a stable completed-tool event contract, so its prompt carries the same cooperative target but only `AGENT_TIMEOUT` can hard-stop it. Capped sessions continue from structured state; the log says `turn-capped; continuing from state`, and the transcript ends with `TURN_SOFT_CAP reached …`. Set `0` to disable. |

Already checkpointed hypotheses and artifacts are preserved. The next
iteration resumes them from structured state; work not checkpointed before a
backend's turn boundary may need to be repeated.

The default is deliberately conservative: recorded Claude request curves
modeled about 28% lower cache reads at 128 while interrupting fewer original
sessions than a 100-turn cap. Use 100 as a more aggressive cost setting only
after checking finding yield and incomplete-artifact rates on your workload:

```bash
TURN_SOFT_CAP=100 bin/audit --target <target> --backend <backend>
```

Native model turns and completed-tool events are not identical units, so treat
the value as a cross-backend rollover target rather than an exact request
quota.

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
| `AUDIT_MODEL_PREFLIGHT` | `1` | Before starting, launch the selected model once through the real agent path — same granted directories as an audit session — and require it to run a command that writes into the target tree. A backend that can reply but cannot act fails here rather than spending the run. Set `0` only for an intentionally offline or mock run. |
| `AUDIT_MODEL_PREFLIGHT_TIMEOUT` | `60` seconds (`300` for Google Gemini CLI) | Ceiling on that probe. Raise it when a slow local model loses the probe and the audit never reaches its first agent. |

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
| `RANK_WORK_LLM_MODE` | `boost` | How far the rerank verdict reaches. `boost` adds a bounded increment to the deterministic score; `primary` sorts the ranked window by the model's score, with the deterministic score breaking ties, inside each buildability tier. In both modes the model reorders the cards it was shown — it cannot add or drop one — and in `primary` mode it cannot lift a card across a buildability tier; on timeout or malformed output the deterministic order stands. The `bin/rank-work --llm-mode` flag takes precedence. |

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

## Directed fuzzing

| Variable | Default | Use it for |
| --- | --- | --- |
| `FUZZ_SEED_CORPUS_DIR` | unset | A local directory of extra seed inputs (an OSS-Fuzz or ClusterFuzz corpus you staged) to fill an empty S4 corpus alongside the target's own test data. Local only — nothing is fetched over the network. |

The path is read only when a harness's corpus is empty, and its inputs are
bounded by the same size and count limits as the in-tree seeds.

```bash
FUZZ_SEED_CORPUS_DIR=/data/oss-fuzz-corpora/<project> bin/audit --target <target> --backend <backend>
```

## Container runtime

`bin/audit-container-shell` has flags for its normal choices, and flags are
better in scripts because they are visible in the command under review.

| Variable | Flag equivalent | Purpose |
| --- | --- | --- |
| `CONTAINER_RUNTIME` | `--runtime` | Container CLI. The current helper accepts Docker. |
| `AUDIT_DOCKER_RUNTIME` | `--docker-runtime` | OCI runtime passed to `docker run`; `--gvisor` selects `runsc`. |
| `AUDIT_FORWARD_CREDENTIALS` | `--forward-credentials` | Set to `1` to forward supported credential variables and read-only Google ADC files into the container. Off by default. |

Inside the container helper, `AUDIT_BUILD_SUFFIX` is set for you so each image
gets its own `build-asan-<image-id>/` tree. `bin/benchmark --isolate-build` sets
it the same way, to `+bench-<input-hash>`. It is runtime state — do not set it by
hand.

## Build leases and source pins

Every process that executes a sanitizer build holds a shared lease on it, and
every rebuild takes the matching exclusive one, so a build is never replaced
while a run is using it. A run additionally pins the source state it is
auditing, which is what catches two runs reading one checkout at different
states — something a per-build lock cannot see.

Both are advisory kernel locks under `targets/<slug>/.audit/`
(`build-locks/<build-dir>.lock` and `source-pins/<pid>.pin`), released when the
holder exits and needing no cleanup. There is nothing to configure, and they bind
only harness commands — a build tool invoked by hand is outside them.

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
