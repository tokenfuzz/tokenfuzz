# Environment variables

TokenFuzz needs no environment file. Use flags for choices that belong to
one run (`--target`, `--backend`, `--model`, `--strategy`) and `target.toml`
for choices that belong to one target. Set a variable for one command by
prefixing it:

```bash
NUM_AGENTS=4 bin/audit --target <target> --backend <backend>
```

The page runs from the variables operators set routinely (worker pool,
spend and time ceilings, model selection, local endpoint, agent security) to
the rarely needed [tuning knobs](#tuning-knobs). A variable not listed here,
such as `RESULTS_DIR`, `LOGDIR`, `ACTIVE_BACKEND`, `MODEL`, or
`TOKENFUZZ_AGENT_SECURITY`, is runtime state the harness sets for its own
child processes, a test hook, or internal tuning. It is not a supported
interface.

## Worker pool

| Variable | Default | Use it for |
| --- | --- | --- |
| `NUM_AGENTS` | unset | A flat pool of `N` shell/generic workers. On a browser target it replaces the browser/shell split, so no browser-mode worker runs. |
| `SHELL_AGENTS` | `2` beside browser workers, `3` otherwise | Shell/generic workers when `NUM_AGENTS` is unset. Slots refill until the run ends, so each extra worker adds concurrent spend against the account's provider quota. |
| `BROWSER_AGENTS` | `1` | Browser-mode workers. Only a page browser gets them: a target whose `[runner].args`, or its build system's browser default, contain `{PROFILE}`. A browser-mode script engine gets shell workers only. |
| `AGENT_ROLES` | unset | One role per slot, comma-separated, each `analysis` or `reproduce`, for example `reproduce,reproduce,analysis`. The count must equal the pool size or the run stops at startup. Unset, a multi-worker pool makes its last slot `analysis` and the rest `reproduce`. |

A one-iteration smoke test always launches one worker.

## Spend and time ceilings

| Variable | Default | Use it for |
| --- | --- | --- |
| `AUDIT_WALL_BUDGET_SECS` | `0` (off) | Productive wall-clock budget: the simplest hard stop for an overnight audit. Sessions are clamped to what remains, and none starts once it is spent. Pauses for provider capacity or transient failures do not count; housekeeping does. |
| `AGENT_TIMEOUT` | `7200` | Ceiling in seconds for one agent session. In cohort mode (fixed-strategy, delta, ensemble, and `--no-refill-workers` runs) it also bounds one iteration: every session in it, refills included, is clamped to what remains, measured from the iteration's first launch. |
| `SHELL_SANITIZER_RUN_BUDGET` | `60` | Sanitizer runs one shell/generic slot may spend per iteration. |
| `BROWSER_SANITIZER_RUN_BUDGET` | `25` | The same budget for browser-mode slots. |
| `SANITIZER_RUN_BUDGET_PER_ITERATION` | unset | When set, replaces both budgets above for every slot. |

For an ordinary run, the positional iteration count is the clearer bound:

```bash
bin/audit --target <target> --backend <backend> 10
```

### When a run stops or restarts by itself

These act on their own and announce themselves in `index.log`.

| Variable | Default | What it controls |
| --- | --- | --- |
| `MAX_DRY_SESSIONS` | `10` | The run stops with `STALL_STOP` once this many iterations in a row produce nothing *and* no hypothesis is open. Raise it for a hard target. Values below `9` are raised to `9`, so S1 can finish its longer dry runway. |
| `TURN_SOFT_CAP` | `128` | Session rollover target, in agent turns or completed tool calls depending on the backend (below). The session exits cleanly, the log says `turn-capped; continuing from state`, the transcript ends with `TURN_SOFT_CAP reached …`, and the next session resumes from structured state. `0` disables it. |
| `CONTEXT_SOFT_CAP` | `0` (off) | Rollover once a request's prompt reaches this many tokens, only on backends that report usage per request (Claude Code, Grok Build). It ends the session the same way; the transcript ends `TURN_SOFT_CAP reached at N context tokens …`. In a benchmark, set it only when every compared backend reports per-request usage, or the conditions are not comparable. |

| Backend | How `TURN_SOFT_CAP` is enforced |
| --- | --- |
| Claude Code, Grok Build | The CLI's native `--max-turns`. |
| Google Gemini CLI | The native `maxSessionTurns` setting, plus a completed-tool-call count for older versions that ignore it. |
| Codex, OpenCode | TokenFuzz ends the session after that many completed tool calls. |
| Antigravity (`agy`) | Not enforceable: the prompt states the target, and only `AGENT_TIMEOUT` hard-stops the session. |

Turns and tool calls are different units, so treat the value as a rollover
target, not a request quota. Checkpointed hypotheses and artifacts survive a
rollover; work not yet checkpointed may be repeated. Check cost and
incomplete-artifact rates before adopting another value:

```bash
TURN_SOFT_CAP=100 bin/audit --target <target> --backend <backend>
```

## Model selection

Use `--backend` and `--model` in reproducible commands. These variables
suit a shared shell or a backend binary outside `PATH`.

| Variable | Default | Use it for |
| --- | --- | --- |
| `AUDIT_BACKEND` | `all` | Backend used when `--backend` is omitted. It also pins the backend `bin/setup-target` uses for its model helpers; `all` leaves them unpinned. |
| `CLAUDE_MODEL_DEFAULT`, `CODEX_MODEL_DEFAULT`, `GROK_MODEL_DEFAULT` | `[models]` in `config/models.toml` | Default Claude Code, Codex, or Grok model. |
| `GEMINI_MODEL_DEFAULT` | `[models]` in `config/models.toml` | Default Gemini model, for both Antigravity and Google Gemini CLI. |
| `CLAUDE_BIN`, `CODEX_BIN`, `GEMINI_BIN`, `GROK_BIN`, `OPENCODE_BIN` | `claude`, `codex`, `agy` (`gemini` when `USE_GEMINI_CLI=1`), `grok`, `opencode` | Backend executable outside `PATH`. |
| `USE_GEMINI_CLI` | unset | `1` makes the `gemini` backend use Google Gemini CLI instead of Antigravity (`agy`). |
| `CODEX_HOME` | `~/.codex` | Codex's home directory. TokenFuzz reads `config.toml` there to switch off your MCP servers and `notify` hook for each launch, and reads session rollouts under `sessions/` to measure usage, deleting the ones it fully resolves. |
| `AUDIT_MODEL_PREFLIGHT` | `1` | `0` skips the [model preflight](../guides/backends.md#model-preflight), the one real agent launch that must write into the target tree before the run starts, and the benchmark's one-line model check before its first cell. Only for an intentionally offline or mock run. |
| `AUDIT_MODEL_PREFLIGHT_TIMEOUT` | `60` seconds (`300` for Google Gemini CLI) | Ceiling on each preflight attempt. Raise it when a slow local model never gets past startup. |
| `AUDIT_MODEL_PREFLIGHT_ATTEMPTS` | `3` | Total preflight attempts, 15 and then 60 seconds apart. A provider refusal or a substituted model stops at once. |

Model precedence is `--model`, then the matching `*_MODEL_DEFAULT`, then
`config/models.toml`. Reasoning effort comes only from that file's `[effort]`
table. The `oss` backend has no default model: always pass the served name
with `--model`. See
[Models and reasoning effort](../guides/backends.md#models-and-reasoning-effort).

### Claude Code settings TokenFuzz applies

Every Claude launch TokenFuzz makes (agent sessions, validators, and
decisions) gets these unless you set them yourself:

| Variable | Value TokenFuzz sets | Why |
| --- | --- | --- |
| `CLAUDE_CODE_PROMPT_CACHE_TTL` | `5m` | The five-minute cache-write tier is cheaper for an audit's closely spaced requests; see the [cost model](../concepts/cost-model.md#what-prompt-caching-can-reuse). It changes cost, never model behaviour. Setting this variable or `FORCE_PROMPT_CACHING_5M` to any value keeps your choice. |
| `BASH_DEFAULT_TIMEOUT_MS`, `BASH_MAX_TIMEOUT_MS` | `3600000` (one hour) | Claude Code backgrounds a command still running at its 120-second default, and a headless session then exits without the result. Fuzz campaigns and long probes must finish in the foreground; the session's own wall still bounds them. |

### Credentials

Authentication variables such as `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`,
`GEMINI_API_KEY`, `GOOGLE_API_KEY`, and `XAI_API_KEY` belong to the backend
CLI. TokenFuzz reads them only to forward them into a container under
`--forward-credentials` (see [Container runtime](#container-runtime)). Agent
sessions inherit the environment of the shell that runs `bin/audit`, so
agent commands can read any credential exported there. Keep keys out of
`target.toml`, reports, and committed shell files.

## Agent security

The execution boundary is the `--agent-security` flag; see
[Agent security modes](../guides/backends.md#agent-security-modes).

| Variable | Default | Use it for |
| --- | --- | --- |
| `IS_SANDBOX` | unset | `1` asserts that an outer container or VM you administer is the boundary for `--agent-security external-bypass`. It only silences the one-time warning an unasserted bypass prints: it does not change the mode, and TokenFuzz does not verify it. `bin/audit-container-shell` sets it. |

## Local model endpoint

These apply to `--backend oss` with a served model id; an `opencode/<id>`
catalog model ignores them.

| Variable | Default | Use it for |
| --- | --- | --- |
| `AUDIT_LOCAL_BASE_URL` | `http://127.0.0.1:8000/v1` | OpenAI-compatible endpoint. TokenFuzz adds `http://` when no scheme is given, drops a trailing `/`, and appends `/v1` when it is missing. |
| `AUDIT_LOCAL_API_KEY` | `EMPTY` | Key for an endpoint that requires authentication. The literal `EMPTY` is sent when it is unset. |

For Ollama:

```bash
export AUDIT_LOCAL_BASE_URL=http://127.0.0.1:11434/v1
bin/audit --target <target> --backend oss --model <served-model>
```

`python3 lib/llm_invoke.py local-model-available --model <served-model>`
exits 0 when the endpoint's `/models` list contains that id.

Slow local models hit timeouts. That is normal on CPU inference or modest
hardware and does not mean the model is misconfigured:

- The audit never gets past startup: raise `AUDIT_MODEL_PREFLIGHT_TIMEOUT`.
- Agents work but findings sit unvalidated: raise `LLM_DECISION_TIMEOUT`
  (see [Model decisions](#model-decisions)).

## Container runtime

`bin/audit-container-shell` has flags for its normal choices; prefer them in
scripts, where the command under review shows them. What the container
isolates is under
[Containerised backend shell](../guides/backends.md#containerised-backend-shell).

| Variable | Flag | Default | Purpose |
| --- | --- | --- | --- |
| `CONTAINER_RUNTIME` | `--runtime` | `docker` | Container CLI. Only Docker is supported. |
| `AUDIT_DOCKER_RUNTIME` | `--docker-runtime` | Docker's default | OCI runtime passed to `docker run`; `--gvisor` selects `runsc`. |
| `AUDIT_FORWARD_CREDENTIALS` | `--forward-credentials` | off | `1` forwards the credential variables below and mounts Google credentials read-only. |
| `AUDIT_CONTAINER_NO_NEW_PRIVS` | none | `1` | `0` drops `--security-opt no-new-privileges` from `docker run`. |
| `AUDIT_CONTAINER_AUTO_START` | none | `1` | `0` stops the helper from trying to start an unreachable Docker daemon (Docker Desktop or Colima on macOS, `systemctl --user start docker` on Linux). |
| `AUDIT_CONTAINER_START_TIMEOUT` | none | `60` | Seconds to wait for that daemon. |
| `CLAUDE_NPM_SPEC`, `CODEX_NPM_SPEC`, `GEMINI_CLI_NPM_SPEC`, `OPENCODE_NPM_SPEC` | none | `@anthropic-ai/claude-code@latest`, `@openai/codex@latest`, `@google/gemini-cli@latest`, `opencode-ai@latest` | npm packages `--rebuild` installs. Pin versions for a reproducible image. |
| `AGY_INSTALL_URL`, `GROK_INSTALL_URL` | none | `https://antigravity.google/cli/install.sh`, `https://x.ai/cli/install.sh` | Installer scripts `--rebuild` downloads and runs. |

`--forward-credentials` forwards whichever of `ANTHROPIC_API_KEY`,
`CLAUDE_CODE_OAUTH_TOKEN`, `OPENAI_API_KEY`, `GEMINI_API_KEY`,
`GOOGLE_API_KEY`, `XAI_API_KEY`, `GOOGLE_CLOUD_PROJECT`,
`GOOGLE_CLOUD_QUOTA_PROJECT`, and `USE_GEMINI_CLI` are set on the host. It
also mounts the file `GOOGLE_APPLICATION_CREDENTIALS` names, and
`~/.config/gcloud` if it exists, read-only. `--env-file` passes any other
variable.

Each container start runs `tests/run-tests.sh --install-container-deps`;
pass `AUDIT_CONTAINER_INSTALL_DEPS=0` through `--env-file` to skip it.

Inside the container the helper sets runtime state you should not set by
hand: `IS_SANDBOX=1`, and `AUDIT_BUILD_SUFFIX=-<image-id>` so each image
gets its own `build-asan-<image-id>/` tree (a suffix already set on the host
is forwarded instead). `bin/benchmark --isolate-build` appends
`+bench-<input-hash>` to the suffix the same way.

## Directed fuzzing

| Variable | Default | Use it for |
| --- | --- | --- |
| `FUZZ_SEED_CORPUS_DIR` | unset | A local directory of extra seed inputs, such as an OSS-Fuzz or ClusterFuzz corpus you staged, used to fill an empty S4 corpus alongside the target's own test data. Nothing is fetched over the network. |

It is read only when a harness's corpus is empty. Every file under it except
source and build files is a candidate, within the same size and count limits
as in-tree seeds.

```bash
FUZZ_SEED_CORPUS_DIR=/data/oss-fuzz-corpora/<project> bin/audit --target <target> --backend <backend>
```

## Toolchain selection

| Variable | Default | Use it for |
| --- | --- | --- |
| `LLVM_PREFIX` | auto-detected | The LLVM installation whose `llvm-symbolizer`, `sancov`, and `llvm-cxxfilt` TokenFuzz uses. A tool not under `$LLVM_PREFIX/bin` is looked for in `/opt/homebrew/opt/llvm`, `/usr/local/opt/llvm`, `/usr/lib/llvm-*` in name order, `/usr/local`, and then `PATH`. It does not choose the compiler. Set it only on hosts with several installations. |
| `AUDIT_JAVA_HOME` | unset | JDK for Java targets. Discovery tries `AUDIT_JAVA_HOME`, then `JAVA_HOME`, then `PATH`; see [Multi-language targets](../guides/multi-language.md). |

## One-off probe selection

`bin/probe` uses the first enabled sanitizer in `target.toml`, or `runner`
when `[sanitizer].enabled = []`. For a deliberate one-off comparison:

```bash
PROBE_SANITIZER=msan bin/probe output/<target>/<backend>/results/scratch-1/testcase
```

`PROBE_SANITIZER` takes `asan`, `ubsan`, `msan`, `tsan`, `race`, or
`runner`. `bin/probe` refuses a sanitizer not in `[sanitizer].enabled`
unless `PROBE_ALLOW_DISABLED_SANITIZER=1` is also set, and refuses every
sanitizer but `runner` when `[sanitizer].enabled = []`. Persistent policy
belongs in `[sanitizer].enabled`.

These replace the matching `target.toml` field for one probe; a relative
path resolves against the target root:

| Variable | Replaces |
| --- | --- |
| `TARGET_ASAN_BIN`, `TARGET_ASAN_LIB` | `asan_bin`, `asan_lib` |
| `TARGET_UBSAN_BIN`, `TARGET_UBSAN_LIB`, `TARGET_MSAN_BIN`, `TARGET_MSAN_LIB`, `TARGET_TSAN_BIN`, `TARGET_TSAN_LIB` | `[sanitizer].<san>_bin`, `[sanitizer].<san>_lib` |
| `TARGET_RUNNER_BIN` | `[runner].bin` |

`PROBE_BUILD_CONFIG` selects a ready ASan
[build configuration](target-toml.md#build-configurations) by name, or
`primary` for the canonical control. Normal audits assign configurations
automatically and compare an alternate-build crash against the primary
without it.

```bash
PROBE_BUILD_CONFIG=compact bin/probe .../scratch-1/testcase
PROBE_BUILD_CONFIG=primary bin/probe .../scratch-1/testcase
```

## Tuning knobs

The defaults below are measured. Change one only for a reason you can
state, and record the change with the results: review-gate and clustering
values in particular make results incomparable with default runs.

### Work queue and scheduling

| Variable | Default | What it controls |
| --- | --- | --- |
| `WORK_CARD_CLAIM_TTL_SECONDS` | `1800` | How long a work-card claim stays valid without its hypothesis closing, so a killed agent does not hold its card. Raise it only for cards known to take longer. |
| `RANK_WORK_LIMIT` | `120` | Distinct source files in the first ranked work-card window. The window grows by the same step once every card in it has been worked. Widen it when `bin/state coverage` shows large files never offered early. |
| `RANK_WORK_DIVERSITY_FLOOR` | `12` | Window slots reserved for low-scoring files, picked round-robin across subsystems, so the ranking regexes do not define the audit's scope. Never more than a fifth of the window; `0` turns it off. See [how the visible window is filled](../concepts/strategy-model.md#how-the-visible-window-is-filled). |
| `WORK_CARD_MIN_RUNS_BEFORE_DISCARD` | `3` | Card-linked `CLEAN` probe runs a card needs before an agent may discard it. The prompt and `bin/state update-card` read the same value. |
| `WORK_CARD_MIN_HYPS_BEFORE_DISCARD` | `2` | Distinct hypotheses those runs must span. |
| `STEWARD_INTERVAL_SECS` | `300` | Continuous runs: seconds between steward ticks. Every tick re-ranks the queue and releases stale claims without stopping a slot. A tick in which a session ended also scores the generation, rotates starved strategy lanes, renews per-iteration budgets, and counts as an iteration everywhere on this page. Index maintenance waits for the final barrier. |
| `POOL_OVERTIME` | `cohort-era` | Cohort mode with refills only. After the initial cohort drains, each slot may take one extra session while a peer still runs. `cohort-era` counts only an initial session, or a refill launched beside one, as that peer, so one overtime session never justifies another; `any-peer` counts any running peer. Any other value is refused. |
| `LLM_DECIDE_MAX_CALLS` | `1000` | One-shot model decisions per iteration, counted separately for the harness process and each agent slot. Once spent, decisions return no answer until the next iteration, and callers treat that as a failed decision. `0` removes the cap. The budgeted sweep is always uncapped; its token budget bounds it. |

### Sanitizer deadlines

| Variable | Default | Use it for |
| --- | --- | --- |
| `ASAN_TIMEOUT`, `UBSAN_TIMEOUT`, `MSAN_TIMEOUT`, `TSAN_TIMEOUT` | `15` seconds (`10` in JavaScript mode) | Deadline for one ordinary probe run. UBSan's fuzz modes also read `UBSAN_TIMEOUT`, with a `600` default. Setup uses `ASAN_TIMEOUT` when proving that a generated ASan Python host can import the staged native package. |
| `FUZZ_ASAN_TIMEOUT`, `FUZZ_MSAN_TIMEOUT`, `FUZZ_TSAN_TIMEOUT` | `600` seconds | Deadline for one fuzz process. |
| `ASAN_FUZZ_REPRO_TIMEOUT`, `UBSAN_FUZZ_REPRO_TIMEOUT`, `MSAN_FUZZ_REPRO_TIMEOUT`, `TSAN_FUZZ_REPRO_TIMEOUT` | `20` seconds | Deadline for replaying one fuzzer crash file. |

### Model decisions

Ranking, peer mapping, triage, and validation use one-shot model decisions.
Each launches a full agent CLI, so its floor is a process launch plus a
reasoning turn.

| Variable | Default | Use it for |
| --- | --- | --- |
| `LLM_DECISION_TIMEOUT` | `45` seconds hosted, `180` for `oss`; longer for the decisions below | Ceiling on each decision. Setting it replaces every default, including those below. When it is unset, the finding gate's quality votes use `300` seconds. A stage deadline may shorten any call, and `bin/audit` refuses a value that is not a positive whole number. |
| `RANK_WORK_LLM_TIMEOUT` | unset | Override for the work-card rerank only. `bin/rank-work --llm-timeout` takes precedence. |
| `RANK_WORK_LLM_MODE` | `boost` | `boost` adds a bounded increment to the deterministic score; `primary` orders the ranked window by the model's score, with the deterministic score breaking ties, inside each buildability tier. Either way the model only reorders the cards it was shown, and on timeout or malformed output the deterministic order stands. `bin/rank-work --llm-mode` takes precedence. |

Decisions observed to run long have their own defaults, scaled from hosted
to `oss` by the same ratio:

| Decision | Hosted | `oss` |
| --- | --- | --- |
| `build-script-converge` | 100 s | 400 s |
| `reachability_fields_batch` | 120 s | 480 s |
| `work_rerank` | 150 s | 600 s |
| `trigger_validator` | 700 s | 2800 s |
| `cluster_expand` | 800 s | 3200 s |

### Review gates

These change the review standard in
[Triage results](../guides/triage-results.md).

| Variable | Default | What it controls |
| --- | --- | --- |
| `FIND_GATE_ACCEPT_QUORUM` | `2` | Accept votes that admit a finding at the substance gate. |
| `FIND_GATE_QUORUM` | `2` | Reject votes that move a finding to `findings-rejected/`. At most `accept + reject − 1` votes are cast. |
| `CRASH_TRIGGER_GATE` | `1` | `0` skips the source-reading trigger review of kept crashes. |
| `CRASH_PROMOTION_PENDING_MAX` | `10` | Consecutive triage passes an incomplete crash bundle stays pending before it is rejected with a `POSSIBLE-FALSE-NEGATIVE` warning. |
| `LLM_FIELD_FILL_MAX_ATTEMPTS` | `2` | Answered model asks a report gets to fill its missing structured fields. Timeouts and unusable output do not count. |
| `LLM_FIELD_FILL_DISABLE` | unset | `1` skips that fill, so reports keep only the fields their authors wrote. |
| `REPORT_GATE_MAX_BYTES` | `98304` (96 KiB) | Largest report a review gate reads whole. A longer one is sent as the first three quarters and last quarter of this size, with a warning on stderr. |

### Clustering and indexes

The rules are in [Deduplication](../concepts/deduplication.md).

| Variable | Default | Use it for |
| --- | --- | --- |
| `CLUSTER_LCS_THRESHOLD` | `2` | Frames two crash states must share, as a longest common subsequence, to merge. Values below `1` count as `1`. |
| `CLUSTER_FUZZY_MATCH` | off | `1`, `true`, `yes`, or `on` enables per-line fuzzy similarity for crash states. Off because it merged distinct bugs in earlier runs. |
| `CLUSTER_FUZZY_THRESHOLD` | `0.9` | Similarity fuzzy matching requires, clamped to `0`–`1`. |
| `CLUSTER_HTML` | on | `0` stops the cluster tools writing HTML cluster pages and HTML copies of member reports; the Markdown indexes remain. |
| `INDEX_HTML_AUTO` | `1` | `0` keeps index maintenance Markdown-only: member reports are not enriched or rendered to HTML, and the rejected indexes get no HTML page. |
| `ENRICH_REPORT_AUTO` | `1` | `0` skips `bin/enrich-report` during index maintenance. |

### Benchmark finalization

After the audit wall, `bin/benchmark` drains crash triage and the finding
gate, pausing when a provider limits the reviewers. See
[the benchmark design](../concepts/benchmark.md).

| Variable | Default | Use it for |
| --- | --- | --- |
| `FIND_GATE_MAX_PAUSES` | `12` | Provider-limit pauses one drain may take before it stops and leaves the rest unjudged. |
| `FIND_GATE_PAUSE_MAX_TOTAL` | `21600` (six hours) | Total seconds one drain may pause. |
| `FIND_GATE_PAUSE_CHUNK` | `1800` | Pause length when the provider reports no reset time; with one, the drain waits until the reset plus 30 seconds. Every pause is clamped to what remains of `--finalize-wall`. |
| `BENCHMARK_RUNID` | unset | Run id used when `--run-id` is not given. |

A drain that stops early logs why; `--regenerate` resumes from saved
receipts.

### Probe output and memory limits

| Variable | Default | Use it for |
| --- | --- | --- |
| `PROBE_ASAN_OUTPUT_MAX_BYTES` | `8388608` (8 MiB) | Largest probe output saved whole. A larger one is saved as a truncation marker plus its head and tail. The diagnostic is classified before truncation. `0` saves everything, which can create a very large file; use it only when the marker shows the omitted middle matters for review. |
| `PROBE_ASAN_OUTPUT_HEAD_BYTES`, `PROBE_ASAN_OUTPUT_TAIL_BYTES` | `262144` (256 KiB) each | Head and tail kept from a truncated output. |
| `SANITIZER_DIGEST_LINE_CHARS` | `4096` | The terminal digest shortens the middle of a longer line, such as a Java classpath. Display only; saved output follows the limits above. `0` shows full lines. |
| `PROBE_RSS_LIMIT_MB` | `5120` | A generic-mode probe process is killed once its resident memory passes this, to protect the host. Raise it for a target that legitimately needs more; `0` turns the limit off. |
