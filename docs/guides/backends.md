# Backends and isolation

A backend is the model CLI that TokenFuzz launches for agent sessions and
one-shot decisions. Target config, work state, testcase execution, triage,
and artifact layout are the same whichever backend runs.

Decide where your source may go and what contains the agent before you pick
a model:

| Need | Route |
| --- | --- |
| Reproducible run or benchmark | One explicit `--backend` and `--model`. |
| Source must stay on the audit host | `oss` against a local OpenAI-compatible endpoint. |
| Several hosted models on one target | `--backend all` ([ensemble mode](#ensemble-mode)). |
| A backend whose own sandbox TokenFuzz refuses | `--agent-security external-bypass` inside a container or VM you administer. |

The shortest safe start on a workstation is a one-worker smoke test on a
backend whose native sandbox TokenFuzz supports:

```bash
bin/audit --target <target> --backend claude 1
```

Read [What the sandbox does not contain](#what-the-sandbox-does-not-contain)
before relying on that boundary for an untrusted target.

## Choose a backend

```bash
# One hosted backend; best for a reproducible run.
bin/audit --target <target> --backend codex --model <model>

# Rotate every available hosted backend the security mode can launch.
bin/audit --target <target> --backend all

# Keep inference on a local OpenAI-compatible endpoint.
bin/audit --target <target> --backend oss --model <served-model-id>
```

| Backend | CLI | Default model | Default security mode |
| --- | --- | --- | --- |
| `claude` | Claude Code (`claude`) | `config/models.toml` | `sandboxed` |
| `codex` | Codex CLI (`codex`) | `config/models.toml` | `sandboxed` |
| `gemini` | Antigravity CLI (`agy`); Google Gemini CLI (`gemini`) when `USE_GEMINI_CLI=1` | `config/models.toml` | `sandboxed`, which refuses it: pass `--agent-security external-bypass` |
| `grok` | Grok Build (`grok`) | `config/models.toml` | `sandboxed`, which refuses it: pass `--agent-security external-bypass` |
| `oss` | OpenCode (`opencode`) | None; `--model` is required | `external-bypass` |

Use an explicit `--backend` and `--model` in any experiment or
reproducibility record. `--backend all` is for exploration, not for holding
model choice constant.

### Ensemble mode

`--backend all` is also what you get when neither `--backend` nor
`AUDIT_BACKEND` is set. It:

- considers `claude → codex → gemini → grok` in that order, and never `oss`;
- keeps a backend only when its CLI is installed and its status check exits
  0: `claude auth status`, `codex login status`, `agy changelog` (or
  `gemini --version` under `USE_GEMINI_CLI=1`, which proves only that the
  CLI is installed), or `grok models` without `not authenticated` in its
  output;
- skips, with a warning, each backend the security mode cannot launch, so
  under the default `sandboxed` mode the rotation is Claude Code and Codex;
- refuses `--model`, because one model name cannot fit every backend;
- with an iteration limit of N, uses at most the first N remaining backends;
- gives each iteration to the next backend in the rotation.

A backend named with `--backend` runs the same check (`opencode --version`
for `oss`) and, if it fails, stops the run with
`FATAL: backend '<name>' is not installed or configured`.

Each backend keeps its own state, evidence, and logs under
`output/<target>/<backend>/`. It is rotation, not consensus voting: the
target-level `output/<target>/finding-clusters.html` and
`crash-clusters.html` cluster the backends' accepted results after the fact
and keep their provenance. An ensemble helps when one provider is
intermittently rate-limited or when you want independent model behaviour
under the same execution and triage rules. Use one backend when you need a
fixed model for a method section, a known price, the local `oss` path, or a
constant backend while comparing harness changes.

### Install and authenticate

Install the chosen CLI through its upstream instructions:
[Claude Code](https://code.claude.com/docs),
[Codex CLI](https://learn.chatgpt.com/docs/codex/cli),
[Antigravity CLI](https://github.com/google-antigravity/antigravity-cli),
[Google Gemini CLI](https://github.com/google-gemini/gemini-cli),
[Grok Build](https://docs.x.ai/build/overview), or
[OpenCode](https://opencode.ai/download).

Then run one direct, non-interactive check. A backend waiting for a login
can otherwise look like a stalled agent:

```bash
claude -p "Reply exactly: tokenfuzz-claude-auth-ok"
codex login status
agy -p "Reply exactly: tokenfuzz-gemini-auth-ok"
grok -p "Reply exactly: tokenfuzz-grok-auth-ok"
opencode run --pure --model opencode/<model-id> "Reply exactly: tokenfuzz-opencode-auth-ok"
```

Credentials stay with each CLI; never put keys in `target.toml` or reports.
Three backends need care:

- Claude Code launches load none of your Claude settings files
  (`--setting-sources ""`), so authenticate by login or environment, not
  through an `apiKeyHelper` or `env` block in `settings.json`.
- Google Gemini CLI, with cross-run memory off (the default), runs from an
  empty home that TokenFuzz stages and points `GEMINI_CLI_HOME` at. That home
  holds no OAuth files, so export `GEMINI_API_KEY` or `GOOGLE_API_KEY`.
- Grok Build needs its CLI credentials, commonly `XAI_API_KEY`. An older
  build that reports no usage gets estimated token counts, labelled as
  estimates.

### Models and reasoning effort

`config/models.toml` holds each backend's default model (`[models]`) and
reasoning effort (`[effort]`). The model is chosen in this order:

1. `--model` (single backend only);
2. `CLAUDE_MODEL_DEFAULT`, `CODEX_MODEL_DEFAULT`, `GEMINI_MODEL_DEFAULT`, or
   `GROK_MODEL_DEFAULT`;
3. `[models]` in `config/models.toml`.

`oss` has neither an environment override nor a configured default.

Effort comes only from `[effort]`; there is no flag or environment override.
Agent sessions, validators, and decisions all read it, so change project
defaults there. An empty value leaves the CLI's own default.

| Backend | `[effort]` key | How it is applied |
| --- | --- | --- |
| `claude` | `claude` | `--effort <value>` |
| `codex` | `codex` | `-c model_reasoning_effort="<value>"` |
| `gemini` on `agy` | `agy` | Selects the label variant, such as `Gemini 3.8 Flash (High)` |
| `gemini` on Google Gemini CLI | `gemini` | `thinkingLevel`, upper-cased, in a generated system settings file |
| `grok` | `grok` | `--reasoning-effort <value>` |
| `oss` | `oss` | Not applied |

`agy` takes a display label from `agy models`, not a slug, and silently
falls back to its remembered model on a value it cannot resolve. TokenFuzz
maps the slugs it knows (`gemini-3.5-flash` through `gemini-3.8-flash`, and
`gemini-3.1-pro-preview`) to labels, and the model preflight fails the run
if `agy` still cannot resolve one.

### Model preflight

Before the first agent starts, `bin/audit` launches each selected backend
once through the real agent path: the same granted directories and security
mode as an audit session, the audit guide in the prompt, and one command
that writes a token file under the target's `.audit/` directory. The run
starts only when that file holds the expected token. Replying is not enough;
the backend has to act.

Each attempt is bounded by `AUDIT_MODEL_PREFLIGHT_TIMEOUT` (60 seconds, or
300 for Google Gemini CLI). Up to `AUDIT_MODEL_PREFLIGHT_ATTEMPTS` (3)
attempts run, 15 and then 60 seconds apart. Four failures stop the run at
once, because a retry cannot change them: a provider refusal (such as a
revoked credential or a model the account cannot use), a different model
served than the one requested, an `agy` model flag it could not resolve, and
Google Gemini CLI dropping the harness admin policies because the host has a
system policies directory. After the run starts, a usage row carries
`served_model` whenever its transcript shows that a different model did the
work.

The variables are under
[Model selection](../reference/environment.md#model-selection); the error
messages and fixes are under
[Preflight fails](../reference/troubleshooting.md#preflight-fails).

## Agent security modes

Every tool-using agent launch (audit sessions, the model preflight, and
validator reviews) runs under one of two modes, chosen with
`--agent-security`:

| Mode | What enforces the boundary | When to use it |
| --- | --- | --- |
| `sandboxed` | The backend CLI's own OS sandbox: Seatbelt on macOS, Landlock/seccomp or bubblewrap on Linux. Approval prompts are off, because a headless run cannot answer one and an approval the model can request is not a boundary. | Normal runs on a machine you also use for other things. |
| `external-bypass` | Nothing in the CLI: each CLI runs with its permission bypass (listed [below](#what-each-backends-sandbox-enforces)). An outer container or VM you administer has to be the boundary. | Inside a container or VM you administer, and for backends `sandboxed` refuses. |

`oss` defaults to `external-bypass`, because OpenCode's permissions are an
approval policy, not an OS sandbox, and `sandboxed` refuses it. Every other
backend defaults to `sandboxed`, including `gemini` and `grok`, which that
mode refuses: run them with `--agent-security external-bypass`.

`IS_SANDBOX=1` is how an outer container or VM announces that it is the
boundary. TokenFuzz cannot measure that claim and does not change the mode
because of it. Under `external-bypass` without it, each process prints one
warning that agents will run target build scripts and harness-authored
testcases with your account's filesystem, credentials, and network, and
then continues: the outer boundary is yours to administer. The one thing
TokenFuzz refuses is `sandboxed` mode for a CLI whose own sandbox provably
cannot host an audit, a capability fact no flag can change.

!!! warning "A default is not a boundary"
    `oss` selects `external-bypass` even on a plain host because that is the
    only mode OpenCode can run. Enter a hardened container or VM first if
    the target or generated testcases must be contained.

There is deliberately no classifier-reviewed `auto` mode: it would add
provider calls, latency, and variable decisions to every run without a
stronger boundary.

```bash
# Default: the backend's own sandbox, no flag needed.
bin/audit --target <target> --backend claude 1

# Only after entering an externally hardened shell.
bin/audit --target <target> --backend grok --agent-security external-bypass 1
```

The mode is written to `state/run-config.json` and inherited by every
subprocess of the run, including source-reading validators. `bin/benchmark`
takes the same flag for both of its conditions and records it; see
[the benchmark page](../concepts/benchmark.md).

### What each backend's sandbox enforces

This is TokenFuzz's tested support policy, not a comparison of what each
vendor CLI can do elsewhere. A backend is supported only where its sandbox
was measured doing the two things an audit needs, reading the target tree
and writing results, while still containing the agent. Where it is not,
TokenFuzz refuses the launch rather than record the run as contained.

| Backend | `sandboxed` | What it enforces, or why it is refused | `external-bypass` launch |
| --- | --- | --- | --- |
| Claude Code | Supported | Commands run in Claude Code's sandbox; an unavailable sandbox is a hard error, and requests to run a command outside it are denied. Writes are confined to the working directory and the `--add-dir` grants, each granted by its resolved path, plus any location the CLI's sandbox always allows. Outbound network and DNS are blocked; loopback binding stays allowed so local client/server harnesses still probe. Bash is the only tool the launch pre-approves; Write and Edit are not, because the permission system rather than the sandbox governs them. | `--dangerously-skip-permissions` |
| Codex | Supported | `--sandbox workspace-write` with `approval_policy="never"`. Writes are confined to the granted roots (`--cd` plus `--add-dir`), plus any location the CLI's sandbox always allows; reads are unrestricted; **all** network is blocked, including loopback, which it has no setting to re-open. | `--sandbox danger-full-access --dangerously-bypass-approvals-and-sandbox` |
| Antigravity (`agy`) | Refused | Its terminal sandbox runs commands in a scratch directory, refuses writes to the launch directory, denies reads outside it, and auto-denies its file-writing tool headless. An audit could neither read the target nor file a result. | `--dangerously-skip-permissions` |
| Google Gemini CLI | Refused | Its container mounts only the launch directory (`--include-directories` adds workspace context, not a mount), so an agent would run blind to the target. Its macOS profile allows outbound network. | `--approval-mode=yolo` |
| Grok Build | Refused | Its `workspace` profile reads the whole host, credential paths included (only writes to them are blocked), and allows outbound network; its stricter profiles block network only on Linux. Its one read-restricting profile sees nothing outside `--cwd`, which would leave a model-direct control blind to the target it is scored against. | `--always-approve` |
| OpenCode (`oss`) | Refused | Its permissions are an approval policy, not an OS sandbox. | `--auto` |

Refused backends stay fully available under `external-bypass`. A refused
backend named with `--backend` is a hard error; `--backend all` skips it and
says which and why.

### What the sandbox does not contain

The security mode governs agent CLI sessions and nothing else:

- **Harness work is outside it.** The harness runs with your account's
  privileges wherever you start `bin/audit`, with no backend sandbox. That
  includes its preflight builds, which run the target's build scripts, and
  its `bin/probe` runs of testcases an agent left unexecuted. Untrusted
  target code and agent-written testcases therefore execute outside any CLI
  sandbox.
- **Writes reach the harness.** An audit session is granted the TokenFuzz
  checkout (also its working directory), the target tree, and the run's
  results directory. The checkout includes harness code that later runs on
  the host, so the sandbox protects the rest of the host from an agent, not
  the harness from it.
- **Reads are unrestricted.** Any file your account can read, an agent can
  read and send to its provider. The native sandbox provides no
  confidentiality.
- **The environment is inherited.** Agent sessions start with the
  environment of the shell that ran `bin/audit`, so a credential exported
  there is readable by agent commands. Keep credentials you do not want an
  agent to read out of that shell.

When an audit must be separated from host files and credentials, run it in a
container or VM with only the required source and output mounted. The
[containerised backend shell](#containerised-backend-shell) is the supported
helper, with its own limits.

### What leaves the host

- **To the model provider:** the rendered prompts, including the audit guide
  and excerpts of run state, and everything the model reads or runs: source,
  tool output, and any file or variable an agent command prints. Decisions
  send their own prompts, such as report text and source excerpts, to the
  same backend. With `oss`, model traffic goes to the local endpoint instead,
  unless the model is an `opencode/<id>` catalog model.
- **From the harness itself:** S6 peer-fix mining queries `api.osv.dev` with
  the configured peer project names and fetches the fix commits it finds,
  and `bin/setup-target` clones or updates the target from its source URL.
- **Kept on disk:** full transcripts and prompts under
  `output/<target>/<backend>/logs/.raw/`. Codex also writes each session's
  rollout, a full transcript, under `$CODEX_HOME/sessions/`. TokenFuzz
  deletes a rollout after reading its usage; one it cannot fully resolve, a
  delegated thread's own rollout, or one left by a killed run stays there.

### One-shot decisions

Ranking, triage, and validation decisions are single model calls, not agent
sessions, so `--agent-security` does not apply: a decision asserts no
execution boundary. Each runs in a throwaway directory that is removed
afterwards, with web tools denied as described
[below](#one-isolation-policy-for-every-launch), and in its backend's
read-only mode where one exists:

| Backend | Decision launch |
| --- | --- |
| Claude Code | `--permission-mode plan`, a read-only permission mode rather than an OS sandbox |
| Codex | `--sandbox read-only` |
| Google Gemini CLI | `--approval-mode=plan` |
| Grok Build | `--permission-mode plan` and `--no-subagents` |
| OpenCode | No read-only mode. Outside a run, OpenCode's `external_directory` permission is denied; an `oss` audit or benchmark exports `external-bypass`, which leaves only the web tools denied. |
| Antigravity (`agy`) | `--dangerously-skip-permissions`. Its plan mode does not stop a shell write, so it is not used. |

### Egress and socket-driving targets

A target whose harness drives a real socket will fail its probes under
`sandboxed` rather than report a finding: a silent recall loss, not an error
visible in the counts. Claude Code keeps loopback for this reason; Codex
cannot. Audit such a target under `external-bypass` in a hardened
environment, and do not publish sandboxed benchmark rows for it.

### One isolation policy for every launch

Agent sessions in both security modes and one-shot decisions get the same
web denial, so nothing reading an untrusted tree has egress through the
model's own tools. Antigravity is the exception: it has no web switch.

| Backend | How web access is denied |
| --- | --- |
| Claude Code | `--disallowedTools WebFetch,WebSearch`. A read-only plan mode gates the filesystem, not the network. |
| Codex | `web_search="disabled"` (its default is on). |
| Google Gemini CLI | The admin policy in `config/gemini-no-web.policy.toml`. |
| Grok Build | `--disable-web-search`. |
| OpenCode | `webfetch` and `websearch` denied in every profile. |
| Antigravity (`agy`) | Not denied; it exposes no web switch. |

Network access from shell commands still depends on the selected sandbox or
outer environment. Cross-project research (S6 peer fixes and advisories) is
done by the harness's own tooling, not by agents.

Your own CLI extensions are switched off per launch too, because an operator
plugin or MCP server could wrap or replace the audit workflow, and MCP
servers run outside the command sandbox:

| Backend | Extension controls |
| --- | --- |
| Claude Code | `--safe-mode` and `--setting-sources ""`: no plugins, skills, hooks, or settings files. |
| Codex | Plugins off; every enabled MCP server in your `config.toml` disabled by name; the `notify` hook off; prompt history not persisted. A launch is refused if that file cannot be read or parsed, or names an enabled server whose name has characters other than letters, digits, `_`, or `-`. |
| Google Gemini CLI | Skills and extensions disabled in a generated system settings file. |
| Antigravity (`agy`) | `--disable-slash-commands`, its only launch-time control over skills. |

Project instruction discovery stops at the launch directory: Codex gets
`project_root_markers=[]`, Google Gemini CLI an empty memory boundary list,
and for Grok Build and Antigravity TokenFuzz writes a minimal `.git` marker
into the directory the CLI treats as its workspace when that directory has
none, never altering an existing one.

Two things stay uneven and are documented rather than fixed:

- **Cross-run memory** is off by default:
  `CLAUDE_CODE_DISABLE_AUTO_MEMORY=1` for Claude Code, `-c` memory overrides
  for Codex, `--no-memory` for Grok Build, and for Google Gemini CLI both an
  admin policy that denies `save_memory` and the empty staged home described
  [above](#install-and-authenticate). Gemini CLI's separate background
  extraction setting, `experimental.autoMemory`, defaults to off and
  TokenFuzz never sets it. `--enable-memory` turns memory on; leave
  it off unless cumulative learning is intentional. Antigravity (`agy`) has
  no memory or home isolation and keeps its memory store beside its OAuth
  token, so its cross-run memory cannot be isolated. Prefer
  `USE_GEMINI_CLI=1` for benchmark rows.
- **Delegation.** Every backend keeps its CLI's default subagent delegation,
  because a control that cannot delegate is not the product a user gets.
  Only the bounded trigger reviews and Grok decisions turn it off. Each
  usage row records what the session delegated as `delegation_events`; on
  Codex, OpenCode, and Grok a delegating row's spend is a floor, as the
  [benchmark page](../concepts/benchmark.md) explains.

## Capacity pauses and provider failures

A provider limit does not end a run. After each session TokenFuzz classifies
the transcript as capacity-limited (a rate limit, quota, or account usage
limit), transient (a server error or overload), or refused (a revoked
credential, a model the provider will not serve, or a safeguard rejection of
the prompt). Any of these stops new launches; in-flight sessions finish, and
then:

| Class | What `bin/audit` does |
| --- | --- |
| Capacity-limited | Pauses until the reset time the provider reports in its structured rate-limit event, plus 30 seconds, then retries. Without a machine-readable reset time it retries every 30 minutes, which also picks up a quota you reset by hand. |
| Transient | Retries after 30 seconds, doubling up to 5 minutes, at most six times in a row. |
| Refused | Stops that backend at once; waiting cannot clear a refusal. |

A backend stops pausing after six hours of pauses in one run (a fixed limit,
not an environment variable). Paused time does not count against
`AUDIT_WALL_BUDGET_SECS`.

When a backend cannot recover, the log says `BACKEND_UNAVAILABLE`, and a
single-backend run exits with status 1. In an ensemble, a capacity-limited
backend leaves the rotation while another backend is still running, and
only the last one pauses; a transient failure moves on to the next backend;
the run exits with status 1 only when every backend has failed. For
`gemini`, a watchdog also ends a session stalled on sustained quota errors
instead of letting it run to `AGENT_TIMEOUT`.

Rerunning the same command resumes from saved state. Log lines and fixes
are under
[The run paused, or the backend went unavailable](../reference/troubleshooting.md#the-run-paused-or-the-backend-went-unavailable).

## Containerised backend shell

The supported container helper puts the backend CLIs and the repository in a
repeatable Linux environment:

```bash
bin/audit-container-shell --rebuild   # first use
bin/audit-container-shell             # reuse the image
```

It opens a shell at `/root/work`; it does not start an audit. What it does
and does not isolate:

- **Mounted:** the whole repository, read-write, including harness code and
  every target and output tree under it. The shell runs as root inside the
  container, with `no-new-privileges` set by default.
- **Not mounted:** host credential directories (`~/.claude`, `~/.codex`,
  `~/.gemini`, `~/.grok`, `~/.local/share/opencode`). Authenticate inside
  the disposable shell, or pass `--forward-credentials` to forward the
  supported API key variables and mount Google credentials read-only (the
  file `GOOGLE_APPLICATION_CREDENTIALS` names, and `~/.config/gcloud`).
- **Not restricted:** network. The container uses Docker's default network.
- **Asserted:** `IS_SANDBOX=1` is set, because the container is the boundary
  `external-bypass` relies on.

The default `sandboxed` mode also works inside the container when the
runtime permits the CLI's nested sandbox; when it does not, use
`--agent-security external-bypass` there. The helper's variables are under
[Container runtime](../reference/environment.md#container-runtime). See
[Where to run the audit](../getting-started/first-audit.md#where-to-run-the-audit)
for the trust boundary and
[Container runtime](../getting-started/prerequisites.md#container-runtime-recommended)
for Docker and gVisor setup.

## OpenCode provider and local models

The `oss` backend can use a model from OpenCode's catalog provider, which is
a hosted service, not your machine. Refresh the catalog and verify the exact
provider-qualified id first:

```bash
opencode models opencode --refresh
opencode run --pure --model opencode/<model-id> "Reply exactly: tokenfuzz-opencode-auth-ok"

bin/audit --target <target> --backend oss --model opencode/<model-id> 1
```

TokenFuzz passes an `opencode/` model reference to the installed CLI, which
keeps OpenCode's own credential and provider handling. No security flag is
needed, but the default is `external-bypass`; read
[Agent security modes](#agent-security-modes) before running it on a host.

### Local OpenAI-compatible models

Any other `--model` value is served through an OpenAI-compatible endpoint,
by default `http://127.0.0.1:8000/v1`; set `AUDIT_LOCAL_BASE_URL` for
another address, and `AUDIT_LOCAL_API_KEY` only when the server requires
authentication. Install OpenCode, then start a server. vLLM suits GPU hosts
and larger models; Ollama suits a desktop or a smaller model:

```bash
# vLLM
python3 -m venv .venv-vllm
. .venv-vllm/bin/activate
pip install -U vllm
vllm serve <model-or-path> --served-model-name audit-model
bin/audit --target <target> --backend oss --model audit-model 1

# Ollama: pass the exact tag its OpenAI-compatible models endpoint reports
ollama pull <model-tag>
ollama serve
export AUDIT_LOCAL_BASE_URL=http://127.0.0.1:11434/v1
bin/audit --target <target> --backend oss --model <model-tag> 1
```

The model preflight catches an endpoint that does not serve the id. To check
it yourself first:

```bash
python3 lib/llm_invoke.py local-model-available --model <served-model-id> \
  && echo served
```

Model traffic stays on the machine only when the endpoint is actually local
and OpenCode is not configured to call another provider. The model still
receives the source excerpts, prompts, state, and reports the audit needs.
Small models may need narrower target scopes and more human review. A slow
local model tends to hit the preflight and decision timeouts; see
[Local model endpoint](../reference/environment.md#local-model-endpoint).

## Inspect and record results

Start with `output/<target>/<backend>/logs/index.log`, which names each
session's extracted text log, then the findings, crashes, and rejected
indexes listed in [Artifacts](../reference/artifacts.md). Judge a backend by
those indexes, not by the style or length of its transcripts: token usage
and tool counts are operational signals, while validated, deduplicated
findings and crash bundles are the security output.

Record the target revision, `target.toml`, backend, model, and any
non-default reasoning effort with results. Review each provider's data
handling and spend before continuous runs. For hosted defensive research,
the provider-access links are under
[Cyber access](../getting-started/prerequisites.md#cyber-access-for-security-research).
