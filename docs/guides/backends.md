# Backends and Ensembling

TokenFuzz keeps the audit contract independent of the model CLI. Target config,
work state, testcase execution, triage, and artifact layout remain the same
whether an audit uses one hosted backend, rotates several, or runs a local
model.

Use one backend for reproducible and cost-controlled work. Use hosted ensemble
mode when operational diversity matters more than a single fixed model.

## Choose a backend

```bash
bin/audit --target <target> --backend <backend> [--model <model>]
bin/audit --target <target> --backend all
```

Agent launches default to `--agent-security sandboxed`, which runs the backend
inside its own OS sandbox and refuses backends whose sandbox cannot host an
audit. `--agent-security external-bypass` drops that boundary for an outer one
you administer, and is refused unless the environment asserts `IS_SANDBOX=1`.
See [Agent security modes](#agent-security-modes).

| Backend | CLI | Model behavior |
| --- | --- | --- |
| `claude` | Claude Code (`claude`) | Uses `config/models.toml` unless `--model` is passed. |
| `codex` | Codex CLI (`codex`) | Uses `config/models.toml` unless `--model` is passed. |
| `gemini` | Antigravity CLI (`agy`) by default | A config model slug is mapped to an `agy models` label. Set `USE_GEMINI_CLI=1` to use Google Gemini CLI instead. |
| `grok` | Grok Build (`grok`) | Uses `config/models.toml` unless `--model` is passed. |
| `oss` | OpenCode (`opencode`) | `--model` is required and must match the exact id served by the local endpoint. |
| `all` | Installed hosted CLIs | Cycles `claude → codex → gemini → grok`; excludes `oss`, and skips any backend the selected [security mode](#agent-security-modes) cannot launch. |

Use an explicit `--backend` and `--model` in any reproduction or benchmark
record. Omitting `--backend` is the same as `--backend all`.

### Models and reasoning effort

`config/models.toml` is the checked-in source of truth for default model names
and backend-native reasoning effort. Model precedence is:

1. `--model`;
2. the backend's `*_MODEL_DEFAULT` environment override;
3. `config/models.toml`.

The `[effort]` table is applied in the backend's native form—for example Codex
model reasoning effort, Gemini thinking level, or the corresponding Claude and
Grok flags. Edit the config when changing project defaults so normal audits,
validation and direct model decisions stay aligned.

For the default `agy` Gemini path, `--model` accepts either the config slug or
an exact label printed by `agy models`. Preflight rejects an unknown mapping
before an agent starts. Under `USE_GEMINI_CLI=1`, the value is passed directly
to Google Gemini CLI.

### Install and authenticate

Install the chosen CLI through its upstream instructions:

- [Claude Code](https://docs.claude.com/en/docs/claude-code)
- [Codex CLI](https://developers.openai.com/codex/cli)
- [Antigravity CLI](https://github.com/google-antigravity/antigravity-cli)
- [Google Gemini CLI](https://github.com/google-gemini/gemini-cli)
- [Grok Build](https://docs.x.ai/build/overview)
- [OpenCode](https://opencode.ai/download)

Run one direct, non-interactive check before an audit. A backend that is waiting
for login can otherwise look like a stalled agent. Credentials remain owned by
the CLI; do not put keys in `target.toml` or reports.

## Agent security modes

Every agent launch runs under one of two modes. `sandboxed` is the default and
needs no flag; `external-bypass` must be asked for and is refused unless the
environment asserts `IS_SANDBOX=1`.

| Mode | What enforces the boundary | When to use it |
| --- | --- | --- |
| `sandboxed` (default) | The backend CLI's own OS sandbox — Seatbelt on macOS, Landlock/seccomp or bubblewrap on Linux. Approval prompts are turned off, because a headless run cannot answer one and an approval the model can request is not a boundary. | Normal runs on a machine you also use for other things. |
| `external-bypass` | Nothing in the CLI. You are asserting that an outer container or VM enforces filesystem, process, credential, and egress policy. | Inside a container or VM you administer, and for the backends `sandboxed` refuses. |

A third, classifier-reviewed `auto` mode is deliberately absent: it would add
provider calls, latency, and variable decisions to the audit and benchmark
contract without creating a stronger boundary.

### What the sandbox does and does not buy

A native sandbox gives **integrity and process containment**: the agent cannot
write outside its workspace or reach the network. It is **not a confidentiality
boundary** — every one of these sandboxes still reads the whole filesystem, and
whatever the model reads travels to its provider by design. If secrets on the
machine are in scope, the boundary is a hardened outer container or VM with only
the target mounted, entered before the audit starts.

### Backend support

A backend is listed as supported only where the sandbox was measured doing the
two things an audit needs — reading the target tree and writing results — while
still containing the agent. Where it is not, TokenFuzz refuses the launch rather
than filing the run as contained.

| Backend | `sandboxed` | What it enforces, or why it is refused |
| --- | --- | --- |
| Claude Code | Supported | Writes confined to the workspace (cwd plus `--add-dir`, including through the benchmark facade's symlinks); outbound network and DNS blocked; loopback kept open so local client/server harnesses still probe; web tools denied; unsandboxed commands denied and an unavailable sandbox is a hard error. |
| Codex | Supported | `workspace-write` with `approval_policy="never"`: writes confined to the workspace roots the harness supplies, reads unrestricted, and **all** network blocked — including loopback, which it has no setting to re-open. |
| Antigravity (`agy`) | Refused | Its terminal sandbox runs commands in a scratch directory, refuses writes to the launch directory, denies reads outside it, and auto-denies its file-writing tool headless. An audit could neither read the target nor file a result. |
| Google Gemini CLI | Refused | Its container mounts only the launch directory — `--include-directories` adds workspace context, not a mount — so a cell runs blind to the target. Its macOS profile allows outbound network. |
| Grok Build | Refused | `workspace` reads the whole host, including `$HOME` (only writes to credential paths are blocked) and allows outbound network — measured, not inferred. Its one read-restricting profile sees nothing outside `--cwd`, which would leave a model-direct control blind to the target it is scored against. |
| OpenCode (`oss`) | Refused | Its permissions are an approval policy, not an OS sandbox. Read-only decision calls still run, with external directories and web tools denied. |

Refused backends stay fully available under `external-bypass`. On a plain host
the default therefore selects Claude Code or Codex; `--backend all` skips the
rest and says which and why.

### Egress and socket-driving targets

A target whose harness drives a real socket will fail its probes under
`sandboxed` rather than report a finding — a silent recall loss, not an error
visible in the counts. Claude Code keeps loopback for exactly this reason; Codex
cannot. Audit such a target under `external-bypass` in a hardened environment,
and do not publish sandboxed benchmark rows for it.

### Using the modes

```bash
# Default: the backend's own sandbox, no flag needed.
bin/audit --target <target> --backend codex 1

# Compatibility path, only after entering an externally hardened shell.
bin/audit --target <target> --backend grok --agent-security external-bypass 1
```

The chosen mode is written to `state/run-config.json` and inherited by every
subprocess of the run, including source-reading validators. `bin/benchmark`
accepts the same flag, applies it to both model-direct and harness cells, writes
it to `run.json`, refuses to resume a run under a different mode, and re-scores
a `--regenerate` under the mode that run recorded. `--backend all` skips a
backend the mode cannot launch and says so; a backend named on the command line
is a hard error instead.

### Grok Build

Grok needs its CLI credentials (commonly `XAI_API_KEY`) before launch:

```bash
grok -p "Reply exactly: tokenfuzz-grok-auth-ok"
# Grok is refused by the default mode; run it inside a boundary you
# administer (see Agent security modes).
bin/audit --target <target> --backend grok --agent-security external-bypass 1
```

TokenFuzz uses headless streaming JSON, disables nested Grok subagents, applies
the configured reasoning effort, and resumes the CLI session on later
iterations. Grok's stream may not expose measured token counts; when it does
not, usage reports label estimates rather than presenting them as measured.

### Google Gemini CLI ripgrep

When `USE_GEMINI_CLI=1`, some npm installations lack the CLI's vendored
`ripgrep` binary. TokenFuzz warns with the path it checked. Repair or reinstall
the Gemini CLI rather than changing TokenFuzz's source-search commands. The
default Antigravity (`agy`) path does not use this bundle layout.

## Containerised backend shell

The supported container helper puts the hosted CLIs and repository in a
repeatable Linux environment:

```bash
bin/audit-container-shell --rebuild   # first use
bin/audit-container-shell             # reuse the image
```

It opens a shell at `/root/work`; it does not start an audit. Host credential
directories (`~/.claude`, `~/.codex`, `~/.gemini`, `~/.grok`) are not mounted.
Authenticate in the disposable shell or pass `--forward-credentials` to forward
supported API variables and read-only Google ADC files explicitly.

See [Where to run the audit](../getting-started/first-audit.md#where-to-run-the-audit)
for the trust boundary and [Container runtime](../getting-started/prerequisites.md#container-runtime-recommended)
for Docker and gVisor setup.

## Ensemble mode

When `--backend` is omitted or set to `all`, each iteration selects the next
installed hosted backend:

```text
claude → codex → gemini → grok → claude → …
```

Each backend has independent evidence and logs:

```text
output/<target>/claude/results/
output/<target>/codex/results/
output/<target>/gemini/results/
output/<target>/grok/results/
```

Target-level cluster summaries combine accepted results:

```text
output/<target>/FINDING-CLUSTERS.html
output/<target>/CRASH-CLUSTERS.html
```

### When ensemble mode helps

- A provider is intermittently rate-limited or degraded.
- You want independent model behavior behind the same execution and triage
  rules.
- You want a target-level view while preserving backend-specific provenance.

### When one backend is better

- You need a reproducible method section with one fixed model.
- You are controlling spend against a known price.
- Source-handling policy requires the local `oss` path.
- You are comparing harness changes and need to hold the backend constant.

Ensemble mode is rotation, not consensus voting. Each backend works its own
state tree; the target-level summaries cluster results after the fact.

## Local models through OpenCode

The `oss` backend runs OpenCode against an OpenAI-compatible server. TokenFuzz
defaults to `http://127.0.0.1:8000/v1` and verifies the requested model against
the server's `/v1/models` response before launching agents.

```bash
bin/audit --target <target> --backend oss --model <served-model-id> 1
```

Install OpenCode, then choose a server:

### vLLM path

vLLM is suited to GPU hosts and larger models:

```bash
python3 -m venv .venv-vllm
. .venv-vllm/bin/activate
pip install -U vllm
vllm serve <model-or-path> --served-model-name audit-model

bin/audit --target <target> --backend oss --model audit-model 1
```

If the server is not on the default address:

```bash
export AUDIT_LOCAL_BASE_URL=http://127.0.0.1:9000/v1
bin/audit --target <target> --backend oss --model audit-model 1
```

### Ollama path

Ollama is convenient for a desktop or smaller local model:

```bash
ollama pull <model-tag>
ollama serve

export AUDIT_LOCAL_BASE_URL=http://127.0.0.1:11434/v1
bin/audit --target <target> --backend oss --model <model-tag> 1
```

Pass the exact tag reported by Ollama's OpenAI-compatible models endpoint. Set
`AUDIT_LOCAL_API_KEY` only when the local server requires authentication.

Local operation keeps model data flow on the selected machine, but the model
still receives the source excerpts, prompts, state, and reports required for
the audit. Small models may need narrower target scopes and more human review.

## Inspect backend results

For one backend, start with:

```text
output/<target>/<backend>/results/findings/FINDING-CLUSTERS.html
output/<target>/<backend>/results/crashes/CRASH-CLUSTERS.html
output/<target>/<backend>/results/crashes-rejected/REJECTED-CRASHES.html
output/<target>/<backend>/logs/index.log
```

Record the target revision, `target.toml`, backend, model, and any non-default
reasoning effort with results. Token usage and tool counts are operational
signals; validated, deduplicated findings and crash bundles are the security
output.

## Backend hygiene

- Authenticate outside the audit loop.
- Pin backend and model for reproducibility.
- Review provider data-handling and spend before continuous runs.
- Keep cross-run learned memory off unless cumulative learning is intentional;
  it is off by default.
- Diagnose startup in `logs/index.log`, then use the named trimmed session log.
- Expect quota pauses on long runs rather than treating them as failures — see
  [The run paused, or the backend went unavailable](../reference/troubleshooting.md#the-run-paused-or-the-backend-went-unavailable).
- Evaluate results through findings, crashes, and rejected indexes—not the
  style or length of the backend transcript.

For hosted defensive research, the provider-access links are collected under
[Cyber access](../getting-started/prerequisites.md#cyber-access-for-security-research).
