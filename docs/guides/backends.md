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

| Backend | CLI | Model behavior |
| --- | --- | --- |
| `claude` | Claude Code (`claude`) | Uses `config/models.toml` unless `--model` is passed. |
| `codex` | Codex CLI (`codex`) | Uses `config/models.toml` unless `--model` is passed. |
| `gemini` | Antigravity CLI (`agy`) by default | A config model slug is mapped to an `agy models` label. Set `USE_GEMINI_CLI=1` to use Google Gemini CLI instead. |
| `grok` | Grok Build (`grok`) | Uses `config/models.toml` unless `--model` is passed. |
| `oss` | OpenCode (`opencode`) | `--model` is required and must match the exact id served by the local endpoint. |
| `all` | Installed hosted CLIs | Cycles `claude → codex → gemini → grok`; excludes `oss`. |

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

### Grok Build

Grok needs its CLI credentials (commonly `XAI_API_KEY`) before launch:

```bash
grok -p "Reply exactly: tokenfuzz-grok-auth-ok"
bin/audit --target <target> --backend grok 1
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
- Evaluate results through findings, crashes, and rejected indexes—not the
  style or length of the backend transcript.

For hosted defensive research, the provider-access links are collected under
[Cyber access](../getting-started/prerequisites.md#cyber-access-for-security-research).
