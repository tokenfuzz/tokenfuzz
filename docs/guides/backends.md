# Backends and Ensembling

TokenFuzz treats agent backends as **interchangeable runners** behind
the same probe and triage contract. That gives you two operating modes
worth knowing:

- **Single backend** — reproducible, lowest cost.
- **Ensemble of hosted backends** — rotated across iterations while
  keeping each backend's evidence in its own result tree.

This page covers backend selection, how the ensemble cycle works, and
how to inspect backend-specific result trees.

## Backend options

```bash
bin/audit --backend <backend> --target <target-name> [--model <model>]
bin/audit --backend all --target <target-name>   # cycle installed hosted backends
```

How to choose:

- `--backend all` (or omitting `--backend` entirely) discovers the
  hosted CLIs installed locally (`claude → codex → gemini → grok` order) and
  **cycles between them** iteration by iteration. Each backend writes
  to its own `output/<target>/<backend>/results/` tree, so the cycle
  does not race or overwrite. `oss` is excluded from the hosted cycle
  because it needs an explicit `--model`.
- Use an explicit `--backend` when you want reproducible runs or cost
  control.
- `<backend>` is one of `all`, `claude`, `codex`, `gemini`, `grok`, or `oss`.
  `all` is the no-`--backend` default described above.
- `--model` overrides the model name for `claude`, `codex`, and `grok`; for
  `oss`, it is required and names the local model served through OpenCode.
  OpenCode is always configured with one local provider ref,
  `local/<model>`. The default local endpoint is vLLM-style
  `http://127.0.0.1:8000/v1`; set `AUDIT_LOCAL_BASE_URL` for Ollama or
  any other OpenAI-compatible server.
  The `gemini` backend uses the Antigravity CLI (`agy`) by default. Pass
  `--model` as either the config slug (e.g. `gemini-3.1-pro-preview`) or
  an exact `agy models` label (e.g. `"Gemini 3.1 Pro (High)"`); the
  harness maps the slug to a label and a preflight rejects an
  unrecognized value before launch. Set `USE_GEMINI_CLI=1` to use the
  Google Gemini CLI (`gemini`) instead, where `--model` is forwarded
  directly. The per-backend defaults live in
  [Model selection](../reference/environment.md#model-selection).
- For `--backend oss`, `--model` is required and must match the exact
  model id listed by the selected provider's `/v1/models` endpoint.

### Grok Build

Install xAI's Grok Build CLI, set its API key, and verify one headless
request before starting an audit:

```bash
curl -fsSL https://x.ai/cli/install.sh | bash
export XAI_API_KEY="<xai-api-key>"
grok -p "Reply exactly: tokenfuzz-grok-auth-ok"
bin/audit --backend grok --target <target-name> 1
```

The default model is `grok-build-0.1`. Override it with `--model`,
`GROK_MODEL_DEFAULT`, or `config/models.toml`; use `GROK_BIN` when the
binary is not named `grok` or is outside `PATH`. TokenFuzz runs Grok in
headless streaming-JSON mode, auto-approves audit tools, disables Grok's
nested subagents, and resumes the CLI session on later iterations. See
xAI's [Grok Build overview](https://docs.x.ai/build/overview) and
[headless mode reference](https://docs.x.ai/build/cli/headless-scripting) for the
upstream CLI contract.

Grok Build's stream does not currently expose token-usage counters, so
TokenFuzz marks its prompt and output token counts as estimates. Cost
reports apply xAI's
[published Grok Build API pricing](https://docs.x.ai/developers/models/grok-build-0.1)
to those estimates.

### Google Gemini CLI ripgrep

When `USE_GEMINI_CLI=1` selects Google Gemini CLI, that CLI looks for
`ripgrep` inside its npm bundle instead of using `rg` from `PATH`. Some
installs miss that bundled file, so Gemini prints `Ripgrep is not
available` and falls back to a slower grep implementation. TokenFuzz
warns at startup and prints the path it checked.

Fix the Gemini CLI install that TokenFuzz will run. `GEMINI_BIN` wins
when set; otherwise TokenFuzz uses the first `gemini` on `PATH`. Use
`type -a gemini` or `whereis gemini` if you need to inspect multiple
installs.

```bash
gemini_bin="${GEMINI_BIN:-$(command -v gemini)}"
system_rg="$(command -v rg)"
[ -n "$gemini_bin" ] || { echo "gemini not found; set GEMINI_BIN=/path/to/gemini" >&2; exit 1; }
[ -n "$system_rg" ] || { echo "rg not found; install ripgrep first" >&2; exit 1; }

bundle_dir="$(node -e 'const p=require("path"),f=require("fs");process.stdout.write(p.dirname(f.realpathSync(process.argv[1])))' "$gemini_bin")"
plat_arch="$(node -e 'process.stdout.write(process.platform+"-"+process.arch)')"
vendor_rg="$bundle_dir/vendor/ripgrep/rg-$plat_arch"

mkdir -p "${vendor_rg%/*}"
ln -sfn "$system_rg" "$vendor_rg"
```

On Windows the vendored file name ends in `.exe`; TokenFuzz's startup
warning prints the exact command for that platform. If the npm bundle is
system-owned and `mkdir` or `ln` fails with permission denied, rerun
those two commands with `sudo`, or set `GEMINI_BIN` to a user-writable
Gemini CLI install.

## Containerised backend shell

`bin/audit-container-shell` opens a clean shell with the hosted backend
CLIs installed and this repository mounted at `/root/work`:

```bash
bin/audit-container-shell
```

See
[Where to run the audit](../getting-started/first-audit.md#where-to-run-the-audit)
for what the helper builds, the base-image and gVisor flags, and why a
container is the recommended default. The helper does **not** start an
audit automatically.

The shell mounts no host CLI credential directories (`~/.claude`,
`~/.codex`, `~/.gemini`, `~/.grok`), so it starts logged out. Log in to the
backend you plan to use, or pass `--forward-credentials` to forward API
key/token environment variables before launching the helper. With
`--forward-credentials`, `~/.config/gcloud` and a
`GOOGLE_APPLICATION_CREDENTIALS` file are mounted read-only when present
so Google API-key / ADC flows still work.

```bash
# codex login     # opens an OAuth URL; codex login status to confirm
# claude          # run once and follow the login prompt
# agy             # run once and follow the printed OAuth URL
```

Then verify auth before launching an audit:

```bash
# codex login status
# claude -p "Reply exactly: tokenfuzz-claude-auth-ok"
# agy -p "Reply exactly: tokenfuzz-gemini-auth-ok"
# grok -p "Reply exactly: tokenfuzz-grok-auth-ok"
```

`codex login status` is a local check; the `claude`/`agy`/`grok` checks make one
small model request and print the reply. Grok needs `XAI_API_KEY` in the
container, normally via `--forward-credentials`, unless you logged in there.
If a check hangs at a prompt,
press Ctrl+C and finish that backend's login before starting
`./bin/audit` from `/root/work`. An in-container login lasts only for
that container session, since the shell runs disposable (`--rm`).

## What changes by backend, what does not

| Changes | Does not change |
| --- | --- |
| Agent CLI process | Target directory layout |
| Model name and provider | `target.toml` format |
| Latency and cost | Result and log directory layout |
| Context behaviour | Probe execution contract |
| Tool-calling style | Triage rules |
| Local versus hosted execution | |

This separation is intentional. Backends are interchangeable because
the harness owns the audit contract.

## Ensemble mode

When `--backend` is omitted or set to `all`, `bin/audit` runs in
**hosted ensemble mode**. At startup it checks the hosted CLIs in
this order:

```text
claude → codex → gemini → grok
```

Only installed and authenticated CLIs join the cycle. `oss` is excluded
because it requires an explicit local model choice.

Each audit iteration selects the next configured hosted backend in
that order and writes into a separate result tree per backend:

```text
output/<target>/claude/results/
output/<target>/codex/results/
output/<target>/gemini/results/
output/<target>/grok/results/
```

That separation keeps backend-local state, logs, scratch inputs, and
rate-limit cooldowns from interfering with each other. Cross-backend
cluster rollups still aggregate at the target root:

```text
output/<target>/CRASH-CLUSTERS.html
output/<target>/FINDING-CLUSTERS.html
```

You get per-backend evidence directories **and** an aggregate view of
what the ensemble found, without writing anything custom.

### What ensemble mode is for

- **Operational rotation.** Rotation spreads work across configured
  hosted providers. That can be useful when one provider is
  rate-limited or temporarily degraded.
- **Separate evidence trees.** Each backend writes its own results,
  logs, scratch inputs, and rejected indexes. The target-level rollups
  still give you one place to review accepted artifacts.

### When a single backend is better

- **Cost-controlled long runs.** A single backend with a known
  per-token price is easier to budget.
- **Reproducibility in published research.** Pin both `--backend` and
  `--model` so the run can be replayed.
- **Source-sensitivity policies.** Use `--backend oss` to keep target
  source on the local machine.

## Inspecting backend results

When you inspect backend-specific output:

1. Record the target source revision.
2. Record the `target.toml` used for the run.
3. Run a bounded session per backend when you need isolated result
   trees:

   ```bash
   bin/audit --backend <backend> --target <target-name> [--model <model>] 10
   ```

4. Inspect each result tree separately:

   ```bash
   for B in claude codex gemini grok oss; do
     R="output/<target>/$B/results"
     echo "== $B =="
     ls "$R/crashes" "$R/findings" 2>/dev/null | head
   done
   ```

The useful review artifacts are:

- confirmed crashes;
- accepted findings;
- rejected-index quality.

Token usage and tool counts are recorded when the backend's log format
exposes them. They are operational signals — the artifact quality
still comes from the cluster tables in `crashes/` and `findings/`. See
[Cost model](../concepts/cost-model.md#what-to-monitor) for which
numbers to watch.

## Local models through OpenCode

```bash
bin/audit --backend oss --model <model-name>
```

The local backend runs OpenCode against a local OpenAI-compatible model
server. Use vLLM when you care about throughput and larger open models;
it is the default because it is built for fast batched inference on GPU
hosts. Use Ollama when you want the simplest desktop setup, especially
on macOS or for smaller models.

Install OpenCode first. The official installer options include:

```bash
curl -fsSL https://opencode.ai/install | bash
# or: npm i -g opencode-ai
# or on macOS: brew install anomalyco/tap/opencode
```

### vLLM path (recommended)

Install [vLLM](https://docs.vllm.ai/en/latest/getting_started/installation/)
on the machine that has the GPU:

```bash
python3 -m venv .venv-vllm
. .venv-vllm/bin/activate
pip install -U vllm
```

Start a model with an explicit served name. The served name is what you
pass to `--model`:

```bash
vllm serve <hf-model-or-local-path> --served-model-name qwen3-8b

bin/audit --backend oss --model qwen3-8b --target <target-name> 1
```

For current larger open models, use the upstream model id as the vLLM
source and choose a short served name for the harness. The ids below are
illustrative — substitute a model you actually serve:

```bash
# Gemma 4 26B-A4B
vllm serve google/gemma-4-26B-A4B --served-model-name gemma4-26b-a4b
bin/audit --backend oss --model gemma4-26b-a4b --target <target-name> 1

# Qwen3.6 35B-A3B
vllm serve Qwen/Qwen3.6-35B-A3B --served-model-name qwen3.6-35b-a3b
bin/audit --backend oss --model qwen3.6-35b-a3b --target <target-name> 1

# GLM-5.2
vllm serve zai-org/GLM-5.2 --served-model-name glm5.2
bin/audit --backend oss --model glm5.2 --target <target-name> 1
```

If vLLM is not on the default URL, point the harness at it:

```bash
export AUDIT_LOCAL_BASE_URL=http://127.0.0.1:8000/v1
bin/audit --backend oss --model qwen3-8b --target <target-name>
```

### Ollama path

Install Ollama from its official download page, then pull and serve the
model:

```bash
# Linux:
curl -fsSL https://ollama.com/install.sh | sh

ollama pull qwen3:8b
ollama serve

export AUDIT_LOCAL_BASE_URL=http://127.0.0.1:11434/v1
bin/audit --backend oss --model qwen3:8b --target <target-name> 1
```

Common Ollama examples use Ollama's tag as the exact model name:

```bash
# Gemma 4 26B-A4B
ollama pull gemma4:26b
export AUDIT_LOCAL_BASE_URL=http://127.0.0.1:11434/v1
bin/audit --backend oss --model gemma4:26b --target <target-name> 1

# Qwen3.6 35B-A3B
ollama pull qwen3.6:35b-a3b
export AUDIT_LOCAL_BASE_URL=http://127.0.0.1:11434/v1
bin/audit --backend oss --model qwen3.6:35b-a3b --target <target-name> 1

# GLM-5.2. Ollama currently publishes this as a cloud tag; use vLLM
# instead when you need fully local GLM-5.2 weights.
ollama pull glm-5.2:cloud
export AUDIT_LOCAL_BASE_URL=http://127.0.0.1:11434/v1
bin/audit --backend oss --model glm-5.2:cloud --target <target-name> 1
```

If Ollama is not on the default URL, set the shared local base URL:

```bash
export AUDIT_LOCAL_BASE_URL=http://127.0.0.1:11434/v1
bin/audit --backend oss --model qwen3:8b --target <target-name>
```

At startup, the harness asks the selected provider's `/v1/models`
endpoint for the served model list. If the model is missing, it fails
before launching agents. That avoids burning an audit session on a
misnamed model or a server that was never started.

Local models are useful for:

- broad experimentation;
- source-sensitive targets;
- running 24/7 without provider rate limits.

They may need shorter task scopes and tighter iteration limits than
hosted models.

## Backend hygiene

- Authenticate the CLI outside the harness first.
- Prefer explicit `--backend` in reproducibility notes.
- Record `--model` overrides alongside `--backend` in run notes.
- Keep API spend visible before continuous runs — see
  [Cost model](../concepts/cost-model.md).
- Check `logs/` for CLI failures before assuming an agent stalled.
- Review runs by `crashes/`, `findings/`, `state/runs.jsonl`, and
  rejected indexes — not by transcript style.

## Cyber access for hosted runs

If you use a hosted model for legitimate defensive security research,
register your organisation and use case ahead of long sessions so the
provider has the context to reduce false-positive interruptions. The
relevant programs and signup links are documented once, in
[Prerequisites](../getting-started/prerequisites.md#cyber-access-for-security-research).
