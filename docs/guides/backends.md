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
  hosted CLIs installed locally (`claude → codex → gemini` order) and
  **cycles between them** iteration by iteration. Each backend writes
  to its own `output/<target>/<backend>/results/` tree, so the cycle
  does not race or overwrite. `oss` is excluded from the hosted cycle
  because it needs an explicit `--model`.
- Use an explicit `--backend` when you want reproducible runs or cost
  control.
- `<backend>` is one of `claude`, `codex`, `gemini`, or `oss`.
- `--model` overrides the model name for `claude` and `codex`; for
  `oss`, it is required and must name an already-pulled Ollama model.
  The `gemini` backend uses Antigravity CLI (`agy`) by default; `agy`
  has no launch-time model selector, so use its interactive `/model`
  command. Set `USE_GEMINI_CLI=1` to use Google Gemini CLI (`gemini`)
  instead; in that mode `--model` is forwarded at launch time. The
  per-backend defaults live in
  [Model selection](../reference/environment.md#model-selection).
- For `--backend oss`, `--model` is required. The harness checks
  `ollama list` at startup and fails fast if the model is not already
  pulled.

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
`~/.codex`, `~/.gemini`), so it starts logged out. Log in to the
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
```

`codex login status` is a local check; the `claude`/`agy` checks make one
small model request and print the reply. If a check hangs at a prompt,
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
claude → codex → gemini
```

Only installed and authenticated CLIs join the cycle. `oss` is excluded
because it requires an explicit local model choice.

Each audit iteration selects the next configured hosted backend in
that order and writes into a separate result tree per backend:

```text
output/<target>/claude/results/
output/<target>/codex/results/
output/<target>/gemini/results/
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
   for B in claude codex gemini oss; do
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

## Local models through Ollama

```bash
bin/audit --backend oss --model <model-name>
```

The local backend runs Codex in OSS mode against an Ollama-hosted
model. Check that Ollama is running and the model is available before
starting a long session:

```bash
ollama list
```

The harness checks this at startup for `--backend oss` and fails fast
if the model is not already listed. That avoids letting Codex trigger
a long implicit download mid-run.

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
