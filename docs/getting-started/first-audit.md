# First Audit

This walkthrough runs **one bounded audit iteration end-to-end** so you
can prove the pipeline works before committing to a long run.

It assumes you have already worked through:

- [Prerequisites](prerequisites.md), and
- [Add a target](add-a-target.md).

If you have not done those yet, do them first — this page picks up
where they end.

Run this **inside a container** if you can — target builds and
agent shells are untrusted code. Setup is in
[Where to run the audit](#where-to-run-the-audit) at the bottom of
this page. On the host, use a machine without long-lived credentials.

## What you will finish with

A single completed `bin/audit --target <target> --backend <backend> 1`
run. Concretely, that means:

- the startup block is in `output/<target>/<backend>/logs/index.log`,
  including an `Agent pool:` line with the actual worker count;
- `output/<target>/<backend>/results/state/` has at least one
  `hypotheses.jsonl` row and one `runs.jsonl` row;
- `scratch-N/` contains the agent's draft testcases;
- `crashes/` and `findings/` exist (probably empty after one
  iteration — that is fine).

The goal is **to prove the pipeline runs end to end**, not to find a
bug. A first run that produces no crash is still a successful first
run.

To keep the commands consistent, set a few variables once:

```bash
export TARGET=libxml2       # any directory name under targets/
export BACKEND="<backend>"  # one of: claude, codex, gemini, oss
# Optional convenience paths for inspecting results.
export RESULTS="output/$TARGET/$BACKEND/results"
export LOGS="output/$TARGET/$BACKEND/logs"
```

Leaving the placeholders unset will fail with
`AUDIT_BACKEND must be all, claude, codex, gemini, or oss`.

## 1. Run one iteration

This runs the whole audit pipeline in miniature: backend launch,
work-card ranking, and as much testcase work as the agent can complete
in one iteration.

```bash
bin/audit --target "$TARGET" --backend "$BACKEND" 1
```

If you do not pass `--model`, the harness picks the default for the
selected backend:

| Backend | Default without `--model` |
|---------|---------------------------|
| `claude` | `claude-opus-4-8` |
| `codex` | `gpt-5.5` |
| `gemini` with Antigravity CLI (`agy`) | `--model` is not supported; `agy` keeps model selection in its interactive `/model` setting. |
| `gemini` with Google Gemini CLI (`USE_GEMINI_CLI=1`) | `gemini-3.1-pro-preview` |
| `oss` | No default; `--model <ollama-model>` is required. |

For a focused smoke test (one strategy only, easier to compare across
runs), add `--strategy S1` (or `S2`, …, `S8`). Strategy rotation is
suspended until you remove the flag.

The startup block is timestamped. Check the `Agent pool:` line first:
it tells you how many workers actually launched after target detection,
backend defaults, and any RAM / sibling-audit autotuning.

```text
[HH:MM:SS] Agent pool: flat pool of 3 generic worker(s) (non-browser target). Set NUM_AGENTS in the environment to override.
[HH:MM:SS] LLM backend: provider=<backend> model=<model> (hosted API)
[HH:MM:SS] Target under audit: slug=<slug> path=<root> repo_type=<git|hg|none> agent_guide=<path>
[HH:MM:SS] Artifact output roots: results (crashes/findings/state) → <results>/    logs (sessions/index) → <logs>/
```

Browser targets show a split pool instead, for example
`1 browser-mode + 2 shell-mode`. If ensemble mode is active, the block
also says which hosted backends will be cycled. Unless
`AUDIT_LOG_LEGEND=0`, one-time legend lines follow the startup block.
Every audit log line is prefixed with `[HH:MM:SS]` — there is no
`[audit]` prefix.

To stop a running audit, press **Ctrl-C** in the terminal where it's
running. The orchestrator catches `SIGINT`, lets in-flight agents
finish their current turn (or hits them with `SIGTERM` and then
`SIGKILL` if they don't), writes a final state checkpoint, and exits.
Partial files may remain in `scratch-N/`; the next run picks up cleanly
from structured state regardless.

## 2. Inspect the run

The single most useful command is `show-recent` — one call bundles the
agent's recent claims, hypotheses, and probe runs:

```bash
bin/state --results-dir "$RESULTS" show-recent --agent 1
```

If you want the narrower views, they're available individually:

```bash
bin/state --results-dir "$RESULTS" recent-runs --agent 1   # probe verdicts only
bin/state --results-dir "$RESULTS" resume       --agent 1   # next-iteration brief
bin/state --results-dir "$RESULTS" list-cards               # the ranked work queue
bin/state --results-dir "$RESULTS" list-crashes             # accepted crashes
bin/state --results-dir "$RESULTS" list-findings            # filed findings
```

Then look at the result tree. The generated HTML pages, opened in a
browser, are the fastest way to read it:

| Path | What's there |
| --- | --- |
| `$RESULTS/crashes/` | Reproducible crash artifacts. Accepted crashes are auto-bundled with `REPORT.md` + `reproduce.sh`. |
| `$RESULTS/crashes/CRASH-CLUSTERS.html` | Crash review table (one row per cluster). |
| `$RESULTS/findings/` | Concrete security findings, with or without a reproducer. |
| `$RESULTS/findings/FINDING-CLUSTERS.html` | Finding review table. |
| `$RESULTS/findings-rejected/` | Findings the LLM substance gate rejected twice. |
| `$RESULTS/crashes-rejected/INDEX.html` | Rejected crash candidates, with reasons. |
| `$RESULTS/crashes-needs-review/` | Borderline rejections paused for one more pass before final demotion. |
| `output/$TARGET/CRASH-CLUSTERS.html` | Cross-backend crash rollup for the target. |
| `output/$TARGET/FINDING-CLUSTERS.html` | Cross-backend finding rollup for the target. |

### How to read an empty `crashes/`

An empty `crashes/` after one iteration is normal. Most first-run
issues are obvious from a single look:

- `$LOGS/index.log` — every per-iteration event is here. Look for
  `FATAL`, `PREFLIGHT`, or backend authentication failures first.
- `$LOGS/session_*_*.log` — trimmed transcript for each agent
  session. Use `$LOGS/.raw/session_*_*.log.raw` only when you need
  the full backend transcript.
- `$RESULTS/crashes-rejected/INDEX.html` — if crashes happened but were
  demoted, the reasons are here (`null-deref`, `OOM`, `out-of-bounds
  beyond target code`, etc.).
- `$RESULTS/state/runs.jsonl` — every probe verdict on disk. `wc -l
  state/runs.jsonl` is the fastest "did anything actually run?" check.

After several iterations with no crashes and no findings, see
[Triage results](../guides/triage-results.md) — most "empty" runs are
actually full of agent activity that just hasn't crossed the
promotion bar yet.

## 3. Continue or stop

Run another bounded session:

```bash
bin/audit --target "$TARGET" --backend "$BACKEND" 10
```

Or run continuously:

```bash
bin/audit --target "$TARGET" --backend "$BACKEND"
```

To start fresh on the same target (wipe state, logs, and any
in-progress artifacts), use the harness helpers:

```bash
bin/cleanup_state   --target "$TARGET" --backend "$BACKEND"   # wipe transient results state
bin/cleanup_logs    --target "$TARGET" --backend "$BACKEND"   # wipe logs/
```

Both are non-destructive to upstream source under `targets/`.

Before committing to a long run, skim
[Triage results](../guides/triage-results.md). That page explains
which artifacts are worth reporting, why every concrete security
finding stays under `findings/`, and how exported crash bundles are
laid out.

## Where to run the audit

You can run TokenFuzz directly on the host, but **we recommend running
it inside a container.** Two reasons:

1. **Untrusted target source.** Auditing means cloning third-party
   projects and compiling, linking, and executing their code under a
   sanitizer. That is arbitrary code execution from the target's side,
   by design. A container limits the blast radius if a build script,
   generator, or test harness in the target tree misbehaves.
2. **Agent tool-use.** Backend agents have a shell tool. A malicious
   instruction embedded in target source could in principle direct the
   agent to touch the rest of your filesystem, credentials, or
   network. A container makes that materially harder.

**Docker is the supported container runtime for the helper.** It is a
reasonable default for open source maintainers and security teams that
want repeatable Linux tooling without putting target build scripts on
the host. On a Linux Docker host, gVisor (`runsc`) is an optional extra
sandbox: it puts a user-space kernel between target code and the host
kernel for most system calls. See [Container runtime
(recommended)](prerequisites.md#container-runtime-recommended) in the
prerequisites for the basic Docker and gVisor configuration.

The harness ships a helper that:

- builds a disposable image with Claude Code, Codex, Antigravity CLI
  (`agy`), and Google Gemini CLI installed;
- mounts the repository at `/root/work`;
- drops you into a shell.

It mounts no host CLI credential directories (`~/.claude`, `~/.codex`,
`~/.gemini`): the container starts logged out, so you log in to each
backend inside the shell or pass `--forward-credentials` to forward API
key/token environment variables. This keeps the host's credential stores
off the container and avoids breaking `agy`, which needs a writable
`~/.gemini` — a read-only mount would fail. With
`--forward-credentials`, `~/.config/gcloud` and a
`GOOGLE_APPLICATION_CREDENTIALS` file are mounted read-only when present,
for Vertex/service-account auth.

```bash
# First run on a host — build the image, then enter the container.
bin/audit-container-shell --rebuild

# Every run after that — reuse the local image (no build).
bin/audit-container-shell

# Refresh the image after bumping a CLI npm spec.
bin/audit-container-shell --rebuild
```

The helper never builds implicitly. It checks for the local image
(`audit-cli-shell:latest` by default) and fails fast with a hint to
re-run with `--rebuild` if it is missing. Once the image exists, plain
`bin/audit-container-shell` always reuses it.

Optional flags:

| Flag | When to use it |
| --- | --- |
| `--gvisor` | Run the audit container with Docker's `runsc` runtime after you have registered it with Docker. |
| `--docker-runtime <name>` | Use a specific Docker OCI runtime for `docker run`. |
| `--image ubuntu` | Build on `ubuntu:latest` instead of the `node:lts-bookworm` default. `fedora` and tag-pinned forms like `ubuntu:24.04` also work. Only consulted with `--rebuild`. |
| `--tag <name>` | Override the local image tag (default `audit-cli-shell:latest`). |
| `--env-file <path>` | Load API keys from an env-file rather than the current shell. |
| `--rebuild` | Build the image. Required on first run, and to refresh the image after bumping a CLI npm spec. |

The helper keeps Docker's normal security profile and adds
`no-new-privileges` by default. For normal audits, do not run it as a
privileged container or mount the Docker socket into it; that weakens
the boundary the container is meant to provide.

The helper does **not** auto-run `bin/audit`. You run it yourself from
the container shell, exactly as on the host. The mounted repo persists
between shells, so sanitizer builds are not thrown away every session.
