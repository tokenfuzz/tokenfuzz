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

Because the command below passes `--backend "$BACKEND"`, leaving
`$BACKEND` unset sends an empty value and fails with
`AUDIT_BACKEND must be all, claude, codex, gemini, or oss`. (Omitting
`--backend` altogether instead cycles every installed hosted backend —
that is the `all` default.)

## 1. Run one iteration

This runs the whole audit pipeline in miniature: backend launch,
work-card ranking, and as much testcase work as the agent can complete
in one iteration. A trailing `1` is a **smoke test** — it launches a
single worker and deliberately skips recon seeding, so
`recon-hypotheses.jsonl` will not appear. Recon kicks in on
multi-iteration and continuous runs.

```bash
bin/audit --target "$TARGET" --backend "$BACKEND" 1
```

If you do not pass `--model`, the harness picks the default for the
selected backend:

| Backend | Default without `--model` |
|---------|---------------------------|
| `claude` | `claude-opus-4-8` |
| `codex` | `gpt-5.5` |
| `gemini` with Antigravity CLI (`agy`) | `gemini-3.1-pro-preview`, mapped to its `agy models` label. Override with `--model` as a config slug or an exact `agy models` label. |
| `gemini` with Google Gemini CLI (`USE_GEMINI_CLI=1`) | `gemini-3.1-pro-preview` |
| `oss` | No default; `--model <served-model-name>` is required. |

The defaults come from `config/models.toml`; override them per run
with `--model` or per shell with the `*_MODEL_DEFAULT` variables in
[Model selection](../reference/environment.md#model-selection).

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
also says which hosted backends will be cycled.

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
| `$RESULTS/crashes-rejected/REJECTED-CRASHES.html` | Rejected crash candidates, with reasons. |
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
- `$RESULTS/crashes-rejected/REJECTED-CRASHES.html` — if crashes happened but were
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
bin/cleanup_state   --target "$TARGET"                       # wipe generated target output
bin/cleanup_logs    --target "$TARGET" --backend "$BACKEND"   # wipe logs/
```

Both are non-destructive to upstream source under `targets/`.
`cleanup_state` also preserves target metadata under `output/`.

Before committing to a long run, skim
[Triage results](../guides/triage-results.md). That page explains
which artifacts are worth reporting, why every concrete security
finding stays under `findings/`, and how exported crash bundles are
laid out.

## Auditing with UBSan, MSan, or TSan

ASan is the default, but a target can be audited under any sanitizer it
enables. Bugs that ASan cannot see — signed-integer overflow, an
uninitialized read, a data race — surface only under the matching
sanitizer, so each one needs its own instrumented build.

Three steps take you from ASan-only to a second sanitizer.

**1. Enable it in `target.toml`.** Add the slug to `[sanitizer].enabled`
and point `<san>_bin` at the binary the build will produce. For a
C-API harness, also set `<san>_lib`:

```toml
[sanitizer]
enabled = ["ubsan", "asan"]
ubsan_bin = "build-ubsan/<binary>"
# ubsan_lib = "build-ubsan/<archive>.a"   # only if a // HARNESS testcase links it
```

Order matters: an audit runs the **first** sanitizer in `enabled`, so
list the one you want to focus on first. See
[Configure a target](../guides/configure-target.md#sanitizer-policy)
for the full field list and per-sanitizer posture.

**2. The build is automatic.** `bin/audit` converges a recipe and
compiles a build tree for *every* sanitizer in `enabled` — not just
ASan — on its first run, and rebuilds when the source changes. To build
up front instead, run:

```bash
bin/setup-target <target> --build
```

Either way this writes `targets/<target>/build-ubsan/` alongside
`build-asan/` and fills in the `ubsan_bin` / `ubsan_lib` paths it
detects. ASan is required; any other sanitizer is best-effort — if its
build fails, the run warns and continues. (Note: `--build` never
re-seeds your `target.toml`. A plain `bin/setup-target <target>` rerun
*does* refresh a config that still holds active `FILL_ME` placeholders,
but that refresh preserves your curated `[threat_model]` and `[s6_peers]`
sections — filling one placeholder will not discard hand or LLM edits.)

**3. Run it.** An audit uses the first enabled sanitizer automatically:

```bash
bin/audit --target <target> --backend "$BACKEND" 1
```

For a one-off `bin/probe` or `bin/benchmark` run against a different
sanitizer than the default, set `PROBE_SANITIZER`:

```bash
PROBE_SANITIZER=ubsan bin/probe --confirm <testcase>
```

A confirmed non-ASan crash is recorded exactly like an ASan one: the
multi-run wrapper measures a reproduction rate (`CRASH_RATE: 5/5`) and
the crash is bundled under `crashes/`.

## Where to run the audit

### Why we recommend a container

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

### Using the container helper

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

## What's next

That is the end of getting started. From here, pick a guide for what
you want to do next:

- [Triage results](../guides/triage-results.md) — read what the run
  produced and decide what is worth a maintainer's time.
- [Backends and ensembling](../guides/backends.md) — run the same
  target with more than one model backend.
- [Recon discovery](../guides/recon-discovery.md) — understand the
  candidate list the audit started from.
- [Audit lifecycle](../concepts/audit-lifecycle.md) — the end-to-end
  design, if you prefer to understand the machine before running it
  longer.
