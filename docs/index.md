# TokenFuzz Documentation

TokenFuzz is an open platform for LLM-based vulnerability research: a
coordinated fleet of agents that audits a codebase, finds security issues, and
hands each one back with the evidence and reasoning a developer needs to
triage it. Point it at any source tree you are authorized to test —
C/C++, Rust, Go, Python, Java, and more, including browsers — and it runs
as a pipeline:

- **Recon sweep.** A cold-start pass runs a CTF-style "find all
  vulnerabilities" survey, split across parallel agents over
  directory-coherent, LOC-balanced slices of the source. On a large
  codebase it scopes to recently-changed code so the pass stays
  bounded. Results land in a prioritized queue. See
  [Recon discovery](guides/recon-discovery.md).
- **Eight investigation strategies.** Deep agents work that queue with
  prior-fix mining, invariant negation, spec-vs-implementation,
  differential testing, lifetime and state, cross-project peer-fix
  mining, parser-input engineering, and property oracles — across Claude,
  Codex, Gemini, or a local Ollama model behind one probe-and-triage
  contract. See [Strategy model](concepts/strategy-model.md) and
  [Backends and ensembling](guides/backends.md).
- **Reachability-labelled findings.** Every finding separates
  attacker-controlled-byte issues from internal caller-misuse and pure
  test- or maintenance-tool surface, so triage moves on signal instead of
  drowning in null-derefs, OOMs, and assertion-only aborts.
- **Cost as a first-class resource.** Prompt caching, capped state views,
  per-agent sanitizer-run budgets, soft turn caps, work-card leases, and
  SHA-pinned recon reuse keep unattended multi-agent runs affordable. See
  [Cost model](concepts/cost-model.md).
- **Fleet coordination.** Shared logging and cluster-level dedup keep
  parallel agents accumulating work rather than repeating each other; an
  independent validator pass with no shared context catches a model's own
  reasoning errors before anything is accepted.
- **Maintainer-ready handoff.** Every accepted crash exports as a bundle —
  sanitizer trace, reproducer testcase, one-command `reproduce.sh`,
  candidate fix direction, and optional `patch.diff` — that rebuilds
  against a clean upstream checkout.

The platform does the discovery, the analysis, the triage, and the
handoff; the final security judgment stays with you.

## Requirements

A Unix-like host (macOS or Linux), a small set of standard tools, an
LLVM toolchain, and at least one agent backend.

- **Host tools:** `bash`, `jq`, `python3`, `perl`, `git`, `rg`, `file`.
- **LLVM tools:** `clang`, `llvm-symbolizer`, `sancov` — only needed
  for building or running sanitizer artifacts.
- **Backend:** one of Claude Code (`claude`), Codex (`codex`), the
  Antigravity CLI (`gemini`, run via the `agy` binary), or a local
  model via `--backend oss --model <name>` (uses Codex with `--oss`
  plus an [Ollama](https://ollama.com) model served locally).

See [Prerequisites](getting-started/prerequisites.md) for per-distro
package commands.

## Quick start

```bash
git clone https://github.com/tokenfuzz/tokenfuzz tokenfuzz
cd tokenfuzz

bash tests/run-tests.sh

export TARGET=libxml2               # any directory name under targets/
export BACKEND="<backend>"          # one of: claude, codex, gemini, oss
# Optional convenience path for inspecting results.
export RESULTS="output/$TARGET/$BACKEND/results"

bin/setup-target "$TARGET" <repo-url>
# --bootstrap prepares the target's build so the audit can run. For C/C++
# it produces a sanitizer build under build-asan/; other languages prepare
# through their own toolchain (cargo, go, swift, npm, ...), which picks up
# sanitizer flags where it supports them (e.g. Go's -race, Swift's
# -sanitize=address). Enabled sanitizers are set per target in
# target.toml's [sanitizer] block.
bin/setup-target "$TARGET" --bootstrap

# Pass 1 for a single-iteration smoke test; omit it for a continuous run.
bin/audit --target "$TARGET" --backend "$BACKEND" 1

ls "$RESULTS"/crashes "$RESULTS"/findings
```

The goal of the first bounded run is **to prove the pipeline runs end
to end**, not to find a bug. A successful first iteration writes
startup logs, state, and either queued work or attempted testcases
under `results/`.

For the full walkthrough, see [First audit](getting-started/first-audit.md).

## What kinds of targets work

Anything you can drive with a testcase:

- a sanitizer-instrumented program;
- a parser, decoder, codec, or protocol implementation;
- a browser, script engine, or browser-like runtime;
- a command-line tool;
- a library entry point.

Native **C and C++** are the headline case — AddressSanitizer gives the
clearest, lowest-noise crash evidence — and the same holds for
**browsers**, **JS/Wasm runtimes**, and **mixed-language** targets whose
build system can produce a sanitizer build.

Sanitizers aren't C/C++-only: **Rust**, **Go**, **Swift**, and the
native extensions of **Python** and **Node** can all run instrumented,
and a sanitizer crash from any of them lands under `crashes/`.
Languages with no sanitizer — **Java**, **Ruby**, **PHP**, and plain
interpreted Python/Node — run in **findings-only mode**, where runtime
diagnostics (tracebacks, panics, exceptions) are captured under
`findings/` instead. ASan is the default wherever one exists; UBSan,
MSan, TSan, and the Go `race` detector are opt-in per target. See
[Auditing non-C/C++ targets](guides/multi-language.md) for the
per-language picture.

## What a run produces

Crash candidates are verified by `bin/probe` before they are promoted.
Findings may be reviewer-only: a runnable reproducer is useful, but not
required. A run usually creates some combination of these artifacts under
`output/<target>/<backend>/results/`:

| Artifact | What it is |
| --- | --- |
| `findings/FIND-*` | A written security finding. This is the primary output: a concrete location, issue class, impact, and reviewer rationale. |
| `findings/FINDING-CLUSTERS.html` | Per-backend cluster summary for findings. |
| `findings-rejected/FIND-*` | FIND reports the quality gate rejected after repeated review. Typical examples are vague "suspicious code" notes or correctness-only issues with no security impact. They are moved here, not deleted, so you can audit false rejects. |
| `crashes/CRASH-*` | A finding the harness also reproduced under a sanitizer. Triage exports a maintainer-ready bundle with `REPORT.md`, `reproduce.sh`, `sanitizer.txt`, `input.<ext>`, and `harness.*` when an API harness is needed. |
| `crashes/CRASH-CLUSTERS.html` | Per-backend cluster summary for crashes. |
| `crashes-rejected/INDEX.html` | Crash candidates that failed triage, with reasons. Examples include null derefs, OOMs, and other low-value crash classes; the original artifacts are retained for review. |

When you run multiple backends against the same target, the per-backend
tables are rolled up at the target root:

- `output/<target>/CRASH-CLUSTERS.html`
- `output/<target>/FINDING-CLUSTERS.html`

Rejected artifacts are still useful audit records. `crashes-rejected/`
prevents later sessions from re-filing known low-value crash candidates.
`findings-rejected/` serves the same purpose for reports that do not meet
the security-finding bar after repeated review.

## How a session is organised

```text
targets/<target>/                      upstream checkout
targets/<target>/build-asan/           sanitizer build for native targets
                                        (suffix-aware inside the container)
        │
        ▼
output/<target>/target.toml            target config + threat model
        │
        ▼
output/<target>/<backend>/
        ├── results/                   one isolated audit run
        │   ├── work-cards.jsonl       ranked source, patch, peer, and recon cards
        │   ├── state/                 claims, hypotheses, notes, and probe runs
        │   ├── recon-hypotheses.jsonl cold-start recon candidates, when recon runs
        │   ├── findings/              accepted non-crashing security findings
        │   ├── findings-rejected/     FIND reports rejected as non-security
        │   ├── crashes/               accepted sanitizer-backed reproductions
        │   └── crashes-rejected/      triaged low-value crash candidates
        └── logs/                      per-agent logs; raw dialogue under logs/.raw/
```

Two things stay apart on disk:

- Upstream source lives under `targets/`.
- Audit evidence lives under `output/`.

That separation makes it easy to refresh a target without disturbing
past runs, and easy to delete past runs without touching upstream
source. The generated config is shared at `output/<target>/target.toml`;
backend-specific evidence stays under `output/<target>/<backend>/results/`.

The full command reference is on the [Commands](reference/commands.md)
page. Agents investigate using a catalog of eight strategies (S1–S8)
plus a shared pattern-search reference — see
[Strategy model](concepts/strategy-model.md) for how they are assigned
and rotated.

## Responsible use

- Only run TokenFuzz on software you are authorised to test.
- All output is written to your local results directory; the harness
  does not publish anything itself. Hosted backends receive the prompts,
  source excerpts, state, and reports needed for the run, and optional
  reachability checks may query public code search.
- When reporting upstream, use the project's normal security-disclosure
  process.
- The repository's security policy is in
  [SECURITY.md](https://github.com/tokenfuzz/tokenfuzz/blob/main/SECURITY.md).

## Where to go next

| If you want to… | Read |
| --- | --- |
| Set up the host and run your first audit | [Getting started](getting-started/index.md) |
| Review `target.toml`, recon, triage, or reproduce a crash | [Guides](guides/index.md) |
| Understand the audit lifecycle, strategies, or cost model | [Concepts](concepts/index.md) |
| Look up a command, a field, an env var, or a path | [Reference](reference/index.md) |
| Debug a failing setup | [Troubleshooting](reference/troubleshooting.md) |
| Ask for help or file a bug | [Getting help](getting-help.md) |

The sidebar carries the full page list.

## Development

See [Development](development.md) for the test discipline, coding rules,
documentation conventions, and development-agent startup prompt.

## License

Apache License 2.0. See
[LICENSE](https://github.com/tokenfuzz/tokenfuzz/blob/main/LICENSE).
