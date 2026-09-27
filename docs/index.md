# TokenFuzz

TokenFuzz is an open-source harness for evidence-driven, LLM-assisted security
auditing. It runs coding agents against a source tree you are authorised to
test. The agents read code, record concrete hypotheses, run testcases, and
file what they find. The harness checks that evidence, and what survives
review becomes a report a maintainer can act on.

It works with C/C++, Rust, Go, Swift, Python, Java, and other languages, from
native libraries and command-line tools to browsers and JavaScript runtimes.

A prompt alone does not make a long audit reliable. The harness adds the parts
that do:

- **Source-to-testcase investigation.** A deterministic ranker builds a shared
  work queue, and eight review strategies steer the analysis. No known bug or
  crashing seed is needed.
- **Evidence-gated results.** Every testcase runs through one probe command.
  A sanitizer crash must reproduce before it is promoted, and a concrete
  security issue that never crashes is still filed as a finding.
- **Fleet coordination.** Work leases, structured state, and clustering let
  parallel agents pick up each other's work instead of rediscovering the same
  root cause.
- **Reviewable triage.** Independent validation, reachability and
  caller-control fields, indexes of rejected results, and severity annotation
  make each model claim traceable rather than self-certifying.
- **Measured review coverage.** The run records every auditable file, agents
  attest the lines they read, their transcripts cross-check those receipts,
  and a report lists what the run never looked at. A clean result is not
  mistaken for a complete one.
- **Maintainer handoff.** Each accepted crash becomes a self-contained bundle:
  a report, the input, the sanitizer output, and a one-command script that
  reproduces it on a clean checkout.
- **Comparable evaluation.** A built-in benchmark runs TokenFuzz and a direct
  vulnerability prompt with the same target, model, and wall-clock budget,
  then compares validated, deduplicated evidence rather than volume of prose.
  See an [example result page](assets/examples/benchmark-sample-c/benchmark-result.html)
  from a run against the C sample.

## Quick start

TokenFuzz runs on macOS and Linux. You need Python 3.11 or newer (or 3.10
with `tomli` installed), Git, ripgrep, `file`, an LLVM toolchain for native
sanitizer targets, and at least one supported model CLI.
[Prerequisites](getting-started/prerequisites.md) has the install commands
for each platform and backend.

```bash
git clone https://github.com/tokenfuzz/tokenfuzz
cd tokenfuzz
bash tests/run-tests.sh      # confirms the host is ready

# Smoke test: one worker against a shipped synthetic Python target.
bin/audit --target samples/sample-python --backend <backend> 1
```

The trailing `1` limits the run to one iteration with one worker. That proves
setup, backend launch, structured state, and result paths work together; it
is not a useful security budget. The repository ships eighteen synthetic
targets (the `canary` and seventeen `samples/sample-*` trees), described in
[Sample targets](getting-started/sample-targets.md).

To audit your own project, set it up once and then run a bounded session, or
omit the count to run until you stop it:

```bash
bin/setup-target <target> <repo-url>
bin/audit --target <target> --backend <backend> 1    # smoke test first
bin/audit --target <target> --backend <backend> 10   # ten iterations
bin/audit --target <target> --backend <backend>      # continuous
```

[First audit](getting-started/first-audit.md) walks through a run end to end.

## Choose your path

| You are… | Start with |
| --- | --- |
| Trying TokenFuzz for the first time | [Getting started](getting-started/index.md) and a [sample target](getting-started/sample-targets.md) |
| Adding an internal or upstream project | [Add a target](getting-started/add-a-target.md), then [review its config](guides/configure-target.md) |
| Operating a longer audit | [Backends and isolation](guides/backends.md) and [First audit](getting-started/first-audit.md) |
| Reviewing results as a security team | [Triage and review](guides/triage-results.md) |
| An upstream maintainer who received a crash | [Reproduce a crash](guides/reproduce-a-crash.md) |
| Deciding whether the harness earns its budget | [Benchmarking](concepts/benchmark.md) and the [example result page](assets/examples/benchmark-sample-c/benchmark-result.html) |
| Understanding or changing the implementation | [System architecture](concepts/system-architecture.md) and [Development](development.md) |
| Looking up an exact command, field, or path | [Reference](reference/index.md) |
| Diagnosing a failed run | [Troubleshooting](reference/troubleshooting.md) |

## What it supports

**Targets.**

- **Native libraries and tools:** C/C++ parsers, codecs, protocol
  implementations, and command-line programs.
- **Compiled language projects:** Rust, Go, and Swift packages, using the
  sanitizer or language runner configured for the target.
- **Managed and interpreted code:** Python, Java, Kotlin, Ruby, PHP,
  JavaScript/TypeScript, Perl, and R.
- **Browsers and runtimes:** full browsers, JavaScript engines, WebAssembly
  runtimes, and mixed-language products.

`bin/setup-target` enables ASan for native C/C++ builds and Swift, and Go's
`race` detector for Go. Other ecosystems start in findings-only mode
(`[sanitizer] enabled = []`): runtime errors guide the investigation, but a
security finding still needs a concrete report.
[Language runners](guides/multi-language.md) has the per-ecosystem details.

**Model backends.** Claude Code, Codex CLI, Gemini (through the Antigravity
CLI or Google Gemini CLI), Grok Build, and OpenCode with either a catalog
provider or a local OpenAI-compatible endpoint. Every backend runs the same
audit contract. Claude Code and Codex CLI run inside their own OS sandbox by
default; Gemini, Grok, and OpenCode need a container or VM you administer.
[Backends and isolation](guides/backends.md) explains how to choose a backend
and how its execution is contained.

## Where results go

A model's claim is where review starts, not where it ends. TokenFuzz files
two kinds of artifact and keeps every review decision next to the evidence it
judged:

| Artifact | What it contains |
| --- | --- |
| Finding | A concrete security claim with a source location and an actionable report. A reproducer is optional. |
| Crash | A sanitizer or runtime-race diagnostic with its testcase and saved output. Confirmation and triage decide whether it becomes a reviewed crash bundle. |

Each artifact stays `pending` until review settles it. Only `reportable`
results earn security credit. Rejected evidence is kept with its reason,
including real defects that fall outside the configured threat model. A
directory name alone does not tell you the state; `validation.json` does.

Source and audit evidence live in separate trees:

```text
targets/<target>/                    source checkout and build artifacts
output/<target>/target.toml          target configuration and threat model
output/<target>/<backend>/results/   findings, crashes, state, and scratch work
output/<target>/<backend>/logs/      run and backend diagnostics
```

Start a review from the generated HTML indexes, all under
`output/<target>/<backend>/results/`:

| Path | Purpose |
| --- | --- |
| `findings/finding-clusters.html` | Concrete security findings, grouped by exact site or crash state. |
| `crashes/crash-clusters.html` | Crash candidates and reviewed bundles, grouped by primitive and stack similarity. |
| `findings-rejected/rejected-findings.html` | Findings triage rejected, with the reason. |
| `crashes-rejected/rejected-crashes.html` | Crash candidates rejected, with the reason. |

Cross-backend summaries are written directly under `output/<target>/`.
[Artifact layout](reference/artifacts.md) lists every generated path, and
[Triage and review](guides/triage-results.md) explains the review standard.

<span id="how-the-pieces-fit"></span>

## The operating model

1. `bin/setup-target` creates or updates the checkout and generates
   `output/<target>/target.toml`.
2. `bin/audit` validates the target, pins a session-local copy of the config,
   ranks work, and launches agents.
3. Agents claim work cards, record hypotheses and the lines they read in
   structured state, and run testcases through `bin/probe`.
4. Triage exports confirmed crashes as maintainer bundles, validates every
   report, keeps rejections with their reasons, and clusters matching
   evidence.
5. `bin/state coverage` reports which files the run offered, read, and
   attested, and which it never reached.

[Audit lifecycle](concepts/audit-lifecycle.md) walks through that flow,
[System architecture](concepts/system-architecture.md) describes the component
boundaries, and [Review coverage](concepts/coverage.md) explains the ledgers
behind the coverage report.

## Boundaries and expectations

- **It does not replace fuzzing, code review, or maintainer judgment.** It is
  another way to spend an audit budget. The
  [benchmark](concepts/benchmark.md) lets you check whether it earns that
  budget on your targets.
- **It does not publish anything.** There is no advisory pipeline and no
  automatic upstream filing.
- **Severity scores are advisory.** CVSS v4.0 vectors are computed offline
  from the report, its evidence, and the target's threat model. Read the
  generated `## Severity rationale` section and consider your deployment
  before citing a score.
- **A finding is a claim until a human checks it.** Automated review can
  admit or reject a result, or leave it pending when review could not finish.
  A gate that fails open preserves uncertain evidence; it does not certify it.
- **Clusters are a review aid, not proof of root cause.** One defect can
  surface at several sinks, and two defects can share one.

## Responsible use

Only run TokenFuzz on software you are authorised to test. Settle three things
before the first long run:

- **The audit executes untrusted code.** Target build scripts and
  agent-written testcases run on the machine you start it on. Use a
  disposable container or an isolated host without long-lived credentials;
  see [Container runtime](getting-started/prerequisites.md#container-runtime-recommended).
- **Hosted backends see the target.** Prompts, source excerpts, state, and
  reports go to the model provider by design. Use the `oss` backend with a
  local endpoint when source must stay on the machine. The agent sandbox
  limits writes and network access, not what the model reads;
  [Agent security modes](guides/backends.md#agent-security-modes) explains
  the difference.
- **Disclosure stays with you.** Report target findings through the upstream
  project's coordinated-disclosure process, and review benchmark archives and
  research output before sharing them, as you would any security artifact.

Security issues in TokenFuzz itself follow
[SECURITY.md](https://github.com/tokenfuzz/tokenfuzz/blob/main/SECURITY.md).
TokenFuzz is available under the
[Apache License 2.0](https://github.com/tokenfuzz/tokenfuzz/blob/main/LICENSE).
