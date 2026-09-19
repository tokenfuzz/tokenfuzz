# TokenFuzz

TokenFuzz is an open-source harness for evidence-driven, LLM-assisted security
auditing. It coordinates agents that read source, form concrete hypotheses,
run testcases, and turn validated results into reports a maintainer can act
on. It works with C/C++, Rust, Go, Python, Java, and other supported
languages, from native libraries and command-line tools to browsers and
JavaScript runtimes.

A prompt alone does not make a long audit reliable. The harness adds the parts
that do:

- **Source-to-testcase investigation.** Deterministic ranking builds a shared
  work queue, and eight review strategies direct the analysis without needing
  a known bug or a crashing seed.
- **Evidence-gated results.** Every testcase runs through one probe contract.
  Sanitizer diagnostics are confirmed before promotion, and concrete
  non-crashing security issues are first-class findings.
- **Fleet coordination.** Work leases, structured state, and clustering let
  parallel agents resume investigations without rediscovering the same root
  cause.
- **Reviewable triage.** Independent validation, reachability and
  caller-control fields, rejected-result indexes, and severity annotation make
  a model's claim traceable instead of self-authenticating.
- **Measured review coverage.** Every auditable file is recorded, agents
  attest the lines they read, transcripts cross-check those receipts, and a
  report shows what the run never looked at. A clean result is not mistaken
  for a complete one.
- **Maintainer handoff.** Accepted crashes become self-contained bundles: a
  report, the input, the sanitizer output, and a one-command reproduction
  script for a clean checkout.
- **Comparable evaluation.** A built-in benchmark runs TokenFuzz and a direct
  vulnerability prompt under matched target, model, and wall-clock budgets,
  then compares validated, deduplicated evidence rather than prose volume.
  See an [example result page](assets/examples/benchmark-sample-c/benchmark-result.html)
  from a run against the C sample.

## Supported targets

- **Native libraries and tools:** C/C++ parsers, codecs, protocol
  implementations, and command-line programs.
- **Compiled language projects:** Rust, Go, and Swift packages, using the
  sanitizer or language runner configured for the target.
- **Managed and interpreted code:** Python, Java, Kotlin, Ruby, PHP,
  JavaScript/TypeScript, Perl, and R.
- **Browsers and runtimes:** full browsers, JavaScript engines, WebAssembly
  runtimes, and mixed-language products.

Setup defaults ordinary C/C++ targets to ASan, Go to its `race` detector, and
Swift to ASan. A project with no sanitizer build can run in findings-only
mode (`[sanitizer] enabled = []`): runtime errors support the investigation,
but a security finding still needs a concrete report. [Language runners](guides/multi-language.md) has the
per-ecosystem details.

TokenFuzz drives Claude Code, Codex CLI, Gemini through the Antigravity CLI or
Google Gemini CLI, Grok Build, and OpenCode with either a catalog provider or
a local OpenAI-compatible endpoint. Hosted and local backends run the same
audit contract.

## Quick start

TokenFuzz runs on macOS and Linux. Install Python 3.10+, Git, ripgrep, `file`,
an LLVM toolchain for native sanitizer targets, and one supported model CLI.
[Prerequisites](getting-started/prerequisites.md) has the platform commands
and backend links.

```bash
git clone https://github.com/tokenfuzz/tokenfuzz
cd tokenfuzz

bash tests/run-tests.sh

# Fastest smoke test: a configured synthetic Python target.
bin/audit --target samples/sample-python --backend <backend> 1

# Or your own project.
bin/setup-target <target> <repo-url>
bin/audit --target <target> --backend <backend> 1
```

The final `1` runs a single-worker smoke test. It proves that setup, backend
launch, structured state, and result paths work together. It is not a useful
security budget. [Sample targets](getting-started/sample-targets.md) lists the
eighteen synthetic targets shipped with the repository. After a healthy smoke
test, run a bounded session, or omit the count to run continuously:

```bash
bin/audit --target <target> --backend <backend> 10
bin/audit --target <target> --backend <backend>
```

[First audit](getting-started/first-audit.md) is the full walkthrough.

## Choose your path

| You are… | Start with |
| --- | --- |
| Trying TokenFuzz for the first time | [Getting started](getting-started/index.md) and a [sample target](getting-started/sample-targets.md) |
| Adding an internal or upstream project | [Add a target](getting-started/add-a-target.md), then [review its config](guides/configure-target.md) |
| Operating a longer audit | [Backends and isolation](guides/backends.md) and [First audit](getting-started/first-audit.md) |
| Reviewing a security-team handoff | [Triage and review](guides/triage-results.md) |
| Receiving a crash as an upstream maintainer | [Reproduce a crash](guides/reproduce-a-crash.md) |
| Deciding whether the harness earns its budget | [Benchmarking](concepts/benchmark.md) and the [example result page](assets/examples/benchmark-sample-c/benchmark-result.html) |
| Understanding or changing the implementation | [System architecture](concepts/system-architecture.md) and [Development](development.md) |
| Looking up an exact command, field, or path | [Reference](reference/index.md) |
| Diagnosing a run that failed | [Troubleshooting](reference/troubleshooting.md) |

## Where results go

A model's claim is where review starts, not where it ends. TokenFuzz records
what was tested and keeps every review decision attached to the evidence it
judged. There are two kinds of artifact:

| Artifact | What it contains |
| --- | --- |
| Finding | A concrete security claim with a source location and an actionable report. A reproducer is optional. |
| Crash | A sanitizer or runtime-race diagnostic with its testcase and saved output. Confirmation and triage decide whether it becomes a reviewed crash bundle. |

Either kind can be pending, reportable, or rejected. Rejected evidence is kept
with its reason, including defects outside the configured security boundary.
Only reportable results earn security credit; a directory name alone does not
establish that state.

Source and audit evidence stay apart:

```text
targets/<target>/                         source checkout and build artifacts
output/<target>/target.toml               target configuration and threat model
output/<target>/<backend>/results/        findings, crashes, state, and scratch work
output/<target>/<backend>/logs/           run and backend diagnostics
```

Start review with the generated HTML indexes. A directory can hold pending
candidates beside reviewed results, so check the publication state in
`validation.json` before counting a report as confirmed.

| Path | Purpose |
| --- | --- |
| `results/findings/finding-clusters.html` | Concrete security findings, grouped by exact evidence signature. |
| `results/crashes/crash-clusters.html` | Crash candidates, reviewed diagnostics, and reproduction bundles. |
| `results/crashes-rejected/rejected-crashes.html` | Crash candidates rejected with an explanation. |
| `results/findings-rejected/rejected-findings.html` | Findings triage rejected, with the reason. |

`results/` here means `output/<target>/<backend>/results/`. Cross-backend
finding and crash summaries are written directly under `output/<target>/`.
[Artifact layout](reference/artifacts.md) describes the generated paths and
[Triage and review](guides/triage-results.md) explains the review standard.

<span id="how-the-pieces-fit"></span>

## The operating model

1. `bin/setup-target` creates or updates the checkout and generates
   `output/<target>/target.toml`.
2. `bin/audit` validates the target, pins a session-local config snapshot,
   ranks work, and launches agents.
3. Agents claim work, record hypotheses and the lines they read in structured
   state, and run testcases through `bin/probe`.
4. Triage validates reports, preserves rejections, clusters matching evidence,
   and exports accepted crashes as maintainer-facing bundles.
5. `bin/state coverage` reports which files the run offered, read, and
   attested, and which it never reached.

[Audit lifecycle](concepts/audit-lifecycle.md) walks through that flow,
[System architecture](concepts/system-architecture.md) describes the component
boundaries, and [Review coverage](concepts/coverage.md) explains the ledgers
behind the coverage report.

## Boundaries and expectations

- **It does not replace fuzzing, code review, or maintainer judgment.** It is
  another way to spend an audit budget. The
  [benchmark](concepts/benchmark.md) exists so you can check whether it earns
  that budget on your targets.
- **It does not publish anything.** There is no advisory pipeline and no
  automatic upstream filing. Disclosure stays yours, through the upstream
  project's process.
- **Severity scores are advisory.** CVSS v4.0 vectors are computed offline
  from the available evidence and report fields. Read the generated
  `## Severity rationale` and consider your deployment before citing a score.
- **A finding is a claim until a human checks it.** Automated review can
  admit, reject, or leave it unsettled. A fail-open gate preserves uncertain
  evidence; it does not certify it.
- **Clusters are a review aid, not root-cause proof.** One defect can split
  across sinks, and two defects can share one.

## Responsible use

Only run TokenFuzz on software you are authorised to test. Settle three facts
before the first long run:

- **The audit executes untrusted code.** Target build scripts and
  agent-authored testcases run on the machine you start it on. Use a
  disposable container or an isolated host without long-lived credentials;
  see [Container runtime](getting-started/prerequisites.md#container-runtime-recommended).
- **Hosted backends see the target.** Prompts, source excerpts, state, and
  reports go to the provider by design. Use the `oss` backend against a local
  endpoint when source must stay on the machine. The agent sandbox contains
  writes and network, not what the model reads;
  [Agent security modes](guides/backends.md#agent-security-modes) explains
  the difference.
- **Disclosure stays yours.** Report target findings through the upstream
  project's coordinated-disclosure process, and review benchmark archives and
  research output before sharing them, as you would any security artifact.

Security issues in TokenFuzz itself follow
[SECURITY.md](https://github.com/tokenfuzz/tokenfuzz/blob/main/SECURITY.md).
TokenFuzz is available under the
[Apache License 2.0](https://github.com/tokenfuzz/tokenfuzz/blob/main/LICENSE).
