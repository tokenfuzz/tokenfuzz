# TokenFuzz

TokenFuzz is an open-source harness for evidence-driven, LLM-assisted security
auditing. It coordinates agents that inspect source, form concrete hypotheses,
run testcases, and turn validated results into reports a maintainer can review.
It works with C/C++, Rust, Go, Python, Java, and other supported languages,
from native libraries and command-line tools to browsers and JavaScript
runtimes.

The harness supplies the parts a long audit needs beyond a prompt:

- **Source-to-testcase investigation.** Deterministic ranking builds a shared
  work queue; eight review strategies guide deeper analysis without requiring
  a known bug or crashing seed.
- **Evidence-gated results.** Testcases run through one probe contract.
  Sanitizer diagnostics are confirmed before promotion, while concrete
  non-crashing security issues remain first-class findings.
- **Fleet coordination.** Work leases, structured state, and clustering let
  parallel agents resume investigations and avoid rediscovering the same root
  cause.
- **Reviewable triage.** Independent validation, reachability and caller-control
  fields, rejected-result indexes, and severity annotation make model claims
  traceable rather than self-authenticating.
- **Maintainer handoff.** Accepted crashes become self-contained bundles with a
  report, input, sanitizer output, and a one-command reproduction script for a
  clean checkout.
- **Comparable evaluation.** A built-in benchmark runs TokenFuzz and a direct
  vulnerability prompt under matched target, model, and wall-clock budgets,
  then compares validated, deduplicated evidence instead of prose volume.

## Supported targets

TokenFuzz works across several kinds of project:

- **Native libraries and tools:** C/C++ parsers, codecs, protocol
  implementations, and command-line programs.
- **Compiled language projects:** Rust, Go, and Swift packages, using the
  sanitizer or language runner configured for the target.
- **Managed and interpreted code:** Python, Java, Kotlin, Ruby, PHP,
  JavaScript/TypeScript, Perl, and R.
- **Browsers and runtimes:** full browsers, JavaScript engines, WebAssembly
  runtimes, and mixed-language products.

Setup defaults ordinary C/C++ targets to ASan, Go to `race`, and Swift to
ASan. Projects without a sanitizer build can use findings-only mode; runtime
errors support investigation, while a security finding still needs a concrete
report. See [Language runners](guides/multi-language.md) for ecosystem details.

TokenFuzz drives Claude Code, Codex CLI, Gemini through the Antigravity CLI or
Google Gemini CLI, Grok Build, and OpenCode with either a catalog provider or a
local OpenAI-compatible endpoint. Hosted and local backends run the same audit
contract.

## Quick start

TokenFuzz supports macOS and Linux. Install Python 3.10+, Git, ripgrep, `file`,
an LLVM toolchain for native sanitizer targets, and one supported model CLI.
[Prerequisites](getting-started/prerequisites.md) has the platform commands and
backend links.

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
launch, structured state, and result paths work together; it is not a useful
security budget. [Sample targets](getting-started/sample-targets.md) lists the
eighteen synthetic targets shipped with the repository. After a healthy smoke
test, run a bounded working session, or omit the count for a continuous run:

```bash
bin/audit --target <target> --backend <backend> 10
bin/audit --target <target> --backend <backend>
```

The complete walkthrough is in [First audit](getting-started/first-audit.md).

## Choose your path

| You are… | Start with |
| --- | --- |
| Trying TokenFuzz for the first time | [Getting started](getting-started/index.md) and a [sample target](getting-started/sample-targets.md) |
| Adding an internal or upstream project | [Add a target](getting-started/add-a-target.md), then [review its config](guides/configure-target.md) |
| Operating a longer audit | [Backends and isolation](guides/backends.md) and [First audit](getting-started/first-audit.md) |
| Reviewing a security-team handoff | [Triage and review](guides/triage-results.md) |
| Receiving a crash as an upstream maintainer | [Reproduce a crash](guides/reproduce-a-crash.md) |
| Deciding whether the harness earns its budget | [Benchmarking](concepts/benchmark.md) |
| Looking up an exact command, field, or path | [Reference](reference/index.md) |
| Diagnosing a run that failed | [Troubleshooting](reference/troubleshooting.md) |
| Changing TokenFuzz itself | [Development](development.md) |

## Where results go

A model's claim is the start of review. TokenFuzz records what was tested and
keeps review decisions attached to the evidence they evaluated. It records two
kinds of artifact:

| Artifact | What it contains |
| --- | --- |
| Finding | A concrete security claim with a source location and an actionable report. A reproducer is optional. |
| Crash | A sanitizer or runtime-race diagnostic with its testcase and saved output. Confirmation and triage determine whether it becomes a reviewed crash bundle. |

Either kind can be pending, reportable, or rejected. Rejected evidence is kept
with the reason, including defects outside the configured security boundary.
Only reportable results receive security credit; directory placement alone
does not establish that state.

TokenFuzz keeps source and audit evidence apart:

```text
targets/<target>/                         source checkout and build artifacts
output/<target>/target.toml               target configuration and threat model
output/<target>/<backend>/results/        findings, crashes, state, and scratch work
output/<target>/<backend>/logs/           run and backend diagnostics
```

Start review with the generated HTML indexes. A directory can contain pending
candidates as well as reviewed results; check the publication state in
`validation.json` before counting a report as confirmed.

| Path | Purpose |
| --- | --- |
| `results/findings/FINDING-CLUSTERS.html` | Concrete security findings, grouped by exact evidence signature. |
| `results/crashes/CRASH-CLUSTERS.html` | Crash candidates, reviewed diagnostics, and reproduction bundles. |
| `results/crashes-rejected/REJECTED-CRASHES.html` | Crash candidates rejected with an explanation. |
| `results/findings-rejected/REJECTED-FINDINGS.html` | Findings triage rejected, with the reason. |

`results/` here means `output/<target>/<backend>/results/`. Cross-backend
finding and crash summaries are written directly under `output/<target>/`.

[Artifact layout](reference/artifacts.md) describes the main generated paths, and
[Triage and review](guides/triage-results.md) explains the review standard.

<span id="how-the-pieces-fit"></span>

## The operating model

1. `bin/setup-target` creates or updates the checkout and generates
   `output/<target>/target.toml`.
2. `bin/audit` validates the target, pins a session-local config snapshot,
   ranks work, and launches agents.
3. Agents claim work, record hypotheses in structured state, and run testcases
   through `bin/probe`.
4. Triage validates reports, preserves rejections, clusters matching evidence,
   and exports accepted crashes as maintainer-facing bundles.

[Audit lifecycle](concepts/audit-lifecycle.md) walks through that flow, and
[System architecture](concepts/system-architecture.md) describes the component
boundaries.

## Boundaries and expectations

- **It does not replace fuzzing, code review, or maintainer judgment.** It is
  another way to spend an audit budget, and the
  [benchmark](concepts/benchmark.md) exists so you can check whether it earns
  that budget on your targets.
- **It does not publish anything.** There is no advisory pipeline and no
  automatic upstream filing. Disclosure stays yours, through the upstream
  project's process.
- **Severity scores are advisory.** CVSS v4.0 vectors are computed offline
  from the available evidence and report fields. Review the generated
  `## Severity rationale` and your deployment context before citing a score.
- **A finding is still a claim until a human checks it.** Automated review can
  admit, reject, or leave it unsettled. A fail-open gate preserves uncertain
  evidence; it does not certify it.
- **Clusters are a review aid, not a root-cause proof.** One defect can split
  across sinks, and two defects can share one.

## Choose what to read next

| What you want to do | Start here |
| --- | --- |
| Try TokenFuzz on a small example | [Getting started](getting-started/index.md) and [Sample targets](getting-started/sample-targets.md) |
| Bring your own project | [Add a target](getting-started/add-a-target.md), then [First audit](getting-started/first-audit.md) |
| Choose a backend and execution boundary | [Backends and isolation](guides/backends.md) |
| Review the output of a run | [Triage and review](guides/triage-results.md) |
| Assess a bundle sent to your project | [Reproduce a crash](guides/reproduce-a-crash.md) |
| Evaluate whether the harness helps | [Benchmarking](concepts/benchmark.md) |
| Understand or change the implementation | [System architecture](concepts/system-architecture.md) and [Development](development.md) |
| Look up a field or diagnose a failure | [Reference](reference/index.md) and [Troubleshooting](reference/troubleshooting.md) |

## Responsible use

Only run TokenFuzz on software you are authorised to test. Settle three facts
before the first long run:

- **The audit executes untrusted code.** Target build scripts and
  agent-authored testcases run on the machine you start it on. Use a
  disposable container or an isolated host without long-lived credentials; see
  [Container runtime](getting-started/prerequisites.md#container-runtime-recommended).
- **Hosted backends see the target.** Prompts, source excerpts, state, and
  reports go to the provider by design. Use the `oss` backend against a local
  endpoint when source must stay on the machine. The agent sandbox contains
  writes and network, not what the model reads;
  [Agent security modes](guides/backends.md#agent-security-modes) spells out
  the difference.
- **Disclosure stays yours.** Report target findings through the upstream
  project's coordinated-disclosure process, and review benchmark archives and
  research output before sharing them, as you would any other security
  artifact.

Security issues in TokenFuzz itself follow
[SECURITY.md](https://github.com/tokenfuzz/tokenfuzz/blob/main/SECURITY.md).
TokenFuzz is available under the
[Apache License 2.0](https://github.com/tokenfuzz/tokenfuzz/blob/main/LICENSE).
