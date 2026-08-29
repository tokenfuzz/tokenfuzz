# TokenFuzz

TokenFuzz is an open-source harness for evidence-driven, LLM-assisted security
auditing. It turns model-led source review into a shared queue of concrete
hypotheses, runs every testcase through one execution contract, and preserves
the result as evidence a security team or upstream maintainer can inspect.

The important distinction is between discovery and proof. Agents can suggest
where a bug may be; TokenFuzz records what was actually tested, keeps review
decisions attached to the evidence they judged, and separates four outcomes:

| Outcome | What it means |
| --- | --- |
| Finding | A concrete security claim with a source location and an actionable report. A reproducer is optional. |
| Crash | A reproducible sanitizer or runtime-race diagnostic with its testcase and saved output. |
| Not reportable | A real engineering defect that review found outside the configured security boundary. It stays visible but receives no security score. |
| Rejected | Evidence that did not meet the relevant gate. It is preserved with the reason. |

TokenFuzz supports native libraries and CLIs, browsers and JavaScript engines,
and language-runner targets including Rust, Go, Python, Java, Kotlin, Swift,
Ruby, PHP, JavaScript/TypeScript, Perl, and R. It can drive Claude Code, Codex
CLI, Gemini through Antigravity or Google Gemini CLI, Grok Build, and OpenCode
with either a catalog provider or a local OpenAI-compatible endpoint.

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
sixteen synthetic targets shipped with the repository. After a healthy smoke
test, run a bounded working session or omit the count for a continuous run:

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
| Changing TokenFuzz itself | [Development](development.md) |

## Where results go

TokenFuzz keeps source and audit evidence separate:

```text
targets/<target>/                         source checkout and build artifacts
output/<target>/target.toml               target configuration and threat model
output/<target>/<backend>/results/        findings, crashes, state, and scratch work
output/<target>/<backend>/logs/           run and backend diagnostics
```

Start review with the generated HTML indexes, not model transcripts:

| Path | Purpose |
| --- | --- |
| `results/findings/FINDING-CLUSTERS.html` | Concrete security findings, grouped by exact evidence signature. |
| `results/crashes/CRASH-CLUSTERS.html` | Confirmed sanitizer or race diagnostics and their reproduction bundles. |
| `results/crashes-rejected/REJECTED-CRASHES.html` | Crash candidates rejected with an explanation. |
| `results/findings-rejected/REJECTED-FINDINGS.html` | Findings triage rejected, with the reason. |

The backend-specific `results/` prefix is
`output/<target>/<backend>/results/`. Cross-backend finding and crash summaries
are written directly under `output/<target>/`.

Read [Artifact layout](reference/artifacts.md) for every generated path and
[Triage results](guides/triage-results.md) for the review standard.

## The operating model

1. `bin/setup-target` creates or updates the checkout and generates
   `output/<target>/target.toml`.
2. `bin/audit` validates the target, pins a session-local config snapshot,
   ranks work, and launches agents.
3. Agents claim work, record hypotheses in structured state, and run testcases
   through `bin/probe`.
4. Triage validates reports, preserves rejections, clusters matching evidence,
   and exports accepted crashes as maintainer-facing bundles.

See [Audit lifecycle](concepts/audit-lifecycle.md) for the detailed flow and
[System architecture](concepts/system-architecture.md) for component boundaries.

## Boundaries and expectations

- **It does not replace fuzzing, code review, or maintainer judgment.** It is
  another way to spend an audit budget, and the
  [benchmark](concepts/benchmark.md) exists so you can check whether it is
  earning that budget on your targets.
- **It does not publish anything.** No advisory pipeline, no automatic upstream
  filing. Disclosure stays yours, through the upstream project's process.
- **Its severity scores are advisory.** They are real CVSS v4.0 vectors,
  computed offline from the report's own fields — but two metrics are
  worst-case defaults the harness cannot know, and only you know what the asset
  is worth. Read the generated `## Severity rationale` before citing a number.
- **A finding is still a claim until a human checks it.** Automated review can
  admit, reject, or leave it unsettled. A fail-open gate preserves uncertain
  evidence; it does not certify it.
- **Clusters are a review aid, not a root-cause proof.** One defect can split
  across sinks, and two defects can share one.

## Responsible use

Only run TokenFuzz on software you are authorised to test. Three facts are
worth settling before the first long run:

- **The audit executes untrusted code.** Target build scripts and
  agent-authored testcases run on the machine you start it on. Use a
  disposable container or an isolated host without long-lived credentials —
  see [Container runtime](getting-started/prerequisites.md#container-runtime-recommended).
- **Hosted backends see the target.** Prompts, source excerpts, state, and
  reports go to the provider by design. Use the `oss` backend against a local
  endpoint when source must stay on the machine. The agent sandbox contains
  writes and network, not what the model reads —
  [Agent security modes](guides/backends.md#agent-security-modes) is explicit
  about the difference.
- **Disclosure stays yours.** Report target findings through the upstream
  project's coordinated-disclosure process, and review benchmark archives and
  research output before sharing them, as you would any other security
  artifact.

Security issues in TokenFuzz itself follow
[SECURITY.md](https://github.com/tokenfuzz/tokenfuzz/blob/main/SECURITY.md).
TokenFuzz is available under the
[Apache License 2.0](https://github.com/tokenfuzz/tokenfuzz/blob/main/LICENSE).
