# TokenFuzz

TokenFuzz is an open-source harness for evidence-driven, LLM-assisted security
auditing. It coordinates agents that inspect source, form concrete hypotheses,
run testcases, and turn validated results into reports a maintainer can review.
It works with C/C++, Rust, Go, Python, Java, and other supported languages,
from native libraries and command-line tools to browsers and JavaScript
runtimes.

The harness supplies the parts a long audit needs beyond a prompt:

- **Source-to-testcase investigation.** Cold-start recon and deterministic
  ranking create a shared work queue; eight review strategies guide deeper
  analysis without requiring a known bug or crashing seed.
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
- **Supported backends.** Claude Code, Codex CLI, Gemini via Antigravity or Google
  Gemini CLI, Grok Build, and local models via OpenCode; `--backend all` rotates hosted backends.

Hosted and local model backends use the same audit contract. Bounded source
reads, prompt reuse, execution budgets, and resumable state keep long runs
operationally manageable. Final security judgment remains with the operator and
the upstream maintainer.

## Quick start

TokenFuzz supports macOS and Linux. Install Python 3.10+, Git, ripgrep, `file`,
an LLVM toolchain for native sanitizer targets, and one supported backend.
[Prerequisites](getting-started/prerequisites.md) has platform-specific setup.

```bash
git clone https://github.com/tokenfuzz/tokenfuzz
cd tokenfuzz

bash tests/run-tests.sh

bin/setup-target <target> <repo-url>
bin/audit --target <target> --backend <claude|codex|gemini|grok|oss> 1
```

The final `1` runs one bounded iteration. Its purpose is to prove that target
setup, the backend, state, and result directories work together—not to find a
vulnerability. When the smoke test is healthy, omit the count for a continuous
run:

```bash
bin/audit --target <target> --backend <backend>
```

The complete walkthrough is in [First audit](getting-started/first-audit.md).

## Supported targets

Anything with a source tree and a testable input boundary can work:

- C/C++ libraries, parsers, codecs, protocol implementations, and CLIs;
- Rust and Go projects with native sanitizer or race diagnostics;
- Python and Java projects, plus Ruby, PHP, Node, Kotlin, and other
  runtimes driven through a configured language runner;
- browsers, JavaScript engines, WebAssembly runtimes, Swift projects, and
  mixed-language code driven through the appropriate sanitizer or
  configured language runner.

ASan is the default for native targets. UBSan, MSan, TSan, and Go `race` are
opt-in. Projects without a sanitizer run in findings-only mode: their runtime
diagnostics and source-backed security issues go to `findings/`, not
`crashes/`. See [Non-C/C++ targets](guides/multi-language.md).

## Where results go

TokenFuzz keeps source and audit evidence separate:

```text
targets/<target>/                         source checkout and build artifacts
output/<target>/target.toml               target configuration and threat model
output/<target>/<backend>/results/        findings, crashes, state, and scratch work
output/<target>/<backend>/logs/           run and backend diagnostics
```

Start review with these generated pages:

| Path | Purpose |
| --- | --- |
| `results/findings/FINDING-CLUSTERS.html` | Concrete security findings, grouped by root cause. |
| `results/crashes/CRASH-CLUSTERS.html` | Confirmed sanitizer or race diagnostics and their reproduction bundles. |
| `results/crashes-rejected/REJECTED-CRASHES.html` | Crash candidates rejected with an explanation. |

The backend-specific `results/` prefix is
`output/<target>/<backend>/results/`. Cross-backend finding and crash summaries
are written directly under `output/<target>/`.

Read [Artifact layout](reference/artifacts.md) for every generated path and
[Triage results](guides/triage-results.md) for the review standard.

## How the pieces fit

1. `bin/setup-target` creates or updates the checkout and generates
   `output/<target>/target.toml`.
2. `bin/audit` validates the config, refreshes stale native sanitizer artifacts
   when supported, surveys and ranks the source, and launches agents.
3. Agents claim work, record hypotheses in structured state, and run testcases
   through `bin/probe`.
4. Triage validates reports, quarantines low-value results, clusters duplicate
   root causes, and exports accepted crashes for maintainers.

See [Audit lifecycle](concepts/audit-lifecycle.md) for the detailed flow and
[System architecture](concepts/system-architecture.md) for component boundaries.

## Choose what to read next

| Goal | Start here |
| --- | --- |
| Install TokenFuzz and run one safe iteration | [Getting started](getting-started/index.md) |
| Add or configure a target | [Add a target](getting-started/add-a-target.md) |
| Choose a hosted or local model backend | [Backends and ensembling](guides/backends.md) |
| Review findings and crash bundles | [Triage results](guides/triage-results.md) |
| Reproduce a reported crash | [Reproduce a crash](guides/reproduce-a-crash.md) |
| Compare the harness with a direct model prompt | [Benchmarking](concepts/benchmark.md) |
| Look up exact commands or config fields | [Reference](reference/index.md) |
| Diagnose a failed run | [Troubleshooting](reference/troubleshooting.md) |
| Change TokenFuzz itself | [Development](development.md) |

## Responsible use

Only run TokenFuzz on software you are authorised to test. Hosted backends
receive the prompts, source excerpts, state, and reports required for the run;
use `--backend oss` when source must stay local. Report target findings through
the upstream project's coordinated-disclosure process. Review benchmark
archives and research results before sharing them, just as you would any other
security artifact.

Security issues in TokenFuzz itself follow
[SECURITY.md](https://github.com/tokenfuzz/tokenfuzz/blob/main/SECURITY.md).
TokenFuzz is available under the
[Apache License 2.0](https://github.com/tokenfuzz/tokenfuzz/blob/main/LICENSE).
