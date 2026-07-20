<p align="center">
  <img src="docs/assets/logo-lockup.svg" alt="TokenFuzz" width="400">
</p>

TokenFuzz is an open-source harness for evidence-driven, LLM-assisted security
auditing. It coordinates agents that inspect source, form concrete hypotheses,
run testcases, and turn validated results into reports a maintainer can review.
It works with C/C++, Rust, Go, Python, Java, and other supported languages,
from native libraries and command-line tools to browsers and JavaScript
runtimes.

The harness supplies the parts a long audit needs beyond a prompt:

- **Source-to-testcase investigation.** Deterministic
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

## Documentation

Read the [documentation](https://tokenfuzz.github.io/tokenfuzz/) for
installation, a first audit, target configuration, result triage, architecture,
benchmarking, and development.

Only test software you are authorised to assess, and report target findings
through the upstream project's security process.
