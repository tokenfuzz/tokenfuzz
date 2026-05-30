# Guides

Task-oriented pages for the operator running an audit and for the
maintainer receiving its output. Pick the one that matches what you
are about to do.

## Read these in order for a first run

1. [Configure a target](configure-target.md) — review the generated
   `target.toml` and make sure the runner or sanitizer build is real.
2. [Backends and ensembling](backends.md) — pick one backend for a
   reproducible run, or cycle hosted backends when you want broader
   coverage.
3. [Non-C/C++ targets](multi-language.md) or
   [Browser targets](browser-targets.md) — only if your target needs
   ecosystem-specific runner setup.
4. [Recon discovery](recon-discovery.md) — understand the cold-start
   survey that `bin/audit` runs automatically, or run it standalone
   when you want to inspect candidate work first.
5. [Triage results](triage-results.md) — review crashes, findings,
   rejected candidates, and duplicate clusters.

## Two rules that shape the guides

- `findings/` is for concrete security issues, with or without a
  runnable reproducer.
- `crashes/` is stricter: it is for sanitizer-backed reproductions,
  runtime-race diagnostics, or accepted security-boundary violations
  that can be clustered and exported.

## All guide pages

| Page | Use it when |
| --- | --- |
| [Configure a target](configure-target.md) | Review `target.toml` after `bin/setup-target` generates it. |
| [Backends and ensembling](backends.md) | Run a single backend, cycle multiple hosted backends, or compare them. |
| [Non-C/C++ targets](multi-language.md) | Configure language runners, findings-only targets, or non-ASan sanitizers such as Go `race`. |
| [Browser targets](browser-targets.md) | Audit Firefox, Chromium, or a JS/Wasm runtime. |
| [Recon discovery](recon-discovery.md) | Understand or refresh the breadth-first source survey that seeds the audit queue. |
| [Triage results](triage-results.md) | Decide which crashes and findings to promote, reject, or refine. |
| [Benchmark the harness](benchmark.md) | Measure, with evidence, whether the harness out-finds a bare CTF prompt on a target. |
| [Reproduce a crash](reproduce-a-crash.md) | Re-run an exported TokenFuzz crash bundle against a clean upstream checkout. |
