# Guides

These are task-oriented pages for audit operators, security reviewers, and
upstream maintainers. If you have not completed a one-iteration smoke test,
start with [Getting started](../getting-started/index.md).

Two rules apply throughout the handbook:

- `findings/` holds concrete security reports, with or without a reproducer.
- `crashes/` holds reproducible sanitizer or runtime-race evidence. A crash can
  later be classified `not-reportable` without being thrown away.

Rejected artifacts are preserved under `findings-rejected/` and
`crashes-rejected/`, with an HTML index explaining each decision.

## All guide pages

### Configure the run

| Page | Use it when |
| --- | --- |
| [Target configuration](configure-target.md) | Review `target.toml` after `bin/setup-target` generates it. |
| [Language runners](multi-language.md) | Configure non-C/C++ targets, findings-only mode, or Go `race`. |
| [Backends and isolation](backends.md) | Choose a model backend and the execution boundary around it. |

### Run a specialized target or strategy

| Page | Use it when |
| --- | --- |
| [Browser targets](browser-targets.md) | Audit Firefox, Chromium, or a JS/Wasm runtime. |
| [Boundary-directed fuzzing](directed-fuzzing.md) | Run S4 against published, reachable, undriven APIs without changing the shared build. |

### Review and share results

| Page | Use it when |
| --- | --- |
| [Triage and review](triage-results.md) | Decide which results are ready for human or upstream review. |
| [Reproduce a crash](reproduce-a-crash.md) | Re-run an exported crash bundle against an upstream checkout. |
