# Guides

These are task-oriented pages for audit operators, security reviewers, and
upstream maintainers. If you have not completed a one-iteration smoke test,
start with [Getting started](../getting-started/index.md).

Results use two main directories:

- `findings/` holds concrete security reports, with or without a reproducer.
- `crashes/` holds sanitizer or runtime-race candidates and reviewed bundles.
  Triage moves out-of-scope results to `crashes-rejected/` with their evidence
  and a reason. Human-pinned or older results can remain `not-reportable` in
  place.

Rejected artifacts are preserved under `findings-rejected/` and
`crashes-rejected/`, each with an HTML index explaining the decision.

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
