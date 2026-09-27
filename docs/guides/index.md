# Guides

Task-oriented pages for audit operators, security reviewers, and upstream
maintainers. If you have not run a one-iteration smoke test yet, start with
[Getting started](../getting-started/index.md).

A run files results in two directories under
`output/<target>/<backend>/results/`:

- `findings/` holds concrete security reports, with or without a reproducer.
- `crashes/` holds sanitizer or runtime-race candidates and reviewed bundles.

Triage moves rejected artifacts to `findings-rejected/` and
`crashes-rejected/`, keeping their evidence and the reason. Each directory has
an HTML index that explains its entries.

## Configure the run

| Page | Use it when |
| --- | --- |
| [Target configuration](configure-target.md) | You are reviewing the `target.toml` that `bin/setup-target` generated. |
| [Language runners](multi-language.md) | The target is not plain C/C++, runs in findings-only mode, or uses Go's `race` detector. |
| [Backends and isolation](backends.md) | You are choosing a model backend and the execution boundary around it. |

## Run a specialised target or strategy

| Page | Use it when |
| --- | --- |
| [Browser targets](browser-targets.md) | You are auditing Firefox, Chromium, or a JavaScript or WebAssembly runtime. |
| [Boundary-directed fuzzing](directed-fuzzing.md) | You want to steer S4, which builds a libFuzzer harness for a published C or C++ API that no existing harness drives and runs one bounded campaign on it. |

## Review and share results

| Page | Use it when |
| --- | --- |
| [Triage and review](triage-results.md) | You are deciding which results are ready for human or upstream review. |
| [Reproduce a crash](reproduce-a-crash.md) | You received an exported crash bundle and want to reproduce it on your own checkout. |
