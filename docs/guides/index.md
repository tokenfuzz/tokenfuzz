# Guides

Task-oriented pages for the operator running an audit and for the
maintainer receiving its output. Pick the one that matches what you
are about to do.

| Page | Use it when |
| --- | --- |
| [Configure a target](configure-target.md) | Review `target.toml` after `bin/setup-target` generates it. |
| [Backends and ensembling](backends.md) | Run a single backend, cycle multiple hosted backends, or compare them. |
| [Breadth-first recon](recon-discovery.md) | Sweep the in-scope source set for candidate bugs before running `bin/audit`. |
| [Non-C/C++ targets](multi-language.md) | Audit Python, Ruby, Go, Java, Kotlin, or Node targets in findings-only mode. |
| [Browser targets](browser-targets.md) | Audit Firefox, Chromium, or a JS/Wasm runtime. |
| [Triage results](triage-results.md) | Decide which crashes and findings to promote, reject, or refine. |
| [Benchmark the harness](benchmark.md) | Measure, with evidence, whether the harness out-finds a bare CTF prompt on a target. |
| [Reproduce a crash](reproduce-a-crash.md) | (For upstream maintainers) re-run a TokenFuzz crash artifact — bundle or raw `reproduce.sh` — against your own checkout. |
