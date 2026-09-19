# Concepts

These pages explain how TokenFuzz works and why its components behave the way
they do. For step-by-step tasks, use the [Guides](../guides/index.md).

If you read them in order, start with [Audit lifecycle](audit-lifecycle.md)
for the end-to-end story. The other pages explain individual components and
cross-cutting design choices.

| Page | What it covers |
| --- | --- |
| [Audit lifecycle](audit-lifecycle.md) | A run from setup to a reviewed finding or maintainer crash bundle, in one place, with a diagram. |
| [System architecture](system-architecture.md) | The components: audit run, work queue, agents, probe runner, triage, backends. |
| [Strategy model](strategy-model.md) | The eight investigation methods, how cards get a strategy, and how evidence-aware rotation works. |
| [Review coverage](coverage.md) | The auditable-file manifest, examined-line receipts, the transcript cross-check, the budgeted sweep, and the cross-file second pass: what a run actually read, and what it never reached. |
| [Cost model](cost-model.md) | What scales with cost on long runs, and the levers the harness gives you. |
| [Deduplication](deduplication.md) | How crashes (stack-similarity clustering) and findings (evidence clustering) group related reports for review. |
| [Benchmarking](benchmark.md) | How `bin/benchmark` compares TokenFuzz against a direct prompt without hiding orchestration or review cost. |
