# Concepts

These pages explain how TokenFuzz works and why it is built the way it is.
For step-by-step tasks, use the [Guides](../guides/index.md).

Read [Audit lifecycle](audit-lifecycle.md) first for the end-to-end story.
Each of the other pages covers one component or one cross-cutting design
choice, and can be read on its own.

| Page | What it covers |
| --- | --- |
| [Audit lifecycle](audit-lifecycle.md) | One run, from setup to a reviewed finding or a maintainer crash bundle, with a diagram. |
| [System architecture](system-architecture.md) | The components and their boundaries: audit run, work queue, agents, probe runner, triage, and backends. |
| [Strategy model](strategy-model.md) | The eight investigation methods, how a work card gets its strategy, and how rotation responds to evidence. |
| [Review coverage](coverage.md) | What a run actually read and what it never reached: the auditable-file manifest, examined-line receipts, the transcript cross-check, the budgeted sweep, and the cross-file second pass. |
| [Deduplication](deduplication.md) | How crashes and findings are grouped for review, and when a duplicate is refused at filing or folded into an existing result. |
| [Cost model](cost-model.md) | What drives cost on long runs, how dollars are estimated, and the levers you control. |
| [Benchmarking](benchmark.md) | How `bin/benchmark` compares TokenFuzz with a direct prompt without hiding orchestration or review cost, and how an answer key measures precision and recall. |
| [Sample benchmark result](../sample-benchmark.md) | A finished result page from a run against the C sample. |
