# Concepts

These pages explain why TokenFuzz is shaped the way it is. They describe the
system rather than walking through an operator task.

If you are reading them in order, [Audit lifecycle](audit-lifecycle.md) is the
one that makes the rest make sense — every other page here expands on one step
of it.

| Page | What it covers |
| --- | --- |
| [Audit lifecycle](audit-lifecycle.md) | A run from setup to a maintainer bundle, in one place, with a diagram. |
| [System architecture](system-architecture.md) | The components — audit run, work queue, agents, probe runner, triage, backends. |
| [Strategy model](strategy-model.md) | The eight investigation methods, how cards get a strategy, and how rotation is effort-gated. |
| [Cost model](cost-model.md) | What scales with cost on long runs, and the levers the harness gives you. |
| [Deduplication](deduplication.md) | How crashes (stack-state bucketing) and findings (evidence clustering) group matching report signatures for review. |
| [Benchmarking](benchmark.md) | How `bin/benchmark` compares TokenFuzz against a direct prompt without hiding orchestration or review cost. |
