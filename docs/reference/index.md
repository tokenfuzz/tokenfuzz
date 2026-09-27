# Reference

Reference pages define exact contracts: command syntax, configuration fields,
environment variables, artifact paths, and shared vocabulary. Use them to
look something up. To learn a workflow, start with
[Getting started](../getting-started/index.md) or the
[Guides](../guides/index.md).

Every page assumes the standard layout, where `<target>` is the target slug
and `<backend>` is the model backend that ran:

```text
output/<target>/target.toml
output/<target>/<backend>/results/
output/<target>/<backend>/logs/
```

| Page | Use it for |
| --- | --- |
| [Commands](commands.md) | Every `bin/` command, grouped by task: setup, audit runs, progress, result review, testcases, benchmarking, maintenance, and agent tools. |
| [Target config](target-toml.md) | Every supported `target.toml` field, placeholder token, default, and path rule. |
| [Environment variables](environment.md) | Operator overrides: worker pool, spend and time ceilings, model selection, agent security, local endpoints, the container helper, toolchains, and one-off probe selection. |
| [Artifact layout](artifacts.md) | Where target config, results, review receipts, reports, rejected artifacts, logs, cross-backend summaries, and benchmark output live. |
| [Bug classes](bug-classes.md) | The canonical class vocabulary used to label, cluster, count, and score results, and what each class maps to. |
| [Troubleshooting](troubleshooting.md) | Fixes indexed by symptom: where messages appear, preflight and setup failures, paused or stuck runs, probe and sanitizer failures, and triage rejections. |
| [Glossary](glossary.md) | Terms used in logs, reports, and these pages: runs, the work queue, coverage, strategies, probing, artifacts, review, configuration, backends, and benchmarking. |
