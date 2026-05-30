# Reference

Reference pages define exact command syntax, artifact paths,
configuration fields, operator-facing environment variables, and
shared vocabulary. Use them when you already know what you are trying
to do and need the canonical shape.

If you are learning a workflow, start with
[Getting started](../getting-started/index.md) or
[Guides](../guides/index.md). Reference pages assume the normal
TokenFuzz layout:

```text
output/<target>/target.toml
output/<target>/<backend>/results/
output/<target>/<backend>/logs/
```

## What to open

| Page | Use it for |
| --- | --- |
| [Commands](commands.md) | CLI syntax for setup, audit runs, probing, state checks, result review, and maintenance. |
| [Artifact layout](artifacts.md) | Where target config, backend results, logs, reports, rejected artifacts, and cross-backend rollups live. |
| [Target config](target-toml.md) | The generated `target.toml` schema, including `[sanitizer]`, `[runner]`, `[threat_model]`, harness build fields, and reproduction metadata. |
| [Environment variables](environment.md) | Operator-facing overrides for agent counts, timeouts, LLVM/model paths, probe selection, and ranking budgets. Most runs need none. |
| [Troubleshooting](troubleshooting.md) | Symptom-indexed fixes for preflight, target config, backend auth, missing results, triage rejects, and logs. |
| [Glossary](glossary.md) | Shared vocabulary for the audit lifecycle, artifacts, triage, strategies, and harness internals. |
