# Project Instructions

- Use neutral vocabulary: bounds / lifetime / type / size / uninit / state.
- Follow `AGENTS.md` for testcase format and audit workflow; same guide covers browser and generic targets.

## Coding Discipline

- Prefer focused LLM calls, structured parsers, schemas, or project APIs over brittle regex extraction.
- No hardcoded caps or thresholds that limit bug exploration. Make exploration depth configurable, visible, and easy to run.
- Keep the harness target-agnostic. Target-specific means **belongs to one codebase under audit** — its types, headers, paths, subsystem boundaries, internal macros. Those must not appear in `bin/` or `lib/`; derive them at runtime from the live target tree, work-card pool, or structured state. If a per-target value is truly unavoidable, isolate it in a target overlay (`targets/<name>/` or an opt-in config), never in the shared harness.

  Industry-wide vocabulary is fair game — build-manifest filenames (`Cargo.toml`, `Package.swift`, `CMakeLists.txt`), widely-adopted assert macros (`assert`, `static_assert`, `DCHECK`), sanitizer names (`asan`, `ubsan`), common spec keywords (`RFC`, `WHATWG`). Prefer **prefix or structural rules that catch the family** (e.g. `[A-Z]+_(?:ASSERT|CHECK)`) over exhaustive enumerations that rot as new projects appear. Where a small named list is unavoidable for debuggability, document the inclusion criterion above it so the list doesn't silently absorb target-specific entries.
- Never inline LLM prompt bodies. Every prompt belongs in `lib/prompts/*.md.j2`, rendered via `render_prompt_template` (shell) or `lib/prompt_render.py` (Python) — not an inline `prompt = """..."""`, a heredoc, or a concatenated string in `bin/`, `lib/`, or `.agents/`. Templates are reviewable, diffable, and cache-stable; `tests/test_prompt_templates.sh` enforces it.
- Under `set -euo pipefail`, don't pipe long-running producers into `grep -q` — it exits early and can turn a successful match into a SIGPIPE failure from the producer. Use `grep -c` or another full-consuming check.

## Testing Discipline

Every change to `bin/`, `lib/`, or `.agents/` must be followed by:

1. **Run all tests.** `bash tests/run-tests.sh` immediately after editing.
2. **Update tests for new behavior.** New functions, renamed symbols, changed output — update assertions. Don't leave stale tests passing by accident.
3. **Fix broken tests only with reason.** Determine whether the test or the code is wrong. Don't blindly update assertions to make green.
4. **Never reuse real stack frames in fixtures.** Findings are filed privately upstream; a test that quotes the real `function file.c:line` tuple, ASan report, or signature turns the repo into a public disclosure artifact. Use neutral placeholders (`child_free child.c:91`, `tool_resolve_entry catalog.c:42`, `apptool`, `sampleproj`) that preserve the shape under test — frame count, `->` separator, file:func:line format, C++/template features — without naming a real subsystem. Industry-wide symbols (`malloc`, `strlen`, `main`, `__asan_*`, libc++ inline-namespace prefixes) are fine.

Tests live in `tests/`. Shared stubs in `tests/helpers.sh` — keep in sync with `bin/audit` and `lib/prompt.sh`.

## Logging Discipline

Files under `output/<target>/<backend>/logs/` that do NOT include `${agent_num}` in the path are SHARED across parallel agents and the orchestrator. Concurrent writes can corrupt or lose lines.

1. **Prefer per-agent paths.** Key log files by `${agent_num}` or a unique session timestamp — race-free by construction. A new log file should be per-agent unless there's a strong reason otherwise.
2. **Forensic dumps stay under `logs/.raw/`.** Session dialogue (`session_*.log.raw`) and recon dialogue (`recon_*.raw`) live under the dotdir so agent file-scans don't pull them in.

For genuinely shared mutable state (counters, the work-card pool), use `lib/workqueue.py` helpers (`jsonl_lock`, `append_jsonl`, `write_jsonl`) — they serialize via `fcntl.flock`. Don't roll your own.
