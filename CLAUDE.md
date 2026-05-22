# Project Instructions

## Context

Automated sanitizer-regression QA framework. Spawns AI agents to write and
run AddressSanitizer testcases against local debug builds of open-source
C/C++ projects. All findings are filed privately with upstream maintainers.

- Use neutral vocabulary: bounds / lifetime / type / size / uninit / state.
- Follow `AGENTS.md` (this file) for testcase format and audit workflow;
  the same guide covers both browser and generic targets.

## Coding Discipline

- Avoid brittle regex extraction when a focused LLM call would be simpler, more
  complete, and robust enough without meaningful cost. Prefer structured parsers,
  schemas, and project APIs when they fit.
- Avoid adding hardcoded constants, especially caps or thresholds that can limit
  bug exploration. Make exploration depth configurable, visible, and easy to run.
- Keep the harness target-agnostic. Target-specific means **belongs to
  one codebase under audit** — its types, headers, file paths, subsystem
  boundaries, internal macros. Those must not appear in `bin/` or `lib/`;
  derive them at runtime from the live target tree, the work-card pool,
  or structured state. If a per-target value is truly unavoidable, isolate
  it in a target overlay (e.g. `targets/<name>/` or an opt-in config
  file), never in the shared harness.

  Industry-wide vocabulary is fair game — build-manifest filenames
  (`Cargo.toml`, `Package.swift`, `CMakeLists.txt`), standard or
  widely-adopted assert macros (`assert`, `static_assert`, `DCHECK`),
  sanitizer names (`asan`, `ubsan`), common spec keywords (`RFC`,
  `WHATWG`). Prefer **prefix or structural rules that catch the family**
  (e.g. `[A-Z]+_(?:ASSERT|CHECK)`) over exhaustive enumerations that rot
  as new projects appear. Where a small named list is unavoidable for
  debuggability, document the inclusion criterion above it so the list
  doesn't silently absorb target-specific entries over time.

- Never inline LLM prompt bodies in code. Every prompt sent to a
  backend belongs in `lib/prompts/*.md.j2`, rendered via
  `render_prompt_template` (shell) or `lib/prompt_render.py` (Python) —
  not an inline `prompt = """..."""`, a heredoc, or a concatenated
  string in `bin/`, `lib/`, or `.agents/`. Keeping prompts in templates
  is what makes them reviewable, diffable, and cache-stable;
  `tests/test_prompt_templates.sh` enforces it.
- Under `set -euo pipefail`, do not pipe long-running producers into
  `grep -q`; `grep -q` exits early and can turn a successful match into a
  SIGPIPE failure from the producer. Use a full-consuming check such as
  `grep -c` or another structured test instead.

## Testing Discipline

Every code change to the harness (`bin/`, `lib/`, `.agents/`) must be followed by:

1. **Run all tests.** `bash tests/run-tests.sh` immediately after editing.
2. **Update tests for new behavior.** New functions, renamed symbols, changed output — update test assertions. Don't leave stale tests passing by accident.
3. **Fix broken tests only with reason.** Determine whether the test or the code is wrong. Don't blindly update assertions to make green.
4. **Never reuse real stack frames in test fixtures.** Findings are filed
   privately upstream; a test that quotes the real `function file.c:line`
   tuple, ASan report, or signature from a finding turns the repo into a
   public disclosure artifact. Use neutral placeholder symbols and files
   (`child_free child.c:91`, `tool_resolve_entry catalog.c:42`, `apptool`,
   `sampleproj`) that preserve the shape under test — frame count, the
   `->` separator, file:func:line format, C++/template features — without
   naming a real subsystem. Industry-wide symbols (`malloc`, `strlen`,
   `main`, `__asan_*`, libc++ inline-namespace prefixes) are fine because
   they aren't tied to a target.

Tests live in `tests/`. Shared stubs in `tests/helpers.sh` — keep in sync with `bin/audit` and `lib/prompt.sh`.

## Logging Discipline

Files written under `output/<target>/<backend>/logs/` that do NOT include `${agent_num}` in the path are SHARED across parallel agents and the orchestrator. Concurrent writes to a shared file can corrupt or lose lines.

Rules:

1. **Prefer per-agent paths.** A path keyed by `${agent_num}` or a unique session timestamp is race-free by construction. The shell side of the harness stays correct by always keying log files this way — a new log file should be per-agent unless there is a strong reason otherwise.
2. **Forensic dumps stay under `logs/.raw/`.** Session dialogue (`session_*.log.raw`) and recon dialogue (`recon_*.raw`) live under the dotdir so agent file-scans don't pull them in.

For genuinely shared mutable state (counters, the work-card pool), use the `lib/workqueue.py` Python helpers (`jsonl_lock`, `append_jsonl`, `write_jsonl`) — they serialize via `fcntl.flock`. Reuse them rather than rolling your own.
