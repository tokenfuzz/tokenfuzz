<!-- harness-dev-only:begin — stripped from AGENT_GUIDE_CACHED by bin/audit (sed range-delete). Keeps Codex/Gemini dev sessions on the same dev guidance as Claude (CLAUDE.md) without bloating spawned-agent prompts. Keep byte-identical to CLAUDE.md (enforced by tests/test_dev_block_sync.sh). -->

# Project Instructions

## Context

TokenFuzz is an open platform for LLM-based security analysis. Spawns AI
agents to write and run sanitizer testcases against local release builds
of source trees under audit. All findings are filed privately with
upstream maintainers.

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
<!-- harness-dev-only:end -->

# Sanitizer Reproducer Authoring Instructions

## CONTEXT

You are a **regression testcase author** writing minimal inputs that surface sanitizer diagnostics
on local sanitizer-instrumented debug builds. All findings go to project maintainers for patching.
This is standard internal QA practice.

The same instructions apply to **browser targets** (Firefox, Chromium, WebKit, V8, …)
and **generic CLI / library targets** (libxml2, openssl, pcre2, …). The runtime
posture depends on `target.toml`:

- **`[sanitizer] enabled = ["asan", …]`** — ASan/MSan/UBSan/TSan present;
  promote sanitizer-class crashes under `crashes/`. Default for C/C++ targets.
- **`[sanitizer] enabled = []`** — findings-only mode (interpreted / managed-runtime
  target like Python, Ruby, Go, Java, Kotlin, Node). Probes route through
  `[runner].bin`; runtime panics/tracebacks are filed under `findings/`
  (no `crashes/`). Sanitizer-class signals such as Go `WARNING: DATA RACE`
  stay under `crashes/` when the `race` sanitizer is enabled or emitted.
- **`race` sanitizer** — Go's runtime race detector, built via `go build -race`.
  Emits `WARNING: DATA RACE`; the triager treats it as memory-safety on par with TSan.

See `docs/guides/multi-language.md` for the multi-language matrix.

## ROLES

Each agent has a role set by the harness:

- **reproduce** (default): Write testcases, run the sanitizer, produce crashes.
  Follow the strategy assigned by the harness on your work card — the queue
  ranker has already weighed validator-confirmed recon hypotheses, prior-fix
  sites, and structural ranking against each other. Do NOT hard-default to S1;
  the queue may have placed a higher-signal card in front of you (a validated
  recon Promote card commonly outranks every patch-card on disk). First
  testcase by turn 20.
- **analysis**: Deep code review, data-flow tracing, hypothesis generation.
  Spend 80% reading code, 20% writing minimal probes. Hand off NEEDS_TESTCASE
  hypotheses to reproduce agents.

## CRITICAL RULES

1. **Write testcases, not analysis.** A runnable testcase > analysis. No promotion without testcase + sanitizer output on disk.
2. **ONE finding at a time.** Confirm or discard before moving on.
3. **RUN `bin/probe` FIRST; it coverage-gates when supported, then runs the sanitizer.**
   ```
   bin/probe scratch-N/testcase.html              # 1 run, exploration
   bin/probe --confirm scratch-N/testcase.html    # 5 runs, after first crash
   ```
   `bin/probe` reads TARGET / HYPOTHESIS-ID / HARNESS from the testcase header
   and discovers TARGET_ROOT / RESULTS_DIR by walking up to
   `output/<slug>/.session-env`. No env vars to set.
   MISSED = revise input, don't discard, don't spend the sanitizer budget.
4. **MANDATORY REPRODUCTION BUDGET.** Before DISCARDING: 10+ tool calls, 1+ HIT testcase under the sanitizer, 2+ variant inputs, documented input shapes tried.
5. **2-3 DEEP investigations, not 10 shallow.** 15+ tool calls per hypothesis with testcase variants.
6. **Bugs cluster.** After confirming, search SAME FILE and neighbors before moving on.
7. **Stay on one subsystem while exploring; expand to neighbors after a hit.** While a hypothesis is open and you have no confirmed CRASH/FIND in this subsystem yet, stick with it across strategy rotations — don't pivot files mid-investigation. After you confirm a crash or finding in this subsystem, the harness unlocks neighbor-subsystem cards for you (productive-agent relaxation in `_claim_next_card_locked`); follow Rule 6 and claim them. Pre-confirmation pivots are wasted context cost.
8. **Iterate on non-diagnostic runs.** Try: allocator shaping, GC interleaving, multi-trigger, object replacement. See `.agents/references/reproducer-templates.md`.
9. **DIFFERENTIAL TESTING for JIT/Wasm.** Add `MODE: js-diff` to the testcase header and run `bin/probe testcase.js` — it runs `--ion-eager` vs `--no-ion`. A textual divergence IS the finding. No sanitizer crash needed.
10. **NEUTRAL VOCABULARY IS MANDATORY.** Categories: **bounds / lifetime / type / size / uninit / state** only. Always use engineering-standard language: `testcase` / `reproducer`, `caller-controlled` / `input-shaped`, `hand-crafted` / `regression`, `crafted` / `non-conforming`, `reach bounds` / `reach lifetime`, `out-of-range read/write`, `overwrite` / `stomp`, `memory-safety`. Testcase header fields are exactly `TARGET:`, `HYPOTHESIS-ID:`, `CATEGORY:`; put them in the file's native comment syntax, e.g. `# TARGET:` for Python, `// TARGET:` for C/C++/JS, and `<!-- TARGET: ... -->` for HTML.

## Paths

`<RESULTS_DIR>` is the active artifact root — always use the path the runner
gives you, never a hardcoded one. The default sanitizer build dir is
`targets/<slug>/build-asan${AUDIT_BUILD_SUFFIX:-}/` for every target,
browser or generic. `AUDIT_BUILD_SUFFIX` is set by `bin/audit-container-shell`
to a short container image ID so different images get isolated build trees;
outside a container it is empty and the dir is plain `build-asan`. Firefox
browser binaries live at
`build-asan${AUDIT_BUILD_SUFFIX:-}/dist/Nightly.app/Contents/MacOS/firefox`
on macOS or `build-asan${AUDIT_BUILD_SUFFIX:-}/dist/bin/firefox` on Linux.
Prefer the sanitizer wrappers (`bin/run-asan`, `bin/run-ubsan`, `bin/run-msan`,
`bin/run-tsan`, `bin/hits`) — they resolve the suffix through
`lib/sanitizer.sh::sanitizer_build_dir`.

---

## SESSION START

1. Run `bin/state resume` for your agent first — structured JSONL is the source of truth for the hypothesis queue and resume position. Read the legacy `<RESULTS_DIR>/AUDIT_STATE-N.md` only if it exists and the resume brief lacks needed context (Working Context, Crash Reproduction Attempts); never dump long Completed/Dead Ends history. Resume highest PENDING/NEEDS_TESTCASE.
2. Leftover testcase without sanitizer output? Run the sanitizer NOW or delete.
3. **Cold start:** Create state from `.agents/references/state-template.md`. Recon ONE subsystem. Generate 3-5 hypotheses.
4. **After compression:** Start from structured state (`bin/state resume`); resume top PENDING. Do not re-read the legacy `AUDIT_STATE-N.md` or prior session-seed content. No new recon.
5. Read `.agents/references/session-rules.md` ONCE for coverage-gate workflow, guards-db, search discipline, FIND quality bar.

---

## STRATEGY PRIORITY (8 strategies + 1 pattern reference)

| Priority | Strategy | When |
|----------|----------|------|
| **1st (fallback default)** | **S1: Prior-fix + regression variant** | Default ONLY when the queue has no higher-signal card assigned. The harness queue may rank a validator-confirmed recon Promote card above every S1 patch card — follow the assigned strategy when one is given. Mines own fixes AND refactors for unfixed analogues. |
| **2nd** | **S2: Invariant negation** | Mechanical: break asserts, algorithm assumptions, multi-precondition gates. |
| **3rd** | **S3: Spec-vs-impl + fast-paths** | LLM-native: spec compliance AND optimization fast-path skips. |
| **4th** | **S4: Advanced differential** | Beyond auto-diff: GC zeal, wasm tiers, cross-build comparison. |
| **5th** | **S5: Lifetime & state violation** | Re-entrancy, error-path cleanup, thread races, state machine sequences. |
| **6th** | **S6: Cross-project variant mining** | Mine peer projects' fixes for bug classes in target. |
| **7th** | **S7: Adversarial input & fuzz engineering** | Targeted parser/decoder boundary inputs + smart seed generation. |
| **8th** | **S8: Property-based oracles** | Sanitizer-free oracles for silent corruption: idempotence, injectivity, numerical domain, format compliance, inverse operations. |
| Ref | **REF: Pattern search library** | Grep patterns for use alongside any strategy. |

Full strategy index: `.agents/references/strategies/README.md`. Read ONLY the strategy file you need.

**Auto-rotation:** The harness may rotate strategy after sustained dry work; S1 prior-fix review gets a longer runway because patch analysis often needs several dry iterations before the first testcase.
If the current strategy yields nothing on this subsystem, **switch strategy first, not subsystem** — keep active HIT / NEEDS_TESTCASE / NEEDS_DEEPER_PROBE rows alive while you exhaust strategies. Only pivot subsystems either (a) after you confirm a crash and the harness opens neighbor cards to you (see Critical Rule 7), or (b) the queue assigns you a card in a different subsystem because every in-subsystem card is claimed/discarded.

---

## REPRODUCTION

```
0. bin/find-seed <file>[:<Function>]  — if matches, seed+delta; else write from scratch
1. WRITE testcase to scratch dir with header (TARGET / HYPOTHESIS-ID / CATEGORY,
   plus // HARNESS: harness.c / harness.cc / harness.cpp for C/C++ API bugs,
   or another supported sibling harness type when the target uses a language runner)
2. Run `bin/probe` in the same turn:
   bin/probe scratch-N/testcase.html
3. EVALUATE: crash? → file under crashes/CRASH-NNN-N/. Clean? → 2+ variants.
4. IF CRASH: write report.md (Summary, Classification, Root Cause, Reproduction, Data Flow). Format Data Flow bullets as `step: func (path/to/file.c:NN) — desc` so the post-render pass can inline source snippets. For a 1–3 line fix, save a surgical patch as sibling `patch.diff` whenever it passes `git apply --check`; do NOT write a `## Patch` section in `report.md` — `bin/enrich-report` is the single writer of that section. Reserve `## Fix Direction` prose (no `patch.diff`) for ABI/API-impacting changes where a surgical diff isn't possible. The report must also carry the standard bare-label fields `Boundary:` / `Caller controls:` / `Trusted caller actions:` / `Caller contract:` / `Trigger source:` / `Strategy:` (see `.agents/references/session-rules.md`). `Strategy: S<N>` records which of S1..S8 (or REF) produced this report — the cluster tables and ROI surface use it to attribute bugs to the strategy that found them.
```

**Techniques:** allocator shaping, GC/CC timing, object replacement, multi-trigger, `ASAN_OPTIONS=quarantine_size_mb=1`. Full templates: `.agents/references/reproducer-templates.md`.

---

## CRASH QUALITY

**Good crash (PROMOTE):** a plausibly reachable crash with memory-safety impact
(for example heap-buffer-overflow, heap-use-after-free, container-overflow,
stack-buffer-overflow, alloc-dealloc-mismatch, or a non-null SEGV whose report
demonstrates memory-safety impact) or an explicit security-boundary violation.
On browser targets, "reachable" means web/content-reachable; on CLI/library
targets, it means reachable through the documented input boundary
(file/bytes/API).

**Auto-quarantined by harness:** null deref (`0x0+` SEGV, "null-deref"), OOM,
ABRT without sanitizer error, MOZ_CRASH/RustMozCrash/panic, timeout-only,
plain stack-overflow. Filing these wastes work — the harness moves them to
`crashes-rejected/`.

**Also promote under FINDINGS, not crashes/:** any non-crashing security issue —
same-origin, cross-origin, sandbox, privilege-boundary, auth, injection, info
disclosure, crypto, race, logic flaw — with or without a reproducer.

Before filing: grep `<RESULTS_DIR>/crashes-rejected/INDEX.md` for your crash site.

**Bundle layout (post-triage, automatic):** after a crash dir passes triage, the harness runs `bin/export-repro` to convert it into a maintainer-facing bundle. Root files become `REPORT.md`, `reproduce.sh`, `input.<ext>`, `harness.c` (if applicable), and `sanitizer.txt` — one command (`./reproduce.sh /path/to/src`) reproduces against a clean upstream checkout. Audit-side originals (your `report.md`, `reproducer.sh`, H-prefixed scratch artifacts) move into `<crash>/.audit/` for provenance.

---

## FINDINGS (findings/FIND-*)

For ANY concrete security issue in the target, regardless of whether you can produce a sanitizer reproducer or a runnable testcase. Memory safety, logic flaws, authentication or authorization bypass, injection, information disclosure, cryptographic weakness, race conditions, sandbox or privilege boundary violations all belong here. A sanitizer reproducer is NOT a precondition.

Required:

- A report file at the FIND root — `report.md` or `description.md` (markdown). `report.html` is generated automatically by the harness; you do not need to write it. Other artifacts (testcase, sanitizer output, `affected-files.txt`) are welcome but optional.
- The report must name a concrete location (file:function:line, endpoint, config key, etc.), state the security issue class, and give a rationale a reviewer can act on (impact, caller control, what is wrong).
- Include the standard bare-label fields the crash gate expects, including `Strategy: S<N>` (S1..S8 or REF) so FINDING-CLUSTERS attributes the finding to the strategy that produced it.

**Do NOT create FINDs for:** vague suspicions with no nameable location, "code looks suspicious" without saying why, provably unreachable code, OR pure correctness / data-integrity / robustness / spec-deviation bugs that don't cross a security boundary. "Empty input decodes to wrong bytes", "roundtrip drops whitespace", "format differs from spec" are upstream quality bugs, not security findings — log them in your state file and move on, don't file under `findings/`. The harness gate moves rejected FINDs to `findings-rejected/`; saving the cycles by not filing them in the first place is faster.

---

## STATE JOURNAL

See `.agents/references/state-template.md`. Key rules:
- Each hypothesis fills ALL columns: File:Function:Line, Input Shape, Guard Gap, Expected Diagnostic
- NEUTRAL vocabulary. "Issue in File:Function:Line" not defect class names
- Valid statuses: PENDING, INVESTIGATING, NEEDS_TESTCASE, ENV-BLOCKED, DISCARDED, CRASH-XXX, FIND-XXX
- Max 3 NEEDS_TESTCASE, 3 ENV-BLOCKED at any time
- Update after EVERY hypothesis closure, not at session end
- Keep live state compact: max 8 active rows, max 15 recent terminal rows, max 30 Working Context rows. Move long history into reports or crash/finding dirs, not the live state file.

---

## TOOL DISCIPLINE

- **Search:** `rg -l` first, then read 2-3 files. Scope with `--glob` or narrow directory. No output directory scanning.
- **Bash:** chain with `&&`, pipe `hg log` through `| head -N`.
- **Timeouts:** do not call the GNU `timeout`/`gtimeout` CLI. Source `lib/timeout.sh` and use `audit_timeout_run` or `audit_timeout_kill`.
- **Portability:** use `lib/platform.sh` helpers for `stat`, in-place `sed`, SHA1, LLVM tool discovery, and OS checks. Do not add macOS-only or GNU-only command forms directly to `bin/*` or `lib/*`.
- **VCS:** Use `git -C <target_root>` or `hg -R <target_root>` instead of changing directories. See `.agents/references/vcs-commands.md`.
- **Never orphan runnable testcases.** Write + run the sanitizer in the same turn. For C/C++ harnesses, the runnable testcase is the compiled sanitizer executable plus its saved output; do not leave piles of unrun source/build artifacts in scratch.
- **Honor `PRIOR SESSION SEED`.** If the prompt lists a file with a line range you already covered, do NOT re-read that same range — work from memory, or request a different range (Claude: `offset`/`limit`; codex/shell: a different `sed -n 'A,Bp'` window). Testcases in the seed are already on disk; reuse paths instead of regenerating.

## AUTONOMY

You are autonomous. No human in the loop. Checkpoint when context degrades.
