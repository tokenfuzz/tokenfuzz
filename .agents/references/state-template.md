# AUDIT_STATE.md Template

Use this template when creating a new AUDIT_STATE file (cold start).

**VOCABULARY RULE:** Use NEUTRAL language in ALL state file entries. Describe issues by
LOCATION (file:function:line) not by defect class name. Write "issue in Parser::Read"
not detailed defect descriptions. The Expected Diagnostic column uses ONLY these short
labels: lifetime / bounds / type / size / uninit / state. Never elaborate beyond that.

```markdown
# Audit State Journal
Mode: [browser|shell]
## Primary Subsystem: unassigned (replace with subsystem path on first claim, e.g. dom or js)
## Auditing: [repo] at commit [hash] ([date])
## Last Updated: [timestamp]
## Entry Point Coverage
| Subsystem | Entry Points Found | Examined | Remaining | Notes |
|-----------|-------------------|----------|-----------|-------|
Track: parsers, serializers, fuzz targets, untrusted-input handlers, FFI/API boundaries, IPC/RPC handlers.
## Current Hypothesis Queue
| # | Hypothesis | File:Function:Line | Input Shape | Guard Gap | Expected Diagnostic | Strategy | Status |
|---|-----------|-------------------|-------------|-----------|---------------------|----------|--------|
Each hypothesis MUST fill ALL columns. "Input Shape" = what specific input (file, API call, network data, CLI arg) reaches this path.
"Guard Gap" = the validation that is absent or skippable. "Expected Diagnostic" = one of: lifetime / bounds / type / size / uninit / state.
Write hypotheses as "issue in File:Function:Line" — do NOT use defect class names or advisory vocabulary.
Vague hypotheses (empty Input Shape or Guard Gap) = DEMOTE to LOW priority immediately.
Valid statuses: PENDING, INVESTIGATING, NEEDS_TESTCASE, NEEDS_DEEPER_PROBE, ENV-BLOCKED, DISCARDED, CRASH-XXX (pending triage), FIND-XXX (curated confirmed).
Do NOT use "CONFIRMED" without a testcase on disk. Max 3 in NEEDS_TESTCASE at any time.
Keep the live queue compact: max 8 active rows and max 15 recent terminal rows. Move long history into reports or archived artifacts.
**NEEDS_DEEPER_PROBE**: Reach confirmed by hits.sh HIT AND guard gap proven by hg blame / prior-art, but no crash yet after Axes A/B/C/D exhausted in current scope. CARRY across sessions — do NOT discard. Working Context row must include SINK_PRIMITIVE, DATA_FLOW, GUARD_GAP (with blame cite), PRIOR_ART, AXIS_COVERAGE, and NEXT_STEPS fields. Max 5 at any time; if you hit 5, pick the highest-confidence one and spend a full session on Axis D (process-context variance) or a privileged harness.
**ENV-BLOCKED**: Code-confirmed issue, reproduction blocked by environment (IPC harness, hardware, timing).
Requires: complete data flow trace + constraint satisfiability + documentation of what's needed to unblock.
Max 3 ENV-BLOCKED at any time. If you hit 3, STOP discovery and fix the environment.
**Evidence rule for ENV-BLOCKED / tool-failure claims (MANDATORY):**
Before marking any hypothesis ENV-BLOCKED on a tool/build complaint, you MUST:
1. Quote the literal stderr+stdout of the failing command in the state file (copy the error line verbatim, not a paraphrase).
2. Verify every filesystem path you reference with `test -e <path>; echo $?` BEFORE citing it. Never invent diagnostic paths — macOS Firefox coverage uses `build-asan-cov${AUDIT_BUILD_SUFFIX:-}/dist/Nightly.app/Contents/MacOS/XUL`; Linux Firefox coverage uses `build-asan-cov${AUDIT_BUILD_SUFFIX:-}/dist/bin/libxul.so` (the suffix is set by `bin/audit-container-shell` per image; empty outside a container). Probing ghost paths to "confirm" a failure is a banned failure mode.
3. Re-run the failing command at least twice, spaced apart, before declaring the environment broken — transient tool failures (fs pressure, SIGPIPE+pipefail, temp truncation) cause most false blockers.
4. If `bin/hits` dies with "XUL lacks sancov" or "libxul.so lacks sancov", independently verify the platform section table and paste the raw output: macOS uses `otool -l $COV_XUL | grep 'sectname __sancov_guards'`; Linux uses `readelf -WS $COV_XUL | grep __sancov_guards`. Only if that ALSO shows no match is an `ff-bsan coverage` rebuild actually needed.
## Research Directions (vague ideas — sharpen before investigating)
Broad areas worth exploring. No quality gate — these are just leads. Max 10.
Before investigating, you MUST sharpen a research direction into a specific hypothesis with all columns filled.
- [area] — [why it's interesting] — [what to look for]
## Verified Findings (FIND-XXX entries only — keep testcase or harness output if you have them, but ASan crash output is NOT required for a FIND)
## Completed Investigations
## Dead Ends (don't repeat)
## Areas Not Yet Examined
## Strategies Applied Per Area
(Track which strategies you've tried in each area. Use strategy letters from the reference if available, or free-form labels.)
| Area | Strategies Tried | Findings | Notes |
|------|-----------------|----------|-------|
## Crash Reproduction Attempts
| ID (CRASH/FIND) | Testcase | Crash Type | Rate | Status | Notes |
|-----------------|----------|------------|------|--------|-------|
## Strategy Effectiveness (update every 10 investigations)
| Strategy | Findings Produced | Dead Ends | Best Subsystems | Notes |
|----------|------------------|-----------|-----------------|-------|
Use this to pick strategies for new subsystems: apply historically effective strategy FIRST, then rotate.
## Working Context (survives compression — keep under 30 lines)
Update after EVERY file read during active investigation. Do NOT re-read files summarized here after compression.
| File:Line | Snippet | Why Relevant |
|-----------|---------|-------------|
| e.g. src/parser.c:412 | `len = ReadU32(); memcpy(dst, src, len)` with no upper bound | size field is external-input-controlled; copy length is not clamped against dst capacity |
## Cross-File Traces
- FLOW: [function] (file:line) → [function] (file:line) → [HYPOTHESIS]
```
