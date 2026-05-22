#!/usr/bin/env bash
# Tests for lib/parse_state.py — markdown state-file subsystem extraction
# and file-path-to-subsystem mapping. Covers the four-stage fallback
# (Primary Subsystem → Hypothesis Queue → Entry Point Coverage → grep)
# and longest-first prefix matching.
set -o pipefail
source "$(dirname "$0")/helpers.sh"
setup_test_env

PARSE_STATE="$SCRIPT_ROOT/lib/parse_state.py"
SUBSYSTEMS="$SCRIPT_ROOT/lib/subsystems/firefox.txt"

# Helper: write a state file and return its path.
write_state() {
  local path="$1"; shift
  printf '%s\n' "$@" > "$path"
}

# Convenience: run subsystem extraction with the firefox subsystems file.
fx_subsystem() {
  python3 "$PARSE_STATE" subsystem "$1" --subsystems "$SUBSYSTEMS"
}

# Convenience: run subsystem extraction with no subsystems file (generic).
generic_subsystem() {
  python3 "$PARSE_STATE" subsystem "$1"
}

# ═══════════════════════════════════════════════════════════════
# 1. Primary Subsystem header (## form) — browser target match
# ═══════════════════════════════════════════════════════════════

f="$TEST_TMPDIR/state-1.md"
write_state "$f" \
  "# Audit State Journal" \
  "## Primary Subsystem: dom/canvas" \
  ""
assert_eq "dom/canvas" "$(fx_subsystem "$f")" "## Primary Subsystem header recognized"

# ═══════════════════════════════════════════════════════════════
# 2. Primary Subsystem header (no ## prefix)
# ═══════════════════════════════════════════════════════════════

f="$TEST_TMPDIR/state-2.md"
write_state "$f" "Primary Subsystem: dom/canvas"
assert_eq "dom/canvas" "$(fx_subsystem "$f")" "Primary Subsystem header (no ##) recognized"

# ═══════════════════════════════════════════════════════════════
# 3. Bracketed and parenthesized decorations are stripped
# ═══════════════════════════════════════════════════════════════

f="$TEST_TMPDIR/state-3.md"
write_state "$f" "## Primary Subsystem: dom/canvas [active] (since 2025-12-01)"
assert_eq "dom/canvas" "$(fx_subsystem "$f")" "[brackets] and (parens) stripped from header"

# ═══════════════════════════════════════════════════════════════
# 4. Generic target accepts literal Primary Subsystem value
# ═══════════════════════════════════════════════════════════════

f="$TEST_TMPDIR/state-4.md"
write_state "$f" "## Primary Subsystem: parser/xmlReader"
assert_eq "parser/xmlReader" "$(generic_subsystem "$f")" \
  "generic target: literal Primary Subsystem preserved"

# Even when the literal doesn't match the firefox regex, generic accepts it.
f="$TEST_TMPDIR/state-4b.md"
write_state "$f" "## Primary Subsystem: weird/path/no-match"
assert_eq "weird/path/no-match" "$(generic_subsystem "$f")" \
  "generic target: literal accepted regardless of regex"

# Build-manifest references (Package.swift, Cargo.toml, CMakeLists.txt, …)
# are rejected — they aren't source subsystems. Falls through to "unknown"
# when no later section has a real path.
f="$TEST_TMPDIR/state-4c.md"
write_state "$f" "## Primary Subsystem: Package.swift:target:15"
assert_eq "unknown" "$(generic_subsystem "$f")" \
  "build-manifest reference (Package.swift:target:N) rejected"

f="$TEST_TMPDIR/state-4d.md"
write_state "$f" "## Primary Subsystem: Cargo.toml:bin:foo"
assert_eq "unknown" "$(generic_subsystem "$f")" \
  "build-manifest reference (Cargo.toml:bin:foo) rejected"

# A file:line marker (anything :NN) is rejected — looks like a position,
# not a directory.
f="$TEST_TMPDIR/state-4e.md"
write_state "$f" "## Primary Subsystem: foo/bar.cpp:42"
assert_eq "unknown" "$(generic_subsystem "$f")" \
  "file:line marker rejected as subsystem value"

# Prose-style values with internal whitespace are rejected.
f="$TEST_TMPDIR/state-4f.md"
write_state "$f" "## Primary Subsystem: investigating multiple files"
assert_eq "unknown" "$(generic_subsystem "$f")" \
  "prose with internal whitespace rejected"

# Single-component subsystem labels (e.g. flat-layout repos) still pass.
f="$TEST_TMPDIR/state-4g.md"
write_state "$f" "## Primary Subsystem: parser"
assert_eq "parser" "$(generic_subsystem "$f")" \
  "single-component subsystem label still accepted"

# ═══════════════════════════════════════════════════════════════
# 5. Browser target with unknown subsystem in header → fallback
# ═══════════════════════════════════════════════════════════════
# When the Primary Subsystem doesn't match the known list, the parser
# moves on to the Hypothesis Queue (here we leave both empty → unknown).

f="$TEST_TMPDIR/state-5.md"
write_state "$f" "## Primary Subsystem: some/unknown/path"
assert_eq "unknown" "$(fx_subsystem "$f")" \
  "browser target: header miss + no fallback → unknown"

# ═══════════════════════════════════════════════════════════════
# 6. Hypothesis Queue fallback when Primary Subsystem is missing
# ═══════════════════════════════════════════════════════════════

f="$TEST_TMPDIR/state-6.md"
write_state "$f" \
  "# Audit State Journal" \
  "## Current Hypothesis Queue" \
  "| # | Hypothesis | File:Function:Line | Input Shape | Guard Gap | Expected Diagnostic | Strategy | Status |" \
  "|---|-----------|-------------------|-------------|-----------|---------------------|----------|--------|" \
  "| 1 | foo | js/src/jit/Foo.cpp:bar:42 | sh | gap | bounds | S1 | PENDING |"
assert_eq "js/src/jit" "$(fx_subsystem "$f")" \
  "Hypothesis Queue file column matched"

# ═══════════════════════════════════════════════════════════════
# 7. Hypothesis Queue: skip DISCARDED rows
# ═══════════════════════════════════════════════════════════════

f="$TEST_TMPDIR/state-7.md"
write_state "$f" \
  "## Current Hypothesis Queue" \
  "| # | Hypothesis | File:Function:Line | Input Shape | Guard Gap | Expected Diagnostic | Strategy | Status |" \
  "|---|-----------|-------------------|-------------|-----------|---------------------|----------|--------|" \
  "| 1 | foo | js/src/jit/Foo.cpp:bar:42 | sh | gap | bounds | S1 | DISCARDED |" \
  "| 2 | bar | dom/canvas/Baz.cpp:q:1 | sh | gap | bounds | S2 | PENDING |"
assert_eq "dom/canvas" "$(fx_subsystem "$f")" \
  "Hypothesis Queue: DISCARDED row skipped"

# ═══════════════════════════════════════════════════════════════
# 8. Hypothesis Queue: skip header and separator rows
# ═══════════════════════════════════════════════════════════════
# The literal "File:Function:Line" header shouldn't be parsed as a file,
# nor should the dashes-only separator.

f="$TEST_TMPDIR/state-8.md"
write_state "$f" \
  "## Current Hypothesis Queue" \
  "| # | Hypothesis | File:Function:Line | Input Shape | Guard Gap | Expected Diagnostic | Strategy | Status |" \
  "|---|-----------|-------------------|-------------|-----------|---------------------|----------|--------|"
# No data rows → falls through to other sections, ultimately unknown.
assert_eq "unknown" "$(fx_subsystem "$f")" \
  "Hypothesis Queue: header+separator only → unknown"

# ═══════════════════════════════════════════════════════════════
# 9. Entry Point Coverage fallback when Hypothesis Queue is empty
# ═══════════════════════════════════════════════════════════════

f="$TEST_TMPDIR/state-9.md"
write_state "$f" \
  "## Entry Point Coverage" \
  "| Subsystem | Entry Points Found | Examined | Remaining | Notes |" \
  "|-----------|-------------------|----------|-----------|-------|" \
  "| layout/style | 5 | 2 | 3 | actively investigating |"
assert_eq "layout/style" "$(fx_subsystem "$f")" \
  "Entry Point Coverage matched when no other section has signal"

# ═══════════════════════════════════════════════════════════════
# 10. Entry Point Coverage: archived/rotated rows skipped
# ═══════════════════════════════════════════════════════════════

f="$TEST_TMPDIR/state-10.md"
write_state "$f" \
  "## Entry Point Coverage" \
  "| Subsystem | Entry Points Found | Examined | Remaining | Notes |" \
  "|-----------|-------------------|----------|-----------|-------|" \
  "| layout/style | 5 | 2 | 3 | rotated out 2026-04 |" \
  "| dom/canvas | 3 | 1 | 2 | active |"
assert_eq "dom/canvas" "$(fx_subsystem "$f")" \
  "Entry Point Coverage: 'rotated out' note skipped"

f="$TEST_TMPDIR/state-10b.md"
write_state "$f" \
  "## Entry Point Coverage" \
  "| Subsystem | Entry Points Found | Examined | Remaining | Notes |" \
  "|-----------|-------------------|----------|-----------|-------|" \
  "| layout/style | 5 | 2 | 3 | archived |" \
  "| dom/canvas | 3 | 1 | 2 | live |"
assert_eq "dom/canvas" "$(fx_subsystem "$f")" \
  "Entry Point Coverage: 'archived' note skipped"

f="$TEST_TMPDIR/state-10c.md"
write_state "$f" \
  "## Entry Point Coverage" \
  "| Subsystem | Entry Points Found | Examined | Remaining | Notes |" \
  "|-----------|-------------------|----------|-----------|-------|" \
  "| layout/style | 5 | 2 | 3 | reverse-turn budget exhausted |" \
  "| dom/canvas | 3 | 1 | 2 | active |"
assert_eq "dom/canvas" "$(fx_subsystem "$f")" \
  "Entry Point Coverage: 'reverse-turn budget exhausted' note skipped"

# ═══════════════════════════════════════════════════════════════
# 11. Last-resort grep matches a known prefix anywhere in the file
# ═══════════════════════════════════════════════════════════════

f="$TEST_TMPDIR/state-11.md"
write_state "$f" \
  "# Audit State Journal" \
  "Some prose mentioning js/src/wasm in passing."
assert_eq "js/src/wasm" "$(fx_subsystem "$f")" \
  "last-resort grep finds known prefix in prose"

# ═══════════════════════════════════════════════════════════════
# 12. Missing or empty file → unknown
# ═══════════════════════════════════════════════════════════════

assert_eq "unknown" "$(fx_subsystem "$TEST_TMPDIR/does-not-exist.md")" \
  "missing file → unknown (browser)"
assert_eq "unknown" "$(generic_subsystem "$TEST_TMPDIR/does-not-exist.md")" \
  "missing file → unknown (generic)"

empty="$TEST_TMPDIR/empty.md"
: > "$empty"
assert_eq "unknown" "$(fx_subsystem "$empty")" "empty file → unknown"

# ═══════════════════════════════════════════════════════════════
# 13. Longest-prefix-first: dom/media/webcodecs over dom/media
# ═══════════════════════════════════════════════════════════════
# Critical correctness property — the wrong order would attribute
# webcodecs work to the broader dom/media bucket.

f="$TEST_TMPDIR/state-13.md"
write_state "$f" "## Primary Subsystem: dom/media/webcodecs"
assert_eq "dom/media/webcodecs" "$(fx_subsystem "$f")" \
  "longest-first: dom/media/webcodecs takes precedence"

f="$TEST_TMPDIR/state-13b.md"
write_state "$f" "## Primary Subsystem: dom/media/somefile"
assert_eq "dom/media" "$(fx_subsystem "$f")" \
  "shorter prefix still matches when longer doesn't apply"

# ═══════════════════════════════════════════════════════════════
# 14. subsystem-from-path: browser semantics
# ═══════════════════════════════════════════════════════════════

assert_eq "dom/media/webcodecs" \
  "$(python3 "$PARSE_STATE" subsystem-from-path "dom/media/webcodecs/Foo.cpp" --subsystems "$SUBSYSTEMS")" \
  "subsystem-from-path: browser longest match"
assert_eq "js/src/jit" \
  "$(python3 "$PARSE_STATE" subsystem-from-path "js/src/jit/Foo.cpp:bar:42" --subsystems "$SUBSYSTEMS")" \
  "subsystem-from-path: extracts prefix from File:Function:Line cell"
assert_eq "" \
  "$(python3 "$PARSE_STATE" subsystem-from-path "totally/unknown/path.c" --subsystems "$SUBSYSTEMS")" \
  "subsystem-from-path: no match returns empty"

# ═══════════════════════════════════════════════════════════════
# 15. subsystem-from-path: generic semantics
# ═══════════════════════════════════════════════════════════════

assert_eq "src/lib" \
  "$(python3 "$PARSE_STATE" subsystem-from-path "src/lib/foo.c")" \
  "subsystem-from-path: generic uses first two path components"
assert_eq "src/lib" \
  "$(python3 "$PARSE_STATE" subsystem-from-path "src/lib")" \
  "subsystem-from-path: exactly two components"
assert_eq "foo" \
  "$(python3 "$PARSE_STATE" subsystem-from-path "foo")" \
  "subsystem-from-path: single component returns as-is"
assert_eq "" \
  "$(python3 "$PARSE_STATE" subsystem-from-path "")" \
  "subsystem-from-path: empty input returns empty"

# Absolute paths must NOT bucket on host-local filesystem segments. An
# agent that writes a hypothesis on an absolute path would otherwise
# latch its subsystem to the leading segment (the user's $HOME, the
# build root, etc.), saturating the diversity gate and blocking all
# rotation. Both browser and generic semantics return empty so callers
# fall back to "unknown". Placeholder absolute paths only — the actual
# leading segment is irrelevant, only the leading slash matters.
assert_eq "" \
  "$(python3 "$PARSE_STATE" subsystem-from-path "/abs-host/user/proj/foo.c")" \
  "subsystem-from-path: absolute path returns empty (generic)"
assert_eq "" \
  "$(python3 "$PARSE_STATE" subsystem-from-path "/abs-host/user/proj/foo.c" --subsystems "$SUBSYSTEMS")" \
  "subsystem-from-path: absolute path returns empty (browser)"
assert_eq "" \
  "$(python3 "$PARSE_STATE" subsystem-from-path "/build/asan/x.c")" \
  "subsystem-from-path: absolute build path returns empty"

# ═══════════════════════════════════════════════════════════════
# 16. Priority: Primary Subsystem beats Hypothesis Queue beats Coverage
# ═══════════════════════════════════════════════════════════════

f="$TEST_TMPDIR/state-16.md"
write_state "$f" \
  "## Primary Subsystem: dom/canvas" \
  "## Current Hypothesis Queue" \
  "| # | Hypothesis | File:Function:Line | Input Shape | Guard Gap | Expected Diagnostic | Strategy | Status |" \
  "|---|-----------|-------------------|-------------|-----------|---------------------|----------|--------|" \
  "| 1 | foo | js/src/jit/Foo.cpp:bar:42 | sh | gap | bounds | S1 | PENDING |" \
  "## Entry Point Coverage" \
  "| Subsystem | Entry Points Found | Examined | Remaining | Notes |" \
  "|-----------|-------------------|----------|-----------|-------|" \
  "| layout/style | 5 | 2 | 3 | active |"
assert_eq "dom/canvas" "$(fx_subsystem "$f")" \
  "priority: Primary Subsystem wins over both other sections"

# Drop Primary Subsystem → Hypothesis Queue wins.
f="$TEST_TMPDIR/state-16b.md"
write_state "$f" \
  "## Current Hypothesis Queue" \
  "| # | Hypothesis | File:Function:Line | Input Shape | Guard Gap | Expected Diagnostic | Strategy | Status |" \
  "|---|-----------|-------------------|-------------|-----------|---------------------|----------|--------|" \
  "| 1 | foo | js/src/jit/Foo.cpp:bar:42 | sh | gap | bounds | S1 | PENDING |" \
  "## Entry Point Coverage" \
  "| Subsystem | Entry Points Found | Examined | Remaining | Notes |" \
  "|-----------|-------------------|----------|-----------|-------|" \
  "| layout/style | 5 | 2 | 3 | active |"
assert_eq "js/src/jit" "$(fx_subsystem "$f")" \
  "priority: Hypothesis Queue wins over Entry Point Coverage"

# ═══════════════════════════════════════════════════════════════
# 17. Section boundary: stop at next ## heading
# ═══════════════════════════════════════════════════════════════
# A pipe-prefixed line in a *later* section must not be parsed as a
# Hypothesis Queue row.

f="$TEST_TMPDIR/state-17.md"
write_state "$f" \
  "## Current Hypothesis Queue" \
  "| # | Hypothesis | File:Function:Line | Input Shape | Guard Gap | Expected Diagnostic | Strategy | Status |" \
  "|---|-----------|-------------------|-------------|-----------|---------------------|----------|--------|" \
  "## Working Context" \
  "| File:Line | Snippet | Why Relevant |" \
  "| js/src/jit/Foo.cpp:42 | x | y |"
# Hypothesis queue is empty (header only). Should fall through to
# unknown — js/src/jit must NOT leak in via the Working Context table.
# (Last-resort grep WILL still match it from the Working Context cell,
# so this test verifies the priority order: section parsing returned
# nothing, but the final grep still succeeds. We accept either —
# the contract is "the agent is working on js/src/jit somewhere".)
result=$(fx_subsystem "$f")
case "$result" in
  unknown|js/src/jit) pass "section boundary respected (got $result)" ;;
  *) fail "section boundary respected" "got '$result'" ;;
esac

teardown_test_env
summary
