#!/usr/bin/env bash
# tests/test_report_enrich.sh — exercise bin/enrich-report + lib/report_enrich
# against synthetic crash/finding fixtures. Verifies:
#   (a) patch.diff is inlined under the canonical "## Patch" section,
#       and any agent-inlined patch body is replaced by the sibling
#       (single-writer rule — only ONE ## Patch section may exist)
#   (b) Data Flow Trace bullets get source snippets injected per file:line
#   (c) ASan-style frames in Expected sanitizer output get annotated stack snippets
#   (d) Severity badge + Reviewer TL;DR card insert under the H1
#   (e) Enrichment is idempotent — re-running replaces, not duplicates
#   (f) Missing source tree degrades gracefully (no crash, no snippets)
#   (g) Upstream URL + pinned rev produce a "View at <rev>" link
#   (h) render-md strips standalone <!-- enrich:NAME --> comment markers

set -o pipefail
source "$(dirname "$0")/helpers.sh"
setup_test_env

ENRICH="$SCRIPT_ROOT/bin/enrich-report"
RENDER="$SCRIPT_ROOT/bin/render-md"
[ -x "$ENRICH" ] || { echo "missing $ENRICH"; exit 1; }
[ -x "$RENDER" ] || { echo "missing $RENDER"; exit 1; }

# ── Fixture: a target tree with one source file we'll reference ──────
TARGET_SRC="$TEST_TMPDIR/src"
mkdir -p "$TARGET_SRC/lib"
cat > "$TARGET_SRC/lib/parser.c" <<'EOF'
#include "parser.h"

int parse_header(const char *buf, size_t len) {
    if (len < 4) {
        return -1;
    }
    /* BUG: read past buf when len == 0 reaches this branch */
    size_t off = buf[len - 1];
    return (int) off;
}

void emit(int v) {
    printf("%d\n", v);
}
EOF

# ── Fixture: a CRASH dir with report.md, patch.diff, sanitizer.txt ──
CD="$RESULTS_DIR/crashes/CRASH-001-1"
mkdir -p "$CD"

cat > "$CD/report.md" <<'EOF'
# CRASH-001-1: parse_header reads past buffer

## Summary
parse_header reads buf[len-1] without enforcing len > 0, producing a 1-byte
heap read past the end of small inputs.

## Classification
- **Severity**: High (auto: I=24/46; R=6/31; ×CF=0.8; primitive=heap-read)
- **Type**: Bounds Issue
- **Location**: lib/parser.c:9
- **Confidence**: High

## Trigger Surface
Surface: library
Boundary: caller-supplied byte buffer to parse_header
Caller controls: buf pointer and len
Trusted caller actions: call parse_header(buf, len) with len matching buf size
Caller contract: obeyed
Trigger source: bytes

## Reproduction
- Reproducer: testcase.c
- Command: ./reproduce.sh
- Result: ASan reports heap-buffer-overflow on read of 1 byte

## Expected sanitizer output

```
==12345==ERROR: AddressSanitizer: heap-buffer-overflow on address 0xdeadbeef
READ of size 1 at 0xdeadbeef thread T0
    #0 0x100000000 in parse_header lib/parser.c:9
    #1 0x100000100 in emit lib/parser.c:14
```

## Data Flow Trace
- entry: `caller` (lib/parser.c:3) — passes buf and len
- step: `parse_header` (lib/parser.c:4) — checks len < 4 only
- affected: `parse_header` (lib/parser.c:9) — reads buf[len-1]

## Patch
Agent-inlined narrative that the single-writer rule must strip and
replace with the sibling diff. If this text survives enrichment, the
strip-and-replace is broken.
EOF

cat > "$CD/patch.diff" <<'EOF'
diff --git a/lib/parser.c b/lib/parser.c
--- a/lib/parser.c
+++ b/lib/parser.c
@@ -1,5 +1,5 @@
 int parse_header(const char *buf, size_t len) {
-    if (len < 4) {
+    if (len == 0 || len < 4) {
         return -1;
     }
EOF

cat > "$CD/sanitizer.txt" <<'EOF'
==12345==ERROR: AddressSanitizer: heap-buffer-overflow
    #0 0x100000000 in parse_header lib/parser.c:9
    #1 0x100000100 in emit lib/parser.c:14
EOF

# ── (a) patch.diff inlined under the canonical ## Patch section ─────
python3 "$ENRICH" --quiet --source-root "$TARGET_SRC" \
                  --upstream-url "https://github.com/acme/widgets" \
                  --pinned-rev "abcdef1234567890" \
                  "$CD/report.md" \
  || fail "enrich-report exited non-zero on baseline fixture"

assert_file_contains "$CD/report.md" "enrich:patch-diff" "patch-diff marker present"
assert_file_contains "$CD/report.md" "len == 0 \|\| len < 4" "patch.diff body inlined under ## Patch"
assert_file_contains "$CD/report.md" "\*\*Captured patch\*\*" "patch caption rendered"
# Single-writer rule: the agent-inlined narrative under ## Patch must
# be stripped; the sibling diff is the only content under ## Patch.
if grep -q "Agent-inlined narrative" "$CD/report.md"; then
  fail "agent-inlined patch body was not stripped by single-writer rule"
else
  pass "agent-inlined patch body stripped before sibling diff inserted"
fi
PATCH_HEADINGS=$(grep -c "^## Patch\b" "$CD/report.md")
assert_eq "1" "$PATCH_HEADINGS" "exactly one ## Patch heading exists after enrichment"

# ── (b) Data Flow snippets injected ─────────────────────────────────
assert_file_contains "$CD/report.md" "enrich:data-flow-snippets" "data-flow-snippets marker present"
assert_file_contains "$CD/report.md" 'buf\[len - 1\]' "source snippet text from lib/parser.c"
assert_file_contains "$CD/report.md" "▶" "snippet target-line marker present"

# ── (c) Annotated ASan stack frames ─────────────────────────────────
assert_file_contains "$CD/report.md" "enrich:asan-snippets" "asan-snippets marker present"
assert_file_contains "$CD/report.md" "parse_header" "asan frame func referenced"

# ── (d) Severity badge + TL;DR card ─────────────────────────────────
assert_file_contains "$CD/report.md" "enrich:severity-badge" "severity badge marker present"
assert_file_contains "$CD/report.md" "Severity: High" "severity badge text rendered"
assert_file_contains "$CD/report.md" "enrich:tldr" "TL;DR marker present"
assert_file_contains "$CD/report.md" "Reviewer TL;DR" "TL;DR heading rendered"

# ── (g) Source link with pinned rev ─────────────────────────────────
assert_file_contains "$CD/report.md" "abcdef123456" "pinned rev appears in source link"
assert_file_contains "$CD/report.md" "blob/abcdef1234567890/lib/parser.c" "blob URL constructed"

# ── (e) Idempotency — re-run replaces, doesn't duplicate ────────────
BEFORE_HASH=$(shasum -a 1 "$CD/report.md" | awk '{print $1}')
python3 "$ENRICH" --quiet --source-root "$TARGET_SRC" \
                  --upstream-url "https://github.com/acme/widgets" \
                  --pinned-rev "abcdef1234567890" \
                  "$CD/report.md" \
  || fail "enrich-report exited non-zero on re-run"
AFTER_HASH=$(shasum -a 1 "$CD/report.md" | awk '{print $1}')
assert_eq "$BEFORE_HASH" "$AFTER_HASH" "enrichment is byte-stable across re-runs"

COUNT=$(grep -c "enrich:patch-diff" "$CD/report.md")
assert_eq "2" "$COUNT" "exactly one open + one close marker for patch-diff (= 2 matches)"

# ── (h) render-md strips the <!-- enrich:NAME --> markers ──────────
python3 "$RENDER" "$CD/report.md" --html "$CD/report.html" --title "CRASH-001-1" --no-pad \
  || fail "render-md failed on enriched report"
if grep -q "enrich:tldr" "$CD/report.html"; then
  fail "render-md did not strip enrichment marker comments from HTML output"
else
  pass "render-md strips enrichment marker comments from HTML"
fi
# Hero-duplicated enrichment blocks (tldr / severity-badge / cluster-siblings)
# are suppressed in HTML when the triage hero card emits — markdown source
# keeps them, but the card carries the same info richer. Verify (a) the
# duplicate text is gone, (b) the hero card carries the signal instead.
if grep -q "Reviewer TL;DR" "$CD/report.html"; then
  fail "TL;DR enrichment block suppressed in HTML" "Reviewer TL;DR still rendered"
else
  pass "TL;DR enrichment block suppressed in HTML (hero card replaces it)"
fi
assert_file_contains "$CD/report.html" 'class="triage-card sev-High"' \
  "hero card carries severity signal in HTML"
assert_file_contains "$CD/report.html" 'class="sev sev-High">High' \
  "hero card emits severity pill instead of duplicate badge prose"

# ── Colon-label heading style is recognised ─────────────────────────
# Some agents use `Data Flow:` rather than `## Data Flow`; render-md
# treats both as H2, so enrichment must too.
CDL="$RESULTS_DIR/crashes/CRASH-001-L"
mkdir -p "$CDL"
cat > "$CDL/report.md" <<EOF
# CRASH-001-L: colon-label format

Summary:
A bug in parse_header with colon-label headings.

Classification:
- **Severity**: High
- Type: Bounds

Data Flow:
- step: parse_header (lib/parser.c:9) — reads buf[len-1] without guard
EOF
python3 "$ENRICH" --quiet --source-root "$TARGET_SRC" "$CDL/report.md" \
  || fail "enrich-report failed on colon-label format"
assert_file_contains "$CDL/report.md" "enrich:data-flow-snippets" \
  "data-flow-snippets injected for colon-label Data Flow"
assert_file_contains "$CDL/report.md" 'buf\[len - 1\]' \
  "snippet body from parser.c reached colon-label report"

# ── patch.diff in .audit/ is still found by enrichment ────────────
# Older bundles that pre-date the _is_bundle_filename allowlist update
# carry patch.diff under .audit/. Enrichment must still inline it.
CDA="$RESULTS_DIR/crashes/CRASH-001-A"
mkdir -p "$CDA/.audit"
cat > "$CDA/REPORT.md" <<'EOF'
# CRASH-001-A: legacy bundle layout

## Summary
Crash in legacy bundle whose patch landed in .audit/.

## Classification
- **Severity**: Medium

EOF
cat > "$CDA/.audit/patch.diff" <<'EOF'
diff --git a/x.c b/x.c
--- a/x.c
+++ b/x.c
@@ -1 +1 @@
-old
+new
EOF
python3 "$ENRICH" --quiet "$CDA/REPORT.md" \
  || fail "enrich-report failed on legacy .audit/ layout"
assert_file_contains "$CDA/REPORT.md" "enrich:patch-diff" \
  "patch.diff in .audit/ inlined via fallback search"
assert_file_contains "$CDA/REPORT.md" "\+new$" \
  "patch body from .audit/patch.diff appears in REPORT.md"
assert_file_contains "$CDA/REPORT.md" "^## Patch" \
  ".audit/ fallback also creates the canonical ## Patch heading"

# ── Patch placement: Reproduce → Fix → Patch → Reachability ───────────
# The reading order puts the patch right after the reproducer and before
# the reference-material scoring sections (Reachability / Severity
# rationale). `## Fix Direction` is the advisory-no-patch mechanism and
# is NOT moved (only a prose `## Fix`/`Suggested fix` is lifted to sit
# above `## Patch`). So with a Fix Direction present, Patch must land
# AFTER Reproduce and BEFORE Reachability.
CDP="$RESULTS_DIR/crashes/CRASH-001-P"
mkdir -p "$CDP"
cat > "$CDP/report.md" <<'EOF'
# CRASH-001-P: placement check

## Summary
A bug.

## Root Cause
The cause is X.

## Fix Direction
Validate the input before the call.

## Reproduce
- Run: ./repro.sh

## Reachability — external callers
None observed.

## Severity rationale
Worst case is an info-leak.
EOF
cat > "$CDP/patch.diff" <<'EOF'
diff --git a/x.c b/x.c
--- a/x.c
+++ b/x.c
@@ -1 +1 @@
-old
+new
EOF
python3 "$ENRICH" --quiet "$CDP/report.md" \
  || fail "enrich-report failed on placement fixture"
# Patch must land AFTER Reproduce and BEFORE Reachability.
patch_line=$(grep -n "^## Patch$" "$CDP/report.md" | cut -d: -f1)
repro_line=$(grep -n "^## Reproduce$" "$CDP/report.md" | cut -d: -f1)
reach_line=$(grep -n "^## Reachability" "$CDP/report.md" | cut -d: -f1)
[ -n "$patch_line" ] && [ -n "$repro_line" ] && [ -n "$reach_line" ] \
  && [ "$patch_line" -gt "$repro_line" ] && [ "$patch_line" -lt "$reach_line" ]
assert_eq 0 $? \
  "## Patch lands between Reproduce (line $repro_line) and Reachability (line $reach_line); got $patch_line"

# ── Prose `## Fix` is lifted to sit Reproduce → Fix → Patch ────────────
# A model-authored prose `## Fix` section (distinct from `## Fix
# Direction`) is moved out of its original position to directly above
# the `## Patch` diff, after the Reproduce section.
CDF="$RESULTS_DIR/crashes/CRASH-001-F"
mkdir -p "$CDF"
cat > "$CDF/report.md" <<'EOF'
# CRASH-001-F: fix reordering

## Summary
A bug.

## Fix
Add a bounds check before the memcpy.

## Reproduce
- Run: ./repro.sh

## Reachability — external callers
None observed.
EOF
cp "$CDP/patch.diff" "$CDF/patch.diff"
python3 "$ENRICH" --quiet "$CDF/report.md" \
  || fail "enrich-report failed on fix-reorder fixture"
repro_f=$(grep -n "^## Reproduce$" "$CDF/report.md" | cut -d: -f1)
fix_f=$(grep -n "^## Fix$" "$CDF/report.md" | cut -d: -f1)
patch_f=$(grep -n "^## Patch$" "$CDF/report.md" | cut -d: -f1)
reach_f=$(grep -n "^## Reachability" "$CDF/report.md" | cut -d: -f1)
[ -n "$repro_f" ] && [ -n "$fix_f" ] && [ -n "$patch_f" ] && [ -n "$reach_f" ] \
  && [ "$repro_f" -lt "$fix_f" ] && [ "$fix_f" -lt "$patch_f" ] && [ "$patch_f" -lt "$reach_f" ]
assert_eq 0 $? \
  "order Reproduce($repro_f) < Fix($fix_f) < Patch($patch_f) < Reachability($reach_f)"
# Exactly one ## Fix (moved, not duplicated).
assert_eq 1 "$(grep -c "^## Fix$" "$CDF/report.md")" "## Fix not duplicated after move"
# Idempotent: a second enrich must not change the file.
H1=$(shasum -a 1 "$CDF/report.md" | awk '{print $1}')
python3 "$ENRICH" --quiet "$CDF/report.md" >/dev/null 2>&1
H2=$(shasum -a 1 "$CDF/report.md" | awk '{print $1}')
assert_eq "$H1" "$H2" "fix-reorder enrichment is byte-stable across re-runs"

# Sparse report: only Classification + Reachability + Severity rationale
# (a real shape observed in live benchmark output). Patch must still
# land BEFORE Reachability — not at end-of-report.
CDP2="$RESULTS_DIR/crashes/CRASH-001-Q"
mkdir -p "$CDP2"
cat > "$CDP2/report.md" <<'EOF'
# CRASH-001-Q: sparse report shape

## Classification
- **Severity**: Medium

## Reachability — external callers
None observed.

## Severity rationale
Local crash only.
EOF
cp "$CDP/patch.diff" "$CDP2/patch.diff"
python3 "$ENRICH" --quiet "$CDP2/report.md" \
  || fail "enrich-report failed on sparse-report fixture"
cls_line=$(grep -n "^## Classification$" "$CDP2/report.md" | cut -d: -f1)
patch_line=$(grep -n "^## Patch$" "$CDP2/report.md" | cut -d: -f1)
reach_line=$(grep -n "^## Reachability" "$CDP2/report.md" | cut -d: -f1)
[ -n "$cls_line" ] && [ -n "$patch_line" ] && [ -n "$reach_line" ] \
  && [ "$patch_line" -gt "$cls_line" ] && [ "$patch_line" -lt "$reach_line" ]
assert_eq 0 $? \
  "## Patch lands between Classification ($cls_line) and Reachability ($reach_line); got $patch_line"

# ── (f) Missing source tree degrades gracefully ─────────────────────
CD2="$RESULTS_DIR/crashes/CRASH-002-1"
mkdir -p "$CD2"
cat > "$CD2/report.md" <<'EOF'
# CRASH-002-1: another bug

## Summary
Another bug.

## Classification
- **Severity**: Low

## Data Flow Trace
- step: `nonexistent` (no/such/file.c:42) — should not crash
EOF

python3 "$ENRICH" --quiet --source-root "$TEST_TMPDIR/does-not-exist" \
                  "$CD2/report.md" \
  || fail "enrich-report should tolerate missing source root"

# No snippet markers when source can't be resolved.
if grep -q "enrich:data-flow-snippets" "$CD2/report.md"; then
  fail "data-flow-snippets block should not be inserted when source missing"
else
  pass "data-flow-snippets cleanly skipped when source root absent"
fi
# Severity badge + TL;DR still land (don't need source tree).
assert_file_contains "$CD2/report.md" "Severity: Low" "badge still inserted without source tree"

summary
