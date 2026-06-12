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
- **Severity**: High (CVSS-BTE 4.0: 8.1 High; CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:H/VI:N/VA:L/SC:N/SI:N/SA:N/E:P/CR:M/IR:M/AR:M; primitive=heap READ; surface=library)
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

# ── (g2) Placeholder upstream URL/rev → no dead "View at" link ───────
# An un-seeded target.toml leaves the URL as FILL_ME and a local-only
# checkout records the rev as "norev". Building a link from either yields
# a dead `FILL_ME/blob/norev/...`, so enrichment must emit the snippet
# WITHOUT any link rather than a broken one.
CDP="$RESULTS_DIR/crashes/CRASH-001-P"
mkdir -p "$CDP"
cat > "$CDP/report.md" <<EOF
# CRASH-001-P: placeholder upstream

Summary:
A bug in parse_header with no pinned upstream.

Data Flow:
- step: parse_header (lib/parser.c:9) — reads buf[len-1] without guard
EOF
python3 "$ENRICH" --quiet --source-root "$TARGET_SRC" \
                  --upstream-url "FILL_ME" --pinned-rev "norev" \
                  "$CDP/report.md" \
  || fail "enrich-report failed with placeholder upstream URL/rev"
assert_file_contains "$CDP/report.md" 'buf\[len - 1\]' \
  "snippet body still rendered when upstream is a placeholder"
assert_file_not_contains "$CDP/report.md" "View at" \
  "no 'View at' link emitted for placeholder upstream"
assert_file_not_contains "$CDP/report.md" "blob/norev" \
  "no dead FILL_ME/blob/norev link emitted"

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

# ── (i) Fence-aware H1 insertion ────────────────────────────────────
# A `# ...` line inside a fenced reproducer block (a shell/diff comment) is
# NOT a Markdown H1. _insert_after_h1 must skip it, or an unclosed reproducer
# fence swallows the TL;DR / badge / cluster-siblings block — it renders as
# escaped code instead of the hero card. Regression: FIND-REJECTED-0106 had
# its only `# ` line be `# -> "reader: malloc failure not reported"` inside a
# fence, so enrichment injected the tldr block inside that fence.
if python3 - "$SCRIPT_ROOT" <<'PY'
import sys
sys.path.insert(0, sys.argv[1] + "/lib")
import report_enrich as m

# (1) Only `#` line is a shell comment inside a fence -> treat as no H1,
#     insert the block at the very top (above the fence), never inside it.
no_h1 = ("## Fields\n\n| a | b |\n\n## Reproducer\n\n```\nclang foo.c\n"
         "# -> \"reader: malloc failure not reported\"\n```\n\n## Impact\n\nx\n")
out = m._insert_after_h1(no_h1, m._wrap_block("tldr", "**TLDR**"))
assert out.index("enrich:tldr") < out.index("```"), "tldr leaked inside the fence"
assert out.lstrip().startswith("<!-- enrich:tldr -->"), "tldr not hoisted to top"

# (2) A real H1 above a fence: block lands right after the real H1, and the
#     `# not a heading` comment inside the fence is ignored.
real = "# Real Title\n\nintro\n\n## Repro\n\n```\n# not a heading\n```\n"
out2 = m._insert_after_h1(real, m._wrap_block("tldr", "**TLDR**"))
li = out2.splitlines()
assert li.index("# Real Title") < next(i for i, l in enumerate(li) if "enrich:tldr" in l) < li.index("## Repro"), \
    "tldr not placed directly under the real H1"

# (3) Fence bookkeeping: the comment line is flagged as fenced; no real H1.
assert m._first_h1_outside_fence(no_h1) is None, "shell comment wrongly seen as H1"
PY
then
  pass "fence-aware H1 insertion: enrichment never lands inside a code fence"
else
  fail "fence-aware H1 insertion" "block landed inside a fence or under a fenced comment"
fi

# The CVSS band "None" (scored 0.0, e.g. internal-surface code) gets a badge
# like every other generated level — it is a real level, not a missing one.
if python3 - "$SCRIPT_ROOT" <<'PY'
import sys
sys.path.insert(0, sys.argv[1] + "/lib")
import report_enrich as m

badge = m._build_severity_badge(
    "- **Severity**: None (CVSS-BTE 4.0: 0.0 None; primitive=x)")
assert badge == "⚪ **Severity: None**", f"unexpected badge: {badge!r}"
PY
then
  pass "severity badge: scored-0.0 band None gets a neutral badge"
else
  fail "severity badge: scored-0.0 band None" "no badge built for level None"
fi

# _source_url returns None for placeholder upstream/rev (no dead links) and a
# real blob URL otherwise; _truncate_anchor never leaves a dangling backtick.
if python3 - "$SCRIPT_ROOT" <<'PY'
import sys
from pathlib import Path
sys.path.insert(0, sys.argv[1] + "/lib")
import report_enrich as m

def _ctx(url, rev):
    return m.EnrichContext(report_path=Path("r.md"), report_dir=Path("."),
                           upstream_url=url, pinned_rev=rev)

real = _ctx("https://github.com/acme/widgets", "abcdef1234567890")
assert m._source_url(real, "lib/parser.c", 9) == \
    "https://github.com/acme/widgets/blob/abcdef1234567890/lib/parser.c#L9", \
    "real url+rev must produce a blob link"

# HEAD is a usable ref (documented exception), so it still produces a link.
head = _ctx("https://github.com/acme/widgets", "HEAD")
assert m._source_url(head, "lib/parser.c", 9) == \
    "https://github.com/acme/widgets/blob/HEAD/lib/parser.c#L9", \
    "HEAD is usable and must still produce a blob link"

for url, rev in (("FILL_ME", "abcdef12"), ("https://x/y", "norev"),
                 ("FILL_ME", "norev"), ("", "abcdef12"), ("https://x/y", "")):
    assert m._source_url(_ctx(url, rev), "lib/parser.c", 9) is None, \
        f"placeholder ({url!r},{rev!r}) must yield no link"

short = "guard: f (a.c:1) — small note"
assert m._truncate_anchor(short) == short, "short anchor unchanged"
long_open = "guard: f (a.c:1) — rejects values larger than the file length, " \
            "but does not compare against `sizeof" + "x" * 80
trunc = m._truncate_anchor(long_open)
assert trunc.endswith("…"), "truncated anchor ends with ellipsis"
assert trunc.count("`") % 2 == 0, f"dangling backtick in: {trunc!r}"
PY
then
  pass "source links: placeholders drop the link; anchors keep backticks balanced"
else
  fail "source links / anchor truncation" "placeholder link emitted or backtick left dangling"
fi

summary
