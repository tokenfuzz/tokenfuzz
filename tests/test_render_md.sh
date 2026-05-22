#!/usr/bin/env bash
# tests/test_render_md.sh — bin/render-md table padding + HTML emission.
#
# Coverage:
#   1. Cells in a markdown table get padded to the widest cell per column.
#   2. Numeric columns marked right-aligned (`---:`) get right-padding.
#   3. Re-running render-md on padded output is idempotent (no churn — the
#      audit loop runs maintain_indexes every iteration).
#   4. --check exits non-zero when a rewrite would change the file.
#   5. Non-table content (headings, paragraphs, links) passes through
#      unchanged.
#   6. --html-sibling emits a self-contained HTML doc.
#   7. Severity cells render as styled .sev-* pills in HTML.
#   8. Surface cells render as .chip-* tokens in HTML.
#   9. .md links inside the source markdown are rewritten to .html in
#      HTML output (so clicks work in Chrome) but the source .md keeps
#      the .md paths for parsers / GitHub renderers.
set -o pipefail
source "$(dirname "$0")/helpers.sh"
setup_test_env

RENDER="$SCRIPT_ROOT/bin/render-md"
[ -x "$RENDER" ] || { echo "missing $RENDER"; exit 1; }

# ── Fixture: small markdown doc with one table ──
fix="$TEST_TMPDIR/sample.md"
cat > "$fix" <<'EOF'
# Sample

_Auto-generated_

| ID | Score | Note |
|:---|------:|:-----|
| [thing](other.md) | 7 | a short one |
| [really-long-id-here](deep/nested/path/REPORT.md) | 12345 | longer note here |
EOF

# 1. Padding
python3 "$RENDER" "$fix" 2>&1 >/dev/null
grep -qE '\| ID +\| ' "$fix" && pass "header padded" || \
  fail "header padded" "got: $(grep '^| ID' "$fix")"

# 2. Right-align padding (Score column has `---:` separator).
grep -qE '\| +7 \|' "$fix" && pass "right-align padding present" || \
  fail "right-align padding present" "got: $(grep '7' "$fix")"

# 3. Idempotence — second run is a no-op.
cp "$fix" "$TEST_TMPDIR/before.md"
python3 "$RENDER" "$fix" >/dev/null 2>&1
diff_out=$(diff "$TEST_TMPDIR/before.md" "$fix" || true)
assert_eq "" "$diff_out" "render-md is idempotent"

# 4. --check exits 0 when already padded.
python3 "$RENDER" "$fix" --check >/dev/null 2>&1
assert_eq 0 $? "--check on padded file exits 0"

# 4b. --check exits non-zero when padding would change the file.
ragged="$TEST_TMPDIR/ragged.md"
cat > "$ragged" <<'EOF'
| A | B |
|:--|:--|
| really long cell | x |
EOF
python3 "$RENDER" "$ragged" --check >/dev/null 2>&1
rc=$?
[ "$rc" -ne 0 ] && pass "--check on unpadded file exits non-zero" \
  || fail "--check on unpadded file exits non-zero" "rc=$rc"
# After --check the file must be unchanged (assertion-only mode).
grep -q 'really long cell ' "$ragged" || \
  fail "--check does not rewrite the file" "ragged.md was modified"
pass "--check does not rewrite the file"

# 5. Non-table content passes through (heading, italic, links inside tables).
grep -q '^# Sample$' "$fix" && pass "heading preserved" \
  || fail "heading preserved" "got: $(head -1 "$fix")"
grep -q '_Auto-generated_' "$fix" && pass "italic line preserved" \
  || fail "italic line preserved" "italic line missing"
# Markdown link syntax in cells must be preserved verbatim — downstream
# parsers (and harness tooling) read these.
grep -q '\[really-long-id-here\](deep/nested/path/REPORT.md)' "$fix" \
  && pass "markdown link in cell preserved" \
  || fail "markdown link in cell preserved" "link mangled"

# ── HTML emission ────────────────────────────────────────────
# 6. --html-sibling produces a self-contained HTML doc.
sev_fix="$TEST_TMPDIR/sev.md"
cat > "$sev_fix" <<'EOF'
# Sample

| Severity      | Cluster        | Surface     | Note |
|:--------------|:---------------|:------------|:-----|
| Critical (68) | `CL-abc12345`  | library-api — pcre2_match | [link](other.md) |
| High          | `CL-def67890`  | cli         | x |
| Medium (33)   | `CL-feedface`  | maint-tool  | y |
| Low           | `CL-cafebabe`  | unknown     | z |
EOF
python3 "$RENDER" "$sev_fix" --html-sibling >/dev/null 2>&1
sev_html="$TEST_TMPDIR/sev.html"
assert_file_exists "$sev_html" "HTML sibling created"
assert_file_contains "$sev_html" '<!DOCTYPE html>' "HTML doctype present"
assert_file_contains "$sev_html" '<table' "HTML table tag present"
assert_file_contains "$sev_html" 'class="table-wrap"' "HTML tables are wrapped in table containers"

# 7. Severity pills are emitted with the right class.
assert_file_contains "$sev_html" 'class="sev sev-Critical">Critical' "Critical pill present"
assert_file_contains "$sev_html" 'class="sev-score">68' "Critical score shown"
assert_file_contains "$sev_html" 'class="sev sev-High">High' "High pill present"
assert_file_contains "$sev_html" 'class="sev sev-Medium">Medium' "Medium pill present"
assert_file_contains "$sev_html" 'class="sev sev-Low">Low' "Low pill present"

# 8. Surface chips are emitted with the right class.
assert_file_contains "$sev_html" 'class="chip chip-library">library-api' "library-api chip present"
assert_file_contains "$sev_html" 'class="chip chip-cli">cli' "cli chip present"
assert_file_contains "$sev_html" 'class="chip chip-maint">maint-tool' "maint-tool chip present"

# 9. .md → .html link rewrite in HTML output, .md preserved in source.
assert_file_contains "$sev_html" 'href="other\.html"' "link rewritten to .html in HTML output"
assert_file_contains "$sev_fix"  '\(other\.md\)' "source markdown still uses .md"

# 10. Sticky header CSS lands in the doc.
assert_file_contains "$sev_html" 'position: sticky' "sticky header CSS present"
assert_file_contains "$sev_html" 'white-space: nowrap;' \
  "table headers do not wrap"

# 10b. Inline code in table cells gets a content-based wrap class so the
#      same rule covers crash clusters, finding clusters, benchmark, and
#      Fields tables without a per-column allowlist. Regression:
#      CRASH-CLUSTERS.html could get a page-wide horizontal scrollbar
#      because `Root signature` rendered as one nowrap code span and the
#      table used max-content as its minimum width.
cluster_fix="$TEST_TMPDIR/cluster.md"
cat > "$cluster_fix" <<'EOF'
# Crash Clusters

| Severity    | Callers | Cluster       | Size | Primitive                 | Strategy | Boundary | Root signature | Members | Status |
|:------------|--------:|:--------------|-----:|:--------------------------|:---------|:---------|:---------------|:--------|:-------|
| Medium (39) |      63 | `CL-f2422e11` |    1 | heap-use-after-free-WRITE | S5       | —        | `node_free node.c:100 -> node_free node.c:120 -> node_free node.c:140` | CRASH-1 | OK |
EOF
python3 "$RENDER" "$cluster_fix" --html-sibling >/dev/null 2>&1
cluster_html="$TEST_TMPDIR/cluster.html"
# Atomic identifier — no whitespace, no `->`: stays nowrap (no .wrap class).
assert_file_contains "$cluster_html" '<code>CL-f2422e11</code>' \
  "atomic cluster id renders without wrap class"
# Stack signature — whitespace + `->`: opts into wrapping.
assert_file_contains "$cluster_html" '<code class="wrap">node_free node.c:100 -&gt; node_free node.c:120' \
  "stack signature code is tagged with wrap class"
# Table-wide CSS: atomic code is nowrap by default, wrap-class opts out.
assert_file_contains "$cluster_html" 'td code, th code' \
  "table code has a shared structural rule"
assert_file_contains "$cluster_html" 'td code.wrap, th code.wrap' \
  "wrap class opts into anywhere-breaking"
assert_file_contains "$cluster_html" 'overflow-wrap: anywhere;' \
  "long signature code can wrap inside table cells"
assert_file_contains "$cluster_html" 'min-width: 100%;' \
  "tables size to the page instead of max-content"
assert_file_not_contains "$cluster_html" 'min-width: max-content;' \
  "tables do not force max-content horizontal scroll"
# No leftover per-column nowrap enumeration.
assert_file_not_contains "$cluster_html" 'th\.col-primitive, td\.col-primitive' \
  "per-column nowrap enumeration is gone (structural rule replaces it)"

# 11. Permalink anchor on h2.
cat >> "$sev_fix" <<'EOF'

## Some Heading

paragraph
EOF
python3 "$RENDER" "$sev_fix" --html-sibling >/dev/null 2>&1
assert_file_contains "$sev_html" 'id="some-heading"' "h2 has slug id"
assert_file_contains "$sev_html" 'class="anchor"' "h2 has permalink anchor"

# 12. Bullet lists render as <ul><li>, not as a run-on paragraph with
#     literal hyphens (REPORT.md "Top callers" / "Vendored copies").
list_fix="$TEST_TMPDIR/list.md"
cat > "$list_fix" <<'EOF'
# Lists

Top callers:
- `github.com/foo/bar` :: `src/x.c`
- `github.com/baz/qux` :: `src/y.c`

Steps:
1. apply delta
2. decode bytes
3. dispatch to interpreter
EOF
python3 "$RENDER" "$list_fix" --html-sibling >/dev/null 2>&1
list_html="$TEST_TMPDIR/list.html"
assert_file_contains "$list_html" '<ul><li><code>github.com/foo/bar' "bullet list rendered as <ul>"
assert_file_contains "$list_html" '<ol><li>apply delta' "numbered list rendered as <ol>"
# A run-on paragraph would contain "- `github.com" verbatim — make sure it doesn't.
grep -q '<p>[^<]*- <code>github\.com' "$list_html" \
  && fail "bullets not collapsed into paragraph" "found run-on '- <code>...' inside <p>" \
  || pass "bullets not collapsed into paragraph"

# 13. The bare-label block REPORT.md keeps for regex parsers
#     (Surface:/Trigger source:/.../- **Severity**: ...) is suppressed
#     in HTML — the same data is already visible in the Fields table
#     above, so duplicating it as a wall of run-on text just looks broken.
bare_fix="$TEST_TMPDIR/bare.md"
cat > "$bare_fix" <<'EOF'
# Sample

| Field    | Value                |
|:---------|:---------------------|
| Surface  | library-api          |
| Severity | Medium (33)          |

Surface: library-api
Trigger source: bytes
Caller contract: obeyed
Boundary: serialized PCRE2 code bytes
Caller controls: bytes
Parameter control: direct
- **Severity**: Medium (auto: primitive=heap READ; score=33)

## Summary

Real prose lives here.
EOF
python3 "$RENDER" "$bare_fix" --html-sibling >/dev/null 2>&1
bare_html="$TEST_TMPDIR/bare.html"
# The markdown source must still carry the bare-label lines (parsers
# read them) — only the HTML render strips them.
grep -q '^Surface: library-api$' "$bare_fix" \
  && pass "bare-label block preserved in markdown source" \
  || fail "bare-label block preserved in markdown source" "lines stripped from .md"
grep -q '^- \*\*Severity\*\*: Medium' "$bare_fix" \
  && pass "Severity rationale preserved in markdown source" \
  || fail "Severity rationale preserved in markdown source" "line stripped from .md"
# HTML: the duplicate paragraph must NOT appear.
grep -q 'Trigger source: bytes' "$bare_html" \
  && fail "bare-label paragraph suppressed in HTML" "still rendered" \
  || pass "bare-label paragraph suppressed in HTML"
grep -q 'Parameter control: direct' "$bare_html" \
  && fail "Parameter control bare-label suppressed in HTML" "still rendered" \
  || pass "Parameter control bare-label suppressed in HTML"
grep -q 'auto: primitive=heap READ' "$bare_html" \
  && fail "Severity rationale paragraph suppressed in HTML" "still rendered" \
  || pass "Severity rationale paragraph suppressed in HTML"
# Real prose still renders.
assert_file_contains "$bare_html" 'Real prose lives here' "real prose still renders"

mixed_fix="$TEST_TMPDIR/bare-mixed.md"
cat > "$mixed_fix" <<'EOF'
# Sample

| Field             | Value          |
|:------------------|:---------------|
| Caller controls   | DNS query name |
| Parameter control | mapped         |

Caller controls:
DNS query name bytes shape the request.
Parameter control: mapped
EOF
python3 "$RENDER" "$mixed_fix" --html-sibling >/dev/null 2>&1
mixed_html="$TEST_TMPDIR/bare-mixed.html"
assert_file_contains "$mixed_html" 'DNS query name bytes shape the request' \
  "mixed bare-label paragraph keeps prose"
grep -q 'Parameter control: mapped' "$mixed_html" \
  && fail "mixed bare-label line suppressed in HTML" "still rendered" \
  || pass "mixed bare-label line suppressed in HTML"

# 14a. Triage hero card — pulls Severity, Primitive, Surface, top
#      ASan frame, repro rate, callers, cluster, summary into one
#      block so a security triager sees the verdict before scrolling.
hero_fix="$TEST_TMPDIR/hero.md"
cat > "$hero_fix" <<'EOF'
# CRASH-001-1

## Fields

| Field             | Value                       |
|:------------------|:----------------------------|
| Primitive         | heap-buffer-overflow        |
| Severity          | High (62)                   |
| Surface           | library-api — public entry  |
| Cluster           | CL-deadbeef (3 reports)     |
| Reproduction rate | 5/5                         |

## Summary

A bug in the foo subsystem causes an out-of-bounds read.

## Expected sanitizer output

```
==<pid>==ERROR: AddressSanitizer: heap-buffer-overflow
    #0 <addr> in strlen+0x400 (libclang_rt.asan_osx_dynamic.dylib:arm64e+0x3ec80)
    #1 <addr> in foo_parse foo.c:42
    #2 <addr> in foo_dispatch dispatch.c:84
    #3 <addr> in foo_entry entry.c:126
    #4 <addr> in main main.c:9
SUMMARY: AddressSanitizer: heap-buffer-overflow foo.c:42 in foo_parse
```

## Reachability — external callers

**External callers (genuine, after ignore + vendor filter): 87**

## Severity rationale

Math goes here.
EOF
python3 "$RENDER" "$hero_fix" --html-sibling >/dev/null 2>&1
hero_html="$TEST_TMPDIR/hero.html"
assert_file_contains "$hero_html" 'class="triage-card sev-High"' "hero card emits severity-tinted border"
assert_file_contains "$hero_html" 'class="primitive cat-bounds">heap-buffer-overflow' "hero shows primitive with category color"
assert_file_contains "$hero_html" 'class="frame-func"><code>foo_parse' "hero shows top ASan frame func"
assert_file_contains "$hero_html" 'foo.c:42' "hero shows top ASan frame loc"
assert_file_contains "$hero_html" '<code>foo_dispatch</code>' "hero shows second dedup frame"
assert_file_contains "$hero_html" '<code>foo_entry</code>' "hero shows third dedup frame"
grep -q 'frame-func"><code>strlen' "$hero_html" \
  && fail "hero skips ClusterFuzz-ignored strlen frame" "hero selected strlen" \
  || pass "hero skips ClusterFuzz-ignored strlen frame"
assert_file_contains "$hero_html" '<strong>Repro</strong> 5/5' "hero shows repro rate"
assert_file_contains "$hero_html" '<strong>87</strong> external callers' "hero shows callers count"
assert_file_contains "$hero_html" 'CL-deadbeef' "hero shows cluster"
assert_file_contains "$hero_html" 'class="triage-summary">A bug in the foo subsystem' "hero shows summary"

# 14b. Collapsible sections — Severity rationale renders as <details>
#      so the math doesn't dominate the visual flow but stays one click
#      away. Expected sanitizer output is the canonical sanitizer view
#      now (with full stack), so it must NOT collapse.
assert_file_contains "$hero_html" '<details class="collapsible" id="severity-rationale">' "Severity rationale renders as <details>"
grep -q '<details[^>]*id="expected-sanitizer-output"' "$hero_html" \
  && fail "Expected sanitizer output not collapsible" "Expected sanitizer output was wrapped in <details>" \
  || pass "Expected sanitizer output not collapsible"

# 14b2. Hero top-frame extraction is heading-agnostic — finds the #0
#       frame whether it lives in the new consolidated `## Expected
#       sanitizer output` block (current shape) or the legacy `## ASan
#       top frames` block (older bundles still on disk).
legacy_fix="$TEST_TMPDIR/legacy_frames.md"
cat > "$legacy_fix" <<'EOF'
# CRASH-LEGACY-1

## Fields

| Field     | Value                |
|:----------|:---------------------|
| Primitive | heap-buffer-overflow |
| Severity  | High (62)            |

## ASan top frames

```
    #0 <addr> in legacy_func legacy.c:11
```
EOF
python3 "$RENDER" "$legacy_fix" --html-sibling >/dev/null 2>&1
legacy_html="$TEST_TMPDIR/legacy_frames.html"
assert_file_contains "$legacy_html" '<code>legacy_func</code>' "hero finds top frame in legacy ASan top frames heading"
assert_file_contains "$legacy_html" 'legacy.c:11' "hero finds frame loc in legacy heading"

# 14b3. Label-style report sections from audit-authored reports render as
#       proper sections, and multi-line key:value blocks render as a compact
#       definition list instead of one run-on paragraph.
labels_fix="$TEST_TMPDIR/labels.md"
cat > "$labels_fix" <<'EOF'
# CRASH-LABELS-1

## Fields

| Field     | Value                 |
|:----------|:----------------------|
| Primitive | heap-use-after-free   |
| Severity  | —                     |

- **Severity**: Medium (auto: primitive=use-after-free READ; score=34)

Summary:
Duplicating a channel reaches a lifetime diagnostic.

Classification:
Category: lifetime
ASan: heap-use-after-free
Crash site: src/lib/event/ares_event_thread.c:ares_event_thread_wake:65

Root Cause:
The duplicate keeps callback data from the original channel.
EOF
python3 "$RENDER" "$labels_fix" --html-sibling >/dev/null 2>&1
labels_html="$TEST_TMPDIR/labels.html"
assert_file_contains "$labels_html" 'class="triage-card sev-Medium"' "hero falls back to auto-Severity bullet"
assert_file_contains "$labels_html" '<h2 id="summary">Summary' "label-style Summary becomes section"
assert_file_contains "$labels_html" '<h2 id="classification">Classification' "label-style Classification becomes section"
assert_file_contains "$labels_html" '<dl class="report-definition">' "classification key:value lines become definition list"
grep -q '<p>Classification: Category:' "$labels_html" \
  && fail "label blocks not rendered as run-on paragraph" "classification was still a paragraph" \
  || pass "label blocks not rendered as run-on paragraph"

# 14c. Cluster placeholder before bin/cluster-crashes runs renders
#      as a muted dash, not the literal "(set by bin/cluster-crashes)".
ph_fix="$TEST_TMPDIR/placeholder.md"
cat > "$ph_fix" <<'EOF'
# Sample

| Field   | Value                          |
|:--------|:-------------------------------|
| Cluster | (set by bin/cluster-crashes)   |
EOF
python3 "$RENDER" "$ph_fix" --html-sibling >/dev/null 2>&1
ph_html="$TEST_TMPDIR/placeholder.html"
grep -q 'set by bin/cluster-crashes' "$ph_html" \
  && fail "Cluster placeholder hidden in HTML" "literal placeholder still visible" \
  || pass "Cluster placeholder hidden in HTML"
assert_file_contains "$ph_html" 'color: var.--muted.">—' "placeholder rendered as muted dash"

# 14. The class attribute on note-style italics must be quoted with
#     real double quotes — not the literal backslash-quote that Python
#     raw-string escaping used to leak into output.
note_fix="$TEST_TMPDIR/note.md"
cat > "$note_fix" <<'EOF'
# Sample

_Probed at: 2026-05-04T00:00:00Z_
EOF
python3 "$RENDER" "$note_fix" --html-sibling >/dev/null 2>&1
note_html="$TEST_TMPDIR/note.html"
assert_file_contains "$note_html" '<em class="note">Probed at' "note italics use real double quotes"
grep -q 'class=\\"note\\"' "$note_html" \
  && fail "no backslash-quoted class attribute" "raw-string escape leaked into HTML" \
  || pass "no backslash-quoted class attribute"

# 15. Link schemes — agent-authored report markdown renders into local
#     HTML that maintainers open, so javascript:/data: URLs must not become
#     clickable hrefs (they would execute in the file:// origin). Safe
#     schemes (http/https/mailto) and relative paths / #anchors stay.
scheme_fix="$TEST_TMPDIR/schemes.md"
cat > "$scheme_fix" <<'EOF'
# Sample

A [bad link](javascript:danger) and a [data link](data:text/html;base64,abcd)
and a [safe link](https://example.com/page) and a [relative link](report.md)
and an [anchor](#summary).
EOF
python3 "$RENDER" "$scheme_fix" --html-sibling >/dev/null 2>&1
scheme_html="$TEST_TMPDIR/schemes.html"
grep -qi 'href="javascript:' "$scheme_html" \
  && fail "javascript: link not emitted as href" "dangerous scheme reached href" \
  || pass "javascript: link not emitted as href"
grep -qi 'href="data:' "$scheme_html" \
  && fail "data: link not emitted as href" "dangerous scheme reached href" \
  || pass "data: link not emitted as href"
# The blocked link still shows its text — only the href is dropped.
assert_file_contains "$scheme_html" 'bad link' "blocked link keeps its text"
# Safe schemes and relative paths stay clickable.
assert_file_contains "$scheme_html" 'href="https://example\.com/page"' "https link kept clickable"
assert_file_contains "$scheme_html" 'href="report\.html"' "relative .md link kept and rewritten"
assert_file_contains "$scheme_html" 'href="#summary"' "anchor link kept clickable"

# Blockquote lines fold into <blockquote> — not a paragraph with a literal
# leading '>' (the benchmark ledger footnotes are written as `>` quotes).
bq_fix="$TEST_TMPDIR/bq.md"
cat > "$bq_fix" <<'EOF'
# Quote

> A footnote about the table above.
EOF
python3 "$RENDER" "$bq_fix" --html-sibling >/dev/null 2>&1
bq_html="$TEST_TMPDIR/bq.html"
assert_file_contains "$bq_html" '<blockquote>A footnote about the table' \
  "blockquote line renders as a <blockquote> element"
if grep -qE '<p>&gt;' "$bq_html"; then
  fail "blockquote not left as a literal '>'" "found a literal > paragraph"
else
  pass "blockquote not left as a literal '>'"
fi

# Every HTML page is styled with the Material 3 stylesheet — no flag,
# no opt-in. The M3 primary colour token is the structural marker.
assert_file_contains "$bq_html" 'Material 3 Expressive' \
  "HTML output is styled with the Material 3 stylesheet"
assert_file_contains "$bq_html" '\-\-m3-primary' \
  "Material 3 stylesheet defines the M3 primary colour token"

teardown_test_env
summary
