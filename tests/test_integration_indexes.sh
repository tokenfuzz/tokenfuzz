#!/usr/bin/env bash
# Integration tests — maintain_indexes produces cluster summaries and the rejected index
set -o pipefail
source "$(dirname "$0")/helpers.sh"
setup_test_env
source "$SCRIPT_ROOT/lib/triage.sh"

# ═══════════════════════════════════════════════════════════════
# Setup: create a mix of crash dirs in various states
# ═══════════════════════════════════════════════════════════════

# Active crash (valid)
mkdir -p "$RESULTS_DIR/crashes/CRASH-001-1"
cat > "$RESULTS_DIR/crashes/CRASH-001-1/asan.txt" <<'EOF'
==12345==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x60200000abcd
#0 0x7fff12345678 in strlen+0x40 (libclang_rt.asan_osx_dynamic.dylib:arm64e+0x3ec80)
#1 0x7fff12345688 in image::Decoder::Process() image/Decoder.cpp:42
EOF
cat > "$RESULTS_DIR/crashes/CRASH-001-1/report.md" <<'EOF'
# CRASH-001-1

## Fields

| Field   | Value                        |
|---------|------------------------------|
| Surface | library-api                  |
| Cluster | (set by bin/cluster-crashes) |

Surface: library-api
Trigger source: bytes

## Root Cause
The image decoder does not bound the decoded chunk size before copying.
EOF

# Active crash (incomplete — missing testcase)
mkdir -p "$RESULTS_DIR/crashes/CRASH-002-2"
cat > "$RESULTS_DIR/crashes/CRASH-002-2/asan.txt" <<'EOF'
==12345==ERROR: AddressSanitizer: heap-use-after-free on address 0x60300000dcba
#0 0x7fff12345678 in dom::Element::Destroy()
EOF
echo "report but crash has web content and memory safety evidence" > "$RESULTS_DIR/crashes/CRASH-002-2/report.md"

# Complete maintainer bundle: exact-case REPORT.md plus canonical artifacts.
mkdir -p "$RESULTS_DIR/crashes/CRASH-003-3"
cat > "$RESULTS_DIR/crashes/CRASH-003-3/asan.txt" <<'EOF'
==12345==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x60400000abcd
READ of size 1 at 0x60400000abcd thread T0
#0 0x7fff12345678 in parser_decode parser.c:42
SUMMARY: AddressSanitizer: heap-buffer-overflow parser.c:42 in parser_decode
EOF
cat > "$RESULTS_DIR/crashes/CRASH-003-3/REPORT.md" <<'EOF'
# Parser bounds read

## Fields

| Field   | Value       |
|---------|-------------|
| Surface | library-api |
| Cluster | CL-test     |

Surface: library-api
Trigger source: bytes

## Classification
- **Severity**: Low (auto: score=10)
EOF
printf 'input bytes' > "$RESULTS_DIR/crashes/CRASH-003-3/input.bin"
cat > "$RESULTS_DIR/crashes/CRASH-003-3/reproduce.sh" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF

# Complete UBSan maintainer bundle: the canonical diagnostic filename remains
# asan.txt for parser compatibility, but the content can be any sanitizer.
mkdir -p "$RESULTS_DIR/crashes/CRASH-004-4"
cat > "$RESULTS_DIR/crashes/CRASH-004-4/asan.txt" <<'EOF'
parser.c:77:5: runtime error: index 4 out of bounds for type 'int[4]'
SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior parser.c:77:5
EOF
cat > "$RESULTS_DIR/crashes/CRASH-004-4/REPORT.md" <<'EOF'
# Parser UBSan bounds diagnostic

## Fields

| Field   | Value       |
|---------|-------------|
| Surface | library-api |
| Cluster | CL-ubsan    |

Surface: library-api
Trigger source: bytes
EOF
printf 'int main(void){return 0;}\n' > "$RESULTS_DIR/crashes/CRASH-004-4/input.c"
cat > "$RESULTS_DIR/crashes/CRASH-004-4/reproduce.sh" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF

# Rejected crash
mkdir -p "$RESULTS_DIR/crashes-rejected/CRASH-010-1"
cat > "$RESULTS_DIR/crashes-rejected/CRASH-010-1/asan.txt" <<'EOF'
==12345==ERROR: AddressSanitizer: SEGV on unknown address 0x000000000000
Hint: address points to the zero page
#0 0x7fff12345678 in nsWidget::Init()
EOF
cat > "$RESULTS_DIR/crashes-rejected/CRASH-010-1/.autodiscard" <<'EOF'
# Auto-rejected by triage_crash_dirs
# Reason: null-deref, not a security-relevant memory-safety class
EOF
echo "# CRASH-010-1 rejected" > "$RESULTS_DIR/crashes-rejected/CRASH-010-1/REPORT.md"

# Rejected finding (validator/FIND-quality gate dropped it). The site is read
# from the report's Fields table; the reason from the .llm-find-quality sidecar.
mkdir -p "$RESULTS_DIR/findings-rejected/FIND-090-robustness-only"
cat > "$RESULTS_DIR/findings-rejected/FIND-090-robustness-only/report.md" <<'EOF'
# Unchecked return is robustness only

## Fields

| Field    | Value         |
| :------- | :------------ |
| File     | `app_parse.c` |
| Function | `app_parse`   |
| Line     | 42            |
EOF
cat > "$RESULTS_DIR/findings-rejected/FIND-090-robustness-only/.llm-find-quality.json" <<'EOF'
{"accept":false,"reason":"robustness only; no security boundary crossed","decision":"find_quality"}
EOF

# Active finding (LLM accepted) with a freeform class + severity that
# FINDING-CLUSTERS.md should surface.
mkdir -p "$RESULTS_DIR/findings/FIND-001-decoder-oob"
cat > "$RESULTS_DIR/findings/FIND-001-decoder-oob/description.md" <<'EOF'
# Heap buffer overflow in PNG decoder
Triggered by <img> tag.
EOF
cat > "$RESULTS_DIR/findings/FIND-001-decoder-oob/.llm-find-quality.json" <<'EOF'
{"decision":"find_quality","decision_version":"v3","accept":true,"reason":"concrete bug","class":"memory-safety:bounds","severity":"high","cached_at":"2026-04-24T00:00:00Z"}
EOF

# Vacuous finding — stays in findings/ with a .needs-attention marker.
# The LLM verdict is pre-seeded so we don't depend on an LLM call here.
mkdir -p "$RESULTS_DIR/findings/FIND-020-weak"
cat > "$RESULTS_DIR/findings/FIND-020-weak/description.md" <<'EOF'
# Weak suspicion — needs more info
The handler looks risky.
EOF
cat > "$RESULTS_DIR/findings/FIND-020-weak/.llm-find-quality.json" <<'EOF'
{"decision":"find_quality","decision_version":"v3","accept":false,"reason":"hand-wavy: no nameable location","class":"","severity":"","cached_at":"2026-04-24T00:00:00Z"}
EOF
{
  echo "Marker: needs-attention"
  echo "When: 2026-04-24T00:00:00Z"
  echo "Reason: LLM substance review: hand-wavy: no nameable location"
} > "$RESULTS_DIR/findings/FIND-020-weak/.needs-attention"

# FIND with no report file at all — needs-content marker.
mkdir -p "$RESULTS_DIR/findings/FIND-030-content"
{
  echo "Marker: needs-content"
  echo "When: 2026-04-24T00:00:00Z"
  echo "Reason: no report file (report.md / description.md / report.html) in FIND dir"
} > "$RESULTS_DIR/findings/FIND-030-content/.needs-content"

# FIND with .reviewed override — bypasses the substance gate.
mkdir -p "$RESULTS_DIR/findings/FIND-040-override"
cat > "$RESULTS_DIR/findings/FIND-040-override/description.md" <<'EOF'
# Reviewed manually
Free-form notes that bypass the gate.
EOF
touch "$RESULTS_DIR/findings/FIND-040-override/.reviewed"

# FIND with an unusual freeform class label — index must surface it verbatim
# without normalising or dropping it.
mkdir -p "$RESULTS_DIR/findings/FIND-050-unusual"
cat > "$RESULTS_DIR/findings/FIND-050-unusual/description.md" <<'EOF'
# Algorithmic DoS in regex engine
Crafted pattern in pkg/regex/match.go:Compile:120 produces O(2^n) backtracking.
EOF
cat > "$RESULTS_DIR/findings/FIND-050-unusual/.llm-find-quality.json" <<'EOF'
{"decision":"find_quality","decision_version":"v3","accept":true,"reason":"clear ReDoS","class":"dos:algorithmic-complexity","severity":"medium","cached_at":"2026-04-24T00:00:00Z"}
EOF

# Finding report that begins with cluster metadata and an id-only heading.
# FINDING-CLUSTERS.md should cluster it without treating metadata as content.
mkdir -p "$RESULTS_DIR/findings/FIND-060-cluster-first"
cat > "$RESULTS_DIR/findings/FIND-060-cluster-first/report.md" <<'EOF'
Cluster: FCL-demo (singleton)
Dedup key: [loc] src/demo.c
# FIND-060-cluster-first

Summary: Parser accepts a stale token after reset.
EOF

# ═══════════════════════════════════════════════════════════════
# 1. maintain_indexes generates cluster summaries, not duplicate indexes
# ═══════════════════════════════════════════════════════════════

maintain_indexes 2>/dev/null

assert_file_exists "$RESULTS_DIR/crashes/CRASH-CLUSTERS.md" "crashes/CRASH-CLUSTERS.md created"
assert_file_not_exists "$RESULTS_DIR/crashes/INDEX.md" "crashes/INDEX.md is not generated"
assert_file_not_exists "$RESULTS_DIR/CRASH-CLUSTERS.md" "per-backend root CRASH-CLUSTERS.md is removed"
assert_file_not_exists "$RESULTS_DIR/CLUSTERS.md" "legacy per-backend CLUSTERS.md is removed"
assert_file_contains "$RESULTS_DIR/crashes/CRASH-CLUSTERS.md" "CRASH-001-1" "crash clusters have CRASH-001"
assert_file_contains "$RESULTS_DIR/crashes/CRASH-CLUSTERS.md" "CRASH-002-2" "crash clusters have CRASH-002"
assert_file_contains "$RESULTS_DIR/crashes/CRASH-CLUSTERS.md" "CRASH-003-3" "crash clusters have complete CRASH-003"
assert_file_contains "$RESULTS_DIR/crashes/CRASH-CLUSTERS.md" "CRASH-004-4" "crash clusters have complete UBSan CRASH-004"
assert_file_contains "$RESULTS_DIR/crashes/CRASH-CLUSTERS.md" '\[CRASH-001-1\]\(CRASH-001-1/(REPORT|report)\.md\)' \
  "crash clusters link CRASH-001 to its report"
assert_file_contains "$RESULTS_DIR/crashes/CRASH-CLUSTERS.md" "image::Decoder::Process|dom::Element::Destroy" \
  "crash clusters show top frame signatures"
grep -q 'strlen' "$RESULTS_DIR/crashes/CRASH-CLUSTERS.md" \
  && fail "crash clusters skip ClusterFuzz-ignored strlen frame" "strlen selected as crash site" \
  || pass "crash clusters skip ClusterFuzz-ignored strlen frame"
assert_file_contains "$RESULTS_DIR/crashes/CRASH-CLUSTERS.md" '\| Severity +\|' \
  "crash clusters have table header"
assert_file_contains "$RESULTS_DIR/crashes/CRASH-CLUSTERS.md" '\| Status +\|' \
  "crash clusters have Status column"
assert_file_contains "$RESULTS_DIR/crashes/CRASH-CLUSTERS.md" '^\| :--' \
  "crash clusters have alignment-marked separator"
cluster_id=$(grep -m1 -E '^Cluster: CL-' "$RESULTS_DIR/crashes/CRASH-001-1/report.md" | sed -E 's/^Cluster: (CL-[0-9a-f]+).*/\1/')
[ -n "$cluster_id" ] && pass "maintain_indexes writes Cluster line before report HTML" \
  || fail "maintain_indexes writes Cluster line before report HTML" "no Cluster line in report.md"
assert_file_contains "$RESULTS_DIR/crashes/CRASH-001-1/report.html" "$cluster_id" \
  "maintain_indexes renders report HTML after cluster update"

# ═══════════════════════════════════════════════════════════════
# 2. crashes-rejected/ keeps semantic reports plus INDEX.md compatibility aliases.
# ═══════════════════════════════════════════════════════════════

assert_file_exists "$RESULTS_DIR/crashes-rejected/INDEX.md" "crashes-rejected/INDEX.md created"
assert_file_exists "$RESULTS_DIR/crashes-rejected/REJECTED-CRASHES.md" \
  "crashes-rejected/REJECTED-CRASHES.md created"
assert_file_contains "$RESULTS_DIR/crashes-rejected/INDEX.md" "CRASH-010-1" "rejected index has CRASH-010"
assert_file_contains "$RESULTS_DIR/crashes-rejected/REJECTED-CRASHES.md" "CRASH-010-1" \
  "rejected crashes report has CRASH-010"
assert_file_contains "$RESULTS_DIR/crashes-rejected/INDEX.md" "DO NOT RE-FILE" "rejected index warns against re-filing"
# Unified schema: ID | Site | Reason | Report, with a hyperlinked report.
# (assert_file_contains greps with -E, so table pipes / link brackets escape.)
assert_file_contains "$RESULTS_DIR/crashes-rejected/INDEX.md" '[|] *ID *[|] *Site *[|] *Reason *[|] *Report *[|]' \
  "crashes-rejected index uses the unified column header"
assert_file_contains "$RESULTS_DIR/crashes-rejected/INDEX.md" "null-deref, not a security-relevant" \
  "crashes-rejected index surfaces the triage rejection reason"
assert_file_contains "$RESULTS_DIR/crashes-rejected/INDEX.md" '\[Link\]\(CRASH-010-1/REPORT\.md\)' \
  "crashes-rejected index links the report"

# 2b. findings-rejected/INDEX.md mirrors the crashes-rejected schema.
assert_file_exists "$RESULTS_DIR/findings-rejected/INDEX.md" "findings-rejected/INDEX.md created"
assert_file_exists "$RESULTS_DIR/findings-rejected/REJECTED-FINDINGS.md" \
  "findings-rejected/REJECTED-FINDINGS.md created"
assert_file_contains "$RESULTS_DIR/findings-rejected/INDEX.md" '[|] *ID *[|] *Site *[|] *Reason *[|] *Report *[|]' \
  "findings-rejected index uses the same unified header"
assert_file_contains "$RESULTS_DIR/findings-rejected/REJECTED-FINDINGS.md" '[|] *ID *[|] *Site *[|] *Reason *[|] *Report *[|]' \
  "findings-rejected report uses the same unified header"
assert_file_contains "$RESULTS_DIR/findings-rejected/INDEX.md" "app_parse.c:app_parse:42" \
  "findings-rejected index surfaces the finding site from the Fields table"
assert_file_contains "$RESULTS_DIR/findings-rejected/INDEX.md" "robustness only; no security boundary" \
  "findings-rejected index surfaces the FIND-quality rejection reason"
assert_file_contains "$RESULTS_DIR/findings-rejected/INDEX.md" '\[Link\]\(FIND-090-robustness-only/report\.md\)' \
  "findings-rejected index links the report"

# ═══════════════════════════════════════════════════════════════
# 3. findings/FINDING-CLUSTERS.md is the primary findings table
# ═══════════════════════════════════════════════════════════════

assert_file_exists "$RESULTS_DIR/findings/FINDING-CLUSTERS.md" "findings/FINDING-CLUSTERS.md created"
assert_file_not_exists "$RESULTS_DIR/findings/INDEX.md" "findings/INDEX.md is not generated"
assert_file_not_exists "$RESULTS_DIR/findings/FIND-CLUSTERS.md" "legacy FIND-CLUSTERS.md is removed"
assert_file_contains "$RESULTS_DIR/findings/FINDING-CLUSTERS.md" "FIND-001-decoder-oob" "finding clusters have FIND-001"
assert_file_contains "$RESULTS_DIR/findings/FINDING-CLUSTERS.md" "Class" "finding clusters have Class column header"
assert_file_contains "$RESULTS_DIR/findings/FINDING-CLUSTERS.md" "Severity" "finding clusters have Severity column header"
assert_file_contains "$RESULTS_DIR/findings/FINDING-CLUSTERS.md" "memory-safety" \
  "finding clusters surface accepted FIND class"
assert_file_contains "$RESULTS_DIR/findings/FINDING-CLUSTERS.md" "High" \
  "finding clusters surface accepted FIND severity"
assert_file_contains "$RESULTS_DIR/findings/FINDING-CLUSTERS.md" "FIND-050-unusual" \
  "finding clusters have FIND-050 (unusual class)"
assert_file_contains "$RESULTS_DIR/findings/FINDING-CLUSTERS.md" "dos" \
  "finding clusters surface unusual freeform class top-level"

# ═══════════════════════════════════════════════════════════════
# 4. findings/FINDING-CLUSTERS.md carries review status inline
# ═══════════════════════════════════════════════════════════════

assert_file_contains "$RESULTS_DIR/findings/FINDING-CLUSTERS.md" "FIND-020-weak" "finding clusters list vacuous FIND"
assert_file_contains "$RESULTS_DIR/findings/FINDING-CLUSTERS.md" "NEEDS ATTENTION" \
  "finding clusters flag vacuous FIND as NEEDS ATTENTION"
assert_file_contains "$RESULTS_DIR/findings/FINDING-CLUSTERS.md" "FIND-030-content" \
  "finding clusters list FIND with no content"
assert_file_contains "$RESULTS_DIR/findings/FINDING-CLUSTERS.md" "NEEDS CONTENT" \
  "finding clusters flag no-report FIND as NEEDS CONTENT"
assert_file_contains "$RESULTS_DIR/findings/FINDING-CLUSTERS.md" "FIND-040-override" \
  "finding clusters list .reviewed FIND"
grep -E 'FIND-040-override.*OK \(override\)' "$RESULTS_DIR/findings/FINDING-CLUSTERS.md" >/dev/null \
  && pass "finding clusters mark .reviewed FIND as OK (override)" \
  || fail "finding clusters mark .reviewed FIND as OK (override)" \
       "row missing OK (override) status"

# The accepted findings must not be moved into findings-rejected/ (only the
# deliberately-planted FIND-090 fixture lives there).
[ ! -d "$RESULTS_DIR/findings-rejected/FIND-001-decoder-oob" ] \
  && [ ! -d "$RESULTS_DIR/findings-rejected/FIND-050-unusual" ] \
  && pass "accepted findings not moved to findings-rejected/" \
  || fail "accepted findings not moved to findings-rejected/" "an accepted FIND was rejected"
[ ! -d "$RESULTS_DIR/findings-needs-review" ] \
  && pass "no findings-needs-review/ directory created" \
  || fail "no findings-needs-review/ directory created" "findings-needs-review/ exists"

# ═══════════════════════════════════════════════════════════════
# 5. maintain_indexes renders report and cluster HTML siblings
# ═══════════════════════════════════════════════════════════════
if command -v python3 >/dev/null 2>&1; then
  assert_file_exists "$RESULTS_DIR/findings/FIND-001-decoder-oob/description.html" \
    "findings: description.md to description.html sibling rendered"
  assert_file_exists "$RESULTS_DIR/findings/FINDING-CLUSTERS.html" \
    "findings: FINDING-CLUSTERS.md to FINDING-CLUSTERS.html sibling rendered"
  assert_file_exists "$RESULTS_DIR/crashes/CRASH-CLUSTERS.html" \
    "crashes: CRASH-CLUSTERS.md to CRASH-CLUSTERS.html sibling rendered"
  assert_file_exists "$RESULTS_DIR/crashes-rejected/REJECTED-CRASHES.html" \
    "crashes-rejected: REJECTED-CRASHES.md to REJECTED-CRASHES.html sibling rendered"
  assert_file_exists "$RESULTS_DIR/findings-rejected/REJECTED-FINDINGS.html" \
    "findings-rejected: REJECTED-FINDINGS.md to REJECTED-FINDINGS.html sibling rendered"
  assert_file_contains "$RESULTS_DIR/crashes/CRASH-CLUSTERS.html" \
    '../crashes-rejected/REJECTED-CRASHES.html' \
    "crash clusters link to the semantic rejected crashes report"
  assert_file_contains "$RESULTS_DIR/findings/FINDING-CLUSTERS.html" \
    '../findings-rejected/REJECTED-FINDINGS.html' \
    "finding clusters link to the semantic rejected findings report"
fi

# ═══════════════════════════════════════════════════════════════
# 6. Cluster output is idempotent
# ═══════════════════════════════════════════════════════════════

cp "$RESULTS_DIR/crashes/CRASH-CLUSTERS.md" "$TEST_TMPDIR/crash_clusters_before.md"
cp "$RESULTS_DIR/findings/FINDING-CLUSTERS.md" "$TEST_TMPDIR/finding_clusters_before.md"
maintain_indexes 2>/dev/null
diff_result=$(diff "$TEST_TMPDIR/crash_clusters_before.md" "$RESULTS_DIR/crashes/CRASH-CLUSTERS.md" || true)
assert_eq "" "$diff_result" "crash clusters are idempotent"
diff_result=$(diff "$TEST_TMPDIR/finding_clusters_before.md" "$RESULTS_DIR/findings/FINDING-CLUSTERS.md" || true)
assert_eq "" "$diff_result" "finding clusters are idempotent"

# ═══════════════════════════════════════════════════════════════
# 6b. Quiescent reports are not re-enriched / re-rendered
# ═══════════════════════════════════════════════════════════════
# Every housekeeping pass used to pay two python subprocesses per
# CRASH/FIND dir even when nothing changed. The post-render signature
# (.audit/.render-sig) must short-circuit both: after a re-run of
# maintain_indexes on unchanged markdown, the HTML sibling is untouched;
# a markdown edit re-renders.

quiescent_dir=$(find "$RESULTS_DIR/crashes" -maxdepth 1 -type d -name 'CRASH-*' 2>/dev/null | sort | head -1)
if command -v python3 >/dev/null 2>&1 && [ -n "$quiescent_dir" ]; then
  quiescent_html=$(find "$quiescent_dir" -maxdepth 1 \( -name 'REPORT.html' -o -name 'report.html' \) 2>/dev/null | head -1)
  assert_file_exists "$quiescent_dir/.audit/.render-sig" \
    "render pass records the post-render signature"
  if [ -n "$quiescent_html" ]; then
    # Pin md older than its html sentinel: both the cluster pass's
    # mtime guard and maintain's content signature must then leave the
    # HTML untouched; any re-render would refresh its mtime to "now".
    report_md=$(find "$quiescent_dir" -maxdepth 1 \( -name 'REPORT.md' -o -name 'report.md' \) 2>/dev/null | head -1)
    touch -t 200001010000 "$report_md" 2>/dev/null || true
    touch -t 200001010001 "$quiescent_html" 2>/dev/null || true
    sentinel_mtime=$(audit_stat_mtime_epoch "$quiescent_html" 2>/dev/null || echo 0)
    maintain_indexes 2>/dev/null
    after_mtime=$(audit_stat_mtime_epoch "$quiescent_html" 2>/dev/null || echo changed)
    assert_eq "$sentinel_mtime" "$after_mtime" \
      "re-run skips re-render of unchanged report HTML"
    echo "edited narrative line" >> "$report_md"
    maintain_indexes 2>/dev/null
    after_edit_mtime=$(audit_stat_mtime_epoch "$quiescent_html" 2>/dev/null || echo "$sentinel_mtime")
    if [ "$after_edit_mtime" != "$sentinel_mtime" ]; then
      pass "edited report re-renders its HTML sibling"
    else
      fail "edited report re-renders its HTML sibling" "html mtime still at sentinel"
    fi

    # ── 6c. patch.diff is keyed by content, not mtime:size ──────────
    # enrich-report inlines patch.diff into the report; a rewrite that
    # keeps the same byte count and the same epoch-second mtime must
    # still re-enrich + re-render.
    patch_file="$quiescent_dir/patch.diff"
    printf 'patch-v1\n' > "$patch_file"
    touch -t 200001010000 "$patch_file" 2>/dev/null || true
    maintain_indexes 2>/dev/null     # converge: sig records sha(patch-v1)
    touch -t 200001010000 "$report_md" 2>/dev/null || true
    touch -t 200001010001 "$quiescent_html" 2>/dev/null || true
    sentinel_mtime=$(audit_stat_mtime_epoch "$quiescent_html" 2>/dev/null || echo 0)
    maintain_indexes 2>/dev/null
    after_mtime=$(audit_stat_mtime_epoch "$quiescent_html" 2>/dev/null || echo changed)
    assert_eq "$sentinel_mtime" "$after_mtime" \
      "unchanged patch.diff still skips the re-render"
    printf 'patch-v2\n' > "$patch_file"          # same size, new bytes
    touch -t 200001010000 "$patch_file" 2>/dev/null || true  # same mtime:size
    maintain_indexes 2>/dev/null
    after_swap_mtime=$(audit_stat_mtime_epoch "$quiescent_html" 2>/dev/null || echo "$sentinel_mtime")
    if [ "$after_swap_mtime" != "$sentinel_mtime" ]; then
      pass "same-size same-mtime patch.diff rewrite re-renders (content sha)"
    else
      fail "same-size same-mtime patch.diff rewrite re-renders (content sha)" "html mtime still at sentinel"
    fi
  fi
fi

# ═══════════════════════════════════════════════════════════════
# 7. Empty directories produce valid but empty cluster tables
# ═══════════════════════════════════════════════════════════════

rm -rf "$RESULTS_DIR/crashes/CRASH-"* "$RESULTS_DIR/crashes-rejected/CRASH-"*
rm -rf "$RESULTS_DIR/findings/FIND-"*

maintain_indexes 2>/dev/null

assert_file_exists "$RESULTS_DIR/crashes/CRASH-CLUSTERS.md" "empty crash clusters exist"
assert_file_contains "$RESULTS_DIR/crashes/CRASH-CLUSTERS.md" "Crash Clusters" "empty crash clusters have header"
assert_file_exists "$RESULTS_DIR/findings/FINDING-CLUSTERS.md" "empty finding clusters exist"
assert_file_contains "$RESULTS_DIR/findings/FINDING-CLUSTERS.md" "Finding Clusters" "empty finding clusters have header"

# The rejected index is ALWAYS written (even empty), and the cluster table's
# footer link to it is unconditional — so the link is never dead. With zero
# rejected crashes the index is present as an empty table (header only).
assert_file_exists "$RESULTS_DIR/crashes-rejected/INDEX.md" \
  "empty rejected set: crashes-rejected/INDEX.md still exists (empty table)"
assert_file_contains "$RESULTS_DIR/crashes-rejected/INDEX.md" "DO NOT RE-FILE" \
  "empty rejected set: empty index keeps its header"
assert_file_contains "$RESULTS_DIR/crashes/CRASH-CLUSTERS.md" "triaged out" \
  "empty rejected set: cluster footer link is present unconditionally"

# ═══════════════════════════════════════════════════════════════
# 8. Rejected index always rebuilds (no skip cache): a newly-rejected dir
#    appears immediately, and a dir indexed before its cell files land is
#    updated once they arrive (no stale "— | — | —" row).
# ═══════════════════════════════════════════════════════════════
mkdir -p "$RESULTS_DIR/findings-rejected/FIND-SKIP-A"
printf '# A\n\n## Fields\n| Field | Value |\n|---|---|\n| File | src/a.c |\n| Line | 1 |\n' \
  > "$RESULTS_DIR/findings-rejected/FIND-SKIP-A/report.md"
printf '{"reason":"non-security a"}\n' > "$RESULTS_DIR/findings-rejected/FIND-SKIP-A/.llm-find-quality.json"
maintain_indexes 2>/dev/null
assert_file_contains "$RESULTS_DIR/findings-rejected/INDEX.md" 'FIND-SKIP-A' \
  "rejected index lists the first rejected dir"

mkdir -p "$RESULTS_DIR/findings-rejected/FIND-SKIP-B"
printf '# B\n\n## Fields\n| Field | Value |\n|---|---|\n| File | src/b.c |\n| Line | 2 |\n' \
  > "$RESULTS_DIR/findings-rejected/FIND-SKIP-B/report.md"
printf '{"reason":"non-security b"}\n' > "$RESULTS_DIR/findings-rejected/FIND-SKIP-B/.llm-find-quality.json"
maintain_indexes 2>/dev/null
assert_file_contains "$RESULTS_DIR/findings-rejected/INDEX.md" 'FIND-SKIP-B' \
  "rejected index rebuilds when a dir is added"

# A dir that is indexed BEFORE its cell files land (incomplete/TTL reject) must
# update once the report + reason arrive — always-rebuild guarantees this; the
# old name-only skip left it stuck at "— | — | —".
mkdir -p "$RESULTS_DIR/findings-rejected/FIND-LATE"
maintain_indexes 2>/dev/null
assert_file_contains "$RESULTS_DIR/findings-rejected/INDEX.md" 'FIND-LATE' \
  "late dir: appears with placeholder cells before its files exist"
printf '# L\n\n## Fields\n| Field | Value |\n|---|---|\n| File | src/late.c |\n| Line | 7 |\n' \
  > "$RESULTS_DIR/findings-rejected/FIND-LATE/report.md"
printf '{"reason":"late non-security"}\n' \
  > "$RESULTS_DIR/findings-rejected/FIND-LATE/.llm-find-quality.json"
maintain_indexes 2>/dev/null
assert_file_contains "$RESULTS_DIR/findings-rejected/INDEX.md" 'src/late.c:7' \
  "late dir: row updates once cell inputs arrive (no stale placeholder)"
rm -rf "$RESULTS_DIR/findings-rejected/FIND-LATE"

# ═══════════════════════════════════════════════════════════════
# 9. cluster-crashes change-skip rebuilds when a crash is added
#    (the skip keys on the crash basenames + asan stat; adding a crash must
#     bust it so the new crash appears in CRASH-CLUSTERS.md).
# ═══════════════════════════════════════════════════════════════
rm -rf "$RESULTS_DIR/crashes/CRASH-"*
maintain_indexes 2>/dev/null   # settle: empty crash clusters + sig
mkdir -p "$RESULTS_DIR/crashes/CRASH-SKIP-9-1"
cat > "$RESULTS_DIR/crashes/CRASH-SKIP-9-1/asan.txt" <<'AEOF'
==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x6020
#0 0x111 in app_parse parser.c:9
SUMMARY: AddressSanitizer: heap-buffer-overflow parser.c:9 in app_parse
AEOF
printf '# CRASH-SKIP-9-1\n- **Severity**: Low (CVSS-BTE 4.0: 3.3)\nbody\n' \
  > "$RESULTS_DIR/crashes/CRASH-SKIP-9-1/report.md"
maintain_indexes 2>/dev/null
assert_file_contains "$RESULTS_DIR/crashes/CRASH-CLUSTERS.md" 'app_parse' \
  "cluster-crashes rebuilds (skip busts) when a crash is added"
assert_file_contains "$RESULTS_DIR/crashes/CRASH-CLUSTERS.md" 'Low' \
  "cluster-crashes table shows the report's initial severity"

# 9b. An in-place severity edit in the report must bust the cluster-crashes
#     skip — the table carries severity, not just asan frames, so a key on
#     asan files alone would leave CRASH-CLUSTERS.md stale at the old rank.
printf '# CRASH-SKIP-9-1\n- **Severity**: High (CVSS-BTE 4.0: 8.7)\nbody\n' \
  > "$RESULTS_DIR/crashes/CRASH-SKIP-9-1/report.md"
maintain_indexes 2>/dev/null
assert_file_contains "$RESULTS_DIR/crashes/CRASH-CLUSTERS.md" 'High' \
  "cluster-crashes reclusters when report severity changes (Low -> High)"

# 9c. Even a same-mtime, same-size in-place severity rewrite must bust it:
#     the sig content-hashes the report (a stat key would miss this). "High"
#     and "None" are both 4 chars, so the file size is identical.
_ref_9c=$(mktemp)
touch -r "$RESULTS_DIR/crashes/CRASH-SKIP-9-1/report.md" "$_ref_9c"
printf '# CRASH-SKIP-9-1\n- **Severity**: None (CVSS-BTE 4.0: 0.0)\nbody\n' \
  > "$RESULTS_DIR/crashes/CRASH-SKIP-9-1/report.md"
touch -r "$_ref_9c" "$RESULTS_DIR/crashes/CRASH-SKIP-9-1/report.md"
rm -f "$_ref_9c"
maintain_indexes 2>/dev/null
if grep -q 'High' "$RESULTS_DIR/crashes/CRASH-CLUSTERS.md"; then
  fail "cluster-crashes reclusters on same-mtime same-size severity rewrite" \
    "table still shows stale High"
else
  pass "cluster-crashes reclusters on same-mtime same-size severity rewrite"
fi

# ═══════════════════════════════════════════════════════════════
# 10. Rejected index busts the dir-name skip when a dir is REMOVED.
#     Rejected dirs are terminal, so the skip keys on the set of dir names;
#     dropping one must remove its row (and keep the others).
# ═══════════════════════════════════════════════════════════════
rm -rf "$RESULTS_DIR/findings-rejected/FIND-SKIP-A"
maintain_indexes 2>/dev/null
assert_file_not_contains "$RESULTS_DIR/findings-rejected/INDEX.md" 'FIND-SKIP-A' \
  "rejected index rebuilds when a dir is removed (row dropped)"
assert_file_contains "$RESULTS_DIR/findings-rejected/INDEX.md" 'FIND-SKIP-B' \
  "rejected index keeps remaining dirs after a removal"

teardown_test_env
summary
