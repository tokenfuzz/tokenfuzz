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
echo "# Auto-rejected" > "$RESULTS_DIR/crashes-rejected/CRASH-010-1/.autodiscard"

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
# 2. crashes-rejected/INDEX.md remains the rejection ledger
# ═══════════════════════════════════════════════════════════════

assert_file_exists "$RESULTS_DIR/crashes-rejected/INDEX.md" "crashes-rejected/INDEX.md created"
assert_file_contains "$RESULTS_DIR/crashes-rejected/INDEX.md" "CRASH-010-1" "rejected index has CRASH-010"
assert_file_contains "$RESULTS_DIR/crashes-rejected/INDEX.md" "DO NOT RE-FILE" "rejected index warns against re-filing"

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

[ ! -d "$RESULTS_DIR/findings-rejected" ] \
  && pass "no findings-rejected/ directory created" \
  || fail "no findings-rejected/ directory created" "findings-rejected/ exists"
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
# 7. Empty directories produce valid but empty cluster tables
# ═══════════════════════════════════════════════════════════════

rm -rf "$RESULTS_DIR/crashes/CRASH-"* "$RESULTS_DIR/crashes-rejected/CRASH-"*
rm -rf "$RESULTS_DIR/findings/FIND-"*

maintain_indexes 2>/dev/null

assert_file_exists "$RESULTS_DIR/crashes/CRASH-CLUSTERS.md" "empty crash clusters exist"
assert_file_contains "$RESULTS_DIR/crashes/CRASH-CLUSTERS.md" "Crash Clusters" "empty crash clusters have header"
assert_file_exists "$RESULTS_DIR/findings/FINDING-CLUSTERS.md" "empty finding clusters exist"
assert_file_contains "$RESULTS_DIR/findings/FINDING-CLUSTERS.md" "Finding Clusters" "empty finding clusters have header"

teardown_test_env
summary
