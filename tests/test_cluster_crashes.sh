#!/usr/bin/env bash
# tests/test_cluster_crashes.sh — exercise bin/cluster-crashes against
# synthetic CRASH-* fixtures. Verifies (a) reports that share the same
# Root Cause keyword cluster together, (b) clusters with different root
# tokens stay separate, (c) the Cluster: line is updated idempotently in
# every grouped REPORT.md, (d) CRASH-CLUSTERS.md is written next to crashes/.
set -o pipefail
source "$(dirname "$0")/helpers.sh"
setup_test_env
source "$SCRIPT_ROOT/lib/platform.sh"

CLUSTER="$SCRIPT_ROOT/bin/cluster-crashes"
[ -x "$CLUSTER" ] || { echo "missing $CLUSTER"; exit 1; }

# ── Fixture: 5 crashes, 2 should cluster on code_start, 1 on name_table,
#    2 standalone. The harness writes CRASH-*/asan.txt (for primitive +
#    top frames) and CRASH-*/REPORT.md (for boundary + root cause). ──
make_crash_with_chain() {
  local id="$1" prim="$2" topfunc="$3" rootbody="$4"
  local caller1="${5:-caller}"
  local caller2="${6:-tail}"
  local d="$RESULTS_DIR/crashes/$id"
  mkdir -p "$d"
  cat > "$d/asan.txt" <<EOF
==12345==ERROR: AddressSanitizer: ${prim} on address 0x60200000abcd
READ of size 4 at 0x60200000abcd
    #0 0x100000000 in strlen+0x40 (libclang_rt.asan_osx_dynamic.dylib:arm64e+0x3ec80)
    #1 0x100000008 in ${topfunc} src/foo.c:42
    #2 0x100000010 in ${caller1} src/bar.c:99
    #3 0x100000018 in ${caller2} src/baz.c:123
    #4 0x100000020 in main harness.c:5
EOF
  cat > "$d/REPORT.md" <<EOF
# $id

| Field   | Value |
|---------|-------|
| Surface | library-api |
| Cluster | (set by bin/cluster-crashes) |

Boundary: serialized PCRE2 code bytes
Trigger source: bytes

## Root Cause
${rootbody}
EOF
}

make_crash() {
  make_crash_with_chain "$1" "$2" "$3" "$4" "caller" "tail"
}

make_crash_with_chain CRASH-A1-1 heap-buffer-overflow match_internal \
  "Decoded \`code_start\` is not bounded inside \`blocksize\`. The match path reads past the end of the decoded allocation." \
  "shared_dispatch" "shared_tail"
make_crash_with_chain CRASH-A2-1 heap-buffer-overflow dfa_match_internal \
  "\`pcre2_serialize_decode\` allows \`code_start\` to point outside the decoded allocation; \`pcre2_dfa_match\` then dereferences it." \
  "shared_dispatch" "shared_tail"
make_crash_with_chain CRASH-B1-1 heap-buffer-overflow nametable_scan \
  "Decoded name_count and name_entry_size are not constrained — the name table extends past the end of the decoded allocation." \
  "name_table_dispatch" "name_table_tail"
make_crash_with_chain CRASH-C1-1 stack-buffer-overflow process_command_line \
  "Unbounded \`name[24]\` copy from stdin token." \
  "command_dispatch" "command_tail"
make_crash_with_chain CRASH-D1-1 heap-buffer-overflow parse_config \
  "Generic parser state reaches a bounds diagnostic without a curated root token." \
  "config_dispatch" "config_tail"
make_crash_with_chain CRASH-E1-1 heap-buffer-overflow shared_leaf \
  "Generic parser state reaches a bounds diagnostic through path E." "abc" "def"
make_crash_with_chain CRASH-F1-1 heap-buffer-overflow shared_leaf \
  "Generic parser state reaches a bounds diagnostic through path F." "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzz" "yyyyyyyyyyyyyyyyyyyyyyyyyyyyyy"

make_start_only_xmlcatalog_crash() {
  local id="$1" target_line="$2" object="$3" object_line="$4"
  local d="$RESULTS_DIR/crashes/$id"
  mkdir -p "$d"
  cat > "$d/asan.txt" <<EOF
==12345==ERROR: AddressSanitizer: stack-buffer-overflow on address 0x1
WRITE of size 1 at 0x1 thread T0
    #0 0x100000000 in main+0x1aac (xmlcatalog:arm64+0x100002f94)
    #1 0x100000008 in start+0x1b4c (dyld:arm64e+0x1fda0)

  This frame has 4 object(s):
    [32, 533) 'buf' (line 78)
    [608, 708) '${object}' (line ${object_line}) <== Memory access at offset 708 overflows this variable
SUMMARY: AddressSanitizer: stack-buffer-overflow (xmlcatalog:arm64+0x100002f94) in main+0x1aac
EOF
  cat > "$d/REPORT.md" <<EOF
# $id

| Field   | Value |
|---------|-------|
| Surface | cli |
| Cluster | (set by bin/cluster-crashes) |

Boundary: xmlcatalog --shell stdin
Trigger source: bytes

## Classification
- **Severity**: Low (auto: score=10)

Target: xmlcatalog.c:usershell:${target_line}

## Root Cause
The parser writes past \`${object}\`.
EOF
}

make_start_only_xmlcatalog_crash CRASH-G1-1 138 command 116
make_start_only_xmlcatalog_crash CRASH-H1-1 155 arg 117

mkdir -p "$RESULTS_DIR/crashes/CRASH-I1-1"
cat > "$RESULTS_DIR/crashes/CRASH-I1-1/asan.txt" <<'EOF'
parser.c:77:5: runtime error: index 4 out of bounds for type 'int[4]'
    #0 0x100000000 in parse_token parser.c:77
SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior parser.c:77:5
EOF
cat > "$RESULTS_DIR/crashes/CRASH-I1-1/REPORT.md" <<'EOF'
# CRASH-I1-1

| Field   | Value |
|---------|-------|
| Surface | library-api |
| Cluster | (set by bin/cluster-crashes) |

Target: parser.c:parse_token:77
Trigger source: bytes
EOF

# Inject Severity lines so we can verify the sort. A1+A2 share a cluster
# whose max severity is High (61); B1's cluster is Medium (33); C1's
# cluster is Low (15). After sorting, the High cluster must come first.
inject_severity() {
  local id="$1" level="$2" score="$3"
  local f="$RESULTS_DIR/crashes/$id/REPORT.md"
  printf '\n## Classification\n- **Severity**: %s (auto: score=%s)\n' "$level" "$score" >> "$f"
}
inject_severity CRASH-A1-1 High     61
inject_severity CRASH-A2-1 Medium   33
inject_severity CRASH-B1-1 Medium   33
inject_severity CRASH-C1-1 Low      15
inject_severity CRASH-D1-1 Low      11
inject_severity CRASH-E1-1 Low      10
inject_severity CRASH-F1-1 Low      10

# ── Run cluster-crashes ────────────────────────────────────────
out=$(python3 "$CLUSTER" "$RESULTS_DIR" 2>&1) || \
  fail "cluster-crashes runs cleanly" "exit nonzero: $out"
pass "cluster-crashes runs cleanly"

assert_file_exists "$RESULTS_DIR/crashes/CRASH-CLUSTERS.md" "CRASH-CLUSTERS.md written"
assert_file_exists "$RESULTS_DIR/crashes/CRASH-CLUSTERS.html" \
  "CRASH-CLUSTERS.html rendered"
assert_file_exists "$RESULTS_DIR/crashes/CRASH-A1-1/REPORT.html" \
  "cluster-crashes renders member REPORT.html"
assert_file_contains "$RESULTS_DIR/crashes/CRASH-CLUSTERS.html" \
  'href="CRASH-A1-1/REPORT.html"' \
  "CRASH-CLUSTERS.html links to rendered member HTML"

# ── Cluster collapse: A1+A2 → one cluster (code_start) ─────────
a1_cluster=$(grep -m1 -E '^Cluster: CL-' "$RESULTS_DIR/crashes/CRASH-A1-1/REPORT.md" | sed -E 's/^Cluster: (CL-[0-9a-f]+).*/\1/')
a2_cluster=$(grep -m1 -E '^Cluster: CL-' "$RESULTS_DIR/crashes/CRASH-A2-1/REPORT.md" | sed -E 's/^Cluster: (CL-[0-9a-f]+).*/\1/')
b1_cluster=$(grep -m1 -E '^Cluster: CL-' "$RESULTS_DIR/crashes/CRASH-B1-1/REPORT.md" | sed -E 's/^Cluster: (CL-[0-9a-f]+).*/\1/')
c1_cluster=$(grep -m1 -E '^Cluster: CL-' "$RESULTS_DIR/crashes/CRASH-C1-1/REPORT.md" | sed -E 's/^Cluster: (CL-[0-9a-f]+).*/\1/')
e1_cluster=$(grep -m1 -E '^Cluster: CL-' "$RESULTS_DIR/crashes/CRASH-E1-1/REPORT.md" | sed -E 's/^Cluster: (CL-[0-9a-f]+).*/\1/')
f1_cluster=$(grep -m1 -E '^Cluster: CL-' "$RESULTS_DIR/crashes/CRASH-F1-1/REPORT.md" | sed -E 's/^Cluster: (CL-[0-9a-f]+).*/\1/')
g1_cluster=$(grep -m1 -E '^Cluster: CL-' "$RESULTS_DIR/crashes/CRASH-G1-1/REPORT.md" | sed -E 's/^Cluster: (CL-[0-9a-f]+).*/\1/')
h1_cluster=$(grep -m1 -E '^Cluster: CL-' "$RESULTS_DIR/crashes/CRASH-H1-1/REPORT.md" | sed -E 's/^Cluster: (CL-[0-9a-f]+).*/\1/')

assert_eq "$a1_cluster" "$a2_cluster" "A1 and A2 share a cluster (ClusterFuzz LCS >= 2)"
[ "$a1_cluster" != "$b1_cluster" ] && pass "A1 and B1 are in different clusters" || \
  fail "A1 and B1 are in different clusters" "both = $a1_cluster"
[ "$a1_cluster" != "$c1_cluster" ] && pass "A1 and C1 are in different clusters" || \
  fail "A1 and C1 are in different clusters" "both = $a1_cluster"
[ "$e1_cluster" != "$f1_cluster" ] && pass "only one common frame does not cluster" || \
  fail "only one common frame does not cluster" "both = $e1_cluster"
[ "$g1_cluster" != "$h1_cluster" ] && pass "runtime-only CLI stacks fall back to report source/object and stay distinct" || \
  fail "runtime-only CLI stacks stay distinct" "both = $g1_cluster"

# ── CRASH-CLUSTERS.md table groups members correctly and links to reports ─────
# Format is `[CRASH-A1-1](CRASH-A1-1/REPORT.md), [CRASH-A2-1](...)`,
# so we look for both the link target and the comma-joined ordering.
assert_file_contains "$RESULTS_DIR/crashes/CRASH-CLUSTERS.md" '\[CRASH-A1-1\]\(CRASH-A1-1/REPORT\.md\)' \
  "CRASH-CLUSTERS.md links A1 to its REPORT.md"
assert_file_contains "$RESULTS_DIR/crashes/CRASH-CLUSTERS.md" '\[CRASH-A2-1\]\(CRASH-A2-1/REPORT\.md\)' \
  "CRASH-CLUSTERS.md links A2 to its REPORT.md"
assert_file_contains "$RESULTS_DIR/crashes/CRASH-CLUSTERS.md" "CRASH-A1-1.*CRASH-A2-1" \
  "CRASH-CLUSTERS.md groups A1 + A2 on the same row"
assert_file_contains "$RESULTS_DIR/crashes/CRASH-CLUSTERS.md" '\[CRASH-B1-1\]' "CRASH-CLUSTERS.md lists B1"
assert_file_contains "$RESULTS_DIR/crashes/CRASH-CLUSTERS.md" '\[CRASH-C1-1\]' "CRASH-CLUSTERS.md lists C1"
assert_file_contains "$RESULTS_DIR/crashes/CRASH-CLUSTERS.md" '\[CRASH-D1-1\]' "CRASH-CLUSTERS.md lists D1"
assert_file_contains "$RESULTS_DIR/crashes/CRASH-CLUSTERS.md" '\[CRASH-E1-1\]' "CRASH-CLUSTERS.md lists E1"
assert_file_contains "$RESULTS_DIR/crashes/CRASH-CLUSTERS.md" '\[CRASH-F1-1\]' "CRASH-CLUSTERS.md lists F1"
assert_file_contains "$RESULTS_DIR/crashes/CRASH-CLUSTERS.md" '\[CRASH-I1-1\]' "CRASH-CLUSTERS.md lists UBSan I1"
assert_file_contains "$RESULTS_DIR/crashes/CRASH-CLUSTERS.md" 'ubsan-out-of-bounds' \
  "CRASH-CLUSTERS.md preserves UBSan primitive instead of unclassified"
assert_file_contains "$RESULTS_DIR/crashes/CRASH-CLUSTERS.md" 'parse_config' \
  "CRASH-CLUSTERS.md signature uses first interesting frame after ignored strlen"
assert_file_contains "$RESULTS_DIR/crashes/CRASH-CLUSTERS.md" 'abc' \
  "CRASH-CLUSTERS.md signature includes ClusterFuzz crash-state frames"
assert_file_contains "$RESULTS_DIR/crashes/CRASH-CLUSTERS.md" 'shared_leaf src/foo.c:42 -> abc src/bar.c:99 -> def src/baz.c:123' \
  "CRASH-CLUSTERS.md root signature shows location-rich dedup frames"
assert_file_contains "$RESULTS_DIR/crashes/CRASH-CLUSTERS.md" 'fallback:xmlcatalog.c:usershell:138 stack-object command line 116' \
  "CRASH-CLUSTERS.md uses report/source fallback when ASan stack is only main/start"
grep -q 'strlen' "$RESULTS_DIR/crashes/CRASH-CLUSTERS.md" \
  && fail "CRASH-CLUSTERS.md omits ClusterFuzz-ignored strlen frame" "strlen leaked into cluster signature" \
  || pass "CRASH-CLUSTERS.md omits ClusterFuzz-ignored strlen frame"
assert_file_contains "$RESULTS_DIR/crashes/CRASH-E1-1/REPORT.md" 'Dedup frames: shared_leaf src/foo.c:42 -> abc src/bar.c:99 -> def src/baz.c:123' \
  "REPORT.md bare label shows top-three dedup frames"
assert_file_contains "$RESULTS_DIR/crashes/CRASH-E1-1/REPORT.md" '\| Dedup frames \| shared_leaf src/foo.c:42 -> abc src/bar.c:99 -> def src/baz.c:123 \|' \
  "REPORT.md Fields table shows top-three dedup frames"

# ── Severity sort + score in cell ───────────────────────────
# CRASH-CLUSTERS.md must list rows by severity descending. The High cluster
# (CRASH-A1-1 + CRASH-A2-1) appears before the Medium cluster (CRASH-B1-1)
# which appears before the Low cluster (CRASH-C1-1). Each non-zero
# score is rendered alongside the level, e.g. "High (61)".
assert_file_contains "$RESULTS_DIR/crashes/CRASH-CLUSTERS.md" '\| Severity ' "Severity column present"
assert_file_contains "$RESULTS_DIR/crashes/CRASH-CLUSTERS.md" '\| High \(61\) ' \
  "High cell shows score (61)"
assert_file_contains "$RESULTS_DIR/crashes/CRASH-CLUSTERS.md" '\| Medium \(33\) ' \
  "Medium cell shows score (33)"
assert_file_contains "$RESULTS_DIR/crashes/CRASH-CLUSTERS.md" '\| Low \(15\) ' \
  "Low cell shows score (15)"
high_line=$(grep -nE '\| High \(61\) ' "$RESULTS_DIR/crashes/CRASH-CLUSTERS.md" | head -1 | cut -d: -f1)
med_line=$(grep -nE '\| Medium \(33\) .*CRASH-B1-1' "$RESULTS_DIR/crashes/CRASH-CLUSTERS.md" | head -1 | cut -d: -f1)
low_line=$(grep -nE '\| Low \(15\) ' "$RESULTS_DIR/crashes/CRASH-CLUSTERS.md" | head -1 | cut -d: -f1)
[ -n "$high_line" ] && [ -n "$med_line" ] && [ -n "$low_line" ] \
  && [ "$high_line" -lt "$med_line" ] && [ "$med_line" -lt "$low_line" ] \
  && pass "CRASH-CLUSTERS.md sorted High → Medium → Low" \
  || fail "CRASH-CLUSTERS.md sorted High → Medium → Low" \
        "high=$high_line med=$med_line low=$low_line"

# ── Canonical column + severity-descending members ──────────────
# The A1+A2 cluster's canonical is the highest-severity member (A1, High 61).
# The Canonical column names it, the Members list bolds it and orders by
# severity descending (A1 before A2), mirroring bin/cluster-findings.
assert_file_contains "$RESULTS_DIR/crashes/CRASH-CLUSTERS.md" '\| Canonical ' \
  "Canonical column present in CRASH-CLUSTERS.md"
a_row=$(grep -E '\| High \(61\) ' "$RESULTS_DIR/crashes/CRASH-CLUSTERS.md" | head -1)
# Canonical column cell links to A1, and the Members cell bolds A1 then lists A2.
echo "$a_row" | grep -qE '\| \[CRASH-A1-1\]\(CRASH-A1-1/REPORT\.md\) \| \*\*\[CRASH-A1-1\]\(CRASH-A1-1/REPORT\.md\)\*\*, \[CRASH-A2-1\]' \
  && pass "Canonical=A1; Members bold A1 first, then A2 (severity descending)" \
  || fail "Canonical=A1; Members bold A1 first, then A2 (severity descending)" \
        "row: $a_row"

# ── Canonical is highest-severity, NOT lowest-id ────────────────
# Two crashes that cluster (shared 2-of-3 frames) where the lexicographically
# FIRST id is Low and the later id is High. Canonical must be the High one —
# proving severity, not id order, picks the canonical.
sev_root="$TEST_TMPDIR/canonical-by-severity"
mk_sev_crash() {
  local id="$1" top="$2" level="$3" score="$4"
  local d="$sev_root/crashes/$id"
  mkdir -p "$d"
  cat > "$d/asan.txt" <<EOF
==1==ERROR: AddressSanitizer: heap-buffer-overflow
READ of size 4 at 0x60200000abcd
    #0 0x1 in ${top} src/x.c:10
    #1 0x2 in shared_mid src/shared.c:99
    #2 0x3 in shared_tail src/shared.c:123
EOF
  cat > "$d/REPORT.md" <<EOF
# ${id}
Trigger source: bytes

## Classification
- **Severity**: ${level} (auto: score=${score})
EOF
}
# CRASH-AAA sorts before CRASH-ZZZ but is the LOWER severity.
mk_sev_crash CRASH-AAA-1 unique_low  Low  12
mk_sev_crash CRASH-ZZZ-1 unique_high High 70
python3 "$CLUSTER" "$sev_root" >/dev/null 2>&1 \
  || fail "canonical-by-severity: cluster-crashes runs cleanly" "exit nonzero"
aaa_cluster=$(grep -m1 -E '^Cluster: CL-' "$sev_root/crashes/CRASH-AAA-1/REPORT.md" | sed -E 's/^Cluster: (CL-[0-9a-f]+).*/\1/')
zzz_cluster=$(grep -m1 -E '^Cluster: CL-' "$sev_root/crashes/CRASH-ZZZ-1/REPORT.md" | sed -E 's/^Cluster: (CL-[0-9a-f]+).*/\1/')
assert_eq "$aaa_cluster" "$zzz_cluster" "canonical-by-severity: AAA and ZZZ share a cluster"
sev_row=$(grep -E '\| High \(70\) ' "$sev_root/crashes/CRASH-CLUSTERS.md" | head -1)
echo "$sev_row" | grep -qE '\| \[CRASH-ZZZ-1\]\(CRASH-ZZZ-1/REPORT\.md\) \| \*\*\[CRASH-ZZZ-1\]' \
  && pass "canonical-by-severity: High ZZZ is canonical despite higher id, listed first" \
  || fail "canonical-by-severity: High ZZZ is canonical despite higher id" \
        "row: $sev_row"

# ── Idempotency: re-running produces byte-identical CRASH-CLUSTERS.md and reports ──
cp "$RESULTS_DIR/crashes/CRASH-CLUSTERS.md" "$TEST_TMPDIR/CRASH-CLUSTERS.md.before"
cp "$RESULTS_DIR/crashes/CRASH-A1-1/REPORT.md" "$TEST_TMPDIR/A1.before"
python3 "$CLUSTER" "$RESULTS_DIR" >/dev/null 2>&1
diff_out=$(diff "$TEST_TMPDIR/CRASH-CLUSTERS.md.before" "$RESULTS_DIR/crashes/CRASH-CLUSTERS.md" || true)
assert_eq "" "$diff_out" "CRASH-CLUSTERS.md is idempotent across runs"
diff_a1=$(diff "$TEST_TMPDIR/A1.before" "$RESULTS_DIR/crashes/CRASH-A1-1/REPORT.md" || true)
assert_eq "" "$diff_a1" "REPORT.md Cluster: line is idempotent"

# ── Dry-run does NOT write CRASH-CLUSTERS.md or modify reports ───────
rm "$RESULTS_DIR/crashes/CRASH-CLUSTERS.md"
mtime_before=$(audit_stat_mtime_epoch "$RESULTS_DIR/crashes/CRASH-A1-1/REPORT.md")
python3 "$CLUSTER" "$RESULTS_DIR" --dry-run > /dev/null 2>&1
[ ! -f "$RESULTS_DIR/crashes/CRASH-CLUSTERS.md" ] && pass "--dry-run does not write CRASH-CLUSTERS.md" \
  || fail "--dry-run does not write CRASH-CLUSTERS.md" "file present after dry run"
mtime_after=$(audit_stat_mtime_epoch "$RESULTS_DIR/crashes/CRASH-A1-1/REPORT.md")
assert_eq "$mtime_before" "$mtime_after" "--dry-run does not touch REPORT.md"

# ── Cross-agent aggregate writes output/<target>/CRASH-CLUSTERS.md ─────
agg_root="$TEST_TMPDIR/output/demo"
mkdir -p "$agg_root/claude/results/crashes/CRASH-AGG-1" \
         "$agg_root/codex/results/crashes/CRASH-AGG-2"
cat > "$agg_root/claude/results/crashes/CRASH-AGG-1/asan.txt" <<'EOF'
==1==ERROR: AddressSanitizer: heap-buffer-overflow
#0 0x1 in shared_bug src/shared.c:10
#1 0x2 in entry_a src/a.c:20
EOF
cat > "$agg_root/codex/results/crashes/CRASH-AGG-2/asan.txt" <<'EOF'
==2==ERROR: AddressSanitizer: heap-buffer-overflow
#0 0x1 in shared_bug src/shared.c:10
#1 0x2 in entry_b src/b.c:20
EOF
cat > "$agg_root/claude/results/crashes/CRASH-AGG-1/REPORT.md" <<'EOF'
# Aggregate crash A
Surface: library-api
EOF
cat > "$agg_root/codex/results/crashes/CRASH-AGG-2/REPORT.md" <<'EOF'
# Aggregate crash B
Surface: library-api
EOF
echo "# legacy" > "$agg_root/CLUSTERS.md"
python3 "$CLUSTER" "$agg_root" >/dev/null 2>&1 \
  || fail "aggregate cluster-crashes runs cleanly" "exit nonzero"
assert_file_exists "$agg_root/CRASH-CLUSTERS.md" \
  "aggregate CRASH-CLUSTERS.md written"
assert_file_contains "$agg_root/CRASH-CLUSTERS.md" 'claude/CRASH-AGG-1' \
  "aggregate CRASH-CLUSTERS.md links claude member"
assert_file_contains "$agg_root/CRASH-CLUSTERS.md" 'codex/CRASH-AGG-2' \
  "aggregate CRASH-CLUSTERS.md links codex member"
assert_file_not_exists "$agg_root/CLUSTERS.md" \
  "aggregate removes legacy CLUSTERS.md"

# ── UBSan distinct-primitive regression ──
# Two UBSan crashes with DIFFERENT sub-kinds (signed-integer-overflow
# vs shift-base) must NOT collapse to a single "undefined-behavior"
# primitive (and therefore must NOT cluster on primitive alone). This
# guards bin/cluster-crashes:_extract_primitive against the order bug
# where the broad substring ladder ran before the SUMMARY-line primitive
# was extracted.
ubsan_root="$TEST_TMPDIR/ubsan-distinct"
mkdir -p "$ubsan_root/crashes/CRASH-UBSAN-SHIFT" \
         "$ubsan_root/crashes/CRASH-UBSAN-OVERFLOW"
cat > "$ubsan_root/crashes/CRASH-UBSAN-SHIFT/asan.txt" <<'EOF'
src/encoder.c:42:9: runtime error: shift exponent 33 is too large for 32-bit type 'int'
    #0 0x100000000 in encode_value src/encoder.c:42:9
    #1 0x100000010 in run_encode src/driver.c:88
SUMMARY: UndefinedBehaviorSanitizer: shift-base src/encoder.c:42:9 in encode_value
EOF
cat > "$ubsan_root/crashes/CRASH-UBSAN-SHIFT/REPORT.md" <<'EOF'
# CRASH-UBSAN-SHIFT
Surface: library-api
Target: src/encoder.c:encode_value:42
EOF
cat > "$ubsan_root/crashes/CRASH-UBSAN-OVERFLOW/asan.txt" <<'EOF'
src/parser.c:120:14: runtime error: signed integer overflow: 2147483647 + 1 cannot be represented in type 'int'
    #0 0x200000000 in add_token src/parser.c:120:14
    #1 0x200000010 in scan_input src/parser.c:200
SUMMARY: UndefinedBehaviorSanitizer: signed-integer-overflow src/parser.c:120:14 in add_token
EOF
cat > "$ubsan_root/crashes/CRASH-UBSAN-OVERFLOW/REPORT.md" <<'EOF'
# CRASH-UBSAN-OVERFLOW
Surface: library-api
Target: src/parser.c:add_token:120
EOF
python3 "$CLUSTER" "$ubsan_root" >/dev/null 2>&1 \
  || fail "UBSan distinct: cluster-crashes runs cleanly" "exit nonzero"
assert_file_contains "$ubsan_root/crashes/CRASH-CLUSTERS.md" 'ubsan-shift-base' \
  "UBSan SUMMARY primitive 'shift-base' is preserved (not collapsed to 'undefined-behavior')"
assert_file_contains "$ubsan_root/crashes/CRASH-CLUSTERS.md" 'ubsan-signed-integer-overflow' \
  "UBSan SUMMARY primitive 'signed-integer-overflow' is preserved"
ubsan_shift_cluster=$(grep -m1 -E '^Cluster: CL-' "$ubsan_root/crashes/CRASH-UBSAN-SHIFT/REPORT.md" | sed -E 's/^Cluster: (CL-[0-9a-f]+).*/\1/')
ubsan_ovf_cluster=$(grep -m1 -E '^Cluster: CL-' "$ubsan_root/crashes/CRASH-UBSAN-OVERFLOW/REPORT.md" | sed -E 's/^Cluster: (CL-[0-9a-f]+).*/\1/')
[ -n "$ubsan_shift_cluster" ] && [ "$ubsan_shift_cluster" != "$ubsan_ovf_cluster" ] \
  && pass "UBSan distinct: shift-base and signed-integer-overflow get separate clusters" \
  || fail "UBSan distinct: shift-base and signed-integer-overflow get separate clusters" \
        "shift=$ubsan_shift_cluster overflow=$ubsan_ovf_cluster"

# UBSan generic 'undefined-behavior' SUMMARY still falls through to the
# substring ladder (so a "runtime error: index ... out of bounds" line
# becomes ubsan-out-of-bounds, not ubsan-undefined-behavior).
mkdir -p "$ubsan_root/crashes/CRASH-UBSAN-FALLBACK"
cat > "$ubsan_root/crashes/CRASH-UBSAN-FALLBACK/asan.txt" <<'EOF'
src/lookup.c:9:5: runtime error: index 4 out of bounds for type 'int[4]'
    #0 0x300000000 in idx_lookup src/lookup.c:9
SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior src/lookup.c:9:5
EOF
cat > "$ubsan_root/crashes/CRASH-UBSAN-FALLBACK/REPORT.md" <<'EOF'
# CRASH-UBSAN-FALLBACK
Surface: library-api
Target: src/lookup.c:idx_lookup:9
EOF
python3 "$CLUSTER" "$ubsan_root" >/dev/null 2>&1
assert_file_contains "$ubsan_root/crashes/CRASH-CLUSTERS.md" 'ubsan-out-of-bounds' \
  "generic 'undefined-behavior' SUMMARY falls through to substring ladder"

# ── LCS threshold env knob ──
# Default LCS threshold is 2 (ClusterFuzz behavior). Tightening to 3
# via CLUSTER_LCS_THRESHOLD=3 must split A1/A2 (which share 2 frames)
# into separate clusters.
lcs_root="$TEST_TMPDIR/lcs-threshold"
mkdir -p "$lcs_root/crashes/CRASH-LCS-A" "$lcs_root/crashes/CRASH-LCS-B"
cat > "$lcs_root/crashes/CRASH-LCS-A/asan.txt" <<'EOF'
==1==ERROR: AddressSanitizer: heap-buffer-overflow
READ of size 4 at 0x60200000abcd
    #0 0x100000000 in unique_top_a src/a.c:42
    #1 0x100000010 in shared_mid src/shared.c:99
    #2 0x100000020 in shared_tail src/shared.c:123
EOF
cat > "$lcs_root/crashes/CRASH-LCS-A/REPORT.md" <<'EOF'
# A
Surface: library-api
EOF
cat > "$lcs_root/crashes/CRASH-LCS-B/asan.txt" <<'EOF'
==2==ERROR: AddressSanitizer: heap-buffer-overflow
READ of size 4 at 0x60200000abcd
    #0 0x200000000 in unique_top_b src/b.c:88
    #1 0x200000010 in shared_mid src/shared.c:99
    #2 0x200000020 in shared_tail src/shared.c:123
EOF
cat > "$lcs_root/crashes/CRASH-LCS-B/REPORT.md" <<'EOF'
# B
Surface: library-api
EOF
python3 "$CLUSTER" "$lcs_root" >/dev/null 2>&1
lcs_a=$(grep -m1 -E '^Cluster: CL-' "$lcs_root/crashes/CRASH-LCS-A/REPORT.md" | sed -E 's/^Cluster: (CL-[0-9a-f]+).*/\1/')
lcs_b=$(grep -m1 -E '^Cluster: CL-' "$lcs_root/crashes/CRASH-LCS-B/REPORT.md" | sed -E 's/^Cluster: (CL-[0-9a-f]+).*/\1/')
[ -n "$lcs_a" ] && [ "$lcs_a" = "$lcs_b" ] \
  && pass "default LCS threshold 2 clusters frames sharing 2-of-3 frames" \
  || fail "default LCS threshold 2 clusters frames sharing 2-of-3 frames" \
        "a=$lcs_a b=$lcs_b"
# Same fixture, stricter threshold: must split.
rm -f "$lcs_root/crashes/CRASH-CLUSTERS.md"
# Strip the Cluster: stamp from each report so the next run re-derives it.
sed -i.bak '/^Cluster: /d' "$lcs_root/crashes/CRASH-LCS-A/REPORT.md" \
  "$lcs_root/crashes/CRASH-LCS-B/REPORT.md" 2>/dev/null || true
rm -f "$lcs_root/crashes/CRASH-LCS-A/REPORT.md.bak" "$lcs_root/crashes/CRASH-LCS-B/REPORT.md.bak"
CLUSTER_LCS_THRESHOLD=3 python3 "$CLUSTER" "$lcs_root" >/dev/null 2>&1
lcs_a_strict=$(grep -m1 -E '^Cluster: CL-' "$lcs_root/crashes/CRASH-LCS-A/REPORT.md" | sed -E 's/^Cluster: (CL-[0-9a-f]+).*/\1/')
lcs_b_strict=$(grep -m1 -E '^Cluster: CL-' "$lcs_root/crashes/CRASH-LCS-B/REPORT.md" | sed -E 's/^Cluster: (CL-[0-9a-f]+).*/\1/')
[ -n "$lcs_a_strict" ] && [ "$lcs_a_strict" != "$lcs_b_strict" ] \
  && pass "CLUSTER_LCS_THRESHOLD=3 splits 2-of-3-frame siblings into distinct clusters" \
  || fail "CLUSTER_LCS_THRESHOLD=3 splits 2-of-3-frame siblings into distinct clusters" \
        "a=$lcs_a_strict b=$lcs_b_strict"

# Fuzzy match disabled by default — two crash states that share NO
# exact frames but have token-shape similarity must NOT cluster.
fuzzy_root="$TEST_TMPDIR/fuzzy-match"
mkdir -p "$fuzzy_root/crashes/CRASH-FUZZ-A" "$fuzzy_root/crashes/CRASH-FUZZ-B"
cat > "$fuzzy_root/crashes/CRASH-FUZZ-A/asan.txt" <<'EOF'
==1==ERROR: AddressSanitizer: heap-buffer-overflow
READ of size 4 at 0x60200000abcd
    #0 0x100000000 in parse_token_a src/a.c:10
    #1 0x100000010 in scan_input_a src/a.c:20
    #2 0x100000020 in driver_a src/a.c:30
EOF
cat > "$fuzzy_root/crashes/CRASH-FUZZ-A/REPORT.md" <<'EOF'
# Fuzz A
Surface: library-api
EOF
cat > "$fuzzy_root/crashes/CRASH-FUZZ-B/asan.txt" <<'EOF'
==2==ERROR: AddressSanitizer: heap-buffer-overflow
READ of size 4 at 0x60200000abcd
    #0 0x200000000 in parse_token_b src/b.c:11
    #1 0x200000010 in scan_input_b src/b.c:21
    #2 0x200000020 in driver_b src/b.c:31
EOF
cat > "$fuzzy_root/crashes/CRASH-FUZZ-B/REPORT.md" <<'EOF'
# Fuzz B
Surface: library-api
EOF
python3 "$CLUSTER" "$fuzzy_root" >/dev/null 2>&1
fuzz_a=$(grep -m1 -E '^Cluster: CL-' "$fuzzy_root/crashes/CRASH-FUZZ-A/REPORT.md" | sed -E 's/^Cluster: (CL-[0-9a-f]+).*/\1/')
fuzz_b=$(grep -m1 -E '^Cluster: CL-' "$fuzzy_root/crashes/CRASH-FUZZ-B/REPORT.md" | sed -E 's/^Cluster: (CL-[0-9a-f]+).*/\1/')
[ -n "$fuzz_a" ] && [ "$fuzz_a" != "$fuzz_b" ] \
  && pass "fuzzy per-line match disabled by default: token-shape-similar crashes stay distinct" \
  || fail "fuzzy per-line match disabled by default" "a=$fuzz_a b=$fuzz_b"

teardown_test_env
summary
