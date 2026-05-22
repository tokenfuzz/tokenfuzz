#!/usr/bin/env bash
# tests/test_edges.sh — Tests for lib/edges.sh + bin/coverage-summary +
# the corpus-promotion edge-novelty gate in lib/quality.sh.
#
# Coverage:
#   1. edges_extract_from_hits_file pairs (function, file:line) and drops
#      noise / "??" frames; column suffix is stripped.
#   2. edges_master_union returns the sorted union across agent journals.
#   3. edges_count_new / edges_diff_new compute novelty correctly.
#   4. edges_record_run is idempotent and isolates per-agent writes.
#   5. edges_summary_subsystem_counts groups by configurable depth and
#      sorts by count desc.
#   6. edges_log_line_has_new_edges parses HIT/MISSED log lines.
#   7. bin/coverage-summary emits markdown / tsv / json.
#   8. promote_corpus_testcases honors CORPUS_REQUIRE_NEW_EDGES.

set -uo pipefail

TESTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$TESTS_DIR/helpers.sh"
source "$SCRIPT_ROOT/lib/edges.sh"

setup_test_env

# Route the lib at the test results dir.
export EDGES_RESULTS_DIR="$RESULTS_DIR"

# ── 1. extractor: pairs, noise filter, column strip, ?? drop ────────
hits_file="$TEST_TMPDIR/hits-1.txt"
cat > "$hits_file" <<'EOF'
Foo::Bar(int)
src/foo.cpp:42:5

Baz::Qux()
src/baz.cpp:10:3

??
??:0:0

__asan_load4
/asan_runtime/asan_interceptors.cpp:100:1

libsystem_malloc::malloc
/libsystem/foo.c:99:7

Foo::Bar(int)
src/foo.cpp:42:5

EOF
out_file="$TEST_TMPDIR/extracted-1.txt"
edges_extract_from_hits_file "$hits_file" > "$out_file"
out_lines=$(wc -l < "$out_file" | tr -d ' ')
assert_eq 2 "$out_lines" "extractor produces 2 unique non-noise edges"
assert_file_contains "$out_file" '^Foo::Bar\(int\)\|src/foo.cpp:42$' "Foo::Bar edge present (column stripped)"
assert_file_contains "$out_file" '^Baz::Qux\(\)\|src/baz.cpp:10$' "Baz::Qux edge present"
assert_file_not_contains "$out_file" '__asan' "noise frame dropped"
assert_file_not_contains "$out_file" 'libsystem' "libsystem frame dropped"
assert_file_not_contains "$out_file" '\?\?' "?? frames dropped"

# Empty / missing input is rc=0 with no output.
empty_file="$TEST_TMPDIR/empty.txt"; : > "$empty_file"
out=$(edges_extract_from_hits_file "$empty_file"); assert_eq "" "$out" "empty input → empty output"
out=$(edges_extract_from_hits_file "/nonexistent/path"); assert_eq "" "$out" "missing input → empty output"

# ── 2. master_union sorted, deduplicated across journals ────────────
mkdir -p "$RESULTS_DIR/coverage"
cat > "$RESULTS_DIR/coverage/edges-agent-1.journal" <<'EOF'
A|src/a.c:1
B|src/b.c:2
EOF
cat > "$RESULTS_DIR/coverage/edges-agent-2.journal" <<'EOF'
B|src/b.c:2
C|src/c.c:3
EOF
union=$(edges_master_union "testproject")
union_lines=$(printf '%s\n' "$union" | grep -c . | tr -d ' ')
assert_eq 3 "$union_lines" "master_union deduplicates across agent journals"
assert_match '^A\|src/a.c:1$' "$union" "union: A present"
assert_match '^B\|src/b.c:2$' "$union" "union: B present once"
assert_match '^C\|src/c.c:3$' "$union" "union: C present"

# Sorted: lines must be in ascending order.
sorted_union=$(printf '%s\n' "$union" | LC_ALL=C sort)
assert_eq "$union" "$sorted_union" "master_union output is sorted"

# ── 3. count_new / diff_new ─────────────────────────────────────────
run_file="$TEST_TMPDIR/run-1.txt"
# Three edges, one already in the union (B), two new (D and E).
LC_ALL=C sort -u > "$run_file" <<'EOF'
B|src/b.c:2
D|src/d.c:4
E|src/e.c:5
EOF
count=$(edges_count_new "testproject" "$run_file")
assert_eq 2 "$count" "count_new sees 2 new edges out of 3"
diff_out=$(edges_diff_new "testproject" "$run_file" | LC_ALL=C sort)
expected=$(printf 'D|src/d.c:4\nE|src/e.c:5')
assert_eq "$expected" "$diff_out" "diff_new returns only the novel edges"

# count_new with empty/missing run file → 0.
empty_run="$TEST_TMPDIR/run-empty.txt"; : > "$empty_run"
count=$(edges_count_new "testproject" "$empty_run")
assert_eq 0 "$count" "count_new handles empty run file"
count=$(edges_count_new "testproject" "/nonexistent/run.txt")
assert_eq 0 "$count" "count_new handles missing run file"

# ── 4. record_run: appends new-only, idempotent, agent-isolated ─────
edges_record_run "testproject" 3 "$run_file"
journal3="$RESULTS_DIR/coverage/edges-agent-3.journal"
assert_file_exists "$journal3" "record_run created agent 3 journal"
journal3_lines=$(wc -l < "$journal3" | tr -d ' ')
assert_eq 2 "$journal3_lines" "agent-3 journal contains 2 new edges (B was already in union)"
assert_file_contains "$journal3" '^D\|src/d.c:4$' "agent-3 journal has D"
assert_file_contains "$journal3" '^E\|src/e.c:5$' "agent-3 journal has E"
assert_file_not_contains "$journal3" '^B\|src/b.c:2$' "agent-3 journal does NOT have B (already in union)"

# Re-recording the same run is a no-op (idempotent).
journal3_before_sha=$(shasum "$journal3" | awk '{print $1}')
edges_record_run "testproject" 3 "$run_file"
journal3_after_sha=$(shasum "$journal3" | awk '{print $1}')
assert_eq "$journal3_before_sha" "$journal3_after_sha" "second record_run is a no-op"

# Recording for agent 4 leaves agent 3's journal untouched (isolation).
run_4="$TEST_TMPDIR/run-4.txt"
LC_ALL=C sort -u > "$run_4" <<'EOF'
F|src/f.c:6
EOF
edges_record_run "testproject" 4 "$run_4"
journal3_after_other=$(shasum "$journal3" | awk '{print $1}')
assert_eq "$journal3_before_sha" "$journal3_after_other" "writing to agent 4 doesn't touch agent 3"
assert_file_exists "$RESULTS_DIR/coverage/edges-agent-4.journal" "agent 4 journal created"

# Concurrent record_run calls for DIFFERENT agents must not lose edges.
# We can't deterministically interleave system calls in shell, but we can
# spawn many background writers and assert the final union has every
# edge each writer produced. Per-agent file isolation makes this safe.
for a in 5 6 7 8; do
  rf="$TEST_TMPDIR/concurrent-$a.txt"
  LC_ALL=C sort -u > "$rf" <<EOF
CONC$a|src/c$a.c:$a
EOF
  ( edges_record_run "testproject" "$a" "$rf" ) &
done
wait
union_after=$(edges_master_union "testproject")
for a in 5 6 7 8; do
  assert_match "CONC${a}\|src/c${a}.c:${a}" "$union_after" "concurrent agent $a survived merge"
done

# ── 5. summary_subsystem_counts: depth + sort ──────────────────────
# Build a fresh slug to avoid interference with above tests.
slug2_root="$TEST_TMPDIR/slug2"
mkdir -p "$slug2_root/coverage"
cat > "$slug2_root/coverage/edges-agent-1.journal" <<'EOF'
fn1|js/src/jit/Ion.cpp:10
fn2|js/src/jit/CodeGen.cpp:20
fn3|js/src/jit/CodeGen.cpp:21
fn4|js/src/wasm/Module.cpp:30
fn5|dom/canvas/CanvasContext.cpp:40
EOF
EDGES_RESULTS_DIR="$slug2_root" edges_summary_subsystem_counts "" 2 > "$TEST_TMPDIR/sum-2.tsv"
# Expected: js/src=3, dom/canvas=1, js/src=... wait depth=2 means js/src
# alone groups everything under js/src/. Re-check: depth=2 takes first 2
# components: js/src = 3 (Ion + CodeGen×2), js/src for wasm=1.
# Actually js/src/jit and js/src/wasm both fold to "js/src" at depth 2.
# So js/src = 4, dom/canvas = 1.
top_subsystem=$(head -1 "$TEST_TMPDIR/sum-2.tsv" | cut -f1)
top_count=$(head -1 "$TEST_TMPDIR/sum-2.tsv" | cut -f2)
assert_eq "js/src" "$top_subsystem" "depth=2 top subsystem is js/src"
assert_eq "4" "$top_count" "depth=2 js/src has 4 edges"

# Depth 3 splits jit and wasm apart.
EDGES_RESULTS_DIR="$slug2_root" edges_summary_subsystem_counts "" 3 > "$TEST_TMPDIR/sum-3.tsv"
assert_file_contains "$TEST_TMPDIR/sum-3.tsv" '^js/src/jit	3$' "depth=3 separates jit"
assert_file_contains "$TEST_TMPDIR/sum-3.tsv" '^js/src/wasm	1$' "depth=3 separates wasm"
# depth=3 takes the first 3 path components literally; canvas's third
# component is the filename, so we get dom/canvas/CanvasContext.cpp.
assert_file_contains "$TEST_TMPDIR/sum-3.tsv" '^dom/canvas/CanvasContext.cpp	1$' "depth=3 keeps full canvas file"

# Sort order: highest count first, ties broken by name asc.
sorted_check=$(awk -F'\t' '{ print $2 }' "$TEST_TMPDIR/sum-3.tsv" | head -2)
first_count=$(echo "$sorted_check" | head -1)
second_count=$(echo "$sorted_check" | tail -1)
assert_eq "3" "$first_count" "sort: highest count first"
[ "$second_count" -le "$first_count" ] && pass "sort: monotonic non-increasing" \
  || fail "sort: monotonic non-increasing" "first=$first_count second=$second_count"

# ── 6. edges_log_line_has_new_edges parses log lines ──────────────
line_yes='HIT: 2026-05-05T10:11:12Z testcase=/x/tc.html want=Foo::Bar edges=412 new=7 frame=Foo::Bar /x:42'
line_no='HIT: 2026-05-05T10:11:12Z testcase=/x/tc.html want=Foo::Bar edges=412 new=0 frame=Foo::Bar /x:42'
line_legacy='HIT: 2026-05-05T10:11:12Z testcase=/x/tc.html want=Foo::Bar frame=Foo::Bar /x:42'
edges_log_line_has_new_edges "$line_yes" && pass "log_line: new=7 reports yes" || fail "log_line: new=7 reports yes"
edges_log_line_has_new_edges "$line_no"   && fail "log_line: new=0 reports no"  || pass "log_line: new=0 reports no"
edges_log_line_has_new_edges "$line_legacy" && fail "log_line: legacy reports no" || pass "log_line: legacy reports no"

# ── 7. bin/hits attributes edge journals to AUDIT_AGENT_NUM ────────
hits_attr_root="$TEST_TMPDIR/hits-attr-root"
hits_tools="$TEST_TMPDIR/hits-tools"
mkdir -p "$hits_attr_root" "$hits_tools"
hits_attr_tc="$TEST_TMPDIR/hits-attr.js"
echo "print('TESTCASE_EXECUTED');" > "$hits_attr_tc"

cat > "$hits_tools/otool" <<'MOCK'
#!/usr/bin/env bash
echo "sectname __sancov_guards"
MOCK
cat > "$hits_tools/sancov" <<'MOCK'
#!/usr/bin/env bash
echo "0x1"
MOCK
cat > "$hits_tools/llvm-symbolizer" <<'MOCK'
#!/usr/bin/env bash
printf 'Foo::Bar()\nsrc/foo.cpp:42:5\n\n'
MOCK
cat > "$hits_tools/js" <<'MOCK'
#!/usr/bin/env bash
cov_dir=$(printf '%s' "${ASAN_OPTIONS:-}" | sed -nE 's/.*coverage_dir=([^:]+).*/\1/p')
mkdir -p "$cov_dir"
: > "$cov_dir/js.$$.sancov"
echo "TESTCASE_EXECUTED"
MOCK
chmod +x "$hits_tools/otool" "$hits_tools/sancov" "$hits_tools/llvm-symbolizer" "$hits_tools/js"

hits_attr_out="$TEST_TMPDIR/hits-attr.out"
PATH="$hits_tools:$PATH" \
EDGES_RESULTS_DIR="$hits_attr_root" RESULTS_DIR="$hits_attr_root" TARGET_SLUG="hitsattr" \
COV_JS="$hits_tools/js" SANCOV="$hits_tools/sancov" SYMBOLIZER="$hits_tools/llvm-symbolizer" \
HITS_SKIP_SANCOV_PROBE=1 \
AUDIT_AGENT_NUM=9 \
  "$SCRIPT_ROOT/bin/hits" --testcase "$hits_attr_tc" --want 'Foo::Bar' --mode js --timeout 2 --slug hitsattr \
  > "$hits_attr_out" 2>&1
assert_eq 0 $? "hits attribution: mocked coverage run succeeds"
assert_file_contains "$hits_attr_out" '^HIT: Foo::Bar' "hits attribution: reports target hit"
assert_file_exists "$hits_attr_root/coverage/edges-agent-9.journal" "hits attribution: AUDIT_AGENT_NUM journal created"
assert_file_not_exists "$hits_attr_root/coverage/edges-agent-0.journal" "hits attribution: no agent-0 journal"

# bin/hits must not use early-exit grep -q pipelines while pipefail is active.
# The mocked section dumper emits the guard near the front and enough trailing
# output to make the historical `printf "$lc" | grep -q ...` check return 141.
hits_sancov_root="$TEST_TMPDIR/hits-sancov-root"
hits_sancov_tools="$TEST_TMPDIR/hits-sancov-tools"
mkdir -p "$hits_sancov_root" "$hits_sancov_tools"
hits_sancov_tc="$TEST_TMPDIR/hits-sancov.js"
echo "print('TESTCASE_EXECUTED');" > "$hits_sancov_tc"

cat > "$hits_sancov_tools/otool" <<'MOCK'
#!/usr/bin/env bash
awk 'BEGIN { print "sectname __sancov_guards"; for (i = 0; i < 120000; i++) print "padding " i }'
MOCK
cat > "$hits_sancov_tools/readelf" <<'MOCK'
#!/usr/bin/env bash
awk 'BEGIN { print "__sancov_guards"; for (i = 0; i < 120000; i++) print "padding " i }'
MOCK
cat > "$hits_sancov_tools/sancov" <<'MOCK'
#!/usr/bin/env bash
echo "0x1"
MOCK
cat > "$hits_sancov_tools/llvm-symbolizer" <<'MOCK'
#!/usr/bin/env bash
printf 'Foo::Bar()\nsrc/foo.cpp:42:5\n\n'
MOCK
cat > "$hits_sancov_tools/js" <<'MOCK'
#!/usr/bin/env bash
cov_dir=$(printf '%s' "${ASAN_OPTIONS:-}" | sed -nE 's/.*coverage_dir=([^:]+).*/\1/p')
mkdir -p "$cov_dir"
: > "$cov_dir/js.$$.sancov"
echo "TESTCASE_EXECUTED"
MOCK
chmod +x "$hits_sancov_tools/otool" "$hits_sancov_tools/readelf" \
  "$hits_sancov_tools/sancov" "$hits_sancov_tools/llvm-symbolizer" \
  "$hits_sancov_tools/js"

hits_sancov_out="$TEST_TMPDIR/hits-sancov.out"
PATH="$hits_sancov_tools:$PATH" \
EDGES_RESULTS_DIR="$hits_sancov_root" RESULTS_DIR="$hits_sancov_root" TARGET_SLUG="hitssancov" \
COV_JS="$hits_sancov_tools/js" SANCOV="$hits_sancov_tools/sancov" SYMBOLIZER="$hits_sancov_tools/llvm-symbolizer" \
AUDIT_AGENT_NUM=10 \
  "$SCRIPT_ROOT/bin/hits" --testcase "$hits_sancov_tc" --want 'Foo::Bar' --mode js --timeout 2 --slug hitssancov \
  > "$hits_sancov_out" 2>&1
assert_eq 0 $? "hits sancov probe: large section output with early guard succeeds"
assert_file_contains "$hits_sancov_out" '^HIT: Foo::Bar' "hits sancov probe: reaches target after section validation"

# ── 8. bin/coverage-summary: md / tsv / json ──────────────────────
out_md="$TEST_TMPDIR/cov.md"
"$SCRIPT_ROOT/bin/coverage-summary" --results-dir "$slug2_root" --depth 3 --format md --out "$out_md"
assert_file_exists "$out_md" "coverage-summary writes md output"
assert_file_contains "$out_md" '# Coverage Summary' "md has top heading"
assert_file_contains "$out_md" '\| `js/src/jit` \|' "md mentions js/src/jit"
assert_file_contains "$out_md" 'Total edges seen' "md reports total"

out_tsv="$TEST_TMPDIR/cov.tsv"
"$SCRIPT_ROOT/bin/coverage-summary" --results-dir "$slug2_root" --depth 2 --format tsv --out "$out_tsv"
assert_file_exists "$out_tsv" "coverage-summary writes tsv output"
assert_file_contains "$out_tsv" '^subsystem	edges	share_pct$' "tsv has header"
assert_file_contains "$out_tsv" '^js/src	4' "tsv contains js/src=4"

many_journals_root="$TEST_TMPDIR/many-journals"
mkdir -p "$many_journals_root/coverage"
for i in $(seq 1 3000); do
  : > "$many_journals_root/coverage/edges-agent-$i.journal"
done
many_journals_out="$TEST_TMPDIR/cov-many.tsv"
"$SCRIPT_ROOT/bin/coverage-summary" --results-dir "$many_journals_root" --format tsv --out "$many_journals_out"
assert_eq 0 $? "coverage-summary consumes journal existence scan fully"
assert_file_contains "$many_journals_out" '^subsystem	edges	share_pct$' "many-journal tsv has header"

out_json="$TEST_TMPDIR/cov.json"
"$SCRIPT_ROOT/bin/coverage-summary" --results-dir "$slug2_root" --depth 3 --format json --out "$out_json"
assert_file_exists "$out_json" "coverage-summary writes json output"
if command -v jq >/dev/null 2>&1; then
  total_in_json=$(jq -r '.total_edges' "$out_json")
  assert_eq "5" "$total_in_json" "json total_edges = 5"
  jit_count=$(jq -r '.subsystems[] | select(.subsystem=="js/src/jit") | .edges' "$out_json")
  assert_eq "3" "$jit_count" "json js/src/jit count = 3"
fi

# Empty coverage dir → exit code 1.
mkdir -p "$TEST_TMPDIR/empty/coverage"
"$SCRIPT_ROOT/bin/coverage-summary" --results-dir "$TEST_TMPDIR/empty" --format md >/dev/null 2>&1
assert_eq 1 $? "empty coverage dir → rc=1"

# ── 9. promote_corpus_testcases respects new=N gate ───────────────
# Set up one agent, two HIT log entries — one with new>0, one with new=0
# — and assert only the novel one is promoted.
source "$SCRIPT_ROOT/lib/quality.sh"
NUM_AGENTS=1
hits_log=$(hits_log_path 1)
scratch=$(scratch_dir_path 1)
mkdir -p "$scratch"
cat > "$scratch/tc-novel.html" <<'EOF'
<!-- TARGET: src/foo.cpp:Foo::Bar -->
<!-- HYPOTHESIS-ID: H99 -->
<!-- CATEGORY: bounds -->
<html></html>
EOF
cat > "$scratch/tc-novel.asan.txt" <<'EOF'
[run-asan] EXECUTION VERIFIED
EXECUTION_RATE: 5/5
ASAN_RUN_HEADER: ok
EOF
cat > "$scratch/tc-stale.html" <<'EOF'
<!-- TARGET: src/foo.cpp:Foo::Bar -->
<!-- HYPOTHESIS-ID: H100 -->
<!-- CATEGORY: bounds -->
<html></html>
EOF
cat > "$scratch/tc-stale.asan.txt" <<'EOF'
[run-asan] EXECUTION VERIFIED
EXECUTION_RATE: 5/5
ASAN_RUN_HEADER: ok
EOF
cat > "$hits_log" <<EOF
HIT: 2026-05-05T10:00:00Z testcase=$scratch/tc-novel.html want=Foo::Bar edges=10 new=4 frame=Foo::Bar /src/foo.cpp:42
HIT: 2026-05-05T10:01:00Z testcase=$scratch/tc-stale.html want=Foo::Bar edges=10 new=0 frame=Foo::Bar /src/foo.cpp:42
EOF

# Promote with default gate on (CORPUS_REQUIRE_NEW_EDGES=1).
promote_corpus_testcases >/dev/null 2>&1 || true
corpus_root=$(corpus_dir_root)
promoted_dirs=$(find "$corpus_root" -maxdepth 1 -type d -name 'COVER-*' 2>/dev/null | wc -l | tr -d ' ')
assert_eq 1 "$promoted_dirs" "novelty gate: only the new=4 testcase is promoted"
promoted_meta=$(find "$corpus_root" -maxdepth 2 -name 'metadata.md' | head -1)
[ -n "$promoted_meta" ] && assert_file_contains "$promoted_meta" 'tc-novel.html' \
  "promoted dir is the novel testcase"
[ -n "$promoted_meta" ] && assert_file_contains "$promoted_meta" 'New edges contributed.*4' \
  "metadata records new-edge count"

# Disable the gate → both promote.
rm -rf "$corpus_root"; mkdir -p "$corpus_root"
CORPUS_REQUIRE_NEW_EDGES=0 promote_corpus_testcases >/dev/null 2>&1 || true
promoted_dirs=$(find "$corpus_root" -maxdepth 1 -type d -name 'COVER-*' 2>/dev/null | wc -l | tr -d ' ')
assert_eq 2 "$promoted_dirs" "CORPUS_REQUIRE_NEW_EDGES=0 promotes both"

teardown_test_env
summary
