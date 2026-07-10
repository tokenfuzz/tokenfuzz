#!/usr/bin/env bash
# tests/test_cleanup_state.sh
#
# Coverage for bin/cleanup_state, which resets output/<target>/ while always
# preserving target metadata. Backend filters intentionally scope deletion to
# the selected backend directories. Symlinks must be unlinked, never followed.

set -o pipefail
source "$(dirname "$0")/helpers.sh"
setup_test_env

CLEANUP="$SCRIPT_ROOT/bin/cleanup_state"

mk_mock_target() {
    local root="$1" target="$2"
    mkdir -p "$root/$target/codex/results/scratch-1" \
             "$root/$target/codex/logs" \
             "$root/$target/claude/results/scratch-1" \
             "$root/$target/claude/logs"

    echo "[meta]" > "$root/$target/target.toml"
    echo "{}" > "$root/$target/codex/results/work-cards.jsonl"
    echo "tc" > "$root/$target/codex/results/scratch-1/tc.input"
    echo "log" > "$root/$target/codex/logs/index.log"
    echo "{}" > "$root/$target/claude/results/work-cards.jsonl"
    echo "tc" > "$root/$target/claude/results/scratch-1/tc.input"
    echo "log" > "$root/$target/claude/logs/index.log"
    echo "<html>" > "$root/$target/CRASH-CLUSTERS.html"
    echo "# crash" > "$root/$target/CRASH-CLUSTERS.md"
    echo "<html>" > "$root/$target/FINDING-CLUSTERS.html"
    echo "# find" > "$root/$target/FINDING-CLUSTERS.md"
    echo "state" > "$root/$target/.target-state"
}

# Section 1: default cleanup removes generated children below target.
sec1="$TEST_TMPDIR/out1"
mk_mock_target "$sec1" libxml2
mk_mock_target "$sec1" cjson
run_out=$("$CLEANUP" --output-root "$sec1" 2>&1)
rc=$?
assert_eq 0 "$rc" "default: clean exits 0 on success"
assert_match 'cleaned=2' "$run_out" "default: reports two cleaned targets"
assert_match 'failed=0' "$run_out" "default: zero failures"
for t in libxml2 cjson; do
    assert_file_exists "$sec1/$t/target.toml" "default $t: target.toml preserved"
    assert_dir_not_exists "$sec1/$t/codex" "default $t: codex backend removed"
    assert_dir_not_exists "$sec1/$t/claude" "default $t: claude backend removed"
    assert_file_not_exists "$sec1/$t/CRASH-CLUSTERS.md" "default $t: crash clusters removed"
    assert_file_not_exists "$sec1/$t/FINDING-CLUSTERS.md" "default $t: finding clusters removed"
    assert_file_not_exists "$sec1/$t/.target-state" "default $t: target dotfile removed"
done

# Section 1a: canary ground truth is preserved with target metadata.
sec1a="$TEST_TMPDIR/out1a"
mk_mock_target "$sec1a" canary
echo "{}" > "$sec1a/canary/.ground-truth.json"
tracked_out=$("$CLEANUP" --output-root "$sec1a" --target canary 2>&1)
rc=$?
assert_eq 0 "$rc" "ground truth: clean exits 0"
assert_match 'removed 7 entries, 2 preserved' "$tracked_out" "ground truth: reports preserved metadata"
assert_file_exists "$sec1a/canary/target.toml" "ground truth: target.toml preserved"
assert_file_exists "$sec1a/canary/.ground-truth.json" "ground truth: ground truth preserved"
assert_dir_not_exists "$sec1a/canary/codex" "ground truth: generated backend removed"
assert_dir_not_exists "$sec1a/canary/claude" "ground truth: generated backend removed"
assert_file_not_exists "$sec1a/canary/CRASH-CLUSTERS.md" "ground truth: generated cluster removed"

# Section 2: --dry-run reports removals but does not delete.
sec2="$TEST_TMPDIR/out2"
mk_mock_target "$sec2" libxml2
dry_out=$("$CLEANUP" --output-root "$sec2" --dry-run 2>&1)
rc=$?
assert_eq 0 "$rc" "dry-run: exits 0"
assert_match 'would remove' "$dry_out" "dry-run: reports what would happen"
assert_file_exists "$sec2/libxml2/target.toml" "dry-run: target.toml still present"
assert_dir_exists "$sec2/libxml2/codex" "dry-run: backend still present"
assert_file_exists "$sec2/libxml2/CRASH-CLUSTERS.md" "dry-run: clusters still present"

# Section 3: --target filter only touches that target.
sec3="$TEST_TMPDIR/out3"
mk_mock_target "$sec3" libxml2
mk_mock_target "$sec3" cjson
"$CLEANUP" --output-root "$sec3" --target libxml2 --quiet
assert_file_exists "$sec3/libxml2/target.toml" "target filter: target.toml preserved"
assert_dir_not_exists "$sec3/libxml2/codex" "target filter: selected target cleaned"
assert_dir_exists "$sec3/cjson/codex" "target filter: other target untouched"
assert_file_exists "$sec3/cjson/CRASH-CLUSTERS.md" "target filter: other target clusters untouched"

# Section 4: --backend/--backends remove only selected backend directories.
sec4="$TEST_TMPDIR/out4"
mk_mock_target "$sec4" libxml2
"$CLEANUP" --output-root "$sec4" --target libxml2 --backends codex --quiet
assert_dir_not_exists "$sec4/libxml2/codex" "backend filter: codex removed"
assert_dir_exists "$sec4/libxml2/claude" "backend filter: claude untouched"
assert_file_exists "$sec4/libxml2/CRASH-CLUSTERS.md" "backend filter: target-level files untouched"

sec4a="$TEST_TMPDIR/out4a"
mk_mock_target "$sec4a" libxml2
"$CLEANUP" --output-root "$sec4a" --target libxml2 --backend codex --quiet
assert_dir_not_exists "$sec4a/libxml2/codex" "backend alias: codex removed"
assert_dir_exists "$sec4a/libxml2/claude" "backend alias: claude untouched"

# Section 5: --keep preserves additional direct children.
sec5="$TEST_TMPDIR/out5"
mk_mock_target "$sec5" libxml2
"$CLEANUP" --output-root "$sec5" --target libxml2 --keep codex --quiet
assert_file_exists "$sec5/libxml2/target.toml" "--keep: target.toml preserved"
assert_dir_exists "$sec5/libxml2/codex" "--keep: codex preserved"
assert_dir_not_exists "$sec5/libxml2/claude" "--keep: unkept backend removed"
assert_file_not_exists "$sec5/libxml2/CRASH-CLUSTERS.md" "--keep: unkept target file removed"

# Section 6: --keep-only preserves only target.toml plus named direct children.
sec6="$TEST_TMPDIR/out6"
mk_mock_target "$sec6" libxml2
"$CLEANUP" --output-root "$sec6" --target libxml2 --keep-only codex --quiet
assert_file_exists "$sec6/libxml2/target.toml" "--keep-only: target.toml preserved"
assert_dir_exists "$sec6/libxml2/codex" "--keep-only: named child preserved"
assert_dir_not_exists "$sec6/libxml2/claude" "--keep-only: unnamed backend removed"
assert_file_not_exists "$sec6/libxml2/CRASH-CLUSTERS.md" "--keep-only: unnamed file removed"

# Section 7: empty --keep-only is valid; target.toml remains the only survivor.
sec7="$TEST_TMPDIR/out7"
mk_mock_target "$sec7" libxml2
empty_out=$("$CLEANUP" --output-root "$sec7" --target libxml2 --keep-only "" 2>&1)
rc=$?
assert_eq 0 "$rc" "empty keep-only: exits 0"
assert_match 'cleaned=1' "$empty_out" "empty keep-only: reports cleaned"
assert_file_exists "$sec7/libxml2/target.toml" "empty keep-only: target.toml preserved"
assert_dir_not_exists "$sec7/libxml2/codex" "empty keep-only: backend removed"

# Section 8: invalid --keep entries (slashes, dots) are rejected.
sec8="$TEST_TMPDIR/out8"
mk_mock_target "$sec8" libxml2
for bad in "../etc" "/etc" ".git" "."; do
    bad_rc=0
    bad_out=$("$CLEANUP" --output-root "$sec8" --keep "$bad" 2>&1) || bad_rc=$?
    assert_eq 2 "$bad_rc" "invalid --keep '$bad': exits 2"
    assert_match 'invalid --keep' "$bad_out" "invalid --keep '$bad': reports"
done
assert_dir_exists "$sec8/libxml2/codex" "invalid --keep: no cleanup performed"

# Section 9: missing output root is rejected.
miss_rc=0
miss_out=$("$CLEANUP" --output-root "$TEST_TMPDIR/no-such-dir" 2>&1) || miss_rc=$?
assert_eq 2 "$miss_rc" "missing output root: exits 2"
assert_match 'output root not found' "$miss_out" "missing output root: reports"

# Section 10: target with no target.toml is still reset safely.
sec10="$TEST_TMPDIR/out10"
mkdir -p "$sec10/orphan/codex/logs"
echo "log" > "$sec10/orphan/codex/logs/index.log"
"$CLEANUP" --output-root "$sec10" --target orphan --quiet
assert_dir_exists "$sec10/orphan" "no target.toml: target dir kept"
assert_dir_not_exists "$sec10/orphan/codex" "no target.toml: child removed"

# Section 11: rerun is idempotent after only target.toml remains.
sec11="$TEST_TMPDIR/out11"
mk_mock_target "$sec11" libxml2
"$CLEANUP" --output-root "$sec11" --quiet
second_run=$("$CLEANUP" --output-root "$sec11" 2>&1)
rc=$?
assert_eq 0 "$rc" "rerun: still exits 0"
assert_match 'already clean' "$second_run" "rerun: reports already clean"

# Section 12: target-root symlink is unlinked, not followed.
sec12="$TEST_TMPDIR/out12"
mk_mock_target "$sec12" libxml2
sentinel="$TEST_TMPDIR/sentinel.keep"
echo "must-survive" > "$sentinel"
ln -s "$sentinel" "$sec12/libxml2/escape-link"
"$CLEANUP" --output-root "$sec12" --target libxml2 --quiet
assert_file_not_exists "$sec12/libxml2/escape-link" "symlink at target root removed"
assert_file_exists "$sentinel" "symlink target outside tree NOT followed"

# Section 13: backend filter also unlinks a backend-named symlink without following.
sec13="$TEST_TMPDIR/out13"
mkdir -p "$sec13/libxml2"
echo "[meta]" > "$sec13/libxml2/target.toml"
backend_sentinel="$TEST_TMPDIR/backend-sentinel.keep"
echo "must-survive" > "$backend_sentinel"
ln -s "$backend_sentinel" "$sec13/libxml2/codex"
"$CLEANUP" --output-root "$sec13" --target libxml2 --backend codex --quiet
assert_file_not_exists "$sec13/libxml2/codex" "backend symlink removed"
assert_file_exists "$backend_sentinel" "backend symlink target NOT followed"

# Section 14: target/backend traversal components are rejected.
sec14="$TEST_TMPDIR/out14"
mk_mock_target "$sec14" libxml2
trav_rc=0
trav_out=$("$CLEANUP" --output-root "$sec14" --target '../libxml2' 2>&1) || trav_rc=$?
assert_eq 1 "$trav_rc" "invalid target traversal: exits non-zero"
assert_match 'invalid target component' "$trav_out" "invalid target traversal: reports"
assert_dir_exists "$sec14/libxml2/codex" "invalid target traversal: no cleanup performed"

bad_backend_rc=0
bad_backend_out=$("$CLEANUP" --output-root "$sec14" --target libxml2 --backends '../codex' 2>&1) || bad_backend_rc=$?
assert_eq 1 "$bad_backend_rc" "invalid backend traversal: exits non-zero"
assert_match 'invalid backend component' "$bad_backend_out" "invalid backend traversal: reports"
assert_dir_exists "$sec14/libxml2/codex" "invalid backend traversal: no cleanup performed"

# Section 15: cleanup_logs --backend alias and traversal guard.
CLEANUP_LOGS="$SCRIPT_ROOT/bin/cleanup_logs"
sec15a="$TEST_TMPDIR/out15a"
mk_mock_target "$sec15a" libxml2
"$CLEANUP_LOGS" --output-root "$sec15a" --target libxml2 --backend codex --quiet
assert_file_not_exists "$sec15a/libxml2/codex/logs/index.log" \
    "cleanup_logs backend alias: codex logs cleared"
assert_file_exists "$sec15a/libxml2/claude/logs/index.log" \
    "cleanup_logs backend alias: claude logs untouched"

sec15b="$TEST_TMPDIR/out15b"
mk_mock_target "$sec15b" libxml2
mkdir -p "$sec15b/libxml2/gemini/logs" "$sec15b/libxml2/grok/logs" "$sec15b/libxml2/oss/logs"
echo "log" > "$sec15b/libxml2/gemini/logs/index.log"
echo "log" > "$sec15b/libxml2/grok/logs/index.log"
echo "log" > "$sec15b/libxml2/oss/logs/index.log"
"$CLEANUP_LOGS" --output-root "$sec15b" --target libxml2 --quiet
assert_file_not_exists "$sec15b/libxml2/claude/logs/index.log" \
    "cleanup_logs default backends: claude logs cleared"
assert_file_not_exists "$sec15b/libxml2/codex/logs/index.log" \
    "cleanup_logs default backends: codex logs cleared"
assert_file_not_exists "$sec15b/libxml2/gemini/logs/index.log" \
    "cleanup_logs default backends: gemini logs cleared"
assert_file_not_exists "$sec15b/libxml2/grok/logs/index.log" \
    "cleanup_logs default backends: grok logs cleared"
assert_file_not_exists "$sec15b/libxml2/oss/logs/index.log" \
    "cleanup_logs default backends: oss logs cleared"

sec15="$TEST_TMPDIR/out15"
mk_mock_target "$sec15" libxml2
logs_rc=0
logs_out=$("$CLEANUP_LOGS" --output-root "$sec15" --target '../libxml2' 2>&1) || logs_rc=$?
assert_eq 1 "$logs_rc" "cleanup_logs invalid target traversal: exits non-zero"
assert_match 'invalid target component' "$logs_out" "cleanup_logs invalid target traversal: reports"
assert_file_exists "$sec15/libxml2/codex/logs/index.log" \
    "cleanup_logs invalid target traversal: no cleanup performed"

# Section 16: default enumeration finds nested real targets but never a
# benchmark repo-root facade. Benchmark cells stage their own
# output/<slug>/target.toml under output/benchmark/.../repo-root/output/, and a
# default cleanup must not delete that run state.
sec16="$TEST_TMPDIR/out16"
mk_mock_target "$sec16" "samples/sample-x"
facade="$sec16/benchmark/codex/run-1/cells/harness-r1/repo-root/output/cjson"
mkdir -p "$facade/claude/results/scratch-1"
echo "[meta]" > "$facade/target.toml"
echo "tc" > "$facade/claude/results/scratch-1/tc.input"

dry16=$("$CLEANUP" --output-root "$sec16" --dry-run 2>&1)
assert_match 'samples/sample-x' "$dry16" \
    "default enumeration includes the nested real target"
if printf '%s' "$dry16" | grep -q 'benchmark/'; then
    fail "benchmark facade must not be enumerated by default cleanup" "$dry16"
else
    pass "benchmark facade is not enumerated by default cleanup"
fi

"$CLEANUP" --output-root "$sec16" --quiet
assert_file_not_exists "$sec16/samples/sample-x/codex/results/scratch-1/tc.input" \
    "nested real target state is cleaned"
assert_file_exists "$sec16/samples/sample-x/target.toml" \
    "nested real target.toml preserved"
assert_file_exists "$facade/claude/results/scratch-1/tc.input" \
    "benchmark facade state is left untouched by default cleanup"

# Section 17: cleanup_logs matches cleanup_state on nested slugs — its default
# enumeration reaches output/samples/<slug>/<backend>/logs and its explicit
# --target accepts a nested slug, while a benchmark repo-root facade's logs are
# never enumerated by a default run.
sec17="$TEST_TMPDIR/out17"
mk_mock_target "$sec17" "samples/sample-x"
lfacade="$sec17/benchmark/codex/run-1/cells/harness-r1/repo-root/output/cjson"
mkdir -p "$lfacade/codex/logs"
echo "[meta]" > "$lfacade/target.toml"
echo "facade" > "$lfacade/codex/logs/index.log"

# Explicit nested --target clears just that target's logs (regression: slug
# validation used to reject the '/').
"$CLEANUP_LOGS" --output-root "$sec17" --target samples/sample-x --backend codex --quiet
assert_file_not_exists "$sec17/samples/sample-x/codex/logs/index.log" \
    "cleanup_logs explicit nested target: logs cleared"
assert_file_exists "$sec17/samples/sample-x/claude/logs/index.log" \
    "cleanup_logs explicit nested target: other backend untouched"

# Default enumeration reaches the nested target but never the benchmark facade.
echo "log" > "$sec17/samples/sample-x/codex/logs/index.log"
dry17=$("$CLEANUP_LOGS" --output-root "$sec17" --dry-run 2>&1)
assert_match 'samples/sample-x' "$dry17" \
    "cleanup_logs default enumeration includes the nested real target"
if printf '%s' "$dry17" | grep -q 'benchmark/'; then
    fail "cleanup_logs must not enumerate a benchmark facade by default" "$dry17"
else
    pass "cleanup_logs does not enumerate a benchmark facade by default"
fi
"$CLEANUP_LOGS" --output-root "$sec17" --quiet
assert_file_not_exists "$sec17/samples/sample-x/claude/logs/index.log" \
    "cleanup_logs default run: nested target logs cleared"
assert_file_exists "$lfacade/codex/logs/index.log" \
    "cleanup_logs default run: benchmark facade logs untouched"

teardown_test_env
summary
