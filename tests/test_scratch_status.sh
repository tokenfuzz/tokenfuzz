#!/usr/bin/env bash
# Unit tests for bin/scratch-status — digest, family aggregation, verdicts
set -o pipefail
source "$(dirname "$0")/helpers.sh"
setup_test_env

SCRATCH_STATUS="$SCRIPT_ROOT/bin/scratch-status"

# ── Fixtures ─────────────────────────────────────────────────────────
# Build a synthetic scratch-1 covering every classification branch.
S1="$RESULTS_DIR/scratch-1"
mkdir -p "$S1"

# Three CLEAN testcases (same family) — verdict via EXECUTION VERIFIED marker.
# Use .bin since lib/quality.py treats *.txt as ambiguous (notes vs input)
# unless the stem matches input*/testcase*/tc-*/repro-* prefixes.
for i in 1 2 3; do
  printf 'GET / HTTP/1.1\r\n' > "$S1/altsvc-expire-size-${i}.bin"
  cat > "$S1/altsvc-expire-size-${i}.asan.txt" <<EOF
ASAN_RUN_HEADER: runs=1 mode=generic
[run-sanitizer-multi] EXECUTION_RATE: 1/1
[run-asan] generic EXECUTION VERIFIED (post-run, rc=0)
EOF
done

# One CRASH testcase.
printf 'crash input\n' > "$S1/aws-sigv4-size-1.bin"
cat > "$S1/aws-sigv4-size-1.asan.txt" <<'EOF'
ASAN_RUN_HEADER: runs=1
==1234==ERROR: AddressSanitizer: heap-buffer-overflow on address 0xdead
EOF

# Two ORPHAN testcases (no .asan.txt). Use distinct families.
printf 'orphan one\n' > "$S1/socks5-gss-len-1.bin"
printf 'orphan two\n' > "$S1/socks5-gss-token-1.bin"

# A harness source — must NOT count as a testcase, must count as a harness.
cat > "$S1/altsvc_file_harness.c" <<'EOF'
int main(int argc, char **argv) { return 0; }
EOF

# A README — must be ignored entirely.
echo "notes" > "$S1/README.md"
echo "compile note" > "$S1/build.log"

# Build a synthetic scratch-2 with underscore-variant naming.
S2="$RESULTS_DIR/scratch-2"
mkdir -p "$S2"
for i in 1 2 3; do
  printf 'cfg %d\n' "$i" > "$S2/version_string_${i}.conf"
  cat > "$S2/version_string_${i}.asan.txt" <<'EOF'
[run-sanitizer-multi] EXECUTION_RATE: 1/1
EOF
done

# ── 1. Help text ─────────────────────────────────────────────────────
output=$("$SCRATCH_STATUS" --help 2>&1)
assert_match "scratch-status" "$output" "help: shows usage"

# ── 2. Syntax check ──────────────────────────────────────────────────
python3 -m py_compile "$SCRATCH_STATUS" 2>/dev/null
assert_eq 0 $? "Python syntax check passes"

# ── 3. --agent N output ──────────────────────────────────────────────
output=$(RESULTS_DIR="$RESULTS_DIR" "$SCRATCH_STATUS" --agent 1 2>&1)
assert_match '\[scratch-1\] 6 testcases' "$output" "scratch-1 totals: 6 testcases"
assert_match '3 CLEAN' "$output" "scratch-1 verdict: 3 CLEAN"
assert_match '1 CRASH' "$output" "scratch-1 verdict: 1 CRASH"
assert_match '2 ORPHAN' "$output" "scratch-1 verdict: 2 ORPHAN flagged"
assert_match '1 harness sources' "$output" "scratch-1 harness count"

# Put misleading platform utilities first on PATH. The Python implementation
# must use os.stat rather than parsing platform-specific command output.
mkdir -p "$TEST_TMPDIR/fake-linux-bin"
cat > "$TEST_TMPDIR/fake-linux-bin/uname" <<'SH'
#!/usr/bin/env bash
printf 'Linux\n'
SH
cat > "$TEST_TMPDIR/fake-linux-bin/stat" <<'SH'
#!/usr/bin/env bash
if [ "$1" = "-f" ]; then
  printf '/\n'
  exit 0
fi
if [ "$1" = "-c" ] && [ "$2" = "%Y" ]; then
  printf '1234567890\n'
  exit 0
fi
exec /usr/bin/stat "$@"
SH
chmod +x "$TEST_TMPDIR/fake-linux-bin/uname" "$TEST_TMPDIR/fake-linux-bin/stat"
output_linux=$(PATH="$TEST_TMPDIR/fake-linux-bin:$PATH" RESULTS_DIR="$RESULTS_DIR" "$SCRATCH_STATUS" --agent 1 2>&1)
assert_not_match 'syntax error|operand expected' "$output_linux" \
  "linux stat branch: no arithmetic error from GNU stat -f output"
assert_match 'ago' "$output_linux" "linux stat branch: age fields still render"

# ── 4. Orphans listed with paths ─────────────────────────────────────
assert_match 'ORPHANS' "$output" "scratch-1: orphan section header"
assert_match 'socks5-gss-len-1.bin' "$output" "scratch-1: orphan path listed"
assert_match 'socks5-gss-token-1.bin' "$output" "scratch-1: second orphan listed"

# ── 5. Family aggregation collapses -<N> variants ────────────────────
assert_match 'altsvc-expire-size' "$output" "family: altsvc-expire-size present"
# Three -<N> variants must collapse to one family — not appear three times.
fam_lines=$(echo "$output" | grep -c '^    altsvc-expire-size *3 testcase')
assert_eq 1 "$fam_lines" "family: altsvc-expire-size collapses to one row"

# ── 6. Family with crash is marked ───────────────────────────────────
assert_match 'aws-sigv4-size.*CRASH' "$output" "family: aws-sigv4-size marked with CRASH"

# ── 7. Underscore variants collapse too (scratch-2 fixture) ──────────
output2=$(RESULTS_DIR="$RESULTS_DIR" "$SCRATCH_STATUS" --agent 2 2>&1)
assert_match 'version_string *3 testcase' "$output2" "family: version_string_<N> collapses"

# ── 7b. Harness-only scratch is valid under nounset / Bash 3.2 ─────────
S3="$RESULTS_DIR/scratch-3"
mkdir -p "$S3"
cat > "$S3/harness.c" <<'EOF'
int main(void) { return 0; }
EOF
output3=$(RESULTS_DIR="$RESULTS_DIR" "$SCRATCH_STATUS" --agent 3 --files 2>&1)
assert_not_match 'unbound variable' "$output3" "harness-only: no empty-array nounset failure"
assert_match '\[scratch-3\] 0 testcases .* 1 harness sources' "$output3" "harness-only: reports harness source"

# ── 8. --terse omits family/newest sections ──────────────────────────
output_terse=$(RESULTS_DIR="$RESULTS_DIR" "$SCRATCH_STATUS" --agent 1 --terse 2>&1)
assert_match '\[scratch-1\]' "$output_terse" "terse: header present"
if grep -q 'families:' <<<"$output_terse"; then
  fail "terse: families section should be omitted"
else
  pass "terse: families section omitted"
fi
if grep -q 'newest 5' <<<"$output_terse"; then
  fail "terse: newest section should be omitted"
else
  pass "terse: newest section omitted"
fi
if grep -q 'recent files' <<<"$output_terse"; then
  fail "terse: recent files should be omitted unless --files is set"
else
  pass "terse: recent files omitted by default"
fi

# ── 9. README / harness / asan.txt are not counted as testcases ──────
# 6 testcases above: 3 altsvc-expire-size, 1 aws-sigv4-size CRASH, 2 ORPHAN.
# A miscount would surface here (e.g. counting the .asan.txt files).
if grep -q '\[scratch-1\] 12 testcases' <<<"$output"; then
  fail "asan.txt files leaked into testcase count"
else
  pass "asan.txt files excluded from testcase count"
fi

# ── 10. Missing agent dir → (missing) marker, exit 0 ─────────────────
output_missing=$(RESULTS_DIR="$RESULTS_DIR" "$SCRATCH_STATUS" --agent 99 2>&1)
assert_match '\(missing\)' "$output_missing" "missing scratch dir: shows (missing)"

# ── 11. No scratch dirs at all → error to stderr ─────────────────────
empty_dir=$(mktemp -d)
output_empty=$(RESULTS_DIR="$empty_dir" "$SCRATCH_STATUS" 2>&1) || true
assert_match 'no scratch dirs found' "$output_empty" "no scratch: error message"
rm -rf "$empty_dir"

# ── 12. Output size sanity ───────────────────────────────────────────
# Even with all sections, scratch-1 fixture digest stays under 2 KB —
# guards against future regressions that bloat the output.
size=$(printf '%s' "$output" | wc -c | tr -d ' ')
if [ "$size" -lt 2048 ]; then
  pass "output size: under 2 KB (was $size B)"
else
  fail "output size: $size B exceeds 2 KB budget"
fi

# ── 13. --files gives a bounded substitute for raw ls -la ─────────────
for i in $(seq 1 25); do
  printf 'artifact %d\n' "$i" > "$S1/artifact-${i}.tmp"
done
output_files=$(RESULTS_DIR="$RESULTS_DIR" "$SCRATCH_STATUS" --agent 1 --files --file-limit 5 2>&1)
assert_match 'recent files \(newest 5 of [0-9]+\)' "$output_files" "files: section header includes bounded count"
assert_match 'artifact-[0-9]+\.tmp' "$output_files" "files: artifacts listed"
assert_match '\[artifact\]' "$output_files" "files: generic artifact kind shown"
assert_match 'more files; narrow by name with bin/scratch-search PATTERN' "$output_files" "files: cap footer suggests scratch-search"
file_rows=$(grep -c '^    .* B  ' <<<"$output_files" || true)
assert_eq 5 "$file_rows" "files: honors --file-limit"

output_files_wide=$(RESULTS_DIR="$RESULTS_DIR" "$SCRATCH_STATUS" --agent 1 --files --file-limit 80 2>&1)
assert_match '\[testcase\]' "$output_files_wide" "files: testcase kind shown"
assert_match '\[sanitizer-output\]' "$output_files_wide" "files: sanitizer-output kind shown"

teardown_test_env
summary
