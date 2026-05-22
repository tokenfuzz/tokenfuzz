#!/usr/bin/env bash
# Unit tests for lib/wrappers/grep — output truncation wrapper
set -o pipefail
source "$(dirname "$0")/helpers.sh"
setup_test_env

GREP_WRAPPER="$SCRIPT_ROOT/lib/wrappers/grep"

# ═══════════════════════════════════════════════════════════════
# 1. Normal output passes through
# ═══════════════════════════════════════════════════════════════

echo -e "foo\nbar\nbaz" > "$TEST_TMPDIR/small.txt"
output=$("$GREP_WRAPPER" "." "$TEST_TMPDIR/small.txt" 2>/dev/null)
assert_match "foo" "$output" "small: passes through"
assert_match "baz" "$output" "small: all lines present"

# ═══════════════════════════════════════════════════════════════
# 2. Large output truncated to 200 lines
# ═══════════════════════════════════════════════════════════════

seq 1 500 > "$TEST_TMPDIR/large.txt"
output=$("$GREP_WRAPPER" "." "$TEST_TMPDIR/large.txt" 2>/dev/null)
line_count=$(echo "$output" | wc -l | tr -d ' ')
# Should be 201 lines (200 data + 1 truncation notice)
assert_match "truncated to 200" "$output" "large: truncation notice shown"

# ═══════════════════════════════════════════════════════════════
# 3. -c flag passes through (bounded output)
# ═══════════════════════════════════════════════════════════════

seq 1 500 > "$TEST_TMPDIR/count.txt"
output=$("$GREP_WRAPPER" -c "." "$TEST_TMPDIR/count.txt" 2>/dev/null)
assert_eq "500" "$output" "-c flag: count is exact"

# ═══════════════════════════════════════════════════════════════
# 4. -l flag passes through
# ═══════════════════════════════════════════════════════════════

echo "match" > "$TEST_TMPDIR/match.txt"
output=$("$GREP_WRAPPER" -l "match" "$TEST_TMPDIR/match.txt" 2>/dev/null)
assert_match "match.txt" "$output" "-l flag: filename shown"

# ═══════════════════════════════════════════════════════════════
# 5. -q flag passes through (silent)
# ═══════════════════════════════════════════════════════════════

echo "match" > "$TEST_TMPDIR/quiet.txt"
"$GREP_WRAPPER" -q "match" "$TEST_TMPDIR/quiet.txt" 2>/dev/null
assert_eq 0 $? "-q flag: exit 0 on match"

"$GREP_WRAPPER" -q "nomatch" "$TEST_TMPDIR/quiet.txt" 2>/dev/null; rc=$?
assert_eq 1 $rc "-q flag: exit 1 on miss"

# ═══════════════════════════════════════════════════════════════
# 6. Exit code preserved
# ═══════════════════════════════════════════════════════════════

echo "hello" > "$TEST_TMPDIR/exit.txt"
"$GREP_WRAPPER" "hello" "$TEST_TMPDIR/exit.txt" >/dev/null 2>&1
assert_eq 0 $? "exit code: 0 on match"

"$GREP_WRAPPER" "zzzznothere" "$TEST_TMPDIR/exit.txt" >/dev/null 2>&1 || rc=$?
assert_eq 1 "${rc:-0}" "exit code: 1 on no match"

# ═══════════════════════════════════════════════════════════════
# 7. stderr stays on stderr and is capped independently
# ═══════════════════════════════════════════════════════════════

out="$TEST_TMPDIR/stderr.out"
err="$TEST_TMPDIR/stderr.err"
rc=0
"$GREP_WRAPPER" "needle" "$TEST_TMPDIR/missing.txt" >"$out" 2>"$err" || rc=$?
assert_eq 2 "${rc:-0}" "stderr: exit code preserved for grep diagnostic"
assert_eq "" "$(cat "$out")" "stderr: diagnostic not mixed into stdout"
assert_match "missing.txt" "$(cat "$err")" "stderr: diagnostic preserved on stderr"
rc=0

many_args=()
i=1
while [ "$i" -le 250 ]; do
  many_args+=("$TEST_TMPDIR/missing-$i.txt")
  i=$((i + 1))
done
"$GREP_WRAPPER" "needle" "${many_args[@]}" >"$out" 2>"$err" || rc=$?
stdout_lines=$(wc -l < "$out" | tr -d ' ')
stderr_lines=$(wc -l < "$err" | tr -d ' ')
assert_eq "0" "$stdout_lines" "stderr cap: stdout remains empty"
assert_eq "201" "$stderr_lines" "stderr cap: 200 diagnostics plus footer"
assert_match "total stderr lines" "$(tail -1 "$err")" "stderr cap: footer emitted on stderr"
rc=0

# ═══════════════════════════════════════════════════════════════
# 8. Byte cap (CAP_BYTES) — defends against single huge match lines.
# ═══════════════════════════════════════════════════════════════

# One match line of ~150 KiB. Line cap doesn't fire (only 1 line) but the
# default 128 KiB byte cap must clip.
HUGE="$TEST_TMPDIR/huge_line.txt"
python3 -c 'import sys; sys.stdout.write("Z" * 150000 + " match\n")' > "$HUGE"
output=$("$GREP_WRAPPER" "match" "$HUGE" 2>/dev/null)
output_bytes=$(printf '%s' "$output" | wc -c | tr -d ' ')
[ "$output_bytes" -le 135000 ] && pass "byte cap: huge match line clipped (got ${output_bytes})" \
  || fail "byte cap: huge match should clip, got ${output_bytes} bytes"
assert_match "stdout clipped at 131072" "$output" "byte cap: footer reports default cap"

# CAP_BYTES env override.
output=$(CAP_BYTES=4096 "$GREP_WRAPPER" "match" "$HUGE" 2>/dev/null)
assert_match "stdout clipped at 4096" "$output" "byte cap: CAP_BYTES env reflected"

# CAP_BYTES=0 disables byte cap.
output=$(CAP_BYTES=0 "$GREP_WRAPPER" "match" "$HUGE" 2>/dev/null)
assert_not_match "clipped" "$output" "byte cap: CAP_BYTES=0 disables clip"

# ═══════════════════════════════════════════════════════════════
# 9. Stdin pipeline — `cat foo | grep pattern` (no FILE arg)
# ═══════════════════════════════════════════════════════════════

# Mirrors the sed-wrapper stream test. Without coverage, a regression that
# broke piped reads would slip through both grep and rg wrappers.
stream_output=$(seq 1 500 | "$GREP_WRAPPER" '.' 2>/dev/null)
stream_lines=$(printf '%s\n' "$stream_output" | grep -cE '^[0-9]+$' || true)
assert_eq "200" "$stream_lines" "stream: stdin pipeline still capped at 200"
assert_match "total stdout lines" "$stream_output" "stream: stdout cap footer fires"

# ═══════════════════════════════════════════════════════════════
# 10. Passthrough boundary — positional arg equal to a passthrough flag
#     must NOT trigger passthrough. Specifically, `grep -- -c FILE` is
#     a literal `-c` pattern; the wrapper should still cap output.
# ═══════════════════════════════════════════════════════════════

PASSTHRU_HAYSTACK="$TEST_TMPDIR/passthru.txt"
i=1
while [ "$i" -le 500 ]; do
  printf -- '-c hit\n' >> "$PASSTHRU_HAYSTACK"
  i=$((i + 1))
done
output=$("$GREP_WRAPPER" -- '-c' "$PASSTHRU_HAYSTACK" 2>/dev/null)
data_lines=$(printf '%s\n' "$output" | grep -cF -- '-c hit' || true)
assert_eq "200" "$data_lines" "passthrough boundary: literal '-c' pattern after -- still capped"
assert_match "total stdout lines" "$output" "passthrough boundary: cap footer fires"

# Real -c flag still triggers passthrough (count is bounded output).
output=$("$GREP_WRAPPER" -c '.' "$PASSTHRU_HAYSTACK" 2>/dev/null)
assert_eq "500" "$output" "passthrough: real -c flag still passes through unchanged"

teardown_test_env
summary
