#!/usr/bin/env bash
# Unit tests for lib/wrappers/sed — output truncation wrapper for sed.
# Mirrors the rg/grep wrapper test surface, with sed-specific cases for
# in-place edits and stream pipelines.
set -o pipefail
source "$(dirname "$0")/helpers.sh"
setup_test_env

SED_WRAPPER="$SCRIPT_ROOT/lib/wrappers/sed"

# ═══════════════════════════════════════════════════════════════
# 1. Small output passes through untouched
# ═══════════════════════════════════════════════════════════════

echo -e "foo\nbar\nbaz" > "$TEST_TMPDIR/small.txt"
output=$("$SED_WRAPPER" -n '1,3p' "$TEST_TMPDIR/small.txt" 2>/dev/null)
assert_match "foo" "$output" "small: passes through"
assert_match "baz" "$output" "small: all lines present"
assert_not_match "truncated" "$output" "small: no truncation footer when under cap"

# ═══════════════════════════════════════════════════════════════
# 2. Line cap: off by default (byte cap governs); explicit CAP_LINES=N fires it
# ═══════════════════════════════════════════════════════════════

seq 1 500 > "$TEST_TMPDIR/large.txt"
# The line range passes through whole; the byte cap (not a line cap) bounds size.
output=$("$SED_WRAPPER" -n '1,500p' "$TEST_TMPDIR/large.txt" 2>/dev/null)
line_count=$(printf '%s\n' "$output" | wc -l | tr -d ' ')
assert_eq "500" "$line_count" "line-range: full range passes through (no line cap)"
assert_not_match "truncated" "$output" "line-range: no line-cap footer"

# ═══════════════════════════════════════════════════════════════
# 3. Byte cap defends against single huge match (e.g. minified file)
# ═══════════════════════════════════════════════════════════════

python3 -c 'import sys; sys.stdout.write("Z" * 150000 + "\n")' > "$TEST_TMPDIR/huge.txt"
output=$("$SED_WRAPPER" -n '1p' "$TEST_TMPDIR/huge.txt" 2>/dev/null)
output_bytes=$(printf '%s' "$output" | wc -c | tr -d ' ')
[ "$output_bytes" -le 56000 ] \
  && pass "byte cap: huge single line head+tail capped (got ${output_bytes})" \
  || fail "byte cap: huge single line should be head+tail capped" "got ${output_bytes} bytes"
assert_match "output_cap: sed-stdout truncated" "$output" "byte cap: default path emits output_cap marker"

# Explicit CAP_BYTES changes the shared head+tail threshold.
output=$(CAP_BYTES=65536 "$SED_WRAPPER" -n '1p' "$TEST_TMPDIR/huge.txt" 2>/dev/null)
assert_match "output_cap: sed-stdout truncated" "$output" "byte cap: explicit CAP_BYTES uses shared marker"

# CAP_BYTES env override.
output=$(CAP_BYTES=4096 "$SED_WRAPPER" -n '1p' "$TEST_TMPDIR/huge.txt" 2>/dev/null)
assert_match "output_cap: sed-stdout truncated" "$output" "byte cap: CAP_BYTES env honored"

# ═══════════════════════════════════════════════════════════════
# 4. CAP_LINES=0 / CAP_BYTES=0 escape hatch — for legitimate large reads
# ═══════════════════════════════════════════════════════════════

output=$(CAP_LINES=0 CAP_BYTES=0 "$SED_WRAPPER" -n '1,500p' "$TEST_TMPDIR/large.txt" 2>/dev/null)
line_count=$(printf '%s\n' "$output" | wc -l | tr -d ' ')
assert_eq "500" "$line_count" "escape: CAP_*=0 returns full output"
assert_not_match "truncated" "$output" "escape: CAP_*=0 suppresses footer"

# ═══════════════════════════════════════════════════════════════
# 5. Stream pipeline: stdin → wrapper → stdout still capped
# ═══════════════════════════════════════════════════════════════

stream_output=$(seq 1 500 | "$SED_WRAPPER" -n 'p' 2>/dev/null)
stream_lines=$(printf '%s\n' "$stream_output" | wc -l | tr -d ' ')
assert_eq "500" "$stream_lines" "stream: stdin pipeline passes through (byte cap governs size)"

# ═══════════════════════════════════════════════════════════════
# 6. In-place edit (-i) preserves file mutation, emits no stdout to cap
# ═══════════════════════════════════════════════════════════════

# macOS sed needs -i '' (empty backup suffix); GNU sed accepts -i alone.
# Detect by behaviour: try macOS form first, fall back to GNU form.
echo -e "foo\nbar" > "$TEST_TMPDIR/inplace.txt"
inplace_stdout=$("$SED_WRAPPER" -i '' 's/foo/FOO/' "$TEST_TMPDIR/inplace.txt" 2>/dev/null) \
  || "$SED_WRAPPER" -i 's/foo/FOO/' "$TEST_TMPDIR/inplace.txt" >/dev/null 2>&1
assert_match "FOO" "$(cat "$TEST_TMPDIR/inplace.txt")" "in-place: file mutated"
assert_eq "" "$inplace_stdout" "in-place: no stdout emitted"

# ═══════════════════════════════════════════════════════════════
# 7. Exit code preserved (sed returns 0 on success, non-zero on missing file)
# ═══════════════════════════════════════════════════════════════

"$SED_WRAPPER" -n '1p' "$TEST_TMPDIR/small.txt" >/dev/null 2>&1
assert_eq 0 $? "exit: 0 on success"

rc=0
"$SED_WRAPPER" -n '1p' "$TEST_TMPDIR/missing.txt" >/dev/null 2>&1 || rc=$?
assert_neq 0 "$rc" "exit: non-zero on missing file"

# ═══════════════════════════════════════════════════════════════
# 8. stderr stays on stderr, diagnostic not mixed into stdout
# ═══════════════════════════════════════════════════════════════

out="$TEST_TMPDIR/sed.stdout"
err="$TEST_TMPDIR/sed.stderr"
"$SED_WRAPPER" -n '1p' "$TEST_TMPDIR/missing.txt" >"$out" 2>"$err" || true
assert_eq "" "$(cat "$out")" "stderr split: stdout empty for missing-file diagnostic"
assert_match "missing.txt" "$(cat "$err")" "stderr split: diagnostic preserved on stderr"

teardown_test_env
summary
