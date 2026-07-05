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
# 2. Many short lines under the byte cap pass through whole (no line cap)
# ═══════════════════════════════════════════════════════════════

seq 1 500 > "$TEST_TMPDIR/large.txt"
output=$("$GREP_WRAPPER" "." "$TEST_TMPDIR/large.txt" 2>/dev/null)
line_count=$(echo "$output" | wc -l | tr -d ' ')
assert_eq "500" "$line_count" "large: full result passes through (no line cap)"
assert_not_match "truncated" "$output" "large: no cap footer under the byte budget"

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

# Recursive grep skips every logs/ dir plus VCS metadata. Unlike rg, grep's
# --exclude-dir matches only a directory's own name (BSD and GNU), so it cannot
# restrict the skip to the harness output tree; a full logs/ skip is the safe
# choice — no self-output leak (prompt dumps, .raw/, vendored gemini home). A
# target's own logs/ source is reached via bin/rg-safe instead. Non-log dirs
# such as .raw/ stay searchable.
LOGTREE="$TEST_TMPDIR/logtree"
mkdir -p "$LOGTREE/src/logs" "$LOGTREE/output/sample/codex/logs/.raw" \
  "$LOGTREE/output/sample/codex/logs/.gemini-home/chats" \
  "$LOGTREE/output/sample/codex/.hg" "$LOGTREE/src/.raw"
echo 'PATCH-grep-wrapper' > "$LOGTREE/src/logs/logger.c"
echo 'PATCH-grep-wrapper' > "$LOGTREE/src/.raw/corpus.txt"
echo 'PATCH-grep-wrapper' > "$LOGTREE/output/sample/codex/logs/session_1.prompt.md"
echo 'PATCH-grep-wrapper' > "$LOGTREE/output/sample/codex/logs/.raw/session_1.log.raw"
echo 'PATCH-grep-wrapper' > "$LOGTREE/output/sample/codex/logs/.gemini-home/chats/s.jsonl"
echo 'PATCH-grep-wrapper' > "$LOGTREE/output/sample/codex/.hg/store"
output=$("$GREP_WRAPPER" -R 'PATCH-grep-wrapper' "$LOGTREE" 2>/dev/null)
assert_match 'src/\.raw/corpus\.txt' "$output" "log paths: non-log .raw dir remains searchable"
assert_not_match 'src/logs/logger\.c' "$output" "log paths: grep conservatively skips every logs/ dir"
assert_not_match 'session_1\.prompt\.md' "$output" "log paths: harness prompt dump excluded"
assert_not_match 'session_1\.log\.raw' "$output" "log paths: harness raw log excluded"
assert_not_match 'gemini-home' "$output" "log paths: vendored gemini home excluded"
assert_not_match '\.hg/store' "$output" "log paths: Mercurial metadata excluded"

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
assert_eq "0" "$stdout_lines" "stderr: stdout stays empty (diagnostics kept on stderr)"
assert_eq "250" "$stderr_lines" "stderr: diagnostics pass through on stderr (byte cap governs size)"
rc=0

# ═══════════════════════════════════════════════════════════════
# 8. Byte cap (CAP_BYTES) — defends against single huge match lines.
# ═══════════════════════════════════════════════════════════════

# One match line of ~150 KiB. Line cap doesn't fire (only 1 line) but the
# default head+tail byte cap must trim it and leave a spill marker.
HUGE="$TEST_TMPDIR/huge_line.txt"
python3 -c 'import sys; sys.stdout.write("Z" * 150000 + " match\n")' > "$HUGE"
output=$("$GREP_WRAPPER" "match" "$HUGE" 2>/dev/null)
output_bytes=$(printf '%s' "$output" | wc -c | tr -d ' ')
[ "$output_bytes" -le 56000 ] && pass "byte cap: huge match line head+tail capped (got ${output_bytes})" \
  || fail "byte cap: huge match should be head+tail capped, got ${output_bytes} bytes"
assert_match "output_cap: grep-stdout truncated" "$output" "byte cap: default path emits output_cap marker"

# Explicit CAP_BYTES preserves the historical chop-and-footer behavior.
output=$(CAP_BYTES=65536 "$GREP_WRAPPER" "match" "$HUGE" 2>/dev/null)
assert_match "stdout clipped at 65536" "$output" "byte cap: explicit CAP_BYTES uses legacy footer"

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
assert_eq "500" "$stream_lines" "stream: stdin pipeline passes through (byte cap governs size)"

# ═══════════════════════════════════════════════════════════════
# 10. Passthrough boundary — positional arg equal to a passthrough flag
#     must NOT trigger passthrough. Specifically, `grep -- -c FILE` is
#     a literal `-c` pattern; the wrapper should still cap output.
# ═══════════════════════════════════════════════════════════════

PASSTHRU_HAYSTACK="$TEST_TMPDIR/passthru.txt"
python3 -c 'import sys; sys.stdout.write(("-c " + "Z"*400 + "\n") * 500)' > "$PASSTHRU_HAYSTACK"
output=$("$GREP_WRAPPER" -- '-c' "$PASSTHRU_HAYSTACK" 2>/dev/null)
out_bytes=$(printf '%s' "$output" | wc -c | tr -d ' ')
[ "$out_bytes" -le 56000 ] && pass "passthrough boundary: literal '-c' pattern after -- still byte-capped" \
  || fail "passthrough boundary: expected ≤56000 bytes, got ${out_bytes}"

# Real -c flag still triggers passthrough (count is bounded output).
output=$("$GREP_WRAPPER" -c '.' "$PASSTHRU_HAYSTACK" 2>/dev/null)
assert_eq "500" "$output" "passthrough: real -c flag still passes through unchanged"

# ═══════════════════════════════════════════════════════════════
# 11. Empty streams emit nothing and preserve grep's exit code.
#     _cap early-returns on an empty stdout/stderr (skipping the wc/cat
#     work); this locks that optimization to byte-identical behavior.
# ═══════════════════════════════════════════════════════════════
echo "needle" > "$TEST_TMPDIR/nomatch.txt"
out=$("$GREP_WRAPPER" "ABSENT_PATTERN_XYZ" "$TEST_TMPDIR/nomatch.txt" 2>/dev/null); rc=$?
assert_eq "" "$out" "empty stdout: no-match prints nothing"
assert_eq "1" "$rc" "empty stdout: no-match preserves grep exit 1"
err=$("$GREP_WRAPPER" "needle" "$TEST_TMPDIR/nomatch.txt" 2>&1 1>/dev/null)
assert_eq "" "$err" "empty stderr: a clean match emits nothing on stderr"

teardown_test_env
summary
