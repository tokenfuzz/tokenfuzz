#!/usr/bin/env bash
# Unit tests for lib/wrappers/rg — byte-cap output wrapper (line cap removed)
set -o pipefail
source "$(dirname "$0")/helpers.sh"
setup_test_env

RG_WRAPPER="$SCRIPT_ROOT/lib/wrappers/rg"

if ! command -v rg >/dev/null 2>&1; then
  pass "rg wrapper: ripgrep not installed, skipping suite"
  teardown_test_env
  summary
  exit 0
fi

echo -e "alpha\nbeta\ngamma" > "$TEST_TMPDIR/small.txt"
output=$("$RG_WRAPPER" "a" "$TEST_TMPDIR/small.txt" 2>/dev/null)
assert_match "alpha" "$output" "small: passes through"
assert_match "gamma" "$output" "small: all matching lines present"

# Many short matching lines stay under the byte cap → the full result passes
# through unmodified (no line cap; the byte cap is the only size guard).
seq 1 500 | sed 's/$/ match/' > "$TEST_TMPDIR/large.txt"
output=$("$RG_WRAPPER" "match" "$TEST_TMPDIR/large.txt" 2>/dev/null)
data_lines=$(printf '%s\n' "$output" | grep -c 'match')
assert_eq "500" "$data_lines" "large: full result passes through (no line cap)"
assert_not_match "clipped" "$output" "large: no cap footer under the byte budget"

output=$("$RG_WRAPPER" --count "match" "$TEST_TMPDIR/large.txt" 2>/dev/null)
assert_match "500" "$output" "--count flag: count is exact"

out="$TEST_TMPDIR/stderr.out"
err="$TEST_TMPDIR/stderr.err"
rc=0
"$RG_WRAPPER" "needle" "$TEST_TMPDIR/missing.txt" >"$out" 2>"$err" || rc=$?
assert_neq 0 "$rc" "stderr: exit code preserved for rg diagnostic"
assert_eq "" "$(cat "$out")" "stderr: diagnostic not mixed into stdout"
assert_match "missing.txt" "$(cat "$err")" "stderr: diagnostic preserved on stderr"

# ─────────────────────────────────────────────────────────────────────────────
# Byte cap (CAP_BYTES) — the sole size guard. Defends against single huge match
# lines (e.g. JSON-shaped haystacks) and large result sets alike.
# ─────────────────────────────────────────────────────────────────────────────

# One match line of ~150 KiB. The default head+tail byte cap must trim it to
# roughly 50 KiB and leave a spill marker.
HUGE="$TEST_TMPDIR/huge_line.txt"
python3 -c 'import sys; sys.stdout.write("Z" * 150000 + " match\n")' > "$HUGE"
output=$("$RG_WRAPPER" "match" "$HUGE" 2>/dev/null)
output_bytes=$(printf '%s' "$output" | wc -c | tr -d ' ')
[ "$output_bytes" -le 56000 ] && pass "byte cap: huge match line head+tail capped (got ${output_bytes} bytes)" \
  || fail "byte cap: huge match should be head+tail capped, got ${output_bytes} bytes"
assert_match "output_cap: rg-stdout truncated" "$output" "byte cap: default path emits output_cap marker"

# Explicit CAP_BYTES preserves the historical chop-and-footer behavior.
output=$(CAP_BYTES=65536 "$RG_WRAPPER" "match" "$HUGE" 2>/dev/null)
assert_match "stdout clipped at 65536 bytes" "$output" "byte cap: explicit CAP_BYTES uses legacy footer"

# CAP_BYTES env override.
output=$(CAP_BYTES=4096 "$RG_WRAPPER" "match" "$HUGE" 2>/dev/null)
output_bytes=$(printf '%s' "$output" | wc -c | tr -d ' ')
[ "$output_bytes" -le 5000 ] && pass "byte cap: CAP_BYTES=4096 honored (got ${output_bytes})" \
  || fail "byte cap: CAP_BYTES=4096 expected ≤5000 bytes, got ${output_bytes}"
assert_match "stdout clipped at 4096" "$output" "byte cap: CAP_BYTES env reflected in footer"

# CAP_BYTES=0 disables byte cap (full huge line passes through).
output=$(CAP_BYTES=0 "$RG_WRAPPER" "match" "$HUGE" 2>/dev/null)
output_bytes=$(printf '%s' "$output" | wc -c | tr -d ' ')
[ "$output_bytes" -ge 150000 ] && pass "byte cap: CAP_BYTES=0 bypasses cap (got ${output_bytes})" \
  || fail "byte cap: CAP_BYTES=0 expected ≥150000 bytes, got ${output_bytes}"
assert_not_match "clipped" "$output" "byte cap: CAP_BYTES=0 suppresses clip footer"

# A large multi-line result set is byte-capped by the default head+tail helper.
COMBO="$TEST_TMPDIR/combo.txt"
python3 -c '
for i in range(500):
    print("W" * 800 + f" match {i}")
' > "$COMBO"
output=$("$RG_WRAPPER" "match" "$COMBO" 2>/dev/null)
combo_bytes=$(printf '%s' "$output" | wc -c | tr -d ' ')
[ "$combo_bytes" -le 56000 ] && pass "byte cap: large result set head+tail capped (got ${combo_bytes})" \
  || fail "byte cap: large result set should be capped, got ${combo_bytes} bytes"
assert_match "output_cap: rg-stdout truncated" "$output" "byte cap: default byte-cap marker present"

# Byte clip aligns to last newline (no partial trailing line).
ALIGN="$TEST_TMPDIR/align.txt"
python3 -c '
for i in range(200):
    print("V" * 40 + f" match {i:03d}")
' > "$ALIGN"
output=$(CAP_BYTES=600 "$RG_WRAPPER" "match" "$ALIGN" 2>/dev/null)
last_data=$(printf '%s\n' "$output" | grep '^V' | tail -1)
case "$last_data" in
  *' match '*) pass "byte cap: clip aligns to newline (no partial line)" ;;
  *) fail "byte cap: clip left a partial line: '${last_data:0:80}'" ;;
esac

# ─────────────────────────────────────────────────────────────────────────────
# Stdin pipeline — `printf | rg PATTERN` with no FILE arg passes through and is
# byte-capped the same as file mode.
# ─────────────────────────────────────────────────────────────────────────────
stream_output=$(seq 1 500 | "$RG_WRAPPER" '[0-9]+' 2>/dev/null)
stream_lines=$(printf '%s\n' "$stream_output" | grep -cE '^[0-9]+$' || true)
assert_eq "500" "$stream_lines" "stream: stdin pipeline passes through (byte cap governs size)"

# ─────────────────────────────────────────────────────────────────────────────
# Passthrough boundary — a positional arg equal to a passthrough flag (pattern
# `--count` after `--`) must NOT trigger passthrough, so the byte cap still
# fires on huge output.
# ─────────────────────────────────────────────────────────────────────────────
PASSTHRU_HAYSTACK="$TEST_TMPDIR/passthru.txt"
python3 -c 'import sys; sys.stdout.write(("--count " + "Z"*400 + "\n") * 400)' > "$PASSTHRU_HAYSTACK"
output=$("$RG_WRAPPER" -- '\-\-count' "$PASSTHRU_HAYSTACK" 2>/dev/null)
out_bytes=$(printf '%s' "$output" | wc -c | tr -d ' ')
[ "$out_bytes" -le 56000 ] && pass "passthrough boundary: literal '--count' pattern after -- still byte-capped" \
  || fail "passthrough boundary: expected ≤56000 bytes, got ${out_bytes}"

# ─────────────────────────────────────────────────────────────────────────────
# Per-tool bypass — AGENT_WRAPPERS_BYPASS runs the named tool uncapped while
# leaving the others capped. Distinguish by bytes on the huge single line.
# ─────────────────────────────────────────────────────────────────────────────
GREP_WRAPPER="$SCRIPT_ROOT/lib/wrappers/grep"
bytes_of() { AGENT_WRAPPERS_BYPASS="$1" "$2" match "$HUGE" 2>/dev/null | wc -c | tr -d ' '; }

[ "$(bytes_of rg  "$RG_WRAPPER")"   -ge 150000 ] && pass "bypass=rg: rg runs uncapped (full huge line)" \
  || fail "bypass=rg: rg should be uncapped"
[ "$(bytes_of rg  "$GREP_WRAPPER")" -le 56000 ]  && pass "bypass=rg: grep stays capped (bypass is per-tool)" \
  || fail "bypass=rg: grep should stay byte-capped"
[ "$(bytes_of all "$RG_WRAPPER")"   -ge 150000 ] && pass "bypass=all: rg uncapped" \
  || fail "bypass=all: rg should be uncapped"
[ "$(bytes_of ''  "$RG_WRAPPER")"   -le 56000 ]  && pass "bypass unset: default byte cap unchanged" \
  || fail "bypass unset: rg should be byte-capped"

teardown_test_env
summary
