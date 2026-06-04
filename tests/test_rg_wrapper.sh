#!/usr/bin/env bash
# Unit tests for lib/wrappers/rg — output truncation wrapper
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

seq 1 500 | sed 's/$/ match/' > "$TEST_TMPDIR/large.txt"
output=$("$RG_WRAPPER" "match" "$TEST_TMPDIR/large.txt" 2>/dev/null)
data_lines=$(printf '%s\n' "$output" | grep -c 'match')
assert_eq "200" "$data_lines" "large: caps stdout at 200 data lines"
assert_match "total stdout lines" "$output" "large: stdout truncation footer"

output=$("$RG_WRAPPER" --count "match" "$TEST_TMPDIR/large.txt" 2>/dev/null)
assert_match "500" "$output" "--count flag: count is exact"

out="$TEST_TMPDIR/stderr.out"
err="$TEST_TMPDIR/stderr.err"
rc=0
"$RG_WRAPPER" "needle" "$TEST_TMPDIR/missing.txt" >"$out" 2>"$err" || rc=$?
assert_neq 0 "$rc" "stderr: exit code preserved for rg diagnostic"
assert_eq "" "$(cat "$out")" "stderr: diagnostic not mixed into stdout"
assert_match "missing.txt" "$(cat "$err")" "stderr: diagnostic preserved on stderr"

many_args=()
i=1
while [ "$i" -le 250 ]; do
  many_args+=("$TEST_TMPDIR/missing-$i.txt")
  i=$((i + 1))
done
rc=0
"$RG_WRAPPER" "needle" "${many_args[@]}" >"$out" 2>"$err" || rc=$?
stdout_lines=$(wc -l < "$out" | tr -d ' ')
stderr_lines=$(wc -l < "$err" | tr -d ' ')
assert_eq "0" "$stdout_lines" "stderr cap: stdout remains empty"
assert_eq "201" "$stderr_lines" "stderr cap: 200 diagnostics plus footer"
assert_match "total stderr lines" "$(tail -1 "$err")" "stderr cap: footer emitted on stderr"

# ─────────────────────────────────────────────────────────────────────────────
# Byte cap (CAP_BYTES) — defends against single huge match lines that would
# otherwise slip past the line cap (e.g. when scanning JSON-shaped haystacks).
# ─────────────────────────────────────────────────────────────────────────────

# One match line of ~150 KiB. Line count is 1 so the line cap doesn't fire,
# but the byte cap (default 128 KiB) must clip it.
HUGE="$TEST_TMPDIR/huge_line.txt"
python3 -c 'import sys; sys.stdout.write("Z" * 150000 + " match\n")' > "$HUGE"
output=$("$RG_WRAPPER" "match" "$HUGE" 2>/dev/null)
output_bytes=$(printf '%s' "$output" | wc -c | tr -d ' ')
[ "$output_bytes" -le 135000 ] && pass "byte cap: huge match line clipped (got ${output_bytes} bytes)" \
  || fail "byte cap: huge match should be clipped, got ${output_bytes} bytes"
assert_match "stdout clipped at 131072 bytes" "$output" "byte cap: footer reports default cap"

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

# Both caps fire together. The line cap applies first (200 lines kept), so
# we need each surviving line big enough that the cumulative bytes still
# blow past CAP_BYTES — 800 chars × 200 lines ≈ 160 KiB > 128 KiB default.
COMBO="$TEST_TMPDIR/combo.txt"
python3 -c '
for i in range(500):
    print("W" * 800 + f" match {i}")
' > "$COMBO"
output=$("$RG_WRAPPER" "match" "$COMBO" 2>/dev/null)
assert_match "total stdout lines" "$output" "combined: line-cap footer present"
assert_match "stdout clipped at 131072" "$output" "combined: byte-cap footer present"

# Byte clip aligns to last newline (no partial trailing line). Cap must be
# big enough to fit at least one full line, otherwise no newline boundary
# exists to align to. ~50-byte lines + 600-byte cap = 10+ full lines kept.
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
# Stdin pipeline — `printf | rg PATTERN` with no FILE arg. Wrapper must cap
# stdout the same way it caps file-mode output. Without this coverage, a
# regression that broke piped reads would slip through.
# ─────────────────────────────────────────────────────────────────────────────
stream_output=$(seq 1 500 | "$RG_WRAPPER" '[0-9]+' 2>/dev/null)
stream_lines=$(printf '%s\n' "$stream_output" | grep -cE '^[0-9]+$' || true)
assert_eq "200" "$stream_lines" "stream: stdin pipeline still capped at 200"
assert_match "total stdout lines" "$stream_output" "stream: stdout cap footer fires"

# ─────────────────────────────────────────────────────────────────────────────
# Passthrough boundary — a positional arg equal to a passthrough flag (e.g.
# pattern `--count` after `--`, or filename `-l`) must NOT trigger
# passthrough. The cap should still fire on huge output. Before the
# `--`-stop fix, the flag-equality scan walked all positionals and would
# wrongly bypass capping.
# ─────────────────────────────────────────────────────────────────────────────
PASSTHRU_HAYSTACK="$TEST_TMPDIR/passthru.txt"
i=1
while [ "$i" -le 500 ]; do
  printf -- '--count\n' >> "$PASSTHRU_HAYSTACK"
  i=$((i + 1))
done
output=$("$RG_WRAPPER" -- '\-\-count' "$PASSTHRU_HAYSTACK" 2>/dev/null)
data_lines=$(printf '%s\n' "$output" | grep -cF -- '--count' || true)
assert_eq "200" "$data_lines" "passthrough boundary: literal '--count' pattern after -- still capped"
assert_match "total stdout lines" "$output" "passthrough boundary: cap footer fires"

# ─────────────────────────────────────────────────────────────────────────────
# Per-tool bypass — AGENT_WRAPPERS_BYPASS runs the named tool uncapped while
# leaving the others capped, so an operator can A/B the cap's effect on
# bug-finding. large.txt has 500 matching lines; capped output keeps 200.
# ─────────────────────────────────────────────────────────────────────────────
GREP_WRAPPER="$SCRIPT_ROOT/lib/wrappers/grep"

# matches <bypass-value> <wrapper> -> count of "match" lines surfaced.
matches() { AGENT_WRAPPERS_BYPASS="$1" "$2" match "$TEST_TMPDIR/large.txt" 2>/dev/null | grep -c match; }

assert_eq "500" "$(matches rg      "$RG_WRAPPER")"   "bypass=rg: rg runs uncapped (all 500 lines)"
assert_eq "200" "$(matches rg      "$GREP_WRAPPER")" "bypass=rg: grep stays capped (bypass is per-tool)"
assert_eq "500" "$(matches grep,rg "$GREP_WRAPPER")" "bypass list: comma-separated entry uncaps grep"
assert_eq "500" "$(matches all     "$RG_WRAPPER")"   "bypass=all: rg uncapped"
assert_eq "200" "$(matches ''      "$RG_WRAPPER")"   "bypass unset: default 200-line cap unchanged"

# Uncapped output also drops the truncation footer.
assert_not_match "total stdout lines" \
  "$(AGENT_WRAPPERS_BYPASS=rg "$RG_WRAPPER" match "$TEST_TMPDIR/large.txt" 2>/dev/null)" \
  "bypass=rg: no truncation footer when uncapped"

teardown_test_env
summary
