#!/usr/bin/env bash
# Tests for bin/peek — clamped source viewer (line-range + grep -A/-B).
set -o pipefail
source "$(dirname "$0")/helpers.sh"
setup_test_env
source "$SCRIPT_ROOT/lib/timeout.sh"

PEEK="$SCRIPT_ROOT/bin/peek"

# ── Syntax check ──
bash -n "$PEEK" 2>/dev/null
assert_eq 0 $? "peek: syntax check passes"

# ── Fixture: a 500-line file that lets line caps fire predictably. ──
FIX="$TEST_TMPDIR/big.c"
seq 1 500 | sed 's/^/line /' > "$FIX"
assert_file_exists "$FIX" "fixture: 500-line source"

# ──────────────────────────────────────────────────────────────────────
# Range mode
# ──────────────────────────────────────────────────────────────────────

# FILE:START-END shows that exact range when it fits under the cap.
output=$("$PEEK" "$FIX:10-15")
expected=$'line 10\nline 11\nline 12\nline 13\nline 14\nline 15'
assert_eq "$expected" "$output" "range: FILE:10-15 returns exactly those lines"

# Footer does not fire when range ≤ PEEK_MAX_LINES.
assert_not_match 'clamped' "$output" "range: no footer when range fits"

# FILE:START-END exceeding PEEK_MAX_LINES clamps to first PEEK_MAX_LINES.
output=$(PEEK_MAX_LINES=10 "$PEEK" "$FIX:1-500")
data_lines=$(printf '%s\n' "$output" | grep -c '^line')
assert_eq "10" "$data_lines" "range: PEEK_MAX_LINES=10 clamps at 10 data lines"
assert_match 'clamped to 10 lines' "$output" "range: footer reports cap"
assert_match 'requested 500' "$output" "range: footer reports requested span"
assert_match 'PEEK_MAX_LINES=N' "$output" "range: footer mentions env override"
# Helper uses `grep -qE`, which treats a leading `--` as end-of-options.
# Anchor the match on the right-side substring to avoid that quirk.
assert_match 'no-cap to widen' "$output" "range: footer mentions --no-cap"

# Clamp keeps the START anchor (head of requested range, not tail).
output=$(PEEK_MAX_LINES=5 "$PEEK" "$FIX:50-100")
first_line=$(printf '%s\n' "$output" | grep '^line' | head -1)
last_data=$(printf '%s\n' "$output" | grep '^line' | tail -1)
assert_eq "line 50" "$first_line" "range clamp: keeps START anchor"
assert_eq "line 54" "$last_data" "range clamp: drops tail past clamp"

# --no-cap returns the full range even when it exceeds PEEK_MAX_LINES.
output=$(PEEK_MAX_LINES=10 "$PEEK" --no-cap "$FIX:1-500")
data_lines=$(printf '%s\n' "$output" | grep -c '^line')
assert_eq "500" "$data_lines" "range --no-cap: returns full range"
assert_not_match 'clamped' "$output" "range --no-cap: suppresses footer"

# Single-int form FILE:START → returns up to PEEK_MAX_LINES from START.
output=$(PEEK_MAX_LINES=20 "$PEEK" "$FIX:100")
data_lines=$(printf '%s\n' "$output" | grep -c '^line')
first_line=$(printf '%s\n' "$output" | grep '^line' | head -1)
assert_eq "20" "$data_lines" "range FILE:N: defaults to PEEK_MAX_LINES rows"
assert_eq "line 100" "$first_line" "range FILE:N: starts at requested line"
# No footer for the single-int form — by construction we never request more
# than PEEK_MAX_LINES, so clamping is a no-op.
assert_not_match 'clamped' "$output" "range FILE:N: no footer (request equals cap)"

# Bare FILE form → first PEEK_MAX_LINES lines (or whole file if smaller).
output=$(PEEK_MAX_LINES=12 "$PEEK" "$FIX")
data_lines=$(printf '%s\n' "$output" | grep -c '^line')
assert_eq "12" "$data_lines" "range bare-file: emits PEEK_MAX_LINES lines"
first_line=$(printf '%s\n' "$output" | head -1)
assert_eq "line 1" "$first_line" "range bare-file: starts at line 1"

# Bare FILE on a small file emits everything (no cap-fire).
small="$TEST_TMPDIR/small.c"
printf 'a\nb\nc\n' > "$small"
output=$("$PEEK" "$small")
assert_eq $'a\nb\nc' "$output" "range bare-file: small file emits everything"

# ── Range error paths ──

# Missing file: short error to stderr, exit 2.
output=$("$PEEK" "$TEST_TMPDIR/no-such-file.c:1-10" 2>&1) && rc=$? || rc=$?
assert_eq "2" "$rc" "range: missing file exits 2"
assert_match 'file not found' "$output" "range: missing file emits clear error"
unset rc

# A bare missing path-like argument must not fall into grep-stdin mode and
# block the agent shell.
output=$(audit_timeout_run 2 "$PEEK" "$TEST_TMPDIR/no-such-file.c" 2>&1) && rc=$? || rc=$?
assert_eq "2" "$rc" "range: bare missing path exits 2 instead of waiting on stdin"
assert_match 'file not found' "$output" "range: bare missing path emits clear error"
unset rc

# Bad range (end < start).
output=$("$PEEK" "$FIX:50-10" 2>&1) && rc=$? || rc=$?
assert_eq "2" "$rc" "range: end<start exits 2"
assert_match 'bad range' "$output" "range: end<start error"
unset rc

# Bad range (non-numeric).
output=$("$PEEK" "$FIX:abc-def" 2>&1) && rc=$? || rc=$?
assert_eq "2" "$rc" "range: non-numeric exits 2"
assert_match 'bad range' "$output" "range: non-numeric error"
unset rc

# Bad range (negative — bash arg parsing accepts this but our validator must reject).
output=$("$PEEK" "$FIX:0-10" 2>&1) && rc=$? || rc=$?
assert_eq "2" "$rc" "range: start<1 exits 2"
unset rc

# PEEK_MAX_LINES=0 means "no cap" (parity with rg-safe RG_CAP=0). Without
# the no-cap translation, every range path collapses to empty/negative.
output=$(PEEK_MAX_LINES=0 "$PEEK" "$FIX:1-500" 2>&1)
data_lines=$(printf '%s\n' "$output" | grep -c '^line')
assert_eq "500" "$data_lines" "range PEEK_MAX_LINES=0: returns full requested range"
assert_not_match 'clamped' "$output" "range PEEK_MAX_LINES=0: no clamp footer"

# PEEK_MAX_LINES=0 in bare-file mode reads the whole file, not zero lines.
output=$(PEEK_MAX_LINES=0 "$PEEK" "$FIX" 2>&1)
data_lines=$(printf '%s\n' "$output" | grep -c '^line')
assert_eq "500" "$data_lines" "range PEEK_MAX_LINES=0 bare-file: emits full file"

# PEEK_MAX_LINES=0 with FILE:N reads from N to EOF.
output=$(PEEK_MAX_LINES=0 "$PEEK" "$FIX:200" 2>&1)
data_lines=$(printf '%s\n' "$output" | grep -c '^line')
assert_eq "301" "$data_lines" "range PEEK_MAX_LINES=0 FILE:N: emits from N to EOF"
first_line=$(printf '%s\n' "$output" | grep '^line' | head -1)
assert_eq "line 200" "$first_line" "range PEEK_MAX_LINES=0 FILE:N: starts at requested line"

# ──────────────────────────────────────────────────────────────────────
# Grep mode (-A / -B / -C clamping)
# ──────────────────────────────────────────────────────────────────────

# Build a fixture with one obvious anchor surrounded by lots of context.
GFIX="$TEST_TMPDIR/grep.c"
{
  for i in $(seq 1 100); do echo "ctx-before-$i"; done
  echo "ANCHOR_LINE"
  for i in $(seq 1 100); do echo "ctx-after-$i"; done
} > "$GFIX"

# -A 100 must clamp to PEEK_GREP_AFTER (default 30).
output=$("$PEEK" -A 100 'ANCHOR_LINE' "$GFIX" 2>&1)
after_count=$(printf '%s\n' "$output" | grep -c '^ctx-after-')
assert_eq "30" "$after_count" "grep -A 100: clamped to default 30"
assert_match 'clamped grep context -A 100->30' "$output" "grep -A: footer reports clamp"

# -A 30 (at the cap) must NOT trigger the clamp footer.
output=$("$PEEK" -A 30 'ANCHOR_LINE' "$GFIX" 2>&1)
assert_not_match 'clamped' "$output" "grep -A 30 (at cap): no footer"

# -A 5 (under the cap) passes through verbatim.
output=$("$PEEK" -A 5 'ANCHOR_LINE' "$GFIX" 2>&1)
after_count=$(printf '%s\n' "$output" | grep -c '^ctx-after-')
assert_eq "5" "$after_count" "grep -A 5: under cap, passes through"

# -B 50 must clamp to PEEK_GREP_BEFORE (default 8).
output=$("$PEEK" -B 50 'ANCHOR_LINE' "$GFIX" 2>&1)
before_count=$(printf '%s\n' "$output" | grep -c '^ctx-before-')
assert_eq "8" "$before_count" "grep -B 50: clamped to default 8"
assert_match 'clamped grep context -B 50->8' "$output" "grep -B: footer reports clamp"

# Joined form -A30 / -B30 also gets clamped.
output=$("$PEEK" -A50 'ANCHOR_LINE' "$GFIX" 2>&1)
after_count=$(printf '%s\n' "$output" | grep -c '^ctx-after-')
assert_eq "30" "$after_count" "grep -A50 (joined): clamped"
assert_match 'A 50->30' "$output" "grep -A50: footer mentions clamp"

# Long form --after-context=N also clamps.
output=$("$PEEK" --after-context=99 'ANCHOR_LINE' "$GFIX" 2>&1)
after_count=$(printf '%s\n' "$output" | grep -c '^ctx-after-')
assert_eq "30" "$after_count" "grep --after-context=99: clamped"

# -C N (combined) splits to -A and -B with their own clamps.
output=$("$PEEK" -C 60 'ANCHOR_LINE' "$GFIX" 2>&1)
after_count=$(printf '%s\n' "$output" | grep -c '^ctx-after-')
before_count=$(printf '%s\n' "$output" | grep -c '^ctx-before-')
assert_eq "30" "$after_count" "grep -C 60: after clamped to 30"
assert_eq "8" "$before_count" "grep -C 60: before clamped to 8"
assert_match 'A 60->30' "$output" "grep -C: footer reports A clamp"
assert_match 'B 60->8' "$output" "grep -C: footer reports B clamp"

# --no-cap disables grep clamping entirely.
output=$("$PEEK" --no-cap -A 100 -B 50 'ANCHOR_LINE' "$GFIX" 2>&1)
after_count=$(printf '%s\n' "$output" | grep -c '^ctx-after-')
before_count=$(printf '%s\n' "$output" | grep -c '^ctx-before-')
assert_eq "100" "$after_count" "grep --no-cap: -A 100 passes through"
assert_eq "50" "$before_count" "grep --no-cap: -B 50 passes through"
assert_not_match 'clamped' "$output" "grep --no-cap: suppresses footer"

# Env knobs override defaults.
output=$(PEEK_GREP_AFTER=3 "$PEEK" -A 100 'ANCHOR_LINE' "$GFIX" 2>&1)
after_count=$(printf '%s\n' "$output" | grep -c '^ctx-after-')
assert_eq "3" "$after_count" "grep PEEK_GREP_AFTER=3: env override honored"

output=$(PEEK_GREP_BEFORE=2 "$PEEK" -B 100 'ANCHOR_LINE' "$GFIX" 2>&1)
before_count=$(printf '%s\n' "$output" | grep -c '^ctx-before-')
assert_eq "2" "$before_count" "grep PEEK_GREP_BEFORE=2: env override honored"

# Exit code passes through grep semantics.
"$PEEK" 'ANCHOR_LINE' "$GFIX" >/dev/null 2>&1
assert_eq "0" "$?" "grep: exit 0 on match"

"$PEEK" 'NEVER_APPEARS_ANYWHERE' "$GFIX" >/dev/null 2>&1
assert_eq "1" "$?" "grep: exit 1 on no match"

# Non-numeric env knob rejected.
output=$(PEEK_GREP_AFTER=abc "$PEEK" 'ANCHOR_LINE' "$GFIX" 2>&1) && rc=$? || rc=$?
assert_eq "2" "$rc" "env: non-numeric PEEK_GREP_AFTER exits 2"
assert_match 'non-numeric' "$output" "env: non-numeric PEEK_GREP_AFTER reports cleanly"
unset rc

# ──────────────────────────────────────────────────────────────────────
# Mode-detection edge cases
# ──────────────────────────────────────────────────────────────────────

# A pattern that contains `:` but doesn't name a real file should fall
# into grep mode. Otherwise we'd misroute `bin/peek 'foo:bar' file.c`.
PATFILE="$TEST_TMPDIR/pat.c"
echo 'foo:bar appears here' > "$PATFILE"
output=$("$PEEK" 'foo:bar' "$PATFILE" 2>&1)
assert_match 'foo:bar appears here' "$output" "mode: pattern with colon routes to grep"

# Empty arg list prints usage to stderr.
output=$("$PEEK" 2>&1) && rc=$? || rc=$?
assert_eq "2" "$rc" "no args: exit 2"
assert_match 'Usage' "$output" "no args: prints usage"
unset rc

# --help prints usage and exits 0.
"$PEEK" --help >/dev/null 2>&1
assert_eq "0" "$?" "--help: exits 0"

# ─────────────────────────────────────────────────────────────────────────────
# Production-PATH interaction: lib/wrappers/{sed,grep} sit on PATH in the
# agent shell. Without explicit cap suppression in peek, peek's internal
# `sed -n '1,Np'` and `grep -A N` calls resolve to the wrappers, which clip
# at 200 lines / 128 KiB. That silently breaks --no-cap (peek thinks it's
# returning the full range; the wrapper has already clipped).
# ─────────────────────────────────────────────────────────────────────────────

WRAPPED_PATH="$SCRIPT_ROOT/lib/wrappers:$PATH"
BIG="$TEST_TMPDIR/big.txt"
seq 1 500 > "$BIG"

# --no-cap on a 500-line range must return all 500 lines.
output=$(PATH="$WRAPPED_PATH" "$PEEK" --no-cap "$BIG":1-500 2>&1)
line_count=$(printf '%s\n' "$output" | wc -l | tr -d ' ')
assert_eq "500" "$line_count" "peek (wrapped PATH): --no-cap returns full 500 lines"

# Default range view still clamps at PEEK_MAX_LINES (200) — the wrapper cap
# is suppressed, so peek's own clamp is the one in effect.
output=$(PATH="$WRAPPED_PATH" "$PEEK" "$BIG":1-500 2>&1)
data_lines=$(printf '%s\n' "$output" | grep -c '^[0-9]')
assert_eq "200" "$data_lines" "peek (wrapped PATH): default clamp keeps own 200-line limit"
assert_match 'clamped to 200 lines' "$output" "peek (wrapped PATH): own footer fires (not wrapper's)"
assert_not_match 'output truncated to 200' "$output" "peek (wrapped PATH): wrapper footer suppressed"

# Grep mode --no-cap with many matches passes full output through.
MANY="$TEST_TMPDIR/many.txt"
seq 1 500 | sed 's/$/ match/' > "$MANY"
output=$(PATH="$WRAPPED_PATH" "$PEEK" --no-cap match "$MANY" 2>&1)
match_lines=$(printf '%s\n' "$output" | grep -c 'match')
assert_eq "500" "$match_lines" "peek grep --no-cap (wrapped PATH): all 500 matches returned"

# ──────────────────────────────────────────────────────────────────────
# Output-cap integration (lib/output_cap.sh) — the line cap alone doesn't
# defend against a 200-line file where each line is 1 KB; the new byte cap
# does. Range mode and grep mode both flow through cap_output_file.
# ──────────────────────────────────────────────────────────────────────

# A 200-line file at ~1 KB / line → ~200 KB, well over the 50 KB cap. The
# line cap (PEEK_MAX_LINES=200 by default) won't fire because the request
# fits the line budget; only the byte cap can save the agent here.
LONGLINES="$TEST_TMPDIR/longlines.c"
python3 -c '
import sys
for i in range(200):
    pad = "x" * 1000
    sys.stdout.write(f"line-{i:03d}-{pad}\n")
' > "$LONGLINES"

output=$("$PEEK" "$LONGLINES:1-200")
out_bytes=$(printf '%s' "$output" | wc -c | tr -d ' ')
[ "$out_bytes" -le 56000 ] && pass "peek range: byte cap fires on long-line files (got ${out_bytes} bytes)" \
  || fail "peek range: expected ≤56000 bytes, got ${out_bytes}"
assert_match 'output_cap: peek-range truncated' "$output" \
  "peek range: byte-cap marker emitted with peek-range label"
assert_match 'line-000-' "$output" "peek range: head preserved"
assert_match 'line-199-' "$output" "peek range: tail preserved"

# --no-cap should bypass both line clamp AND byte cap.
output=$("$PEEK" --no-cap "$LONGLINES:1-200")
assert_not_match 'output_cap:' "$output" "peek range --no-cap: byte cap suppressed"
out_bytes=$(printf '%s' "$output" | wc -c | tr -d ' ')
[ "$out_bytes" -gt 180000 ]
assert_eq 0 $? "peek range --no-cap: full content returned (got ${out_bytes} bytes)"

# OUTCAP_MAX_BYTES=0 disables byte cap independent of --no-cap.
output=$(OUTCAP_MAX_BYTES=0 "$PEEK" "$LONGLINES:1-200")
assert_not_match 'output_cap:' "$output" "peek range OUTCAP_MAX_BYTES=0: byte cap suppressed"

# Grep mode: many matches, each with substantial context, can blow past
# 50 KB even with the line cap not yet firing. Build a fixture where the
# matches are paired with long surrounding lines so -A/-B amplifies bytes.
GREPFIX="$TEST_TMPDIR/grepfix.c"
python3 -c '
for i in range(100):
    print("x" * 800)
    print(f"hit-{i:03d} match-token")
    print("y" * 800)
' > "$GREPFIX"

output=$("$PEEK" -A 5 -B 5 'match-token' "$GREPFIX")
out_bytes=$(printf '%s' "$output" | wc -c | tr -d ' ')
[ "$out_bytes" -le 56000 ] && pass "peek grep: byte cap fires on context-heavy match (got ${out_bytes} bytes)" \
  || fail "peek grep: expected ≤56000 bytes, got ${out_bytes}"
assert_match 'output_cap: peek-grep truncated' "$output" \
  "peek grep: byte-cap marker emitted with peek-grep label"

teardown_test_env
summary
