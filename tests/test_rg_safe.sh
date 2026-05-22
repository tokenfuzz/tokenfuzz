#!/usr/bin/env bash
# Tests for bin/rg-safe — output cap with opt-out, exit-code passthrough.
set -o pipefail
source "$(dirname "$0")/helpers.sh"
setup_test_env

RG_SAFE="$SCRIPT_ROOT/bin/rg-safe"

# Skip if rg is not installed (CI environments without ripgrep).
if ! command -v rg >/dev/null 2>&1; then
  pass "rg-safe: ripgrep not installed, skipping suite"
  teardown_test_env
  summary
  exit 0
fi

# ── Fixture: a file with N matching lines so the cap can fire. ──
FIX="$TEST_TMPDIR/big.txt"
i=1
while [ "$i" -le 500 ]; do
  printf 'line %d match\n' "$i" >> "$FIX"
  i=$((i + 1))
done

# ── Syntax check ──
bash -n "$RG_SAFE" 2>/dev/null
assert_eq 0 $? "rg-safe: syntax check passes"

# ── Default cap is 200; footer fires when total > cap. ──
output=$("$RG_SAFE" match "$FIX" 2>&1)
data_lines=$(printf '%s\n' "$output" | grep -c '^line')
assert_eq "200" "$data_lines" "rg-safe: default cap keeps exactly 200 data lines"
assert_match 'capped at 200 of 500 lines' "$output" "rg-safe: footer reports cap and total"
assert_match 'RG_CAP=0' "$output" "rg-safe: footer mentions opt-out"

# Last data line is line 200 — head from top, not tail.
assert_match '^line 200 match$' "$output" "rg-safe: keeps head (lines 1..N)"
assert_not_match '^line 201 match$' "$output" "rg-safe: drops past-cap lines"

# ── --cap N overrides default. ──
output=$("$RG_SAFE" --cap 50 match "$FIX" 2>&1)
data_lines=$(printf '%s\n' "$output" | grep -c '^line')
assert_eq "50" "$data_lines" "rg-safe: --cap N caps at N"
assert_match 'capped at 50 of 500' "$output" "rg-safe: --cap reflected in footer"

# ── --cap=N (= form) also works. ──
output=$("$RG_SAFE" --cap=25 match "$FIX" 2>&1)
data_lines=$(printf '%s\n' "$output" | grep -c '^line')
assert_eq "25" "$data_lines" "rg-safe: --cap=N (equals form)"

# ── RG_CAP env var overrides default; --cap flag wins over env. ──
output=$(RG_CAP=10 "$RG_SAFE" match "$FIX" 2>&1)
data_lines=$(printf '%s\n' "$output" | grep -c '^line')
assert_eq "10" "$data_lines" "rg-safe: RG_CAP env var honored"

output=$(RG_CAP=10 "$RG_SAFE" --cap 30 match "$FIX" 2>&1)
data_lines=$(printf '%s\n' "$output" | grep -c '^line')
assert_eq "30" "$data_lines" "rg-safe: --cap wins over RG_CAP env"

# ── --no-cap bypasses entirely; no footer. ──
output=$("$RG_SAFE" --no-cap match "$FIX" 2>&1)
data_lines=$(printf '%s\n' "$output" | grep -c '^line')
assert_eq "500" "$data_lines" "rg-safe: --no-cap returns all matches"
assert_not_match 'capped at' "$output" "rg-safe: --no-cap suppresses footer"

# ── RG_CAP=0 also bypasses. ──
output=$(RG_CAP=0 "$RG_SAFE" match "$FIX" 2>&1)
data_lines=$(printf '%s\n' "$output" | grep -c '^line')
assert_eq "500" "$data_lines" "rg-safe: RG_CAP=0 bypasses cap"
assert_not_match 'capped at' "$output" "rg-safe: RG_CAP=0 suppresses footer"

# ── Output below cap is byte-identical to plain rg, no footer. ──
SMALL="$TEST_TMPDIR/small.txt"
printf 'foo\nbar\nbaz\n' > "$SMALL"
output=$("$RG_SAFE" 'a' "$SMALL" 2>&1)
expected=$(rg 'a' "$SMALL")
assert_eq "$expected" "$output" "rg-safe: small output is byte-identical to rg"

# ── Exit code passes through: rg returns 1 when no match. ──
"$RG_SAFE" 'unobtainium-zzzzz' "$SMALL" >/dev/null 2>&1
assert_eq "1" "$?" "rg-safe: exit code 1 for no match (rg semantics)"

"$RG_SAFE" 'foo' "$SMALL" >/dev/null 2>&1
assert_eq "0" "$?" "rg-safe: exit code 0 on match"

# ── Invalid --cap value rejected with explanatory error. ──
output=$("$RG_SAFE" --cap notanumber match "$FIX" 2>&1) || true
assert_match 'non-numeric --cap' "$output" "rg-safe: rejects non-numeric --cap"

# ── --cap with no value errors out. ──
"$RG_SAFE" --cap 2>/dev/null
assert_neq "0" "$?" "rg-safe: --cap with no value exits non-zero"

# ── Pass-through of -- separator: args after -- go to rg verbatim. ──
output=$("$RG_SAFE" --cap 5 -- match "$FIX" 2>&1)
data_lines=$(printf '%s\n' "$output" | grep -c '^line')
assert_eq "5" "$data_lines" "rg-safe: '--' passthrough still respects cap"

# ── PATH lookup failure: invoking with no rg in PATH returns helpful error.
# Invoke through an absolute bash path so PATH can be completely isolated.
mkdir -p "$TEST_TMPDIR/no-rg-bin"
output=$(PATH="$TEST_TMPDIR/no-rg-bin" /bin/bash "$RG_SAFE" foo "$SMALL" 2>&1) || true
assert_match 'rg .ripgrep. not found' "$output" "rg-safe: helpful error when rg missing"

# ─────────────────────────────────────────────────────────────────────────────
# Byte cap (RG_BYTES / --cap-bytes) — the line cap is useless against
# haystacks where a single match line is itself very large (e.g. .log.raw).
# ─────────────────────────────────────────────────────────────────────────────

# Single line of ~150 KiB, well over the 50 KB default head+tail cap and
# also over the legacy 128 KiB byte cap, but only 1 line so the line cap
# never fires.
HUGE_LINE="$TEST_TMPDIR/huge_line.txt"
python3 -c 'import sys; sys.stdout.write("X" * 150000 + " match\n")' > "$HUGE_LINE"

# With the default RG_BYTES (131072), rg-safe routes through the head+tail+
# spill helper from lib/output_cap.sh — strictly more informative than the
# legacy "capped at N of M bytes" footer. The total emitted should be at
# most ~55 KB (50 KB head+tail + marker overhead), well under the legacy
# 128 KiB ceiling.
output=$("$RG_SAFE" match "$HUGE_LINE" 2>&1)
output_bytes=$(printf '%s' "$output" | wc -c | tr -d ' ')
[ "$output_bytes" -le 56000 ] && pass "rg-safe: helper-path caps single huge match line (got ${output_bytes} bytes)" \
  || fail "rg-safe: helper-path expected ≤56000 bytes, got ${output_bytes}"
assert_match 'output_cap: rg-safe truncated' "$output" \
  "rg-safe: default-cap path emits output_cap marker"
assert_match 'OUTCAP_MAX_BYTES=0 to disable' "$output" \
  "rg-safe: output_cap marker advertises the disable knob"

# Legacy clip-and-footer path is still reachable via explicit RG_BYTES.
# This proves callers that pinned the historical contract still get it.
output=$(RG_BYTES=65536 "$RG_SAFE" match "$HUGE_LINE" 2>&1)
assert_match 'capped at 65536 of' "$output" \
  "rg-safe: explicit RG_BYTES uses legacy chop-and-footer path"

# RG_BYTES env override: 8 KiB.
output=$(RG_BYTES=8192 "$RG_SAFE" match "$HUGE_LINE" 2>&1)
output_bytes=$(printf '%s' "$output" | wc -c | tr -d ' ')
[ "$output_bytes" -le 9000 ] && pass "rg-safe: RG_BYTES=8192 honored (got ${output_bytes} bytes)" \
  || fail "rg-safe: RG_BYTES=8192 expected ≤9000 bytes, got ${output_bytes}"
assert_match 'capped at 8192 of' "$output" "rg-safe: --cap-bytes reflected in footer"

# --cap-bytes wins over RG_BYTES env.
output=$(RG_BYTES=8192 "$RG_SAFE" --cap-bytes 4096 match "$HUGE_LINE" 2>&1)
assert_match 'capped at 4096 of' "$output" "rg-safe: --cap-bytes wins over RG_BYTES env"

# --cap-bytes=N (equals form).
output=$("$RG_SAFE" --cap-bytes=2048 match "$HUGE_LINE" 2>&1)
assert_match 'capped at 2048 of' "$output" "rg-safe: --cap-bytes=N (equals form)"

# RG_BYTES=0 disables byte cap (huge line passes through unclipped).
output=$(RG_BYTES=0 "$RG_SAFE" match "$HUGE_LINE" 2>&1)
output_bytes=$(printf '%s' "$output" | wc -c | tr -d ' ')
[ "$output_bytes" -ge 150000 ] && pass "rg-safe: RG_BYTES=0 bypasses byte cap (got ${output_bytes} bytes)" \
  || fail "rg-safe: RG_BYTES=0 should pass huge match through, got ${output_bytes}"
assert_not_match 'capped at' "$output" "rg-safe: RG_BYTES=0 suppresses footer"

# --no-cap-bytes also disables byte cap.
output=$("$RG_SAFE" --no-cap-bytes match "$HUGE_LINE" 2>&1)
assert_not_match 'capped at' "$output" "rg-safe: --no-cap-bytes disables byte cap"

# --no-cap disables BOTH caps.
output=$("$RG_SAFE" --no-cap match "$HUGE_LINE" 2>&1)
assert_not_match 'capped at' "$output" "rg-safe: --no-cap disables both line and byte caps"

# Both caps fire simultaneously: many lines, each large enough that the
# byte cap also fires before the line cap finishes counting.
COMBO="$TEST_TMPDIR/combo.txt"
python3 -c '
for i in range(500):
    print("Y" * 200 + f" match {i}")
' > "$COMBO"
output=$("$RG_SAFE" --cap 100 --cap-bytes 4096 match "$COMBO" 2>&1)
assert_match 'capped at 100 of 500 lines AND' "$output" "rg-safe: combined footer when both caps fire"
assert_match 'bytes' "$output" "rg-safe: combined footer mentions bytes"

# Byte clip falls back to last newline (no partial trailing line).
output=$("$RG_SAFE" --cap-bytes 500 match "$COMBO" 2>&1)
last_data=$(printf '%s\n' "$output" | grep '^Y' | tail -1)
# Each match line is "Y"*200 + " match N" → at least 207 chars → last data
# line must end with " match <num>" (no mid-line clip).
case "$last_data" in
  *' match '*) pass "rg-safe: byte clip aligns to newline (no partial line)" ;;
  *) fail "rg-safe: byte clip left a partial line: '${last_data:0:80}...'" ;;
esac

# Non-numeric --cap-bytes rejected.
output=$("$RG_SAFE" --cap-bytes notanumber match "$FIX" 2>&1) || true
assert_match 'non-numeric --cap-bytes' "$output" "rg-safe: rejects non-numeric --cap-bytes"

# --cap-bytes with no value errors out.
"$RG_SAFE" --cap-bytes 2>/dev/null
assert_neq "0" "$?" "rg-safe: --cap-bytes with no value exits non-zero"

# Output below both caps: byte-identical to plain rg, no footer.
output=$("$RG_SAFE" 'a' "$SMALL" 2>&1)
expected=$(rg 'a' "$SMALL")
assert_eq "$expected" "$output" "rg-safe: small output stays byte-identical with byte cap added"

# ─────────────────────────────────────────────────────────────────────────────
# Default exclusions — `**/logs/**` and `**/.git/**`. Nothing under a logs/
# directory is searchable by default, regardless of file extension; .git/ is
# always excluded. Audit data showed zero legitimate agent reads inside
# logs/ across 405 sessions, so the broader directory-level exclusion is
# strictly an improvement over file-by-file rules.
# ─────────────────────────────────────────────────────────────────────────────

LOGTREE="$TEST_TMPDIR/logtree"
mkdir -p "$LOGTREE/output/foo/codex/logs" "$LOGTREE/output/foo/codex/.git" "$LOGTREE/source"
echo 'PATCH-deadbeef found here' > "$LOGTREE/source/code.c"
echo 'PATCH-deadbeef found here' > "$LOGTREE/output/foo/codex/logs/sess.log.raw"
echo 'PATCH-deadbeef found here' > "$LOGTREE/output/foo/codex/logs/index.log"
echo 'PATCH-deadbeef found here' > "$LOGTREE/output/foo/codex/logs/index.jsonl"
echo 'PATCH-deadbeef found here' > "$LOGTREE/output/foo/codex/logs/session_x.log"
echo 'PATCH-deadbeef found here' > "$LOGTREE/output/foo/codex/logs/session_x.log.summary.md"
echo 'PATCH-deadbeef found here' > "$LOGTREE/output/foo/codex/.git/HEAD"

# Default: source matches; everything under logs/ and .git/ is skipped.
output=$("$RG_SAFE" 'PATCH-deadbeef' "$LOGTREE" 2>&1)
assert_match 'source/code\.c' "$output" "rg-safe: default scan finds source matches"
assert_not_match 'sess\.log\.raw' "$output" "rg-safe: default excludes *.log.raw under logs/"
assert_not_match 'codex/logs/index\.log' "$output" "rg-safe: default excludes index.log"
assert_not_match 'codex/logs/index\.jsonl' "$output" "rg-safe: default excludes index.jsonl"
assert_not_match 'session_x\.log:' "$output" "rg-safe: default excludes session text logs"
assert_not_match 'session_x\.log\.summary\.md' "$output" "rg-safe: default excludes summary md under logs/"
assert_not_match '\.git/HEAD' "$output" "rg-safe: default excludes .git/"

# --include-logs: matches everywhere under logs/, but .git/ stays excluded.
output=$("$RG_SAFE" --include-logs 'PATCH-deadbeef' "$LOGTREE" 2>&1)
assert_match 'source/code\.c' "$output" "rg-safe: --include-logs still finds source matches"
assert_match 'sess\.log\.raw' "$output" "rg-safe: --include-logs allows *.log.raw"
assert_match 'codex/logs/index\.log' "$output" "rg-safe: --include-logs allows codex/logs/"
assert_not_match '\.git/HEAD' "$output" "rg-safe: --include-logs still excludes .git/"

# RG_INCLUDE_LOGS=1 also drops the logs/ exclusion.
output=$(RG_INCLUDE_LOGS=1 "$RG_SAFE" 'PATCH-deadbeef' "$LOGTREE" 2>&1)
assert_match 'sess\.log\.raw' "$output" "rg-safe: RG_INCLUDE_LOGS=1 env honored"

# Caller --glob still works alongside the default exclusions.
output=$("$RG_SAFE" --glob '!**/source/**' 'PATCH-deadbeef' "$LOGTREE" 2>&1) || true
assert_not_match 'source/code\.c' "$output" "rg-safe: caller --glob still applies"
assert_not_match 'sess\.log\.raw' "$output" "rg-safe: default log exclusion still applies under caller --glob"

# The byte-cap clip works when scanning a real .log.raw via --include-logs:
# build a single huge JSON line (the actual pathology in production —
# observed up to ~1 MB per turn) and confirm byte cap fires at the new
# 128 KiB default.
HUGE_RAW="$LOGTREE/output/foo/codex/logs/huge.log.raw"
python3 -c '
import sys, json
payload = {"command": "/bin/zsh -lc rg-safe match", "aggregated_output": "X" * 200000}
sys.stdout.write(json.dumps({"type":"item.completed","item":payload}) + "\n")
' > "$HUGE_RAW"
output=$("$RG_SAFE" --include-logs 'aggregated_output' "$HUGE_RAW" 2>&1)
output_bytes=$(printf '%s' "$output" | wc -c | tr -d ' ')
[ "$output_bytes" -le 135000 ] && pass "rg-safe: byte cap fires on real .log.raw shape (got ${output_bytes})" \
  || fail "rg-safe: byte cap should clip .log.raw scan, got ${output_bytes} bytes"

# ─────────────────────────────────────────────────────────────────────────────
# Production-PATH interaction: lib/wrappers/rg sits on PATH in the agent shell
# (see lib/wrappers/_zdotdir/.zprofile). Without explicit cap suppression,
# rg-safe's invocation of `rg` resolves to the wrapper, which clips at 200
# lines / 128 KiB BEFORE rg-safe sees the output. That silently breaks
# --no-cap, --cap N>200, and the "X of Y" line-count footer (Y stops at 201).
# These tests exercise the production config to catch any regression.
# ─────────────────────────────────────────────────────────────────────────────

WRAPPED_PATH="$SCRIPT_ROOT/lib/wrappers:$PATH"

# --no-cap with wrappers on PATH must return ALL matches, not 200.
output=$(PATH="$WRAPPED_PATH" "$RG_SAFE" --no-cap match "$FIX" 2>&1)
data_lines=$(printf '%s\n' "$output" | grep -c '^line')
assert_eq "500" "$data_lines" "rg-safe (wrapped PATH): --no-cap returns all 500 matches"
assert_not_match 'capped at' "$output" "rg-safe (wrapped PATH): --no-cap suppresses both footers"

# --cap N>200 must return up to N, not silently top at 200.
output=$(PATH="$WRAPPED_PATH" "$RG_SAFE" --cap 350 match "$FIX" 2>&1)
data_lines=$(printf '%s\n' "$output" | grep -c '^line')
assert_eq "350" "$data_lines" "rg-safe (wrapped PATH): --cap 350 actually returns 350"
assert_match 'capped at 350 of 500' "$output" "rg-safe (wrapped PATH): footer reports true total"

# Default cap (200) footer must report true total (500), not the wrapper's
# pre-clipped 201.
output=$(PATH="$WRAPPED_PATH" "$RG_SAFE" match "$FIX" 2>&1)
assert_match 'capped at 200 of 500 lines' "$output" "rg-safe (wrapped PATH): default footer reports true 500-line total"
assert_not_match 'capped at 200 of 201' "$output" "rg-safe (wrapped PATH): no spurious 'of 201' from double-cap"

# Byte-cap escape (RG_BYTES=0) must also pass full huge match through, not
# silently clip at the wrapper's default.
output=$(PATH="$WRAPPED_PATH" RG_BYTES=0 "$RG_SAFE" match "$HUGE_LINE" 2>&1)
output_bytes=$(printf '%s' "$output" | wc -c | tr -d ' ')
[ "$output_bytes" -ge 150000 ] && pass "rg-safe (wrapped PATH): RG_BYTES=0 bypasses both byte caps (got ${output_bytes})" \
  || fail "rg-safe (wrapped PATH): RG_BYTES=0 must pass full huge line, got ${output_bytes}"

teardown_test_env
summary
