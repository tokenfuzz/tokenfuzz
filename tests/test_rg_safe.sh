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
python3 -m py_compile "$RG_SAFE" 2>/dev/null
assert_eq 0 $? "rg-safe: syntax check passes"

# ── Line cap removed: output under the byte cap passes through whole. ──
output=$("$RG_SAFE" match "$FIX" 2>&1)
data_lines=$(printf '%s\n' "$output" | grep -c '^line')
assert_eq "500" "$data_lines" "rg-safe: full result passes through (byte cap is the only guard)"
assert_not_match 'capped at' "$output" "rg-safe: no cap footer under the byte budget"

# ── --no-cap suppresses the byte cap too; small output unchanged. ──
output=$("$RG_SAFE" --no-cap match "$FIX" 2>&1)
data_lines=$(printf '%s\n' "$output" | grep -c '^line')
assert_eq "500" "$data_lines" "rg-safe: --no-cap returns all matches"
assert_not_match 'capped at' "$output" "rg-safe: --no-cap suppresses footer"

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

# ── Pass-through of -- separator: args after -- go to rg verbatim. ──
output=$("$RG_SAFE" -- match "$FIX" 2>&1)
data_lines=$(printf '%s\n' "$output" | grep -c '^line')
assert_eq "500" "$data_lines" "rg-safe: '--' passthrough returns all matches"

# ── PATH lookup failure: invoking with no rg in PATH returns helpful error.
# Invoke through an absolute bash path so PATH can be completely isolated.
mkdir -p "$TEST_TMPDIR/no-rg-bin"
PYTHON_BIN=$(command -v python3)
output=$(PATH="$TEST_TMPDIR/no-rg-bin" "$PYTHON_BIN" "$RG_SAFE" foo "$SMALL" 2>&1) || true
assert_match 'rg .ripgrep. not found' "$output" "rg-safe: helpful error when rg missing"

# ─────────────────────────────────────────────────────────────────────────────
# Byte cap (RG_BYTES / --cap-bytes) — the line cap is useless against
# haystacks where a single match line is itself very large (e.g. .log.raw).
# ─────────────────────────────────────────────────────────────────────────────

# Single line of ~150 KiB, well over the 50 KB default head+tail cap and
# also over the former 128 KiB threshold, but only 1 line so the line cap
# never fires.
HUGE_LINE="$TEST_TMPDIR/huge_line.txt"
python3 -c 'import sys; sys.stdout.write("X" * 150000 + " match\n")' > "$HUGE_LINE"

# The default routes through the shared head+tail+spill helper. The total
# emitted should be at most ~55 KB (50 KB head+tail + marker overhead).
output=$("$RG_SAFE" match "$HUGE_LINE" 2>&1)
output_bytes=$(printf '%s' "$output" | wc -c | tr -d ' ')
[ "$output_bytes" -le 56000 ] && pass "rg-safe: helper-path caps single huge match line (got ${output_bytes} bytes)" \
  || fail "rg-safe: helper-path expected ≤56000 bytes, got ${output_bytes}"
assert_match 'output_cap: rg-safe truncated' "$output" \
  "rg-safe: default-cap path emits output_cap marker"
assert_match 'OUTCAP_MAX_BYTES=0 to disable' "$output" \
  "rg-safe: output_cap marker advertises the disable knob"

# Explicit RG_BYTES changes the shared head+tail threshold.
output=$(RG_BYTES=65536 "$RG_SAFE" match "$HUGE_LINE" 2>&1)
assert_match 'output_cap: rg-safe truncated' "$output" \
  "rg-safe: explicit RG_BYTES uses shared output cap"

# RG_BYTES env override: 8 KiB.
output=$(RG_BYTES=8192 "$RG_SAFE" match "$HUGE_LINE" 2>&1)
output_bytes=$(printf '%s' "$output" | wc -c | tr -d ' ')
[ "$output_bytes" -le 9000 ] && pass "rg-safe: RG_BYTES=8192 honored (got ${output_bytes} bytes)" \
  || fail "rg-safe: RG_BYTES=8192 expected ≤9000 bytes, got ${output_bytes}"
assert_match 'output_cap: rg-safe truncated' "$output" "rg-safe: RG_BYTES emits shared marker"

# --cap-bytes wins over RG_BYTES env.
output=$(RG_BYTES=8192 "$RG_SAFE" --cap-bytes 4096 match "$HUGE_LINE" 2>&1)
output_bytes=$(printf '%s' "$output" | wc -c | tr -d ' ')
[ "$output_bytes" -le 5000 ] && pass "rg-safe: --cap-bytes wins over RG_BYTES env" \
  || fail "rg-safe: --cap-bytes expected ≤5000 bytes, got ${output_bytes}"

# --cap-bytes=N (equals form).
output=$("$RG_SAFE" --cap-bytes=2048 match "$HUGE_LINE" 2>&1)
output_bytes=$(printf '%s' "$output" | wc -c | tr -d ' ')
[ "$output_bytes" -le 3000 ] && pass "rg-safe: --cap-bytes=N (equals form)" \
  || fail "rg-safe: --cap-bytes=N expected ≤3000 bytes, got ${output_bytes}"

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
assert_not_match 'capped at' "$output" "rg-safe: --no-cap disables the byte cap"

# Byte cap fires on a large multi-line result set.
COMBO="$TEST_TMPDIR/combo.txt"
python3 -c '
for i in range(500):
    print("Y" * 200 + f" match {i}")
' > "$COMBO"
output=$("$RG_SAFE" --cap-bytes 4096 match "$COMBO" 2>&1)
assert_match 'output_cap: rg-safe truncated' "$output" "rg-safe: byte cap fires on large result set"

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
# Default exclusions — the harness output-logs tree and VCS metadata. The
# harness writes self-output under `output/`, so `**/output/**/logs/**` hides
# every self-output file (transcripts, prompt dumps, recon logs, index.*, .raw/
# spills, and the vendored .gemini-home/) while a target's own source under a
# `logs/` package (no output/ ancestor) stays searchable. Source a target keeps
# under its own output/.../logs/ is also hidden (accepted: output/ is normally
# build output; --include-logs reaches it). .git/ and .hg/ are always excluded.
# ─────────────────────────────────────────────────────────────────────────────

LOGTREE="$TEST_TMPDIR/logtree"
mkdir -p "$LOGTREE/output/foo/codex/logs/.raw" \
  "$LOGTREE/output/foo/codex/logs/.gemini-home/chats" \
  "$LOGTREE/output/foo/codex/.git" "$LOGTREE/output/foo/codex/.hg" \
  "$LOGTREE/targets/foo/src/logs" "$LOGTREE/targets/foo/src/.raw" \
  "$LOGTREE/targets/foo/output/pkg/logs"
# Target source: a real logs/ package, a non-harness .raw/ corpus dir, and a
# source file under a nested output/.../logs/ (accepted collateral exclusion).
echo 'PATCH-deadbeef found here' > "$LOGTREE/targets/foo/src/code.c"
echo 'PATCH-deadbeef found here' > "$LOGTREE/targets/foo/src/logs/parser.c"
echo 'PATCH-deadbeef found here' > "$LOGTREE/targets/foo/src/.raw/corpus.txt"
echo 'PATCH-deadbeef found here' > "$LOGTREE/targets/foo/output/pkg/logs/source.c"
# Harness self-output under output/**/logs/ — including the top-level prompt/
# recon logs that a file-basename list historically leaked, plus the vendored
# gemini home.
echo 'PATCH-deadbeef found here' > "$LOGTREE/output/foo/codex/logs/.raw/session_x.prompt.md"
echo 'PATCH-deadbeef found here' > "$LOGTREE/output/foo/codex/logs/recon_1.log"
echo 'PATCH-deadbeef found here' > "$LOGTREE/output/foo/codex/logs/sess.log.raw"
echo 'PATCH-deadbeef found here' > "$LOGTREE/output/foo/codex/logs/.raw/session.raw"
echo 'PATCH-deadbeef found here' > "$LOGTREE/output/foo/codex/logs/index.log"
echo 'PATCH-deadbeef found here' > "$LOGTREE/output/foo/codex/logs/session_x.log"
echo 'PATCH-deadbeef found here' > "$LOGTREE/output/foo/codex/logs/.gemini-home/chats/s.jsonl"
echo 'PATCH-deadbeef found here' > "$LOGTREE/output/foo/codex/.git/HEAD"
echo 'PATCH-deadbeef found here' > "$LOGTREE/output/foo/codex/.hg/store"

# Default: target src/logs/ matches; nothing under any output/**/logs/ does —
# neither harness logs nor a target's own output/.../logs/ source.
output=$("$RG_SAFE" 'PATCH-deadbeef' "$LOGTREE" 2>&1)
assert_match 'src/code\.c' "$output" "rg-safe: default scan finds source matches"
assert_match 'src/logs/parser\.c' "$output" \
  "rg-safe: default scan does not hide target source dirs named logs"
assert_not_match 'output/pkg/logs/source\.c' "$output" \
  "rg-safe: default excludes any output/**/logs (incl. a target's own; --include-logs reaches it)"
assert_not_match 'session_x\.prompt\.md' "$output" "rg-safe: default excludes prompt dumps under output logs"
assert_not_match 'recon_1\.log' "$output" "rg-safe: default excludes recon logs under output logs"
assert_not_match 'sess\.log\.raw' "$output" "rg-safe: default excludes *.log.raw under output logs"
assert_not_match 'codex/logs/\.raw/session\.raw' "$output" "rg-safe: default excludes output logs/.raw/"
assert_not_match 'codex/logs/index\.log' "$output" "rg-safe: default excludes index.log"
assert_not_match 'session_x\.log:' "$output" "rg-safe: default excludes session text logs"
assert_not_match '\.git/HEAD' "$output" "rg-safe: default excludes .git/"
assert_not_match '\.hg/store' "$output" "rg-safe: default excludes .hg/"

# With --hidden, ripgrep searches dotdirs. The output-logs glob still hides the
# vendored gemini home and .raw/ spill; a non-harness .raw/ under target source
# stays visible.
output=$("$RG_SAFE" --hidden 'PATCH-deadbeef' "$LOGTREE" 2>&1)
assert_match 'src/\.raw/corpus\.txt' "$output" \
  "rg-safe: --hidden keeps non-log .raw dirs under target source"
assert_not_match 'gemini-home' "$output" "rg-safe: --hidden still excludes vendored home under output logs"
assert_not_match 'codex/logs/\.raw/session\.raw' "$output" "rg-safe: --hidden still excludes output logs/.raw/"
assert_not_match '\.git/HEAD' "$output" "rg-safe: --hidden still excludes .git/"
assert_not_match '\.hg/store' "$output" "rg-safe: --hidden still excludes .hg/"

# --include-logs: matches under output logs too, but VCS metadata stays excluded.
output=$("$RG_SAFE" --include-logs 'PATCH-deadbeef' "$LOGTREE" 2>&1)
assert_match 'src/code\.c' "$output" "rg-safe: --include-logs still finds source matches"
assert_match 'session_x\.log' "$output" "rg-safe: --include-logs allows output logs"
assert_match 'codex/logs/index\.log' "$output" "rg-safe: --include-logs allows codex/logs/"
assert_not_match '\.git/HEAD' "$output" "rg-safe: --include-logs still excludes .git/"
assert_not_match '\.hg/store' "$output" "rg-safe: --include-logs still excludes .hg/"

# RG_INCLUDE_LOGS=1 also drops the output-logs exclusion.
output=$(RG_INCLUDE_LOGS=1 "$RG_SAFE" 'PATCH-deadbeef' "$LOGTREE" 2>&1)
assert_match 'session_x\.log' "$output" "rg-safe: RG_INCLUDE_LOGS=1 env honored"

# Caller --glob still works alongside the default exclusions.
output=$(cd "$LOGTREE" && "$RG_SAFE" --glob '!**/src/**' 'PATCH-deadbeef' . 2>&1) || true
assert_not_match 'src/code\.c' "$output" "rg-safe: caller --glob still applies"
assert_not_match 'sess\.log\.raw' "$output" "rg-safe: default log exclusion still applies under caller --glob"

# The byte-cap clip works when scanning a real .log.raw via --include-logs:
# build a single huge JSON line (the actual pathology in production —
# observed up to ~1 MB per turn) and confirm the default head+tail cap fires.
HUGE_RAW="$LOGTREE/output/foo/codex/logs/huge.log.raw"
python3 -c '
import sys, json
payload = {"command": "/bin/zsh -lc rg-safe match", "aggregated_output": "X" * 200000}
sys.stdout.write(json.dumps({"type":"item.completed","item":payload}) + "\n")
' > "$HUGE_RAW"
output=$("$RG_SAFE" --include-logs 'aggregated_output' "$HUGE_RAW" 2>&1)
output_bytes=$(printf '%s' "$output" | wc -c | tr -d ' ')
[ "$output_bytes" -le 56000 ] && pass "rg-safe: byte cap fires on real .log.raw shape (got ${output_bytes})" \
  || fail "rg-safe: byte cap should head+tail cap .log.raw scan, got ${output_bytes} bytes"

# ─────────────────────────────────────────────────────────────────────────────
# Production-PATH interaction: lib/wrappers/rg sits on PATH in the agent shell
# (see lib/wrappers/_zdotdir/.zprofile). rg-safe suppresses the inherited
# wrapper cap so it can apply its own byte cap once, without double-capping.
# ─────────────────────────────────────────────────────────────────────────────

WRAPPED_PATH="$SCRIPT_ROOT/lib/wrappers:$PATH"

# --no-cap with wrappers on PATH must return ALL matches.
output=$(PATH="$WRAPPED_PATH" "$RG_SAFE" --no-cap match "$FIX" 2>&1)
data_lines=$(printf '%s\n' "$output" | grep -c '^line')
assert_eq "500" "$data_lines" "rg-safe (wrapped PATH): --no-cap returns all 500 matches"
assert_not_match 'capped at' "$output" "rg-safe (wrapped PATH): --no-cap suppresses the footer"

# A result set under the byte cap passes through whole (no double-cap).
output=$(PATH="$WRAPPED_PATH" "$RG_SAFE" match "$FIX" 2>&1)
data_lines=$(printf '%s\n' "$output" | grep -c '^line')
assert_eq "500" "$data_lines" "rg-safe (wrapped PATH): full result passes through, no double-cap"

# Finding 1 regression: --include-logs must actually re-expose output logs even
# with lib/wrappers/rg first on PATH. rg-safe execs the real rg (skipping the
# wrapper), so the wrapper's own log glob can't silently undo the escape hatch.
output=$(PATH="$WRAPPED_PATH" AGENT_WRAPPERS_PATH="$SCRIPT_ROOT/lib/wrappers" \
  "$RG_SAFE" --include-logs -l 'PATCH-deadbeef' "$LOGTREE" 2>&1)
assert_match 'session_x\.log' "$output" \
  "rg-safe (wrapped PATH): --include-logs re-exposes output logs (Finding 1)"
# And the default still excludes them under the wrapped PATH.
output=$(PATH="$WRAPPED_PATH" AGENT_WRAPPERS_PATH="$SCRIPT_ROOT/lib/wrappers" \
  "$RG_SAFE" -l 'PATCH-deadbeef' "$LOGTREE" 2>&1) || true
assert_not_match 'session_x\.log' "$output" \
  "rg-safe (wrapped PATH): default still excludes output logs"

# Byte-cap escape (RG_BYTES=0) must also pass full huge match through, not
# silently clip at the wrapper's default.
output=$(PATH="$WRAPPED_PATH" RG_BYTES=0 "$RG_SAFE" match "$HUGE_LINE" 2>&1)
output_bytes=$(printf '%s' "$output" | wc -c | tr -d ' ')
[ "$output_bytes" -ge 150000 ] && pass "rg-safe (wrapped PATH): RG_BYTES=0 bypasses both byte caps (got ${output_bytes})" \
  || fail "rg-safe (wrapped PATH): RG_BYTES=0 must pass full huge line, got ${output_bytes}"

teardown_test_env
summary
