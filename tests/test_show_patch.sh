#!/usr/bin/env bash
# Tests for bin/show-patch — git show wrapper with --unified=$PATCH_CONTEXT.
set -o pipefail
source "$(dirname "$0")/helpers.sh"
setup_test_env

SHOW_PATCH="$SCRIPT_ROOT/bin/show-patch"

if ! command -v git >/dev/null 2>&1; then
  pass "show-patch: git not installed, skipping suite"
  teardown_test_env
  summary
  exit 0
fi

# ── Syntax check ──
bash -n "$SHOW_PATCH" 2>/dev/null
assert_eq 0 $? "show-patch: syntax check passes"

# ── Build a tiny git repo with a commit whose changed function spans
#    enough lines that --unified=20 vs --unified=80 produces different
#    hunk sizes. ──
REPO="$TEST_TMPDIR/repo"
mkdir -p "$REPO"
cd "$REPO" || exit 2
git init -q
git config user.email "test@example.com"
git config user.name "Test"

# Write a file with 200 lines where line 100 is the only line we'll change.
i=1
{
  while [ "$i" -le 200 ]; do
    if [ "$i" -eq 100 ]; then
      printf 'middle line %d ORIGINAL\n' "$i"
    else
      printf 'context line %d\n' "$i"
    fi
    i=$((i + 1))
  done
} > big.c
git add big.c
git commit -qm "initial big.c"

# Modify just line 100.
sed -i.bak 's/ORIGINAL/MODIFIED/' big.c && rm big.c.bak
git add big.c
git commit -qm "tweak middle line"

COMMIT=$(git rev-parse HEAD)

# ── Default: --unified=10 around the single changed line.
output=$("$SHOW_PATCH" "$COMMIT" 2>&1)
assert_match 'middle line 100 MODIFIED' "$output" "show-patch: shows the changed line"
assert_match 'context line 90' "$output" "show-patch: keeps 10 lines of leading context (line 100-10)"
assert_match 'context line 110' "$output" "show-patch: keeps 10 lines of trailing context (line 100+10)"
assert_not_match 'context line 80' "$output" "show-patch: drops context past the default 10-line window"
assert_not_match 'context line 120' "$output" "show-patch: drops trailing context past 10 lines"

# Hunk count: should be exactly 1 hunk header at default unified=10.
hunks=$(printf '%s\n' "$output" | grep -c '^@@')
assert_eq "1" "$hunks" "show-patch: produces a single hunk for one-line change"

# ── PATCH_CONTEXT=80 widens (per-call env override).
output=$(PATCH_CONTEXT=80 "$SHOW_PATCH" "$COMMIT" 2>&1)
assert_match 'context line 30' "$output" "show-patch: PATCH_CONTEXT=80 widens leading context"
assert_match 'context line 170' "$output" "show-patch: PATCH_CONTEXT=80 widens trailing context"

# ── Caller-supplied --unified=N takes precedence over PATCH_CONTEXT.
output=$(PATCH_CONTEXT=20 "$SHOW_PATCH" --unified=60 "$COMMIT" 2>&1)
assert_match 'context line 50' "$output" "show-patch: caller --unified=60 wins over PATCH_CONTEXT"

# ── --stat flag pass-through (no diff narrowing logic should interfere).
output=$("$SHOW_PATCH" --stat "$COMMIT" 2>&1)
assert_match 'big\.c +\| +[0-9]+ +[+-]+' "$output" "show-patch: --stat passthrough lists changed file with diffstat"
# --stat alone produces no diff body, so context lines must NOT appear.
assert_not_match 'context line' "$output" "show-patch: --stat does not emit diff body"

# ── --no-patch (commit-message only) passes through.
output=$("$SHOW_PATCH" --no-patch "$COMMIT" 2>&1)
assert_match 'tweak middle line' "$output" "show-patch: --no-patch passthrough"
assert_not_match 'context line' "$output" "show-patch: --no-patch suppresses diff body"

# ── --no-pager is a top-level git option; tolerate it anywhere agents put it.
output=$("$SHOW_PATCH" "$COMMIT" --no-pager 2>&1)
assert_match 'middle line 100 MODIFIED' "$output" "show-patch: trailing --no-pager tolerated"
output=$("$SHOW_PATCH" --no-pager "$COMMIT" 2>&1)
assert_match 'middle line 100 MODIFIED' "$output" "show-patch: leading --no-pager tolerated"

# ── -U (short form, joined per git syntax) is detected as a user override.
output=$(PATCH_CONTEXT=10 "$SHOW_PATCH" -U40 "$COMMIT" 2>&1)
assert_match 'context line 70' "$output" "show-patch: -U40 widens past default"

# ── No args: usage to stderr, exit 2.
output=$("$SHOW_PATCH" 2>&1) || rc=$?
assert_match 'Usage:' "$output" "show-patch: no args prints usage"
assert_eq "2" "${rc:-0}" "show-patch: no args exits 2"
unset rc

# ── Non-numeric PATCH_CONTEXT errors out before invoking git.
output=$(PATCH_CONTEXT=abc "$SHOW_PATCH" "$COMMIT" 2>&1) || true
assert_match 'non-numeric PATCH_CONTEXT' "$output" "show-patch: rejects non-numeric PATCH_CONTEXT"

# ── Path filter passes through correctly: `-- big.c` keeps the diff
#    scoped to that file (and there's only one anyway).
output=$("$SHOW_PATCH" "$COMMIT" -- big.c 2>&1)
assert_match 'middle line 100 MODIFIED' "$output" "show-patch: path filter passthrough"

# ── TARGET_ROOT makes the wrapper target-repo aware even when launched from
#    the harness repo or another working directory.
cd "$TEST_TMPDIR" || exit 2
output=$(TARGET_ROOT="$REPO" "$SHOW_PATCH" "$COMMIT" -- big.c 2>&1)
assert_match 'middle line 100 MODIFIED' "$output" "show-patch: TARGET_ROOT resolves commits outside cwd"
cd "$REPO" || exit 2

# ── Unknown revision: short, single-line error instead of git's multi-line
#    "ambiguous argument …" splat. Exit code is git's standard 128.
output=$("$SHOW_PATCH" deadbeefdeadbeef 2>&1) && rc=$? || rc=$?
assert_eq "128" "$rc" "show-patch: unknown revision exits 128"
assert_match 'unknown revision: deadbeefdeadbeef' "$output" "show-patch: unknown-rev error is one line"
assert_not_match 'ambiguous argument' "$output" "show-patch: suppresses git's multi-line splat"
assert_not_match "Use '--' to separate" "$output" "show-patch: suppresses git's hint splat"
unset rc

# ── A clearly-bad ref that happens to look path-like must still fail
#    cleanly via the rev-parse pre-check (it's neither a path nor a ref).
output=$("$SHOW_PATCH" not-a-ref-and-not-a-path 2>&1) && rc=$? || rc=$?
assert_eq "128" "$rc" "show-patch: bad ref exits 128"
assert_match 'unknown revision' "$output" "show-patch: bad ref reports unknown revision"
unset rc

# ── Short hash (≥7 chars) of a real commit still resolves through rev-parse.
short=$(printf '%s' "$COMMIT" | cut -c1-12)
output=$("$SHOW_PATCH" "$short" 2>&1)
assert_match 'middle line 100 MODIFIED' "$output" "show-patch: short hash resolves"

# ── PATCH_MAX_LINES caps total output. Build a commit whose diff blows
#    way past 1500 lines so we can verify the clip footer fires and that
#    PATCH_MAX_LINES=0 disables it. ──
BIG_REPO="$TEST_TMPDIR/big-repo"
mkdir -p "$BIG_REPO"
cd "$BIG_REPO" || exit 2
git init -q
git config user.email "test@example.com"
git config user.name "Test"
seq 1 3000 > tab.txt
git add tab.txt
git commit -qm "initial 3000-line table"
seq 1 3000 | sed 's/.*/MODIFIED &/' > tab.txt
git add tab.txt
git commit -qm "rewrite every line"
BIG_COMMIT=$(git rev-parse HEAD)

# Default cap = 1500 lines. Output is 1500 data lines + a 5-line stat tail:
#   blank line, "[show-patch: clipped..." notice, --stat row, "N files changed",
#   "Drill in: ..." line. Disable the byte cap so we isolate the line-cap path.
output=$(PATCH_MAX_BYTES=0 "$SHOW_PATCH" "$BIG_COMMIT" 2>&1)
output_lines=$(printf '%s\n' "$output" | wc -l | tr -d ' ')
assert_eq "1505" "$output_lines" "show-patch: default line cap clips to 1500 + 5-line stat tail"
assert_match 'clipped at 1500 of' "$output" "show-patch: clip notice reports total"
assert_match 'Tree of this commit' "$output" "show-patch: tail header present"
assert_match 'tab\.txt' "$output" "show-patch: --stat tail lists changed file"
assert_match '1 file changed' "$output" "show-patch: --stat tail summary present"
assert_match 'Drill in:' "$output" "show-patch: drill-in hint present"
assert_match 'PATCH_MAX_LINES=0 PATCH_MAX_BYTES=0' "$output" "show-patch: drill-in hint shows both opt-outs"

# Custom PATCH_MAX_LINES caps to that value (200 + 5-line stat tail).
output=$(PATCH_MAX_BYTES=0 PATCH_MAX_LINES=200 "$SHOW_PATCH" "$BIG_COMMIT" 2>&1)
output_lines=$(printf '%s\n' "$output" | wc -l | tr -d ' ')
assert_eq "205" "$output_lines" "show-patch: PATCH_MAX_LINES=200 caps at 200 + 5-line tail"

# Both caps off = unbounded output, no clip notice.
output=$(PATCH_MAX_LINES=0 PATCH_MAX_BYTES=0 "$SHOW_PATCH" "$BIG_COMMIT" 2>&1)
output_lines=$(printf '%s\n' "$output" | wc -l | tr -d ' ')
[ "$output_lines" -gt 1500 ] && pass "show-patch: both caps disabled = unbounded ($output_lines lines)" \
  || fail "show-patch: both caps disabled expected >1500 lines, got $output_lines"
assert_not_match 'clipped at' "$output" "show-patch: both caps disabled = no clip notice"

# Non-numeric PATCH_MAX_LINES errors out.
output=$(PATCH_MAX_LINES=abc "$SHOW_PATCH" "$BIG_COMMIT" 2>&1) || true
assert_match 'non-numeric PATCH_MAX_LINES' "$output" "show-patch: rejects non-numeric PATCH_MAX_LINES"

# Non-numeric PATCH_MAX_BYTES errors out.
output=$(PATCH_MAX_BYTES=xyz "$SHOW_PATCH" "$BIG_COMMIT" 2>&1) || true
assert_match 'non-numeric PATCH_MAX_BYTES' "$output" "show-patch: rejects non-numeric PATCH_MAX_BYTES"

# Byte cap fires alone when line count is well under PATCH_MAX_LINES.
# 3000-line × ~10 char rewrite is ~46 KB; default PATCH_MAX_BYTES=32768.
output=$(PATCH_MAX_LINES=0 "$SHOW_PATCH" "$BIG_COMMIT" 2>&1)
assert_match 'clipped at 32768 of' "$output" "show-patch: byte cap fires when line cap disabled"
assert_match 'bytes' "$output" "show-patch: byte cap notice mentions bytes unit"
assert_not_match 'lines AND' "$output" "show-patch: byte-only clip does not claim line cap"

# Both caps firing → combined notice ("lines AND ... bytes").
# 1500 short lines of `+MOD N` ≈ 8 KB; PATCH_MAX_BYTES=4000 also fires.
output=$(PATCH_MAX_LINES=1500 PATCH_MAX_BYTES=4000 "$SHOW_PATCH" "$BIG_COMMIT" 2>&1)
assert_match 'lines AND .* bytes' "$output" "show-patch: combined clip notice when both fire"

# PATCH_MAX_BYTES=0 disables byte cap alone (line cap still fires).
# Use PATCH_NO_CACHE=1 so we exercise the cap path directly — without it the
# identical earlier `PATCH_MAX_BYTES=0 BIG_COMMIT` call would short-circuit to
# the cache-hit preamble, which legitimately mentions "bytes" in its summary.
output=$(PATCH_MAX_BYTES=0 PATCH_NO_CACHE=1 "$SHOW_PATCH" "$BIG_COMMIT" 2>&1)
assert_not_match 'clipped at .* bytes' "$output" "show-patch: PATCH_MAX_BYTES=0 suppresses byte clip notice"

# Small commit (the earlier one-line-change repo) must not show a stat tail
# because nothing was clipped.
cd "$REPO"
output=$("$SHOW_PATCH" "$COMMIT" 2>&1)
cd "$BIG_REPO"
assert_not_match 'clipped at' "$output" "show-patch: small commit emits no clip notice"
assert_not_match 'Tree of this commit' "$output" "show-patch: small commit emits no stat tail"
assert_not_match 'Drill in:' "$output" "show-patch: small commit emits no drill-in hint"

# Cache key includes PATCH_MAX_BYTES — running with a different byte cap
# from the same RESULTS_DIR re-emits rather than returning the memoized line.
SESS_BYTES="$TEST_TMPDIR/results-bytes"
mkdir -p "$SESS_BYTES"
first_b=$(RESULTS_DIR="$SESS_BYTES" PATCH_MAX_BYTES=32768 "$SHOW_PATCH" "$BIG_COMMIT" 2>&1)
first_blines=$(printf '%s\n' "$first_b" | wc -l | tr -d ' ')
[ "$first_blines" -gt 100 ] && pass "show-patch cache: first call at 32k emits full output" \
  || fail "show-patch cache: first call expected >100 lines, got $first_blines"
# Same args, different cap → different cache key → another full emit.
second_b=$(RESULTS_DIR="$SESS_BYTES" PATCH_MAX_BYTES=8192 "$SHOW_PATCH" "$BIG_COMMIT" 2>&1)
second_blines=$(printf '%s\n' "$second_b" | wc -l | tr -d ' ')
[ "$second_blines" -gt 100 ] && pass "show-patch cache: different PATCH_MAX_BYTES bypasses cache" \
  || fail "show-patch cache: different PATCH_MAX_BYTES expected >100 lines, got $second_blines"
# Same call again with same cap → memoized (cached pointer + 40-line preview).
third_b=$(RESULTS_DIR="$SESS_BYTES" PATCH_MAX_BYTES=32768 "$SHOW_PATCH" "$BIG_COMMIT" 2>&1)
assert_match 'cached at' "$third_b" "show-patch cache: same PATCH_MAX_BYTES memoizes"

# ── Per-session memoization: identical args called twice with RESULTS_DIR
#    set returns a short note, not the full patch. ──
SESS_RESULTS="$TEST_TMPDIR/results-memo"
mkdir -p "$SESS_RESULTS"
first=$(RESULTS_DIR="$SESS_RESULTS" "$SHOW_PATCH" "$BIG_COMMIT" 2>&1)
first_lines=$(printf '%s\n' "$first" | wc -l | tr -d ' ')
[ "$first_lines" -gt 100 ] && pass "show-patch: first call returns full output" \
  || fail "show-patch: first call expected >100 lines, got $first_lines"

second=$(RESULTS_DIR="$SESS_RESULTS" "$SHOW_PATCH" "$BIG_COMMIT" 2>&1)
assert_match 'cached at' "$second" "show-patch: memoization note on repeat call"
assert_match 'call #2' "$second" "show-patch: hit count visible"
# Cache-hit emits one header line + up to 40 preview lines + optional "... N more"
# tail. Far smaller than the >100-line full diff but not strictly one line, so
# the assertion bounds the size rather than pinning it.
second_lines=$(printf '%s\n' "$second" | wc -l | tr -d ' ')
[ "$second_lines" -gt 0 ] && [ "$second_lines" -le 50 ] \
  && pass "show-patch: memoized call returns ≤50-line preview ($second_lines)" \
  || fail "show-patch: memoized call expected ≤50 lines, got $second_lines"

third=$(RESULTS_DIR="$SESS_RESULTS" "$SHOW_PATCH" "$BIG_COMMIT" 2>&1)
assert_match 'call #3' "$third" "show-patch: hit count increments"

# PATCH_NO_CACHE=1 forces re-emit even when memoized.
forced=$(RESULTS_DIR="$SESS_RESULTS" PATCH_NO_CACHE=1 "$SHOW_PATCH" "$BIG_COMMIT" 2>&1)
forced_lines=$(printf '%s\n' "$forced" | wc -l | tr -d ' ')
[ "$forced_lines" -gt 100 ] && pass "show-patch: PATCH_NO_CACHE=1 bypasses memoization" \
  || fail "show-patch: PATCH_NO_CACHE=1 expected >100 lines, got $forced_lines"

# Different args (path filter added) bypass the cache key.
diff_args=$(RESULTS_DIR="$SESS_RESULTS" "$SHOW_PATCH" "$BIG_COMMIT" -- tab.txt 2>&1)
diff_lines=$(printf '%s\n' "$diff_args" | wc -l | tr -d ' ')
[ "$diff_lines" -gt 100 ] && pass "show-patch: different args bypass memoization" \
  || fail "show-patch: different args expected >100 lines, got $diff_lines"

# Without RESULTS_DIR set, memoization is skipped (back-compat). We use
# `env -u RESULTS_DIR` to actually drop the var — setup_test_env exports
# RESULTS_DIR, so omitting it from the inline env wouldn't be enough.
nocache_a=$(env -u RESULTS_DIR "$SHOW_PATCH" "$BIG_COMMIT" 2>&1)
nocache_b=$(env -u RESULTS_DIR "$SHOW_PATCH" "$BIG_COMMIT" 2>&1)
a_lines=$(printf '%s\n' "$nocache_a" | wc -l | tr -d ' ')
b_lines=$(printf '%s\n' "$nocache_b" | wc -l | tr -d ' ')
assert_eq "$a_lines" "$b_lines" "show-patch: no RESULTS_DIR means no memoization (line counts match)"
# Both must be the full clipped output, not a 1-line memo note.
[ "$a_lines" -gt 100 ] \
  && pass "show-patch: no RESULTS_DIR means each call emits full output ($a_lines lines)" \
  || fail "show-patch: no RESULTS_DIR expected full output, got $a_lines lines"
assert_not_match 'cached at' "$nocache_b" \
  "show-patch: no RESULTS_DIR never returns the memo note"

cd /
teardown_test_env
summary
