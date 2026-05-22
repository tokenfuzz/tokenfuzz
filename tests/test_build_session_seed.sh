#!/usr/bin/env bash
# Tests for lib/build_session_seed.py
# Validates: range merging, exclude patterns, path shortening,
# empty-log handling, MAX_SEED_BYTES truncation, malformed input.
set -o pipefail
source "$(dirname "$0")/helpers.sh"
setup_test_env

GEN="$SCRIPT_ROOT/lib/build_session_seed.py"

# Helper: emit one Read tool_use + matching tool_result event into JSONL.
# is_error param is "true" or "false" (JSON booleans).
emit_read_pair() {
  local tid="$1" path="$2" offset="${3:-0}" limit="${4:-0}" is_error="${5:-false}"
  printf '{"type":"assistant","message":{"content":[{"type":"tool_use","id":"%s","name":"Read","input":{"file_path":"%s","offset":%s,"limit":%s}}]}}\n' \
    "$tid" "$path" "$offset" "$limit"
  printf '{"type":"user","message":{"content":[{"type":"tool_result","tool_use_id":"%s","is_error":%s}]}}\n' \
    "$tid" "$is_error"
}

emit_write() {
  local tid="$1" path="$2"
  printf '{"type":"assistant","message":{"content":[{"type":"tool_use","id":"%s","name":"Write","input":{"file_path":"%s","content":"x"}}]}}\n' \
    "$tid" "$path"
}

# ── Codex schema emitters ──────────────────────────────────────
emit_codex_header() {
  printf '{"type":"thread.started","thread_id":"%s"}\n' "${1:-test-thread}"
  printf '{"type":"turn.started"}\n'
}

# emit_codex_cmd <command-string>
emit_codex_cmd() {
  python3 -c "
import json, sys
print(json.dumps({
  'type': 'item.completed',
  'item': {'id': 'i1', 'type': 'command_execution',
           'command': sys.argv[1], 'aggregated_output': ''}
}))
" "$1"
}

# emit_codex_file_change <path>
emit_codex_file_change() {
  printf '{"type":"item.completed","item":{"id":"i2","type":"file_change","changes":[{"path":"%s","kind":"add"}],"status":"completed"}}\n' "$1"
}

# ═══════════════════════════════════════════════════════════════
# 1. Empty raw log → no seed file written (don't stomp prior seed)
# ═══════════════════════════════════════════════════════════════

raw="$TEST_TMPDIR/empty.raw"
out="$TEST_TMPDIR/empty.seed"
: > "$raw"
python3 "$GEN" "$raw" "$out" 2>/dev/null
assert_file_not_exists "$out" "empty raw → no seed written"

# ═══════════════════════════════════════════════════════════════
# 2. Missing raw log → exit 0, no output file
# ═══════════════════════════════════════════════════════════════

out="$TEST_TMPDIR/missing.seed"
python3 "$GEN" "$TEST_TMPDIR/does-not-exist.raw" "$out"
ec=$?
assert_eq 0 "$ec" "missing raw → exit 0"
assert_file_not_exists "$out" "missing raw → no seed written"

# ═══════════════════════════════════════════════════════════════
# 3. Single Read → seed lists path + range
# ═══════════════════════════════════════════════════════════════

raw="$TEST_TMPDIR/single.raw"
out="$TEST_TMPDIR/single.seed"
emit_read_pair "tid1" "/Users/dev/work/lib/foo.sh" 1 50 > "$raw"
python3 "$GEN" "$raw" "$out"
assert_file_exists "$out" "single read → seed written"
assert_file_contains "$out" "Already Read" "seed has header"
assert_file_contains "$out" "lib/foo.sh: 1-50" "seed shows shortened path + range"

# ═══════════════════════════════════════════════════════════════
# 4. Default Read (no offset/limit) → uses 1-2000 default range
# ═══════════════════════════════════════════════════════════════

raw="$TEST_TMPDIR/default.raw"
out="$TEST_TMPDIR/default.seed"
emit_read_pair "tid1" "/Users/dev/work/lib/foo.sh" 0 0 > "$raw"
python3 "$GEN" "$raw" "$out"
assert_file_contains "$out" "lib/foo.sh: 1-2000" "default Read uses full 1-2000 span"

# ═══════════════════════════════════════════════════════════════
# 5. Overlapping ranges → merged into single span
# ═══════════════════════════════════════════════════════════════

raw="$TEST_TMPDIR/merge.raw"
out="$TEST_TMPDIR/merge.seed"
{
  emit_read_pair "tid1" "/Users/dev/work/lib/foo.sh" 1 100
  emit_read_pair "tid2" "/Users/dev/work/lib/foo.sh" 50 100   # overlaps 50-149
  emit_read_pair "tid3" "/Users/dev/work/lib/foo.sh" 200 50   # disjoint 200-249
} > "$raw"
python3 "$GEN" "$raw" "$out"
assert_file_contains "$out" "lib/foo.sh: 1-149, 200-249" "overlapping ranges merge; disjoint preserved"

# ═══════════════════════════════════════════════════════════════
# 6. AUDIT_STATE files excluded (legitimate re-reads)
# ═══════════════════════════════════════════════════════════════

raw="$TEST_TMPDIR/exclude.raw"
out="$TEST_TMPDIR/exclude.seed"
{
  emit_read_pair "tid1" "/tmp/results/AUDIT_STATE-1.md" 1 100
  emit_read_pair "tid2" "/tmp/results/.session_seed_1.md" 1 100
  emit_read_pair "tid3" "/tmp/results/.read_log_1" 1 100
  emit_read_pair "tid4" "/tmp/results/.static-prompt-rules.md" 1 100
  emit_read_pair "tid5" "/Users/dev/work/lib/foo.sh" 1 100
} > "$raw"
python3 "$GEN" "$raw" "$out"
assert_file_not_contains "$out" "AUDIT_STATE" "AUDIT_STATE excluded"
assert_file_not_contains "$out" "session_seed" "session_seed excluded"
assert_file_not_contains "$out" "read_log" "read_log excluded"
assert_file_not_contains "$out" "static-prompt-rules" "static-prompt-rules excluded"
assert_file_contains "$out" "lib/foo.sh" "non-excluded path retained"

# ═══════════════════════════════════════════════════════════════
# 7. is_error tool_result → Read NOT recorded
# ═══════════════════════════════════════════════════════════════

raw="$TEST_TMPDIR/err.raw"
out="$TEST_TMPDIR/err.seed"
{
  emit_read_pair "tid1" "/Users/dev/work/lib/missing.sh" 1 100 true
  emit_read_pair "tid2" "/Users/dev/work/lib/foo.sh" 1 100 false
} > "$raw"
python3 "$GEN" "$raw" "$out"
assert_file_not_contains "$out" "missing.sh" "errored Read not recorded"
assert_file_contains "$out" "lib/foo.sh" "successful Read recorded"

# ═══════════════════════════════════════════════════════════════
# 8. Writes section — testcases listed
# ═══════════════════════════════════════════════════════════════

raw="$TEST_TMPDIR/writes.raw"
out="$TEST_TMPDIR/writes.seed"
{
  emit_read_pair "tid1" "/Users/dev/work/lib/foo.sh" 1 100
  emit_write "tid2" "/Users/dev/work/output/firefox/claude/results/scratch-1/tc1.html"
  emit_write "tid3" "/Users/dev/work/output/firefox/claude/results/scratch-1/tc2.html"
} > "$raw"
python3 "$GEN" "$raw" "$out"
assert_file_contains "$out" "Testcases written" "writes section present"
assert_file_contains "$out" "tc1.html" "testcase 1 listed"
assert_file_contains "$out" "tc2.html" "testcase 2 listed"

# ═══════════════════════════════════════════════════════════════
# 9. Duplicate Writes → deduplicated in output
# ═══════════════════════════════════════════════════════════════

raw="$TEST_TMPDIR/dup-writes.raw"
out="$TEST_TMPDIR/dup-writes.seed"
{
  emit_read_pair "tid0" "/Users/dev/work/lib/foo.sh" 1 100
  emit_write "tid1" "/Users/dev/work/output/firefox/claude/results/scratch-1/tc1.html"
  emit_write "tid2" "/Users/dev/work/output/firefox/claude/results/scratch-1/tc1.html"
  emit_write "tid3" "/Users/dev/work/output/firefox/claude/results/scratch-1/tc1.html"
} > "$raw"
python3 "$GEN" "$raw" "$out"
n=$(grep -c "tc1.html" "$out" 2>/dev/null || echo 0)
assert_eq 1 "$n" "duplicate Writes deduplicated"

# ═══════════════════════════════════════════════════════════════
# 10. Path shortening — /targets/<target>/ stripped
# ═══════════════════════════════════════════════════════════════

raw="$TEST_TMPDIR/short.raw"
out="$TEST_TMPDIR/short.seed"
emit_read_pair "tid1" "/Users/dev/work/targets/firefox/dom/canvas/foo.cpp" 1 100 > "$raw"
python3 "$GEN" "$raw" "$out"
assert_file_contains "$out" "dom/canvas/foo.cpp: 1-100" "targets prefix stripped"
assert_file_not_contains "$out" "/targets/firefox/" "targets prefix not present"

# ═══════════════════════════════════════════════════════════════
# 11. Malformed JSON line → skipped silently, valid lines processed
# ═══════════════════════════════════════════════════════════════

raw="$TEST_TMPDIR/bad.raw"
out="$TEST_TMPDIR/bad.seed"
{
  echo "not valid json {{{"
  emit_read_pair "tid1" "/Users/dev/work/lib/foo.sh" 1 100
  echo "{\"truncated"
} > "$raw"
python3 "$GEN" "$raw" "$out"
assert_file_contains "$out" "lib/foo.sh" "valid line processed despite malformed neighbors"

# ═══════════════════════════════════════════════════════════════
# 12. MAX_SEED_BYTES enforced — bulk reads truncated
# ═══════════════════════════════════════════════════════════════

raw="$TEST_TMPDIR/big.raw"
out="$TEST_TMPDIR/big.seed"
: > "$raw"
for i in $(seq 1 200); do
  emit_read_pair "tid$i" "/Users/dev/work/lib/file_${i}_with_a_long_padding_name.sh" 1 100 >> "$raw"
done
python3 "$GEN" "$raw" "$out"
size=$(wc -c < "$out")
# The cap is 2048; allow up to 2200 to absorb final newline + truncation note.
if [ "$size" -le 2200 ]; then
  pass "seed body within MAX_SEED_BYTES (got $size bytes)"
else
  fail "seed body exceeds MAX_SEED_BYTES (got $size bytes)"
fi
assert_file_contains "$out" "Already Read" "header survives truncation"

# ═══════════════════════════════════════════════════════════════
# 13. Wrong arg count → exit 2
# ═══════════════════════════════════════════════════════════════

set +e
python3 "$GEN" 2>/dev/null
ec=$?
set -e
assert_eq 2 "$ec" "no args → exit 2"

# ═══════════════════════════════════════════════════════════════
# 14. Output dir auto-created
# ═══════════════════════════════════════════════════════════════

raw="$TEST_TMPDIR/auto.raw"
out="$TEST_TMPDIR/new_dir/auto.seed"
emit_read_pair "tid1" "/Users/dev/work/lib/foo.sh" 1 100 > "$raw"
python3 "$GEN" "$raw" "$out"
assert_file_exists "$out" "output dir auto-created"

# ═══════════════════════════════════════════════════════════════
# CODEX BACKEND TESTS
# ═══════════════════════════════════════════════════════════════

# 15. Codex: thread.started + sed range → reads recorded
raw="$TEST_TMPDIR/codex_sed.raw"
out="$TEST_TMPDIR/codex_sed.seed"
{
  emit_codex_header
  emit_codex_cmd "/bin/zsh -lc \"sed -n '100,200p' /tmp/work/firefox/dom/foo.cpp\""
} > "$raw"
TARGET_ROOT=/tmp/work/firefox python3 "$GEN" "$raw" "$out"
assert_file_exists "$out" "codex sed: seed written"
assert_file_contains "$out" "dom/foo.cpp: 100-200" "codex sed: range extracted, TARGET_ROOT prefix stripped"

# 16. Codex: head -n N file → 1..N
raw="$TEST_TMPDIR/codex_head.raw"
out="$TEST_TMPDIR/codex_head.seed"
{
  emit_codex_header
  emit_codex_cmd "/bin/zsh -lc \"head -n 50 /tmp/work/firefox/dom/foo.cpp\""
} > "$raw"
TARGET_ROOT=/tmp/work/firefox python3 "$GEN" "$raw" "$out"
assert_file_contains "$out" "dom/foo.cpp: 1-50" "codex head: 1..N range"

# 17. Codex: cat absolute file → DEFAULT range
raw="$TEST_TMPDIR/codex_cat.raw"
out="$TEST_TMPDIR/codex_cat.seed"
{
  emit_codex_header
  emit_codex_cmd "/bin/zsh -lc \"cat /tmp/work/firefox/dom/bar.cpp\""
} > "$raw"
TARGET_ROOT=/tmp/work/firefox python3 "$GEN" "$raw" "$out"
assert_file_contains "$out" "dom/bar.cpp: 1-2000" "codex cat: default 1-2000 span"

# 18. Codex: cat heredoc / non-file → not recorded
raw="$TEST_TMPDIR/codex_heredoc.raw"
out="$TEST_TMPDIR/codex_heredoc.seed"
{
  emit_codex_header
  emit_codex_cmd "/bin/zsh -lc \"cat <<EOF\nhello\nEOF\""
  emit_codex_cmd "/bin/zsh -lc \"sed -n '1,10p' /tmp/work/firefox/baz.cpp\""
} > "$raw"
TARGET_ROOT=/tmp/work/firefox python3 "$GEN" "$raw" "$out"
assert_file_contains "$out" "baz.cpp" "codex heredoc: real read still recorded"
assert_file_not_contains "$out" "<<EOF" "codex heredoc: marker not treated as file"
assert_file_not_contains "$out" "hello" "codex heredoc: body not treated as file"

# 19. Codex: file_change → write recorded
raw="$TEST_TMPDIR/codex_write.raw"
out="$TEST_TMPDIR/codex_write.seed"
{
  emit_codex_header
  emit_codex_cmd "/bin/zsh -lc \"sed -n '1,10p' /tmp/work/firefox/foo.cpp\""
  emit_codex_file_change "/tmp/work/results/scratch-1/H1-test.html"
  emit_codex_file_change "/tmp/work/results/scratch-1/H2-test.html"
} > "$raw"
TARGET_ROOT=/tmp/work/firefox python3 "$GEN" "$raw" "$out"
assert_file_contains "$out" "Testcases written" "codex: writes section present"
assert_file_contains "$out" "H1-test.html" "codex: testcase 1 listed"
assert_file_contains "$out" "H2-test.html" "codex: testcase 2 listed"

# 20. Codex: AUDIT_STATE writes excluded
raw="$TEST_TMPDIR/codex_state.raw"
out="$TEST_TMPDIR/codex_state.seed"
{
  emit_codex_header
  emit_codex_cmd "/bin/zsh -lc \"sed -n '1,10p' /tmp/foo.cpp\""
  emit_codex_file_change "/tmp/results/AUDIT_STATE-1.md"
  emit_codex_file_change "/tmp/results/scratch-1/test.html"
} > "$raw"
python3 "$GEN" "$raw" "$out"
assert_file_not_contains "$out" "AUDIT_STATE" "codex: AUDIT_STATE write excluded"
assert_file_contains "$out" "test.html" "codex: scratch write retained"

# 21. Codex: malformed sed → skipped, valid commands still parsed
raw="$TEST_TMPDIR/codex_bad.raw"
out="$TEST_TMPDIR/codex_bad.seed"
{
  emit_codex_header
  emit_codex_cmd "/bin/zsh -lc \"sed -n '500,100p' /tmp/work/firefox/inverted.cpp\""    # end < start
  emit_codex_cmd "/bin/zsh -lc \"sed -n '1,10p' /tmp/work/firefox/good.cpp\""
} > "$raw"
TARGET_ROOT=/tmp/work/firefox python3 "$GEN" "$raw" "$out"
assert_file_not_contains "$out" "inverted.cpp" "codex: inverted range skipped"
assert_file_contains "$out" "good.cpp" "codex: valid range still recorded"

# 22. Codex: agent_message events ignored (not reads)
raw="$TEST_TMPDIR/codex_agent_msg.raw"
out="$TEST_TMPDIR/codex_agent_msg.seed"
{
  emit_codex_header
  printf '{"type":"item.completed","item":{"id":"i0","type":"agent_message","text":"hello"}}\n'
  emit_codex_cmd "/bin/zsh -lc \"sed -n '1,10p' /tmp/work/firefox/foo.cpp\""
} > "$raw"
TARGET_ROOT=/tmp/work/firefox python3 "$GEN" "$raw" "$out"
assert_file_contains "$out" "foo.cpp" "codex: agent_message ignored, sed still parsed"
assert_file_not_contains "$out" "hello" "codex: agent_message body not in seed"

# 23. Codex: format auto-detected (no env var needed)
raw="$TEST_TMPDIR/codex_detect.raw"
out="$TEST_TMPDIR/codex_detect.seed"
{
  emit_codex_header  # only thread.started + turn.started
  emit_codex_cmd "/bin/zsh -lc \"sed -n '1,10p' /Users/x/proj/foo.c\""
} > "$raw"
python3 "$GEN" "$raw" "$out"  # no TARGET_ROOT → falls through path-shortener
assert_file_contains "$out" "foo.c" "codex format auto-detected without env"

# 24. Mixed: claude-format log not parsed as codex
raw="$TEST_TMPDIR/mixed.raw"
out="$TEST_TMPDIR/mixed.seed"
emit_read_pair "tid1" "/Users/dev/work/lib/claude_only.sh" 1 50 > "$raw"
python3 "$GEN" "$raw" "$out"
assert_file_contains "$out" "lib/claude_only.sh" "claude format still works after codex addition"

# 25. detect_format: empty file defaults to claude (silent skip path)
raw="$TEST_TMPDIR/empty2.raw"
: > "$raw"
out="$TEST_TMPDIR/empty2.seed"
python3 "$GEN" "$raw" "$out"
assert_file_not_exists "$out" "empty file → no seed (claude default path)"

# 26. Quote stripping — path wrapped in inner double quotes (real codex pattern)
raw="$TEST_TMPDIR/codex_quoted.raw"
out="$TEST_TMPDIR/codex_quoted.seed"
emit_codex_header > "$raw"
# Build the command string as it appears AFTER JSON decode (i.e. with literal
# double quotes around the path, plus an unbalanced trailing " from the
# /bin/zsh -lc "..." wrapper). Use python to emit the JSON directly.
python3 -c "
import json
cmd = '/bin/zsh -lc \"sed -n \\'1,50p\\' \"/tmp/work/firefox/quoted.cpp\"\"'
print(json.dumps({
  'type': 'item.completed',
  'item': {'id': 'i9', 'type': 'command_execution',
           'command': cmd, 'aggregated_output': ''}
}))
" >> "$raw"
TARGET_ROOT=/tmp/work/firefox python3 "$GEN" "$raw" "$out"
assert_file_contains "$out" "quoted.cpp: 1-50" "codex: leading/trailing quotes stripped from path"
assert_file_not_contains "$out" 'quoted\.cpp"' "codex: no stray trailing quote in path"

teardown_test_env
summary
