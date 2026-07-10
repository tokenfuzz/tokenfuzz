#!/usr/bin/env bash
# Unit tests for bin/probe-history — read-only digest of state/runs.jsonl.
#
# These tests synthesize runs.jsonl directly and never invoke bin/probe, so
# we exercise the digester independently of the harness. See bin/probe-history
# for the schema fields exercised here (sanitizer_runs, testcase_sha1).

set -o pipefail
source "$(dirname "$0")/helpers.sh"
setup_test_env

PH="$SCRIPT_ROOT/bin/probe-history"

# ── Fixtures ─────────────────────────────────────────────────────────
# We hand-craft a runs.jsonl covering:
#   - two paths sharing one content sha1 (rename scenario)
#   - a confirmed (sanitizer_runs=5) CRASH and an unconfirmed one
#   - a NO_EXEC entry
#   - a different hypothesis / agent / mode for filter coverage

STATE_DIR="$RESULTS_DIR/state"
mkdir -p "$STATE_DIR"

TC1="$RESULTS_DIR/scratch-1/altsvc-expire-size-3.bin"
TC2="$RESULTS_DIR/scratch-1/altsvc-expire-size-3-renamed.bin"
TC_OTHER="$RESULTS_DIR/scratch-2/version_string_1.bin"
mkdir -p "$RESULTS_DIR/scratch-1" "$RESULTS_DIR/scratch-2"
printf 'GET / HTTP/1.1\r\n' > "$TC1"
cp "$TC1" "$TC2"                       # identical content → same sha1
printf 'different testcase\n' > "$TC_OTHER"

TC1_SHA1=$(shasum -a 1 "$TC1" | awk '{print $1}')
TC_OTHER_SHA1=$(shasum -a 1 "$TC_OTHER" | awk '{print $1}')

# Synthesize runs.jsonl.
cat > "$STATE_DIR/runs.jsonl" <<EOF
{"id":"RUN-aaaa000001","agent":"1","hypothesis_id":"H-altsvc","card_id":"PATCH-001","mode":"generic","testcase":"$TC1","testcase_sha1":"$TC1_SHA1","asan_output":"$TC1.asan.txt","verdict":"NO_EXEC","sanitizer_runs":1,"created_at":"2026-05-11T14:13:00Z"}
{"id":"RUN-aaaa000002","agent":"1","hypothesis_id":"H-altsvc","card_id":"PATCH-001","mode":"generic","testcase":"$TC1","testcase_sha1":"$TC1_SHA1","asan_output":"$TC1.asan.txt","verdict":"CRASH","sanitizer_runs":1,"created_at":"2026-05-11T14:18:00Z"}
{"id":"RUN-aaaa000003","agent":"1","hypothesis_id":"H-altsvc","card_id":"PATCH-001","mode":"generic","testcase":"$TC1","testcase_sha1":"$TC1_SHA1","asan_output":"$TC1.asan.txt","verdict":"CRASH","sanitizer_runs":5,"created_at":"2026-05-11T14:21:00Z"}
{"id":"RUN-aaaa000004","agent":"3","hypothesis_id":"H-altsvc","card_id":"PATCH-001","mode":"generic","testcase":"$TC2","testcase_sha1":"$TC1_SHA1","asan_output":"$TC2.asan.txt","verdict":"CRASH","sanitizer_runs":5,"created_at":"2026-05-11T15:04:00Z"}
{"id":"RUN-bbbb000005","agent":"2","hypothesis_id":"H-version","card_id":"PATCH-002","mode":"generic","testcase":"$TC_OTHER","testcase_sha1":"$TC_OTHER_SHA1","asan_output":"$TC_OTHER.asan.txt","verdict":"CLEAN","sanitizer_runs":1,"created_at":"2026-05-11T15:10:00Z"}
EOF

# ── 1. Help and usage ────────────────────────────────────────────────
output=$(python3 "$PH" --help 2>&1)
assert_match "probe-history" "$output" "help: identifies tool name"
assert_match "Read-only digest" "$output" "help: read-only framing"

# Missing args → exit 2 with usage hint.
out=$(python3 "$PH" 2>&1) ; rc=$?
assert_eq 2 "$rc" "no args: exit 2"
assert_match "supply TESTCASE" "$out" "no args: helpful error"

# RESULTS_DIR unset → exit 2 (env wipe).
out=$(env -u RESULTS_DIR python3 "$PH" --all 2>&1) ; rc=$?
assert_eq 2 "$rc" "RESULTS_DIR unset: exit 2"
assert_match "RESULTS_DIR not set" "$out" "RESULTS_DIR unset: clear error"

# Bad --sha1 → exit 2.
out=$(RESULTS_DIR="$RESULTS_DIR" python3 "$PH" --sha1 "not-hex!!!" 2>&1) ; rc=$?
assert_eq 2 "$rc" "bad --sha1: exit 2"
assert_match "must be a hex string" "$out" "bad --sha1: clear error"

# Bad --verdict regex → exit 2.
out=$(RESULTS_DIR="$RESULTS_DIR" python3 "$PH" --all --verdict "[(unclosed" 2>&1) ; rc=$?
assert_eq 2 "$rc" "bad --verdict: exit 2"
assert_match "invalid --verdict regex" "$out" "bad --verdict: clear error"

# ── 2. Lookup by testcase path ───────────────────────────────────────
out=$(RESULTS_DIR="$RESULTS_DIR" python3 "$PH" "$TC1" 2>&1) ; rc=$?
assert_eq 0 "$rc" "by path: exit 0 when history exists"
assert_match "altsvc-expire-size-3.bin" "$out" "by path: testcase displayed"
assert_match "sha1=${TC1_SHA1:0:12}" "$out" "by path: on-disk sha1 shown"
# We seeded 3 runs at $TC1 and 1 run at $TC2 sharing the same sha1.
assert_match '4 runs across 2 agents' "$out" "by path: matches both paths via sha1 + path"
out_all=$(RESULTS_DIR="$RESULTS_DIR" python3 "$PH" "$TC1" --limit 0 2>&1)
body_rows=$(echo "$out_all" | grep -c '^  202')
assert_eq 4 "$body_rows" "by path --limit 0: shows all 4 body rows uncapped"
if grep -q "more)" <<<"$out_all"; then
  fail "by path --limit 0: should NOT show 'more' overflow"
else
  pass "by path --limit 0: no overflow line"
fi
# Confirmed marker present on the sanitizer_runs=5 rows.
assert_match "← confirmed" "$out" "by path: ← confirmed marker on sanitizer_runs=5"
# Footer reflects presence of a confirmed verdict.
assert_match "confirmed verdict" "$out" "by path: footer mentions confirmed verdict"

# ── 3. Lookup by --sha1 alone ────────────────────────────────────────
out=$(RESULTS_DIR="$RESULTS_DIR" python3 "$PH" --sha1 "$TC1_SHA1" 2>&1) ; rc=$?
assert_eq 0 "$rc" "by sha1: exit 0"
assert_match "${TC1_SHA1:0:12}" "$out" "by sha1: hash echoed in header"
assert_match "4 runs across 2 agents" "$out" "by sha1: matches recorded hashes"

# ── 4. Filter by --hypothesis-id ─────────────────────────────────────
out=$(RESULTS_DIR="$RESULTS_DIR" python3 "$PH" --hypothesis-id H-version 2>&1) ; rc=$?
assert_eq 0 "$rc" "by hyp: exit 0"
assert_match "version_string_1.bin" "$out" "by hyp: matches H-version run"
assert_match "1 runs" "$out" "by hyp: count is 1"
# Inverse: a non-existent hypothesis → exit 1, no history line.
out_miss=$(RESULTS_DIR="$RESULTS_DIR" python3 "$PH" --hypothesis-id H-nope 2>&1) ; rc=$?
assert_eq 1 "$rc" "by hyp miss: exit 1"
assert_match "no matching runs" "$out_miss" "by hyp miss: clear status"

# ── 5. Filter by --card-id ───────────────────────────────────────────
out=$(RESULTS_DIR="$RESULTS_DIR" python3 "$PH" --card-id PATCH-001 2>&1)
assert_match "PATCH-001" "$out" "by card-id: header references card filter"
# 4 runs are recorded under PATCH-001.
assert_match "4 runs" "$out" "by card-id: count is 4"

# ── 6. --agent filter ────────────────────────────────────────────────
out=$(RESULTS_DIR="$RESULTS_DIR" python3 "$PH" "$TC1" --agent 3 2>&1)
assert_match "1 runs" "$out" "by path + agent: filtered to one"
# agent=1 has 3 rows at TC1.
out=$(RESULTS_DIR="$RESULTS_DIR" python3 "$PH" "$TC1" --agent 1 2>&1)
assert_match "3 runs" "$out" "by path + agent=1: matches 3 rows"

# ── 7. --verdict regex filter ────────────────────────────────────────
out=$(RESULTS_DIR="$RESULTS_DIR" python3 "$PH" --all --verdict CRASH 2>&1)
assert_match "3 runs" "$out" "by --verdict CRASH: exactly 3 rows"
if grep -qE "CLEAN|NO_EXEC" <<<"$out"; then
  fail "by --verdict CRASH: leaked non-CRASH verdicts"
else
  pass "by --verdict CRASH: no non-CRASH rows"
fi

# ── 8. --all mode ────────────────────────────────────────────────────
out=$(RESULTS_DIR="$RESULTS_DIR" python3 "$PH" --all --limit 0 2>&1)
assert_match "5 runs" "$out" "--all: includes every row"
assert_match "all runs" "$out" "--all: header shows filter label"

# ── 9. --format tsv ──────────────────────────────────────────────────
out=$(RESULTS_DIR="$RESULTS_DIR" python3 "$PH" --all --format tsv 2>&1)
header=$(echo "$out" | head -1)
assert_match "created_at" "$header" "tsv: header row present"
assert_match "sanitizer_runs" "$header" "tsv: header includes sanitizer_runs"
# Body row count = 5 (excluding header).
body_count=$(echo "$out" | tail -n +2 | grep -c '^20')
assert_eq 5 "$body_count" "tsv: body has 5 data rows"

# ── 10. --format json ────────────────────────────────────────────────
out=$(RESULTS_DIR="$RESULTS_DIR" python3 "$PH" --all --format json 2>&1)
line_count=$(echo "$out" | grep -c '^{')
assert_eq 5 "$line_count" "json: one object per run"
# Confirm the first JSON line round-trips via python.
first=$(echo "$out" | head -1)
python3 -c "import json,sys; obj=json.loads(sys.argv[1]); assert 'verdict' in obj" "$first"
assert_eq 0 $? "json: first row is valid JSON with verdict field"

# ── 11. --limit cap ──────────────────────────────────────────────────
out=$(RESULTS_DIR="$RESULTS_DIR" python3 "$PH" --all --limit 2 2>&1)
assert_match "more)" "$out" "--limit 2: shows overflow indicator"
assert_match "5 runs across 3 agents" "$out" "--limit 2: summary still counts all matches"
assert_match "\\[summary\\] 3 CRASH · 1 CLEAN · 1 NO_EXEC" "$out" \
  "--limit 2: verdict summary still counts all matches"
# Body rows (start with "  202") capped at 2.
body=$(echo "$out" | grep -c '^  202')
assert_eq 2 "$body" "--limit 2: only 2 history rows shown"
ph_src=$(cat "$PH")
assert_match '^def read_jsonl\(' "$ph_src" \
  "probe-history: keeps a local read-only JSONL reader"
assert_not_match 'from workqueue import' "$ph_src" \
  "probe-history: avoids importing the full workqueue module"

# ── 12. Empty runs.jsonl ─────────────────────────────────────────────
empty_dir=$(mktemp -d)
mkdir -p "$empty_dir/state"
: > "$empty_dir/state/runs.jsonl"
out=$(RESULTS_DIR="$empty_dir" python3 "$PH" --all 2>&1) ; rc=$?
assert_eq 1 "$rc" "empty runs.jsonl: exit 1"
assert_match "no matching runs" "$out" "empty runs.jsonl: helpful note"
rm -rf "$empty_dir"

# ── 13. Missing state dir ────────────────────────────────────────────
missing_dir=$(mktemp -d)
out=$(RESULTS_DIR="$missing_dir" python3 "$PH" --all 2>&1) ; rc=$?
assert_eq 1 "$rc" "missing state dir: exit 1"
rm -rf "$missing_dir"

# ── 14. No-confirm footer is shown when no confirmed run exists ──────
nc_dir=$(mktemp -d)
mkdir -p "$nc_dir/state"
cat > "$nc_dir/state/runs.jsonl" <<EOF
{"id":"RUN-dddd000001","agent":"1","hypothesis_id":"H-x","card_id":"","mode":"generic","testcase":"/tmp/x.bin","testcase_sha1":"abc","asan_output":"/tmp/x.asan.txt","verdict":"CLEAN","sanitizer_runs":1,"created_at":"2026-05-11T16:00:00Z"}
EOF
out=$(RESULTS_DIR="$nc_dir" python3 "$PH" --all 2>&1)
assert_match "no --confirm run recorded yet" "$out" "no-confirm: encourages --confirm refresh"
if grep -q "← confirmed" <<<"$out"; then
  fail "no-confirm: confirmed marker leaked"
else
  pass "no-confirm: no confirmed marker"
fi
rm -rf "$nc_dir"

# ── 15. Path-OR-sha1: missing on-disk file falls back to path only ───
# Drop the on-disk file. The history is recorded under TC1's path, so a
# lookup by path still works even though we can't sha1 the missing file.
rm -f "$TC1"
out=$(RESULTS_DIR="$RESULTS_DIR" python3 "$PH" "$TC1" 2>&1) ; rc=$?
assert_eq 0 "$rc" "missing on-disk file: still matches by path"
assert_match "sha1=?" "$out" "missing on-disk file: header sha1 placeholder"
# Restore for any later checks.
printf 'GET / HTTP/1.1\r\n' > "$TC1"

# ── 16. Output size stays under PRETTY cap (8 KB) ────────────────────
# Synthesize 200 runs at TC1 and ensure pretty output clips, but the
# row body remains a coherent prefix (no half-line).
big_dir=$(mktemp -d)
mkdir -p "$big_dir/state"
big_runs="$big_dir/state/runs.jsonl"
for i in $(seq 1 200); do
  printf '{"id":"RUN-eeee%06d","agent":"1","hypothesis_id":"H-bulk","card_id":"PATCH-bulk","mode":"generic","testcase":"%s","testcase_sha1":"%s","asan_output":"x.asan.txt","verdict":"CLEAN","sanitizer_runs":1,"created_at":"2026-05-11T17:00:%02dZ"}\n' \
    "$i" "$TC1" "$TC1_SHA1" "$((i % 60))" >> "$big_runs"
done
# Write to a real file so we can inspect the trailing byte (bash $() strips
# trailing newlines, defeating a direct "ends in \n" check).
out_file=$(mktemp)
RESULTS_DIR="$big_dir" python3 "$PH" "$TC1" --limit 0 > "$out_file" 2>&1
size=$(wc -c < "$out_file" | tr -d ' ')
if [ "$size" -le 8500 ]; then
  pass "pretty output: stays within byte cap ($size B)"
else
  fail "pretty output: $size B exceeds 8500 B cap"
fi
assert_match "output clipped" "$(cat "$out_file")" "pretty output: clip notice present"
# Last byte must be a newline so no caller sees a half-line.
last_byte=$(tail -c1 "$out_file" | od -An -tx1 | tr -d ' \n')
if [ "$last_byte" = "0a" ]; then
  pass "pretty output: ends on a newline boundary"
else
  fail "pretty output: final byte is 0x$last_byte (expected 0x0a)"
fi
rm -f "$out_file"
rm -rf "$big_dir"

teardown_test_env
summary
