#!/usr/bin/env bash
# tests/test_audit_log_summary_concurrency.sh
#
# Verifies that concurrent invocations of lib/audit_log_summary.py do not
# interleave or truncate rows when appending to a shared index.jsonl.
# The fcntl.flock guard around the append is what makes this safe; this
# test would intermittently fail without it once rows cross PIPE_BUF.

set -uo pipefail
TESTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$TESTS_DIR/helpers.sh"
setup_test_env

SUMMARY="$SCRIPT_ROOT/lib/audit_log_summary.py"
INDEX_FILE="$TEST_TMPDIR/index.jsonl"
: > "$INDEX_FILE"

# Build a fake raw log file that the summarizer will scan. Content is
# irrelevant for this test — we only care that each invocation appends
# exactly one row to the index.
fake_raw="$TEST_TMPDIR/fake.raw"
printf '%s\n' '{"type":"thread.started","thread_id":"t1"}' > "$fake_raw"
fake_log="$TEST_TMPDIR/fake.log"
: > "$fake_log"

N=12
for i in $(seq 1 "$N"); do
  (
    summary_md="$TEST_TMPDIR/sess-${i}.summary.md"
    SESSION_SUMMARY_TARGET="t" \
    SESSION_SUMMARY_ROLE="role-${i}" \
    SESSION_SUMMARY_AGENT="$i" \
    SESSION_SUMMARY_BACKEND="codex" \
    SESSION_SUMMARY_MODEL="m" \
    SESSION_SUMMARY_MODE="generic" \
    SESSION_SUMMARY_EXIT="0" \
    python3 "$SUMMARY" "$fake_raw" "$fake_log" "$summary_md" "$INDEX_FILE" 2>/dev/null
  ) &
done
wait

# Every line must be parseable JSON with the expected schema.
rows=$(wc -l < "$INDEX_FILE" | tr -d ' ')
assert_eq "$N" "$rows" "concurrent summary: N=${N} appends produce N rows"
parsed=$(python3 -c '
import json, sys
ok = 0
seen = set()
for line in open(sys.argv[1], encoding="utf-8"):
    line = line.strip()
    if not line: continue
    try:
        row = json.loads(line)
    except Exception as e:
        print(f"PARSE_FAIL: {e!r} line={line[:120]!r}", file=sys.stderr); sys.exit(2)
    seen.add(row["role"])
    ok += 1
print(ok)
print(",".join(sorted(seen)))
' "$INDEX_FILE")
parse_count=$(echo "$parsed" | head -1)
roles=$(echo "$parsed" | tail -1)
assert_eq "$N" "$parse_count" "concurrent summary: every row is valid JSON"
# Each subshell wrote a unique role; the set should have N distinct entries.
distinct=$(echo "$roles" | tr ',' '\n' | sort -u | wc -l | tr -d ' ')
assert_eq "$N" "$distinct" "concurrent summary: N distinct roles preserved"

# ── index.log concurrency: audit_flock_append serializes line appends ──
# run_agent runs backgrounded (one process per agent) and writes the
# shared index.log timeline through audit_flock_append, an flock-guarded
# append. Without the lock, concurrent appends of lines past PIPE_BUF can
# interleave or tear. Pull just that function out of bin/audit.
audit_extract_function() {
  awk -v fn="$1" '
    $0 ~ "^"fn"\\(\\) \\{" { in_fn=1 }
    in_fn { print }
    in_fn && $0 == "}" { exit }
  ' "$SCRIPT_ROOT/bin/audit"
}
eval "$(audit_extract_function audit_flock_append)"

LOG_FILE="$TEST_TMPDIR/index.log"
: > "$LOG_FILE"
# Each writer appends a long, self-identifying line (well past the 512 B
# macOS PIPE_BUF) many times. A torn write shows up as a line that does
# not match the exact payload shape.
M=40
pad=$(printf 'x%.0s' $(seq 1 600))
for i in $(seq 1 "$N"); do
  (
    for _ in $(seq 1 "$M"); do
      audit_flock_append "$LOG_FILE" "agent-${i}-${pad}-end"
    done
  ) &
done
wait
total=$(wc -l < "$LOG_FILE" | tr -d ' ')
assert_eq "$((N * M))" "$total" "concurrent index.log: N*M appends produce N*M lines"
# A clean line is `agent-<n>-<run of x>-end`. An interleaved write splices
# another writer's payload mid-line, introducing `agent`/`end`/digits into
# the x-run, so the unbounded `x+` match fails for any torn line.
bad=$(grep -cvE '^agent-[0-9]+-x+-end$' "$LOG_FILE" || true)
assert_eq "0" "$bad" "concurrent index.log: no torn or interleaved lines"

teardown_test_env
summary
