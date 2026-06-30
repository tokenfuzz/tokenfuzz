#!/usr/bin/env bash
# tests/test_benchmark_quota_detect.sh — unit tests for the benchmark
# post-run quota detector (cell_log_has_quota_exhaustion / cell_backend_succeeded
# in bin/benchmark).
#
# Regression: a single transient "status 503" (service unavailable) line that
# gemini-cli retried with backoff was being read as quota exhaustion. That
# flipped an otherwise-successful model-direct cell to status=quota_exhausted,
# armed the cross-cell short-circuit, and dropped the cell's real confirmed
# crashes from the pool (build_pool / aggregate count only status=done cells).
# The fix: quota classification is delegated to lib/audit_helpers.py, and a
# terminal success result in backend.raw.log vetoes the quota flag entirely.
set -euo pipefail

TESTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT_ROOT="$(cd "$TESTS_DIR/.." && pwd)"
# shellcheck disable=SC1091
source "$TESTS_DIR/helpers.sh"
setup_test_env

BENCH="$SCRIPT_ROOT/bin/benchmark"

work=$(mktemp -d)
trap 'rm -rf "$work" 2>/dev/null || true; teardown_test_env 2>/dev/null || true' EXIT

# Extract the two detector functions from bin/benchmark and eval them into
# this shell, the same brace-depth-tracking approach test_benchmark_cells.sh
# uses for prepare_harness_facade. This tests the real source without booting
# a full benchmark run.
extract_fn() {
  awk -v fn="$1" '
    $0 ~ "^" fn "\\(\\) \\{" { in_func=1 }
    in_func {
      line=$0
      opens=gsub(/\{/, "{", line)
      closes=gsub(/\}/, "}", line)
      depth += opens - closes
      print
      if (depth == 0) exit
    }
  ' "$BENCH"
}
eval "$(extract_fn cell_backend_succeeded)"
eval "$(extract_fn cell_provider_issue)"
eval "$(extract_fn cell_has_result_artifacts)"
eval "$(extract_fn model_direct_capacity_blocked)"
eval "$(extract_fn cell_log_has_quota_exhaustion)"
eval "$(extract_fn set_cell_run_quality)"
eval "$(extract_fn sync_harness_provider_markers)"

# The terminal success record gemini-cli writes once the stream completes.
RESULT_OK='{"type":"result","timestamp":"2026-06-07T01:21:56.849Z","status":"success","stats":{"tool_calls":124}}'

# ── T1: recovered transient 503 in a successful run is NOT quota ────────────
cell1="$work/cell-503-recovered"
mkdir -p "$cell1"
{
  printf 'Attempt 1 failed with status 503. Retrying with backoff... _ApiError: {"code":503,"status":"UNAVAILABLE"}\n'
  printf '%s\n' "$RESULT_OK"
} > "$cell1/backend.raw.log"
if cell_log_has_quota_exhaustion "$cell1"; then
  fail "T1: recovered 503 in a successful run must NOT be flagged as quota" \
    "cell_log_has_quota_exhaustion returned true"
else
  pass "T1: recovered 503 in a successful run is not flagged as quota"
fi

# ── T2: 503 alone (no success line) is still not quota — it is transient ────
cell2="$work/cell-503-only"
mkdir -p "$cell2"
printf 'Attempt 1 failed with status 503. Retrying with backoff...\n' \
  > "$cell2/backend.raw.log"
if cell_log_has_quota_exhaustion "$cell2"; then
  fail "T2: a 503 service-unavailable error must not count as quota exhaustion" \
    "cell_log_has_quota_exhaustion returned true"
else
  pass "T2: a bare 503 is not quota exhaustion (transient, excluded from regex)"
fi

# ── T3: a recovered 429 inside a successful run is NOT quota ────────────────
# Even the genuine quota signal, once retried to a successful completion,
# means the session finished — the success result vetoes the flag.
cell3="$work/cell-429-recovered"
mkdir -p "$cell3"
{
  printf 'Attempt 1 failed with status 429. Retrying with backoff...\n'
  printf '%s\n' "$RESULT_OK"
} > "$cell3/backend.raw.log"
if cell_log_has_quota_exhaustion "$cell3"; then
  fail "T3: a 429 recovered into a successful result must not be flagged" \
    "cell_log_has_quota_exhaustion returned true"
else
  pass "T3: a 429 recovered into a successful result is not flagged"
fi

# ── T4: sustained 429 with no success result IS quota exhaustion ────────────
# The real death case must still be detected so the run short-circuits. A real
# gemini/agy log carries the Antigravity banner (as every gemini fixture does);
# the classifier requires that provider-CLI dialect marker before trusting a
# bare plain-text 429/quota line, so a stray "status 429" in arbitrary tool
# output is not mistaken for a backend death.
cell4="$work/cell-429-dead"
mkdir -p "$cell4"
{
  printf 'I0519 17:22:48.681 12345 server.go:1295] Antigravity CLI starting\n'
  for i in $(seq 1 12); do
    printf 'Attempt %d failed with status 429. Retrying...\n' "$i"
  done
  printf 'RESOURCE_EXHAUSTED: quota reached\n'
} > "$cell4/backend.raw.log"
if cell_log_has_quota_exhaustion "$cell4"; then
  pass "T4: sustained 429/RESOURCE_EXHAUSTED with no success is flagged as quota"
else
  fail "T4: a genuine quota death must still be flagged" \
    "cell_log_has_quota_exhaustion returned false"
fi

# ── T5: cell_backend_succeeded only trusts a terminal result record ─────────
# A "status":"success" buried in tool output is not a session verdict.
cell5="$work/cell-stray-success"
mkdir -p "$cell5"
printf '{"type":"tool_result","output":"deploy \\"status\\":\\"success\\" ok"}\n' \
  > "$cell5/backend.raw.log"
if cell_backend_succeeded "$cell5"; then
  fail "T5: a stray status:success in tool output must not read as the verdict" \
    "cell_backend_succeeded returned true"
else
  pass "T5: cell_backend_succeeded ignores status:success outside a result record"
fi

# ── T6: no backend.raw.log → no success claim (harness-cell fall-through) ───
cell6="$work/cell-empty"
mkdir -p "$cell6"
if cell_backend_succeeded "$cell6"; then
  fail "T6: cell_backend_succeeded must be false without a backend.raw.log" \
    "returned true on a cell with no log"
else
  pass "T6: cell_backend_succeeded is false without a backend.raw.log"
fi

# ── T7: model-direct capacity verdict for a NON-Gemini (claude) cell ─────────
# Locks the rc!=0 assumption: a claude capacity death (api_error_status:429,
# no terminal success, no artifacts) is provider-limited when the backend exits
# non-zero, but a recovered/clean exit (rc=0) stays done, and a cell that wrote
# artifacts is never discarded. This is the model-direct path bin/benchmark:
# run_model_direct_cell uses to decide .backend-unavailable.
cell7="$work/cell-md-claude"
mkdir -p "$cell7"
printf '{"type":"result","is_error":true,"api_error_status":429}\n' \
  > "$cell7/backend.raw.log"
assert_eq "capacity_limited" "$(cell_provider_issue "$cell7")" \
  "T7: claude api_error_status:429 model-direct log classifies as capacity"

if model_direct_capacity_blocked "$(cell_provider_issue "$cell7")" 1 "$cell7"; then
  pass "T7a: claude capacity + rc!=0 + no artifacts → provider-limited"
else
  fail "T7a: claude capacity + rc!=0 + no artifacts → provider-limited" "not blocked"
fi

# rc=0 (recovered or clean exit) must NOT be discarded — the assumption that a
# real capacity death exits non-zero, made explicit so a future change is
# deliberate.
if model_direct_capacity_blocked "$(cell_provider_issue "$cell7")" 0 "$cell7"; then
  fail "T7b: claude capacity + rc=0 must NOT be provider-limited (relies on non-zero exit)" \
    "blocked on a clean exit"
else
  pass "T7b: claude capacity + rc=0 stays done (rc!=0 assumption locked)"
fi

# A cell that produced artifacts is useful work — never discarded.
mkdir -p "$cell7/findings/FIND-001"
if model_direct_capacity_blocked "$(cell_provider_issue "$cell7")" 1 "$cell7"; then
  fail "T7c: a capacity cell WITH artifacts must NOT be provider-limited" "blocked despite artifacts"
else
  pass "T7c: capacity + artifacts is not provider-limited"
fi

# A transient issue never blocks, even with rc!=0 and no artifacts — it becomes
# a plain failed cell the next replicate re-runs.
cell8="$work/cell-md-transient"
mkdir -p "$cell8"
printf '{"type":"error","error":{"message":"Server returned 503"}}\n' \
  > "$cell8/backend.raw.log"
assert_eq "transient" "$(cell_provider_issue "$cell8")" \
  "T7d: claude 503 model-direct log classifies as transient"
if model_direct_capacity_blocked "$(cell_provider_issue "$cell8")" 1 "$cell8"; then
  fail "T7e: a transient cell must NOT be provider-limited" "transient blocked"
else
  pass "T7e: transient + rc!=0 + no artifacts is not provider-limited (plain failed)"
fi

# ── T8: harness provider markers sync from the LOGDIR sibling of results ─────
# Regression: bin/audit writes .run-quality/.backend-unavailable to its LOGDIR
# (<root>/<backend>/logs), a SIBLING of the results dir (.../results), not a
# child. sync_harness_provider_markers used to read "$results_dir/logs", which
# never existed, so a harness cell whose backend hit a capacity wall stayed
# run_quality=clean and never armed the cross-cell skip — the quota death was
# reported as a clean zero and the next replicate was launched into a preflight
# FATAL. Pin the sibling path so the markers reach the cell.
cell9="$work/cell-harness"
results9="$cell9/repo-root/output/tgt-exp/claude/results"
logs9="$cell9/repo-root/output/tgt-exp/claude/logs"
mkdir -p "$cell9" "$results9" "$logs9"
printf 'provider_limited\n' > "$logs9/.run-quality"
: > "$logs9/.backend-unavailable"
sync_harness_provider_markers "$cell9" "$results9"
assert_eq "provider_limited" "$(cat "$cell9/.run-quality" 2>/dev/null)" \
  "T8: .run-quality synced from the LOGDIR sibling of results"
if [ -f "$cell9/.backend-unavailable" ]; then
  pass "T8a: .backend-unavailable synced from the LOGDIR sibling (arms cross-cell skip)"
else
  fail "T8a: .backend-unavailable must sync from the LOGDIR sibling" "marker not copied"
fi

# ── T9: markers misplaced under results_dir/logs (the old wrong path) are NOT
# read — guards against silently reverting to the child-path bug.
cell10="$work/cell-harness-wrongpath"
results10="$cell10/repo-root/output/tgt-exp/claude/results"
mkdir -p "$cell10" "$results10/logs"
printf 'provider_limited\n' > "$results10/logs/.run-quality"
: > "$results10/logs/.backend-unavailable"
sync_harness_provider_markers "$cell10" "$results10"
if [ -f "$cell10/.backend-unavailable" ]; then
  fail "T9: a marker under results_dir/logs must NOT be read (wrong path)" \
    "child-path marker was synced — sync reverted to the buggy path"
else
  pass "T9: markers under results_dir/logs are ignored (sibling path only)"
fi

summary
