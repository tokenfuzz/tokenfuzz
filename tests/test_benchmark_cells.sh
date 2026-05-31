#!/usr/bin/env bash
# Tests for bin/benchmark "cell" execution: model-direct + harness cells run
# under fake backends, exercising the cell-launch wiring (--cd, --bench-root
# resolution, claude --max-turns omission, failure propagation, and the
# "do not dirty the real repo root" guarantee).
#
# Carved out of test_benchmark.sh so this slow block (~60s of `bash bin/benchmark`
# dry-runs that each spawn ~30 python subprocesses) can run in parallel with
# the rest of the benchmark test suite under tests/run-tests.sh.
set -euo pipefail

TESTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT_ROOT="$(cd "$TESTS_DIR/.." && pwd)"
# shellcheck disable=SC1091
source "$TESTS_DIR/helpers.sh"
# shellcheck disable=SC1091
source "$SCRIPT_ROOT/lib/timeout.sh"

setup_test_env

BENCH="$SCRIPT_ROOT/bin/benchmark"

work=$(mktemp -d)
trap 'rm -rf "$work" 2>/dev/null || true; teardown_test_env 2>/dev/null || true' EXIT

# ── T16: model-direct codex cells pass exactly one cwd flag ─────────────────────
fake_codex="$work/fake-codex"
cat > "$fake_codex" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
count=0
cd_val=""
want_cd=0
for arg in "$@"; do
  if [ "$want_cd" = 1 ]; then cd_val="$arg"; want_cd=0; fi
  if [ "$arg" = "--cd" ]; then count=$((count + 1)); want_cd=1; fi
done
printf 'fake-codex args:'
printf ' [%s]' "$@"
printf '\n'
if [ "$count" -ne 1 ]; then
  printf 'expected exactly one --cd, got %s\n' "$count" >&2
  exit 64
fi
# The --cd path must be absolute and exist: codex resolves it after its
# own chdir, so a relative path here resolves against the wrong root.
case "$cd_val" in
  /*) ;;
  *)  printf 'expected absolute --cd path, got %s\n' "$cd_val" >&2; exit 65 ;;
esac
if [ ! -d "$cd_val" ]; then
  printf '--cd path does not exist: %s\n' "$cd_val" >&2
  exit 66
fi
printf '{"type":"item.completed","usage":{"input_tokens":1,"cached_input_tokens":0,"output_tokens":1}}\n'
SH
chmod +x "$fake_codex"
bench_target="benchmark-test-target-$$"
mkdir -p "$SCRIPT_ROOT/targets/$bench_target/build-asan" \
         "$SCRIPT_ROOT/targets/$bench_target/lib" \
         "$SCRIPT_ROOT/targets/$bench_target/findings/FIND-stale"
cat > "$SCRIPT_ROOT/targets/$bench_target/target.toml" <<'TOML'
target = "benchmark-test-target"

[sanitizer]
enabled = []

[runner]
bin = "/bin/true"
args = []
TOML
printf '#!/bin/sh\nprintf helper\n' \
  > "$SCRIPT_ROOT/targets/$bench_target/build-asan/generated-helper"
chmod 0644 "$SCRIPT_ROOT/targets/$bench_target/build-asan/generated-helper"
printf 'int benchmark_visible;\n' \
  > "$SCRIPT_ROOT/targets/$bench_target/lib/benchmark-visible.c"
printf 'stale target finding\n' \
  > "$SCRIPT_ROOT/targets/$bench_target/findings/FIND-stale/report.md"
touch -t 202001010101 \
  "$SCRIPT_ROOT/targets/$bench_target/findings/FIND-stale/report.md" \
  "$SCRIPT_ROOT/targets/$bench_target/findings/FIND-stale" \
  "$SCRIPT_ROOT/targets/$bench_target/findings"
reltest_root="$SCRIPT_ROOT/output/benchmark-reltest-$$"
trap 'rm -rf "$work" "$SCRIPT_ROOT/targets/$bench_target" "$reltest_root"* "${SCRIPT_ROOT}/${root_junk_name:-__no_such_benchmark_root_junk__}" "${SCRIPT_ROOT}/${model_direct_junk_name:-__no_such_benchmark_model_direct_junk__}" 2>/dev/null || true; teardown_test_env 2>/dev/null || true' EXIT
codex_root="$work/codex-bench"
codex_out=$(CODEX_BIN="$fake_codex" \
  bash "$BENCH" --target "$bench_target" --backend codex --replicates 1 \
  --conditions model-direct --budget-wall 5 --bench-root "$codex_root" 2>&1)
assert_eq "0" "$?" "T16a: model-direct codex cell succeeds with one --cd"
assert_match "cells complete: 1 done, 0 failed" "$codex_out" \
  "T16b: codex benchmark cell marked done"
# The target tree must stay byte-identical: no chmod, no copy, no rewrite.
# Inspect the literal mode bits via stat rather than `[ -x file ]`. The
# latter lies on Docker-for-Mac bind mounts (root + virtiofs returns
# access=ok regardless of u/g/o execute bits), so a 0644 helper would
# read as "executable" even when the benchmark never touched it.
helper_path="$SCRIPT_ROOT/targets/$bench_target/build-asan/generated-helper"
helper_mode=$(stat -c '%a' "$helper_path" 2>/dev/null \
  || stat -f '%Lp' "$helper_path" 2>/dev/null)
if [ -n "$helper_mode" ] && [ "$(( 0$helper_mode & 0111 ))" -eq 0 ]; then
  pass "T16b2: model-direct prep does NOT chmod the target tree"
else
  fail "T16b2: model-direct prep does NOT chmod the target tree" \
    "target helper mode is now $helper_mode; benchmark must not mutate the target"
fi
assert_file_exists \
  "$SCRIPT_ROOT/targets/$bench_target/findings/FIND-stale/report.md" \
  "T16b3: pre-existing files in the target tree are left undisturbed"

# A relative --bench-root must still yield an absolute, existing --cd:
# the script cd's to SCRIPT_ROOT, so the root resolves there. fake-codex
# rejects a relative or missing --cd, so a clean run proves the fix.
codex_rel_out=$(cd "$SCRIPT_ROOT" && CODEX_BIN="$fake_codex" bash "$BENCH" \
  --target "$bench_target" --backend codex --replicates 1 \
  --conditions model-direct --budget-wall 5 \
  --bench-root "output/benchmark-reltest-$$" 2>&1)
codex_rel_rc=$?
assert_eq "0" "$codex_rel_rc" "T16c: model-direct codex cell succeeds with relative --bench-root"
assert_match "cells complete: 1 done, 0 failed" "$codex_rel_out" \
  "T16d: relative-root codex benchmark cell marked done"

# ── T16e: claude model-direct flags omit --max-turns ────────────────────────
# Model-direct is an open-ended audit task; the wall-clock budget is its only
# real ceiling. A turn cap there just kills the agent mid-investigation
# (observed: 120 tool calls of pure recon, zero findings written before the
# cap fired). The benchmark passes max_turns=0 to llm_agent_flags, which
# must omit --max-turns entirely so claude self-paces against the timeout.
claude_flags_out=$(bash -c '
  set -euo pipefail
  source '"$SCRIPT_ROOT"'/lib/llm_invoke.sh
  declare -a flags=()
  llm_agent_flags claude flags "" 0 "/tmp"
  printf "%s\n" "${flags[@]}"
')
if printf '%s\n' "$claude_flags_out" | grep -qx -- '--max-turns'; then
  fail "T16e: max_turns=0 must omit --max-turns from claude flags" \
    "got: $claude_flags_out"
else
  pass "T16e: max_turns=0 omits --max-turns from claude flags"
fi
# Sanity: a positive max_turns still emits the flag.
claude_flags_capped=$(bash -c '
  set -euo pipefail
  source '"$SCRIPT_ROOT"'/lib/llm_invoke.sh
  declare -a flags=()
  llm_agent_flags claude flags "" 80 "/tmp"
  printf "%s\n" "${flags[@]}"
')
if printf '%s\n' "$claude_flags_capped" | grep -qx -- '--max-turns'; then
  pass "T16f: positive max_turns still emits --max-turns (sub-agents stay capped)"
else
  fail "T16f: positive max_turns must still emit --max-turns" \
    "got: $claude_flags_capped"
fi

# ── T16g: a claude cell that genuinely fails is still marked failed ────────────
# A non-zero exit is a real failure and must not be laundered into a done cell.
# (Previously error_max_turns was treated as success; with the model-direct
# turn cap removed, that special case is gone and any non-zero exit fails.)
fake_claude_fail="$work/fake-claude-fail"
cat > "$fake_claude_fail" <<'SH'
#!/usr/bin/env bash
printf '{"type":"result","subtype":"error_during_execution","is_error":true}\n'
exit 1
SH
chmod +x "$fake_claude_fail"
claude_fail_out=$(cd "$SCRIPT_ROOT" && CLAUDE_BIN="$fake_claude_fail" bash "$BENCH" \
  --target "$bench_target" --backend claude --replicates 1 \
  --conditions model-direct --budget-wall 5 \
  --bench-root "$reltest_root-claudefail" 2>&1) || true
rm -rf "$reltest_root-claudefail" 2>/dev/null || true
assert_match "cells complete: 0 done, 1 failed" "$claude_fail_out" \
  "T16g: a genuinely failed claude cell stays failed"

# ── T16h-k: model-direct cells do not dirty the real repo root ───────────
fake_gemini="$work/fake-gemini"
cat > "$fake_gemini" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
prompt="$(cat 2>/dev/null || true)"
case "$prompt" in
  *MODEL_PREFLIGHT_OK*)
    if [ -n "${FAKE_BACKEND_RELATIVE_WRITE:-}" ]; then
      printf 'junk from preflight %s\n' "$(pwd)" > "$FAKE_BACKEND_RELATIVE_WRITE"
    fi
    printf 'MODEL_PREFLIGHT_OK\n'
    exit 0
    ;;
esac
if [ -n "${FAKE_BACKEND_RELATIVE_WRITE:-}" ]; then
  printf 'junk from %s\n' "$(pwd)" > "$FAKE_BACKEND_RELATIVE_WRITE"
fi
printf '{"id":"REC-empty","slice":"fake","confidence":"AUDIT-CLEAN","notes":"fake clean"}\n'
SH
chmod +x "$fake_gemini"
model_direct_junk_name="benchmark-model-direct-junk-$$.txt"
rm -f "$SCRIPT_ROOT/$model_direct_junk_name" 2>/dev/null || true
gemini_direct_root="$work/gemini-direct-bench"
gemini_direct_out=$(GEMINI_BIN="$fake_gemini" FAKE_BACKEND_RELATIVE_WRITE="$model_direct_junk_name" \
  bash "$BENCH" --target "$bench_target" --backend gemini \
    --replicates 1 --conditions model-direct --budget-wall 5 \
    --bench-root "$gemini_direct_root" 2>&1)
gemini_direct_rc=$?
assert_eq "0" "$gemini_direct_rc" \
  "T16h: fake-gemini model-direct benchmark cell exits cleanly"
assert_match "cells complete: 1 done, 0 failed" "$gemini_direct_out" \
  "T16i: fake-gemini model-direct benchmark cell marked done"
assert_file_not_exists "$SCRIPT_ROOT/$model_direct_junk_name" \
  "T16j: model-direct benchmark does not create bare junk in the real repo root"
model_direct_junk=$(find "$gemini_direct_root/gemini" \
  -path "*/cells/model-direct-r1/$model_direct_junk_name" | head -1)
assert_file_exists "$model_direct_junk" \
  "T16k: bare junk lands inside the model-direct cell dir (which IS cwd)"

gemini_unlimited_root="$work/gemini-direct-unlimited-bench"
gemini_unlimited_out=$(GEMINI_BIN="$fake_gemini" \
  bash "$BENCH" --target "$bench_target" --backend gemini \
    --replicates 1 --conditions model-direct --budget-wall 0 \
    --bench-root "$gemini_unlimited_root" 2>&1)
gemini_unlimited_rc=$?
assert_eq "0" "$gemini_unlimited_rc" \
  "T16k2: fake-gemini model-direct benchmark supports unlimited wall time"
assert_match "budget=unlimited" "$gemini_unlimited_out" \
  "T16k3: unlimited wall-time mode is visible in benchmark logs"

# Regression: when benchmark output is captured by a shell command
# substitution, the console-log FIFO path can deadlock in the EXIT trap
# waiting for tee. Gemini CLI + unlimited wall time used to expose this:
# the cell finished and console.log said "done", but bash never returned.
gemini_cli_unlimited_root="$work/gemini-cli-unlimited-bench"
gemini_cli_unlimited_out=$(USE_GEMINI_CLI=1 GEMINI_BIN="$fake_gemini" \
  audit_timeout_run 8 bash "$BENCH" --target "$bench_target" --backend gemini \
    --replicates 1 --conditions model-direct --budget-wall 0 \
    --bench-root "$gemini_cli_unlimited_root" 2>&1)
gemini_cli_unlimited_rc=$?
assert_eq "0" "$gemini_cli_unlimited_rc" \
  "T16k4: captured Gemini CLI unlimited benchmark exits without tee deadlock"
assert_match "cells complete: 1 done, 0 failed" "$gemini_cli_unlimited_out" \
  "T16k5: captured Gemini CLI unlimited benchmark cell marked done"

# ── T16l-o: benchmark harness cells do not dirty the real repo root ──────
# bin/audit cd's to its SCRIPT_ROOT before launching backend agents. In a
# benchmark harness cell, SCRIPT_ROOT must be the cell's repo facade, not the
# operator's real checkout; otherwise Gemini/agy writing a bare relative
# testcase leaves files like test_logic.c in /Users/.../work.
root_junk_name="benchmark-root-junk-$$.txt"
rm -f "$SCRIPT_ROOT/$root_junk_name" 2>/dev/null || true
gemini_harness_root="$work/gemini-harness-bench"
# This path starts the real bin/audit facade before the fake backend runs.
# The fake handles model preflight and writes immediately; the timeout is only
# the harness cell's normal stop condition, not the behavior under test here.
gemini_harness_out=$(GEMINI_BIN="$fake_gemini" FAKE_BACKEND_RELATIVE_WRITE="$root_junk_name" \
  bash "$BENCH" --target "$bench_target" --backend gemini \
    --replicates 1 --conditions harness --agents 1 --budget-wall 8 \
    --bench-root "$gemini_harness_root" 2>&1)
gemini_harness_rc=$?
assert_eq "0" "$gemini_harness_rc" \
  "T16l: fake-gemini harness benchmark cell exits cleanly"
assert_match "cells complete: 1 done, 0 failed" "$gemini_harness_out" \
  "T16m: fake-gemini harness benchmark cell marked done"
assert_file_not_exists "$SCRIPT_ROOT/$root_junk_name" \
  "T16n: harness benchmark does not create bare junk in the real repo root"
facade_junk=$(find "$gemini_harness_root/gemini" \
  -path "*/cells/harness-r1/repo-root/$root_junk_name" | head -1)
assert_file_exists "$facade_junk" \
  "T16o: bare junk is contained inside the harness cell repo facade"

summary
