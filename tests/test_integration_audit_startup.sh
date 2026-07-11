#!/usr/bin/env bash
# Fast subprocess smoke test for the complete bin/audit startup chain.
set -euo pipefail

TESTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT_ROOT="$(cd "$TESTS_DIR/.." && pwd)"
source "$TESTS_DIR/helpers.sh"

setup_test_env
slug="audit-startup-$PPID-$$"
target="$SCRIPT_ROOT/targets/$slug"
output="$SCRIPT_ROOT/output/$slug"
fake_codex="$TEST_TMPDIR/fake-codex"
trace="$TEST_TMPDIR/fake-codex.trace"
run_log="$TEST_TMPDIR/audit.log"
trap 'rm -rf "$target" "$output"; teardown_test_env' EXIT

mkdir -p "$target/src" "$output"
printf 'int sample_parse(void) { return 0; }\n' > "$target/src/sample.c"
printf '%s\n' \
  'target = "audit-startup"' \
  'is_browser = "0"' \
  '' \
  '[sanitizer]' \
  'enabled = []' \
  '' \
  '[runner]' \
  'bin = "/bin/true"' \
  'args = []' > "$output/target.toml"

cat > "$fake_codex" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
if [ "${1:-}" = "login" ] && [ "${2:-}" = "status" ]; then
  exit 0
fi
prompt=$(cat)
printf '%s\n' "$*" >> "$FAKE_CODEX_TRACE"
printf '{"type":"thread.started","thread_id":"startup-smoke"}\n'
printf '{"type":"item.completed","item":{"type":"command_execution","command":"fixture-read","exit_code":0}}\n'
case "$prompt" in
  *MODEL_PREFLIGHT_OK*) text=MODEL_PREFLIGHT_OK ;;
  *) text=done ;;
esac
printf '{"type":"item.completed","item":{"type":"agent_message","text":"%s"}}\n' "$text"
printf '{"type":"turn.completed","usage":{"input_tokens":1,"cached_input_tokens":0,"output_tokens":1}}\n'
SH
chmod +x "$fake_codex"

rc=0
FAKE_CODEX_TRACE="$trace" \
AUDIT_MODEL_PREFLIGHT_ATTEMPTS=1 \
AUDIT_MODEL_PREFLIGHT_TIMEOUT=10 \
COOLDOWN=0 \
LLM_DECIDE_DISABLE=1 \
NUM_AGENTS=1 \
"$SCRIPT_ROOT/bin/audit" \
  --target "$slug" \
  --backend codex \
  --model fixture-model \
  --codex-bin "$fake_codex" \
  --skip-recon \
  1 > "$run_log" 2>&1 || rc=$?

assert_eq 0 "$rc" "bin/audit completes one fake-backend iteration"
assert_file_contains "$run_log" "Model preflight passed" \
  "startup reaches model preflight"
assert_file_contains "$run_log" "Iteration 1 starting" \
  "startup reaches the real audit iteration"
assert_file_contains "$run_log" "Agent 1 cold-start finished rc=0" \
  "startup launches and collects the fake agent"
assert_file_not_contains "$run_log" "Traceback" \
  "startup has no uncaught Python exception"
assert_file_not_contains "$run_log" "AttributeError" \
  "runtime construction and preflight agree on their contract"

invocations=$(wc -l < "$trace" | tr -d ' ')
assert_eq 2 "$invocations" "fake backend receives model preflight and agent launch"

summary
