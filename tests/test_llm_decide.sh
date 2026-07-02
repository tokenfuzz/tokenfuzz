#!/usr/bin/env bash
# tests/test_llm_decide.sh — Unit tests for lib/llm_decide.sh
#
# Covers:
#   1. Disabled mode short-circuits.
#   2. Mock-based JSON returns success.
#   3. Per-decision mock wins over global mock.
#   4. File-based mock (@/path) reads JSON from file.
#   5. Missing required keys → rc=1.
#   6. Malformed JSON → rc=1.
#   7. Fenced JSON is unwrapped.
#   8. Balanced {…}/[…] extraction from prose-wrapped / multi-object output.
#   9. Array root with array key validation.
#  10. Empty prompt → rc=1.
#  11. Per-process call budget short-circuits.

set -uo pipefail

TESTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$TESTS_DIR/helpers.sh"
source "$SCRIPT_ROOT/lib/llm_decide.sh"

setup_test_env

# 1. Disabled mode
LLM_DECIDE_DISABLE=1 out=$(echo "anything" | llm_decide demo "" 2 2>/dev/null) || rc=$?
assert_eq "" "$out" "disable: stdout empty"
assert_eq "1" "${rc:-0}"  "disable: rc=1"

# 2. Mock JSON returns success
unset LLM_DECIDE_DISABLE
LLM_DECIDE_MOCK='{"keep":true,"reason":"test"}'
export LLM_DECIDE_MOCK
out=$(echo "anything" | llm_decide demo "keep,reason" 2)
rc=$?
assert_eq "0" "$rc" "mock: rc=0"
echo "$out" | jq -e '.keep == true' >/dev/null 2>&1 && pass "mock: keep=true parsed" || fail "mock: parse"
echo "$out" | jq -e '.reason == "test"' >/dev/null 2>&1 && pass "mock: reason parsed" || fail "mock: reason"
unset LLM_DECIDE_MOCK

# 3. Per-decision mock beats global mock
export LLM_DECIDE_MOCK='{"keep":false,"reason":"global"}'
export LLM_DECIDE_MOCK_DEMO='{"keep":true,"reason":"specific"}'
out=$(echo "x" | llm_decide demo "keep,reason" 2)
echo "$out" | jq -e '.reason == "specific"' >/dev/null 2>&1 && pass "per-decision mock wins" || fail "per-decision mock wins"
unset LLM_DECIDE_MOCK LLM_DECIDE_MOCK_DEMO

# 4. File-based mock
tmpf=$(mktemp)
printf '{"keep":true,"reason":"from-file"}' > "$tmpf"
export LLM_DECIDE_MOCK="@$tmpf"
out=$(echo "x" | llm_decide crash_triage "keep,reason" 2)
echo "$out" | jq -e '.reason == "from-file"' >/dev/null 2>&1 && pass "file mock read" || fail "file mock read"
rm -f "$tmpf"
unset LLM_DECIDE_MOCK

# 5. Missing required keys → rc=1
export LLM_DECIDE_MOCK='{"keep":true}'
out=$(echo "x" | llm_decide demo "keep,reason" 2 2>/dev/null) || rc=$?
assert_eq "1" "${rc:-0}" "missing key: rc=1"
assert_eq ""  "$out"     "missing key: empty stdout"
unset LLM_DECIDE_MOCK

# 6. Malformed JSON → rc=1
unset rc
export LLM_DECIDE_MOCK="not json at all"
out=$(echo "x" | llm_decide demo "keep" 2 2>/dev/null) || rc=$?
assert_eq "1" "${rc:-0}" "malformed: rc=1"
unset LLM_DECIDE_MOCK

# 7. Fenced JSON unwrapped
tmpf=$(mktemp)
{
  echo "Here is the answer:"
  echo '```json'
  echo '{"keep":true,"reason":"fenced"}'
  echo '```'
  echo "Hope that helps."
} > "$tmpf"
export LLM_DECIDE_MOCK="@$tmpf"
out=$(echo "x" | llm_decide demo "keep,reason" 2)
echo "$out" | jq -e '.reason == "fenced"' >/dev/null 2>&1 && pass "fence stripped" || fail "fence stripped: out=$out"
rm -f "$tmpf"
unset LLM_DECIDE_MOCK

# 8. Balanced span from prose-wrapped JSON
tmpf=$(mktemp)
printf 'Here it is: {"keep":false,"reason":"prose"} done.' > "$tmpf"
export LLM_DECIDE_MOCK="@$tmpf"
out=$(echo "x" | llm_decide demo "keep,reason" 2)
echo "$out" | jq -e '.reason == "prose"' >/dev/null 2>&1 && pass "balanced span extracted" || fail "balanced span: out=$out"
rm -f "$tmpf"
unset LLM_DECIDE_MOCK

# 8b. Trailing prose containing a brace. The old greedy {.*} span ran to
#     the LAST brace in the output and failed to parse; the balanced
#     scanner stops at the first complete object.
tmpf=$(mktemp)
printf '{"keep":true,"reason":"balanced"} note: see {placeholder}.' > "$tmpf"
export LLM_DECIDE_MOCK="@$tmpf"
out=$(echo "x" | llm_decide demo "keep,reason" 2)
echo "$out" | jq -e '.reason == "balanced"' >/dev/null 2>&1 \
  && pass "balanced extract: trailing brace-prose ignored" \
  || fail "balanced extract: trailing brace-prose: out=$out"
rm -f "$tmpf"
unset LLM_DECIDE_MOCK

# 8c. Two JSON objects — the FIRST is returned. Greedy spanned both plus
#     the gap between them and parsed as nothing.
tmpf=$(mktemp)
printf '{"keep":true,"reason":"first"}\n{"keep":false,"reason":"second"}' > "$tmpf"
export LLM_DECIDE_MOCK="@$tmpf"
out=$(echo "x" | llm_decide demo "keep,reason" 2)
echo "$out" | jq -e '.reason == "first"' >/dev/null 2>&1 \
  && pass "balanced extract: first of two objects" \
  || fail "balanced extract: two objects: out=$out"
rm -f "$tmpf"
unset LLM_DECIDE_MOCK

# 8d. A brace inside a JSON string value must not end the object early,
#     even with a stray brace later in the prose.
tmpf=$(mktemp)
printf 'answer: {"keep":true,"reason":"has } brace"} and {junk}' > "$tmpf"
export LLM_DECIDE_MOCK="@$tmpf"
out=$(echo "x" | llm_decide demo "keep,reason" 2)
echo "$out" | jq -e '.reason == "has } brace"' >/dev/null 2>&1 \
  && pass "balanced extract: brace inside string literal" \
  || fail "balanced extract: brace in string: out=$out"
rm -f "$tmpf"
unset LLM_DECIDE_MOCK

# 9. Array root validation: every element must contain key
export LLM_DECIDE_MOCK='[{"id":"a"},{"id":"b"}]'
out=$(echo "x" | llm_decide demo "id" 2)
echo "$out" | jq -e 'length == 2' >/dev/null 2>&1 && pass "array all-keys ok" || fail "array all-keys"
unset LLM_DECIDE_MOCK
unset rc
export LLM_DECIDE_MOCK='[{"id":"a"},{}]'
out=$(echo "x" | llm_decide demo "id" 2 2>/dev/null) || rc=$?
assert_eq "1" "${rc:-0}" "array missing key on element → rc=1"
unset LLM_DECIDE_MOCK

# 10. OSS backend invokes OpenCode with provider/model config
fake_opencode="$TEST_TMPDIR/fake-opencode-oss"
cat > "$fake_opencode" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$*" > "$FAKE_OPENCODE_ARGS"
printf '%s\n' "${OPENCODE_CONFIG_CONTENT:-}" > "$FAKE_OPENCODE_CONFIG"
printf '{"type":"message","role":"assistant","content":"{\\"keep\\":true,\\"reason\\":\\"oss\\"}"}\n'
EOF
chmod +x "$fake_opencode"
unset rc
unset LLM_DECIDE_DISABLE
export ACTIVE_BACKEND=oss
export MODEL="qwen3-14b"
export OPENCODE_BIN="$fake_opencode"
export FAKE_OPENCODE_ARGS="$TEST_TMPDIR/fake-opencode-oss.args"
export FAKE_OPENCODE_CONFIG="$TEST_TMPDIR/fake-opencode-oss.config"
export LLM_DECIDE_COUNTER_FILE="$TEST_TMPDIR/llm-count-oss"
out=$(echo "x" | llm_decide demo "keep,reason" 2)
assert_eq "0" "$?" "oss backend: llm_decide succeeds through fake OpenCode"
assert_match '"reason":"oss"|\"reason\": \"oss\"' "$out" "oss backend: parses fake OpenCode JSON"
oss_args=$(cat "$FAKE_OPENCODE_ARGS")
assert_match 'run --model local/qwen3-14b --format json x' "$oss_args" \
  "oss backend: OpenCode args pass prompt as message"
assert_not_match '--file' "$oss_args" \
  "oss backend: OpenCode args do not attach prompt file"
oss_config=$(cat "$FAKE_OPENCODE_CONFIG")
assert_match '"provider":\{"local"' "$oss_config" "oss backend: OpenCode config defines shared local provider"
assert_match '"qwen3-14b"' "$oss_config" "oss backend: OpenCode config includes resolved model"
if grep -q -- '--output-schema' <<<"$oss_args"; then
  fail "oss backend: decision calls use plain text JSON, not CLI schema flags" "got: $oss_args"
else
  pass "oss backend: decision calls use plain text JSON, not CLI schema flags"
fi
unset ACTIVE_BACKEND MODEL OPENCODE_BIN FAKE_OPENCODE_ARGS FAKE_OPENCODE_CONFIG LLM_DECIDE_COUNTER_FILE

# 10b. Standalone helper compatibility: BACKEND is accepted when
# ACTIVE_BACKEND is unset. bin/audit still uses ACTIVE_BACKEND internally
# after resolving --backend all to one concrete provider.
fake_codex_backend_alias="$TEST_TMPDIR/fake-codex-backend-alias"
cat > "$fake_codex_backend_alias" <<'EOF'
#!/usr/bin/env bash
cat >/dev/null
printf '{"keep":true,"reason":"backend-alias"}\n'
EOF
chmod +x "$fake_codex_backend_alias"
unset rc ACTIVE_BACKEND LLM_DECIDE_DISABLE
export BACKEND=codex
export CODEX_BIN="$fake_codex_backend_alias"
export LLM_DECIDE_COUNTER_FILE="$TEST_TMPDIR/llm-count-backend-alias"
out=$(echo "x" | llm_decide demo "keep,reason" 2)
assert_eq "0" "$?" "BACKEND alias: llm_decide succeeds without ACTIVE_BACKEND"
assert_match '"reason":"backend-alias"|\"reason\": \"backend-alias\"' "$out" \
  "BACKEND alias: parses fake Codex JSON"
unset BACKEND CODEX_BIN LLM_DECIDE_COUNTER_FILE

# 10c. Codex decision calls use the same plain-text JSON contract as
# Claude/Gemini. Nested outputs are accepted through JSON extraction and
# backend-independent runtime shape validation, not through CLI schemas.
fake_codex_nested="$TEST_TMPDIR/fake-codex-nested-json"
cat > "$fake_codex_nested" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$*" > "$FAKE_CODEX_ARGS"
cat >/dev/null
printf 'Here is JSON:\n{"rows":[{"file":"a.cc","function":"f","line":1,"hypothesis":"h","category":"bounds"}]}\n'
EOF
chmod +x "$fake_codex_nested"
unset rc LLM_DECIDE_DISABLE ACTIVE_BACKEND BACKEND
export ACTIVE_BACKEND=codex
export CODEX_BIN="$fake_codex_nested"
export FAKE_CODEX_ARGS="$TEST_TMPDIR/fake-codex-nested.args"
export LLM_DECIDE_COUNTER_FILE="$TEST_TMPDIR/llm-count-codex-nested"
out=$(echo "x" | llm_decide cluster_expand "rows" 2)
assert_eq "0" "$?" "Codex text JSON: nested cluster decision succeeds"
echo "$out" | jq -e '.rows[0].line == 1 and .rows[0].category == "bounds"' >/dev/null 2>&1 \
  && pass "Codex text JSON: nested row parsed and validated" \
  || fail "Codex text JSON: nested row parsed and validated" "$out"
codex_nested_args=$(cat "$FAKE_CODEX_ARGS")
if grep -q -- '--output-schema' <<<"$codex_nested_args"; then
  fail "Codex text JSON: no schema flag is passed" "got: $codex_nested_args"
else
  pass "Codex text JSON: no schema flag is passed"
fi
unset ACTIVE_BACKEND CODEX_BIN FAKE_CODEX_ARGS LLM_DECIDE_COUNTER_FILE

# 10d. Runtime shape validation is backend-independent: even if a
# backend returns valid JSON with the required key, wrong value types are
# rejected before consumers see the payload.
unset rc
export LLM_DECIDE_MOCK='{"attacker_controls":"{\"attacker_controls\":[\"bytes\"]}"}'
out=$(echo "x" | llm_decide threat-model-suggest "attacker_controls" 2 2>/dev/null) || rc=$?
assert_eq "1" "${rc:-0}" "shape validation: rejects nested JSON string in attacker_controls"
assert_eq "" "$out" "shape validation: wrong-type response has empty stdout"
unset LLM_DECIDE_MOCK

# 11. Gemini backend invokes the Antigravity CLI (agy) in --print mode.
fake_gemini="$TEST_TMPDIR/fake-agy-decision"
cat > "$fake_gemini" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$*" > "$FAKE_GEMINI_ARGS"
cat >/dev/null
printf '{"keep":true,"reason":"agy"}\n'
EOF
chmod +x "$fake_gemini"
unset rc
unset LLM_DECIDE_DISABLE
export ACTIVE_BACKEND=gemini
unset USE_GEMINI_CLI
export GEMINI_BIN="$fake_gemini"
export FAKE_GEMINI_ARGS="$TEST_TMPDIR/fake-agy-decision.args"
export LLM_DECIDE_COUNTER_FILE="$TEST_TMPDIR/llm-count-gemini"
out=$(echo "x" | llm_decide demo "keep,reason" 2)
assert_eq "0" "$?" "gemini backend: llm_decide succeeds through fake agy"
assert_match '"reason":"agy"|\"reason\": \"agy\"' "$out" "gemini backend: parses fake agy JSON"
gemini_args=$(cat "$FAKE_GEMINI_ARGS")
assert_match '.*--dangerously-skip-permissions' "$gemini_args" "gemini backend: passes --dangerously-skip-permissions"
assert_match '.* -p' "$gemini_args" "gemini backend: uses prompt flag"
# agy 1.0.5+ pins the model by its display label (mapped from the config slug),
# but still has no --output-format / --approval-mode equivalents.
assert_match '--model Gemini 3.1 Pro \(High\)' "$gemini_args" "gemini backend: wires the mapped agy model label"
if grep -qE -- '--output-format|--approval-mode' <<<"$gemini_args"; then
  fail "gemini backend: must not pass legacy gemini-cli flags" "got: $gemini_args"
else
  pass "gemini backend: omits legacy gemini-cli flags"
fi
unset ACTIVE_BACKEND GEMINI_BIN FAKE_GEMINI_ARGS LLM_DECIDE_COUNTER_FILE

# 11b. USE_GEMINI_CLI keeps backend name "gemini" but switches flags to
# Google Gemini CLI equivalents.
fake_gemini_cli="$TEST_TMPDIR/fake-gemini-cli-decision"
cat > "$fake_gemini_cli" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$*" > "$FAKE_GEMINI_CLI_ARGS"
cat >/dev/null
printf '{"keep":true,"reason":"gemini-cli"}\n'
EOF
chmod +x "$fake_gemini_cli"
unset rc
unset LLM_DECIDE_DISABLE
export ACTIVE_BACKEND=gemini
export USE_GEMINI_CLI=1
export GEMINI_BIN="$fake_gemini_cli"
export FAKE_GEMINI_CLI_ARGS="$TEST_TMPDIR/fake-gemini-cli-decision.args"
export LLM_DECIDE_COUNTER_FILE="$TEST_TMPDIR/llm-count-gemini-cli"
out=$(echo "x" | llm_decide demo "keep,reason" 2)
assert_eq "0" "$?" "gemini backend: llm_decide succeeds through fake Gemini CLI"
assert_match '"reason":"gemini-cli"|\"reason\": \"gemini-cli\"' "$out" "gemini backend: parses fake Gemini CLI JSON"
gemini_cli_args=$(cat "$FAKE_GEMINI_CLI_ARGS")
assert_match '.*--approval-mode=plan' "$gemini_cli_args" "gemini backend CLI: uses plan approval mode for decide"
assert_match '.*--skip-trust' "$gemini_cli_args" "gemini backend CLI: skips workspace trust prompt"
assert_match '.*--model gemini-3.1-pro-preview' "$gemini_cli_args" "gemini backend CLI: passes default model"
assert_match '.* -p' "$gemini_cli_args" "gemini backend CLI: uses prompt flag"
if grep -q -- '--dangerously-skip-permissions' <<<"$gemini_cli_args"; then
  fail "gemini backend CLI: must not pass agy skip-permissions" "got: $gemini_cli_args"
else
  pass "gemini backend CLI: omits agy skip-permissions"
fi
unset ACTIVE_BACKEND USE_GEMINI_CLI GEMINI_BIN FAKE_GEMINI_CLI_ARGS LLM_DECIDE_COUNTER_FILE

# 11c. Cross-run memory is disabled at the ENV level for the claude subprocess
#      llm_decide launches — covers standalone tools (bin/setup-target,
#      bin/suggest-*) that import llm_decide without going through a bash entry
#      point's llm_apply_memory_policy. The fake claude echoes the env var it
#      was launched with.
fake_claude_mem="$TEST_TMPDIR/fake-claude-mem"
cat > "$fake_claude_mem" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "${CLAUDE_CODE_DISABLE_AUTO_MEMORY:-UNSET}" > "$FAKE_CLAUDE_MEM_ENV"
cat >/dev/null
printf '{"keep":true,"reason":"claude-mem"}\n'
EOF
chmod +x "$fake_claude_mem"
unset rc LLM_DECIDE_DISABLE TOKENFUZZ_MEMORY_ENABLED CLAUDE_CODE_DISABLE_AUTO_MEMORY
export ACTIVE_BACKEND=claude
export CLAUDE_BIN="$fake_claude_mem"
export FAKE_CLAUDE_MEM_ENV="$TEST_TMPDIR/fake-claude-mem.env"
export LLM_DECIDE_COUNTER_FILE="$TEST_TMPDIR/llm-count-claude-mem"
out=$(echo "x" | llm_decide demo "keep,reason" 2)
assert_eq "0" "$?" "claude memory: llm_decide succeeds through fake claude"
assert_eq "1" "$(cat "$FAKE_CLAUDE_MEM_ENV")" \
  "claude memory: subprocess sees CLAUDE_CODE_DISABLE_AUTO_MEMORY=1 by default"
# --enable-memory (TOKENFUZZ_MEMORY_ENABLED=1): the disable env is NOT forced on.
export TOKENFUZZ_MEMORY_ENABLED=1
out=$(echo "x" | llm_decide demo "keep,reason" 2)
assert_eq "UNSET" "$(cat "$FAKE_CLAUDE_MEM_ENV")" \
  "claude memory: --enable-memory leaves CLAUDE_CODE_DISABLE_AUTO_MEMORY unset"
unset TOKENFUZZ_MEMORY_ENABLED ACTIVE_BACKEND CLAUDE_BIN FAKE_CLAUDE_MEM_ENV LLM_DECIDE_COUNTER_FILE

# 11d. The Gemini CLI subprocess is launched with GEMINI_CLI_HOME relocated to
#      a throwaway home that excludes the global GEMINI.md — read+write
#      isolation, since denying save_memory alone does not stop the auto-load
#      of ~/.gemini/GEMINI.md nor write_file appends to it.
fake_gemini_mem="$TEST_TMPDIR/fake-gemini-mem"
cat > "$fake_gemini_mem" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "${GEMINI_CLI_HOME:-UNSET}" > "$FAKE_GEMINI_MEM_ENV"
cat >/dev/null
printf '{"keep":true,"reason":"gemini-mem"}\n'
EOF
chmod +x "$fake_gemini_mem"
unset rc LLM_DECIDE_DISABLE TOKENFUZZ_MEMORY_ENABLED GEMINI_CLI_HOME
export ACTIVE_BACKEND=gemini USE_GEMINI_CLI=1
export GEMINI_BIN="$fake_gemini_mem"
export FAKE_GEMINI_MEM_ENV="$TEST_TMPDIR/fake-gemini-mem.env"
export LLM_DECIDE_COUNTER_FILE="$TEST_TMPDIR/llm-count-gemini-mem"
out=$(echo "x" | llm_decide demo "keep,reason" 2)
assert_eq "0" "$?" "gemini memory: llm_decide succeeds through fake Gemini CLI"
gem_home_used="$(cat "$FAKE_GEMINI_MEM_ENV")"
if [ "$gem_home_used" != "UNSET" ] && [ -d "$gem_home_used/.gemini" ] \
   && [ -e "$gem_home_used/.gemini/.tokenfuzz-memory-isolated" ] \
   && [ ! -e "$gem_home_used/.gemini/GEMINI.md" ] \
   && [ ! -e "$gem_home_used/.gemini/tmp" ]; then
  pass "gemini memory: subprocess GEMINI_CLI_HOME relocated without memory state"
else
  fail "gemini memory: subprocess GEMINI_CLI_HOME relocated without memory state" \
    "got: $gem_home_used"
fi
# Clean up the throwaway isolated home this test staged.
[ "$gem_home_used" != "UNSET" ] && [ -d "$gem_home_used" ] && rm -rf "$gem_home_used"
unset ACTIVE_BACKEND USE_GEMINI_CLI GEMINI_BIN FAKE_GEMINI_MEM_ENV LLM_DECIDE_COUNTER_FILE

# 12. Empty prompt → rc=1
unset rc
out=$(echo -n "" | llm_decide demo "" 2 2>/dev/null) || rc=$?
assert_eq "1" "${rc:-0}" "empty prompt → rc=1"

# 13. Budget cap
unset rc
export LLM_DECIDE_COUNTER_FILE="$TEST_TMPDIR/llm-count"
export LLM_DECIDE_MAX_CALLS=1
export LLM_DECIDE_MOCK='{"keep":true,"reason":"budget"}'
out=$(echo "x" | llm_decide demo "keep,reason" 2)
assert_match '"reason":"budget"|\"reason\": \"budget\"' "$out" "budget: first call succeeds"
out=$(echo "x" | llm_decide demo "keep,reason" 2 2>/dev/null) || rc=$?
assert_eq "1" "${rc:-0}" "budget: second call fails"
unset LLM_DECIDE_COUNTER_FILE LLM_DECIDE_MAX_CALLS LLM_DECIDE_MOCK

# 13a. Empty / whitespace-only prompts MUST NOT charge budget.
#      Previously budget_available() ran first; an empty prompt drained one
#      unit and then immediately FAIL'd. A second valid call would then be
#      starved by budget exhaustion even though no backend was ever invoked.
unset rc
export LLM_DECIDE_COUNTER_FILE="$TEST_TMPDIR/llm-count-empty"
export LLM_DECIDE_MAX_CALLS=1
export LLM_DECIDE_MOCK='{"keep":true,"reason":"after-empty"}'
# First: a bogus empty-prompt call.
out=$(echo -n "" | llm_decide demo "keep,reason" 2 2>/dev/null) || rc=$?
assert_eq "1" "${rc:-0}" "empty-vs-budget: empty prompt still rc=1"
counter_after_empty=$(cat "$LLM_DECIDE_COUNTER_FILE" 2>/dev/null || echo 0)
counter_after_empty=${counter_after_empty:-0}
assert_eq "0" "$counter_after_empty" \
  "empty-vs-budget: counter file did not advance for the empty prompt"
# Second: a real call now has the full budget waiting for it.
unset rc
out=$(echo "x" | llm_decide demo "keep,reason" 2)
rc=$?
assert_eq "0" "$rc" "empty-vs-budget: subsequent real call succeeds (budget intact)"
assert_match '"reason":"after-empty"|\"reason\": \"after-empty\"' "$out" \
  "empty-vs-budget: returned the real-call mock JSON"
unset LLM_DECIDE_COUNTER_FILE LLM_DECIDE_MAX_CALLS LLM_DECIDE_MOCK

# 13b. Standalone helper calls have no LOGDIR/counter file; they must not
# inherit a stale global /tmp counter from unrelated terminal runs.
unset rc LOGDIR LLM_DECIDE_COUNTER_FILE LLM_DECIDE_MAX_CALLS
export LLM_DECIDE_MOCK='{"keep":true,"reason":"standalone"}'
out=$(echo "x" | llm_decide demo "keep,reason" 2)
assert_match '"reason":"standalone"|\"reason\": \"standalone\"' "$out" \
  "budget: standalone calls without LOGDIR do not use stale global counter"
unset LLM_DECIDE_MOCK

# 14. Telemetry: prompt-byte + elapsed-seconds appended to log lines.
# We exercise the MOCK path (deterministic, no real backend) and verify
# both the OK success line and a controlled FAIL line carry the new
# bytes=N elapsed=Ns fields. Future cost-analysis depends on this format,
# so any rename of these field keys should land alongside its consumers.
unset rc
tel_log="$TEST_TMPDIR/llm-telemetry.log"
: > "$tel_log"
export LLM_DECIDE_LOG="$tel_log"
export LLM_DECIDE_MOCK='{"keep":true,"reason":"telemetry"}'
export LLM_DECIDE_COUNTER_FILE="$TEST_TMPDIR/llm-count-tel"

# Success path: prompt has known byte count (29 chars + 1 newline from echo).
prompt='telemetry assertion prompt'
expected_bytes=$(printf '%s' "$prompt" | wc -c | tr -d ' ')
echo "$prompt" | llm_decide demo "keep,reason" 2 >/dev/null
log_content=$(cat "$tel_log")
assert_match "demo MOCK bytes=${expected_bytes} elapsed=" "$log_content" \
  "telemetry: MOCK line carries bytes and elapsed"
assert_match "demo OK bytes=${expected_bytes} elapsed=[0-9]+s" "$log_content" \
  "telemetry: OK line format matches bytes=N elapsed=Ns"

# Failure path: invalid mock JSON triggers extract-json FAIL. Telemetry
# still appears so we can see what we paid for an unparseable response.
: > "$tel_log"
export LLM_DECIDE_MOCK="not-json-at-all"
echo "$prompt" | llm_decide demo "keep" 2 2>/dev/null || true
log_content=$(cat "$tel_log")
assert_match "demo FAIL extract-json bytes=${expected_bytes} elapsed=[0-9]+s" "$log_content" \
  "telemetry: extract-json failure carries bytes + elapsed"

# Missing-keys failure: parseable JSON but missing a required key.
: > "$tel_log"
export LLM_DECIDE_MOCK='{"keep":true}'
echo "$prompt" | llm_decide demo "keep,reason" 2 2>/dev/null || true
log_content=$(cat "$tel_log")
assert_match "demo FAIL missing-keys=keep,reason bytes=${expected_bytes} elapsed=[0-9]+s" \
  "$log_content" "telemetry: missing-keys failure carries bytes + elapsed"

# Empty-prompt is BEFORE the byte/elapsed window — no telemetry expected.
# This documents the explicit boundary so future changes don't accidentally
# log bytes=0 (and confuse the cost analysis).
: > "$tel_log"
export LLM_DECIDE_MOCK='{"keep":true,"reason":"x"}'
echo -n "" | llm_decide demo "keep,reason" 2 2>/dev/null || true
log_content=$(cat "$tel_log")
assert_match "demo FAIL empty-prompt" "$log_content" \
  "telemetry: empty-prompt logs the FAIL marker"
if grep -q 'empty-prompt bytes=' <<< "$log_content"; then
  fail "telemetry: empty-prompt must NOT carry bytes (no prompt was captured)"
else
  pass "telemetry: empty-prompt correctly omits bytes/elapsed"
fi

unset LLM_DECIDE_LOG LLM_DECIDE_MOCK LLM_DECIDE_COUNTER_FILE

# 15. Concurrent budget — race-safety. N concurrent callers race to
#     consume a cap of K calls; exactly K must succeed and N-K must be
#     denied. Without a serialized read-modify-write, the race in
#     llm_decide_budget_available silently allowed more than K calls
#     to slip past the cap (lost updates from interleaved increments).
unset rc LLM_DECIDE_MOCK
N=20
K=8
export LLM_DECIDE_COUNTER_FILE="$TEST_TMPDIR/llm-count-race"
export LLM_DECIDE_MAX_CALLS="$K"
rm -f "$LLM_DECIDE_COUNTER_FILE"
oks_file="$TEST_TMPDIR/budget-race-oks"
: > "$oks_file"
for i in $(seq 1 "$N"); do
  ( llm_decide_budget_available && echo "ok" >> "$oks_file" ) &
done
wait
ok_count=$(wc -l < "$oks_file" | tr -d ' ')
counter_final=$(cat "$LLM_DECIDE_COUNTER_FILE" 2>/dev/null)
assert_eq "$K" "$ok_count" "concurrent budget: exactly K=${K} callers consumed budget"
assert_eq "$K" "$counter_final" "concurrent budget: counter file matches K"
unset LLM_DECIDE_COUNTER_FILE LLM_DECIDE_MAX_CALLS

# 16. find_quality: shape validation checks only the required fields
#     (accept/reason/class/severity) and ignores any extra key a model emits —
#     including a stray `dedup_key:null` left over from an older prompt. Such an
#     unknown field must NOT discard the verdict (that would re-incur the call
#     every maintain_indexes pass); a null on a REQUIRED field must still fail.
unset rc
export LLM_DECIDE_MOCK_FIND_QUALITY='{"accept":true,"reason":"ok","class":"memory-safety","severity":"high","dedup_key":null}'
out=$(echo "x" | llm_decide find_quality "accept,reason,class,severity" 2 2>/dev/null) || rc=$?
assert_eq "0" "${rc:-0}" "find_quality: null optional dedup_key → rc=0 (verdict kept)"
echo "$out" | jq -e '.accept == true and .class == "memory-safety"' >/dev/null 2>&1 \
  && pass "find_quality: verdict survives a null dedup_key" \
  || fail "find_quality: verdict dropped on null dedup_key: out=$out"
unset LLM_DECIDE_MOCK_FIND_QUALITY rc
export LLM_DECIDE_MOCK_FIND_QUALITY='{"accept":true,"reason":"ok","class":null,"severity":"high"}'
out=$(echo "x" | llm_decide find_quality "accept,reason,class,severity" 2 2>/dev/null) || rc=$?
assert_eq "1" "${rc:-0}" "find_quality: null on REQUIRED class still rejected"
unset LLM_DECIDE_MOCK_FIND_QUALITY rc

# 17. Failed-decision circuit breaker. A decision whose exact (decision,
#     prompt) keeps failing must not re-invoke the backend forever — that is
#     the OSS cluster_expand 180s-timeout-every-pass waste. After the failure
#     threshold the breaker opens and identical requests are skipped without a
#     backend call; a different prompt is unaffected; a success clears the key.
unset rc LLM_DECIDE_MOCK LLM_DECIDE_DISABLE
fake_fail="$TEST_TMPDIR/fake-codex-cb-fail"
cat > "$fake_fail" <<'EOF'
#!/usr/bin/env bash
echo call >> "$FAKE_CB_CALLS"
cat >/dev/null
exit 1
EOF
chmod +x "$fake_fail"
fake_ok="$TEST_TMPDIR/fake-codex-cb-ok"
cat > "$fake_ok" <<'EOF'
#!/usr/bin/env bash
echo call >> "$FAKE_CB_CALLS"
cat >/dev/null
printf '{"keep":true,"reason":"cb-ok"}\n'
EOF
chmod +x "$fake_ok"
export ACTIVE_BACKEND=codex
export CODEX_BIN="$fake_fail"
export FAKE_CB_CALLS="$TEST_TMPDIR/fake-cb.calls"
: > "$FAKE_CB_CALLS"
export LLM_DECIDE_COUNTER_FILE="$TEST_TMPDIR/llm-count-cb"
export LLM_DECIDE_FAILCACHE_FILE="$TEST_TMPDIR/llm-failcache-cb"
export LLM_DECIDE_FAIL_THRESHOLD=1

# First failing call reaches the backend and records the failure.
out=$(echo "same-prompt" | llm_decide demo "keep" 5 2>/dev/null) || rc=$?
assert_eq "1" "${rc:-0}" "circuit breaker: first failing call returns rc=1"
assert_eq "1" "$(wc -l < "$FAKE_CB_CALLS" | tr -d ' ')" \
  "circuit breaker: first call invoked the backend"

# Identical repeat is skipped — the backend is NOT invoked again.
unset rc
out=$(echo "same-prompt" | llm_decide demo "keep" 5 2>/dev/null) || rc=$?
assert_eq "1" "${rc:-0}" "circuit breaker: repeat identical call still rc=1"
assert_eq "1" "$(wc -l < "$FAKE_CB_CALLS" | tr -d ' ')" \
  "circuit breaker: repeat identical call skipped the backend"

# A different prompt has its own key and still reaches the backend.
unset rc
out=$(echo "other-prompt" | llm_decide demo "keep" 5 2>/dev/null) || rc=$?
assert_eq "2" "$(wc -l < "$FAKE_CB_CALLS" | tr -d ' ')" \
  "circuit breaker: a different prompt still reaches the backend"
unset ACTIVE_BACKEND CODEX_BIN FAKE_CB_CALLS LLM_DECIDE_COUNTER_FILE \
  LLM_DECIDE_FAILCACHE_FILE LLM_DECIDE_FAIL_THRESHOLD

# 17b. A success clears the recorded failure so the threshold counts
#      consecutive failures (a high threshold keeps the breaker from opening
#      during the test so the success call is dispatched, not skipped).
unset rc
export ACTIVE_BACKEND=codex
export FAKE_CB_CALLS="$TEST_TMPDIR/fake-cb2.calls"
: > "$FAKE_CB_CALLS"
export LLM_DECIDE_COUNTER_FILE="$TEST_TMPDIR/llm-count-cb2"
export LLM_DECIDE_FAILCACHE_FILE="$TEST_TMPDIR/llm-failcache-cb2"
export LLM_DECIDE_FAIL_THRESHOLD=5
rm -f "$LLM_DECIDE_FAILCACHE_FILE"
export CODEX_BIN="$fake_fail"
out=$(echo "clearme" | llm_decide demo "keep" 5 2>/dev/null) || true
grep -q '"demo:' "$LLM_DECIDE_FAILCACHE_FILE" 2>/dev/null \
  && pass "circuit breaker: failure recorded in failcache" \
  || fail "circuit breaker: failure recorded in failcache"
export CODEX_BIN="$fake_ok"
out=$(echo "clearme" | llm_decide demo "keep" 5)
assert_eq "0" "$?" "circuit breaker: success call dispatched below threshold"
if grep -q '"demo:' "$LLM_DECIDE_FAILCACHE_FILE" 2>/dev/null; then
  fail "circuit breaker: success did not clear the failcache key"
else
  pass "circuit breaker: success cleared the failcache key"
fi
unset ACTIVE_BACKEND CODEX_BIN FAKE_CB_CALLS LLM_DECIDE_COUNTER_FILE \
  LLM_DECIDE_FAILCACHE_FILE LLM_DECIDE_FAIL_THRESHOLD

# 17c. A corrupted failcache value must never raise into the decision path.
#      The failcache is best-effort telemetry; a non-numeric value under the
#      real key is treated as count 0, so a real-backend decision still runs.
#      Without the guard, int("garbage") would raise out of the skip check
#      and crash the decision (rc!=0). The key is demo:<sha1(prompt)[:16]>.
unset rc LLM_DECIDE_MOCK
export ACTIVE_BACKEND=codex
export CODEX_BIN="$fake_ok"
export FAKE_CB_CALLS="$TEST_TMPDIR/fake-cb3.calls"
: > "$FAKE_CB_CALLS"
export LLM_DECIDE_COUNTER_FILE="$TEST_TMPDIR/llm-count-cb3"
export LLM_DECIDE_FAILCACHE_FILE="$TEST_TMPDIR/llm-failcache-corrupt"
export LLM_DECIDE_FAIL_THRESHOLD=1
corrupt_key="demo:$(printf 'x' | shasum -a 1 | cut -c1-16)"
printf '{"%s":"garbage","other":[1,2]}' "$corrupt_key" > "$LLM_DECIDE_FAILCACHE_FILE"
out=$(echo "x" | llm_decide demo "keep,reason" 5 2>/dev/null) || rc=$?
assert_eq "0" "${rc:-0}" "circuit breaker: corrupted failcache value does not crash the decision"
assert_match '"reason":"cb-ok"|\"reason\": \"cb-ok\"' "$out" \
  "circuit breaker: decision still returns its result despite corrupt failcache"
unset ACTIVE_BACKEND CODEX_BIN FAKE_CB_CALLS LLM_DECIDE_COUNTER_FILE \
  LLM_DECIDE_FAILCACHE_FILE LLM_DECIDE_FAIL_THRESHOLD

# 17d. Half-open cooldown: a tripped key is skipped only until the cooldown
#      elapses, then one retry reaches the backend — so a transiently
#      unhealthy backend self-heals instead of being skipped all session.
#      Timestamps are seeded directly to avoid a real sleep.
unset rc LLM_DECIDE_MOCK
key="demo:$(printf 'x' | shasum -a 1 | cut -c1-16)"
export ACTIVE_BACKEND=codex
export CODEX_BIN="$fake_ok"
export FAKE_CB_CALLS="$TEST_TMPDIR/fake-cb4.calls"
export LLM_DECIDE_COUNTER_FILE="$TEST_TMPDIR/llm-count-cb4"
export LLM_DECIDE_FAILCACHE_FILE="$TEST_TMPDIR/llm-failcache-cd"
export LLM_DECIDE_FAIL_THRESHOLD=2
export LLM_DECIDE_FAIL_COOLDOWN=600

# Recent failure (ts=now): within the 600s cooldown → still skipped.
: > "$FAKE_CB_CALLS"
now=$(date +%s)
printf '{"%s":[3,%s]}' "$key" "$now" > "$LLM_DECIDE_FAILCACHE_FILE"
out=$(echo "x" | llm_decide demo "keep,reason" 5 2>/dev/null) || rc=$?
assert_eq "1" "${rc:-0}" "cooldown: tripped key within cooldown returns rc=1"
assert_eq "0" "$(wc -l < "$FAKE_CB_CALLS" | tr -d ' ')" \
  "cooldown: tripped key within cooldown skips the backend"

# Stale failure (ancient ts): cooldown elapsed → one half-open retry reaches
# the backend, which now succeeds and clears the key.
: > "$FAKE_CB_CALLS"
printf '{"%s":[3,1.0]}' "$key" > "$LLM_DECIDE_FAILCACHE_FILE"
unset rc
out=$(echo "x" | llm_decide demo "keep,reason" 5 2>/dev/null) || rc=$?
assert_eq "0" "${rc:-0}" "cooldown: half-open retry after cooldown succeeds"
assert_eq "1" "$(wc -l < "$FAKE_CB_CALLS" | tr -d ' ')" \
  "cooldown: half-open retry reaches the backend"
if grep -q "\"$key\"" "$LLM_DECIDE_FAILCACHE_FILE" 2>/dev/null; then
  fail "cooldown: a successful half-open retry did not clear the key"
else
  pass "cooldown: a successful half-open retry cleared the key"
fi
unset ACTIVE_BACKEND CODEX_BIN FAKE_CB_CALLS LLM_DECIDE_COUNTER_FILE \
  LLM_DECIDE_FAILCACHE_FILE LLM_DECIDE_FAIL_THRESHOLD LLM_DECIDE_FAIL_COOLDOWN

# 17e. The cooldown default is backend-tiered so a healthy cloud target
#      recovers fast while OSS's expensive deterministic timeouts back off
#      hard. An explicit LLM_DECIDE_FAIL_COOLDOWN still overrides both.
unset LLM_DECIDE_FAIL_COOLDOWN
cd_oss=$(ACTIVE_BACKEND=oss python3 -c \
  "import sys; sys.path.insert(0,'$SCRIPT_ROOT/lib'); import llm_decide as L; print(int(L._fail_cooldown()))")
cd_codex=$(ACTIVE_BACKEND=codex python3 -c \
  "import sys; sys.path.insert(0,'$SCRIPT_ROOT/lib'); import llm_decide as L; print(int(L._fail_cooldown()))")
cd_claude=$(ACTIVE_BACKEND=claude python3 -c \
  "import sys; sys.path.insert(0,'$SCRIPT_ROOT/lib'); import llm_decide as L; print(int(L._fail_cooldown()))")
cd_override=$(ACTIVE_BACKEND=oss LLM_DECIDE_FAIL_COOLDOWN=42 python3 -c \
  "import sys; sys.path.insert(0,'$SCRIPT_ROOT/lib'); import llm_decide as L; print(int(L._fail_cooldown()))")
assert_eq "1800" "$cd_oss" "cooldown default: oss gets the long (30 min) window"
assert_eq "300" "$cd_codex" "cooldown default: cloud codex gets the short (5 min) window"
assert_eq "300" "$cd_claude" "cooldown default: cloud claude gets the short (5 min) window"
assert_eq "42" "$cd_override" "cooldown: explicit env override wins over the backend default"

# 17f. Concurrency: the half-open retry is claimed atomically. N callers hit
#      one stale tripped key simultaneously; exactly ONE must reach the
#      backend (the reserved retry), the rest skip. A read-only stale check
#      would let all N retry at once — the bug this guards against.
unset rc LLM_DECIDE_MOCK
NCONC=8
cc_key="demo:$(printf 'cc' | shasum -a 1 | cut -c1-16)"
export ACTIVE_BACKEND=codex
export CODEX_BIN="$fake_fail"
export FAKE_CB_CALLS="$TEST_TMPDIR/fake-cb-conc.calls"
: > "$FAKE_CB_CALLS"
export LLM_DECIDE_COUNTER_FILE="$TEST_TMPDIR/llm-count-conc"
export LLM_DECIDE_FAILCACHE_FILE="$TEST_TMPDIR/llm-failcache-conc"
export LLM_DECIDE_FAIL_THRESHOLD=2
export LLM_DECIDE_FAIL_COOLDOWN=600
# Tripped (count 3 >= 2) with an ancient ts → cooldown elapsed → half-open.
printf '{"%s":[3,1.0]}' "$cc_key" > "$LLM_DECIDE_FAILCACHE_FILE"
for i in $(seq 1 "$NCONC"); do
  ( echo "cc" | llm_decide demo "keep" 5 >/dev/null 2>&1 ) &
done
wait
conc_calls=$(wc -l < "$FAKE_CB_CALLS" | tr -d ' ')
assert_eq "1" "$conc_calls" \
  "cooldown: concurrent half-open callers reserve exactly one backend retry"
unset ACTIVE_BACKEND CODEX_BIN FAKE_CB_CALLS LLM_DECIDE_COUNTER_FILE \
  LLM_DECIDE_FAILCACHE_FILE LLM_DECIDE_FAIL_THRESHOLD LLM_DECIDE_FAIL_COOLDOWN

# 17g. Legacy failcache entries used a bare integer count with no timestamp.
#      Treat that missing/0 timestamp as stale so old entries get one
#      half-open retry instead of staying skipped forever.
unset rc LLM_DECIDE_MOCK
legacy_key="demo:$(printf 'legacy' | shasum -a 1 | cut -c1-16)"
export ACTIVE_BACKEND=codex
export CODEX_BIN="$fake_ok"
export FAKE_CB_CALLS="$TEST_TMPDIR/fake-cb-legacy.calls"
: > "$FAKE_CB_CALLS"
export LLM_DECIDE_COUNTER_FILE="$TEST_TMPDIR/llm-count-legacy"
export LLM_DECIDE_FAILCACHE_FILE="$TEST_TMPDIR/llm-failcache-legacy"
export LLM_DECIDE_FAIL_THRESHOLD=2
export LLM_DECIDE_FAIL_COOLDOWN=600
printf '{"%s":3}' "$legacy_key" > "$LLM_DECIDE_FAILCACHE_FILE"
out=$(echo "legacy" | llm_decide demo "keep,reason" 5 2>/dev/null) || rc=$?
assert_eq "0" "${rc:-0}" "cooldown: legacy bare-int entry half-opens"
assert_eq "1" "$(wc -l < "$FAKE_CB_CALLS" | tr -d ' ')" \
  "cooldown: legacy bare-int entry reaches the backend once"
if grep -q "\"$legacy_key\"" "$LLM_DECIDE_FAILCACHE_FILE" 2>/dev/null; then
  fail "cooldown: successful legacy half-open retry did not clear the key"
else
  pass "cooldown: successful legacy half-open retry cleared the key"
fi
unset ACTIVE_BACKEND CODEX_BIN FAKE_CB_CALLS LLM_DECIDE_COUNTER_FILE \
  LLM_DECIDE_FAILCACHE_FILE LLM_DECIDE_FAIL_THRESHOLD LLM_DECIDE_FAIL_COOLDOWN

# 17h. Per-TYPE circuit breaker: a decision class that is erroring FAST (the
#      backend runs and exits non-zero — rate-limit / overload) must be paused
#      even though every request is a DIFFERENT prompt, which the per-prompt
#      breaker can never catch (each is a fresh key at count 0). Per-prompt
#      threshold is set out of reach (100) to isolate the type breaker.
unset rc LLM_DECIDE_MOCK
export ACTIVE_BACKEND=codex
export CODEX_BIN="$fake_fail"                 # exit 1 → backend error
export FAKE_CB_CALLS="$TEST_TMPDIR/fake-type.calls"
: > "$FAKE_CB_CALLS"
export LLM_DECIDE_COUNTER_FILE="$TEST_TMPDIR/llm-count-type"
export LLM_DECIDE_FAILCACHE_FILE="$TEST_TMPDIR/llm-failcache-type"
export LLM_DECIDE_FAIL_THRESHOLD=100          # per-prompt effectively off
export LLM_DECIDE_TYPE_FAIL_THRESHOLD=2
export LLM_DECIDE_FAIL_COOLDOWN=600
echo "s1" | llm_decide demo "keep" 5 >/dev/null 2>&1 || true
echo "s2" | llm_decide demo "keep" 5 >/dev/null 2>&1 || true   # type count hits 2
echo "s3" | llm_decide demo "keep" 5 >/dev/null 2>&1 || true   # tripped → skipped
assert_eq "2" "$(wc -l < "$FAKE_CB_CALLS" | tr -d ' ')" \
  "type breaker: fast backend errors on different prompts open the class after threshold"
unset ACTIVE_BACKEND CODEX_BIN FAKE_CB_CALLS LLM_DECIDE_COUNTER_FILE \
  LLM_DECIDE_FAILCACHE_FILE LLM_DECIDE_FAIL_THRESHOLD LLM_DECIDE_TYPE_FAIL_THRESHOLD \
  LLM_DECIDE_FAIL_COOLDOWN

# 17h2. Bash callers often set harness knobs as shell variables before calling
#       llm_decide; the shim must force-export the type threshold just like the
#       older failcache knobs. An unexported 0 disables the type breaker, so all
#       nine different prompts reach the failing backend instead of tripping at
#       the default threshold of 8.
unset rc LLM_DECIDE_MOCK LLM_DECIDE_TYPE_FAIL_THRESHOLD
export ACTIVE_BACKEND=codex
export CODEX_BIN="$fake_fail"
export FAKE_CB_CALLS="$TEST_TMPDIR/fake-type-disable.calls"
: > "$FAKE_CB_CALLS"
export LLM_DECIDE_COUNTER_FILE="$TEST_TMPDIR/llm-count-type-disable"
export LLM_DECIDE_FAILCACHE_FILE="$TEST_TMPDIR/llm-failcache-type-disable"
export LLM_DECIDE_FAIL_THRESHOLD=100
LLM_DECIDE_TYPE_FAIL_THRESHOLD=0             # intentionally not exported
export LLM_DECIDE_FAIL_COOLDOWN=600
for p in d1 d2 d3 d4 d5 d6 d7 d8 d9; do
  echo "$p" | llm_decide demo "keep" 5 >/dev/null 2>&1 || true
done
assert_eq "9" "$(wc -l < "$FAKE_CB_CALLS" | tr -d ' ')" \
  "type breaker: unexported disable knob is forwarded by the bash shim"
if grep -q '"__type__:demo"' "$LLM_DECIDE_FAILCACHE_FILE" 2>/dev/null; then
  fail "type breaker: disabled type breaker must not create a type key"
else
  pass "type breaker: disabled type breaker leaves the type key unset"
fi
unset ACTIVE_BACKEND CODEX_BIN FAKE_CB_CALLS LLM_DECIDE_COUNTER_FILE \
  LLM_DECIDE_FAILCACHE_FILE LLM_DECIDE_FAIL_THRESHOLD LLM_DECIDE_TYPE_FAIL_THRESHOLD \
  LLM_DECIDE_FAIL_COOLDOWN

# 17i. The type breaker must NOT arm on malformed output: the backend answered
#      (exit 0) but its JSON was unusable for THIS prompt. That is a per-prompt
#      content problem, not a failing class, so different prompts keep flowing.
fake_garbage="$TEST_TMPDIR/fake-codex-garbage"
cat > "$fake_garbage" <<'EOF'
#!/usr/bin/env bash
echo call >> "$FAKE_CB_CALLS"
cat >/dev/null
printf 'not json at all\n'
EOF
chmod +x "$fake_garbage"
unset rc LLM_DECIDE_MOCK
export ACTIVE_BACKEND=codex
export CODEX_BIN="$fake_garbage"
export FAKE_CB_CALLS="$TEST_TMPDIR/fake-garbage.calls"
: > "$FAKE_CB_CALLS"
export LLM_DECIDE_COUNTER_FILE="$TEST_TMPDIR/llm-count-garbage"
export LLM_DECIDE_FAILCACHE_FILE="$TEST_TMPDIR/llm-failcache-garbage"
export LLM_DECIDE_FAIL_THRESHOLD=100
export LLM_DECIDE_TYPE_FAIL_THRESHOLD=2
export LLM_DECIDE_FAIL_COOLDOWN=600
echo "g1" | llm_decide demo "keep" 5 >/dev/null 2>&1 || true
echo "g2" | llm_decide demo "keep" 5 >/dev/null 2>&1 || true
echo "g3" | llm_decide demo "keep" 5 >/dev/null 2>&1 || true
assert_eq "3" "$(wc -l < "$FAKE_CB_CALLS" | tr -d ' ')" \
  "type breaker: malformed output does not open the class (backend still answered)"
if grep -q '"__type__:demo"' "$LLM_DECIDE_FAILCACHE_FILE" 2>/dev/null; then
  fail "type breaker: malformed output must not create a type key"
else
  pass "type breaker: malformed output leaves the type key unset"
fi
unset ACTIVE_BACKEND CODEX_BIN FAKE_CB_CALLS LLM_DECIDE_COUNTER_FILE \
  LLM_DECIDE_FAILCACHE_FILE LLM_DECIDE_FAIL_THRESHOLD LLM_DECIDE_TYPE_FAIL_THRESHOLD \
  LLM_DECIDE_FAIL_COOLDOWN

# 17j. The type breaker must NOT arm on a timeout (rc=124). A timeout means
#      "needed more time" — handled by the decision-timeout floors — not "the
#      backend is failing". Arming here would sideline a gate that is merely
#      slow (the cluster_expand trap). The fake sleeps past the 1s cap.
fake_slow="$TEST_TMPDIR/fake-codex-slow"
cat > "$fake_slow" <<'EOF'
#!/usr/bin/env bash
echo call >> "$FAKE_CB_CALLS"
cat >/dev/null
sleep 3
printf '{"keep":true}\n'
EOF
chmod +x "$fake_slow"
unset rc LLM_DECIDE_MOCK
export ACTIVE_BACKEND=codex
export CODEX_BIN="$fake_slow"
export FAKE_CB_CALLS="$TEST_TMPDIR/fake-slow.calls"
: > "$FAKE_CB_CALLS"
export LLM_DECIDE_COUNTER_FILE="$TEST_TMPDIR/llm-count-slow"
export LLM_DECIDE_FAILCACHE_FILE="$TEST_TMPDIR/llm-failcache-slow"
export LLM_DECIDE_FAIL_THRESHOLD=100
export LLM_DECIDE_TYPE_FAIL_THRESHOLD=2
export LLM_DECIDE_FAIL_COOLDOWN=600
echo "t1" | llm_decide demo "keep" 1 >/dev/null 2>&1 || true   # timeout at 1s
echo "t2" | llm_decide demo "keep" 1 >/dev/null 2>&1 || true
echo "t3" | llm_decide demo "keep" 1 >/dev/null 2>&1 || true
assert_eq "3" "$(wc -l < "$FAKE_CB_CALLS" | tr -d ' ')" \
  "type breaker: timeouts do not open the class (slow != failing)"
unset ACTIVE_BACKEND CODEX_BIN FAKE_CB_CALLS LLM_DECIDE_COUNTER_FILE \
  LLM_DECIDE_FAILCACHE_FILE LLM_DECIDE_FAIL_THRESHOLD LLM_DECIDE_TYPE_FAIL_THRESHOLD \
  LLM_DECIDE_FAIL_COOLDOWN

# 17k. Half-open + self-heal for the type key: a tripped class is skipped within
#      cooldown, then one probe reaches the backend after cooldown; a success
#      clears the type key so the class resumes normally.
unset rc LLM_DECIDE_MOCK
type_key="__type__:demo"
export ACTIVE_BACKEND=codex
export FAKE_CB_CALLS="$TEST_TMPDIR/fake-typeheal.calls"
: > "$FAKE_CB_CALLS"
export LLM_DECIDE_COUNTER_FILE="$TEST_TMPDIR/llm-count-typeheal"
export LLM_DECIDE_FAILCACHE_FILE="$TEST_TMPDIR/llm-failcache-typeheal"
export LLM_DECIDE_FAIL_THRESHOLD=100
export LLM_DECIDE_TYPE_FAIL_THRESHOLD=2
export LLM_DECIDE_FAIL_COOLDOWN=600
# Fresh tripped type key (ts=now) → class paused within cooldown.
export CODEX_BIN="$fake_ok"
now=$(date +%s)
printf '{"%s":[3,%s]}' "$type_key" "$now" > "$LLM_DECIDE_FAILCACHE_FILE"
unset rc
out=$(echo "z1" | llm_decide demo "keep,reason" 5 2>/dev/null) || rc=$?
assert_eq "1" "${rc:-0}" "type breaker: tripped class within cooldown is skipped"
assert_eq "0" "$(wc -l < "$FAKE_CB_CALLS" | tr -d ' ')" \
  "type breaker: paused class does not reach the backend"
# Ancient ts → cooldown elapsed → one half-open probe reaches the backend,
# succeeds, and clears the class.
printf '{"%s":[3,1.0]}' "$type_key" > "$LLM_DECIDE_FAILCACHE_FILE"
unset rc
out=$(echo "z2" | llm_decide demo "keep,reason" 5 2>/dev/null) || rc=$?
assert_eq "0" "${rc:-0}" "type breaker: half-open probe after cooldown succeeds"
if grep -q "\"$type_key\"" "$LLM_DECIDE_FAILCACHE_FILE" 2>/dev/null; then
  fail "type breaker: a successful probe did not clear the class"
else
  pass "type breaker: a successful probe cleared the class (self-heal)"
fi
unset ACTIVE_BACKEND CODEX_BIN FAKE_CB_CALLS LLM_DECIDE_COUNTER_FILE \
  LLM_DECIDE_FAILCACHE_FILE LLM_DECIDE_FAIL_THRESHOLD LLM_DECIDE_TYPE_FAIL_THRESHOLD \
  LLM_DECIDE_FAIL_COOLDOWN

teardown_test_env
summary
