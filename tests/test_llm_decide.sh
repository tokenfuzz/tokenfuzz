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

# 10. OSS backend invokes Codex exec with Ollama provider flags
fake_codex="$TEST_TMPDIR/fake-codex-oss"
cat > "$fake_codex" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$*" > "$FAKE_CODEX_ARGS"
cat >/dev/null
printf '{"keep":true,"reason":"oss"}\n'
EOF
chmod +x "$fake_codex"
unset rc
unset LLM_DECIDE_DISABLE
export ACTIVE_BACKEND=oss
export MODEL="qwen3:14b"
export CODEX_BIN="$fake_codex"
export FAKE_CODEX_ARGS="$TEST_TMPDIR/fake-codex-oss.args"
export LLM_DECIDE_COUNTER_FILE="$TEST_TMPDIR/llm-count-oss"
out=$(echo "x" | llm_decide demo "keep,reason" 2)
assert_eq "0" "$?" "oss backend: llm_decide succeeds through fake Codex"
assert_match '"reason":"oss"|\"reason\": \"oss\"' "$out" "oss backend: parses fake Codex JSON"
oss_args=$(cat "$FAKE_CODEX_ARGS")
assert_match 'exec --oss --local-provider ollama --ephemeral --skip-git-repo-check --sandbox read-only --model qwen3:14b -' "$oss_args" \
  "oss backend: Codex args are ordered for exec"
if grep -q -- '--output-schema' <<<"$oss_args"; then
  fail "oss backend: decision calls use plain text JSON, not Codex schema" "got: $oss_args"
else
  pass "oss backend: decision calls use plain text JSON, not Codex schema"
fi
unset ACTIVE_BACKEND MODEL CODEX_BIN FAKE_CODEX_ARGS LLM_DECIDE_COUNTER_FILE

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

teardown_test_env
summary
