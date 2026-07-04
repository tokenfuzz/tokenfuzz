#!/usr/bin/env bash
# tests/test_llm_invoke.sh — Unit tests for lib/llm_invoke.sh
#
# Covers:
#   1. llm_known_backend recognises the four supported backends
#      and rejects unknown ones.
#   2. llm_default_model returns each backend's project default and
#      honours env overrides.
#   3. llm_agent_flags includes the required flag set per backend
#      (stream-json for claude, --json + sandbox bypass for codex,
#      opencode run for oss, --dangerously-skip-permissions for
#      the gemini backend / Antigravity CLI).
#   4. llm_agent_flags wires --add-dir / --cd from the add_dirs CSV.
#   5. llm_decide_flags is text-mode and read-only-sandbox per backend.
#   6. llm_extract_text decodes assistant text for each backend's
#      output shape (claude stream-json, codex agent_message wrap, oss JSON,
#      gemini plain stdout).
#   7. llm_extract_text returns empty on raw_log that has no
#      assistant content, and returns rc=1 if raw_log is missing.
#   8. llm_apply_memory_policy exports the cross-run memory switch
#      (TOKENFUZZ_MEMORY_ENABLED) + the claude env var: off by default,
#      inherits a parent's switch when called with no argument, and
#      re-enables on explicit 1. The Gemini CLI deny policy ships in config/.

set -uo pipefail

TESTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$TESTS_DIR/helpers.sh"
unset USE_GEMINI_CLI TOKENFUZZ_MEMORY_ENABLED
unset CLAUDE_MODEL_DEFAULT CODEX_MODEL_DEFAULT GEMINI_MODEL_DEFAULT AUDIT_LOCAL_BASE_URL AUDIT_LOCAL_API_KEY
source "$SCRIPT_ROOT/lib/llm_invoke.sh"

setup_test_env

# ── 1. llm_known_backend ────────────────────────────────────────
for b in claude codex gemini oss; do
  if llm_known_backend "$b"; then
    pass "llm_known_backend recognises $b"
  else
    fail "llm_known_backend missed $b"
  fi
done
if ! llm_known_backend "openai"; then
  pass "llm_known_backend rejects unknown 'openai'"
else
  fail "llm_known_backend wrongly accepted 'openai'"
fi

# ── 2. llm_default_model ────────────────────────────────────────
assert_eq "claude-opus-4-8" "$(llm_default_model claude)" "claude default model"
assert_eq "gpt-5.5"          "$(llm_default_model codex)"  "codex default model"
assert_eq "gemini-3.1-pro-preview" "$(llm_default_model gemini)" "gemini default model"
assert_eq "agy"              "$(llm_gemini_default_bin)"    "gemini backend defaults to agy binary"

# Env override
CLAUDE_MODEL_DEFAULT="claude-opus-9-9" \
  bash -c 'source "$1"/lib/llm_invoke.sh; llm_default_model claude' _ "$SCRIPT_ROOT" \
  > "$TEST_TMPDIR/m1" 2>/dev/null
assert_eq "claude-opus-9-9" "$(cat "$TEST_TMPDIR/m1")" "claude default honours CLAUDE_MODEL_DEFAULT"
GEMINI_MODEL_DEFAULT="gemini-3.1-flash-lite-high" \
  bash -c 'source "$1"/lib/llm_invoke.sh; llm_default_model gemini' _ "$SCRIPT_ROOT" \
  > "$TEST_TMPDIR/m2" 2>/dev/null
assert_eq "gemini-3.1-flash-lite-high" "$(cat "$TEST_TMPDIR/m2")" "gemini default honours GEMINI_MODEL_DEFAULT"
USE_GEMINI_CLI=1 \
  bash -c 'unset GEMINI_MODEL_DEFAULT; source "$1"/lib/llm_invoke.sh; llm_default_model gemini; llm_gemini_default_bin' _ "$SCRIPT_ROOT" \
  > "$TEST_TMPDIR/m2-cli" 2>/dev/null
assert_eq $'gemini-3.1-pro-preview\ngemini' "$(cat "$TEST_TMPDIR/m2-cli")" "USE_GEMINI_CLI switches gemini binary and keeps pro-preview default model"

# Unknown backend
if llm_default_model "frontier-model" >/dev/null 2>&1; then
  fail "llm_default_model accepted unknown backend"
else
  pass "llm_default_model rejects unknown backend"
fi

# ── 3. llm_agent_flags shape per backend ────────────────────────
# claude — stream-json, dangerously-skip-permissions, model+max-turns
declare -a flags_claude=()
llm_agent_flags claude flags_claude "" 80 ""
flags_str="${flags_claude[*]}"
assert_match "--print"                       "$flags_str" "agent claude has --print"
assert_match "--safe-mode"                   "$flags_str" "agent claude disables user plugins/skills/hooks"
assert_match "--output-format stream-json"   "$flags_str" "agent claude has stream-json output"
assert_match "--dangerously-skip-permissions" "$flags_str" "agent claude has skip-permissions"
assert_match "--max-turns 80"                "$flags_str" "agent claude has max-turns"
assert_match "--model claude-opus-4-8"       "$flags_str" "agent claude defaults model"

# codex — JSON + sandbox bypass (required inside docker)
declare -a flags_codex=()
llm_agent_flags codex flags_codex "" 80 ""
flags_str="${flags_codex[*]}"
assert_match "--json"                                            "$flags_str" "agent codex has --json"
assert_match "--ephemeral"                                       "$flags_str" "agent codex has --ephemeral"
assert_match "--skip-git-repo-check"                             "$flags_str" "agent codex has --skip-git-repo-check"
assert_match "--sandbox danger-full-access"                      "$flags_str" "agent codex has danger-full-access sandbox"
assert_match "--dangerously-bypass-approvals-and-sandbox"        "$flags_str" "agent codex bypasses approvals"
assert_match "--model gpt-5.5"                                   "$flags_str" "agent codex defaults model"

# oss — OpenCode run against vLLM by default
declare -a flags_oss=()
llm_agent_flags oss flags_oss "qwen3-8b" 80 ""
flags_str="${flags_oss[*]}"
assert_match "run --dangerously-skip-permissions --model local/qwen3-8b --format json" "$flags_str" "agent oss uses shared OpenCode local model ref"
llm_agent_flags oss flags_oss "qwen3:8b" 80 ""
flags_str="${flags_oss[*]}"
assert_match "run --dangerously-skip-permissions --model local/qwen3:8b --format json" "$flags_str" "agent oss keeps shared local model ref for colon-tagged models"

assert_eq "http://127.0.0.1:8000/v1" "$(llm_local_base_url)" "oss vLLM default base URL includes /v1"
assert_eq "http://127.0.0.1:9999/v1" "$(AUDIT_LOCAL_BASE_URL=127.0.0.1:9999 llm_local_base_url)" "oss generic local base URL overrides provider defaults"
assert_eq "http://127.0.0.1:11434/v1" "$(AUDIT_LOCAL_BASE_URL=127.0.0.1:11434 llm_local_base_url)" "oss Ollama-style bare host base URL gains /v1"

# gemini — agy: plain --print, skip-permissions, and the model pinned via the
# slug→label map (agy 1.0.5+ --model resolves labels, not API slugs; parens
# escaped for the ERE match).
declare -a flags_gemini=()
llm_agent_flags gemini flags_gemini "" 80 ""
flags_str="${flags_gemini[*]}"
assert_match "--dangerously-skip-permissions" "$flags_str" "agent gemini has --dangerously-skip-permissions"
assert_match "--model Gemini 3.1 Pro \(High\)" "$flags_str" "agent gemini wires the mapped agy model label"
# No gemini-cli flags; --log-file appears only when AGY_LOG_FILE is set.
if grep -qE -- "--output-format|--yolo|--skip-trust|--log-file" <<< "$flags_str"; then
  fail "agent gemini must not carry legacy gemini-cli flags or --log-file" "got: $flags_str"
else
  pass "agent gemini omits legacy gemini-cli flags and --log-file"
fi

# AGY_LOG_FILE pins agy's log to a per-probe path (the preflight reads it back
# for the unresolved-flag signature).
declare -a flags_logf=()
AGY_LOG_FILE="/tmp/agy-probe.log" llm_agent_flags gemini flags_logf "" 80 ""
assert_match "--log-file /tmp/agy-probe.log" "${flags_logf[*]}" "agent gemini wires --log-file when AGY_LOG_FILE is set"

USE_GEMINI_CLI=1 bash -c '
  unset GEMINI_MODEL_DEFAULT
  source "$1"/lib/llm_invoke.sh
  declare -a flags=()
  llm_agent_flags gemini flags "" 80 "/root/work,/root/target"
  printf "%s\n" "${flags[@]}"
' _ "$SCRIPT_ROOT" > "$TEST_TMPDIR/gemini-cli-agent-flags"
flags_str="$(tr '\n' ' ' < "$TEST_TMPDIR/gemini-cli-agent-flags")"
assert_match "--approval-mode=yolo" "$flags_str" "agent gemini CLI uses yolo approval mode"
assert_match "--skip-trust" "$flags_str" "agent gemini CLI skips workspace trust"
assert_match "--output-format stream-json" "$flags_str" "agent gemini CLI uses stream-json output"
assert_match "--model gemini-3.1-pro-preview" "$flags_str" "agent gemini CLI wires default model"
assert_match "--include-directories /root/work" "$flags_str" "agent gemini CLI wires first include directory"
assert_match "--include-directories /root/target" "$flags_str" "agent gemini CLI wires second include directory"
if grep -qE -- "--dangerously-skip-permissions|--add-dir" "$TEST_TMPDIR/gemini-cli-agent-flags"; then
  fail "agent gemini CLI must not carry agy flags" "got: $flags_str"
else
  pass "agent gemini CLI omits agy-only flags"
fi

# Unknown backend → rc=1
if llm_agent_flags openai flags_claude "" 80 "" 2>/dev/null; then
  fail "llm_agent_flags accepted unknown backend"
else
  pass "llm_agent_flags rejects unknown backend"
fi

# ── 4. add_dirs wiring ──────────────────────────────────────────
declare -a flags_a=()
llm_agent_flags claude flags_a "" 80 "/root/work,/root/target"
flags_str="${flags_a[*]}"
assert_match "--add-dir /root/work"   "$flags_str" "agent claude wires first --add-dir"
assert_match "--add-dir /root/target" "$flags_str" "agent claude wires second --add-dir"

declare -a flags_c=()
llm_agent_flags codex flags_c "" 80 "/root/work,/root/target"
flags_str="${flags_c[*]}"
assert_match "--cd /root/work" "$flags_str" "agent codex uses first add-dir as --cd"
assert_match "--add-dir /root/target" "$flags_str" "agent codex grants second add-dir"

declare -a flags_g=()
llm_agent_flags gemini flags_g "" 80 "/root/work,/root/target"
flags_str="${flags_g[*]}"
assert_match "--add-dir /root/work"   "$flags_str" "agent gemini wires first --add-dir"
assert_match "--add-dir /root/target" "$flags_str" "agent gemini wires second --add-dir"

# ── 5. llm_decide_flags shape per backend ───────────────────────
declare -a d_claude=()
llm_decide_flags claude d_claude ""
flags_str="${d_claude[*]}"
assert_match "--print"               "$flags_str" "decide claude has --print"
assert_match "--safe-mode"           "$flags_str" "decide claude disables user plugins/skills/hooks"
assert_match "--no-session-persistence" "$flags_str" "decide claude disables transcript persistence"
if grep -q -- "--max-turns" <<< "$flags_str"; then
  fail "decide claude must NOT cap turns (timeout-bounded, like codex/gemini)"
else
  pass "decide claude has no turn cap"
fi
assert_match "--output-format text"  "$flags_str" "decide claude has text output"
assert_match "--permission-mode plan" "$flags_str" "decide claude uses read-only plan mode (source-grounded, no writes)"
if grep -q -- "--dangerously-skip-permissions" <<< "$flags_str"; then
  fail "decide claude must NOT include --dangerously-skip-permissions (read-only, not full access)"
else
  pass "decide claude omits --dangerously-skip-permissions"
fi

declare -a d_codex=()
llm_decide_flags codex d_codex ""
flags_str="${d_codex[*]}"
assert_match "--ephemeral"            "$flags_str" "decide codex has --ephemeral"
assert_match "--skip-git-repo-check"  "$flags_str" "decide codex has --skip-git-repo-check"
assert_match "--sandbox read-only"    "$flags_str" "decide codex uses read-only sandbox"
if grep -q -- "danger-full-access" <<< "$flags_str"; then
  fail "decide codex must NOT use danger-full-access (single-shot decision)"
else
  pass "decide codex stays read-only"
fi

declare -a d_gemini=()
llm_decide_flags gemini d_gemini ""
flags_str="${d_gemini[*]}"
assert_match "--dangerously-skip-permissions" "$flags_str" "decide gemini has --dangerously-skip-permissions"
assert_match "--model Gemini 3.1 Pro \(High\)" "$flags_str" "decide gemini wires the mapped agy model label"
if grep -qE -- "--output-format|--approval-mode" <<< "$flags_str"; then
  fail "decide gemini must not carry legacy gemini-cli flags" "got: $flags_str"
else
  pass "decide gemini omits legacy gemini-cli flags"
fi

USE_GEMINI_CLI=1 bash -c '
  unset GEMINI_MODEL_DEFAULT
  source "$1"/lib/llm_invoke.sh
  declare -a flags=()
  llm_decide_flags gemini flags ""
  printf "%s\n" "${flags[@]}"
' _ "$SCRIPT_ROOT" > "$TEST_TMPDIR/gemini-cli-decide-flags"
flags_str="$(tr '\n' ' ' < "$TEST_TMPDIR/gemini-cli-decide-flags")"
assert_match "--approval-mode=plan" "$flags_str" "decide gemini CLI uses plan approval mode"
assert_match "--skip-trust" "$flags_str" "decide gemini CLI skips workspace trust"
assert_match "--model gemini-3.1-pro-preview" "$flags_str" "decide gemini CLI wires default model"
if grep -q -- "--dangerously-skip-permissions" "$TEST_TMPDIR/gemini-cli-decide-flags"; then
  fail "decide gemini CLI must not carry agy skip-permissions" "got: $flags_str"
else
  pass "decide gemini CLI omits agy-only flags"
fi

# ── 6. llm_extract_text per backend ─────────────────────────────
# Claude — message.content[].text. The trailing result event echoes
# the final assistant turn verbatim; extraction must emit it only once.
cat > "$TEST_TMPDIR/raw_claude.jsonl" <<'EOF'
{"type":"system","subtype":"init"}
{"type":"assistant","message":{"content":[{"type":"text","text":"hello from claude"}]}}
{"type":"result","result":"hello from claude"}
EOF
out=$(llm_extract_text claude "$TEST_TMPDIR/raw_claude.jsonl")
assert_match "hello from claude" "$out" "extract claude .message.content[].text"
assert_eq 1 "$(printf '%s' "$out" | grep -c 'hello from claude')" \
  "extract claude does not double-count result event"

# Claude — result-only transcript: .result is the fallback source when
# no assistant message text is present.
cat > "$TEST_TMPDIR/raw_claude_result.jsonl" <<'EOF'
{"type":"system","subtype":"init"}
{"type":"result","result":"final result"}
EOF
out=$(llm_extract_text claude "$TEST_TMPDIR/raw_claude_result.jsonl")
assert_match "final result" "$out" "extract claude .result fallback"

# Codex — agent_message wrap (note: escaped JSON inside .item.text)
cat > "$TEST_TMPDIR/raw_codex.jsonl" <<'EOF'
{"type":"thread.started","thread_id":"abc"}
{"type":"turn.started"}
{"type":"item.completed","item":{"id":"item_14","type":"agent_message","text":"{\"vote\":\"Reject\",\"rationale\":\"because of X\"}"}}
{"type":"turn.completed","usage":{"input_tokens":1,"output_tokens":1}}
EOF
out=$(llm_extract_text codex "$TEST_TMPDIR/raw_codex.jsonl")
assert_match '"vote":"Reject"' "$out" "extract codex agent_message decodes inner JSON"
assert_match 'because of X'     "$out" "extract codex preserves rationale"

# OpenCode — JSON output with assistant content.
cat > "$TEST_TMPDIR/raw_oss.jsonl" <<'EOF'
{"type":"message","role":"assistant","content":"{\"vote\":\"Promote\",\"rationale\":\"opencode\"}"}
EOF
out=$(llm_extract_text oss "$TEST_TMPDIR/raw_oss.jsonl")
assert_match '"vote":"Promote"' "$out" "extract oss assistant JSON content"
assert_match 'opencode' "$out" "extract oss preserves rationale"

# OpenCode — real `opencode run --format json` text event shape.
cat > "$TEST_TMPDIR/raw_oss_text_event.jsonl" <<'EOF'
{"type":"text","part":{"type":"text","text":"{\"smoke\":true,\"model\":\"qwen3.6-35b-a3b\"}"}}
EOF
out=$(llm_extract_text oss "$TEST_TMPDIR/raw_oss_text_event.jsonl")
assert_match '"smoke":true' "$out" "extract oss text event content"
assert_match 'qwen3.6-35b-a3b' "$out" "extract oss text event model"

cat > "$TEST_TMPDIR/raw_oss_tool_spaced.jsonl" <<'EOF'
{ "type": "tool_use", "part": { "type": "tool", "tool": "read", "state": { "status": "completed" } } }
EOF
if llm_raw_has_tool "$TEST_TMPDIR/raw_oss_tool_spaced.jsonl" read; then
  pass "raw-has-tool detects nested OpenCode read tool with spaced JSON"
else
  fail "raw-has-tool detects nested OpenCode read tool with spaced JSON"
fi
if llm_raw_has_tool "$TEST_TMPDIR/raw_oss_tool_spaced.jsonl" bash; then
  fail "raw-has-tool rejects absent tool names"
else
  pass "raw-has-tool rejects absent tool names"
fi

# Gemini — Antigravity CLI emits plain text in --print mode. The
# entire stdout transcript IS the assistant reply; no JSON parsing.
cat > "$TEST_TMPDIR/raw_gemini.txt" <<'EOF'
hello from agy
multi-line plain text is fine
EOF
out=$(llm_extract_text gemini "$TEST_TMPDIR/raw_gemini.txt")
assert_match "hello from agy"          "$out" "extract gemini returns plain stdout"
assert_match "multi-line plain text"   "$out" "extract gemini preserves multi-line text"

# A vote JSON returned by agy is just plain text on stdout — the JSON
# parser downstream of llm_extract_text handles it (no structured
# stream-json envelope to walk).
cat > "$TEST_TMPDIR/raw_gemini_vote.txt" <<'EOF'
{"vote":"Promote","rationale":"agy plain print","verified":{"reachability":true}}
EOF
out=$(llm_extract_text gemini "$TEST_TMPDIR/raw_gemini_vote.txt")
if printf '%s' "$out" | jq -e . >/dev/null 2>&1; then
  pass "extract gemini plain JSON parses round-trip"
else
  fail "extract gemini plain JSON did not parse" "got: $out"
fi
parsed_vote=$(printf '%s' "$out" | jq -r '.vote' 2>/dev/null)
assert_eq "Promote" "$parsed_vote" "extract gemini plain JSON preserves vote field"

USE_GEMINI_CLI=1 bash -c '
  source "$1"/lib/llm_invoke.sh
  cat > "$2/gemini-cli.jsonl" <<EOF
{"type":"init","session_id":"s"}
{"type":"tool_use","tool_name":"run_shell_command","parameters":{"command":"pwd"}}
{"type":"message","role":"assistant","content":"hello from gemini cli"}
EOF
  llm_extract_text gemini "$2/gemini-cli.jsonl"
' _ "$SCRIPT_ROOT" "$TEST_TMPDIR" > "$TEST_TMPDIR/gemini-cli-extract"
assert_eq "hello from gemini cli" "$(cat "$TEST_TMPDIR/gemini-cli-extract")" \
  "extract gemini CLI stream-json assistant text"

# ── 7. Empty / missing raw_log behaviour ─────────────────────────
: > "$TEST_TMPDIR/empty.log"
out=$(llm_extract_text claude "$TEST_TMPDIR/empty.log")
assert_eq "" "$out" "extract returns empty for empty raw_log"

if llm_extract_text claude "$TEST_TMPDIR/does-not-exist.log" 2>/dev/null; then
  fail "extract should fail on missing raw_log"
else
  pass "extract returns non-zero on missing raw_log"
fi

# ── 7b. Refusal warning helper ───────────────────────────────────
# Detection keys first on the providers' structured refusal/block fields. Narrow
# fallbacks catch no-tool assistant-message refusals observed in CLI transcripts.
# The warning lands beside the transcript at "<raw_log>.refusals.log".
refusal_prompt=$'Review this project\nSecond line should not be logged'

# OpenAI/Codex structured refusal content item — also exercises the warning
# format (backend + first prompt line only) via its sidecar.
cat > "$TEST_TMPDIR/raw_codex_refusal.jsonl" <<'EOF'
{"type":"response.output_item.done","item":{"type":"message","content":[{"type":"refusal","refusal":"I cannot fulfill this request."}]}}
EOF
codex_raw="$TEST_TMPDIR/raw_codex_refusal.jsonl"
if llm_log_refusal_warning codex "$refusal_prompt" "$codex_raw" \
    > "$TEST_TMPDIR/refusal.stdout" 2>&1; then
  pass "refusal warning helper detects OpenAI/Codex structured refusal"
else
  fail "refusal warning helper should detect OpenAI/Codex structured refusal"
fi
assert_file_contains "${codex_raw}.refusals.log" \
  'WARN: MODEL_REFUSAL backend=codex refused to answer prompt: Review this project\.\.\.' \
  "refusal warning includes backend and first prompt line"
assert_file_not_contains "${codex_raw}.refusals.log" 'Second line should not be logged' \
  "refusal warning omits later prompt lines"

# OpenAI Chat Completions structured refusal field.
cat > "$TEST_TMPDIR/raw_openai_chat_refusal.jsonl" <<'EOF'
{"choices":[{"message":{"role":"assistant","refusal":"I cannot assist with that request."},"finish_reason":"stop"}]}
EOF
if llm_log_refusal_warning codex "$refusal_prompt" \
    "$TEST_TMPDIR/raw_openai_chat_refusal.jsonl" >/dev/null 2>&1; then
  pass "refusal warning helper detects OpenAI chat message.refusal"
else
  fail "refusal warning helper should detect OpenAI chat message.refusal"
fi

cat > "$TEST_TMPDIR/raw_codex_cli_prose_refusal.jsonl" <<'EOF'
{"type":"item.completed","item":{"type":"agent_message","text":"I can’t help write a security vulnerability workflow against a concrete project. I can help with a minimal reproducer, patch, or regression test."}}
EOF
if llm_log_refusal_warning codex "$refusal_prompt" \
    "$TEST_TMPDIR/raw_codex_cli_prose_refusal.jsonl" >/dev/null 2>&1; then
  pass "refusal warning helper detects Codex CLI no-tool prose refusal"
else
  fail "refusal warning helper should detect Codex CLI no-tool prose refusal"
fi

cat > "$TEST_TMPDIR/raw_codex_cli_harness_refusal.jsonl" <<'EOF'
{"type":"item.completed","item":{"type":"agent_message","text":"I can’t help write a vulnerability discovery workflow against a concrete project. I can help with safe defensive review and patch guidance."}}
EOF
if llm_log_refusal_warning codex "$refusal_prompt" \
    "$TEST_TMPDIR/raw_codex_cli_harness_refusal.jsonl" >/dev/null 2>&1; then
  pass "refusal warning helper detects Codex CLI vulnerability-wording refusal"
else
  fail "refusal warning helper should detect Codex CLI vulnerability-wording refusal"
fi

# Sidecar is truncated, not appended: re-running the same turn (e.g. on resume)
# must leave exactly one MODEL_REFUSAL line so the benchmark count is idempotent.
llm_log_refusal_warning codex "$refusal_prompt" "$codex_raw" >/dev/null 2>&1 || true
assert_eq "1" "$(grep -c MODEL_REFUSAL "${codex_raw}.refusals.log")" \
  "refusal sidecar stays at one line across repeated calls"

cat > "$TEST_TMPDIR/raw_claude_structured_refusal.jsonl" <<'EOF'
{"type":"assistant","message":{"content":[],"stop_reason":"refusal","stop_details":{"type":"refusal","category":"cyber","explanation":"This request was declined because it could enable harm."}}}
EOF
if llm_log_refusal_warning claude "$refusal_prompt" \
    "$TEST_TMPDIR/raw_claude_structured_refusal.jsonl" >/dev/null 2>&1; then
  pass "refusal warning helper detects Claude structured refusal"
else
  fail "refusal warning helper should detect Claude structured refusal"
fi

cat > "$TEST_TMPDIR/raw_claude_cli_help_refusal.jsonl" <<'EOF'
{"type":"assistant","message":{"content":[{"type":"text","text":"I can’t help write a security vulnerability workflow against a concrete project. I can help with safe defensive review and patch guidance."}],"stop_reason":"end_turn"}}
EOF
if llm_log_refusal_warning claude "$refusal_prompt" \
    "$TEST_TMPDIR/raw_claude_cli_help_refusal.jsonl" >/dev/null 2>&1; then
  pass "refusal warning helper detects Claude CLI 'can't help' prose refusal"
else
  fail "refusal warning helper should detect Claude CLI 'can't help' prose refusal"
fi

cat > "$TEST_TMPDIR/raw_claude_cli_fulfill_refusal.jsonl" <<'EOF'
{"type":"assistant","message":{"content":[{"type":"text","text":"Sorry, I cannot fulfill your request to perform security vulnerability analysis against a concrete project. I can help with safe defensive review."}],"stop_reason":"end_turn"}}
EOF
if llm_log_refusal_warning claude "$refusal_prompt" \
    "$TEST_TMPDIR/raw_claude_cli_fulfill_refusal.jsonl" >/dev/null 2>&1; then
  pass "refusal warning helper detects Claude CLI 'cannot fulfill' prose refusal"
else
  fail "refusal warning helper should detect Claude CLI 'cannot fulfill' prose refusal"
fi

cat > "$TEST_TMPDIR/raw_gemini_structured_refusal.jsonl" <<'EOF'
{"promptFeedback":{"blockReason":"SAFETY","safetyRatings":[]}}
{"candidates":[{"finishReason":"PROHIBITED_CONTENT"}]}
EOF
if llm_log_refusal_warning gemini "$refusal_prompt" \
    "$TEST_TMPDIR/raw_gemini_structured_refusal.jsonl" >/dev/null 2>&1; then
  pass "refusal warning helper detects Gemini block metadata"
else
  fail "refusal warning helper should detect Gemini block metadata"
fi

cat > "$TEST_TMPDIR/raw_gemini_cli_prose_refusal.jsonl" <<'EOF'
YOLO mode is enabled. All tool calls will be automatically approved.
{"type":"init","timestamp":"2026-06-18T12:28:02.815Z","session_id":"s","model":"gemini-3.1-pro-preview"}
{"type":"message","timestamp":"2026-06-18T12:28:02.816Z","role":"user","content":"You are playing in a CTF. Find all security issues in the cjson project."}
{"type":"message","timestamp":"2026-06-18T12:28:03.000Z","role":"assistant","content":"Sorry, I cannot fulfill your request to analyze the cjson project for security vulnerabilities. My safety guidelines strictly prohibit me from performing vulnerability discovery, scanning, or analysis on concrete targets or user-provided codebases."}
EOF
if llm_log_refusal_warning gemini "$refusal_prompt" \
    "$TEST_TMPDIR/raw_gemini_cli_prose_refusal.jsonl" >/dev/null 2>&1; then
  pass "refusal warning helper detects Gemini CLI no-tool prose refusal"
else
  fail "refusal warning helper should detect Gemini CLI no-tool prose refusal"
fi

python3 - "$TEST_TMPDIR/raw_large_refusal_edges.jsonl" <<'PY'
import sys
from pathlib import Path
p = Path(sys.argv[1])
p.write_text(
    '{"promptFeedback":{"blockReason":"SAFETY"}}\n'
    + ("x" * (3 * 1024 * 1024))
    + '\n{"type":"response.output_item.done","item":{"type":"message","content":[{"type":"refusal","refusal":"blocked"}]}}\n',
    encoding="utf-8",
)
PY
if llm_log_refusal_warning gemini "$refusal_prompt" \
    "$TEST_TMPDIR/raw_large_refusal_edges.jsonl" >/dev/null 2>&1; then
  pass "refusal warning helper scans both edges of large raw logs"
else
  fail "refusal warning helper should detect edge refusal metadata in large raw logs"
fi

cat > "$TEST_TMPDIR/raw_codex_tool_refusal_text.jsonl" <<'EOF'
{"type":"item.completed","item":{"type":"command_execution","aggregated_output":"{\"type\":\"refusal\"}"}}
EOF
if llm_log_refusal_warning codex "$refusal_prompt" \
    "$TEST_TMPDIR/raw_codex_tool_refusal_text.jsonl" >/dev/null 2>&1; then
  fail "refusal warning helper should not flag tool output mentioning refusal"
else
  pass "refusal warning helper ignores tool output mentioning refusal"
fi

cat > "$TEST_TMPDIR/raw_codex_working_cannot.jsonl" <<'EOF'
{"type":"item.completed","item":{"type":"agent_message","text":"I can't help write the report yet because the sanitizer output is missing; I will run the probe first."}}
EOF
if llm_log_refusal_warning codex "$refusal_prompt" \
    "$TEST_TMPDIR/raw_codex_working_cannot.jsonl" >/dev/null 2>&1; then
  fail "refusal warning helper should not flag Codex working 'can't help write' prose"
else
  pass "refusal warning helper ignores Codex working 'can't help write' prose"
fi

cat > "$TEST_TMPDIR/raw_gemini_working_cannot.jsonl" <<'EOF'
{"type":"init","session_id":"s"}
{"type":"tool_use","tool_name":"run_shell_command","parameters":{"command":"pwd"}}
{"type":"message","role":"assistant","content":"I cannot provide a reproducer for this overflow yet; I cannot generate a testcase that reaches it, so I will keep fuzzing."}
EOF
if llm_log_refusal_warning gemini "$refusal_prompt" \
    "$TEST_TMPDIR/raw_gemini_working_cannot.jsonl" >/dev/null 2>&1; then
  fail "refusal warning helper should not flag Gemini working 'cannot' prose after tool use"
else
  pass "refusal warning helper ignores Gemini working 'cannot' prose after tool use"
fi

# Regression guard: refusal-shaped prose with NO structured refusal field is
# ordinary bug-finding work, not a refusal, and must not be flagged.
cat > "$TEST_TMPDIR/raw_claude_not_refusal.jsonl" <<'EOF'
{"type":"assistant","message":{"content":[{"type":"text","text":"I cannot provide a reproducer for this overflow yet; I cannot generate a testcase that reaches it, so I will keep fuzzing."}],"stop_reason":"end_turn"}}
EOF
if llm_log_refusal_warning claude "$refusal_prompt" \
    "$TEST_TMPDIR/raw_claude_not_refusal.jsonl" >/dev/null 2>&1; then
  fail "refusal warning helper should not flag ordinary 'cannot' working prose"
else
  pass "refusal warning helper ignores ordinary 'cannot' working prose"
fi
assert_file_not_exists "$TEST_TMPDIR/raw_claude_not_refusal.jsonl.refusals.log" \
  "no sidecar written when the turn is not a refusal"

# ── 8. llm_apply_memory_policy ───────────────────────────────────
# The shipped Gemini CLI deny-policy asset.
gem_policy="$SCRIPT_ROOT/config/gemini-no-memory.policy.toml"
assert_file_exists "$gem_policy" "gemini no-memory admin policy ships in config/"
assert_file_contains "$gem_policy" "save_memory" "policy denies the save_memory tool"
assert_file_contains "$gem_policy" 'decision = "deny"' "policy decision is deny"

# Disabled (explicit 0): exports the switch off + claude env var on.
(
  unset CLAUDE_CODE_DISABLE_AUTO_MEMORY TOKENFUZZ_MEMORY_ENABLED
  llm_apply_memory_policy 0
  printf '%s\n%s\n' "${TOKENFUZZ_MEMORY_ENABLED:-UNSET}" \
    "${CLAUDE_CODE_DISABLE_AUTO_MEMORY:-UNSET}"
) > "$TEST_TMPDIR/mem-off" 2>/dev/null
assert_eq "0" "$(sed -n 1p "$TEST_TMPDIR/mem-off")" \
  "memory off exports TOKENFUZZ_MEMORY_ENABLED=0"
assert_eq "1" "$(sed -n 2p "$TEST_TMPDIR/mem-off")" \
  "memory off sets CLAUDE_CODE_DISABLE_AUTO_MEMORY=1"

# No argument + no inherited switch ⇒ disabled (the default).
(
  unset CLAUDE_CODE_DISABLE_AUTO_MEMORY TOKENFUZZ_MEMORY_ENABLED
  llm_apply_memory_policy
  printf '%s\n' "${CLAUDE_CODE_DISABLE_AUTO_MEMORY:-UNSET}"
) > "$TEST_TMPDIR/mem-default" 2>/dev/null
assert_eq "1" "$(cat "$TEST_TMPDIR/mem-default")" \
  "memory policy disables by default with no argument and no inherited switch"

# No argument INHERITS a parent's exported switch (sub-tool behaviour).
(
  export TOKENFUZZ_MEMORY_ENABLED=1
  unset CLAUDE_CODE_DISABLE_AUTO_MEMORY
  llm_apply_memory_policy
  printf '%s\n%s\n' "${TOKENFUZZ_MEMORY_ENABLED:-UNSET}" \
    "${CLAUDE_CODE_DISABLE_AUTO_MEMORY:-UNSET}"
) > "$TEST_TMPDIR/mem-inherit" 2>/dev/null
assert_eq "1" "$(sed -n 1p "$TEST_TMPDIR/mem-inherit")" \
  "no-arg inherits an enabled parent switch"
assert_eq "UNSET" "$(sed -n 2p "$TEST_TMPDIR/mem-inherit")" \
  "inherited-enabled keeps CLAUDE_CODE_DISABLE_AUTO_MEMORY unset"

# Enabled (explicit 1, --enable-memory): switch on, claude disable cleared.
(
  export CLAUDE_CODE_DISABLE_AUTO_MEMORY=1
  unset TOKENFUZZ_MEMORY_ENABLED
  llm_apply_memory_policy 1
  printf '%s\n%s\n' "${TOKENFUZZ_MEMORY_ENABLED:-UNSET}" \
    "${CLAUDE_CODE_DISABLE_AUTO_MEMORY:-UNSET}"
) > "$TEST_TMPDIR/mem-on" 2>/dev/null
assert_eq "1" "$(sed -n 1p "$TEST_TMPDIR/mem-on")" \
  "enable-memory exports TOKENFUZZ_MEMORY_ENABLED=1"
assert_eq "UNSET" "$(sed -n 2p "$TEST_TMPDIR/mem-on")" \
  "enable-memory unsets CLAUDE_CODE_DISABLE_AUTO_MEMORY"

# Staging is separate from the policy: llm_apply_memory_policy runs at startup
# before $LOGDIR is known, so it sets only the claude env + switch and does NOT
# relocate the gemini home.
(
  unset GEMINI_CLI_HOME
  export USE_GEMINI_CLI=1
  llm_apply_memory_policy 0
  printf '%s\n' "${GEMINI_CLI_HOME:-UNSET}"
) > "$TEST_TMPDIR/mem-policy-no-stage" 2>/dev/null
assert_eq "UNSET" "$(cat "$TEST_TMPDIR/mem-policy-no-stage")" \
  "llm_apply_memory_policy does not relocate the gemini home (staging is separate)"

# llm_stage_gemini_memory_home (memory off + Gemini CLI dialect) stages a clean,
# EMPTY home under $LOGDIR: a .gemini/ holding ONLY the marker — no GEMINI.md, no
# symlinks, no credential files (auth rides on GEMINI_API_KEY).
gem_logdir="$TEST_TMPDIR/gem-run-logs"
mkdir -p "$gem_logdir"
(
  unset GEMINI_CLI_HOME TOKENFUZZ_MEMORY_ENABLED
  export USE_GEMINI_CLI=1 LOGDIR="$gem_logdir" GEMINI_API_KEY=test-key
  llm_apply_memory_policy 0
  llm_stage_gemini_memory_home
  printf '%s\n' "${GEMINI_CLI_HOME:-UNSET}"
) > "$TEST_TMPDIR/mem-gem-cli" 2>/dev/null
gem_home="$(cat "$TEST_TMPDIR/mem-gem-cli")"
# -ef compares the resolved file (device+inode), so a // vs / or symlink
# difference between the bash literal and Python's normalized Path doesn't
# matter — the staged dir is the one under $LOGDIR.
if [ "$gem_home" != "UNSET" ] && [ "$(basename "$gem_home")" = ".gemini-home" ] \
   && [ "$gem_home" -ef "$gem_logdir/.gemini-home" ] \
   && [ -d "$gem_home/.gemini" ] \
   && [ -e "$gem_home/.gemini/.tokenfuzz-memory-isolated" ] \
   && [ ! -e "$gem_home/.gemini/GEMINI.md" ] \
   && [ "$(ls -A "$gem_home/.gemini")" = ".tokenfuzz-memory-isolated" ]; then
  pass "memory off + Gemini CLI: clean empty GEMINI_CLI_HOME staged under \$LOGDIR"
else
  fail "memory off + Gemini CLI: clean empty GEMINI_CLI_HOME staged under \$LOGDIR" \
    "got: $gem_home"
fi

# Disabled + agy dialect (USE_GEMINI_CLI unset): no relocation. Antigravity CLI
# has persistent state under ~/.gemini/antigravity-cli/, but it exposes no
# memory-off/profile flag and naive HOME relocation breaks auth (false
# "successful" empty runs), so the harness leaves agy untouched. Use
# USE_GEMINI_CLI=1 for strict Gemini memory isolation.
(
  unset GEMINI_CLI_HOME USE_GEMINI_CLI
  export LOGDIR="$gem_logdir"
  llm_stage_gemini_memory_home
  printf '%s\n' "${GEMINI_CLI_HOME:-UNSET}"
) > "$TEST_TMPDIR/mem-gem-agy" 2>/dev/null
assert_eq "UNSET" "$(cat "$TEST_TMPDIR/mem-gem-agy")" \
  "memory off + agy: no Gemini CLI home relocation (agy left untouched)"

# A leaked USE_GEMINI_CLI=1 in the operator environment must not make
# non-gemini backends require Gemini auth or stage a Gemini home. Entry points
# pass the active backend so claude/codex/oss remain independent.
(
  unset GEMINI_CLI_HOME TOKENFUZZ_MEMORY_ENABLED GEMINI_API_KEY GOOGLE_API_KEY
  export USE_GEMINI_CLI=1 LOGDIR="$TEST_TMPDIR/non-gemini/logs"
  mkdir -p "$LOGDIR"
  llm_apply_memory_policy 0
  if llm_stage_gemini_memory_home claude 2>/dev/null; then
    printf '%s\n' "RET0:${GEMINI_CLI_HOME:-UNSET}"
  else
    printf '%s\n' "FAILED:${GEMINI_CLI_HOME:-UNSET}"
  fi
) > "$TEST_TMPDIR/mem-non-gemini-leaked-switch"
assert_eq "RET0:UNSET" "$(cat "$TEST_TMPDIR/mem-non-gemini-leaked-switch")" \
  "USE_GEMINI_CLI leaked in env does not make non-gemini backends require Gemini auth"

# Sequential cells with DIFFERENT $LOGDIR in one shell (bin/benchmark's
# model-direct cells) must each get their own clean home: cell B must NOT
# inherit cell A's already-exported GEMINI_CLI_HOME (that would leak cell A's
# memory into cell B). Plant memory in A, then stage B and assert B is a
# distinct, clean home under B's logdir.
(
  unset GEMINI_CLI_HOME TOKENFUZZ_MEMORY_ENABLED
  export USE_GEMINI_CLI=1 GEMINI_API_KEY=test-key
  llm_apply_memory_policy 0
  export LOGDIR="$TEST_TMPDIR/cell-a/logs"; mkdir -p "$LOGDIR"
  llm_stage_gemini_memory_home gemini
  printf '%s' "$GEMINI_CLI_HOME" > "$TEST_TMPDIR/cell-a-home"
  printf 'STALE A MEMORY\n' > "$GEMINI_CLI_HOME/.gemini/GEMINI.md"
  # Cell B: new logdir, same shell, A's GEMINI_CLI_HOME still exported.
  export LOGDIR="$TEST_TMPDIR/cell-b/logs"; mkdir -p "$LOGDIR"
  llm_stage_gemini_memory_home gemini
  printf '%s' "$GEMINI_CLI_HOME" > "$TEST_TMPDIR/cell-b-home"
) 2>/dev/null
cell_a_home="$(cat "$TEST_TMPDIR/cell-a-home")"
cell_b_home="$(cat "$TEST_TMPDIR/cell-b-home")"
if [ -n "$cell_b_home" ] && [ "$cell_b_home" != "$cell_a_home" ] \
   && [ "$cell_b_home" -ef "$TEST_TMPDIR/cell-b/logs/.gemini-home" ] \
   && [ ! -e "$cell_b_home/.gemini/GEMINI.md" ]; then
  pass "sequential cells with different \$LOGDIR each stage a distinct clean home"
else
  fail "sequential cells with different \$LOGDIR each stage a distinct clean home" \
    "a=$cell_a_home b=$cell_b_home"
fi

# Fail LOUD when isolation applies but no API key is set: an empty home cannot
# authenticate, so the function returns nonzero and exports NO home rather than
# silently falling through to the operator's global ~/.gemini/GEMINI.md.
(
  unset GEMINI_CLI_HOME TOKENFUZZ_MEMORY_ENABLED GEMINI_API_KEY GOOGLE_API_KEY
  export USE_GEMINI_CLI=1 LOGDIR="$TEST_TMPDIR/noauth/logs"
  mkdir -p "$LOGDIR"
  llm_apply_memory_policy 0
  if llm_stage_gemini_memory_home gemini 2>/dev/null; then
    printf '%s\n' "RET0:${GEMINI_CLI_HOME:-UNSET}"
  else
    printf '%s\n' "FAILED:${GEMINI_CLI_HOME:-UNSET}"
  fi
) > "$TEST_TMPDIR/mem-gem-noauth"
assert_eq "FAILED:UNSET" "$(cat "$TEST_TMPDIR/mem-gem-noauth")" \
  "memory off + Gemini CLI without an API key fails loud (no silent memory leak)"

teardown_test_env
summary
