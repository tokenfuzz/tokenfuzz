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
#      --oss for the oss alias, --dangerously-skip-permissions for
#      the gemini backend / Antigravity CLI).
#   4. llm_agent_flags wires --add-dir / --cd from the add_dirs CSV.
#   5. llm_decide_flags is text-mode and read-only-sandbox per backend.
#   6. llm_extract_text decodes assistant text for each backend's
#      output shape (claude stream-json, codex agent_message wrap,
#      gemini plain stdout).
#   7. llm_extract_text returns empty on raw_log that has no
#      assistant content, and returns rc=1 if raw_log is missing.

set -uo pipefail

TESTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$TESTS_DIR/helpers.sh"
unset USE_GEMINI_CLI
unset CLAUDE_MODEL_DEFAULT CODEX_MODEL_DEFAULT GEMINI_MODEL_DEFAULT CODEX_OSS_MODEL_DEFAULT
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

# oss — codex flags PLUS --oss --local-provider ollama
declare -a flags_oss=()
llm_agent_flags oss flags_oss "" 80 ""
flags_str="${flags_oss[*]}"
assert_match "--oss"                  "$flags_str" "agent oss has --oss"
assert_match "--local-provider ollama" "$flags_str" "agent oss has --local-provider ollama"
assert_match "--sandbox danger-full-access" "$flags_str" "agent oss inherits danger-full-access"

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
assert_match "--max-turns 1"         "$flags_str" "decide claude pins max-turns 1"
assert_match "--output-format text"  "$flags_str" "decide claude has text output"
if grep -q -- "--dangerously-skip-permissions" <<< "$flags_str"; then
  fail "decide claude must NOT include --dangerously-skip-permissions (no tools)"
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

teardown_test_env
summary
