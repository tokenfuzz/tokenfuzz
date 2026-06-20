#!/usr/bin/env bash
# lib/llm_decide.sh — Bash shim over lib/llm_decide.py.
#
# Public API (preserved from the prior all-bash version):
#
#   llm_decide DECISION_NAME REQUIRED_KEYS_CSV [TIMEOUT_SECS]
#       prompt → stdin
#       JSON → stdout (rc=0)   |   nothing (rc=1)
#
#   llm_decide_budget_available
#       Race-safe per-process budget RMW. Returns 0 if under cap, 1 if at cap.
#
# The engine — mock dispatch, budget counter, backend invocation, JSON
# extraction, required-key validation — moved to lib/llm_decide.py to
# eliminate the prior bash-engine / python-wrapper split. Bash callers
# pay a single subprocess hop per LLM call (~100 ms), which is <2% of a
# typical 5–15 s LLM response. Python callers should
# `from llm_decide import llm_decide` directly (lib/ is on every harness
# binary's sys.path).
#
# Test/safety knobs unchanged:
#   LLM_DECIDE_DISABLE=1, LLM_DECIDE_MOCK=<json|@path>,
#   LLM_DECIDE_MOCK_<UPPER>=<json|@path>, LLM_DECIDE_COUNTER_FILE,
#   LLM_DECIDE_MAX_CALLS, etc.

_llm_decide_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
_LLM_DECIDE_PY="$_llm_decide_dir/llm_decide.py"
unset _llm_decide_dir

llm_decide() {
  local decision="$1"
  local required_csv="${2:-}"
  local timeout_secs="${3:-15}"
  # The Python engine reads its config from env vars (ACTIVE_BACKEND/BACKEND,
  # MODEL, *_BIN, LLM_DECIDE_*). Bash functions inherit the caller's
  # *unexported* variables, but subprocess children do not — so we
  # force-export the relevant vars in a subshell before exec-ing python.
  # The subshell isolates the exports so they don't leak back to the
  # caller (matching the prior all-bash semantics).
  (
    export ACTIVE_BACKEND="${ACTIVE_BACKEND:-}"
    export BACKEND="${BACKEND:-}"
    export MODEL="${MODEL:-}"
    export CLAUDE_BIN="${CLAUDE_BIN:-}"
    export CODEX_BIN="${CODEX_BIN:-}"
    export GEMINI_BIN="${GEMINI_BIN:-}"
    # oss/OpenCode decide path: the python child builds the local provider
    # config from these, so forward them like the agent path's
    # _llm_invoke_export_env does. Without the base URL the decide child would
    # fall back to the default endpoint and miss the operator's local server.
    export OPENCODE_BIN="${OPENCODE_BIN:-}"
    export AUDIT_LOCAL_BASE_URL="${AUDIT_LOCAL_BASE_URL:-}"
    export AUDIT_LOCAL_API_KEY="${AUDIT_LOCAL_API_KEY:-}"
    export USE_GEMINI_CLI="${USE_GEMINI_CLI:-}"
    export LLM_DECIDE_DISABLE="${LLM_DECIDE_DISABLE:-}"
    export LLM_DECIDE_MOCK="${LLM_DECIDE_MOCK:-}"
    export LLM_DECIDE_LOG="${LLM_DECIDE_LOG:-}"
    export LLM_DECIDE_COUNTER_FILE="${LLM_DECIDE_COUNTER_FILE:-}"
    export LLM_DECIDE_MAX_CALLS="${LLM_DECIDE_MAX_CALLS:-}"
    export LLM_DECIDE_FAILCACHE_FILE="${LLM_DECIDE_FAILCACHE_FILE:-}"
    export LLM_DECIDE_FAIL_THRESHOLD="${LLM_DECIDE_FAIL_THRESHOLD:-}"
    export LLM_DECIDE_FAIL_COOLDOWN="${LLM_DECIDE_FAIL_COOLDOWN:-}"
    export LOGDIR="${LOGDIR:-}"
    # Per-decision mocks (LLM_DECIDE_MOCK_<UPPER>) have dynamic names —
    # enumerate them via compgen and forward each.
    local _n
    while IFS= read -r _n; do
      [ -n "$_n" ] && export "$_n=${!_n}"
    done < <(compgen -v 2>/dev/null | grep '^LLM_DECIDE_MOCK_' || true)
    python3 "$_LLM_DECIDE_PY" decide "$decision" "$required_csv" "$timeout_secs"
  )
}

llm_decide_budget_available() {
  (
    export LLM_DECIDE_COUNTER_FILE="${LLM_DECIDE_COUNTER_FILE:-}"
    export LLM_DECIDE_MAX_CALLS="${LLM_DECIDE_MAX_CALLS:-}"
    export LOGDIR="${LOGDIR:-}"
    python3 "$_LLM_DECIDE_PY" budget-check
  )
}
