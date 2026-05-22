#!/usr/bin/env bash
# lib/llm_invoke.sh — Bash shim over lib/llm_invoke.py.
#
# The actual flag-picker / model-default / assistant-text-extractor
# logic lives in lib/llm_invoke.py — single source of truth shared with
# lib/llm_decide.py (which imports `decide_flags` directly to avoid the
# subprocess hop). This bash module preserves the previous function-call
# API so bin/audit, bin/audit-recon, bin/validate-finding don't have to
# change: they still write
#
#     declare -a flags=()
#     llm_agent_flags claude flags "$model" "$max_turns" "$add_dirs"
#     "${CLAUDE_BIN}" "${flags[@]}" -p "$prompt"
#
# and the array gets populated from Python output. Each bash call costs
# one python startup (~80–150 ms); the impacted sites all call this
# 1–4× per agent launch, never in a hot loop.
#
# Public API (preserved exactly):
#
#   llm_known_backend <backend>
#       rc=0 if backend ∈ {claude, codex, oss, gemini}, else rc=1.
#
#   llm_use_gemini_cli
#       rc=0 when USE_GEMINI_CLI=1 selects the Google Gemini CLI dialect.
#
#   llm_gemini_default_bin
#       Echo gemini when USE_GEMINI_CLI=1, otherwise agy.
#
#   llm_default_model <backend>
#       Echo the project-wide default model name. Honours CLAUDE_MODEL_DEFAULT
#       / CODEX_MODEL_DEFAULT / GEMINI_MODEL_DEFAULT /
#       CODEX_OSS_MODEL_DEFAULT env vars.
#
#   llm_agent_flags <backend> <out-array-name> [model] [max_turns] [add_dirs_csv]
#       Populate <out-array-name> with agent-mode flags (stream-json, sandbox
#       bypass, --add-dir / --cd wiring).
#
#   llm_run_agent_prompt <backend> <prompt> <timeout_secs> <raw_log_path>
#                        [model] [max_turns] [add_dirs_csv] [cwd]
#       Invoke a backend with the shared agent flags and write its raw
#       transcript to <raw_log_path>. The caller must have sourced
#       lib/timeout.sh first so audit_timeout_run is available.
#
#   llm_run_agent_prompt_no_timeout <backend> <prompt> <raw_log_path>
#                                   [model] [max_turns] [add_dirs_csv] [cwd]
#       Same as llm_run_agent_prompt, but without an outer wall-clock timeout.
#
#   llm_decide_flags <backend> <out-array-name> [model]
#       Populate <out-array-name> with decide-mode flags (text output, no tools).
#
#   llm_extract_text <backend> <raw_log_path>
#       Stream the assistant's natural-language text to stdout.

_llm_invoke_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
_LLM_INVOKE_PY="$_llm_invoke_dir/llm_invoke.py"
unset _llm_invoke_dir

# Model defaults live in lib/llm_invoke.py so every caller sees the same
# values. This shim exports explicit caller values for the Python subprocess.

llm_use_gemini_cli() {
  [ "${USE_GEMINI_CLI:-0}" = "1" ]
}

llm_gemini_default_bin() {
  if llm_use_gemini_cli; then
    printf '%s\n' "gemini"
  else
    printf '%s\n' "agy"
  fi
}

# Forward the env-var defaults to the python subprocess. The caller's
# shell scope has them set (via the `: "${VAR:=…}"` defaults above or an
# explicit assignment) but bash function callers may not have exported
# them. Each subprocess invocation needs them visible.
_llm_invoke_export_env() {
  export CLAUDE_MODEL_DEFAULT CODEX_MODEL_DEFAULT GEMINI_MODEL_DEFAULT CODEX_OSS_MODEL_DEFAULT
  export USE_GEMINI_CLI="${USE_GEMINI_CLI:-}"
}

llm_known_backend() {
  ( _llm_invoke_export_env
    python3 "$_LLM_INVOKE_PY" known-backend "$1" ) >/dev/null 2>&1
}

llm_default_model() {
  ( _llm_invoke_export_env
    python3 "$_LLM_INVOKE_PY" default-model "$1" )
}

# bash 3.2 (macOS default) lacks `local -n` nameref. The original
# llm_invoke.sh used `eval` for the array assignment; this helper is
# the same trick.
_llm_assign_array() {
  local _name="$1"; shift
  local _i=0 _e _q
  eval "${_name}=()"
  for _e in "$@"; do
    _q=$(printf '%q' "$_e")
    eval "${_name}[${_i}]=${_q}"
    _i=$((_i + 1))
  done
}

# Read Python's one-flag-per-line output into a bash array. Returns
# non-zero if the inner command fails (unknown backend, etc.) so callers
# that test `llm_agent_flags …` for failure see the right rc.
# Process substitution `< <(…)` would swallow the rc, hence the explicit
# command-substitution-then-read pattern.
_llm_invoke_read_flags() {
  local _out_var="$1"; shift
  local _output _rc
  _output=$("$@") || _rc=$?
  if [ -n "${_rc:-}" ]; then
    return "$_rc"
  fi
  local -a _tmp=()
  local _line
  while IFS= read -r _line; do
    _tmp+=("$_line")
  done <<< "$_output"
  # An empty $_output produces one phantom empty element via <<< — drop
  # it so callers see an empty array (the bash original's behavior).
  if [ "${#_tmp[@]}" -eq 1 ] && [ -z "${_tmp[0]}" ]; then
    _tmp=()
  fi
  _llm_assign_array "$_out_var" "${_tmp[@]}"
}

llm_agent_flags() {
  local backend="$1" out_var="$2"
  local model="${3:-}" max_turns="${4:-80}" add_dirs="${5:-}"
  _llm_invoke_export_env
  _llm_invoke_read_flags "$out_var" \
    python3 "$_LLM_INVOKE_PY" agent-flags "$backend" \
      --model "$model" --max-turns "$max_turns" --add-dirs "$add_dirs"
}

llm_backend_bin() {
  case "$1" in
    claude) printf '%s\n' "${CLAUDE_BIN:-claude}" ;;
    codex|oss) printf '%s\n' "${CODEX_BIN:-codex}" ;;
    gemini) printf '%s\n' "${GEMINI_BIN:-$(llm_gemini_default_bin)}" ;;
    *) return 1 ;;
  esac
}

_llm_first_add_dir() {
  local add_dirs="${1:-}" first
  first="${add_dirs%%,*}"
  printf '%s\n' "$first"
}

llm_run_agent_prompt() {
  local backend="$1" prompt="$2" timeout_secs="$3" raw_log="$4"
  local model="${5:-}" max_turns="${6:-80}" add_dirs="${7:-}" cwd="${8:-}"
  local bin rc=0

  command -v audit_timeout_run >/dev/null 2>&1 || {
    echo "llm_run_agent_prompt: audit_timeout_run is not available; source lib/timeout.sh first" >&2
    return 127
  }
  bin="$(llm_backend_bin "$backend")" || return 1
  [ -n "$cwd" ] || cwd="$(_llm_first_add_dir "$add_dirs")"
  [ -n "$cwd" ] || cwd="$PWD"

  declare -a flags=()
  llm_agent_flags "$backend" flags "$model" "$max_turns" "$add_dirs" || return $?

  case "$backend" in
    claude)
      ( cd "$cwd" && audit_timeout_run "$timeout_secs" "$bin" "${flags[@]}" \
        -p "$prompt" ) > "$raw_log" 2>&1 || rc=$?
      ;;
    codex|oss)
      ( cd "$cwd" && printf '%s' "$prompt" \
        | audit_timeout_run "$timeout_secs" "$bin" exec "${flags[@]}" - ) \
        > "$raw_log" 2>&1 || rc=$?
      ;;
    gemini)
      if llm_use_gemini_cli; then
        ( cd "$cwd" && printf '%s' "$prompt" \
          | audit_timeout_run "$timeout_secs" "$bin" "${flags[@]}" -p "" ) \
          > "$raw_log" 2>&1 || rc=$?
      else
        ( cd "$cwd" && printf '%s' "$prompt" \
          | audit_timeout_run "$timeout_secs" "$bin" "${flags[@]}" \
              --print-timeout "${timeout_secs}s" -p "" ) \
          > "$raw_log" 2>&1 || rc=$?
      fi
      ;;
    *)
      return 1
      ;;
  esac
  return "$rc"
}

llm_run_agent_prompt_no_timeout() {
  local backend="$1" prompt="$2" raw_log="$3"
  local model="${4:-}" max_turns="${5:-80}" add_dirs="${6:-}" cwd="${7:-}"
  local bin rc=0

  bin="$(llm_backend_bin "$backend")" || return 1
  [ -n "$cwd" ] || cwd="$(_llm_first_add_dir "$add_dirs")"
  [ -n "$cwd" ] || cwd="$PWD"

  declare -a flags=()
  llm_agent_flags "$backend" flags "$model" "$max_turns" "$add_dirs" || return $?

  case "$backend" in
    claude)
      ( cd "$cwd" && "$bin" "${flags[@]}" -p "$prompt" ) > "$raw_log" 2>&1 || rc=$?
      ;;
    codex|oss)
      ( cd "$cwd" && printf '%s' "$prompt" | "$bin" exec "${flags[@]}" - ) \
        > "$raw_log" 2>&1 || rc=$?
      ;;
    gemini)
      if llm_use_gemini_cli; then
        ( cd "$cwd" && printf '%s' "$prompt" | "$bin" "${flags[@]}" -p "" ) \
          > "$raw_log" 2>&1 || rc=$?
      else
        ( cd "$cwd" && printf '%s' "$prompt" | "$bin" "${flags[@]}" -p "" ) \
          > "$raw_log" 2>&1 || rc=$?
      fi
      ;;
    *)
      return 1
      ;;
  esac
  return "$rc"
}

llm_decide_flags() {
  local backend="$1" out_var="$2" model="${3:-}"
  _llm_invoke_export_env
  _llm_invoke_read_flags "$out_var" \
    python3 "$_LLM_INVOKE_PY" decide-flags "$backend" --model "$model"
}

llm_extract_text() {
  local backend="$1" raw_log="$2"
  [ -r "$raw_log" ] || return 1
  python3 "$_LLM_INVOKE_PY" extract-text "$backend" "$raw_log"
}
