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
#   llm_apply_memory_policy [enabled]
#       Set the process-wide cross-run auto-memory policy (default off),
#       exporting TOKENFUZZ_MEMORY_ENABLED + the claude env var so backend
#       children inherit it. With no argument it inherits the parent's
#       exported switch. See the function for the per-backend mechanism.
#
#   llm_default_model <backend>
#       Echo the project-wide default model name. Honours CLAUDE_MODEL_DEFAULT
#       / CODEX_MODEL_DEFAULT / GEMINI_MODEL_DEFAULT env vars.
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
#
#   llm_log_refusal_warning <backend> <prompt> <raw_log_path>
#       Detect a structured backend refusal/block in the raw transcript and
#       emit a one-line MODEL_REFUSAL warning (backend + first prompt line) to
#       stderr and to a "<raw_log_path>.refusals.log" sidecar. The sidecar is
#       truncated, not appended: one transcript = at most one refusal, so a
#       resumed run that re-runs the same turn stays idempotent.

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

# llm_apply_memory_policy [enabled]
#   Set the process-wide cross-run "auto-memory" policy. Exports the single
#   switch TOKENFUZZ_MEMORY_ENABLED (read by the flag builders in
#   lib/llm_invoke.py) plus the claude env var, so every spawned backend
#   child inherits the decision. Call once at startup from each entry point.
#
#   With an explicit argument (0/1) the caller forces the decision —
#   bin/audit passes its --enable-memory state, bin/benchmark always passes 0.
#   With NO argument it inherits a parent's exported TOKENFUZZ_MEMORY_ENABLED
#   (default off), so sub-tools (bin/audit-recon, bin/validate-finding) honour
#   the audit that spawned them yet still default to off when run standalone.
#
# Some backend CLIs accumulate learned notes across runs and inject them into
# every later session's context: Claude Code's MEMORY.md + memory/*, Codex's
# ~/.codex/memories/, and Google Gemini CLI's save_memory tool (appends to the
# global ~/.gemini/GEMINI.md). One wrong note then steers every future run — a
# confirmed failure mode (a stale "this surface is saturated" note walked an
# audit straight past a real bug). The harness disables it by DEFAULT so each
# run reasons from the target code, not from a prior run's guesses.
#
# Scope is the auto-accumulated, cross-run channel only. Operator-authored
# project context — AGENTS.md (every backend) and project GEMINI.md — is the
# audit contract and is never touched.
#
# Per-backend mechanism (applied where it actually takes effect):
#   claude  CLAUDE_CODE_DISABLE_AUTO_MEMORY=1, exported here (claude reads the
#           env var directly; it has no launch flag for this).
#   codex   `-c features.memories=false` + memories.use_memories/generate=false,
#           injected by llm_invoke.py's flag builders keyed on
#           TOKENFUZZ_MEMORY_ENABLED, so EVERY launch path gets them.
#   oss     OpenCode is launched with a per-call provider config. No
#           cross-run memory controls are currently needed.
#   gemini  (Google Gemini CLI) GEMINI_CLI_HOME relocated to a clean, EMPTY
#           per-run home so the global ~/.gemini/GEMINI.md is neither read nor
#           written (no setting or flag disables that load — verified). Auth
#           rides on the GEMINI_API_KEY env the harness forwards, so the empty
#           home needs no credential files. Staged by
#           llm_stage_gemini_memory_home AFTER $LOGDIR is known (so the home
#           lives under the run's output tree), NOT here. The save_memory deny
#           in the flag builders is only a defence-in-depth backstop.
#   gemini  (agy / Antigravity) — left untouched. The CLI persists state under
#           ~/.gemini/antigravity-cli (including brain/implicit/conversations),
#           but it exposes no documented memory-off flag or auth-preserving
#           isolated home/profile switch in headless `agy -p`. Relocating HOME
#           creates fresh state but breaks auth, so the harness does not do it
#           implicitly. Use USE_GEMINI_CLI=1 when strict Gemini memory
#           isolation is required.
llm_apply_memory_policy() {
  local enabled
  if [ $# -ge 1 ]; then
    enabled="$1"
  else
    enabled="${TOKENFUZZ_MEMORY_ENABLED:-0}"
  fi
  if [ "$enabled" = "1" ]; then
    export TOKENFUZZ_MEMORY_ENABLED=1
    unset CLAUDE_CODE_DISABLE_AUTO_MEMORY
    return 0
  fi
  export TOKENFUZZ_MEMORY_ENABLED=0
  export CLAUDE_CODE_DISABLE_AUTO_MEMORY=1
}

# llm_stage_gemini_memory_home [backend]
#   Stage a clean, empty per-run Gemini CLI home and export GEMINI_CLI_HOME so
#   the global ~/.gemini/GEMINI.md is neither read nor written this run. No-op
#   unless <backend> is gemini, cross-run memory is OFF, and the gemini-cli
#   dialect is in use (agy is never touched). <backend> defaults from
#   ACTIVE_BACKEND / BACKEND when available, then gemini for direct helper tests.
#   Call from each entry point AFTER $LOGDIR is set: the home then lands at
#   $LOGDIR/.gemini-home — wiped fresh each run, cleaned with the run's artifacts,
#   never littering /tmp. Staging once here and exporting the result means every
#   later launch (bash agents and the llm_decide.py subprocess) inherits and
#   reuses the one staged home.
#
#   Fails LOUD (rc=1) when isolation applies but cannot be guaranteed: the whole
#   point is that the operator's global GEMINI.md is not read/written, so a
#   silent fall-through to it would defeat the guard. Callers treat a nonzero
#   return as fatal. Two ways it bails:
#     * no API key — an empty home has no credential files, so it can only
#       authenticate via GEMINI_API_KEY / GOOGLE_API_KEY in the env. Without
#       one, fail now rather than dying opaquely mid-run on an auth error (or,
#       worse, silently reading the global home).
#     * staging produced no home — python could not stage it (e.g. an
#       unwritable $LOGDIR, or a python too old to run the module at all).
llm_stage_gemini_memory_home() {
  local _backend="${1:-${ACTIVE_BACKEND:-${BACKEND:-gemini}}}"
  [ "$_backend" = "gemini" ] || return 0
  [ "${TOKENFUZZ_MEMORY_ENABLED:-0}" = "1" ] && return 0
  llm_use_gemini_cli || return 0
  if [ -z "${GEMINI_API_KEY:-}" ] && [ -z "${GOOGLE_API_KEY:-}" ]; then
    {
      echo "ERROR: Gemini CLI cross-run memory isolation needs an API key."
      echo "       The harness relocates GEMINI_CLI_HOME to a clean, EMPTY home"
      echo "       (no cross-run memory, no credential files), which can only"
      echo "       authenticate via an env API key. Set GEMINI_API_KEY or"
      echo "       GOOGLE_API_KEY, or run the default agy backend (unset"
      echo "       USE_GEMINI_CLI), or pass --enable-memory to opt back in."
    } >&2
    return 1
  fi
  local _gemini_home _rc=0
  _llm_invoke_export_env
  export LOGDIR="${LOGDIR:-}"
  # Capture rc without `set -e` aborting the assignment; let python's stderr
  # flow through so the real cause (e.g. an ImportError) is visible.
  _gemini_home="$(python3 "$_LLM_INVOKE_PY" gemini-isolated-home)" || _rc=$?
  if [ "$_rc" -ne 0 ] || [ -z "$_gemini_home" ]; then
    {
      echo "ERROR: Gemini CLI memory isolation failed to stage a clean home"
      echo "       (python3 lib/llm_invoke.py gemini-isolated-home: rc=$_rc," \
           "home='$_gemini_home')."
      echo "       Refusing to run: the global ~/.gemini/GEMINI.md would"
      echo "       otherwise be read and written. Check that python3" \
           "($(command -v python3 || echo not-found)) can run the module."
    } >&2
    return 1
  fi
  export GEMINI_CLI_HOME="$_gemini_home"
}

# Forward the env-var defaults to the python subprocess. The caller's
# shell scope has them set (via the `: "${VAR:=…}"` defaults above or an
# explicit assignment) but bash function callers may not have exported
# them. Each subprocess invocation needs them visible.
_llm_invoke_export_env() {
  export CLAUDE_MODEL_DEFAULT CODEX_MODEL_DEFAULT GEMINI_MODEL_DEFAULT
  export AUDIT_LOCAL_BASE_URL AUDIT_LOCAL_API_KEY OPENCODE_BIN
  export USE_GEMINI_CLI="${USE_GEMINI_CLI:-}"
  # The flag builders gate the per-backend memory-disable flags on this; an
  # unset value reads as "memory off" (the harness default).
  export TOKENFUZZ_MEMORY_ENABLED="${TOKENFUZZ_MEMORY_ENABLED:-}"
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
    codex) printf '%s\n' "${CODEX_BIN:-codex}" ;;
    oss) printf '%s\n' "${OPENCODE_BIN:-opencode}" ;;
    gemini) printf '%s\n' "${GEMINI_BIN:-$(llm_gemini_default_bin)}" ;;
    *) return 1 ;;
  esac
}

llm_opencode_config_content() {
  local model="${1:-}"
  ( _llm_invoke_export_env
    python3 "$_LLM_INVOKE_PY" opencode-config --model "$model" )
}

llm_resolve_model_name() {
  local backend="$1" model="${2:-}"
  ( _llm_invoke_export_env
    python3 "$_LLM_INVOKE_PY" resolve-model "$backend" --model "$model" )
}

llm_local_base_url() {
  ( _llm_invoke_export_env
    python3 "$_LLM_INVOKE_PY" local-base-url )
}

llm_newest_agy_cli_log() {
  local dir newest="" f
  dir="${AUDIT_GEMINI_CLI_LOG_DIR:-${GEMINI_DIR:-$HOME/.gemini}/antigravity-cli/log}"
  [ -d "$dir" ] || return 1
  for f in "$dir"/cli-*.log; do
    [ -e "$f" ] || continue
    if [ -z "$newest" ] || [ "$f" -nt "$newest" ]; then
      newest="$f"
    fi
  done
  [ -n "$newest" ] || return 1
  printf '%s\n' "$newest"
}

llm_capture_gemini_cli_log_diag() {
  local dest="$1" newest matches
  newest="$(llm_newest_agy_cli_log 2>/dev/null || true)"
  [ -n "$newest" ] && [ -f "$newest" ] || return 0
  matches="$(grep -E 'RESOURCE_EXHAUSTED|[Qq]uota|429|503|UNAVAILABLE|executor error|Resets in' \
    "$newest" 2>/dev/null | tail -15 || true)"
  [ -n "$matches" ] || return 0
  {
    printf '[agy CLI log tail: %s]\n' "$newest"
    printf '%s\n' "$matches"
  } >> "$dest" 2>/dev/null || true
}

llm_log_refusal_warning() {
  local backend="$1" prompt="$2" raw_log="$3"
  local warning
  _llm_invoke_export_env
  warning="$(printf '%s' "$prompt" \
    | python3 "$_LLM_INVOKE_PY" refusal-warning "$backend" "$raw_log" 2>/dev/null)" \
    || return 1
  [ -n "$warning" ] || return 1
  printf '%s\n' "$warning" >&2
  # Truncate, not append: the sidecar path is unique per transcript, so one
  # line per refusing turn keeps the benchmark count idempotent across resume.
  printf '%s\n' "$warning" > "${raw_log}.refusals.log" 2>/dev/null || true
  return 0
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

  # Stdin-fed backends take the prompt through a redirect, never a pipe: a
  # CLI that exits before draining stdin (quota rejection, auth failure)
  # kills the writer with SIGPIPE, and pipefail would report that 141 as the
  # CLI's own status — masking the rc==0 empty-output and quota diagnostics
  # below. A redirect keeps the writer out of the pipeline's status.
  case "$backend" in
    claude)
      ( cd "$cwd" && audit_timeout_run "$timeout_secs" "$bin" "${flags[@]}" \
        -p "$prompt" ) > "$raw_log" 2>&1 || rc=$?
      ;;
    codex)
      ( cd "$cwd" && audit_timeout_run "$timeout_secs" "$bin" exec "${flags[@]}" - \
        < <(printf '%s' "$prompt") ) > "$raw_log" 2>&1 || rc=$?
      ;;
    oss)
      # OpenCode `run` takes the prompt as a positional argument; it has no
      # stdin path (unlike codex `exec -`), so the prompt rides in argv.
      local opencode_config
      opencode_config="$(llm_opencode_config_content "$model")" || return $?
      ( cd "$cwd" && OPENCODE_CONFIG_CONTENT="$opencode_config" \
        audit_timeout_run "$timeout_secs" "$bin" "${flags[@]}" \
          "$prompt" \
        ) \
        > "$raw_log" 2>&1 || rc=$?
      ;;
    gemini)
      if llm_use_gemini_cli; then
        ( cd "$cwd" && audit_timeout_run "$timeout_secs" "$bin" "${flags[@]}" -p "" \
          < <(printf '%s' "$prompt") ) > "$raw_log" 2>&1 || rc=$?
      else
        ( cd "$cwd" && audit_timeout_run "$timeout_secs" "$bin" "${flags[@]}" \
            --print-timeout "${timeout_secs}s" -p "" \
          < <(printf '%s' "$prompt") ) > "$raw_log" 2>&1 || rc=$?
        [ -s "$raw_log" ] || llm_capture_gemini_cli_log_diag "$raw_log"
      fi
      ;;
    *)
      return 1
      ;;
  esac
  llm_log_refusal_warning "$backend" "$prompt" "$raw_log" || true
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
    codex)
      ( cd "$cwd" && "$bin" exec "${flags[@]}" - < <(printf '%s' "$prompt") ) \
        > "$raw_log" 2>&1 || rc=$?
      ;;
    oss)
      # Prompt rides in argv — OpenCode `run` has no stdin path.
      local opencode_config
      opencode_config="$(llm_opencode_config_content "$model")" || return $?
      ( cd "$cwd" && OPENCODE_CONFIG_CONTENT="$opencode_config" "$bin" "${flags[@]}" \
          "$prompt" \
        ) \
        > "$raw_log" 2>&1 || rc=$?
      ;;
    gemini)
      if llm_use_gemini_cli; then
        ( cd "$cwd" && "$bin" "${flags[@]}" -p "" < <(printf '%s' "$prompt") ) \
          > "$raw_log" 2>&1 || rc=$?
      else
        ( cd "$cwd" && "$bin" "${flags[@]}" -p "" < <(printf '%s' "$prompt") ) \
          > "$raw_log" 2>&1 || rc=$?
        [ -s "$raw_log" ] || llm_capture_gemini_cli_log_diag "$raw_log"
      fi
      ;;
    *)
      return 1
      ;;
  esac
  llm_log_refusal_warning "$backend" "$prompt" "$raw_log" || true
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

llm_raw_has_tool() {
  local raw_log="$1" tool_name="$2"
  [ -r "$raw_log" ] || return 1
  python3 "$_LLM_INVOKE_PY" raw-has-tool "$raw_log" "$tool_name"
}

# llm_transient_tail <raw_log> — exit 0 when the tail of a raw transcript
# shows a fatal transient provider failure (overload / 429 / 5xx / rate
# limit / timeout) that cut the run off. Single, backend-agnostic source of
# transient-error detection: it understands both a plain stderr error line
# and a JSON error event, so callers check the RAW transcript (the
# stream-json text extractor drops these) without hand-rolling a regex.
llm_transient_tail() {
  local raw_log="$1"
  [ -r "$raw_log" ] || return 1
  python3 "$_LLM_INVOKE_PY" transient-tail "$raw_log"
}
