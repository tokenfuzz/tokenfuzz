# Re-prepend agent shell guards after a login shell's path_helper reset.

if [ -z "${AGENT_SHELL_GUARDS_PATH:-}" ] && [ -n "${ZDOTDIR:-}" ]; then
  case "$ZDOTDIR" in
    */_zdotdir)
      AGENT_SHELL_GUARDS_PATH="${ZDOTDIR%/_zdotdir}"
      export AGENT_SHELL_GUARDS_PATH
      ;;
  esac
fi

_agent_prepend_path() {
  [ -n "$1" ] || return
  case ":$PATH:" in
    *":$1:"*)
      _agent_stripped=":${PATH}:"
      _agent_stripped="${_agent_stripped//:$1:/:}"
      _agent_stripped="${_agent_stripped#:}"
      _agent_stripped="${_agent_stripped%:}"
      PATH="$_agent_stripped"
      unset _agent_stripped
      ;;
  esac
  PATH="$1:$PATH"
}

# A launcher can forward ZDOTDIR while filtering other env vars, and
# path_helper only demotes PATH entries rather than dropping them. Recover the
# audit wrappers from their marker file so search stays capped. A launch that
# never had them — model-direct — has no such entry and keeps the real tools.
if [ -z "${AGENT_WRAPPERS_PATH:-}" ]; then
  for _agent_entry in $path; do
    if [ -f "$_agent_entry/wrapper_tools.py" ]; then
      AGENT_WRAPPERS_PATH="$_agent_entry"
      export AGENT_WRAPPERS_PATH
      break
    fi
  done
  unset _agent_entry
fi

# Prepend the audit wrappers first so the process guards finish in front.
_agent_prepend_path "${AGENT_WRAPPERS_PATH:-}"
_agent_prepend_path "${AGENT_SHELL_GUARDS_PATH:-}"
export PATH
unfunction _agent_prepend_path 2>/dev/null
