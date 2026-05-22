# lib/wrappers/_zdotdir/.zprofile — sourced by `zsh -l` when ZDOTDIR points here.
#
# Why this exists: codex executes shell commands via `/bin/zsh -lc "..."`. On
# macOS, /etc/zprofile runs path_helper which OVERWRITES PATH from /etc/paths
# and /etc/paths.d, wiping out anything bin/audit prepended. Without this file
# the cap wrappers in lib/wrappers/ are unreachable from inside agent commands
# and raw `rg` runs at full firehose (observed: 7.2 MB of rg output across one
# audit run, vs ~2 MB when wrappers actually fire).
#
# Runs after /etc/zprofile, so we win the path_helper race. Silent no-op when
# AGENT_WRAPPERS_PATH is unset (lets developers source this dir without harm).

if [ -n "${AGENT_WRAPPERS_PATH:-}" ]; then
  # Strip any existing copy first so wrappers always win the PATH race —
  # path_helper on macOS may have re-positioned them after /opt/homebrew/bin
  # which means raw `rg` would still resolve to the unwrapped binary.
  case ":$PATH:" in
    *":$AGENT_WRAPPERS_PATH:"*)
      _stripped=":${PATH}:"
      _stripped="${_stripped//:$AGENT_WRAPPERS_PATH:/:}"
      _stripped="${_stripped#:}"; _stripped="${_stripped%:}"
      PATH="$_stripped"
      unset _stripped
      ;;
  esac
  export PATH="$AGENT_WRAPPERS_PATH:$PATH"
fi
