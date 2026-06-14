# lib/wrappers/_zdotdir/.zshenv — bootstrap wrapper path for all zsh modes.
#
# zsh reads this before .zprofile, and also for non-login shells. Keep it tiny:
# infer AGENT_WRAPPERS_PATH from ZDOTDIR when possible, then prepend it for
# non-login shells. Login shells still get a second, post-path_helper prepend in
# .zprofile, which removes duplicates and wins the macOS PATH reset.

if [ -z "${AGENT_WRAPPERS_PATH:-}" ] && [ -n "${ZDOTDIR:-}" ]; then
  case "$ZDOTDIR" in
    */_zdotdir)
      AGENT_WRAPPERS_PATH="${ZDOTDIR%/_zdotdir}"
      export AGENT_WRAPPERS_PATH
      ;;
  esac
fi

if [ -n "${AGENT_WRAPPERS_PATH:-}" ]; then
  case ":$PATH:" in
    *":$AGENT_WRAPPERS_PATH:"*) ;;
    *) export PATH="$AGENT_WRAPPERS_PATH:$PATH" ;;
  esac
fi
