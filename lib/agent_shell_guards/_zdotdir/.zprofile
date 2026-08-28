# zsh reads this after macOS /etc/zprofile may have reset PATH.
PATH="${_TOKENFUZZ_INHERITED_PATH:-$PATH}"
unset _TOKENFUZZ_INHERITED_PATH
source "${ZDOTDIR}/_path.zsh"
