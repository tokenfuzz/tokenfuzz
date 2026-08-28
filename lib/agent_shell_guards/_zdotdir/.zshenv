# zsh reads this before macOS /etc/zprofile can reorder PATH. Preserve the
# launcher's resolved tool order so .zprofile can restore it afterwards.
_TOKENFUZZ_INHERITED_PATH="$PATH"
source "${ZDOTDIR}/_path.zsh"
