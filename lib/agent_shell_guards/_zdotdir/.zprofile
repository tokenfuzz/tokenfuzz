# zsh reads this after macOS /etc/zprofile may have reset PATH.
if [ -n "${_TOKENFUZZ_INHERITED_PATH:-}" ]; then
  # Preserve the launcher's selected order while retaining genuinely new
  # /etc/paths.d entries at the tail. Dropping those breaks sparse GUI launch
  # environments; allowing path_helper to put them first changes toolchains.
  typeset -a _tokenfuzz_merged_path
  _tokenfuzz_merged_path=(
    "${(@s/:/)_TOKENFUZZ_INHERITED_PATH}"
    "${path[@]}"
  )
  typeset -U _tokenfuzz_merged_path
  path=("${_tokenfuzz_merged_path[@]}")
  unset _tokenfuzz_merged_path
fi
unset _TOKENFUZZ_INHERITED_PATH
source "${ZDOTDIR}/_path.zsh"
