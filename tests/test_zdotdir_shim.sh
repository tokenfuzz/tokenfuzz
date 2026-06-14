#!/usr/bin/env bash
# Tests for lib/wrappers/_zdotdir/.zprofile/.zshenv — re-prepends the harness
# wrappers after macOS's /etc/zprofile path_helper resets PATH inside
# `zsh -lc`, and bootstraps non-login zsh shells too.
set -o pipefail
source "$(dirname "$0")/helpers.sh"
setup_test_env

ZDOTDIR_PATH="$SCRIPT_ROOT/lib/wrappers/_zdotdir"
WRAPPERS="$SCRIPT_ROOT/lib/wrappers"

# Skip if zsh isn't available (CI without it).
if ! command -v zsh >/dev/null 2>&1 && [ ! -x /bin/zsh ]; then
  pass "zdotdir shim: zsh not installed, skipping suite"
  teardown_test_env
  summary
  exit 0
fi

ZSH_BIN="${ZSH_BIN:-/bin/zsh}"
[ -x "$ZSH_BIN" ] || ZSH_BIN="$(command -v zsh)"

# ── .zprofile exists and is sourceable ──
[ -f "$ZDOTDIR_PATH/.zprofile" ]
assert_eq 0 $? "zdotdir: .zprofile exists at expected location"
bash -n "$ZDOTDIR_PATH/.zprofile" 2>/dev/null
# (.zprofile is zsh-flavored; bash -n is a smoke check, not exact)

[ -f "$ZDOTDIR_PATH/.zshenv" ]
assert_eq 0 $? "zdotdir: .zshenv exists at expected location"
bash -n "$ZDOTDIR_PATH/.zshenv" 2>/dev/null

# ── With ZDOTDIR + AGENT_WRAPPERS_PATH, wrappers win the PATH race
#    even after /etc/zprofile's path_helper. ──
output=$(ZDOTDIR="$ZDOTDIR_PATH" AGENT_WRAPPERS_PATH="$WRAPPERS" \
          "$ZSH_BIN" -lc 'echo "$PATH" | cut -d: -f1')
assert_eq "$WRAPPERS" "$output" "zdotdir: wrappers dir is first in PATH inside zsh -lc"

# ── A deferred `which rg` resolves to our wrapper, not the real rg.
output=$(ZDOTDIR="$ZDOTDIR_PATH" AGENT_WRAPPERS_PATH="$WRAPPERS" \
          "$ZSH_BIN" -lc 'command -v rg')
assert_eq "$WRAPPERS/rg" "$output" "zdotdir: rg resolves to wrapper"

# ── If a backend preserves ZDOTDIR but drops AGENT_WRAPPERS_PATH, infer the
#    wrapper directory from the shim path. This keeps rg/grep capped in Codex
#    command shells even when auxiliary env vars are filtered. ──
output=$(ZDOTDIR="$ZDOTDIR_PATH" "$ZSH_BIN" -lc 'command -v rg' 2>&1)
assert_eq "$WRAPPERS/rg" "$output" "zdotdir: ZDOTDIR-only login shell infers wrappers dir"

# ── Non-login zsh reads .zshenv but not .zprofile; it should still find
#    wrappers from ZDOTDIR alone. ──
output=$(ZDOTDIR="$ZDOTDIR_PATH" "$ZSH_BIN" -c 'command -v rg' 2>&1)
assert_eq "$WRAPPERS/rg" "$output" "zdotdir: ZDOTDIR-only non-login shell infers wrappers dir"

# ── Idempotent: if PATH already contains the wrappers dir somewhere
#    (path_helper relocates it mid-PATH), the shim strips and re-prepends
#    rather than leaving a duplicate. ──
output=$(ZDOTDIR="$ZDOTDIR_PATH" AGENT_WRAPPERS_PATH="$WRAPPERS" \
          PATH="/usr/bin:$WRAPPERS:/usr/local/bin" \
          "$ZSH_BIN" -lc 'echo "$PATH" | tr : "\n" | grep -cFx "$AGENT_WRAPPERS_PATH"')
assert_eq "1" "$output" "zdotdir: pre-existing wrappers entry is deduped"

teardown_test_env
summary
