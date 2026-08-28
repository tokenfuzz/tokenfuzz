#!/usr/bin/env bash
# Tests for lib/agent_shell_guards/_zdotdir — re-prepends the process guards
# and, for audit agents, the harness wrappers after macOS's /etc/zprofile
# path_helper reorders PATH inside `zsh -lc`, and bootstraps non-login zsh too.
set -o pipefail
source "$(dirname "$0")/helpers.sh"
setup_test_env

GUARD_ZDOTDIR="$SCRIPT_ROOT/lib/agent_shell_guards/_zdotdir"
GUARDS="$SCRIPT_ROOT/lib/agent_shell_guards"
WRAPPERS="$SCRIPT_ROOT/lib/wrappers"
BASE_PATH="/usr/bin:/bin:/usr/sbin:/sbin"

# Skip if zsh isn't available (CI without it).
if ! command -v zsh >/dev/null 2>&1 && [ ! -x /bin/zsh ]; then
  pass "zdotdir shim: zsh not installed, skipping suite"
  teardown_test_env
  summary
  exit 0
fi

ZSH_BIN="${ZSH_BIN:-/bin/zsh}"
[ -x "$ZSH_BIN" ] || ZSH_BIN="$(command -v zsh)"

# ── The bootstrap files exist and are sourceable ──
for name in .zshenv .zprofile _path.zsh; do
  [ -f "$GUARD_ZDOTDIR/$name" ]
  assert_eq 0 $? "zdotdir: $name exists at expected location"
  # (zsh-flavored; bash -n is a smoke check, not exact)
  bash -n "$GUARD_ZDOTDIR/$name" 2>/dev/null
done

# ── Guards win the PATH race even after /etc/zprofile's path_helper. ──
output=$(ZDOTDIR="$GUARD_ZDOTDIR" AGENT_SHELL_GUARDS_PATH="$GUARDS" \
          PATH="$GUARDS:$BASE_PATH" "$ZSH_BIN" -lc 'echo "$PATH" | cut -d: -f1')
assert_eq "$GUARDS" "$output" "zdotdir: guards dir is first in PATH inside zsh -lc"

# macOS path_helper can move /usr/bin ahead of an operator-selected runtime.
# Preserve the complete inherited order, not only TokenFuzz's own prefixes.
RUNTIME_BIN="$TEST_TMPDIR/runtime-bin"
mkdir -p "$RUNTIME_BIN"
touch "$RUNTIME_BIN/java"
chmod +x "$RUNTIME_BIN/java"
output=$(ZDOTDIR="$GUARD_ZDOTDIR" AGENT_SHELL_GUARDS_PATH="$GUARDS" \
          PATH="$GUARDS:$RUNTIME_BIN:$BASE_PATH" \
          "$ZSH_BIN" -lc 'command -v java')
assert_eq "$RUNTIME_BIN/java" "$output" \
  "zdotdir: login shell preserves the operator-selected runtime"

# Keep paths the system profile added after .zshenv, but behind the launcher's
# explicit order. GUI-launched agents may rely on /etc/paths.d to discover a
# tool that was absent from the sparse launcher environment.
SYSTEM_BIN="$TEST_TMPDIR/system-bin"
mkdir -p "$SYSTEM_BIN"
output=$(ZDOTDIR="$GUARD_ZDOTDIR" AGENT_SHELL_GUARDS_PATH="$GUARDS" \
          PATH="$GUARDS:$RUNTIME_BIN:$BASE_PATH" "$ZSH_BIN" -c \
          '_TOKENFUZZ_INHERITED_PATH="'"$RUNTIME_BIN:$BASE_PATH"'"; PATH="'"$SYSTEM_BIN"':$PATH"; source "$ZDOTDIR/.zprofile"; printf "%s\n" "$PATH"')
assert_eq "$GUARDS:$RUNTIME_BIN:$BASE_PATH:$SYSTEM_BIN" "$output" \
  "zdotdir: system-profile additions survive behind launcher PATH"

# ── A launcher that forwards ZDOTDIR but filters other env vars still gets the
#    guards: the shim infers them from the bootstrap path. ──
for mode in -lc -c; do
  output=$(env -u AGENT_SHELL_GUARDS_PATH -u AGENT_WRAPPERS_PATH \
            ZDOTDIR="$GUARD_ZDOTDIR" PATH="$BASE_PATH" \
            "$ZSH_BIN" "$mode" 'command -v pkill' 2>&1)
  assert_eq "$GUARDS/pkill" "$output" "zdotdir: zsh $mode infers guards from ZDOTDIR alone"
done

# ── Model-direct and validator launches get the process guards, never the
#    TokenFuzz search/compiler wrappers. ──
output=$(env -u AGENT_WRAPPERS_PATH ZDOTDIR="$GUARD_ZDOTDIR" \
          AGENT_SHELL_GUARDS_PATH="$GUARDS" PATH="$GUARDS:$BASE_PATH" \
          "$ZSH_BIN" -lc 'printf "%s\n%s\n" "$(command -v pkill)" "$(command -v rg)"')
assert_eq "$GUARDS/pkill" "$(printf '%s\n' "$output" | sed -n '1p')" \
  "guard zdotdir: pkill resolves to safety guard"
if [ "$(printf '%s\n' "$output" | sed -n '2p')" = "$WRAPPERS/rg" ]; then
  fail "guard zdotdir: model-direct inherited TokenFuzz rg wrapper"
else
  pass "guard zdotdir: model-direct keeps the real rg"
fi

# ── Harness audit agents explicitly add the full wrappers behind the guards. ──
output=$(ZDOTDIR="$GUARD_ZDOTDIR" AGENT_SHELL_GUARDS_PATH="$GUARDS" \
          AGENT_WRAPPERS_PATH="$WRAPPERS" PATH="$GUARDS:$WRAPPERS:$BASE_PATH" \
          "$ZSH_BIN" -lc 'printf "%s\n%s\n" "$(command -v pkill)" "$(command -v rg)"')
assert_eq "$GUARDS/pkill" "$(printf '%s\n' "$output" | sed -n '1p')" \
  "guard zdotdir: process guard stays ahead of audit wrappers"
assert_eq "$WRAPPERS/rg" "$(printf '%s\n' "$output" | sed -n '2p')" \
  "guard zdotdir: harness audit retains TokenFuzz rg wrapper"

# ── An audit launch whose AGENT_WRAPPERS_PATH was filtered still keeps search
#    capped: path_helper demotes the PATH entry but never drops it. ──
output=$(env -u AGENT_WRAPPERS_PATH ZDOTDIR="$GUARD_ZDOTDIR" \
          PATH="$GUARDS:$WRAPPERS:$BASE_PATH" "$ZSH_BIN" -lc 'command -v rg' 2>&1)
assert_eq "$WRAPPERS/rg" "$output" "zdotdir: wrappers recovered from PATH when env var is filtered"

# ── Idempotent: if PATH already contains the dirs somewhere (path_helper
#    relocates them mid-PATH), the shim strips and re-prepends rather than
#    leaving duplicates. ──
output=$(ZDOTDIR="$GUARD_ZDOTDIR" AGENT_SHELL_GUARDS_PATH="$GUARDS" \
          AGENT_WRAPPERS_PATH="$WRAPPERS" PATH="/usr/bin:$WRAPPERS:$GUARDS:/usr/local/bin" \
          "$ZSH_BIN" -lc \
          'echo "$PATH" | tr : "\n" | grep -cFx "$AGENT_WRAPPERS_PATH"; echo "$PATH" | tr : "\n" | grep -cFx "$AGENT_SHELL_GUARDS_PATH"')
assert_eq "1" "$(printf '%s\n' "$output" | sed -n '1p')" "zdotdir: pre-existing wrappers entry is deduped"
assert_eq "1" "$(printf '%s\n' "$output" | sed -n '2p')" "zdotdir: pre-existing guards entry is deduped"

teardown_test_env
summary
