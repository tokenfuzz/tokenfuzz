#!/usr/bin/env bash
# Portable process-tree cleanup for long-running shell entrypoints.

process_tree_kill_descendants() {
  local root_pid="$1" sig="${2:-TERM}" grace="${3:-1}"
  [ -n "${root_pid:-}" ] || return 0
  command -v python3 >/dev/null 2>&1 || return 0
  python3 "$SCRIPT_ROOT/lib/process_tree.py" \
    kill-descendants "$root_pid" "$sig" "$grace" 2>/dev/null || true
}
