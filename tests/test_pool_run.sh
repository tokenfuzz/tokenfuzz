#!/usr/bin/env bash
# tests/test_pool_run.sh — lib/platform.sh's pool_run: the bounded FIFO
# sliding-window fork pool shared by every triage/recon parallel sweep
# (lib/triage.sh crash sweep, find gate, find-quality, cluster expand,
# maintain_indexes render; bin/audit-recon survivor validation).
#
# Coverage:
#   1. Every item runs exactly once, serial (pool=1) and parallel (pool=N).
#   2. Serial execution preserves order and the 1-based INDEX argument.
#   3. Items containing spaces/tabs are ONE item each — never word-split
#      (a split would silently drop/duplicate work: a false negative).
#   4. Empty item list is a no-op under `set -u` (no unbound-var error).
#   5. REGRESSION: the final drain waits only on its own workers, so a
#      foreground pool completes even when the shell also owns a long-lived
#      sibling job (the benchmark console `tee` that a bare `wait` deadlocked).

set -uo pipefail

TESTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$TESTS_DIR/helpers.sh"                 # also sources lib/platform.sh
source "$SCRIPT_ROOT/lib/timeout.sh"

WORK=$(mktemp -d "${TMPDIR:-/tmp}/pool-run-test.XXXXXX")
trap 'rm -rf "$WORK" 2>/dev/null || true' EXIT

# Each call drops one uniquely-named file, so the file count is an exact,
# race-free tally of how many times the worker actually ran.
_count_worker() { mktemp "$WORK/call.XXXXXX" >/dev/null 2>&1 || true; }
_calls() { find "$WORK" -maxdepth 1 -name 'call.*' 2>/dev/null | wc -l | tr -d ' '; }
_reset() { rm -f "$WORK"/call.* "$WORK"/order.log 2>/dev/null || true; }

# ── 1. every item runs exactly once ─────────────────────────────────
_reset
pool_run 1 _count_worker a b c d e
assert_eq 5 "$(_calls)" "serial pool runs every item exactly once"

_reset
pool_run 4 _count_worker a b c d e f g h i j
assert_eq 10 "$(_calls)" "parallel pool runs every item exactly once"

# Window smaller than the item count still drains everything.
_reset
pool_run 3 _count_worker 1 2 3 4 5 6 7
assert_eq 7 "$(_calls)" "parallel pool drains beyond a full window"

# ── 2. serial order + 1-based INDEX ─────────────────────────────────
_reset
_record_order() { printf '%s:%s\n' "$2" "$1" >> "$WORK/order.log"; }
pool_run 1 _record_order alpha beta gamma
got=$(tr '\n' ' ' < "$WORK/order.log")
assert_eq "1:alpha 2:beta 3:gamma " "$got" "serial pool preserves order and 1-based index"

# ── 3. spaces/tabs are never word-split (false-negative guard) ───────
_reset
pool_run 1 _count_worker "a b c" "d" "e	f"
assert_eq 3 "$(_calls)" "serial pool treats a spaced/tabbed item as ONE item"

_reset
pool_run 4 _count_worker "a b c" "d" "e	f"
assert_eq 3 "$(_calls)" "parallel pool treats a spaced/tabbed item as ONE item"

# The item value reaches the worker intact (no truncation at the space).
_reset
_capture_first() { [ -e "$WORK/first" ] || printf '%s' "$1" > "$WORK/first"; }
pool_run 1 _capture_first "x y z"
assert_eq "x y z" "$(cat "$WORK/first")" "spaced item value reaches the worker intact"

# ── 4. empty item list is a no-op under set -u ──────────────────────
_reset
rc=0
pool_run 4 _count_worker || rc=$?
assert_eq 0 "$rc" "empty item list returns 0"
assert_eq 0 "$(_calls)" "empty item list runs no workers"

# ── 5. regression: drain alongside a long-lived sibling job ─────────
# Reproduces the benchmark deadlock: a foreground pool draining while the
# shell also owns a long-lived background child. A bare `wait` blocks on the
# sibling forever; pool_run waits only on its own workers. Run under a hard
# timeout so a regression fails loudly instead of hanging the suite. The
# sibling sleep (30s) outlasts the 8s timeout, so a hang is unambiguous.
sib_script='
  source "'"$SCRIPT_ROOT"'/lib/platform.sh"
  sleep 30 &                       # long-lived sibling (console-tee analog)
  _noop() { : ; }
  pool_run 4 _noop a b c d e f g h
'
rc=0
audit_timeout_kill 8 bash -c "$sib_script" || rc=$?
assert_eq 0 "$rc" "pool_run drains with a long-lived sibling job (no bare-wait deadlock)"

summary
