#!/usr/bin/env bash
# Portable timeout helpers for audit scripts.
#
# This module intentionally does not depend on GNU coreutils `timeout`.
# macOS does not ship that utility by default, so callers should source this
# file and use audit_timeout_run / audit_timeout_kill instead.
#
# The runner itself is lib/timeout.py. Resolve its path once at source time
# so callers can cd anywhere afterwards.

_audit_timeout_py="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/timeout.py"

audit_timeout_run() {
  local secs="$1"; shift
  python3 "$_audit_timeout_py" "$secs" TERM 0 "$@"
}

audit_timeout_kill() {
  local secs="$1"; shift
  python3 "$_audit_timeout_py" "$secs" KILL 0 "$@"
}

# audit_timeout_run_rss <secs> <rss_mb> <cmd...>
#   Like audit_timeout_run, but also SIGKILLs the command's process tree if its
#   summed resident memory crosses <rss_mb> MB — a host-protection cap for
#   generic probe runs where one huge-allocation testcase can swap-wedge the
#   box. <rss_mb> of 0/empty means "no cap" and is byte-identical to
#   audit_timeout_run. The watchdog lives in the same poll loop as the timeout
#   so an over-RSS kill reuses the exact group-kill path, and it is allocator-
#   agnostic — unlike ASan's hard_rss_limit_mb, which is inert on macOS.
audit_timeout_run_rss() {
  local secs="$1" rss_mb="$2"; shift 2
  python3 "$_audit_timeout_py" "$secs" TERM "${rss_mb:-0}" "$@"
}
