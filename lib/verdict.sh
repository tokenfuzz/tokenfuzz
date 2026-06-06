#!/usr/bin/env bash
# lib/verdict.sh — single source of truth for sanitizer-output crash
# classification.
#
# bin/probe (the authoritative CRASH/DIFF/CLEAN/NO_EXEC verdict),
# bin/scratch-status (read-only verdict display) and lib/quality.sh
# (orphan-enforcement result lines) all source this file, so a Go data
# race / Rust panic / Python fatal / SEGV is recognised identically
# everywhere. Previously each caller carried its own crash regex — an
# impoverished subset of probe's — so the same testcase could read as
# CRASH in one place and CLEAN in another.
#
# Out of scope on purpose:
#   - bin/run-sanitizer-multi's digest has_crash regex serves output
#     digest-truncation, not verdict; it intentionally keys off a narrower,
#     formatting-oriented set. (Crash-rate counting there now uses
#     verdict_file_has_crash from this file.)
#   - lib/quality.py's verified-output regex answers a different
#     question ("was the testcase executed at all"), not "did it crash".

# ─── Canonical crash markers ────────────────────────────────────────
#
# Each entry MUST be a clear runtime-fatal signal — a plain Python
# AssertionError or a Go fmt.Println must NOT trigger CRASH. When in
# doubt prefer NO_EXEC / CLEAN and let lib/triage.sh decide whether a
# finding belongs under crashes/ or findings/.
#
# Per-target additions flow through TARGET_RUNNER_CRASH_PATTERNS (from
# target.toml); verdict_file_has_crash unions them in at match time.
VERDICT_CRASH_PATTERNS=(
  # ── LLVM sanitizers (work for any language that links the runtime) ──
  'ERROR: AddressSanitizer'
  'ERROR: HWAddressSanitizer'
  'AddressSanitizer:DEADLYSIGNAL'
  'WARNING: ThreadSanitizer:'
  'WARNING: MemorySanitizer:'
  'WARNING: DataflowSanitizer:'
  'runtime error:.*UndefinedBehaviorSanitizer'
  'UndefinedBehaviorSanitizer:'
  '\[run-asan\] CRASH DETECTED'
  '\[run-ubsan\] UBSan issue detected'
  # ── Go runtime ──
  'WARNING: DATA RACE'
  'panic: runtime error:'
  'fatal error: stack overflow'
  'fatal error: out of memory'
  'fatal error: concurrent map'
  # ── Rust runtime ──
  "thread '.*' panicked at"
  'fatal runtime error:'
  # ── Java / JVM ──
  '^Exception in thread'
  'java\.lang\.OutOfMemoryError'
  'java\.lang\.StackOverflowError'
  # ── Python ──
  'Fatal Python error:'
  # ── Node.js ──
  '^FATAL ERROR:.*JavaScript heap out of memory'
  '^FATAL ERROR:.*Allocation failed'
  # ── Ruby ──
  '\(NoMemoryError\)'
  'SystemStackError'
  # ── PHP ──
  'PHP Fatal error:'
  # ── ASan/Sanitizer-style hardware traps ──
  '==[0-9]+==SEGV on'
  '==[0-9]+==ERROR:'
)

# verdict_crash_alternation — echo the canonical crash markers joined into
# one extended-regex alternation, with any TARGET_RUNNER_CRASH_PATTERNS
# (per-target, from target.toml) unioned in. The builtin half is built
# once and cached; the per-target half is appended every call so a
# caller that sets TARGET_RUNNER_CRASH_PATTERNS late still sees it.
_VERDICT_CRASH_ALT_BUILTIN=""
verdict_crash_alternation() {
  if [ -z "$_VERDICT_CRASH_ALT_BUILTIN" ]; then
    local p
    for p in "${VERDICT_CRASH_PATTERNS[@]}"; do
      _VERDICT_CRASH_ALT_BUILTIN="${_VERDICT_CRASH_ALT_BUILTIN:+${_VERDICT_CRASH_ALT_BUILTIN}|}${p}"
    done
  fi
  local alt="$_VERDICT_CRASH_ALT_BUILTIN" p
  for p in "${TARGET_RUNNER_CRASH_PATTERNS[@]:-}"; do
    [ -n "$p" ] && alt="${alt}|${p}"
  done
  printf '%s' "$alt"
}

# verdict_file_has_crash <file> — return 0 if <file> carries any crash
# marker. A single grep over the precomputed alternation (faster than a
# per-pattern loop, and identical in result — "any marker, anywhere").
verdict_file_has_crash() {
  local f="$1"
  [ -s "$f" ] || return 1
  grep -qE "$(verdict_crash_alternation)" "$f" 2>/dev/null
}

# verdict_clean_marker_re — echo the canonical "execution verified" regex.
# CLEAN requires wrapper-issued post-run evidence: a non-zero
# run-sanitizer-multi execution rate (the old run-asan-multi label is kept
# for historical artifacts), or a run-<san>/probe EXECUTION VERIFIED marker
# emitted after rc=0 / browser-marker inspection. Raw testcase stdout (e.g. a
# bare TESTCASE_EXECUTED print) is intentionally ignored.
verdict_clean_marker_re() {
  printf '%s' '^\[run-(asan|sanitizer)-multi\] EXECUTION_RATE: [1-9][0-9]*/[0-9]+$|^\[run-(asan|ubsan|msan|tsan)\] (browser|js|xpcshell|generic) EXECUTION VERIFIED \(post-run|^\[run-ubsan\] EXECUTION VERIFIED:|^\[probe\] (asan|ubsan|msan|tsan|race|runner) EXECUTION VERIFIED \(post-run'
}

# verdict_file_is_clean <file> — return 0 if <file> carries wrapper-issued
# execution-verified evidence.
verdict_file_is_clean() {
  local f="$1"
  [ -s "$f" ] || return 1
  grep -qE "$(verdict_clean_marker_re)" "$f" 2>/dev/null
}
