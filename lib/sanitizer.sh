#!/usr/bin/env bash
# lib/sanitizer.sh — shared helpers for bin/run-{asan,ubsan,msan,tsan}.
#
# Responsibilities:
#   - Resolve the canonical *_OPTIONS string for a sanitizer/mode pair via
#     sanitizer_options_for, reading lib/sanitizer_options.conf — the single
#     source of truth shared with bin/export-repro.
#   - Build the *_OPTIONS string, appending the per-target suppressions
#     file (TARGET_<NAME>_SUPPRESSIONS) and extra options
#     (TARGET_<NAME>_OPTIONS) from target.toml.
#   - Warn — without aborting — when a sanitizer is invoked for a target
#     that did not opt into it via [sanitizer].enabled. Operators may
#     legitimately run a one-off MSan repro on an ASan-only target; we
#     surface the mismatch but never block the run.
#   - Warn when a configured suppressions file is missing, again without
#     aborting (audits often start before suppression files are written).
#
# This file is sourced by the runners after lib/target_config.sh has
# already been sourced and target_load has been attempted.

# Resolve the path to a sanitizer build dir, honouring AUDIT_BUILD_SUFFIX.
# Outside a container the suffix is empty and the dir is plain build-<name>;
# inside bin/audit-container-shell the suffix is the short container image
# ID so different images get isolated build-<name>-<id> trees.
#
# Usage: sanitizer_build_dir <name> [<root>]
#   name : asan | ubsan | msan | tsan | asan-cov | ...
#   root : defaults to ${TARGET_ROOT}
sanitizer_build_dir() {
  local name="$1" root="${2:-${TARGET_ROOT:-}}"
  printf '%s/build-%s%s' "$root" "$name" "${AUDIT_BUILD_SUFFIX:-}"
}

# Keep sanitizer runtime environments exclusive. Ambient variables from a
# parent shell are otherwise inherited by `env NAME_OPTIONS=... cmd`, so a
# UBSan run can accidentally carry ASAN_OPTIONS, or a findings/race runner can
# carry stale sanitizer state. The selected sanitizer's variable is preserved
# so explicit one-off overrides still work.
sanitizer_prepare_runtime_env() {
  local selected="$1"
  case "$selected" in
    asan)
      unset UBSAN_OPTIONS MSAN_OPTIONS TSAN_OPTIONS
      ;;
    ubsan)
      unset ASAN_OPTIONS MSAN_OPTIONS TSAN_OPTIONS
      ;;
    msan)
      unset ASAN_OPTIONS UBSAN_OPTIONS TSAN_OPTIONS
      ;;
    tsan)
      unset ASAN_OPTIONS UBSAN_OPTIONS MSAN_OPTIONS
      ;;
    none|runner|race|"")
      unset ASAN_OPTIONS UBSAN_OPTIONS MSAN_OPTIONS TSAN_OPTIONS
      ;;
    *)
      return 1
      ;;
  esac
}

sanitizer_options_env_name() {
  case "$1" in
    asan)  printf '%s\n' ASAN_OPTIONS ;;
    ubsan) printf '%s\n' UBSAN_OPTIONS ;;
    msan)  printf '%s\n' MSAN_OPTIONS ;;
    tsan)  printf '%s\n' TSAN_OPTIONS ;;
    *)     return 1 ;;
  esac
}

sanitizer_runtime_options() {
  local name="$1" base="$2" env_name="" existing=""
  env_name="$(sanitizer_options_env_name "$name")" || return 1
  existing="${!env_name-}"
  if [ -n "$existing" ]; then
    if [ -n "$base" ]; then
      printf '%s:%s' "$base" "$existing"
    else
      printf '%s' "$existing"
    fi
  else
    printf '%s' "$base"
  fi
}

# Append `suppressions=<path>` and any extra opts to a base options string.
# Reads TARGET_<NAME>_SUPPRESSIONS via target_sanitizer_suppressions_path
# and TARGET_<NAME>_OPTIONS via target_sanitizer_extra_options.
#
# Usage: san_compose_options <name> <base_opts>
#   name: asan | ubsan | msan | tsan
#   base_opts: existing colon-delimited *_OPTIONS string
sanitizer_compose_options() {
  local name="$1" base="$2"
  local sup="" extra=""
  if declare -F target_sanitizer_suppressions_path >/dev/null 2>&1; then
    sup="$(target_sanitizer_suppressions_path "$name" 2>/dev/null || true)"
    extra="$(target_sanitizer_extra_options "$name" 2>/dev/null || true)"
  fi
  local out="$base"
  if [ -n "$sup" ]; then
    if [ -f "$sup" ]; then
      [ -n "$out" ] && out="${out}:"
      out="${out}suppressions=${sup}"
    else
      echo "[sanitizer] WARNING: ${name} suppressions file not found: $sup" >&2
    fi
  fi
  if [ -n "$extra" ]; then
    [ -n "$out" ] && out="${out}:"
    out="${out}${extra}"
  fi
  printf '%s' "$out"
}

# sanitizer_generic_rss_limit_mb — echo the per-run resident-memory ceiling (MB)
# the generic runners pass to audit_timeout_run_rss, or nothing when uncapped.
#
# A single probe of a huge-allocation bug (size_t truncation, length overflow)
# can balloon RSS and thrash the host into swap until it wedges, taking every
# parallel agent down with it — a machine wedge, not a clean OOM-kill. The
# generic runners enforce this ceiling with the external RSS watchdog in
# audit_timeout_run_rss, which SIGKILLs the probe tree once its summed RSS
# crosses the cap and prints an `rss limit exceeded` diagnostic. Recall-positive:
# the bug is *caught* (host-protection class), not lost with the host, and real
# memory-safety crashes reproduce identically under the cap.
#
# Why a watchdog and not ASan's hard_rss_limit_mb: that flag's RSS-monitor
# thread is Linux-only in compiler-rt and silently inert on macOS/Apple clang
# (verified — a 1024MB cap let a process reach 15GB and exit 0). The watchdog is
# allocator-agnostic and cross-platform, so the same cap also covers ubsan (no
# allocator) and any child the probe forks. Scope is generic/CLI mode only —
# browser and xpcshell (Firefox+ASan) legitimately exceed several GB and never
# call this. PROBE_RSS_LIMIT_MB overrides the per-host ceiling (default 5120);
# set it to 0 to disable.
sanitizer_generic_rss_limit_mb() {
  local mb="${PROBE_RSS_LIMIT_MB:-5120}"
  case "$mb" in
    ''|*[!0-9]*) return 0 ;;   # non-numeric → uncapped
  esac
  [ "$mb" -gt 0 ] || return 0  # 0 → disabled
  printf '%s' "$mb"
}

# Borrowed ClusterFuzz offline symbolizer, resolved relative to this file.
_SANITIZER_SYMBOLIZER_PY="${BASH_SOURCE[0]%/*}/clusterfuzz_symbolizer.py"

# sanitizer_symbolizer_path — echo a usable llvm-symbolizer path, else empty.
# llvm-symbolizer is the preferred backend; lib/clusterfuzz_symbolizer.py falls
# back to atos/addr2line when it is absent, so an empty result is not fatal.
sanitizer_symbolizer_path() {
  local t
  t="$(audit_llvm_tool llvm-symbolizer)"
  case "$t" in
    */*) [ -x "$t" ] && { printf '%s' "$t"; return 0; } ;;
  esac
  command -v llvm-symbolizer 2>/dev/null || true
}

# sanitizer_symbolize_available — succeed (rc 0) when we can actually
# re-symbolize a symbolize=0 report: the CF symbolizer module is present AND
# some backend it can drive is reachable — llvm-symbolizer, else the platform
# tool (atos on macOS, addr2line on Linux). Callers gate symbolize=0 on this:
# only decouple symbolization when both halves exist, otherwise leave the inline
# symbolizer in charge. The module check matters because sanitizer_symbolize_file
# falls open (no-ops) if the helper is missing — without this gate, a tree that
# shipped the sanitizer.sh change but not clusterfuzz_symbolizer.py would set
# symbolize=0 and then never re-symbolize, leaking raw frames into clustering.
# The backend check is crucially true on stock macOS (Apple clang ships atos but
# no llvm-symbolizer), which is the platform whose inline atos hang motivates the
# whole fix.
sanitizer_symbolize_available() {
  [ -f "$_SANITIZER_SYMBOLIZER_PY" ] || return 1
  [ -n "$(sanitizer_symbolizer_path)" ] && return 0
  command -v atos >/dev/null 2>&1 && return 0
  command -v addr2line >/dev/null 2>&1 && return 0
  return 1
}

# sanitizer_report_has_raw_frames <file> — succeed (rc 0) when <file> holds at
# least one unsymbolized `#N 0xpc (module+0xoffset)` frame, i.e. there is
# something for the offline symbolizer to resolve. Lets the symbolize step skip
# the interpreter spin-up on clean runs and already-symbolized reports. File
# grep (no pipe → no pipefail/SIGPIPE hazard).
sanitizer_report_has_raw_frames() {
  grep -qE '^ *#[0-9]+ +0x[0-9a-f]+ +\([^)]*\+0x[0-9a-f]+\)' "$1" 2>/dev/null
}

# sanitizer_symbolize_file <file> — offline-symbolize a sanitizer report that
# was captured with symbolize=0, rewriting <file> in place.
#
# This decouples symbolization from the crashing run. On macOS the sanitizer's
# in-process symbolizer (atos) is slow and can deadlock while building a report,
# so under the run timeout the report is killed after the "ERROR:" header but
# before any frames print — leaving the crash with no state for
# bin/cluster-crashes to dedup on (it then falls back to a per-crash
# `pending:<id>` cluster). With symbolize=0 the crashing process emits raw
# `#N 0xpc (module+0xoffset)` frames immediately; we resolve them here, with the
# process already dead. See lib/clusterfuzz_symbolizer.py.
#
# Best-effort and falls open: on any failure or a >60s overrun, <file> is left
# untouched so the raw (still ASLR-stable) frames survive. The module picks
# llvm-symbolizer or atos/addr2line itself, so the llvm path here may be empty.
# Never returns non-zero.
sanitizer_symbolize_file() {
  local f="$1" tmp
  [ -s "$f" ] || return 0
  [ -f "$_SANITIZER_SYMBOLIZER_PY" ] || return 0
  # Skip the interpreter spin-up unless there is a raw frame to resolve, so
  # clean runs and already-symbolized reports are a true no-op.
  sanitizer_report_has_raw_frames "$f" || return 0
  tmp="$(mktemp "${TMPDIR:-/tmp}/sanitizer-symbolize-XXXXXX")" || return 0
  # Pick the offline backend. On macOS prefer atos: it resolves frames straight
  # from the Mach-O debug map (the .o DWARF a CMake/-g1 build leaves behind) and
  # from a .dSYM if one exists, so it needs no .dSYM and cannot be defeated by a
  # .dSYM going stale after a relink. llvm-symbolizer follows neither a debug map
  # nor a UUID-mismatched .dSYM, so reserve it for hosts without atos and for
  # Linux (where -g1 DWARF lives in the ELF). Use --no-llvm-symbolizer, NOT an
  # empty --llvm-symbolizer: the latter still falls through to a PATH
  # llvm-symbolizer and never reaches atos.
  local sym_args
  if audit_is_darwin && command -v atos >/dev/null 2>&1; then
    sym_args=(--no-llvm-symbolizer)
  else
    sym_args=(--llvm-symbolizer "$(sanitizer_symbolizer_path)")
  fi
  if audit_timeout_run 60 python3 "$_SANITIZER_SYMBOLIZER_PY" \
       "${sym_args[@]}" <"$f" >"$tmp" 2>/dev/null \
       && [ -s "$tmp" ]; then
    cat "$tmp" >"$f"
  fi
  rm -f "$tmp"
  return 0
}

# Path to the sanitizer option-string source of truth, resolved relative
# to this file so it works regardless of the caller's CWD.
_SANITIZER_OPTIONS_CONF="${BASH_SOURCE[0]%/*}/sanitizer_options.conf"

# sanitizer_options_for <sanitizer> <mode>
#   Echo the canonical *_OPTIONS string for a sanitizer/mode pair, read from
#   lib/sanitizer_options.conf (the single source of truth, also parsed by
#   bin/export-repro). A mode with no explicit row falls back to that
#   sanitizer's `full` row. This is what lets bin/run-{asan,ubsan,msan,tsan}
#   declare their ASAN_OPTS_* / UBSAN_OPTS_* / … without re-hardcoding the
#   option strings in four places.
sanitizer_options_for() {
  local san="$1" mode="$2" f_san f_mode f_opts full=""
  if [ ! -f "$_SANITIZER_OPTIONS_CONF" ]; then
    echo "[sanitizer] FATAL: option table missing: $_SANITIZER_OPTIONS_CONF" >&2
    return 1
  fi
  while read -r f_san f_mode f_opts; do
    case "$f_san" in ''|'#'*) continue ;; esac
    [ "$f_san" = "$san" ] || continue
    if [ "$f_mode" = "$mode" ]; then
      printf '%s' "$f_opts"
      return 0
    fi
    [ "$f_mode" = "full" ] && full="$f_opts"
  done < "$_SANITIZER_OPTIONS_CONF"
  printf '%s' "$full"
}

# ─── Shared runner helpers ────────────────────────────────────────
# These four helpers were previously duplicated verbatim across
# bin/run-{asan,ubsan,msan,tsan} (about 100 lines of byte-identical
# code). Centralizing them removes the drift risk where a fix to one
# runner's helper silently goes missing in the others. Naming is kept
# unchanged (`_fuzz_timeout`, `_validate_fuzzer_name`, ...) so the
# runner call sites and any operator muscle memory continue to work.
# Requires lib/timeout.sh to be sourced before this file
# (audit_timeout_kill).

# libFuzzer installs a SIGTERM handler that runs an atexit chain which
# panics during TLS teardown on some platforms. SIGKILL bypasses it,
# guaranteeing a clean kill at the timeout boundary.
_fuzz_timeout() {
    local secs="$1"; shift
    audit_timeout_kill "$secs" "$@"
}

# libFuzzer writes crash-*, oom-*, timeout-* artifacts to CWD. All
# fuzz modes must cd into a per-FUZZER subdir so nothing lands at repo
# root. Caller can override via FUZZ_CRASH_DIR.
_fuzz_default_crash_dir() {
    local audit_results
    audit_results="${RESULTS_DIR:-results}"
    echo "${audit_results}/fuzz-crashes/${FUZZER}"
}

# Reject FUZZER values that could interpolate as a shell metacharacter.
# Strict identifier shape — the variable is used as a path component
# and CLI argument; anything outside [A-Za-z0-9_] gets blocked.
_validate_fuzzer_name() {
    if [[ "${FUZZER:-}" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]]; then
        return 0
    fi
    echo "Error: FUZZER must match ^[A-Za-z_][A-Za-z0-9_]*$ (got '${FUZZER:-}')" >&2
    return 2
}

# Strip Firefox console noise from a captured browser run and print the
# filtered content to stdout (caller decides whether to redirect to a
# file or display). Called by browser-mode runners after the inferior
# exits. Self-contained (only depends on python3 being on PATH).
filter_browser_output() {
    python3 - "$1" <<'PY'
import re
import sys

patterns = [
    re.compile(r"^Nightly GPU Helper\["),
    re.compile(r"^UNSUPPORTED \(log once\): POSSIBLE ISSUE: unit 1 GLD_TEXTURE_INDEX_2D"),
    re.compile(r'^console\.debug: "Registering new SmartBlock shim content scripts"'),
    re.compile(r'^console\.debug: "Registering new webcompat intervention content scripts"'),
    re.compile(r'^console\.debug: "Registering redirect listener for requestStorageAccess helper"'),
    re.compile(r'^console\.debug: "Allowing access to these logos:"'),
    re.compile(r'^console\.debug: "Shimming these"'),
    re.compile(r'^console\.debug: "Enabled" [0-9]+ "webcompat'),
    re.compile(r'^console\.debug: "Skipped" [0-9]+ "un-needed webcompat interventions"'),
    re.compile(r'^Exiting due to channel error\.$'),
]

with open(sys.argv[1], "r", errors="replace") as f:
    for line in f:
        if any(p.search(line) for p in patterns):
            continue
        sys.stdout.write(line)
PY
}

# Print a one-line warning if `name` is being invoked for a target that
# did not list it under [sanitizer].enabled in target.toml. Never aborts
# — keeps manual/repro workflows uninterrupted.
sanitizer_warn_if_disabled() {
  local name="$1"
  # Skip the check entirely when target.toml isn't loaded (no slug
  # discovered) — runners can still be invoked from contexts that don't
  # carry an output/<slug>/ tree (eg. fresh Firefox checkouts). Use
  # ${TARGET_SANITIZERS_ENABLED+_set} so a missing array under `set -u`
  # falls through silently instead of aborting the runner.
  if [ -z "${TARGET_SANITIZERS_ENABLED+set}" ] \
     || [ "${#TARGET_SANITIZERS_ENABLED[@]}" -eq 0 ]; then
    return 0
  fi
  if declare -F target_sanitizer_is_enabled >/dev/null 2>&1; then
    if ! target_sanitizer_is_enabled "$name"; then
      echo "[sanitizer] NOTE: '${name}' is not in [sanitizer].enabled in target.toml — running anyway. Add '${name}' to enable it for the audit harness." >&2
    fi
  fi
}
