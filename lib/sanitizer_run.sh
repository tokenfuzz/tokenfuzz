#!/usr/bin/env bash
# lib/sanitizer_run.sh — shared mode-dispatch helpers for the standalone
# (non-browser) sanitizer runners.
#
# bin/run-msan and bin/run-tsan are thin shims over these helpers; bin/run-ubsan
# delegates its non-browser modes (generic, js) here too. bin/run-asan keeps its
# own richer generic/js implementations — findings-only [runner].bin resolution,
# ASAN_GENERIC_SKIP_TESTCASE handling, shell-flag/script-arg splitting — and is
# intentionally NOT routed through this file; its modes are not byte-equivalent.
#
# Each helper is parameterised by the lowercase sanitizer name (`msan`, `tsan`,
# `ubsan`). From that name it derives the runtime-option env var
# (`MSAN_OPTIONS`, …), the instrumented-binary env vars (`MSAN_GENERIC_BIN`,
# `TARGET_MSAN_BIN`, `MSAN_JS`) and the build dir, so a runner never repeats the
# dispatch body. Sanitizer-standard option strings and per-mode timeouts stay in
# the calling runner (they are sanitizer-specific, not target-specific).
#
# Helpers return the child's exit code; callers `exit` with it. fuzz / fuzz-js
# return 0 after reporting artifacts, matching the legacy collect-and-continue
# behaviour.
#
# Prerequisites — the caller must already have sourced:
#   lib/timeout.sh         (audit_timeout_run)
#   lib/target_config.sh   (target_resolve_path)
#   lib/sanitizer.sh       (sanitizer_build_dir, sanitizer_runtime_options,
#                           _fuzz_timeout, _fuzz_default_crash_dir,
#                           _validate_fuzzer_name)

# _sanitizer_run_upper <name> — uppercase a sanitizer name for env-var derivation.
_sanitizer_run_upper() {
  printf '%s' "$1" | tr '[:lower:]' '[:upper:]'
}

# _sanitizer_run_resolve_bin <SAN> — echo the instrumented binary path.
# Precedence: <SAN>_GENERIC_BIN env override, else TARGET_<SAN>_BIN from
# target.toml resolved against the target tree. Echoes empty when neither set.
_sanitizer_run_resolve_bin() {
  local SAN="$1"
  local binvar="${SAN}_GENERIC_BIN"
  local tgtvar="TARGET_${SAN}_BIN"
  local bin="${!binvar:-}"
  if [ -z "$bin" ] && [ -n "${!tgtvar:-}" ]; then
    bin="$(target_resolve_path "${!tgtvar}")"
  fi
  printf '%s' "$bin"
}

# sanitizer_run_generic <san> <opts> <timeout> <testcase> [target args...]
#   Runs a generic CLI / probe-built HARNESS binary under the sanitizer.
sanitizer_run_generic() {
  local san="$1" opts="$2" timeout_val="$3"
  shift 3
  if [ "$#" -lt 1 ]; then
    echo "Usage: $0 generic <testcase> [target args...]" >&2
    return 1
  fi
  local SAN bin generic_testcase rc=0
  SAN="$(_sanitizer_run_upper "$san")"
  bin="$(_sanitizer_run_resolve_bin "$SAN")"
  if [ -z "$bin" ] || [ ! -x "$bin" ]; then
    echo "[run-$san] generic runner missing or unset: ${bin:-<unset>}" >&2
    echo "[run-$san] set [sanitizer].${san}_bin in output/<slug>/target.toml, or pass ${SAN}_GENERIC_BIN=" >&2
    return 2
  fi
  generic_testcase="$1"; shift
  audit_timeout_run "$timeout_val" env \
    "${SAN}_OPTIONS=$(sanitizer_runtime_options "$san" "$opts")" \
    "$bin" "$generic_testcase" "$@" || rc=$?
  if [ "$rc" -eq 124 ]; then
    echo "[run-$san] generic runner timed out after ${timeout_val}s" >&2
    return "$rc"
  fi
  if [ "$rc" -eq 0 ]; then
    echo "[run-$san] generic EXECUTION VERIFIED (post-run, rc=0)" >&2
  else
    echo "[run-$san] generic EXECUTION INCONCLUSIVE (post-run, rc=${rc})" >&2
  fi
  return "$rc"
}

# sanitizer_run_js <san> <opts> <timeout> [js args...]
#   Runs the standalone JS shell (dist/bin/js). Honours <SAN>_JS as an override.
sanitizer_run_js() {
  local san="$1" opts="$2" timeout_val="$3"
  shift 3
  local SAN jsvar js_bin rc=0
  SAN="$(_sanitizer_run_upper "$san")"
  jsvar="${SAN}_JS"
  js_bin="${!jsvar:-$(sanitizer_build_dir "$san")/dist/bin/js}"
  audit_timeout_run "$timeout_val" env "${SAN}_OPTIONS=$opts" "$js_bin" "$@" || rc=$?
  if [ "$rc" -eq 124 ]; then
    echo "[run-$san] JS shell timed out after ${timeout_val}s" >&2
  elif [ "$rc" -eq 0 ]; then
    # Post-run execution evidence (mirrors sanitizer_run_generic). Without
    # this, run-sanitizer-multi cannot count a clean js run and reports a
    # false EXECUTION_RATE: 0/N for msan/tsan/ubsan js-mode testcases.
    echo "[run-$san] js EXECUTION VERIFIED (post-run, rc=0)" >&2
  fi
  return "$rc"
}

# sanitizer_run_fuzz <san> <opts> <timeout> [fuzzer args...]
#   Runs a standalone libFuzzer harness over a corpus. Requires FUZZER set.
sanitizer_run_fuzz() {
  local san="$1" opts="$2" timeout_val="$3"
  shift 3
  local SAN bin crash_dir rc=0
  SAN="$(_sanitizer_run_upper "$san")"
  if [ -z "${FUZZER:-}" ]; then
    echo "Error: FUZZER env var must be set. Example: FUZZER=Foo $0 fuzz /tmp/corpus" >&2
    return 1
  fi
  _validate_fuzzer_name || return $?
  bin="$(_sanitizer_run_resolve_bin "$SAN")"
  if [ -z "$bin" ] || [ ! -x "$bin" ]; then
    echo "[run-$san] fuzz target missing: ${bin:-<unset>}" >&2
    echo "[run-$san] set [sanitizer].${san}_bin to a libFuzzer harness, or pass ${SAN}_GENERIC_BIN=" >&2
    return 2
  fi
  local fuzz_args=() arg
  for arg in "$@"; do
    [[ "$arg" =~ ^-fork= ]] || fuzz_args+=("$arg")
  done
  crash_dir="${FUZZ_CRASH_DIR:-$(_fuzz_default_crash_dir)}"
  mkdir -p "$crash_dir"
  ( cd "$crash_dir" && \
    _fuzz_timeout "$timeout_val" env \
      FUZZER="$FUZZER" \
      "${SAN}_OPTIONS=$opts" \
      "$bin" ${fuzz_args[@]+"${fuzz_args[@]}"} \
  ) || {
    rc=$?
    if [ "$rc" -eq 124 ] || [ "$rc" -eq 137 ]; then
      echo "[run-$san] Fuzz target killed after ${timeout_val}s" >&2
    fi
  }
  echo "[run-$san] Fuzz artifacts (if any): $crash_dir" >&2
  return 0
}

# sanitizer_run_fuzz_repro <san> <opts> <timeout> <crash-file> [args...]
#   Re-runs one libFuzzer crash file with halt_on_error=1 for a clean diagnostic.
sanitizer_run_fuzz_repro() {
  local san="$1" opts="$2" timeout_val="$3"
  shift 3
  if [ "$#" -lt 1 ]; then
    echo "Error: provide a crash file to reproduce." >&2
    return 1
  fi
  local SAN bin rc=0
  SAN="$(_sanitizer_run_upper "$san")"
  bin="$(_sanitizer_run_resolve_bin "$SAN")"
  if [ -z "$bin" ] || [ ! -x "$bin" ]; then
    echo "[run-$san] fuzz-repro target missing: ${bin:-<unset>}" >&2
    return 2
  fi
  # Resolve testcase paths to absolute before libFuzzer reads them.
  local repro_args=() arg
  for arg in "$@"; do
    if [[ "$arg" != -* && -f "$arg" ]]; then
      repro_args+=("$(cd "$(dirname "$arg")" && pwd)/$(basename "$arg")")
    else
      repro_args+=("$arg")
    fi
  done
  _fuzz_timeout "$timeout_val" env \
    "${SAN}_OPTIONS=$opts" \
    "$bin" "${repro_args[@]}" || rc=$?
  if [ "$rc" -eq 124 ] || [ "$rc" -eq 137 ]; then
    echo "[run-$san] Fuzz repro killed after ${timeout_val}s" >&2
  fi
  return "$rc"
}

# sanitizer_run_fuzz_js <san> <opts> <timeout> [fuzzer args...]
#   Runs the standalone SpiderMonkey fuzz-tests binary. Requires FUZZER set.
sanitizer_run_fuzz_js() {
  local san="$1" opts="$2" timeout_val="$3"
  shift 3
  local SAN fuzz_tests crash_dir rc=0
  SAN="$(_sanitizer_run_upper "$san")"
  fuzz_tests="$(sanitizer_build_dir "$san")/dist/bin/fuzz-tests"
  if [ ! -x "$fuzz_tests" ]; then
    echo "Error: fuzz-tests binary not found at $fuzz_tests. Run ff-bsan $san first." >&2
    return 1
  fi
  if [ -z "${FUZZER:-}" ]; then
    echo "Error: FUZZER env var must be set." >&2
    return 1
  fi
  _validate_fuzzer_name || return $?
  local fuzz_args=() arg
  for arg in "$@"; do
    [[ "$arg" =~ ^-fork= ]] || fuzz_args+=("$arg")
  done
  crash_dir="${FUZZ_CRASH_DIR:-$(_fuzz_default_crash_dir)}"
  mkdir -p "$crash_dir"
  ( cd "$crash_dir" && \
    audit_timeout_run "$timeout_val" env \
      FUZZER="$FUZZER" \
      "${SAN}_OPTIONS=$opts" \
      "$fuzz_tests" ${fuzz_args[@]+"${fuzz_args[@]}"} \
  ) || {
    rc=$?
    if [ "$rc" -eq 124 ]; then
      echo "[run-$san] Fuzz target timed out after ${timeout_val}s" >&2
    fi
  }
  echo "[run-$san] Fuzz artifacts (if any): $crash_dir" >&2
  return 0
}
