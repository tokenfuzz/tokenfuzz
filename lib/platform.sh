#!/usr/bin/env bash
# Small cross-platform helpers for audit shell scripts.
#
# Keep this file dependency-light: bin/* wrappers run on macOS developer
# machines and Linux CI/container hosts.

# Timestamped log helper for lib code. Uses bin/audit's log() when present so
# all sourced libs share one prefix format; falls back to a self-contained
# timestamp when libs are exercised in isolation (tests / direct sourcing).
# Output goes to stdout — callers pipe to INDEX via tee where appropriate.
audit_log() {
  if declare -F log >/dev/null 2>&1; then
    log "$@"
  else
    printf '[%s] %s\n' "$(date +%H:%M:%S)" "$*"
  fi
}

# audit_log_throttled <key> <msg> [throttle_secs]
#
# Emits <msg> at most once per <throttle_secs> per <key>. Used for chatty
# WARN lines whose underlying state persists across many iterations (e.g.
# "crashes/CRASH-001-1 incomplete"); without throttling these flood the
# index log every loop and bury the events that actually changed.
#
# Throttle state lives under LOGDIR/.warns/. The message text is hashed
# into the stamp so a *changed* message for the same key always emits.
# Default window: AUDIT_WARN_THROTTLE_SECS (1800s / 30 min).
audit_log_throttled() {
  local key="$1" msg="$2" window="${3:-${AUDIT_WARN_THROTTLE_SECS:-1800}}"
  [ -n "$key" ] && [ -n "$msg" ] || { audit_log "$msg"; return; }
  local logdir="${LOGDIR:-}"
  if [ -z "$logdir" ] || [ ! -d "$logdir" ]; then
    audit_log "$msg"
    return
  fi
  local stamp_dir="$logdir/.warns"
  mkdir -p "$stamp_dir" 2>/dev/null || { audit_log "$msg"; return; }
  local safe_key
  safe_key=$(printf '%s' "$key" | tr -cs '[:alnum:]._-' '-')
  local stamp="$stamp_dir/$safe_key"
  local msg_sig
  msg_sig=$(printf '%s' "$msg" | audit_sha1 2>/dev/null | awk '{print $1}')
  if [ -s "$stamp" ]; then
    local prev_ts prev_sig now
    prev_ts=$(sed -n '1p' "$stamp" 2>/dev/null)
    prev_sig=$(sed -n '2p' "$stamp" 2>/dev/null)
    now=$(date +%s 2>/dev/null || echo 0)
    case "$prev_ts" in ''|*[!0-9]*) prev_ts=0 ;; esac
    case "$window" in ''|*[!0-9]*) window=1800 ;; esac
    if [ "$prev_sig" = "$msg_sig" ] && [ $((now - prev_ts)) -lt "$window" ]; then
      return 0
    fi
  fi
  { date +%s; printf '%s\n' "${msg_sig:-?}"; } > "$stamp" 2>/dev/null || true
  audit_log "$msg"
}

audit_os() {
  uname -s 2>/dev/null || echo unknown
}

audit_is_darwin() {
  [ "$(audit_os)" = "Darwin" ]
}

audit_is_linux() {
  [ "$(audit_os)" = "Linux" ]
}

# audit_make_dsyms <build-dir>
# macOS only, best-effort: give every Mach-O shared library / executable under
# <build-dir> a self-contained .dSYM bundle.
#
# Why this exists: a CMake/-g1 build links a dylib whose DWARF lives only in the
# .o object files, reachable through a Mach-O *debug map*; the linked dylib
# carries no embedded DWARF and no .dSYM. atos follows the debug map, but
# llvm-symbolizer does NOT — it reads DWARF only from the binary itself or a
# .dSYM. The audit's offline symbolizer (lib/clusterfuzz_symbolizer.py) prefers
# llvm-symbolizer and treats a function-only result as final, so without a .dSYM
# library crash frames lose file:line and render as `func (module)`. dsymutil
# bakes the debug map's DWARF into a sibling .dSYM that both backends consume,
# making symbolization backend- and timing-independent. Recipes that compile
# and link source files in a single clang invocation can still produce an
# unrepairable debug map pointing at deleted temporary objects; build recipes
# should compile to durable object files under the build directory first. No-op
# on Linux, where -g1 DWARF is embedded directly in the ELF .so.
_audit_dsym_dwarf_file() {
  local f="${1:-}"
  [ -n "$f" ] || return 1
  printf '%s.dSYM/Contents/Resources/DWARF/%s\n' "$f" "$(basename "$f")"
}

_audit_dsym_has_line_tables() {
  local f="${1:-}" dwarf
  dwarf="$(_audit_dsym_dwarf_file "$f")" || return 1
  [ -f "$dwarf" ] || return 1
  command -v dwarfdump >/dev/null 2>&1 || return 0
  dwarfdump --debug-line "$dwarf" 2>/dev/null | awk '
    /^Address[[:space:]]+Line[[:space:]]+Column/ { found = 1 }
    END { exit found ? 0 : 1 }
  '
}

_audit_macho_has_debug_map_objects() {
  local f="${1:-}" n
  [ -n "$f" ] && command -v nm >/dev/null 2>&1 || return 1
  n="$(nm -ap "$f" 2>/dev/null | awk '$5 == "OSO" { n++ } END { print n + 0 }')"
  [ "${n:-0}" -gt 0 ]
}

_audit_warn_incomplete_dsym() {
  local f="${1:-}" log="${2:-}" reason=""
  [ -n "$f" ] || return 0
  if [ -n "$log" ] && [ -s "$log" ]; then
    reason="$(awk '
      /unable to open object file|could not find object file/ { print; exit }
    ' "$log" 2>/dev/null || true)"
  fi
  if [ -z "$reason" ] &&
     _audit_macho_has_debug_map_objects "$f" &&
     ! _audit_dsym_has_line_tables "$f"; then
    reason="generated dSYM has no debug line table"
  fi
  [ -n "$reason" ] || return 0
  printf '%s\n' "[audit_make_dsyms] WARN: incomplete dSYM for $f: $reason" >&2
  printf '%s\n' "[audit_make_dsyms] WARN: sanitizer stacks for this binary may be function-only; compile sources to durable .o files under the build directory before linking." >&2
}

audit_make_dsyms() {
  audit_is_darwin || return 0
  local build="${1:-}"
  [ -n "$build" ] && [ -d "$build" ] || return 0
  command -v dsymutil >/dev/null 2>&1 || return 0

  local f ftype log
  while IFS= read -r -d '' f; do
    # Incremental rebuilds: keep a .dSYM that is at least as new as its binary.
    if [ -e "${f}.dSYM" ] && [ ! "$f" -nt "${f}.dSYM" ]; then
      _audit_warn_incomplete_dsym "$f" ""
      continue
    fi
    case "$f" in
      *.dylib|*.so|*.so.*) : ;;          # shared library — always a candidate
      *)
        # Executable found via the +x sweep: only real Mach-O, never scripts.
        ftype="$(file -b "$f" 2>/dev/null || true)"
        case "$ftype" in *Mach-O*) : ;; *) continue ;; esac
        ;;
    esac
    # Best-effort: a binary with no usable debug map just warns; never fatal.
    log="$(mktemp "${TMPDIR:-/tmp}/audit-dsymutil-XXXXXX")" || log=""
    if [ -n "$log" ]; then
      dsymutil "$f" -o "${f}.dSYM" >"$log" 2>&1 || true
      _audit_warn_incomplete_dsym "$f" "$log"
      rm -f "$log"
    else
      dsymutil "$f" -o "${f}.dSYM" >/dev/null 2>&1 || true
      _audit_warn_incomplete_dsym "$f" ""
    fi
  done < <(find "$build" -type f \( \
             -name '*.dylib' -o -name '*.so' -o -name '*.so.*' -o -perm -u+x \
           \) ! -path '*/CMakeFiles/*' ! -path '*.dSYM/*' -print0 2>/dev/null)
}

# audit_make_dsyms_for_target <target-root>
# Apply audit_make_dsyms to every sanitizer build tree under <target-root> —
# the build-<san> dirs (build-asan, build-ubsan, build-msan, build-tsan, and any
# AUDIT_BUILD_SUFFIX variants) that setup-target materializes. Lets the audit /
# benchmark fresh-build paths repair all enabled sanitizers' .dSYMs without
# hardcoding a sanitizer or duplicating the build-dir glob. The build-<san>
# layout is a harness-wide convention, not target-specific. Idempotent;
# macOS-only no-op.
audit_make_dsyms_for_target() {
  audit_is_darwin || return 0
  local root="${1:-}" d
  [ -n "$root" ] && [ -d "$root" ] || return 0
  for d in "$root"/build-*; do
    [ -d "$d" ] && audit_make_dsyms "$d"
  done
}

audit_stat_mtime_epoch() {
  # Portable mtime in epoch seconds. Returns 0 on any failure so the
  # caller can do arithmetic / numeric comparison unconditionally.
  #
  # Why the numeric guard: on GNU stat (Linux), `-f` does NOT mean
  # "format string" — it prints filesystem status (multi-line junk).
  # Callers used to feed that junk into `[ -gt ]` and trip "integer
  # expression expected". We validate numeric output before returning.
  local path="$1" m=""
  if audit_is_darwin; then
    m=$(stat -f '%m' "$path" 2>/dev/null || true)
  else
    m=$(stat -c '%Y' "$path" 2>/dev/null || true)
  fi
  case "$m" in
    ''|*[!0-9]*) printf '0' ;;
    *) printf '%s' "$m" ;;
  esac
}

audit_stat_size() {
  local path="$1" s=""
  if audit_is_darwin; then
    s=$(stat -f '%z' "$path" 2>/dev/null || true)
  else
    s=$(stat -c '%s' "$path" 2>/dev/null || true)
  fi
  case "$s" in
    ''|*[!0-9]*) printf '0' ;;
    *) printf '%s' "$s" ;;
  esac
}

audit_stat_key() {
  local path="$1" m s
  m="$(audit_stat_mtime_epoch "$path" 2>/dev/null || true)"
  s="$(audit_stat_size "$path" 2>/dev/null || true)"
  [ -n "$m" ] && [ -n "$s" ] || return 1
  printf '%s:%s\n' "$m" "$s"
}

audit_realpath() {
  local path="$1"
  python3 - "$path" <<'PY' 2>/dev/null && return 0
import os
import sys

print(os.path.realpath(sys.argv[1]))
PY

  # Fallback for very early bootstrap shells where python3 is absent.
  # Unlike GNU readlink, pwd -P is available on both macOS and Linux.
  if [ -d "$path" ]; then
    (cd "$path" 2>/dev/null && pwd -P) && return 0
  else
    local dir base
    dir=$(dirname "$path" 2>/dev/null) || dir=.
    base=$(basename "$path" 2>/dev/null) || base="$path"
    if [ -d "$dir" ]; then
      (cd "$dir" 2>/dev/null && printf '%s/%s\n' "$(pwd -P)" "$base") && return 0
    fi
  fi
  printf '%s\n' "$path"
}

audit_mtime_utc() {
  local path="$1" fmt="${2:-%Y-%m-%dT%H:%M:%SZ}"
  python3 - "$path" "$fmt" <<'PY'
import datetime
import os
import sys

path, fmt = sys.argv[1], sys.argv[2]
try:
    ts = os.path.getmtime(path)
except OSError:
    sys.exit(1)
print(datetime.datetime.fromtimestamp(ts, datetime.timezone.utc).strftime(fmt))
PY
}

audit_format_epoch_local() {
  local epoch="$1" fmt="${2:-%H:%M:%S %Z}"
  python3 - "$epoch" "$fmt" <<'PY'
import datetime
import sys

epoch, fmt = sys.argv[1], sys.argv[2]
try:
    ts = int(epoch)
except ValueError:
    sys.exit(1)
if ts < 0:
    sys.exit(1)
print(datetime.datetime.fromtimestamp(ts).strftime(fmt))
PY
}

audit_hash() {
  local algo="$1"
  shift
  python3 -c '
import hashlib
import sys

algo = sys.argv[1]
paths = sys.argv[2:]
try:
    factory = getattr(hashlib, algo)
except AttributeError:
    sys.exit(2)

def digest_file(path):
    h = factory()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

if paths:
    for path in paths:
        print(f"{digest_file(path)}  {path}")
else:
    h = factory()
    for chunk in iter(lambda: sys.stdin.buffer.read(1024 * 1024), b""):
        h.update(chunk)
    print(h.hexdigest())
' "$algo" "$@" 2>/dev/null && return 0
  case "$algo" in
    sha1)
      if command -v shasum >/dev/null 2>&1; then
        shasum -a 1 "$@"
      elif command -v sha1sum >/dev/null 2>&1; then
        sha1sum "$@"
      else
        cksum "$@"
      fi
      ;;
    sha256)
      if command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$@"
      elif command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$@"
      else
        audit_hash sha1 "$@"
      fi
      ;;
    *)
      return 2
      ;;
  esac
}

audit_sha1() {
  audit_hash sha1 "$@"
}

audit_sha256() {
  audit_hash sha256 "$@"
}

audit_cpu_count() {
  local n=""
  n=$(getconf _NPROCESSORS_ONLN 2>/dev/null || true)
  if [ -z "$n" ] && command -v sysctl >/dev/null 2>&1; then
    n=$(sysctl -n hw.ncpu 2>/dev/null || true)
  fi
  case "$n" in ''|*[!0-9]*) n=1 ;; esac
  [ "$n" -lt 1 ] && n=1
  printf '%s\n' "$n"
}

audit_sed_in_place() {
  if audit_is_darwin; then
    sed -i '' "$@"
  else
    sed -i "$@"
  fi
}

audit_llvm_tool() {
  local tool="$1"
  if [ -n "${LLVM_PREFIX:-}" ] && [ -x "${LLVM_PREFIX}/bin/${tool}" ]; then
    printf '%s\n' "${LLVM_PREFIX}/bin/${tool}"
    return
  fi
  for prefix in /opt/homebrew/opt/llvm /usr/local/opt/llvm /usr/lib/llvm-* /usr/local; do
    if [ -x "${prefix}/bin/${tool}" ]; then
      printf '%s\n' "${prefix}/bin/${tool}"
      return
    fi
  done
  if command -v "$tool" >/dev/null 2>&1; then
    command -v "$tool"
    return
  fi
  printf '%s\n' "$tool"
}

# pool_run POOL WORKER ITEM...
#
# Run WORKER once per ITEM through a bounded FIFO sliding-window fork pool —
# the scheduling idiom that replaced all-jobs batch barriers for a 10-60x
# housekeeping speedup. Keep POOL workers in flight at once; when the window is
# full, block on the OLDEST worker (a specific pid — bash 3.2 has no `wait -n`)
# and launch the next immediately, so the batch never idles on its slowest
# member. Workers are independent (each writes its own sidecar/output), so
# window ordering changes scheduling only, never results.
#
# WORKER is a function name; it is invoked as `WORKER ITEM INDEX` (INDEX is
# 1-based across all items) and runs in a subshell that still sees the caller's
# dynamically-scoped locals (e.g. bin_dir, outcome_dir). Falls back to in-line
# serial execution when POOL<=1 or there is a single item.
#
# The final drain waits ONLY on this pool's own worker pids — never a bare
# `wait`, which would also reap unrelated long-lived siblings of the calling
# shell (e.g. the benchmark console `tee`) and deadlock the caller.
pool_run() {
  local _pool="$1" _worker="$2"
  shift 2
  local _i=0 _it
  if [ "$_pool" -le 1 ] || [ "$#" -le 1 ]; then
    for _it in ${1+"$@"}; do
      _i=$((_i + 1))
      "$_worker" "$_it" "$_i"
    done
    return 0
  fi
  local -a _pp=()
  for _it in "$@"; do
    _i=$((_i + 1))
    ( "$_worker" "$_it" "$_i" ) &
    _pp+=("$!")
    if [ "${#_pp[@]}" -ge "$_pool" ]; then
      wait "${_pp[0]}" 2>/dev/null || true
      _pp=("${_pp[@]:1}")
    fi
  done
  [ "${#_pp[@]}" -gt 0 ] && { wait "${_pp[@]}" 2>/dev/null || true; }
  return 0
}
