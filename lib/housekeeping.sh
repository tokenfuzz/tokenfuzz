#!/usr/bin/env bash
# lib/housekeeping.sh — dirty-check helpers for audit loop housekeeping.
#
# Expensive post-iteration tasks should run when their inputs change, not just
# because another agent iteration finished. These helpers store a per-task input
# signature under RESULTS_DIR and rerun unchanged tasks periodically so transient
# LLM/network-dependent gates still get another chance.

_housekeeping_cache_dir() {
  local d="${HOUSEKEEPING_CACHE_DIR:-${RESULTS_DIR:-}/.housekeeping-cache}"
  [ -n "$d" ] || return 1
  mkdir -p "$d" 2>/dev/null || return 1
  printf '%s\n' "$d"
}

_housekeeping_slug() {
  printf '%s' "$1" | tr -cs '[:alnum:]._-' '-'
}

_housekeeping_sha1_file() {
  local f="$1" out
  if declare -F audit_sha1 >/dev/null 2>&1; then
    # audit_sha1 prints "<hex>  <path>"; strip the path in bash instead of
    # forking awk (the hash never contains a space). Runs ~7x/iteration via
    # housekeeping_signature, so the saved fork compounds. Byte-identical:
    # command substitution strips the trailing newline either way, and a
    # failed audit_sha1 yields an empty string here exactly as the awk did.
    out=$(audit_sha1 "$f" 2>/dev/null) || true
    printf '%s' "${out%% *}"
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 1 "$f" 2>/dev/null | awk '{print $1}'
  elif command -v sha1sum >/dev/null 2>&1; then
    sha1sum "$f" 2>/dev/null | awk '{print $1}'
  else
    cksum "$f" 2>/dev/null | awk '{print $1 "-" $2}'
  fi
}

housekeeping_stamp_path() {
  local label="$1" d
  d=$(_housekeeping_cache_dir) || return 1
  printf '%s/%s.sig\n' "$d" "$(_housekeeping_slug "$label")"
}

housekeeping_signature() {
  local label="$1"; shift || true
  local tmp
  tmp=$(mktemp "${TMPDIR:-/tmp}/housekeeping-sig-XXXXXXXX") || return 1

  {
    printf 'schema=3\n'
    printf 'label=%s\n' "$label"
    printf 'target_slug=%s\n' "${TARGET_SLUG:-}"
    printf 'is_browser=%s\n' "${IS_BROWSER_TARGET:-}"
    printf 'attacker_controls=%s\n' "${TARGET_ATTACKER_CONTROLS_CSV:-}"
    printf 'crash_confirm_auto=%s\n' "${CRASH_CONFIRM_AUTO:-1}"
    printf 'find_reject_needs_review=%s\n' "${FIND_REJECT_NEEDS_REVIEW:-1}"
    printf 'crash_reject_needs_review=%s\n' "${CRASH_REJECT_NEEDS_REVIEW:-1}"
    printf 'reachability_auto=%s\n' "${REACHABILITY_AUTO:-1}"
    printf 'llm_decide_disable=%s\n' "${LLM_DECIDE_DISABLE:-}"
    printf 'reachability_cache_dir=%s\n' "${REACHABILITY_CACHE_DIR:-}"
    if declare -f current_target_source_signature >/dev/null 2>&1; then
      case "$label" in
        patch-review|work-cards-refresh)
          printf 'target_source_signature_begin\n'
          current_target_source_signature 2>/dev/null || true
          printf 'target_source_signature_end\n'
          ;;
      esac
    fi
  } > "$tmp"

  python3 - "$@" >> "$tmp" <<'PY' || { rm -f "$tmp"; return 1; }
import os
import stat
import sys

# Metadata-only dirty-check: record (mode, size, mtime_ns) per file, never file
# contents. All inputs are harness-written artifact dirs (crashes/, findings/,
# coverage/, corpus/, target.toml, patch files); the harness only ever creates,
# appends to, or replaces them, and every such write bumps mtime, so size+mtime
# already detects any change. Content-hashing added no signal here and made a
# sparse repro (e.g. a file-size testcase, 1 TiB logical but a few KiB on disk)
# cost minutes of CPU per pass. Target *source* identity, where content matters
# and mtime is unreliable, is captured separately via VCS rev (see audit).

def emit(path):
    try:
        st = os.lstat(path)
    except OSError as exc:
        print(f"MISSING\t{path}\t{type(exc).__name__}")
        return
    mode = st.st_mode
    mtime_ns = getattr(st, "st_mtime_ns", int(st.st_mtime * 1_000_000_000))
    if stat.S_ISDIR(mode):
        print(f"D\t{path}\t{mode:o}\t{mtime_ns}")
        for dirpath, dirnames, filenames in os.walk(path, followlinks=False):
            dirnames.sort()
            filenames.sort()
            for name in dirnames:
                child = os.path.join(dirpath, name)
                try:
                    cst = os.lstat(child)
                    cmtime = getattr(cst, "st_mtime_ns", int(cst.st_mtime * 1_000_000_000))
                    print(f"D\t{child}\t{cst.st_mode:o}\t{cmtime}")
                except OSError as exc:
                    print(f"ERR\t{child}\t{type(exc).__name__}")
            for name in filenames:
                emit(os.path.join(dirpath, name))
        return
    if stat.S_ISLNK(mode):
        try:
            target = os.readlink(path)
        except OSError:
            target = "<unreadable>"
        print(f"L\t{path}\t{mode:o}\t{st.st_size}\t{mtime_ns}\t{target}")
        return
    if stat.S_ISREG(mode):
        print(f"F\t{path}\t{mode:o}\t{st.st_size}\t{mtime_ns}")
        return
    print(f"O\t{path}\t{mode:o}\t{st.st_size}\t{mtime_ns}")

for arg in sys.argv[1:]:
    emit(arg)
PY

  local sig
  sig=$(_housekeeping_sha1_file "$tmp")
  rm -f "$tmp"
  [ -n "$sig" ] || return 1
  printf '%s\n' "$sig"
}

housekeeping_should_run() {
  local label="$1" sig="$2" ttl="${3:-${HOUSEKEEPING_UNCHANGED_RERUN_SECS:-3600}}"
  [ "${HOUSEKEEPING_DIRTY_CHECKS:-1}" = "0" ] && return 0
  [ -n "$sig" ] || return 0

  local stamp old_sig old_ts now
  stamp=$(housekeeping_stamp_path "$label") || return 0
  [ -s "$stamp" ] || return 0
  old_sig=$(sed -n '1p' "$stamp" 2>/dev/null)
  old_ts=$(sed -n '2p' "$stamp" 2>/dev/null)
  [ "$old_sig" = "$sig" ] || return 0

  case "$ttl" in ''|*[!0-9]*) ttl=3600 ;; esac
  [ "$ttl" -le 0 ] && return 1
  case "$old_ts" in ''|*[!0-9]*) return 0 ;; esac
  now=$(date +%s)
  [ $((now - old_ts)) -ge "$ttl" ]
}

housekeeping_mark_clean() {
  local label="$1" sig="$2" stamp
  [ -n "$sig" ] || return 0
  stamp=$(housekeeping_stamp_path "$label") || return 0
  {
    printf '%s\n' "$sig"
    date +%s
  } > "$stamp" 2>/dev/null || true
}

housekeeping_run_if_dirty() {
  local label="$1" cmd="$2"; shift 2 || true
  local sig rc after_sig
  sig=$(housekeeping_signature "$label" "$@" 2>/dev/null) || sig=""
  if [ -n "$sig" ] && ! housekeeping_should_run "$label" "$sig"; then
    if [ "${HOUSEKEEPING_LOG_SKIPS:-0}" = "1" ] && declare -f log >/dev/null 2>&1; then
      log "housekeeping: skip ${label} (unchanged)" | tee -a "${INDEX:-/dev/null}" >/dev/null
    fi
    return 0
  fi

  "$cmd"
  rc=$?
  if [ "$rc" -eq 0 ]; then
    after_sig=$(housekeeping_signature "$label" "$@" 2>/dev/null || true)
    housekeeping_mark_clean "$label" "${after_sig:-$sig}"
  fi
  return "$rc"
}
