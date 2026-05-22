#!/usr/bin/env bash
# output_cap.sh — replacement-style head+tail truncation for tool output that
# would otherwise dominate the cached agent transcript.
#
# Background: each tool output that lands in an agent's aggregated_output gets
# replayed as cached input on every subsequent turn. A 130 KB rg-safe dump
# emitted at turn 5 of a 130-turn session adds ~16 MB of cached tokens. The
# existing rg-safe / sed wrappers cap at 128 KiB by chopping the *tail* and
# appending a footer ("clipped at N bytes — narrow your search"). That keeps
# the head intact but loses the tail entirely; it also doesn't help peek
# (no byte cap) or ASan crash output (uncapped on crash by design).
#
# This module replaces the chop-the-tail behavior with a head + middle-elide
# + tail layout, line-aligned, and spills the full original to disk so the
# agent can re-read it deterministically via `cat <spill-path>`.
#
# Sourced by:
#   - bin/peek         (range mode + grep mode)
#   - bin/rg-safe      (post-cap step)
#   - bin/run-asan-multi  (crash digest path)
#
# Defaults — keep these in sync with .agents/references/session-rules.digest.md
# so the prompt documents what agents will see.
#   OUTCAP_MAX_BYTES=51200      ~50 KB total surfaced to the agent
#   OUTCAP_HEAD_BYTES=24576     ~24 KB from the top
#   OUTCAP_TAIL_BYTES=20480     ~20 KB from the bottom
#   OUTCAP_SPILL_DIR=<unset>    where the full original is written. When
#                               unset it resolves to ${RESULTS_DIR}/logs/.raw/
#                               outcap (forensic dumps belong under logs/.raw/),
#                               or, with no results tree, a private 0700
#                               per-process dir under $TMPDIR. Spill files are
#                               created mode 0600. An explicit value is honored
#                               verbatim. See _outcap_resolve_spill_dir.
#
# Why those numbers: ASan ERROR headers + first ~150 frames fit in 24 KB;
# SUMMARY/ABORTING lines plus a probe verdict footer fit in well under 20 KB.
# rg-safe outputs over 50 KB are pathologically broad searches; the head
# shows the first matches, the tail shows the bottom of the result set, and
# anything in the middle was already noise the agent shouldn't have asked
# for. Spill keeps the option open without poisoning context.
#
# Disable by setting OUTCAP_MAX_BYTES=0. That bypasses both the cap and the
# spill, restoring pre-fix behavior for one-off interactive debugging.

# Guard against double-source. Re-sourcing is safe — pure function defs —
# but the guard makes the intent explicit when reading other files.
if [ "${_OUTPUT_CAP_SH_LOADED:-0}" = "1" ]; then return 0 2>/dev/null || true; fi
_OUTPUT_CAP_SH_LOADED=1

# Default knob values. Callers may override per-invocation by exporting the
# matching env var or by passing explicit args to cap_output_file.
: "${OUTCAP_MAX_BYTES:=51200}"
: "${OUTCAP_HEAD_BYTES:=24576}"
: "${OUTCAP_TAIL_BYTES:=20480}"
# OUTCAP_SPILL_DIR is resolved lazily by _outcap_resolve_spill_dir — see below.

# Validate integers up front so an env typo fails loudly instead of producing
# silent zero-byte output later.
_outcap_check_int() {
  local name="$1" val="$2"
  case "$val" in
    ''|*[!0-9]*) echo "[output_cap] ${name} must be a non-negative integer (got: $val)" >&2; return 2 ;;
  esac
  return 0
}

# _outcap_resolve_spill_dir — echo a writable directory for spill files,
# creating it if needed. Memoized for the life of the process.
#
# Selection order:
#   1. An explicit OUTCAP_SPILL_DIR — honored verbatim (callers/tests pin it).
#   2. ${RESULTS_DIR}/logs/.raw/outcap — the audit's own forensic-dump area
#      (CLAUDE.md logging discipline). Lives in the results tree, not /tmp.
#   3. A private per-process directory created with `mktemp -d` under $TMPDIR.
#
# Cases 1 and 2 reuse a stable, predictable directory; case 3 is the only one
# that may land in a shared/world-writable /tmp, so it gets an unguessable
# name. Every resolved directory is forced to mode 0700, and spill files
# inside it are written 0600 (see cap_output_file), so predictable per-file
# names cannot be pre-created or symlink-redirected by other local users.
_OUTCAP_SPILL_DIR_RESOLVED=""
_outcap_resolve_spill_dir() {
  if [ -n "$_OUTCAP_SPILL_DIR_RESOLVED" ]; then
    printf '%s' "$_OUTCAP_SPILL_DIR_RESOLVED"
    return 0
  fi
  local dir=""
  if [ -n "${OUTCAP_SPILL_DIR:-}" ]; then
    dir="$OUTCAP_SPILL_DIR"
    mkdir -p "$dir" 2>/dev/null || return 1
  elif [ -n "${RESULTS_DIR:-}" ]; then
    dir="${RESULTS_DIR}/logs/.raw/outcap"
    mkdir -p "$dir" 2>/dev/null || return 1
  else
    dir="$(mktemp -d "${TMPDIR:-/tmp}/outcap-XXXXXXXX" 2>/dev/null)" || return 1
  fi
  chmod 700 "$dir" 2>/dev/null || true
  _OUTCAP_SPILL_DIR_RESOLVED="$dir"
  printf '%s' "$dir"
}

# cap_output_file <input-file> [label]
#
# Reads <input-file>, emits to stdout:
#   - If size ≤ OUTCAP_MAX_BYTES: passthrough byte-for-byte.
#   - Else: head H bytes (line-aligned) + marker + tail T bytes (line-aligned).
#           The full <input-file> is preserved on disk at OUTCAP_SPILL_DIR
#           under a stable name; marker points there.
#
# The optional [label] is shown in the truncation marker so agents can tell
# which tool emitted it ("rg-safe", "peek", "asan-crash").
#
# Exit code: 0 on success; 2 on bad env. Never errors out for a missing file —
# treats it as empty and emits nothing (caller already handles "file missing").
cap_output_file() {
  local in_file="$1"
  local label="${2:-output}"
  # label is spliced into a spill filename — restrict it to a safe path
  # charset so a caller (now or later) cannot inject a separator or `..`.
  label="$(printf '%s' "$label" | tr -c 'A-Za-z0-9._-' '-')"
  [ -n "$label" ] || label="output"

  _outcap_check_int OUTCAP_MAX_BYTES  "$OUTCAP_MAX_BYTES"  || return 2
  _outcap_check_int OUTCAP_HEAD_BYTES "$OUTCAP_HEAD_BYTES" || return 2
  _outcap_check_int OUTCAP_TAIL_BYTES "$OUTCAP_TAIL_BYTES" || return 2

  if [ ! -f "$in_file" ]; then
    return 0
  fi

  # OUTCAP_MAX_BYTES=0 means "no cap" — bypass everything, including the
  # spill. This mirrors the CAP_LINES=0/CAP_BYTES=0 convention used by
  # lib/wrappers/_cap, so a single env knob disables every output cap path.
  if [ "$OUTCAP_MAX_BYTES" -eq 0 ]; then
    cat "$in_file"
    return 0
  fi

  local total_bytes
  total_bytes=$(wc -c < "$in_file" 2>/dev/null | tr -d ' ')
  total_bytes=${total_bytes:-0}

  if [ "$total_bytes" -le "$OUTCAP_MAX_BYTES" ]; then
    cat "$in_file"
    return 0
  fi

  # Past the cap. Spill the full original first so the marker can name the
  # path. We tolerate spill failure (e.g. read-only filesystem) by emitting a
  # marker that says "spill unavailable" rather than dropping the truncation
  # — losing context is worse than losing the disk copy.
  local spill_path="" spill_dir=""
  spill_dir="$(_outcap_resolve_spill_dir)"
  if [ -n "$spill_dir" ]; then
    local stamp pid sha
    stamp=$(date +%s 2>/dev/null || echo 0)
    pid="$$"
    # Hash the input bytes so reruns of the same command produce the same
    # filename — handy when an agent re-reads spilled output. Falls back to
    # a pid/stamp combo if no hasher is on PATH.
    if declare -F audit_sha1 >/dev/null 2>&1; then
      sha=$(audit_sha1 "$in_file" 2>/dev/null | awk '{print $1}' | cut -c1-12)
    elif command -v shasum >/dev/null 2>&1; then
      sha=$(shasum -a 1 "$in_file" 2>/dev/null | awk '{print $1}' | cut -c1-12)
    elif command -v sha1sum >/dev/null 2>&1; then
      sha=$(sha1sum "$in_file" 2>/dev/null | awk '{print $1}' | cut -c1-12)
    else
      sha=""
    fi
    if [ -n "$sha" ]; then
      spill_path="${spill_dir}/outcap-${label}-${sha}.txt"
    else
      spill_path="${spill_dir}/outcap-${label}-${stamp}-${pid}.txt"
    fi
    # Write with a private umask so the spill lands mode 0600, and unlink
    # any pre-existing path first: the filename is predictable, so a stale
    # entry — or a symlink planted by another local user — must not be
    # followed or appended to. The spill dir itself is mode 0700.
    if ! ( umask 077 && rm -f "$spill_path" 2>/dev/null; cp "$in_file" "$spill_path" ) 2>/dev/null; then
      spill_path=""
    fi
  fi

  # Head + tail emission. Both portions are line-aligned: take H bytes from
  # the top, back up to the last newline so we never print a partial line;
  # take T bytes from the bottom, advance past the first newline likewise.
  # If python3 is unavailable, fall back to head/tail-by-bytes which can
  # leave partial lines — uglier but never corrupting.
  if command -v python3 >/dev/null 2>&1; then
    python3 - "$in_file" "$OUTCAP_HEAD_BYTES" "$OUTCAP_TAIL_BYTES" \
                "$total_bytes" "$label" "$spill_path" <<'PY'
import sys, os
path, head_n, tail_n, total, label, spill = sys.argv[1:]
head_n = int(head_n); tail_n = int(tail_n); total = int(total)

with open(path, "rb") as f:
    head = f.read(head_n)
# Back up to the last newline so we don't split a record. If there is no
# newline at all (one massive line) we keep the head as-is — agent will see
# a partial line but no data loss within the H window.
nl = head.rfind(b"\n")
if nl >= 0:
    head = head[: nl + 1]

with open(path, "rb") as f:
    f.seek(max(0, total - tail_n))
    tail = f.read()
# Advance past the first newline so the tail starts at a record boundary,
# mirroring the head logic. Same caveat for one-line files.
nl = tail.find(b"\n")
if nl >= 0 and nl + 1 < len(tail):
    tail = tail[nl + 1 :]

sys.stdout.buffer.write(head)

elided = total - len(head) - len(tail)
if elided < 0:
    elided = 0
spill_str = spill if spill else "<spill unavailable>"
marker = (
    f"\n[output_cap: {label} truncated — {total:,} total bytes, "
    f"{len(head):,} head + {len(tail):,} tail shown, {elided:,} bytes elided. "
    f"Full output: {spill_str}. Re-read with `cat {spill_str}` "
    f"or narrow your query. Override: OUTCAP_MAX_BYTES=0 to disable.]\n"
)
sys.stdout.buffer.write(marker.encode("utf-8"))
sys.stdout.buffer.write(tail)
# Ensure trailing newline so the next agent line doesn't visually butt up
# against the last byte of tail content.
if not tail.endswith(b"\n"):
    sys.stdout.buffer.write(b"\n")
PY
    return 0
  fi

  # Fallback path: python3 missing. head/tail by bytes; marker is plain text.
  # Used only on minimal containers; production audit nodes have python3.
  local elided=$((total_bytes - OUTCAP_HEAD_BYTES - OUTCAP_TAIL_BYTES))
  [ "$elided" -lt 0 ] && elided=0
  head -c "$OUTCAP_HEAD_BYTES" "$in_file"
  if [ -n "$spill_path" ]; then
    printf '\n[output_cap: %s truncated — %d total bytes, head/tail shown, %d bytes elided. Full output: %s. Re-read with `cat %s` or narrow your query.]\n' \
      "$label" "$total_bytes" "$elided" "$spill_path" "$spill_path"
  else
    printf '\n[output_cap: %s truncated — %d total bytes, head/tail shown, %d bytes elided. (spill unavailable.) Narrow your query or disable with OUTCAP_MAX_BYTES=0.]\n' \
      "$label" "$total_bytes" "$elided"
  fi
  tail -c "$OUTCAP_TAIL_BYTES" "$in_file"
  return 0
}

# cap_output_stdin <label>
#
# Convenience wrapper: read stdin to a temp file, then run cap_output_file.
# Removes the temp on exit. Useful for pipelines:
#   some_command | cap_output_stdin label
cap_output_stdin() {
  local label="${1:-output}"
  local tmp
  tmp=$(mktemp "${TMPDIR:-/tmp}/outcap-XXXXXXXX") || {
    echo "[output_cap] failed to allocate temp file" >&2
    cat  # passthrough rather than swallow
    return 1
  }
  cat > "$tmp"
  cap_output_file "$tmp" "$label"
  local rc=$?
  rm -f "$tmp"
  return "$rc"
}
