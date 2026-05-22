#!/usr/bin/env bash
# lib/edges.sh — Edge-novelty bookkeeping for the coverage probe.
#
# bin/hits emits a flat list of (function, file:line) pairs reached during
# a testcase run via sancov + llvm-symbolizer. Historically the harness
# threw all of that away except a single boolean: "did the run reach the
# named --want symbol?". This file persists the per-target union of edges
# seen across runs and exposes:
#
#   edges_extract_from_hits_file <hits_file>
#       Read an interleaved llvm-symbolizer dump and emit one canonical
#       edge token per line. Token format is `<function>|<file:line>`.
#       Empty lines, "??" placeholders, and noise frames are dropped.
#       Output is sorted-unique.
#
#   edges_root <slug>
#       Per-target coverage directory: <results_root>/coverage/. Created
#       on demand.
#
#   edges_journal_path <slug> <agent_num>
#       Per-agent journal file: append-only sorted-unique edge tokens
#       this agent has contributed. Per-agent files mean concurrent
#       writers never contend on the same file — the union view across
#       all journals is computed at read time.
#
#   edges_master_union <slug>
#       Print the deduplicated union of every agent journal for the slug,
#       one edge token per line, sorted. Stable across calls when no new
#       edges have been recorded.
#
#   edges_count_new <slug> <run_edges_file>
#       Print the count of edges in <run_edges_file> NOT already in the
#       master union. Pure read; does not mutate state.
#
#   edges_diff_new <slug> <run_edges_file>
#       Print the edges in <run_edges_file> NOT already in the master
#       union, one per line.
#
#   edges_record_run <slug> <agent_num> <run_edges_file>
#       Append the new-only edges from <run_edges_file> to the agent's
#       journal. Idempotent: re-recording a run that already contributed
#       its edges is a no-op. Atomic against concurrent invocations of
#       the same agent — and fully isolated against other agents because
#       agents write to disjoint files.
#
#   edges_summary_subsystem_counts <slug> [depth]
#       Walk the master union, group by subsystem (top-N path components
#       of the file path; default depth=2), and emit one TSV line per
#       subsystem: "<subsystem>\t<edge_count>". Sorted desc by count.
#
# Edge-token format design notes:
#   * function|file:line, NOT function|file:line:col — column noise
#     would inflate the bitmap with edges that aren't semantically new.
#   * function part can be `Foo::Bar(int)` (libc++ demangled) or a plain
#     C name. We do not normalize template/argument lists; two distinct
#     overloads count as two edges, which is the correct semantics.
#   * file path is whatever the symbolizer emits. Callers that want to
#     report "edges reached in src/parser/" should string-match the
#     file portion against a path prefix.

# Default noise regex — filters interceptors, dyld, ASan/sanitizer
# runtime, sancov runtime, dynamic linker, libc init, and the macOS
# launch-services bootstrap. Override per-target with EDGES_NOISE_RE.
EDGES_DEFAULT_NOISE_RE='__asan|__sanitizer|__interceptor|libc\+\+abi|libsystem_|libobjc|libdyld|^_dyld_|libsancov|asan_interceptors|^_dispatch_|^_pthread_|^start\+|^_main$|^XPCOMGlueLoad|^NS_LogInit|^NSApplicationMain'

# ─── Internals ────────────────────────────────────────────────────

# Print the configured results root for a slug. We don't import the
# orchestrator here — callers must export RESULTS_DIR (audit harness) or
# pass --results-dir explicitly via env. This keeps the lib usable from
# bin/hits, bin/coverage-summary, tests, and future tools.
_edges_results_root() {
  local slug="${1:-}"
  if [ -n "${EDGES_RESULTS_DIR:-}" ]; then
    printf '%s' "$EDGES_RESULTS_DIR"
    return 0
  fi
  if [ -n "${RESULTS_DIR:-}" ]; then
    printf '%s' "$RESULTS_DIR"
    return 0
  fi
  if [ -n "$slug" ] && [ -n "${SCRIPT_ROOT:-}" ]; then
    local output_root
    if declare -F target_output_root >/dev/null 2>&1; then
      output_root="$(target_output_root "$SCRIPT_ROOT" "$slug" "${AUDIT_EXPERIMENT_NAME:-}" "${AUDIT_EXPERIMENT_SUFFIX:-}" 2>/dev/null || true)"
    fi
    if [ -z "${output_root:-}" ]; then
      output_root="$SCRIPT_ROOT/output/${TARGET_OUTPUT_SLUG:-$slug}"
    fi
    # Honor either layout: output/<slug>/results/ (the audit canonical
    # path under audit harness) or output/<slug>/coverage/ as a flat
    # fallback for ad-hoc use.
    if [ -d "$output_root/results" ]; then
      printf '%s/results' "$output_root"
      return 0
    fi
    printf '%s' "$output_root"
    return 0
  fi
  return 1
}

# ─── Public API ───────────────────────────────────────────────────

edges_root() {
  local slug="${1:-}"
  local results_root
  results_root=$(_edges_results_root "$slug") || return 1
  local d="$results_root/coverage"
  mkdir -p "$d" 2>/dev/null || true
  printf '%s' "$d"
}

edges_journal_path() {
  local slug="${1:-}" agent="${2:-1}"
  local root
  root=$(edges_root "$slug") || return 1
  printf '%s/edges-agent-%s.journal' "$root" "$agent"
}

# Extract canonical edge tokens from a hits-file (the interleaved output
# of `sancov -print | llvm-symbolizer -e <bin>`). The format the producer
# emits is:
#   <function-or-??>
#   <file>:<line>:<col>
#   (blank)
# Repeated. We pair function with file:line, drop ??, strip column
# suffix, filter noise, and emit sorted-unique.
edges_extract_from_hits_file() {
  local hits_file="${1:-}"
  [ -n "$hits_file" ] && [ -s "$hits_file" ] || return 0
  local noise_re="${EDGES_NOISE_RE:-$EDGES_DEFAULT_NOISE_RE}"
  awk '
    function trim(s) { sub(/^[[:space:]]+/, "", s); sub(/[[:space:]]+$/, "", s); return s }
    /^[[:space:]]*$/ { fn=""; next }
    fn == "" { fn = trim($0); next }
    {
      file = trim($0)
      # The symbolizer emits "??" / "??:0:0" when it cannot resolve the
      # PC. These are useless for novelty tracking — drop them.
      if (fn == "??" || fn == "" || file == "??:0:0" || file == "" || file == "??") {
        fn = ""
        next
      }
      # Strip a trailing :col so two hits on the same line do not
      # bloat the bitmap. Keep the file:line prefix.
      sub(/:[0-9]+$/, "", file)
      print fn "|" file
      fn = ""
    }
  ' "$hits_file" \
    | (if [ -n "$noise_re" ]; then grep -vE "$noise_re"; else cat; fi) \
    | LC_ALL=C sort -u
}

# Print the deduplicated master union of all agent journals for a slug.
# Empty / missing slug or empty / missing journals → no output, rc=0.
edges_master_union() {
  local slug="${1:-}"
  local root
  root=$(edges_root "$slug" 2>/dev/null) || return 0
  [ -d "$root" ] || return 0
  local journals=()
  while IFS= read -r f; do
    [ -n "$f" ] && [ -s "$f" ] && journals+=("$f")
  done < <(find "$root" -maxdepth 1 -type f -name 'edges-agent-*.journal' 2>/dev/null | LC_ALL=C sort)
  [ "${#journals[@]}" -gt 0 ] || return 0
  LC_ALL=C sort -u -m "${journals[@]}" 2>/dev/null
}

# Print edges from <run_edges_file> that are NOT already in the master
# union. The run_edges_file must already be sorted-unique (the contract
# of edges_extract_from_hits_file).
edges_diff_new() {
  local slug="${1:-}" run_file="${2:-}"
  [ -n "$run_file" ] && [ -s "$run_file" ] || return 0
  # Use process substitution so we don't have to materialize a temp file
  # for the master union. comm -23 emits lines unique to the first input.
  LC_ALL=C comm -23 "$run_file" <(edges_master_union "$slug")
}

# Count edges in <run_edges_file> not already in master.
edges_count_new() {
  local slug="${1:-}" run_file="${2:-}"
  local n
  n=$(edges_diff_new "$slug" "$run_file" | wc -l 2>/dev/null | tr -d ' ')
  printf '%s' "${n:-0}"
}

# Append the new-only edges to the agent's journal. Atomic against
# concurrent calls for the SAME agent (rename-based). Concurrent calls
# for DIFFERENT agents touch disjoint files and need no coordination.
edges_record_run() {
  local slug="${1:-}" agent="${2:-1}" run_file="${3:-}"
  [ -n "$run_file" ] && [ -s "$run_file" ] || return 0
  local journal
  journal=$(edges_journal_path "$slug" "$agent") || return 0
  local new
  new=$(mktemp "${TMPDIR:-/tmp}/edges-new-XXXXXXXX")
  edges_diff_new "$slug" "$run_file" > "$new" 2>/dev/null || { rm -f "$new"; return 0; }
  if [ ! -s "$new" ]; then
    rm -f "$new"
    return 0
  fi
  # Merge new + existing journal (if any) into a sorted-unique tempfile,
  # then atomically rename. This is safe under multiple writers for the
  # SAME agent because the rename is atomic; under no writers it just
  # creates the journal.
  local merged
  merged=$(mktemp "${TMPDIR:-/tmp}/edges-merged-XXXXXXXX")
  if [ -s "$journal" ]; then
    LC_ALL=C sort -u -m "$journal" "$new" > "$merged" 2>/dev/null || {
      rm -f "$new" "$merged"; return 1
    }
  else
    cp "$new" "$merged" 2>/dev/null || { rm -f "$new" "$merged"; return 1; }
  fi
  mv -f "$merged" "$journal" 2>/dev/null || {
    rm -f "$new" "$merged"; return 1
  }
  rm -f "$new"
  return 0
}

# Walk the master union, group edges by subsystem (the first <depth>
# slash-delimited components of the file path), emit one
# "<subsystem>\t<edges>" line per subsystem, sorted by count desc.
# depth defaults to 2.
edges_summary_subsystem_counts() {
  local slug="${1:-}" depth="${2:-2}"
  case "$depth" in ''|*[!0-9]*) depth=2 ;; esac
  edges_master_union "$slug" | awk -v depth="$depth" '
    BEGIN { FS="|" }
    NF < 2 { next }
    {
      path = $2
      # Strip the line suffix; we want the path only.
      sub(/:[0-9]+$/, "", path)
      n = split(path, parts, "/")
      if (n == 0) next
      take = (n < depth ? n : depth)
      sub_path = parts[1]
      for (i = 2; i <= take; i++) sub_path = sub_path "/" parts[i]
      counts[sub_path]++
    }
    END {
      for (s in counts) printf "%s\t%d\n", s, counts[s]
    }
  ' | LC_ALL=C sort -t$'\t' -k2,2nr -k1,1
}

# Convenience: parse a hits-log line emitted by bin/hits (HIT/MISSED/
# EXEC_FAIL/NO_COVERAGE) and pull the new-edge count. Returns 0 if a
# `new=N` field is found and N>0; returns 1 otherwise. Used by the
# corpus-promotion gate.
edges_log_line_has_new_edges() {
  local line="${1:-}"
  [ -n "$line" ] || return 1
  case "$line" in
    *new=0*) return 1 ;;
    *new=*)
      local n
      n=$(printf '%s' "$line" | sed -nE 's/.*[[:space:]]new=([0-9]+).*/\1/p')
      [ -n "$n" ] && [ "$n" -gt 0 ] 2>/dev/null
      ;;
    *) return 1 ;;
  esac
}
