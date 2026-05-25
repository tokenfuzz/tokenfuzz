#!/usr/bin/env bash
# lib/triage.sh — Crash classification, FIND validation, index regeneration.
# Sourced by bin/audit.
#
# ── Why this is bash, not Python ─────────────────────────────────────
# This module is the 58-function crash-triage state machine: classify →
# validate → route. Every function in it consumes the audit runtime
# (RESULTS_DIR, TARGET_ROOT, TARGET_SLUG, INDEX, LOGDIR, SCRIPT_ROOT
# globals; the audit_log / agent_role / structured_state_* / hits_log_path
# helper functions sourced by bin/audit) and shares crash-directory
# conventions with the bash routing code. A clean Python port at
# production quality is 40–60 hours by honest estimate — a week of
# work, not a session — and would either duplicate the runtime contract
# in Python or force a subprocess hop per primitive. The expensive
# computations that DON'T belong in bash (stack-frame clustering,
# finding-signature dedup) are already Python: see bin/cluster-crashes,
# bin/cluster-findings, lib/finding_signature.py, lib/stack_frames.py.
# What remains here is exactly the glue that bash does well.

# llm_decide is sourced by bin/audit before triage.sh; in tests we source it
# directly. Tolerate either order.
if ! declare -f llm_decide >/dev/null 2>&1; then
  _triage_llm_dir="${SCRIPT_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
  [ -f "$_triage_llm_dir/lib/llm_decide.sh" ] && source "$_triage_llm_dir/lib/llm_decide.sh"
  unset _triage_llm_dir
fi

if ! declare -f render_prompt_template >/dev/null 2>&1; then
  _triage_prompt_dir="${SCRIPT_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
  [ -f "$_triage_prompt_dir/lib/prompt_template.sh" ] && source "$_triage_prompt_dir/lib/prompt_template.sh"
  unset _triage_prompt_dir
fi

if ! declare -f audit_timeout_run >/dev/null 2>&1; then
  _triage_timeout_dir="${SCRIPT_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
  [ -f "$_triage_timeout_dir/lib/timeout.sh" ] && source "$_triage_timeout_dir/lib/timeout.sh"
  unset _triage_timeout_dir
fi

if ! declare -f audit_mtime_utc >/dev/null 2>&1; then
  _triage_platform_dir="${SCRIPT_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
  [ -f "$_triage_platform_dir/lib/platform.sh" ] && source "$_triage_platform_dir/lib/platform.sh"
  unset _triage_platform_dir
fi

_triage_file_sha1() {
  local f="$1"
  audit_sha1 "$f" 2>/dev/null | awk '{print $1}'
}

_triage_text_sha1() {
  audit_sha1 2>/dev/null | awk '{print $1}'
}

# ─── LLM gate cache helpers ───────────────────────────────────────
# The crash/find triage gates all cache LLM verdicts by content SHA-1 in
# a sidecar JSON next to the artifact. The cache plumbing is identical
# across gates — only the prompt, decision name, sha1 field, and
# business fields vary. These helpers factor out the plumbing so each
# call site shows the *question being asked* instead of jq incantations.

# True (rc=0) iff `$cache` is a non-empty JSON file whose `<field>` —
# or the legacy `signature_sha1` / `sha1` fallbacks — matches
# `$expected`. The legacy fallbacks preserve read-compatibility with
# cache files written by older schemas; new writes use the explicit
# field name. Returns 1 when the cache is missing, stale, or jq is
# unavailable.
_triage_cache_sha1_matches() {
  local cache="$1" sha1_field="$2" expected="$3"
  [ -n "$expected" ] || return 1
  [ -s "$cache" ] || return 1
  command -v jq >/dev/null 2>&1 || return 1
  local cached
  cached=$(jq -r --arg f "$sha1_field" '.[$f] // .signature_sha1 // .sha1 // ""' "$cache" 2>/dev/null)
  [ "$cached" = "$expected" ]
}

# Write the canonical cache envelope. Reads a JSON object on stdin
# (caller-supplied business fields), wraps it with
# decision/cached_at/<sha1_field>, and atomically writes to `$cache`.
# No-op (rc=0) when jq is absent or sha1 is empty — caching is always
# best-effort, callers never depend on it succeeding.
_triage_cache_write_envelope() {
  local cache="$1" decision="$2" sha1_field="$3" sha1="$4"
  command -v jq >/dev/null 2>&1 || return 0
  [ -n "$sha1" ] || return 0
  jq --arg decision "$decision" --arg sha1 "$sha1" --arg field "$sha1_field" \
     '. + {decision: $decision, cached_at: (now|todate)} | .[$field] = $sha1' \
     > "$cache" 2>/dev/null || true
}

# ─── Crash report parsing (Caller contract + Trigger source) ──────
# These extract the two normalized fields from a crash report:
#
#   Caller contract: obeyed | violated | unspecified
#   Trigger source:  data | call-sequence | both | race | env | timing | ...
#                    (comma-separated; "both" expands to data + call-sequence)

# Read a single "Field: value" line from the report. Returns the trimmed,
# lowercased value. Empty if the field is absent or the value is blank.
_extract_report_field() {
  local file="$1" field="$2"
  [ -f "$file" ] && [ -s "$file" ] || return 0
  local raw
  raw=$(grep -m1 -iE "^${field}:[[:space:]]" "$file" 2>/dev/null) || return 0
  raw="${raw#*:}"
  raw="${raw#"${raw%%[![:space:]]*}"}"
  raw="${raw%"${raw##*[![:space:]]}"}"
  printf '%s' "$raw" | tr '[:upper:]' '[:lower:]'
}

# Returns "obeyed" / "violated" / "unspecified" / "" (field absent).
parse_caller_contract() {
  local file="$1"
  [ -f "$file" ] || return 0
  local v
  v=$(_extract_report_field "$file" "Caller contract")
  case "$v" in
    obeyed|violated|unspecified) printf '%s' "$v" ;;
  esac
}

# Returns "direct" / "mapped" / "harness-only" / "none" / "".
# Optional field used to make offset/size/index/lifetime provenance explicit.
parse_parameter_control() {
  local file="$1"
  [ -f "$file" ] || return 0
  local v
  v=$(_extract_report_field "$file" "Parameter control")
  case "$v" in
    direct|mapped|none) printf '%s' "$v" ;;
    harness-only|harness_only|harness|testcase-only|testcase_only)
      printf 'harness-only' ;;
  esac
}

# Returns a comma-separated, normalized trigger token list.
# Components are lowercased and de-aliased to the same vocabulary used by
# attacker_controls in target.toml, so the verdict matrix is a pure set
# membership test. Aliases:
#   data, data-driven, input         → bytes
#   call-order, sequence, call_seq   → call-sequence
# Empty result means the field is absent — caller decides on a default.
parse_trigger_source() {
  local file="$1"
  [ -f "$file" ] || return 0
  local raw
  raw=$(_extract_report_field "$file" "Trigger source")
  [ -z "$raw" ] && return 0

  local cleaned out="" seen=":" tok
  cleaned=$(printf '%s' "$raw" | tr ',' '\n')
  while IFS= read -r tok; do
    tok="${tok#"${tok%%[![:space:]]*}"}"
    tok="${tok%"${tok##*[![:space:]]}"}"
    [ -z "$tok" ] && continue
    case "$tok" in
      data|data-driven|input)        tok="bytes" ;;
      call-order|call_order)         tok="call-sequence" ;;
      call-seq|call_sequence)        tok="call-sequence" ;;
      sequence)                      tok="call-sequence" ;;
    esac
    case "$seen" in *:"$tok":*) continue ;; esac
    seen="${seen}${tok}:"
    [ -n "$out" ] && out="${out},"
    out="${out}${tok}"
  done <<< "$cleaned"
  printf '%s' "$out"
}

# Membership test: is needle ($1) present in the comma-separated haystack ($2)?
_csv_contains() {
  local needle="$1" haystack="$2"
  case ",${haystack}," in *,"${needle}",*) return 0 ;; esac
  return 1
}

# Expand the special "both" token into "bytes,call-sequence". Returns the
# expanded CSV with duplicates removed. Pure passthrough for non-"both" lists.
_expand_trigger_components() {
  local csv="$1" out="" seen=":" tok sub
  local IFS=','
  set -- $csv
  unset IFS
  for tok in "$@"; do
    case "$tok" in
      both)
        for sub in bytes call-sequence; do
          case "$seen" in *:"$sub":*) continue ;; esac
          seen="${seen}${sub}:"
          [ -n "$out" ] && out="${out},"
          out="${out}${sub}"
        done
        ;;
      *)
        case "$seen" in *:"$tok":*) continue ;; esac
        seen="${seen}${tok}:"
        [ -n "$out" ] && out="${out},"
        out="${out}${tok}"
        ;;
    esac
  done
  printf '%s' "$out"
}

# Compute the triage verdict for a crash report given a threat model.
#
# Args:
#   $1  path to the crash report file (report.md / REPORT.md / description.md)
#   $2  attacker_controls CSV (e.g. "bytes" or "bytes,call-sequence,timing").
#       Empty / unset → defaults to "bytes".
#
# Output: one line "verdict\treason" on stdout. Verdicts:
#   promote        Trigger ⊆ attacker_controls AND contract ∈ {obeyed,unspecified}
#                  → keep in crashes/ as a security candidate.
#   contract-flag  Caller contract is reported as violated, parameter
#                  control is harness-only, or the trigger has a
#                  component outside attacker_controls. The crash dir
#                  STAYS in crashes/ with a `.contract-flagged`
#                  sidecar and a "## Contract concern" report block.
#                  The downstream reachability scorer applies a ×0.7
#                  multiplier on caller_contract=violated (see
#                  test_severity.sh), so contract-flagged crashes are
#                  automatically deprioritized in Severity without
#                  being lost from the crashes/ count.
#                  crashes-rejected/ is reserved for non-security
#                  classes (OOM, panic, null-deref, MOZ_CRASH,
#                  stack-overflow, incomplete artifacts, threat-
#                  boundary failures).
#   incomplete     Report missing both Caller contract and Trigger source
#                  → caller may fall back to other gates instead of rejecting.
#
# Always exits 0. The verdict is on stdout so callers can capture it.
evaluate_crash_verdict() {
  local report="$1" controls_csv="$2"
  [ -z "$controls_csv" ] && controls_csv="bytes"

  local contract parameter_control trigger_csv
  contract=$(parse_caller_contract "$report")
  parameter_control=$(parse_parameter_control "$report")
  trigger_csv=$(parse_trigger_source "$report")

  if [ "$contract" = "violated" ]; then
    printf 'contract-flag\tcaller contract violated per report fields\n'
    return 0
  fi

  if [ "$parameter_control" = "harness-only" ]; then
    printf 'contract-flag\tharness-only parameter control violates caller/API contract\n'
    return 0
  fi

  if [ -z "$contract" ] && [ -z "$trigger_csv" ]; then
    printf 'incomplete\tno Caller contract or Trigger source field in report\n'
    return 0
  fi

  # Default trigger when only the contract field is present.
  [ -z "$trigger_csv" ] && trigger_csv="bytes"

  local expanded missing="" tok
  expanded=$(_expand_trigger_components "$trigger_csv")
  local IFS=','
  set -- $expanded
  unset IFS
  for tok in "$@"; do
    [ -z "$tok" ] && continue
    if ! _csv_contains "$tok" "$controls_csv"; then
      [ -n "$missing" ] && missing="${missing},"
      missing="${missing}${tok}"
    fi
  done

  if [ -n "$missing" ]; then
    printf 'contract-flag\ttrigger requires [%s] outside attacker_controls=[%s]; treat as robustness/low-severity within this threat model\n' \
      "$missing" "$controls_csv"
    return 0
  fi
  printf 'promote\ttrigger=[%s] within attacker_controls=[%s]\n' \
    "$expanded" "$controls_csv"
}

# ─── Auto-discard crash classifier ────────────────────────────────
# Per AGENTS.md "Crash Quality": null deref, OOM, MOZ_CRASH/RustMozCrash/panic,
# ABRT, plain stack-overflow are auto-quarantined as low-value crashes.
#   0 → auto-discard (drop it)
#   1 → interesting crash OR no crash at all
_triage_has_sanitizer_diagnostic() {
  local f="$1"
  [ -s "$f" ] || return 1
  grep -qE 'ERROR: (AddressSanitizer|UndefinedBehaviorSanitizer)|SUMMARY: (AddressSanitizer|UndefinedBehaviorSanitizer)|WARNING: (ThreadSanitizer|MemorySanitizer):|SUMMARY: (ThreadSanitizer|MemorySanitizer):|^WARNING: DATA RACE$|UndefinedBehaviorSanitizer:|^[^[:space:]].*:[0-9]+:[0-9]+: runtime error:' "$f" 2>/dev/null
}

is_autodiscard_crash_output() {
  local f="$1"
  [ -f "$f" ] && [ -s "$f" ] || return 1

  # Short-circuit KEEP for interesting sanitizer-visible categories
  if grep -qE 'AddressSanitizer: (heap-buffer-overflow|use-after-free|heap-use-after-free|container-overflow|dynamic-stack-buffer-overflow|stack-buffer-overflow|stack-use-after-return|stack-use-after-scope|global-buffer-overflow|alloc-dealloc-mismatch|intra-object-overflow|double-free|negative-size-param|bad-free|calloc-overflow|new-delete-type-mismatch|invalid-pointer-pair)' "$f" 2>/dev/null; then
    return 1
  fi

  # Null-deref
  if grep -qE 'Hint: address points to the zero page|SCARINESS: [0-9]+ \(null-deref\)|SEGV on unknown address 0x0+[^0-9a-fA-F]' "$f" 2>/dev/null; then
    return 0
  fi

  # MOZ_CRASH / MOZ_ASSERT (anchored to avoid matching frame names)
  if grep -qE '(^|[][[:space:]:>])Hit MOZ_CRASH\(|^Assertion failure:|###!!! ASSERTION:' "$f" 2>/dev/null; then
    return 0
  fi

  # Debug-only assert aborts: plain assert(...) routed through libc
  # __assert_rtn / __assert_fail, or any [A-Z_]*(?:ASSERT|CHECK) macro
  # (bare ASSERT / CHECK or a prefixed family like DEBUGASSERT / DCHECK)
  # the project compiles out in release. ASan reports these as an ABRT,
  # not a memory-safety class, so they pass the SIGABRT-without-ASan
  # gate below but still aren't security bugs in the shipped binary.
  if grep -qE '^Assertion failed:|__assert_rtn|__assert_fail|^[[:space:]]*#[0-9]+ .* in [A-Z][A-Z0-9_]*(ASSERT|CHECK)\b' "$f" 2>/dev/null && \
     grep -qE 'AddressSanitizer: ABRT|SIGABRT' "$f" 2>/dev/null; then
    return 0
  fi

  # Rust panic (anchored)
  if grep -qE "^thread '[^']*' panicked at " "$f" 2>/dev/null; then
    return 0
  fi
  if grep -qE '\bRustMozCrash\b' "$f" 2>/dev/null; then
    return 0
  fi

  # Plain stack-overflow (not dynamic-stack-buffer-overflow)
  if grep -qE 'AddressSanitizer: stack-overflow( |$)' "$f" 2>/dev/null; then
    return 0
  fi

  # OOM / allocator failure
  if grep -qE 'AddressSanitizer: (allocation-size-too-big|out-of-memory)|AddressSanitizer failed to allocate|requested allocation size .* exceeds maximum' "$f" 2>/dev/null; then
    return 0
  fi

  # SIGABRT without any sanitizer diagnostic.
  if grep -qE 'SIGABRT|^abort\(\)|libsystem_kernel.*__pthread_kill' "$f" 2>/dev/null && \
     ! _triage_has_sanitizer_diagnostic "$f"; then
    return 0
  fi
  return 1
}

# LLM crash triage. Three-valued result:
#   rc=0 + reason on stdout → discard (LLM marked this as non-finding)
#   rc=2                    → keep (LLM said interesting; override regex)
#   rc=1                    → undecided (LLM unavailable / malformed; fall back)
llm_triage_crash_decision() {
  local asan_path="$1"
  declare -f llm_decide >/dev/null 2>&1 || return 1
  [ -s "$asan_path" ] || return 1

  local hash cache audit_cache
  hash=$(_triage_file_sha1 "$asan_path" 2>/dev/null || true)
  cache="$(dirname "$asan_path")/.llm-triage.json"
  audit_cache="$(dirname "$asan_path")/.audit/.llm-triage.json"
  # Two cache locations: the canonical sidecar plus a legacy path under
  # .audit/. On a hit at the legacy path we promote it to the canonical
  # location so subsequent reads short-circuit on the first candidate.
  local cache_candidate
  for cache_candidate in "$cache" "$audit_cache"; do
    if _triage_cache_sha1_matches "$cache_candidate" "content_sha1" "$hash"; then
      [ "$cache_candidate" = "$cache" ] || cp "$cache_candidate" "$cache" 2>/dev/null || true
      local cached_keep
      cached_keep=$(jq -r '.keep' "$cache_candidate" 2>/dev/null)
      if [ "$cached_keep" = "false" ]; then
        jq -r '.reason // "cached LLM discard"' "$cache_candidate" 2>/dev/null
        return 0
      fi
      if [ "$cached_keep" = "true" ]; then
        return 2
      fi
    fi
  done

  local trace
  trace=$(head -c 6000 "$asan_path" 2>/dev/null) || return 1
  [ -n "$trace" ] || return 1

  local prompt
  prompt=$(render_prompt_template triage_crash_trace.md.j2 \
    --var "trace=${trace}") || return 1

  local json
  json=$(printf '%s' "$prompt" | llm_decide crash_triage "keep,reason" 12) || return 1
  local keep
  keep=$(printf '%s' "$json" | jq -r '.keep' 2>/dev/null)
  if [ "$keep" = "false" ]; then
    local reason
    reason=$(printf '%s' "$json" | jq -r '.reason' 2>/dev/null)
    { jq -n --arg reason "$reason" '{keep: false, reason: $reason}' \
        | _triage_cache_write_envelope "$cache" "crash_triage" "content_sha1" "$hash"; } || true
    printf '%s' "$reason"
    return 0
  fi
  if [ "$keep" = "true" ]; then
    local reason
    reason=$(printf '%s' "$json" | jq -r '.reason' 2>/dev/null)
    { jq -n --arg reason "$reason" '{keep: true, reason: $reason}' \
        | _triage_cache_write_envelope "$cache" "crash_triage" "content_sha1" "$hash"; } || true
    return 2
  fi
  return 1
}

# Final pre-promotion LLM gate. Runs AFTER:
#   - regex/LLM trace triage (llm_triage_crash_decision)
#   - file-completeness validation
#   - export-repro bundling
#   - optional reachability/severity annotation
#   - caller-contract / Trigger source verdict matrix
# and looks at the finished report.md (or REPORT.md after bundling) to ask:
# is this a real, security-relevant memory-safety crash that an upstream
# maintainer can act on? Cached by report SHA-1 alongside .llm-triage.json
# so re-running triage on an unchanged report is free.
#
# Three-valued result, mirrors llm_triage_crash_decision and
# llm_find_quality_decision so callers can chain them with the same shape:
#   rc=0 + reason on stdout → REJECT (LLM marked report as not a finding)
#   rc=2                    → ACCEPT (LLM confirmed)
#   rc=1                    → UNDECIDED / LLM unavailable (caller falls back
#                             to the existing pipeline outcome)
llm_confirm_crash_report() {
  local report_path="$1"
  declare -f llm_decide >/dev/null 2>&1 || return 1
  [ -s "$report_path" ] || return 1

  local hash cache
  hash=$(_triage_file_sha1 "$report_path" 2>/dev/null || true)
  cache="$(dirname "$report_path")/.llm-confirm.json"
  if _triage_cache_sha1_matches "$cache" "content_sha1" "$hash"; then
    local cached_accept cached_reason
    cached_accept=$(jq -r '.accept' "$cache" 2>/dev/null)
    cached_reason=$(jq -r '.reason // ""' "$cache" 2>/dev/null)
    if [ "$cached_accept" = "true" ]; then
      return 2
    fi
    if [ "$cached_accept" = "false" ]; then
      printf '%s' "${cached_reason:-cached LLM rejection}"
      return 0
    fi
  fi

  local body
  body=$(head -c 12000 "$report_path" 2>/dev/null) || return 1
  [ -n "$body" ] || return 1

  local prompt
  prompt=$(render_prompt_template triage_crash_confirm.md.j2 \
    --var "body=${body}") || return 1

  local json
  json=$(printf '%s' "$prompt" | llm_decide crash_confirm "accept,reason" 15) || return 1
  local accept reason
  accept=$(printf '%s' "$json" | jq -r '.accept' 2>/dev/null)
  reason=$(printf '%s' "$json" | jq -r '.reason' 2>/dev/null)
  if [ "$accept" = "true" ]; then
    [ -n "$reason" ] && [ "$reason" != "null" ] || reason="LLM confirmed report"
    { jq -n --arg reason "$reason" '{accept: true, reason: $reason}' \
        | _triage_cache_write_envelope "$cache" "crash_confirm" "content_sha1" "$hash"; } || true
    return 2
  fi
  if [ "$accept" = "false" ]; then
    [ -n "$reason" ] && [ "$reason" != "null" ] || reason="LLM rejected report at confirm gate"
    { jq -n --arg reason "$reason" '{accept: false, reason: $reason}' \
        | _triage_cache_write_envelope "$cache" "crash_confirm" "content_sha1" "$hash"; } || true
    printf '%s' "$reason"
    return 0
  fi
  return 1
}

# Locate the primary sanitizer output file inside a CRASH-* directory.
# The canonical bundle filename is `sanitizer.txt` (neutral across asan/
# msan/tsan/ubsan). `asan.txt` is a legacy alias kept here as a fallback
# so bundles already shipped to maintainers stay readable.
find_primary_asan_in_crash_dir() {
  local d="$1"
  [ -d "$d" ] || return 1
  local f
  for f in "$d/sanitizer.txt" "$d/asan.txt" "$d/asan-output.txt" "$d/asan_output.txt" \
           "$d/msan.txt" "$d/tsan.txt" "$d/ubsan.txt"; do
    [ -s "$f" ] && { printf '%s\n' "$f"; return 0; }
  done
  local found=""
  while IFS= read -r -d '' f; do
    [ -s "$f" ] || continue
    found="$f"
    break
  done < <(find "$d" -maxdepth 1 -type f \
             \( -name 'asan-output*.txt' -o -name 'asan_output*.txt' -o -name 'asan-raw*.txt' \
                -o -name '*.asan.txt' -o -name '*.msan.txt' -o -name '*.tsan.txt' -o -name '*.ubsan.txt' \) \
             -print0 2>/dev/null | sort -z)
  [ -n "$found" ] && { printf '%s\n' "$found"; return 0; }
  return 1
}

find_primary_crash_narrative() {
  local d="$1"
  [ -d "$d" ] || return 1
  local f
  for f in "$d/report.md" "$d/description.md" "$d/README.md"; do
    [ -s "$f" ] && { printf '%s\n' "$f"; return 0; }
  done
  local found=""
  while IFS= read -r -d '' f; do
    [ -s "$f" ] || continue
    found="$f"
    break
  done < <(find "$d" -maxdepth 1 -type f -name '*.md' -size +0c -print0 2>/dev/null | sort -z)
  [ -n "$found" ] && { printf '%s\n' "$found"; return 0; }
  return 1
}

find_primary_testcase_in_crash_dir() {
  local d="$1"
  [ -d "$d" ] || return 1
  # Default min-bytes = 1: many real bugs reproduce on empty/single-byte
  # input (zero-length string, integer parser with one non-digit, off-by-one
  # with empty container). The prior 17-byte floor demoted real
  # CRASH-NNN dirs to "incomplete" forever. Override via env for tooling
  # that genuinely wants a higher floor (CRASH_TC_MIN_BYTES).
  local min_bytes="${CRASH_TC_MIN_BYTES:-1}"
  case "$min_bytes" in ''|*[!0-9]*) min_bytes=1 ;; esac
  [ "$min_bytes" -lt 1 ] && min_bytes=1
  local bin_dir
  bin_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/../bin" 2>/dev/null && pwd)
  if command -v python3 >/dev/null 2>&1 && [ -x "$bin_dir/find-crash-testcase" ]; then
    local found
    found=$(python3 "$bin_dir/find-crash-testcase" "$d" --min-bytes "$min_bytes" 2>/dev/null || true)
    [ -n "$found" ] && [ -s "$found" ] && { printf '%s\n' "$found"; return 0; }
  fi

  local f stem lower sz prefixed
  while IFS= read -r -d '' f; do
    [ -s "$f" ] || continue
    stem="${f##*/}"
    lower=$(printf '%s' "$stem" | tr '[:upper:]' '[:lower:]')
    case "$stem" in
      .*|REPORT.md|REPORT.html|report.md|description.md|README.md|reproduce.sh|testcase.sh|reproducer.sh|asan.txt|asan-output.txt|asan_output.txt|msan.txt|tsan.txt|ubsan.txt|harness.c|harness.cc|harness.cpp|harness.cxx|reachability.json|promotion.log|*.asan.txt|*.msan.txt|*.tsan.txt|*.ubsan.txt|*.log|*.md) continue ;;
    esac
    case "$lower" in
      asan*|msan*|tsan*|ubsan*|*.asan.*|*.msan.*|*.tsan.*|*.ubsan.*) continue ;;
    esac
    if [ -x "$f" ] && command -v file >/dev/null 2>&1 \
       && file "$f" 2>/dev/null | grep -qiE 'executable|Mach-O|ELF|shared object|dSYM'; then
      continue
    fi
    sz=$(wc -c < "$f" 2>/dev/null | tr -d ' ')
    [ "${sz:-0}" -ge "$min_bytes" ] || continue
    prefixed=0
    case "$lower" in
      input.*|input_*|input-*|testcase*|test-case*|tc.*|tc_*|tc-*|repro.*|repro_*|repro-*|reproducer*) prefixed=1 ;;
    esac
    case "$lower" in
      *.txt) [ "$prefixed" -eq 1 ] || continue ;;
    esac
    printf '%s\n' "$f"
    return 0
  done < <(find "$d" -maxdepth 1 -type f ! -name '.*' -print0 2>/dev/null | sort -z)
  return 1
}

crash_dir_contains_regex() {
  local d="$1" regex="$2"
  [ -d "$d" ] || return 1
  local f
  while IFS= read -r -d '' f; do
    if grep -qiE "$regex" "$f" 2>/dev/null; then
      return 0
    fi
  done < <(find "$d" -maxdepth 1 -type f \
             \( -name '*.md' -o -name '*.html' -o -name '*.xhtml' -o -name '*.svg' \
                -o -name '*.xml' -o -name '*.js' -o -name '*.mjs' -o -name '*.c' \
                -o -name '*.cc' -o -name '*.cpp' -o -name '*.py' -o -name '*.rs' \
                -o -name 'testcase*' -o -name 'repro*' \) \
             -print0 2>/dev/null)
  return 1
}

crash_dir_has_memory_safety_asan_signal() {
  local d="$1"
  local asan_path
  asan_path=$(find_primary_asan_in_crash_dir "$d" 2>/dev/null || true)
  [ -n "$asan_path" ] || return 1
  grep -qiE 'AddressSanitizer: (heap-buffer-overflow|use-after-free|heap-use-after-free|container-overflow|dynamic-stack-buffer-overflow|stack-buffer-overflow|stack-use-after-return|stack-use-after-scope|global-buffer-overflow|alloc-dealloc-mismatch|intra-object-overflow|double-free|negative-size-param|bad-free|calloc-overflow|new-delete-type-mismatch|invalid-pointer-pair)' "$asan_path" 2>/dev/null && return 0
  grep -qE 'SEGV on unknown address 0x[0-9a-fA-F]*[1-9a-fA-F]' "$asan_path" 2>/dev/null \
    && grep -qE 'SCARINESS: [0-9]+ \(wild-addr' "$asan_path" 2>/dev/null && return 0
  # ThreadSanitizer (data race / used after free in heap object).
  grep -qE 'WARNING: ThreadSanitizer: (data race|heap-use-after-free|thread-leak|deadlock)' "$asan_path" 2>/dev/null && return 0
  # MemorySanitizer (read of uninit memory).
  grep -qE 'WARNING: MemorySanitizer: use-of-uninitialized-value' "$asan_path" 2>/dev/null && return 0
  # Go race detector emits the same TSan banner via the runtime hook.
  grep -qE '^WARNING: DATA RACE$' "$asan_path" 2>/dev/null && return 0
  # UBSan memory-safety-adjacent diagnostics. Not every UBSan check is a
  # security crash by itself, but these preserve sanitizer-confirmed bounds,
  # object-size, null, vptr, alignment, and pointer-overflow reports for the
  # downstream caller-contract/security gate.
  grep -qE 'UndefinedBehaviorSanitizer|^[^[:space:]].*:[0-9]+:[0-9]+: runtime error: (load of misaligned address|store to misaligned address|member access within misaligned|reference binding to misaligned|null pointer|out of bounds|index .* out of bounds|object-size|vptr|pointer overflow|pointer-overflow)' "$asan_path" 2>/dev/null && return 0
  return 1
}

# Detect runtime crash diagnostics from interpreted / managed languages.
# These are NOT necessarily memory-safety bugs (a Python KeyError is not a
# UAF) but the crash dir's report.md may still document a security finding
# that lib/triage.sh should keep. The verdict matrix demotes to findings/
# rather than promoting to crashes/ when this is the only signal.
crash_dir_has_runtime_diagnostic_signal() {
  local d="$1"
  local asan_path
  asan_path=$(find_primary_asan_in_crash_dir "$d" 2>/dev/null || true)
  [ -n "$asan_path" ] || return 1
  # Go.
  grep -qE 'panic: runtime error:|fatal error: (stack overflow|out of memory|concurrent map)|^goroutine [0-9]+ \[' "$asan_path" 2>/dev/null && return 0
  # Rust.
  grep -qE "^thread '.*' panicked at|fatal runtime error:" "$asan_path" 2>/dev/null && return 0
  # JVM (Java/Kotlin).
  grep -qE '^Exception in thread|java\.lang\.(OutOfMemoryError|StackOverflowError|NullPointerException|IndexOutOfBoundsException|VerifyError|ClassCastException)' "$asan_path" 2>/dev/null && return 0
  # Python.
  grep -qE '^Fatal Python error:|^Traceback \(most recent call last\):' "$asan_path" 2>/dev/null && return 0
  # Ruby.
  grep -qE '^\[BUG\]|\(NoMemoryError\)|SystemStackError|^.+: stack level too deep' "$asan_path" 2>/dev/null && return 0
  # Node.js / V8.
  grep -qE '^FATAL ERROR:.*(heap out of memory|Allocation failed)|RangeError: Maximum call stack' "$asan_path" 2>/dev/null && return 0
  # PHP.
  grep -qE '^PHP Fatal error:|^Fatal error:.*Stack overflow|^Uncaught \w+Error:' "$asan_path" 2>/dev/null && return 0
  # Swift / Objective-C.
  grep -qE '^Fatal error:|libsystem_pthread\.dylib.*pthread_kill' "$asan_path" 2>/dev/null && return 0
  return 1
}

# Returns 0 iff the target.toml [sanitizer] section is explicitly empty
# (findings-only mode). bin/audit exports TARGET_SANITIZERS_EXPLICITLY_DISABLED
# to the triage subshell. When set, the triager prefers demotion to findings/
# over rejection to crashes-rejected/ for runtime-diagnostic crashes.
crash_dir_is_findings_only_target() {
  [ "${TARGET_SANITIZERS_EXPLICITLY_DISABLED:-0}" = "1" ]
}

crash_dir_has_security_impact_evidence() {
  local d="$1"
  crash_dir_has_memory_safety_asan_signal "$d" && return 0
  crash_dir_contains_regex "$d" '\b(memory[-[:space:]]safety|type confusion|use[-[:space:]]after[-[:space:]](free|scope|return)|out[-[:space:]]of[-[:space:]]bounds|heap[-[:space:]]buffer[-[:space:]]overflow|stack[-[:space:]]buffer[-[:space:]]overflow|container[-[:space:]]overflow|alloc[-[:space:]]dealloc[-[:space:]]mismatch|double[-[:space:]]free|intra[-[:space:]]object[-[:space:]]overflow|wild[-[:space:]]address[[:space:]](read|write)|wild[[:space:]](read|write)|out[-[:space:]]of[-[:space:]]range[[:space:]](read|write)|same[-[:space:]]origin|cross[-[:space:]]origin|origin[[:space:]-](policy|check|violation|bypass|isolation)|sandbox[[:space:]](escape|bypass|violation)|privilege[[:space:]](boundary|escalation|bypass|violation)|security[[:space:]]boundary|uxss|xss|csp[[:space:]]bypass|site[[:space:]-]isolation)\b' && return 0
  return 1
}

crash_dir_has_web_reachability_evidence() {
  local d="$1"
  crash_dir_contains_regex "$d" '(\bweb[-[:space:]]content\b|\bweb[-[:space:]]reachab|\bpage[[:space:]]load\b|<img\b|<video\b|<audio\b|<canvas\b|<svg\b|<iframe\b|<form\b|\bfetch\(|postMessage|Service[[:space:]]Worker|WebIDL|content[-[:space:]]script|HTML[[:space:]]parser|CSS[[:space:]]parser|MutationObserver|XMLHttpRequest|Request\(|Blob\(|FormData|multipart[[:space:]]form|same[-[:space:]]origin|cross[-[:space:]]origin|origin[[:space:]]policy|content[[:space:]]process|page[[:space:]]script|document\.|window\.|Worker\(|navigator\.)' && return 0
  local f
  for f in "$d"/*.html "$d"/*.xhtml "$d"/*.svg "$d"/*.xml; do
    [ -f "$f" ] || continue
    local sz
    sz=$(wc -c < "$f" 2>/dev/null | tr -d ' ')
    [ "${sz:-0}" -gt 16 ] && return 0
  done
  return 1
}

crash_dir_has_nonweb_only_markers() {
  local d="$1"
  crash_dir_contains_regex "$d" '(\|jit-test\||getSelfHostedValue\(|\bxpcshell\b|Services\.prefs|Cc\["@mozilla\.org/|Ci\.nsIPrefOverrideMap|privileged[-[:space:]]API[-[:space:]]only|chrome[-[:space:]]only|shell[-[:space:]]only|only[[:space:]]reachable[[:space:]]from[[:space:]](xpcshell|chrome|privileged))'
}

crash_dir_static_legitimacy_rejection_reason() {
  local d="$1" require_web_gate="${2:-${IS_BROWSER_TARGET:-0}}"

  if ! crash_dir_has_security_impact_evidence "$d"; then
    # Findings-only mode: a CRASH dir that lacks ASan/security signal but
    # DOES have a runtime diagnostic (Python traceback, Go panic, Java
    # exception, …) gets a "demote-to-findings" rejection reason instead
    # of "missing evidence". lib/triage.sh's caller routes the dir into
    # findings/ when this reason prefix is seen.
    if crash_dir_is_findings_only_target \
       && crash_dir_has_runtime_diagnostic_signal "$d"; then
      printf '%s\n' "demote-to-findings: runtime diagnostic without sanitizer-class memory-safety signal"
      return 0
    fi
    printf '%s\n' "missing memory-safety impact or explicit security-boundary evidence"
    return 0
  fi

  if [ "$require_web_gate" -eq 1 ] && crash_dir_has_nonweb_only_markers "$d"; then
    printf '%s\n' "xpcshell/chrome-only trigger without web/content reachability"
    return 0
  fi

  # Caller contract / Trigger source verdict matrix.
  # Read whatever narrative the dir actually has (report.md, REPORT.md,
  # description.md, …) and run it through evaluate_crash_verdict against
  # the target's declared attacker_controls.
  #
  # Contract-concern reasons (verdict=contract-flag from the matrix,
  # callback-releases-active regex, private/internal include regex)
  # are returned with a `contract-flag:` prefix. triage_crash_dirs
  # then annotates the dir in place (.contract-flagged sidecar +
  # report block) and KEEPS it in crashes/. The downstream
  # reachability scorer applies a ×0.7 multiplier on
  # caller_contract=violated, so these are automatically rated low in
  # Severity. crashes-rejected/ stays reserved for non-security
  # classes (OOM, panic, null-deref, stack-overflow, no sanitizer
  # signal, threat-boundary failures, incomplete-bundle TTL).
  local _verdict_report
  _verdict_report=$(find_primary_crash_narrative "$d" 2>/dev/null || true)
  if [ -n "$_verdict_report" ]; then
    local _verdict_line _verdict _verdict_reason
    _verdict_line=$(evaluate_crash_verdict "$_verdict_report" "${TARGET_ATTACKER_CONTROLS_CSV:-bytes}" 2>/dev/null) || _verdict_line=""
    _verdict="${_verdict_line%%	*}"
    _verdict_reason="${_verdict_line#*	}"
    case "$_verdict" in
      contract-flag)
        printf 'contract-flag: %s\n' "$_verdict_reason"
        return 0
        ;;
    esac
  fi

  if crash_dir_contains_regex "$d" 'free[sd]?[[:space:]]+(the[[:space:]]+)?active[[:space:]]+(parser[[:space:]]+)?(context|callback|object)|callback[[:space:]].*(free|release)[sd]?[[:space:]]+(the[[:space:]]+)?active'; then
    printf 'contract-flag: callback releases active target object\n'
    return 0
  fi

  if crash_dir_contains_regex "$d" '#[[:space:]]*include[[:space:]]+[<"][^>"]*(private|internal)/'; then
    printf 'contract-flag: private/internal target API used\n'
    return 0
  fi

  return 1
}

collect_crash_legitimacy_evidence() {
  local d="$1"
  [ -d "$d" ] || return 1

  local asan_path
  asan_path=$(find_primary_asan_in_crash_dir "$d" 2>/dev/null || true)
  if [ -n "$asan_path" ]; then
    {
      echo ">>> ASAN SUMMARY"
      grep -E 'ERROR: AddressSanitizer|SUMMARY: AddressSanitizer|SCARINESS|READ of size|WRITE of size|#[0-9]+' "$asan_path" 2>/dev/null | head -24
      echo
    }
  fi

  local narrative
  narrative=$(find_primary_crash_narrative "$d" 2>/dev/null || true)
  if [ -n "$narrative" ]; then
    echo ">>> ${narrative##*/}"
    head -c 2600 "$narrative" 2>/dev/null
    echo
  fi

  echo ">>> ARTIFACTS"
  find "$d" -maxdepth 1 -type f ! -name '.*' -print0 2>/dev/null \
    | while IFS= read -r -d '' f; do printf '%s\n' "${f##*/}"; done \
    | sort | head -40
  echo

  local f count=0
  while IFS= read -r -d '' f; do
    [ "$count" -ge 3 ] && break
    echo ">>> ${f##*/}"
    head -c 1400 "$f" 2>/dev/null
    echo
    count=$((count + 1))
  done < <(find "$d" -maxdepth 1 -type f \
             \( -name '*.c' -o -name '*.cc' -o -name '*.cpp' -o -name '*.rs' \
                -o -name '*.py' -o -name '*.js' -o -name '*.mjs' -o -name '*.html' \
                -o -name '*.xml' -o -name '*.svg' -o -name 'testcase*' -o -name 'repro*' \) \
             ! -name '.*' \
             -print0 2>/dev/null | sort -z)
}

llm_crash_legitimacy_decision() {
  local d="$1" require_web_gate="${2:-${IS_BROWSER_TARGET:-0}}"
  declare -f llm_decide >/dev/null 2>&1 || return 1
  [ -d "$d" ] || return 1

  local evidence hash cache cached_require cached_legit
  evidence=$(collect_crash_legitimacy_evidence "$d" 2>/dev/null) || evidence=""
  [ -n "$evidence" ] || return 1

  hash=$(printf '%s' "$evidence" | _triage_text_sha1 2>/dev/null || true)
  cache="$d/.llm-legit-crash.json"
  # Asymmetric cache semantics: a positive (legitimate) decision is
  # stable across idempotent reruns (auto-bundling and reachability can
  # mutate report fields without changing the underlying crash), so we
  # accept it on require_web match alone. A negative decision still
  # requires the exact evidence hash so a content edit can re-litigate.
  if [ -n "$hash" ] && [ -s "$cache" ] && command -v jq >/dev/null 2>&1; then
    cached_require=$(jq -r '.require_web // ""' "$cache" 2>/dev/null)
    if [ "$cached_require" = "$require_web_gate" ]; then
      cached_legit=$(jq -r '.legitimate' "$cache" 2>/dev/null)
      if [ "$cached_legit" = "true" ]; then
        return 2
      fi
      if [ "$cached_legit" = "false" ] && _triage_cache_sha1_matches "$cache" "evidence_sha1" "$hash"; then
        jq -r '.reason // "cached crash promotion rejection"' "$cache" 2>/dev/null
        return 0
      fi
    fi
  fi

  local prompt
  # Refuse to render with an empty RESULTS_DIR — would expand
  # `{{ results_dir }}/crashes/` to `/crashes/` (absolute under root).
  if [ -z "${RESULTS_DIR:-}" ]; then
    echo "FATAL: triage_legit_crash render called with empty RESULTS_DIR" >&2
    return 1
  fi
  prompt=$(render_prompt_template triage_legit_crash.md.j2 \
    --var "require_web_gate=${require_web_gate}" \
    --var "results_dir=${RESULTS_DIR}" \
    --var "evidence=${evidence}") || return 1

  local json legitimate reason
  json=$(printf '%s' "$prompt" | llm_decide legit_crash "legitimate,reason" 30) || {
    return 1
  }
  legitimate=$(printf '%s' "$json" | jq -r '.legitimate' 2>/dev/null)
  reason=$(printf '%s' "$json" | jq -r '.reason // ""' 2>/dev/null)
  [ -n "$reason" ] && [ "$reason" != "null" ] || reason="crash promotion gate rejected"

  { jq -n --arg require_web "$require_web_gate" \
       --argjson legitimate "$([ "$legitimate" = "true" ] && echo true || echo false)" \
       --arg reason "$reason" \
       '{require_web: $require_web, legitimate: $legitimate, reason: $reason}' \
      | _triage_cache_write_envelope "$cache" "legit_crash" "evidence_sha1" "$hash"; } || true

  if [ "$legitimate" = "true" ]; then
    return 2
  fi
  printf '%s\n' "$reason"
  return 0
}

crash_dir_security_rejection_reason() {
  local d="$1"
  local require_web_gate="${2:-${IS_BROWSER_TARGET:-0}}"

  local static_reason=""
  static_reason=$(crash_dir_static_legitimacy_rejection_reason "$d" "$require_web_gate" 2>/dev/null)
  if [ -n "$static_reason" ]; then
    printf '%s\n' "$static_reason"
    return 0
  fi

  local legitimacy_reason=""
  local legitimacy_status=1
  legitimacy_reason=$(llm_crash_legitimacy_decision "$d" "$require_web_gate" 2>/dev/null)
  legitimacy_status=$?
  if [ -n "$legitimacy_reason" ]; then
    printf '%s\n' "$legitimacy_reason"
    return 0
  fi
  if [ "$legitimacy_status" -eq 2 ]; then
    return 1
  fi

  return 1
}

# Bundle a crash dir via bin/export-repro. Idempotent. Best-effort: a
# failure here doesn't block triage — it just leaves audit-side files in
# place. Logs a warning to $INDEX on failure.
_triage_has_exact_file() {
  local d="$1" want="$2" f
  for f in "$d"/*; do
    [ -e "$f" ] || continue
    [ "${f##*/}" = "$want" ] && [ -s "$f" ] && return 0
  done
  return 1
}

_triage_exact_file_path() {
  local d="$1" want="$2" f
  for f in "$d"/*; do
    [ -e "$f" ] || continue
    if [ "${f##*/}" = "$want" ] && [ -s "$f" ]; then
      printf '%s\n' "$f"
      return 0
    fi
  done
  return 1
}

_triage_bundle_missing_artifacts() {
  local d="$1"
  _triage_has_exact_file "$d" "REPORT.md" || printf '%s\n' "REPORT.md"
  _triage_has_exact_file "$d" "reproduce.sh" || printf '%s\n' "reproduce.sh"
  local diag_path
  diag_path=$(_triage_exact_file_path "$d" "sanitizer.txt" 2>/dev/null || true)
  # Fall back to the legacy alias if a pre-rename bundle is being triaged.
  if [ -z "$diag_path" ]; then
    diag_path=$(_triage_exact_file_path "$d" "asan.txt" 2>/dev/null || true)
  fi
  if [ -n "$diag_path" ]; then
    if ! _triage_has_sanitizer_diagnostic "$diag_path"; then
      printf '%s\n' "sanitizer.txt(valid)"
    fi
  else
    printf '%s\n' "sanitizer.txt"
  fi

  local input_found=0 f base
  for f in "$d"/*; do
    [ -s "$f" ] || continue
    base="${f##*/}"
    case "$base" in
      input.*)
        case "$base" in
          input.asan.txt|input.*.asan.txt|input.msan.txt|input.*.msan.txt|input.tsan.txt|input.*.tsan.txt|input.ubsan.txt|input.*.ubsan.txt)
            continue
            ;;
        esac
        input_found=1
        break
        ;;
    esac
  done
  [ "$input_found" -eq 1 ] || printf '%s\n' "input.*"
}

_triage_has_completed_bundle() {
  local d="$1"
  [ -z "$(_triage_bundle_missing_artifacts "$d")" ] || return 1
  local report="$d/REPORT.md"
  local source_report="$d/.audit/report.md"
  if [ -s "$source_report" ] && [ "$source_report" -nt "$report" ]; then
    return 1
  fi
  return 0
}

_triage_bundle_crash_dir() {
  local d="$1" id="$2" bin_dir="$3"
  [ -x "$bin_dir/export-repro" ] || return 0
  _triage_has_completed_bundle "$d" && return 0

  local audit_dir="$d/.audit"
  mkdir -p "$audit_dir" 2>/dev/null || true
  local out_log="$audit_dir/export-repro.out"
  local err_log="$audit_dir/export-repro.err"
  if "$bin_dir/export-repro" "$id" --slug "${TARGET_SLUG:-}" --crash-dir "$d" >"$out_log" 2>"$err_log"; then
    return 0
  fi
  local reason
  reason=$(grep -m1 -v '^[[:space:]]*$' "$err_log" 2>/dev/null | head -c 220 || true)
  [ -n "$reason" ] || reason="see ${err_log}"
  audit_log "WARN: bin/export-repro failed for crash ${id} (${reason}) — the audit-side bundle is left in place so triage can continue; the upstream-shareable repro tar.gz was not produced this iteration" | tee -a "$INDEX"
}

# Run a single-shot LLM classification pass on the report's narrative to
# fill structured fields the agent did not emit (Surface / Primitive
# class / Caller controls / Caller contract). The result is written to
# ``$d/.llm_fields.json`` so bin/reachability picks it up as a fallback
# — agent-authored fields always win. Best-effort: failure leaves the
# report dir untouched.
#
# Knob: LLM_FIELD_FILL_DISABLE=1 skips the call (also blocked by global
# LLM_DECIDE_DISABLE=1 from lib/llm_decide.sh).
_triage_llm_fill_fields() {
  local d="$1" id="$2"
  [ "${LLM_FIELD_FILL_DISABLE:-0}" = "1" ] && return 0
  command -v jq >/dev/null 2>&1 || return 0
  declare -f llm_decide >/dev/null 2>&1 || return 0
  # Skip if the sidecar already exists for this triage pass — re-running
  # the LLM on every iteration burns budget and rarely changes the answer.
  [ -s "$d/.llm_fields.json" ] && return 0

  local report=""
  if   [ -s "$d/report.md" ]; then report="$d/report.md"
  elif [ -s "$d/REPORT.md" ]; then report="$d/REPORT.md"
  elif [ -s "$d/.audit/report.md" ]; then report="$d/.audit/report.md"
  else return 0
  fi

  # Cheap pre-flight: check whether any of the four target fields are
  # already present in the report. If all are filled, the LLM call adds
  # nothing — skip it. Looks for either `| Surface |` table rows or
  # bare `Surface:` lines.
  local missing=0 fld
  for fld in Surface Primitive 'Caller contract' 'Caller controls'; do
    if ! grep -Eiq "(^\|[[:space:]]*${fld}[[:space:]]*\||^${fld}:)" "$report"; then
      missing=1
      break
    fi
  done
  [ "$missing" = "1" ] || return 0

  # Bound the prompt at ~6KB of narrative — enough for any reasonable
  # report's classification-relevant content without burning tokens on
  # the auto-generated rationale section, which the scorer strips
  # anyway. We just head -c the report; the LLM tolerates truncation.
  local narrative
  narrative=$(head -c 6000 "$report" 2>/dev/null || true)
  [ -n "$narrative" ] || return 0

  local prompt
  prompt=$(render_prompt_template triage_reachability_fields.md.j2 \
    --var "narrative=${narrative}") || return 0

  local out
  out=$(printf '%s' "$prompt" | llm_decide reachability-fields '' 20 2>/dev/null) || return 0
  [ -n "$out" ] || return 0
  # Validate it's a JSON object before writing.
  if printf '%s' "$out" | jq -e 'type=="object"' >/dev/null 2>&1; then
    printf '%s' "$out" > "$d/.llm_fields.json" 2>/dev/null || true
  fi
  return 0
}

# Run bin/reachability against a crash dir after the sanitizer evidence,
# testcase, and report are already present. This is post-processing for
# severity/report annotation, not a discovery or preservation gate.
# Best-effort with a wall-clock cap (REACHABILITY_TIMEOUT, default 180s).
#
# The external-caller search hits Sourcegraph + GitHub APIs serially; on
# popular OSS symbols (hundreds of callers across many repos) those
# round-trips legitimately take 60-120s. A 60s cap was producing empty
# .err logs and a useless "timeout/error; see <empty file>" warning on
# every finding. Default bumped to 180; override via REACHABILITY_TIMEOUT.
#
# REACHABILITY_AUTO controls behaviour:
#   1 / external / unset (default) → query public code-search backends
#                                    (Sourcegraph + GitHub) for external callers.
#                                    This is the default because OSS targets'
#                                    symbol names are already public — the
#                                    reachability signal materially improves
#                                    severity scoring (library_popular tier
#                                    upgrade, callers tilt).
#   local / severity-only          → skip backends; compute severity from
#                                    the report fields only. Use this when
#                                    auditing private code whose symbol
#                                    names should not be exposed to public
#                                    search.
#   0                              → disable the hook entirely.
#
# REACHABILITY_EXTERNAL=1 is a legacy alias for REACHABILITY_AUTO=external.
# Honors REACHABILITY_MOCK_DIR for tests.
_triage_run_reachability() {
  local d="$1" id="$2" bin_dir="$3"
  rm -f "$d/.reachability_ok" "$d/.reachability_pending" "$d/.reachability_failed" 2>/dev/null || true

  local _reach_setting="${REACHABILITY_AUTO:-1}"
  if [ "$_reach_setting" != "1" ] \
     && [ "$_reach_setting" != "external" ] \
     && [ "$_reach_setting" != "local" ] \
     && [ "$_reach_setting" != "severity-only" ]; then
    printf 'disabled by REACHABILITY_AUTO=%s\n' "$_reach_setting" > "$d/.reachability_pending" 2>/dev/null || true
    return 0
  fi

  if [ ! -x "$bin_dir/reachability" ]; then
    printf 'bin/reachability not executable: %s/reachability\n' "$bin_dir" > "$d/.reachability_pending" 2>/dev/null || true
    return 0
  fi
  if [ ! -s "$d/report.md" ] && [ ! -s "$d/REPORT.md" ] && [ ! -s "$d/.audit/report.md" ]; then
    printf 'report missing; reachability waits for report.md or REPORT.md\n' > "$d/.reachability_pending" 2>/dev/null || true
    return 0
  fi

  local _reach_target=()
  [ -n "${TARGET_SLUG:-}" ] && _reach_target=(--target "$TARGET_SLUG")
  # Default is external (full reachability). Opt out with
  # REACHABILITY_AUTO=local or REACHABILITY_AUTO=severity-only.
  local _reach_mode=()
  if [ "$_reach_setting" = "local" ] || [ "$_reach_setting" = "severity-only" ]; then
    _reach_mode=(--severity-only)
  fi
  local audit_dir="$d/.audit"
  mkdir -p "$audit_dir" 2>/dev/null || true
  local out_log="$audit_dir/reachability.out"
  local err_log="$audit_dir/reachability.err"
  local _reach_timeout="${REACHABILITY_TIMEOUT:-180}"
  local rc=0
  if declare -f audit_timeout_run >/dev/null 2>&1; then
    audit_timeout_run "$_reach_timeout" "$bin_dir/reachability" --report "$d" ${_reach_target[@]+"${_reach_target[@]}"} ${_reach_mode[@]+"${_reach_mode[@]}"} >"$out_log" 2>"$err_log"
    rc=$?
  else
    "$bin_dir/reachability" --report "$d" ${_reach_target[@]+"${_reach_target[@]}"} ${_reach_mode[@]+"${_reach_mode[@]}"} >"$out_log" 2>"$err_log"
    rc=$?
  fi
  if [ "$rc" -eq 0 ]; then
    printf 'ok\n' > "$d/.reachability_ok" 2>/dev/null || true
    return 0
  fi
  local reason
  reason=$(grep -m1 -v '^[[:space:]]*$' "$err_log" 2>/dev/null | head -c 220 || true)
  if [ -z "$reason" ]; then
    if [ "$rc" -eq 124 ]; then
      reason="timed out after ${_reach_timeout}s (override via REACHABILITY_TIMEOUT)"
    else
      reason="exit ${rc} with no stderr; see ${err_log}"
    fi
  fi
  printf '%s\n' "$reason" > "$d/.reachability_failed" 2>/dev/null || true
  audit_log "WARN: skipped reachability analysis (severity / caller-chain enrichment) for crash ${id}: ${reason} — the crash dir is preserved without enrichment and other gates still apply" | tee -a "$INDEX"
}

# Move a triaged dir into crashes-rejected/ with an .autodiscard marker.
# Caller has already populated $d/.autodiscard if needed.
_triage_annotate_rejection_report() {
  local d="$1" id="$2" reason="$3"
  local report=""
  if [ -s "$d/REPORT.md" ]; then
    report="$d/REPORT.md"
  elif [ -s "$d/report.md" ]; then
    report="$d/report.md"
  else
    return 0
  fi

  local tmp
  tmp=$(mktemp "${TMPDIR:-/tmp}/rejection-report.XXXXXX") || return 0
  awk -v reason="$reason" '
    function emit_decision() {
      explanation = "The sanitizer diagnostic is preserved for upstream robustness review, but it is not kept as a security crash candidate for this target because the trigger is outside the configured attacker-controlled boundary."
      if (reason ~ /(contract|violat|harness-only|parameter)/) {
        explanation = "The sanitizer diagnostic is preserved for upstream robustness review, but it is not kept as a security crash candidate for this target because reaching it requires a caller action that the projects published docs explicitly forbid, or parameter control outside the documented API contract. If the rejection cites an undocumented or inferred contract, the rejection is likely wrong — promote the crash back to crashes/ and refer to safety_framing.md / triage_legit_crash.md for the documented-prohibition requirement."
      }
      print "## Triage decision"
      print ""
      print "Rejected from `crashes/`: " reason "."
      print ""
      print explanation
      print ""
    }
    BEGIN { inserted=0; skip=0 }
    /^## Triage decision[[:space:]]*$/ { skip=1; next }
    skip && /^## / { skip=0 }
    skip { next }
    !inserted && (/^Summary:[[:space:]]*$/ || /^##[[:space:]]+Summary[[:space:]]*$/) {
      emit_decision()
      inserted=1
    }
    { print }
    END {
      if (!inserted) {
        print ""
        emit_decision()
      }
    }
  ' "$report" > "$tmp" 2>/dev/null && mv "$tmp" "$report" 2>/dev/null || {
    rm -f "$tmp" 2>/dev/null || true
    return 0
  }

  local bin_dir render
  bin_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/../bin" 2>/dev/null && pwd)
  render="$bin_dir/render-md"
  if [ -x "$render" ] && command -v python3 >/dev/null 2>&1; then
    python3 "$render" "$report" --html-sibling --title "$id" >/dev/null 2>&1 || true
  fi
}

# Annotate a crash dir IN PLACE for contract concerns. The dir stays
# in crashes/; the existing reachability scorer rates it low
# (caller_contract=violated triggers a ×0.7 severity multiplier in
# bin/reachability — see test_severity.sh) so the downstream score
# reflects the contract concern without losing the crash from the
# count. Used by triage_crash_dirs step 4 when the static gate or
# verdict matrix returns a `contract-flag:` reason.
#
# Writes a `.contract-flagged` sidecar (machine-readable marker) and
# prepends a "## Contract concern" block to the report (REPORT.md
# preferred, then report.md) so a reviewer opening the dir sees the
# concern in-place.
_triage_annotate_contract_concern() {
  local d="$1" id="$2" reason="$3"
  local report=""
  if [ -s "$d/REPORT.md" ]; then
    report="$d/REPORT.md"
  elif [ -s "$d/report.md" ]; then
    report="$d/report.md"
  fi

  {
    echo "# Contract-flagged by triage_crash_dirs"
    echo "# Reason: $reason"
    echo "# When: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "# Action: dir stays in crashes/. Reachability scorer applies a ×0.7 multiplier on caller_contract=violated, so Severity is automatically deprioritized without losing the crash from the count. Promote back to full severity only if the cited contract is independently disproven."
  } >> "$d/.contract-flagged" 2>/dev/null || true

  [ -n "$report" ] || return 0

  local tmp
  tmp=$(mktemp "${TMPDIR:-/tmp}/contract-flag.XXXXXX") || return 0
  awk -v reason="$reason" '
    function emit_block() {
      print "## Contract concern"
      print ""
      print "Triage kept this crash in `crashes/` and flagged a contract concern: " reason "."
      print ""
      print "The sanitizer diagnostic is real. The downstream reachability scorer rates contract-flagged crashes low automatically (×0.7 multiplier on caller_contract=violated). Promote to a higher Severity only if the concern is independently disproven — e.g. the cited contract is undocumented or inferred, or the reach path does not actually require the prohibited caller action."
      print ""
    }
    BEGIN { inserted=0; skip=0 }
    /^## Contract concern[[:space:]]*$/ { skip=1; next }
    skip && /^## / { skip=0 }
    skip { next }
    !inserted && (/^Summary:[[:space:]]*$/ || /^##[[:space:]]+Summary[[:space:]]*$/) {
      emit_block()
      inserted=1
    }
    { print }
    END {
      if (!inserted) {
        print ""
        emit_block()
      }
    }
  ' "$report" > "$tmp" 2>/dev/null && mv "$tmp" "$report" 2>/dev/null || {
    rm -f "$tmp" 2>/dev/null || true
    return 0
  }

  local bin_dir render
  bin_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/../bin" 2>/dev/null && pwd)
  render="$bin_dir/render-md"
  if [ -x "$render" ] && command -v python3 >/dev/null 2>&1; then
    python3 "$render" "$report" --html-sibling --title "$id" >/dev/null 2>&1 || true
  fi
  return 0
}

# Remove the .promotion_pending marker AND its TTL sidecars.
# Call this whenever a crash dir clears triage validation OR moves out of
# crashes/ so we don't leave a stale counter behind in the move destination.
_triage_clear_promotion_sidecars() {
  local d="$1"
  rm -f "$d/.promotion_pending" \
        "$d/.promotion_pending.sig" \
        "$d/.promotion_pending.count" \
        "$d/.audit/.promotion_pending" \
        "$d/.audit/.promotion_pending.sig" \
        "$d/.audit/.promotion_pending.count" 2>/dev/null || true
}

# Track repeated promotion-pending state across triage passes.
# Returns the (incremented) count via stdout.
#   * Same missing signature as last pass  → count += 1
#   * Different (or first) signature       → count  = 1
# The signature is the sorted, comma-joined missing-set with a scope prefix
# ("missing:" or "bundle:") so a dir transitioning between the two branches
# resets cleanly rather than aggregating unrelated failures.
_triage_bump_promotion_pending() {
  local d="$1" scope="$2"; shift 2
  local sig prev_sig prev_count
  sig=$(printf '%s\n' "$@" | LC_ALL=C sort -u | tr '\n' ',' | sed 's/,$//')
  sig="${scope}:${sig}"
  prev_sig=$(head -n1 "$d/.promotion_pending.sig" 2>/dev/null || true)
  prev_count=$(head -n1 "$d/.promotion_pending.count" 2>/dev/null || true)
  case "$prev_count" in ''|*[!0-9]*) prev_count=0 ;; esac
  local count
  if [ "$sig" = "$prev_sig" ]; then
    count=$((prev_count + 1))
  else
    count=1
  fi
  printf '%s\n' "$sig"   > "$d/.promotion_pending.sig"   2>/dev/null || true
  printf '%s\n' "$count" > "$d/.promotion_pending.count" 2>/dev/null || true
  printf '%s\n' "$count"
}

# Log a false-negative-risk warning BEFORE the rejection move for crash
# dirs that timed out on incomplete artifacts (steps 2 and 3 of
# triage_crash_dirs). These are NOT non-security classes (OOM / panic /
# null-deref) — they are crashes that the agent produced a sanitizer
# diagnostic for but never finished bundling (missing REPORT.md,
# reproduce.sh, valid sanitizer.txt, or a testcase). The dir is still
# preserved on disk in crashes-rejected/ — the warning exists so an
# operator skimming the audit log can spot real bugs lost to bundling /
# reproduction failure without having to grep every crashes-rejected/
# entry by hand.
#
# Also annotates the rejected report with a "## Possible false
# negative" block so a reviewer opening the rejected dir sees the
# warning in-place, not just in the index log.
_triage_log_ttl_false_negative() {
  local d="$1" id="$2" scope="$3" pending_count="$4" max_pending="$5" missing_csv="$6"
  local full_path="$d"
  if command -v readlink >/dev/null 2>&1; then
    local _resolved
    _resolved=$(readlink -f "$d" 2>/dev/null || true)
    [ -n "$_resolved" ] && full_path="$_resolved"
  fi
  local note
  case "$scope" in
    missing) note="agent never produced a valid sanitizer artifact set for this dir" ;;
    bundle)  note="export-repro could not assemble the upstream-shippable bundle for this dir" ;;
    *)       note="bundle/artifact TTL exhausted" ;;
  esac
  audit_log "POSSIBLE-FALSE-NEGATIVE: crashes/${id} aged out of crashes/ after ${pending_count}/${max_pending} incomplete triage passes — ${note}; missing artifact(s): ${missing_csv}. The dir is preserved at crashes-rejected/${id} (full path: ${full_path}). Inspect it before the next benchmark run; the sanitizer signal may be real and this is more likely a bundling/reproduction failure than a non-security class. To make TTL more lenient, raise CRASH_PROMOTION_PENDING_MAX (current=${max_pending})." | tee -a "$INDEX"

  local report=""
  if [ -s "$d/REPORT.md" ]; then
    report="$d/REPORT.md"
  elif [ -s "$d/report.md" ]; then
    report="$d/report.md"
  fi
  [ -n "$report" ] || return 0
  {
    echo ""
    echo "## Possible false negative — incomplete-bundle TTL"
    echo ""
    echo "This crash dir was moved to \`crashes-rejected/\` after ${pending_count}/${max_pending} consecutive triage passes left it incomplete (${note}; missing: ${missing_csv}). It is **not** in the same disposition class as OOM / panic / null-deref autodiscards — those crashes-rejected/ entries are non-security by signal. This one was rejected because the artifact bundle never converged: the sanitizer signal may be real and this is most likely a bundling / reproduction failure."
    echo ""
    echo "Action: review the dir, re-run the agent on the testcase, or raise \`CRASH_PROMOTION_PENDING_MAX\` (current=${max_pending}) to give bundling more passes."
  } >> "$report" 2>/dev/null || true
}

_triage_move_to_rejected() {
  local d="$1" id="$2" reason="$3"
  _triage_annotate_rejection_report "$d" "$id" "$reason"
  _triage_clear_promotion_sidecars "$d"
  local dest="$RESULTS_DIR/crashes-rejected/${id}"
  [ -d "$dest" ] && dest="${dest}.$(date +%Y%m%d_%H%M%S)"
  if mv "$d" "$dest" 2>/dev/null; then
    audit_log "REJECT: crashes/${id} → crashes-rejected/$(basename "$dest") — ${reason}" | tee -a "$INDEX"
    _triage_record_card_reject_skip "$id" "$reason"
    return 0
  fi
  audit_log "WARN: triage tried to move directory '${d}' to '${dest}' but the move failed — the source dir is left in place to avoid losing artifacts; check filesystem permissions / disk space" | tee -a "$INDEX"
  return 1
}

# P5: tell the queue not to re-offer the originating card to the same
# agent. We look up the hypothesis row whose status is the rejected
# crash id, recover its (card_id, agent) pair, and append a marker so
# claim_next_card skips that (card, agent) pair on subsequent claims.
# A different agent may still be offered the same card — bugs can hide
# in a sibling angle on the same surface.
#
# Best-effort: a missing card_id, missing bin/state, or origin lookup
# failure is a no-op (with a single audit_log line so operators see it
# in the index but the rejection itself isn't blocked).
#
# Opt-out via CRASH_REJECT_SKIP_DO_NOT_REVISIT=0 for benchmarks that
# want to measure the un-tightened gate.
_triage_record_card_reject_skip() {
  local id="$1" reason="$2"
  case "${CRASH_REJECT_SKIP_DO_NOT_REVISIT:-1}" in 0|false|no|"") [ "${CRASH_REJECT_SKIP_DO_NOT_REVISIT:-1}" = "0" ] && return 0 ;; esac
  [ "${CRASH_REJECT_SKIP_DO_NOT_REVISIT:-1}" = "0" ] && return 0
  local script_root
  script_root="${SCRIPT_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." 2>/dev/null && pwd)}"
  local state_bin="$script_root/bin/state"
  [ -x "$state_bin" ] || { audit_log "DEBUG: do-not-revisit skip: bin/state not executable at $state_bin"; return 0; }
  [ -n "${RESULTS_DIR:-}" ] || return 0
  local out
  out=$("$state_bin" --results-dir "$RESULTS_DIR" \
      ${TARGET_SLUG:+--target-slug "$TARGET_SLUG"} \
      ${TARGET_ROOT:+--target-path "$TARGET_ROOT"} \
      mark-card-reject-skip --crash-id "$id" --reason "$reason" 2>&1) \
    || { audit_log "DEBUG: do-not-revisit skip for crash ${id}: ${out}"; return 0; }
  # Optional log: parse the card_id from the JSON reply for the index trail.
  if command -v python3 >/dev/null 2>&1; then
    local card_id
    card_id=$(printf '%s' "$out" | python3 -c "import json,sys
try: print(json.loads(sys.stdin.read()).get('card_id',''))
except Exception: print('')" 2>/dev/null)
    [ -n "$card_id" ] && audit_log "REJECT-SKIP: card ${card_id} marked do-not-revisit (rejected crash ${id})" | tee -a "$INDEX"
  fi
  return 0
}

# Move a triaged crash dir into findings/ instead of crashes-rejected/.
# Used when the dir contains a real runtime diagnostic (Python traceback,
# Go panic, Java exception, ...) on a findings-only target. The dir is
# renamed CRASH-<n>-<agent> → FIND-<n>-<agent> so the audit accounting
# treats it as a finding the maintainer can act on rather than a wasted
# crash slot. We rewrite the leading CRASH- prefix only — the agent
# suffix and any extra identifiers are preserved.
_triage_move_to_findings() {
  local d="$1" id="$2" reason="$3"
  _triage_annotate_rejection_report "$d" "$id" "$reason"
  _triage_clear_promotion_sidecars "$d"
  local find_id
  case "$id" in
    CRASH-*) find_id="FIND-${id#CRASH-}" ;;
    *)       find_id="FIND-${id}" ;;
  esac
  local dest="$RESULTS_DIR/findings/${find_id}"
  [ -d "$dest" ] && dest="${dest}.$(date +%Y%m%d_%H%M%S)"
  mkdir -p "$RESULTS_DIR/findings" 2>/dev/null || true
  if mv "$d" "$dest" 2>/dev/null; then
    audit_log "DEMOTE: crashes/${id} → findings/$(basename "$dest") — ${reason}" | tee -a "$INDEX"
    return 0
  fi
  audit_log "WARN: triage tried to move directory '${d}' to '${dest}' but the move failed — the source dir is left in place to avoid losing artifacts; check filesystem permissions / disk space" | tee -a "$INDEX"
  return 1
}

# Dispatch helper: routes a rejected dir to findings/ when the reason
# begins with the `demote-to-findings:` sentinel, else to crashes-rejected.
_triage_route_rejection() {
  local d="$1" id="$2" reason="$3"
  case "$reason" in
    demote-to-findings:*) _triage_move_to_findings "$d" "$id" "$reason" ;;
    *)                    _triage_move_to_rejected "$d" "$id" "$reason" ;;
  esac
}

# Borderline rejections (LLM-confirm uncertainty) go here first instead of
# straight to crashes-rejected/. The crash directory survives a single
# shaky judgement: a second LLM call (next iteration) or a human can promote
# it back. Hard rejections (regex DISCARD class, security-boundary) bypass
# this and go directly to crashes-rejected/ as before.
#
# Override CRASH_REJECT_NEEDS_REVIEW=0 to disable the purgatory entirely
# (every rejection goes to crashes-rejected/ — the historical behavior).
_triage_move_to_needs_review() {
  local d="$1" id="$2" reason="$3"
  if [ "${CRASH_REJECT_NEEDS_REVIEW:-1}" = "0" ]; then
    _triage_move_to_rejected "$d" "$id" "$reason"
    return $?
  fi
  _triage_annotate_rejection_report "$d" "$id" "NEEDS-REVIEW: $reason"
  _triage_clear_promotion_sidecars "$d"
  mkdir -p "$RESULTS_DIR/crashes-needs-review" 2>/dev/null || true
  local dest="$RESULTS_DIR/crashes-needs-review/${id}"
  [ -d "$dest" ] && dest="${dest}.$(date +%Y%m%d_%H%M%S)"
  if mv "$d" "$dest" 2>/dev/null; then
    {
      echo "# Needs-review: borderline rejection"
      echo "# Reason: $reason"
      echo "# When: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
      echo "# Behavior: requeued for review next iteration. To force-reject,"
      echo "#           set CRASH_REJECT_NEEDS_REVIEW=0 or move to crashes-rejected/."
    } > "$dest/.needs-review" 2>/dev/null || true
    audit_log "NEEDS-REVIEW: crashes/${id} → crashes-needs-review/$(basename "$dest") — ${reason}" | tee -a "$INDEX"
    return 0
  fi
  audit_log "WARN: triage tried to move directory '${d}' to '${dest}' but the move failed — the source dir is left in place to avoid losing artifacts; check filesystem permissions / disk space" | tee -a "$INDEX"
  return 1
}

_requeue_crash_needs_review_dirs() {
  [ "${CRASH_REJECT_NEEDS_REVIEW:-1}" = "0" ] && return 0
  [ -d "$RESULTS_DIR/crashes-needs-review" ] || return 0
  mkdir -p "$RESULTS_DIR/crashes" 2>/dev/null || true

  local d id dest requeued=0
  for d in "$RESULTS_DIR"/crashes-needs-review/CRASH-*/; do
    [ -d "$d" ] || continue
    [ -f "$d/.review-requeued" ] && continue
    id=$(basename "$d")
    dest="$RESULTS_DIR/crashes/$id"
    if [ -e "$dest" ]; then
      dest="$RESULTS_DIR/crashes/${id}.review.$(date +%Y%m%d_%H%M%S)"
    fi
    rm -f "$d/.llm-confirm.json" "$d/.needs-review" 2>/dev/null || true
    {
      echo "# Requeued from crashes-needs-review"
      echo "# When: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
      echo "# Reason: second-pass review requested"
    } > "$d/.review-requeued" 2>/dev/null || true
    if mv "$d" "$dest" 2>/dev/null; then
      requeued=$((requeued + 1))
    fi
  done
  [ "$requeued" -gt 0 ] && audit_log "NEEDS-REVIEW: requeued ${requeued} crash dir(s) for second-pass triage" | tee -a "$INDEX" >/dev/null 2>&1 || true
  return 0
}

# ─── Crash triage ─────────────────────────────────────────────────
#
# Order is significant:
#   1. Cheap LLM/regex DISCARD  — kill obvious garbage (null-deref, OOM,
#                                 MOZ_CRASH, panic, stack-overflow) before
#                                 spending any reach budget on it.
#   2. Validate required files  — incomplete dirs get .promotion_pending
#                                 and we wait for the agent to finish.
#   3. Bundle (export-repro)    — convert audit-side names to the
#                                 maintainer bundle layout. Idempotent.
#   4. Security-boundary check  — deterministic caller-contract / trigger
#                                 checks plus crash legitimacy review.
#                                 Reachability score absence is not a
#                                 rejection reason.
#   5. Reachability             — best-effort post-processing. Writes
#                                 reachability.json + Severity into the
#                                 report and .reachability_* status markers.
#                                 Failure never moves a crash out of
#                                 crashes/.
#   6. LLM confirm-agent        — final report sanity review.
triage_crash_dirs() {
  mkdir -p "$RESULTS_DIR/crashes" "$RESULTS_DIR/crashes-rejected" 2>/dev/null || true
  _requeue_crash_needs_review_dirs

  local bin_dir
  bin_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/../bin" 2>/dev/null && pwd)

  local bad=0 rejected=0 d
  for d in "$RESULTS_DIR"/crashes/CRASH-*/; do
    [ -d "$d" ] || continue
    local id
    id=$(basename "$d")

    local asan_path
    asan_path=$(find_primary_asan_in_crash_dir "$d" 2>/dev/null || true)

    # ── 1. LLM/regex DISCARD ─────────────────────────────────────────
    # Three-valued LLM semantics:
    #   rc=0 (DISCARD) → LLM-named reason wins, skip regex.
    #   rc=2 (KEEP)    → regex bypass; do not auto-discard even if it would.
    #   rc=1 (UNDEC)   → fall through to regex.
    local llm_status=1 llm_discard_reason="" regex_says_discard=0
    if [ -n "$asan_path" ]; then
      llm_discard_reason=$(llm_triage_crash_decision "$asan_path" 2>/dev/null)
      llm_status=$?
      is_autodiscard_crash_output "$asan_path" && regex_says_discard=1
    fi

    local discard=0 discard_reason=""
    case "$llm_status" in
      0)  if [ -n "$llm_discard_reason" ]; then
            discard=1
            discard_reason="LLM: $llm_discard_reason"
          fi ;;
      2)  discard=0 ;;
      *)  if [ "$regex_says_discard" -eq 1 ]; then
            discard=1
            discard_reason="non-finding class (null-deref/OOM/MOZ_CRASH/panic/stack-overflow)"
          fi ;;
    esac

    if [ "$discard" -eq 1 ]; then
      if [ ! -f "$d/.autodiscard" ]; then
        {
          echo "# Auto-rejected by triage_crash_dirs"
          echo "# Reason: $discard_reason"
          echo "# Source: $(basename "${asan_path:-unknown}")"
          [ -n "$asan_path" ] && grep -E 'ERROR: AddressSanitizer|SCARINESS|Hint: address|MOZ_CRASH|panicked|allocation-size|stack-overflow|SIGABRT' \
            "$asan_path" 2>/dev/null | head -6 || true
        } > "$d/.autodiscard" 2>/dev/null || true
      fi
      _triage_move_to_rejected "$d" "$id" "$discard_reason" && rejected=$((rejected + 1))
      continue
    fi

    # ── 2. Validate required files ─────────────────────────────────
    # Accept the pre-bundle lowercase report.md, the finished bundle
    # REPORT.md, or the migrated audit-side .audit/report.md. The last
    # form is important when a previous export-repro pass partially bundled
    # the dir: it moves report.md into .audit/ before installing the final
    # REPORT.md, so a failed install leaves only .audit/report.md and the
    # next pass must still be able to re-run export-repro cleanly.
    # For sanitizer output: the bundle has sanitizer.txt at root (legacy:
    # asan.txt); pre-bundle dirs may have *_confirm.asan.txt / *.asan.txt only.
    local missing=()
    if [ ! -s "$d/report.md" ] && [ ! -s "$d/REPORT.md" ] && [ ! -s "$d/.audit/report.md" ]; then
      missing+=("report.md")
    fi
    local asan_ok=0
    if [ -n "$asan_path" ] && _triage_has_sanitizer_diagnostic "$asan_path"; then
      asan_ok=1
    elif [ -s "$d/sanitizer.txt" ] && _triage_has_sanitizer_diagnostic "$d/sanitizer.txt"; then
      asan_ok=1
    elif [ -s "$d/asan.txt" ] && _triage_has_sanitizer_diagnostic "$d/asan.txt"; then
      asan_ok=1
    fi
    # Findings-only targets ([sanitizer] enabled = []) have no ASan output
    # to validate. Accept the dir if it has SOME diagnostic file — either
    # a sanitizer trace (covered above) OR a runtime crash signal in the
    # captured output. crash_dir_has_runtime_diagnostic_signal looks for
    # language-runtime panics / tracebacks / race-detector banners.
    if [ "$asan_ok" -ne 1 ] && crash_dir_is_findings_only_target \
       && crash_dir_has_runtime_diagnostic_signal "$d"; then
      asan_ok=1
    fi
    [ "$asan_ok" -eq 1 ] || missing+=("sanitizer.txt(valid)")
    local tc_ok=0 testcase_path=""
    testcase_path=$(find_primary_testcase_in_crash_dir "$d" 2>/dev/null || true)
    [ -n "$testcase_path" ] && tc_ok=1
    [ "$tc_ok" -eq 1 ] || missing+=("testcase(>=${CRASH_TC_MIN_BYTES:-1}B, non-sidecar)")
    if [ "${#missing[@]}" -gt 0 ]; then
      local max_pending="${CRASH_PROMOTION_PENDING_MAX:-10}"
      case "$max_pending" in ''|*[!0-9]*) max_pending=10 ;; esac
      local pending_count
      pending_count=$(_triage_bump_promotion_pending "$d" missing "${missing[@]}")
      printf '%s\n' "${missing[@]}" > "$d/.promotion_pending" 2>/dev/null || true
      if [ "$pending_count" -ge "$max_pending" ]; then
        local missing_csv
        missing_csv=$(printf '%s,' "${missing[@]}" | sed 's/,$//')
        local ttl_reason="never-reproduced-under-sanitizer: missing ${missing_csv} across ${pending_count} triage passes"
        if [ ! -f "$d/.autodiscard" ]; then
          {
            echo "# Auto-rejected by triage_crash_dirs (promotion-pending TTL)"
            echo "# Reason: ${ttl_reason}"
            echo "# Threshold: CRASH_PROMOTION_PENDING_MAX=${max_pending}"
          } > "$d/.autodiscard" 2>/dev/null || true
        fi
        _triage_log_ttl_false_negative "$d" "$id" missing "$pending_count" "$max_pending" "$missing_csv"
        _triage_move_to_rejected "$d" "$id" "$ttl_reason" && rejected=$((rejected + 1))
        continue
      fi
      bad=$((bad + 1))
      audit_log_throttled "incomplete-${id}" "WARN: crashes/${id} incomplete (pass ${pending_count}/${max_pending}) — missing: ${missing[*]}" | tee -a "$INDEX"
      continue
    fi

    if crash_dir_is_findings_only_target \
       && crash_dir_has_runtime_diagnostic_signal "$d" \
       && ! crash_dir_has_memory_safety_asan_signal "$d"; then
      local runtime_demote_reason="demote-to-findings: runtime diagnostic without sanitizer-class memory-safety signal"
      _triage_route_rejection "$d" "$id" "$runtime_demote_reason" && rejected=$((rejected + 1))
      continue
    fi

    # NOTE: do NOT clear .promotion_pending sidecars here. The bump
    # function below treats sig changes (e.g., missing: → bundle:) as a
    # reset to count=1 already, so clearing between steps 2 and 3 just
    # wiped the bundle-scope counter every pass and made the TTL
    # auto-reject branch unreachable for export-repro failures.
    # Sidecars get cleared only on actual triage success (after step 3
    # passes, see _triage_clear_promotion_sidecars below) or on move
    # to crashes-rejected/.

    # ── 3. Bundle (export-repro) ───────────────────────────────────
    _triage_bundle_crash_dir "$d" "$id" "$bin_dir"
    local bundle_missing
    bundle_missing=$(_triage_bundle_missing_artifacts "$d" 2>/dev/null || true)
    if [ -n "$bundle_missing" ]; then
      local max_pending="${CRASH_PROMOTION_PENDING_MAX:-10}"
      case "$max_pending" in ''|*[!0-9]*) max_pending=10 ;; esac
      local bundle_csv
      bundle_csv=$(printf '%s' "$bundle_missing" | tr '\n' ',' | sed 's/,$//')
      local pending_count
      # Pass the missing list one-per-arg so the signature is stable.
      local IFS_save="$IFS"; IFS=$'\n'
      local -a bundle_arr=($bundle_missing)
      IFS="$IFS_save"
      pending_count=$(_triage_bump_promotion_pending "$d" bundle "${bundle_arr[@]}")
      printf '%s\n' "$bundle_missing" > "$d/.promotion_pending" 2>/dev/null || true
      if [ "$pending_count" -ge "$max_pending" ]; then
        local ttl_reason="bundle-incomplete: missing ${bundle_csv} across ${pending_count} triage passes"
        if [ ! -f "$d/.autodiscard" ]; then
          {
            echo "# Auto-rejected by triage_crash_dirs (promotion-pending TTL)"
            echo "# Reason: ${ttl_reason}"
            echo "# Threshold: CRASH_PROMOTION_PENDING_MAX=${max_pending}"
          } > "$d/.autodiscard" 2>/dev/null || true
        fi
        _triage_log_ttl_false_negative "$d" "$id" bundle "$pending_count" "$max_pending" "$bundle_csv"
        _triage_move_to_rejected "$d" "$id" "$ttl_reason" && rejected=$((rejected + 1))
        continue
      fi
      bad=$((bad + 1))
      audit_log_throttled "bundle-${id}" "WARN: crashes/${id} incomplete bundle (pass ${pending_count}/${max_pending}) — missing: ${bundle_csv}" | tee -a "$INDEX"
      continue
    fi
    _triage_clear_promotion_sidecars "$d"

    # ── 4. Security-boundary check ─────────────────────────────────
    # This check separates three dispositions:
    #   - HARD reject (missing security evidence, web-only on browser
    #     target): move to crashes-rejected/. These are the
    #     no-sanitizer-signal / wrong-threat-boundary cases that
    #     crashes-rejected/ exists for, alongside Step 1 autodiscards
    #     (OOM / panic / null-deref).
    #   - SOFT contract-flag (verdict=contract-flag from the matrix,
    #     callback-releases-active regex, private/internal include
    #     regex): annotate IN PLACE with a .contract-flagged sidecar
    #     + "## Contract concern" report block and KEEP in crashes/.
    #     The downstream reachability scorer applies a ×0.7 multiplier
    #     when caller_contract=violated (see test_severity.sh), so
    #     these are automatically deprioritized in Severity without
    #     being lost from the crashes/ count or the
    #     reachability/scoring pipeline.
    #   - demote-to-findings: existing path, routed through
    #     _triage_route_rejection.
    # This check must not depend on bin/reachability output.
    local security_reject_reason=""
    security_reject_reason=$(crash_dir_security_rejection_reason "$d" 2>/dev/null || true)
    if [ -n "$security_reject_reason" ]; then
      case "$security_reject_reason" in
        contract-flag:*)
          local flag_reason="${security_reject_reason#contract-flag: }"
          _triage_annotate_contract_concern "$d" "$id" "$flag_reason"
          audit_log "CONTRACT-FLAG: crashes/${id} kept in crashes/ with contract-concern annotation — ${flag_reason}. Reachability scorer will rate this low (×0.7 multiplier on caller_contract=violated)." | tee -a "$INDEX"
          ;;
        *)
          if [ ! -f "$d/.autodiscard" ]; then
            {
              echo "# Auto-rejected by triage_crash_dirs"
              echo "# Reason: $security_reject_reason"
              if [ "${IS_BROWSER_TARGET:-0}" -eq 1 ]; then
                echo "# Requirement: crashes/ keeps only security-relevant, plausibly web/content-reachable crash candidates"
              else
                echo "# Requirement: crashes/ keeps only security-relevant crash candidates from legitimate public API/input boundaries"
              fi
              echo "# Source: $(basename "${asan_path:-unknown}")"
            } > "$d/.autodiscard" 2>/dev/null || true
          fi
          _triage_route_rejection "$d" "$id" "$security_reject_reason" && rejected=$((rejected + 1))
          continue
          ;;
      esac
    fi

    # ── 5. Reachability post-processing ────────────────────────────
    # Best-effort severity/report enrichment only. Failure is recorded via
    # .reachability_failed and never blocks crash preservation. The LLM
    # hybrid pass fills any missing structured fields before scoring.
    _triage_llm_fill_fields "$d" "$id"
    _triage_run_reachability "$d" "$id" "$bin_dir"

    # ── 6. LLM confirm-agent (final pre-promotion gate) ────────────
    # Looks at the finished, bundled report.md and asks
    # whether it is genuinely fileable upstream. Cached by report SHA-1
    # so unchanged reports are free on rerun. Disabled targets / LLM
    # unavailable → undecided → fall through (existing behavior).
    if [ "${CRASH_CONFIRM_AUTO:-1}" = "1" ]; then
      local confirm_report=""
      local _f
      for _f in "$d/REPORT.md" "$d/report.md" "$d/.audit/report.md"; do
        [ -s "$_f" ] && { confirm_report="$_f"; break; }
      done
      if [ -n "$confirm_report" ]; then
        local confirm_reason="" confirm_status=1
        confirm_reason=$(llm_confirm_crash_report "$confirm_report" 2>/dev/null)
        confirm_status=$?
        if [ "$confirm_status" -eq 0 ] && [ -n "$confirm_reason" ]; then
          if [ ! -f "$d/.autodiscard" ]; then
            {
              echo "# Auto-rejected by triage_crash_dirs (LLM confirm-agent)"
              echo "# Reason: LLM-CONFIRM: $confirm_reason"
              echo "# Source: $(basename "$confirm_report")"
            } > "$d/.autodiscard" 2>/dev/null || true
          fi
          _triage_move_to_needs_review "$d" "$id" "LLM-CONFIRM: $confirm_reason" && rejected=$((rejected + 1))
          continue
        fi
      fi
    fi
  done
  [ "$bad" -gt 0 ] && audit_log_throttled "promotion-pending-total" "WARN: ${bad} crash dir(s) need promotion completion (see .promotion_pending)" | tee -a "$INDEX"
  [ "$rejected" -gt 0 ] && audit_log "REJECT: ${rejected} crash dir(s) moved to crashes-rejected/ this iteration" | tee -a "$INDEX"
  return 0
}

# ── Persistent harness build-failure tally ─────────────────────────
# Per-testcase C/C++ harness compile failures are cached under
# scratch-*/.harness-cache/<stem>.<hash>.build.log. They are visible to
# the LLM via probe stderr, but never surface to the operator. When the
# cache accumulates past a threshold, post a single warning to INDEX with
# a link to the most recent log and a short head digest, so:
#   * the operator notices a systemic toolchain/config problem early
#   * the LLM's next prompt (which scans this WARN line via index.log)
#     gets a clear cue to read the build log and adjust target.toml /
#     harness #includes instead of just retrying.
#
# Threshold: BUILD_FAILURE_WARN_THRESHOLD (default 25). Increment of the
# threshold also fires (50, 75, ...) so repeated regression is visible.
warn_persistent_harness_build_failures() {
  [ -d "$RESULTS_DIR" ] || return 0
  local threshold="${BUILD_FAILURE_WARN_THRESHOLD:-25}"
  case "$threshold" in ''|*[!0-9]*) threshold=25 ;; esac
  [ "$threshold" -gt 0 ] || return 0

  local total=0 latest="" latest_mtime=0 f mtime
  while IFS= read -r -d '' f; do
    [ -s "$f" ] || continue
    total=$((total + 1))
    # audit_stat_mtime_epoch is the portable wrapper around stat. The
    # previous open-coded `stat -f '%m' || stat -c '%Y'` chain tripped
    # on GNU stat, which accepts `-f` to mean filesystem-status and
    # spilled multi-line output into the numeric `[ -gt ]` test below.
    mtime=$(audit_stat_mtime_epoch "$f")
    if [ -z "$latest" ] || [ "$mtime" -gt "$latest_mtime" ]; then
      latest="$f"
      latest_mtime="$mtime"
    fi
  done < <(find "$RESULTS_DIR" -maxdepth 4 -path '*/.harness-cache/*.build.log' \
              -type f -print0 2>/dev/null)

  [ "$total" -ge "$threshold" ] || return 0

  local stamp="${LOGDIR:-$RESULTS_DIR/../logs}/.harness_build_failures_warned"
  local prev=0
  prev=$(head -n1 "$stamp" 2>/dev/null || echo 0)
  case "$prev" in ''|*[!0-9]*) prev=0 ;; esac
  # Re-warn only on each threshold boundary crossing.
  local current_band prev_band
  current_band=$(( total / threshold ))
  prev_band=$(( prev / threshold ))
  if [ "$current_band" -le "$prev_band" ] && [ "$prev" -gt 0 ]; then
    return 0
  fi
  printf '%s\n' "$total" > "$stamp" 2>/dev/null || true

  local head_lines=""
  if [ -n "$latest" ] && [ -s "$latest" ]; then
    head_lines=$(grep -m3 -E 'error:|fatal error:|undefined (reference|symbol)|ld: ' "$latest" 2>/dev/null \
                  | sed -e 's/[[:space:]]\+/ /g' -e 's/^[[:space:]]*//' \
                  | head -c 400)
    [ -n "$head_lines" ] || head_lines=$(head -3 "$latest" 2>/dev/null | sed -e 's/[[:space:]]\+/ /g' | head -c 400)
  fi

  audit_log "WARN: persistent harness build failures — ${total} cached log(s) under ${RESULTS_DIR}/scratch-*/.harness-cache/" | tee -a "$INDEX"
  if [ -n "$latest" ]; then
    audit_log "WARN: most recent failure: ${latest}" | tee -a "$INDEX"
    [ -n "$head_lines" ] && audit_log "WARN: ${head_lines}" | tee -a "$INDEX"
  fi
  audit_log "WARN: if these repeat, edit ${SCRIPT_ROOT:-..}/output/${TARGET_SLUG:-<slug>}/target.toml (includes / link_libs) or fix harness #include order; mark hypothesis ENV-BLOCKED if unfixable" | tee -a "$INDEX"

  # ── LLM-based target.toml auto-repair ───────────────────────────
  # Off-by-default safety rail flipped on when we have a backend AND
  # a real build log to look at. The helper is idempotent and rate-
  # limits itself via a digest marker in $LOGDIR, so calling it on
  # every threshold-band warn is cheap.
  _triage_attempt_auto_repair_target_toml "$latest"
  return 0
}

# Best-effort wrapper around bin/auto-repair-target-toml. Logs each
# attempt via audit_log so a maintainer scrolling index.log can see
# whether the repair fired and whether it succeeded.
#
# Knobs:
#   TARGET_TOML_AUTO_REPAIR=0  — disables the helper entirely (default
#                                 is "on, but only when an LLM backend
#                                 is reachable")
#   LLM_DECIDE_DISABLE=1       — also short-circuits (covers tests)
_triage_attempt_auto_repair_target_toml() {
  local build_log="$1"
  [ -n "$build_log" ] || return 0
  [ -s "$build_log" ] || return 0
  [ "${TARGET_TOML_AUTO_REPAIR:-1}" != "0" ] || return 0

  # Resolve target.toml. Prefer the active RESULTS_DIR namespace so
  # experiment runs repair output/<slug>-<experiment>/target.toml, then
  # fall back to the base slug config for legacy callers.
  local script_root="${SCRIPT_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
  local slug="${TARGET_SLUG:-}"
  local toml_path=""
  if declare -F target_toml_from_results >/dev/null 2>&1; then
    toml_path="$(target_toml_from_results "${RESULTS_DIR:-}" 2>/dev/null || true)"
    [ -f "$toml_path" ] || toml_path=""
  fi
  if [ -z "$toml_path" ] && [ -n "$slug" ] && [ -f "$script_root/output/$slug/target.toml" ]; then
    toml_path="$script_root/output/$slug/target.toml"
  elif [ -z "$toml_path" ] && [ -f "${RESULTS_DIR:-/nonexistent}/../target.toml" ]; then
    toml_path="$(cd "$RESULTS_DIR/.." && pwd)/target.toml"
  fi
  [ -n "$toml_path" ] && [ -f "$toml_path" ] || return 0

  local helper="$script_root/bin/auto-repair-target-toml"
  [ -x "$helper" ] || return 0

  # The build-log path encodes the harness basename (H-<id>-<name>.c.<sha>.build.log).
  # Glob the matching harness source so the LLM sees what was being compiled.
  local harness_arg=()
  local harness_base
  harness_base=$(basename "$build_log" 2>/dev/null | sed -E 's/\.[0-9a-f]{20,}\.build\.log$//')
  if [ -n "$harness_base" ]; then
    local scratch_dir
    scratch_dir=$(dirname "$build_log" 2>/dev/null)
    scratch_dir="${scratch_dir%/.harness-cache}"
    local candidate=""
    for ext in c cc cpp cxx; do
      if [ -f "$scratch_dir/${harness_base}.${ext}" ]; then
        candidate="$scratch_dir/${harness_base}.${ext}"
        break
      fi
    done
    [ -n "$candidate" ] && harness_arg=(--harness "$candidate")
  fi

  local logdir_arg=()
  [ -n "${LOGDIR:-}" ] && logdir_arg=(--logdir "$LOGDIR")

  local out=""
  if out=$("$helper" --toml "$toml_path" --build-log "$build_log" \
                     "${harness_arg[@]}" "${logdir_arg[@]}" 2>&1); then
    audit_log "INFO: target.toml auto-repair: applied or no-op (${toml_path##*/output/})" | tee -a "$INDEX"
  else
    local rc=$?
    # Only escalate to a user-visible WARN when the helper actively
    # refused (rc=2) or hard-failed. rc=1 just means "no proposal" /
    # "disabled" — quiet path.
    if [ "$rc" -ge 2 ]; then
      audit_log "WARN: target.toml auto-repair refused proposal — see ${LOGDIR:-$RESULTS_DIR/../logs}/target-toml-auto-repair.log" | tee -a "$INDEX"
    fi
  fi
  return 0
}

# LLM FIND substance + classifier. Single open-ended call: the prompt
# does NOT enumerate allowed issue classes (that would bias the model
# against unfamiliar ones). It asks "is this a concrete SECURITY
# finding with security implications?" and, if yes, requests a freeform
# class label the model picks. Pure correctness / data-integrity /
# robustness bugs without a security boundary crossing are REJECTED —
# QA teams only triage security issues from this pipeline.
#
# The verdict is written inline to .llm-find-quality.json in the FIND
# dir. validate_find_gate uses the cache to decide whether to keep or
# delete the dir; this helper itself does not move files.
#
#   accept=true   → .llm-find-quality.json carries accept=true + class
#                   + reason. FIND is considered substantive security.
#   accept=false  → .llm-find-quality.json carries accept=false + reason.
#                   Caller will drop the dir unless .keep / .reviewed
#                   pins it.
#   undecided     → .llm-find-quality.json is left alone; no caller action.
#
# Returns 0 on success (cache written), 1 if LLM unavailable / undecided.
llm_find_quality_decision() {
  local desc_path="$1" find_dir="${2:-}"
  declare -f llm_decide >/dev/null 2>&1 || return 1
  [ -s "$desc_path" ] || return 1
  [ -n "$find_dir" ] || find_dir=$(dirname "$desc_path")

  # Bump when the prompt/criteria change so stale cached verdicts from
  # older rubrics don't apply to the current gate.
  # v4 added dedup_key for cluster-findings.
  # v5 tightens the rubric to reject non-security correctness bugs
  # (data-integrity, robustness, missing-feature, semantic mismatch)
  # so QA only sees actual security issues.
  # v6 inverts the in-doubt default to ACCEPT (a false-reject
  # permanently hides a real bug; a false-accept just costs QA time)
  # and tracks reject_count so the gate requires TWO independent
  # reject verdicts before dropping (handled by validate_find_gate).
  # v7 flips the rubric to "Reject only if ALL of these clearly fail"
  # (rather than "Accept ONLY if ALL hold") and removes the
  # auto-reject on self-deprecating hedging in Impact/Reachability
  # notes; reviewers now judge the substance, not the writeup tone.
  local decision_version="v7"

  local hash cache
  hash=$(_triage_file_sha1 "$desc_path" 2>/dev/null || true)
  cache="$find_dir/.llm-find-quality.json"
  # reject_count is stored in a SEPARATE marker file rather than in the
  # cache because cluster-findings stamps `Cluster:` lines into report.md
  # at the end of each triage pass, which changes the content hash and
  # would otherwise reset the counter every time. The marker tracks
  # "how many independent reject verdicts has THIS find directory
  # received", which is what we actually want for quorum.
  local reject_marker="$find_dir/.find_reject_count"
  local prev_reject_count=0
  if [ -s "$reject_marker" ]; then
    prev_reject_count=$(head -c 16 "$reject_marker" 2>/dev/null | tr -cd '0-9')
    [ -n "$prev_reject_count" ] || prev_reject_count=0
  fi
  # Cache short-circuits the LLM only when the cached verdict is accept
  # OR reject_count has already reached the quorum threshold (default
  # 2). Otherwise we re-ask to get a second independent opinion. The
  # content hash + version check still applies for accepts: if the
  # report content changed, re-evaluate.
  # Cache hit also requires decision_version to match — bumping the
  # rubric (decision_version) intentionally invalidates older verdicts.
  if _triage_cache_sha1_matches "$cache" "content_sha1" "$hash"; then
    local cached_version cached_accept
    cached_version=$(jq -r '.decision_version // ""' "$cache" 2>/dev/null)
    cached_accept=$(jq -r '.accept' "$cache" 2>/dev/null)
    if [ "$cached_version" = "$decision_version" ]; then
      if [ "$cached_accept" = "true" ]; then
        return 0
      fi
      if [ "$cached_accept" = "false" ] && [ "$prev_reject_count" -ge 2 ]; then
        return 0
      fi
    fi
  fi

  local body
  body=$(head -c 8000 "$desc_path" 2>/dev/null) || return 1

  # Collect existing dedup_keys from sibling FINDs so the LLM can REUSE a
  # canonical key when the new finding matches a known root cause. Without
  # this, two FINDs about the same root cause filed in separate sessions
  # get two different dedup_keys and Layer 2 fails to collapse them.
  # Wrapped in `|| true` so any one segment failing (grep on empty input,
  # jq on missing files) doesn't abort the function under pipefail.
  local known_keys=""
  if command -v jq >/dev/null 2>&1 && [ -d "${RESULTS_DIR:-}/findings" ]; then
    known_keys=$( { jq -r 'select(.accept == true) | .dedup_key // empty' \
                       "$RESULTS_DIR"/findings/FIND-*/.llm-find-quality.json \
                       2>/dev/null \
                    | sort -u \
                    | grep -v '^$' \
                    | head -40 \
                    | paste -sd, - 2>/dev/null; } || true )
  fi
  local known_keys_block=""
  if [ -n "$known_keys" ]; then
    known_keys_block=$(printf 'Existing canonical dedup_keys in this audit (reuse one if your finding matches that root cause):\n%s\n\n' "$known_keys")
  fi

  local prompt
  prompt=$(render_prompt_template triage_find_quality.md.j2 \
    --var "known_keys_block=${known_keys_block}" \
    --var "body=${body}") || return 1

  local json
  # dedup_key is OPTIONAL — older mock/backend outputs may omit it. We
  # keep it out of the required CSV so the validator doesn't reject a
  # response that's otherwise valid; the jq read below tolerates a
  # missing field via `// ""`.
  json=$(printf '%s' "$prompt" | llm_decide find_quality "accept,reason,class,severity" 14) || return 1
  local accept reason class severity dedup_key
  accept=$(printf '%s' "$json" | jq -r '.accept' 2>/dev/null)
  reason=$(printf '%s' "$json" | jq -r '.reason' 2>/dev/null)
  class=$(printf '%s' "$json" | jq -r '.class // ""' 2>/dev/null)
  severity=$(printf '%s' "$json" | jq -r '.severity // ""' 2>/dev/null)
  dedup_key=$(printf '%s' "$json" | jq -r '.dedup_key // ""' 2>/dev/null)

  case "$accept" in
    true|false) ;;
    *) return 1 ;;
  esac

  [ "$reason" = "null" ] && reason=""
  [ "$class" = "null" ] && class=""
  [ "$severity" = "null" ] && severity=""
  [ "$dedup_key" = "null" ] && dedup_key=""

  # Lower-case + tighten the dedup_key. Invalid keys are dropped — the
  # downstream signature falls back to (class, file, func).
  if [ -n "$dedup_key" ]; then
    dedup_key=$(printf '%s' "$dedup_key" \
                | tr '[:upper:]' '[:lower:]' \
                | tr ' ' '-' \
                | tr -cd 'a-z0-9_-' \
                | head -c 60)
    case "$dedup_key" in
      *[!a-z0-9_-]*|"") dedup_key="" ;;
    esac
    # Require at least one hyphen or underscore (multi-token).
    case "$dedup_key" in
      *[-_]*) ;;
      *)      dedup_key="" ;;
    esac
    if [ ${#dedup_key} -lt 4 ]; then
      dedup_key=""
    fi
  fi

  if [ "$accept" = "true" ]; then
    [ -n "$reason" ] || reason="LLM accepted finding"
    rm -f "$find_dir/.needs-attention" 2>/dev/null || true
    # Accept resets the reject counter — a later content edit that
    # produced an accept should not still carry old reject signal.
    rm -f "$reject_marker" 2>/dev/null || true
    { jq -n --arg reason "$reason" --arg class "$class" \
         --arg severity "$severity" --arg dedup_key "$dedup_key" \
         --arg version "$decision_version" \
         '{decision_version: $version, accept: true, reason: $reason, class: $class, severity: $severity, dedup_key: $dedup_key}' \
        | _triage_cache_write_envelope "$cache" "find_quality" "content_sha1" "$hash"; } || true
    return 0
  fi

  # accept=false: increment reject_count in the marker file and record
  # the verdict in the cache. The caller (validate_find_gate) only
  # quarantines once reject_count reaches the quorum (default 2) — two
  # independent verdicts guard against single-call LLM noise that would
  # permanently hide a real bug.
  [ -n "$reason" ] || reason="LLM marked finding as non-security"
  local new_reject_count=$((prev_reject_count + 1))
  printf '%s\n' "$new_reject_count" > "$reject_marker" 2>/dev/null || true
  { jq -n --arg reason "$reason" --arg version "$decision_version" \
       --argjson reject_count "$new_reject_count" \
       '{decision_version: $version, accept: false, reason: $reason, class: "", severity: "", dedup_key: "", reject_count: $reject_count}' \
      | _triage_cache_write_envelope "$cache" "find_quality" "content_sha1" "$hash"; } || true
  return 0
}

# ─── FIND enrichment + index gate ──────────────────────────────────
# This pipeline only keeps SECURITY findings. Non-security correctness /
# data-integrity / robustness bugs are rejected out of findings/ — QA teams
# shouldn't see them in the confirmed finding set. Pipeline:
#   1. Find a non-empty report file. If missing → drop .needs-content
#      marker (still in findings/, just flagged).
#   2. Ask the LLM whether it is a substantive security finding and
#      how to classify it. Verdict cached inline in .llm-find-quality.json.
#   3. If the verdict is accept=false at quorum, move the FIND dir to
#      findings-rejected/ (override: .keep / .reviewed pins it). The audit log
#      records the reject reason.
#   4. Run bin/reachability against surviving FIND dirs for caller /
#      severity annotation (same helper crashes use).
#   5. report.md → report.html sibling render happens in maintain_indexes
#      so the artifact set matches crashes/.
validate_find_gate() {
  local bin_dir
  bin_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/../bin" 2>/dev/null && pwd)

  # Augment-don't-refile dedup: any agent-filed FIND-* whose
  # (file,function) signature matches an existing FIND-RECON-* gets
  # moved to findings-rejected/ before the rest of the gate runs. The
  # prompt instructs agents to augment recon-materialized FINDs, but
  # prompt compliance is soft — this sweep is the mechanical guarantee
  # that an ignored prompt cannot inflate the headline finding count.
  # Safe to call every gate pass: dedupe_recon_findings is idempotent
  # (returns 0 moves once the duplicates are gone).
  local script_root
  script_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." 2>/dev/null && pwd)
  if [ -x "$script_root/lib/recon_to_cards.py" ] \
      && [ -d "$RESULTS_DIR/findings" ]; then
    python3 "$script_root/lib/recon_to_cards.py" --dedupe-only \
      --results-dir "$RESULTS_DIR" \
      ${TARGET_ROOT:+--target-path "$TARGET_ROOT"} 2>&1 \
      | sed 's/^/[find-dedup] /' >> "$INDEX" 2>/dev/null || true
  fi

  local d
  for d in "$RESULTS_DIR"/findings/FIND-*/; do
    [ -d "$d" ] || continue
    local id
    id=$(basename "$d")

    [ -f "$d/.reviewed" ] || [ -f "$d/.keep" ] && continue

    # Find a non-empty narrative. Any of these qualifies.
    local desc="" c
    for c in "$d/report.md" "$d/description.md" "$d/analysis.md" "$d/README.md"; do
      [ -s "$c" ] && { desc="$c"; break; }
    done
    [ -z "$desc" ] && desc=$(find "$d" -maxdepth 1 -type f -name '*.md' -size +0c 2>/dev/null | head -1)
    [ -z "$desc" ] && desc=$(find "$d" -maxdepth 1 -type f \( -name '*.html' -o -name '*.htm' \) -size +0c 2>/dev/null | head -1)

    if [ -z "$desc" ]; then
      {
        echo "Marker: needs-content"
        echo "When: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
        echo "Reason: no report file (report.md / description.md / report.html) in FIND dir"
        echo "Hint: write a report describing the security issue, then re-run triage."
      } > "$d/.needs-content" 2>/dev/null || true
      continue
    fi
    # Clear stale "missing content" marker now that we have a report.
    rm -f "$d/.needs-content" 2>/dev/null || true

    # LLM substance + classification. Writes verdict cache inline.
    llm_find_quality_decision "$desc" "$d" >/dev/null 2>&1 || true

    # Drop non-security findings: this pipeline only keeps
    # security-relevant FINDs. Override via .keep / .reviewed (checked
    # at the top of the loop, so we only reach here without those).
    #
    # We never delete: a rejected FIND is MOVED to findings-rejected/<id>/
    # so QA can audit false-rejects and recover bugs the LLM gate threw
    # away. We also require TWO independent LLM reject verdicts on the
    # same content (reject_count >= 2 in the cache) before quarantining
    # — single-call LLM noise should not permanently hide a real bug.
    # Tunables: FIND_GATE_QUORUM (default 2), FIND_GATE_QUARANTINE_DIR
    # (default $RESULTS_DIR/findings-rejected).
    local cache="$d/.llm-find-quality.json"
    if [ -s "$cache" ] && command -v jq >/dev/null 2>&1; then
      # NB: do not use `.accept // ""` — jq's // treats `false` as falsy
      # and would coerce a legitimate reject verdict into the empty string.
      local accept reason reject_count quorum reject_marker
      accept=$(jq -r '.accept' "$cache" 2>/dev/null)
      reason=$(jq -r '.reason // ""' "$cache" 2>/dev/null)
      # reject_count is authoritative in the marker file, not the cache,
      # because cluster-findings rewrites report.md (changing the cache
      # content_sha1) and we'd otherwise lose the counter between passes.
      reject_marker="$d/.find_reject_count"
      if [ -s "$reject_marker" ]; then
        reject_count=$(head -c 16 "$reject_marker" 2>/dev/null | tr -cd '0-9')
        [ -n "$reject_count" ] || reject_count=0
      else
        reject_count=0
      fi
      quorum="${FIND_GATE_QUORUM:-2}"
      case "$quorum" in ''|*[!0-9]*) quorum=2 ;; esac
      if [ "$accept" = "false" ]; then
        if [ "$reject_count" -ge "$quorum" ]; then
          local qroot="${FIND_GATE_QUARANTINE_DIR:-$RESULTS_DIR/findings-rejected}"
          mkdir -p "$qroot" 2>/dev/null || true
          local target="$qroot/$id"
          # Avoid clobbering a prior quarantine of the same id by
          # suffixing a timestamp on collision.
          if [ -e "$target" ]; then
            target="${target}.$(date -u +%Y%m%dT%H%M%SZ)"
          fi
          if mv "$d" "$target" 2>/dev/null; then
            local rel_target="${target#$RESULTS_DIR/}"
            [ "$rel_target" != "$target" ] || rel_target="$(basename "$qroot")/$(basename "$target")"
            audit_log "DROP: findings/${id} → ${rel_target} — non-security (${reject_count}/${quorum} reject): ${reason}" \
              | tee -a "${INDEX:-/dev/null}" >/dev/null 2>&1 || true
          else
            audit_log "WARN: could not quarantine findings/${id}; leaving in place" \
              | tee -a "${INDEX:-/dev/null}" >/dev/null 2>&1 || true
          fi
          continue
        else
          # Pending second verdict — leave dir in place with a marker so
          # QA can see why it's flagged. Next triage pass re-asks the LLM.
          {
            echo "Marker: pending-drop"
            echo "When: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
            echo "Reject count: ${reject_count}/${quorum}"
            echo "Reason: ${reason}"
            echo "Hint: next triage pass will re-evaluate; touch .keep to pin."
          } > "$d/.pending-drop" 2>/dev/null || true
          continue
        fi
      else
        # Verdict flipped to accept (or first verdict was accept) —
        # clear any stale pending-drop marker so the FIND is normal.
        rm -f "$d/.pending-drop" 2>/dev/null || true
      fi
    fi

    # Reachability annotation (same helper crashes use). Best-effort.
    # The LLM hybrid pass fills missing structured fields beforehand so
    # the deterministic scorer can class non-memory findings (open
    # redirect, SSRF, …) instead of falling through to "unclassified".
    _triage_llm_fill_fields "$d" "$id"
    _triage_run_reachability "$d" "$id" "$bin_dir"
  done

  # Layered dedup: write FINDING-CLUSTERS.md and stamp Cluster: lines into
  # each report.md. Mirrors how maintain_indexes runs bin/cluster-crashes
  # after CRASH triage. Best-effort — silent failure if python3 / the
  # script is unavailable. Set FIND_CLUSTER_DISABLE=1 to skip.
  if [ -z "${FIND_CLUSTER_DISABLE:-}" ] \
     && [ -d "$RESULTS_DIR/findings" ] \
     && [ -x "$bin_dir/cluster-findings" ] \
     && command -v python3 >/dev/null 2>&1; then
    TARGET_ROOT="${TARGET_ROOT:-}" python3 "$bin_dir/cluster-findings" \
      "$RESULTS_DIR" >/dev/null 2>&1 || true
  fi

  return 0
}

# ─── Bug cluster expansion ────────────────────────────────────────
# After a CRASH lands, ask the LLM to enumerate 3 sibling hypotheses
# (same-file siblings, neighbor handlers with the same pattern, callers
# that share the bug class). Each hypothesis is appended as a PENDING
# table row to the agent state file pointed to by AGENT_CLUSTER_STATE
# (or the first AUDIT_STATE-*.md file in RESULTS_DIR if unset).

# Collect the top frames from the primary ASan output. Returns up to 8 lines.
_cluster_top_frames() {
  local d="$1"
  local asan_path
  asan_path=$(find_primary_asan_in_crash_dir "$d" 2>/dev/null || true)
  [ -n "$asan_path" ] || return 1
  grep -E '^[ \t]*#[0-9]+ ' "$asan_path" 2>/dev/null | head -8
}

# Read the source files referenced in the top frames, returning a
# small bounded slice of each. Helps the LLM see the actual code
# without us having to reason about file:line ourselves.
_cluster_nearby_source() {
  local d="$1" max_files=3
  local frames file line snippet
  frames=$(_cluster_top_frames "$d") || return 1
  [ -n "$frames" ] || return 1
  local count=0
  while IFS= read -r f; do
    file=$(echo "$f" | grep -oE '/[A-Za-z0-9_/.-]+\.(cpp|cc|c|h|hpp|rs|mjs|js):[0-9]+' | head -1)
    [ -n "$file" ] || continue
    line=$(echo "$file" | awk -F: '{print $NF}')
    file="${file%:*}"
    [ -f "$file" ] || continue
    [ -n "$line" ] && [ "$line" -gt 0 ] 2>/dev/null || line=1
    local from=$((line - 6))
    [ "$from" -lt 1 ] && from=1
    local to=$((line + 6))
    snippet=$(sed -n "${from},${to}p" "$file" 2>/dev/null | head -20)
    [ -n "$snippet" ] || continue
    printf '\n>>> %s:%s\n%s\n' "$file" "$line" "$snippet"
    count=$((count + 1))
    [ "$count" -ge "$max_files" ] && break
  done <<<"$frames"
  return 0
}

# Append cluster-expansion rows to a state file.
expand_cluster_for_crash() {
  local d="$1"
  local state_file="${2:-${AGENT_CLUSTER_STATE:-}}"

  declare -f llm_decide >/dev/null 2>&1 || return 0
  [ -d "$d" ] || return 0

  if [ -z "$state_file" ]; then
    state_file=$(find "${RESULTS_DIR:-/nonexistent}" -maxdepth 1 -name 'AUDIT_STATE-*.md' \
                 -type f 2>/dev/null | sort | head -1)
  fi
  [ -n "$state_file" ] || return 0
  [ -f "$state_file" ] || return 0

  # Skip if this CRASH has already been expanded.
  local id; id=$(basename "$d")
  [ -f "$d/.cluster_expanded" ] && return 0

  local frames source_block
  frames=$(_cluster_top_frames "$d" 2>/dev/null) || return 0
  [ -n "$frames" ] || return 0
  source_block=$(_cluster_nearby_source "$d" 2>/dev/null || true)

  local prompt
  prompt=$(render_prompt_template triage_cluster_expand.md.j2 \
    --var "id=${id}" \
    --var "frames=${frames}" \
    --var "source_block=${source_block}") || return 0

  local json
  json=$(printf '%s' "$prompt" | llm_decide cluster_expand "rows" 15) || return 0

  # Validate and append rows.
  local count
  count=$(printf '%s' "$json" | jq -r '.rows | length' 2>/dev/null) || return 0
  [ "${count:-0}" -ge 1 ] || return 0

  {
    echo ""
    echo "<!-- cluster-expansion ${id} $(date -u +%Y-%m-%dT%H:%M:%SZ) -->"
    echo "## Cluster expansion from ${id}"
    echo ""
    echo "| # | Hypothesis | File:Function:Line | Input Shape | Guard Gap | Expected Diagnostic | Strategy | Status |"
    echo "|---|-----------|--------------------|-------------|-----------|--------------------|----------|--------|"
    printf '%s' "$json" | jq -r --arg src "$id" '
      .rows[] | "| - | \(.hypothesis) | \(.file):\(.function):\(.line) | (sibling of \($src)) | (unknown) | \(.category) issue diagnostic | S5 | PENDING |"
    ' 2>/dev/null
  } >> "$state_file"

  : > "$d/.cluster_expanded" 2>/dev/null || true
  audit_log "CLUSTER-EXPAND: ${id} → ${count} sibling hypotheses appended to $(basename "$state_file")" \
    | tee -a "${INDEX:-/dev/null}"
}

# Run cluster expansion across all CRASH-* dirs that have not yet been
# expanded. Best-effort.
expand_clusters_for_new_crashes() {
  declare -f llm_decide >/dev/null 2>&1 || return 0
  [ -d "${RESULTS_DIR:-/nonexistent}/crashes" ] || return 0
  local d
  for d in "$RESULTS_DIR"/crashes/CRASH-*/; do
    [ -d "$d" ] || continue
    [ -f "$d/.cluster_expanded" ] && continue
    [ -f "$d/.autodiscard" ] && continue
    expand_cluster_for_crash "$d" 2>/dev/null || true
  done
  return 0
}

# ─── Patch-aware re-run review ────────────────────────────────────
# After upstream pulls, ask the LLM whether any open CRASH/FIND testcases
# look like they would be silently fixed by a recent diff. Flagged dirs
# get a .rerun_pending marker so the next iteration re-runs the testcase
# under ASan and demotes/closes it on the new behavior.

# Returns the tracked subsystem(s) for currently-open CRASH/FIND dirs.
# Used to scope the diff window so the prompt stays small.
_review_subsystem_from_dir() {
  local d="$1"
  local f
  for f in "$d/report.md" "$d/description.md"; do
    [ -s "$f" ] || continue
    grep -m1 -oE '[A-Za-z0-9_/.-]+\.(cpp|cc|c|h|hpp|rs|mjs|js)' "$f" 2>/dev/null \
      | head -1 \
      | awk -F'/' '{ if (NF>=2) print $1"/"$2; else print $1 }'
    return 0
  done
  return 1
}

# Collect a small diff for a subsystem in the target repo. Output may be
# empty (no recent changes). Caller must guard for empty.
_review_recent_diff() {
  local subsystem="$1" max_lines="${2:-400}"
  [ -n "$subsystem" ] || return 1
  [ -n "${TARGET_ROOT:-}" ] && [ -d "$TARGET_ROOT" ] || return 1
  case "${TARGET_REPO_TYPE:-none}" in
    git)
      git -C "$TARGET_ROOT" log --since='3 days ago' -p --stat \
          -- "$subsystem" 2>/dev/null | head -n "$max_lines"
      ;;
    hg)
      hg -R "$TARGET_ROOT" log --date '-3' -p --include "$subsystem" 2>/dev/null \
        | head -n "$max_lines"
      ;;
    *) return 1 ;;
  esac
}

# Ask the LLM which open IDs the diff plausibly fixes.
# Marks each flagged dir with .rerun_pending. Best-effort; on any
# failure we leave the world unchanged.
#
# Uses a flat tempfile (subsystem<TAB>id) instead of associative arrays
# because macOS ships bash 3.2 which lacks `declare -A`.
patch_aware_rerun_review() {
  declare -f llm_decide >/dev/null 2>&1 || return 0
  [ -d "${RESULTS_DIR:-/nonexistent}" ] || return 0

  local mapfile
  mapfile=$(mktemp "${TMPDIR:-/tmp}/patch-review-map.XXXXXX") || return 0

  local d id sub
  for d in "$RESULTS_DIR"/crashes/CRASH-*/ "$RESULTS_DIR"/findings/FIND-*/; do
    [ -d "$d" ] || continue
    [ -f "$d/.reviewed" ] && continue
    [ -f "$d/.rerun_pending" ] && continue
    id=$(basename "$d")
    sub=$(_review_subsystem_from_dir "$d") || continue
    [ -n "$sub" ] || continue
    printf '%s\t%s\n' "$sub" "$id" >> "$mapfile"
  done

  if [ ! -s "$mapfile" ]; then
    rm -f "$mapfile"
    return 0
  fi

  local subsystems
  subsystems=$(awk -F'\t' '{print $1}' "$mapfile" | sort -u)

  local subsys
  while IFS= read -r subsys; do
    [ -n "$subsys" ] || continue
    local diff
    diff=$(_review_recent_diff "$subsys" 300 2>/dev/null) || continue
    [ -n "$diff" ] || continue

    local id_list_block=""
    local cur_id rdir
    while IFS=$'\t' read -r row_sub cur_id; do
      [ "$row_sub" = "$subsys" ] || continue
      if [ -d "$RESULTS_DIR/crashes/$cur_id" ]; then
        rdir="$RESULTS_DIR/crashes/$cur_id"
      else
        rdir="$RESULTS_DIR/findings/$cur_id"
      fi
      local first_heading="" f
      for f in "$rdir/report.md" "$rdir/description.md"; do
        [ -s "$f" ] || continue
        first_heading=$(grep -m1 '^# ' "$f" 2>/dev/null | sed 's/^# *//' | head -c 200)
        break
      done
      id_list_block+=$(printf '  - %s :: %s\n' "$cur_id" "${first_heading:-(no title)}")
      id_list_block+=$'\n'
    done < "$mapfile"

    local prompt
    prompt=$(render_prompt_template triage_patch_review.md.j2 \
      --var "subsys=${subsys}" \
      --var "id_list_block=${id_list_block}" \
      --var "diff=${diff}") || continue
    local json
    json=$(printf '%s' "$prompt" | llm_decide patch_review "fixed" 20) || continue
    local flagged
    flagged=$(printf '%s' "$json" | jq -r '.fixed[]?' 2>/dev/null) || continue
    [ -n "$flagged" ] || continue

    local fid
    while IFS= read -r fid; do
      [ -n "$fid" ] || continue
      rdir=""
      [ -d "$RESULTS_DIR/crashes/$fid" ] && rdir="$RESULTS_DIR/crashes/$fid"
      [ -z "$rdir" ] && [ -d "$RESULTS_DIR/findings/$fid" ] && rdir="$RESULTS_DIR/findings/$fid"
      [ -z "$rdir" ] && [ -d "$RESULTS_DIR/recon/$fid" ] && rdir="$RESULTS_DIR/recon/$fid"
      [ -n "$rdir" ] || continue
      {
        echo "Patch-aware re-run flagged $(date -u +%Y-%m-%dT%H:%M:%SZ)"
        echo "Subsystem: $subsys"
        echo "Reason: LLM patch_review marked diff as plausibly fixing this finding."
        echo "Action: re-run testcase under ASan; demote to .reviewed if no longer crashes."
      } > "$rdir/.rerun_pending" 2>/dev/null || true
      audit_log "PATCH-REVIEW: $fid flagged for re-run (sub=$subsys)" | tee -a "${INDEX:-/dev/null}"
    done <<<"$flagged"
  done <<<"$subsystems"

  rm -f "$mapfile"
  return 0
}

# ─── Index regeneration ───────────────────────────────────────────
_triage_finding_subject() {
  local desc="$1" id="$2"
  [ -s "$desc" ] || return 1
  awk -v id="$id" '
    function trim(s) {
      sub(/^[[:space:]]+/, "", s)
      sub(/[[:space:]]+$/, "", s)
      return s
    }
    function clean(s) {
      s = trim(s)
      gsub(/^#+[[:space:]]*/, "", s)
      gsub(/^[Ss]ummary:[[:space:]]*/, "", s)
      gsub(/^[`*[:space:]]+|[`*[:space:]]+$/, "", s)
      if (index(s, id) == 1) {
        rest = substr(s, length(id) + 1)
        if (rest == "") {
          s = ""
        } else if (rest ~ /^[[:space:]:-]/) {
          s = trim(substr(rest, 2))
        }
      }
      sub(/^FIND-[A-Za-z0-9_.-]+[[:space:]:-]+[[:space:]]*/, "", s)
      return trim(s)
    }
    function useful(s) {
      s = clean(s)
      if (s == "" || s == id) return 0
      if (s ~ /^Cluster:/ || s ~ /^Dedup key:/) return 0
      if (s ~ /^FIND-[0-9][A-Za-z0-9_.-]*$/) return 0
      return 1
    }
    /^Cluster:/ || /^Dedup key:/ { next }
    /^# / {
      s = clean($0)
      if (useful(s)) { print substr(s, 1, 120); found=1; exit }
      next
    }
    /^Summary:[[:space:]]*./ {
      s = clean($0)
      if (useful(s)) { print substr(s, 1, 120); found=1; exit }
      next
    }
    /^##[[:space:]]+Summary[[:space:]]*$/ || /^Summary:[[:space:]]*$/ {
      in_summary=1
      next
    }
    in_summary && /^[[:space:]]*$/ { next }
    in_summary {
      s = clean($0)
      if (useful(s)) { print substr(s, 1, 120); found=1; exit }
      in_summary=0
    }
    !fallback && $0 !~ /^[[:space:]]*$/ {
      s = clean($0)
      if (useful(s)) fallback=s
    }
    END {
      if (!found && fallback) print substr(fallback, 1, 120)
    }
  ' "$desc" 2>/dev/null
}

maintain_indexes() {
  mkdir -p "$RESULTS_DIR/crashes" "$RESULTS_DIR/crashes-rejected" "$RESULTS_DIR/findings" 2>/dev/null || true

  # Refresh CRASH/FINDING cluster summaries + Cluster: lines first so report
  # HTML rendered below sees the cluster ids on the first run.
  # Best-effort: failures or a missing python3 don't block the audit. Set
  # CLUSTER_AUTO=0 to disable.
  if [ "${CLUSTER_AUTO:-1}" = "1" ]; then
    local _bin_dir _cluster_bin _finding_cluster_bin
    _bin_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/../bin" 2>/dev/null && pwd)
    _cluster_bin="$_bin_dir/cluster-crashes"
    _finding_cluster_bin="$_bin_dir/cluster-findings"
    if [ -x "$_cluster_bin" ] && command -v python3 >/dev/null 2>&1; then
      python3 "$_cluster_bin" "$RESULTS_DIR" >/dev/null 2>&1 \
        || audit_log "WARN: cluster-crashes refresh failed (CRASH-CLUSTERS.md may be stale)" \
             | tee -a "${INDEX:-/dev/null}" >/dev/null 2>&1 || true
      # Cross-backend aggregate at output/<slug>/CRASH-CLUSTERS.md. Concurrent
      # backends serialize internally via fcntl.flock on .cluster-lock; the
      # loser exits 0 immediately so this never stalls our audit loop.
      local _target_root="$(dirname "$RESULTS_DIR")"
      _target_root="$(dirname "$_target_root")"
      if [ -d "$_target_root" ] && [ "$(basename "$(dirname "$_target_root")")" = "output" ]; then
        python3 "$_cluster_bin" "$_target_root" >/dev/null 2>&1 \
          || audit_log "WARN: cluster-crashes target-root aggregate failed" \
               | tee -a "${INDEX:-/dev/null}" >/dev/null 2>&1 || true
      fi
    fi
    if [ -x "$_finding_cluster_bin" ] && command -v python3 >/dev/null 2>&1; then
      TARGET_ROOT="${TARGET_ROOT:-}" python3 "$_finding_cluster_bin" "$RESULTS_DIR" >/dev/null 2>&1 \
        || audit_log "WARN: cluster-findings refresh failed (FINDING-CLUSTERS.md may be stale)" \
             | tee -a "${INDEX:-/dev/null}" >/dev/null 2>&1 || true
      local _target_root="$(dirname "$RESULTS_DIR")"
      _target_root="$(dirname "$_target_root")"
      if [ -d "$_target_root" ] && [ "$(basename "$(dirname "$_target_root")")" = "output" ]; then
        TARGET_ROOT="${TARGET_ROOT:-}" python3 "$_finding_cluster_bin" "$_target_root" >/dev/null 2>&1 \
          || audit_log "WARN: cluster-findings target-root aggregate failed" \
               | tee -a "${INDEX:-/dev/null}" >/dev/null 2>&1 || true
      fi
    fi
  fi

  local _frame_bin_dir _frame_helper
  _frame_bin_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/../bin" 2>/dev/null && pwd)
  _frame_helper="$_frame_bin_dir/../lib/stack_frames.py"

  # CRASH/FINDING cluster files are now the primary review tables. Remove
  # stale legacy per-directory indexes so reviewers do not see two competing
  # summaries for the same artifacts.
  rm -f "$RESULTS_DIR/crashes/INDEX.md" "$RESULTS_DIR/crashes/INDEX.html" \
        "$RESULTS_DIR/findings/INDEX.md" "$RESULTS_DIR/findings/INDEX.html" \
        "$RESULTS_DIR/CLUSTERS.md" "$RESULTS_DIR/CLUSTERS.html" \
        "$RESULTS_DIR/CRASH-CLUSTERS.md" "$RESULTS_DIR/CRASH-CLUSTERS.html" \
        "$RESULTS_DIR/findings/FIND-CLUSTERS.md" \
        "$RESULTS_DIR/findings/FIND-CLUSTERS.html" 2>/dev/null || true

  # crashes-rejected/INDEX.md — Crash site only; the full ERROR line is in
  # the per-dir asan output. ID is plain text since rejected dirs are not
  # supposed to be re-opened.
  {
    echo "# Rejected crashes — non-finding classes (DO NOT RE-FILE)"
    echo ""
    echo "| ID | Crash site | Rejected at |"
    echo "|:---|:-----------|:------------|"
    local d
    for d in "$RESULTS_DIR"/crashes-rejected/CRASH-*/; do
      [ -d "$d" ] || continue
      local id frame ts
      id=$(basename "$d")
      local asan_path
      asan_path=$(find_primary_asan_in_crash_dir "$d" 2>/dev/null || true)
      frame="(unknown)"
      if [ -n "$asan_path" ]; then
        if [ -s "$_frame_helper" ] && command -v python3 >/dev/null 2>&1; then
          frame=$(python3 "$_frame_helper" --first-display "$asan_path" 2>/dev/null | head -c 70 || true)
        fi
        if [ -z "$frame" ]; then
          frame=$(awk '
            /^[[:space:]]*#[0-9]+/ {
              if ($0 ~ /__asan|__sanitizer|__interceptor|libc\+\+|libsystem_|libdyld|libobjc|asan_interceptors|libsancov|libclang_rt|\bstart\+/) next
              print; exit
            }
          ' "$asan_path" 2>/dev/null \
            | sed -E 's/^[[:space:]]*#[0-9]+[[:space:]]+0x[0-9a-fA-F]+[[:space:]]+in[[:space:]]+//' \
            | head -c 70 || true)
        fi
        [ -z "$frame" ] && frame="(unknown)"
      fi
      ts="?"
      [ -f "$d/.autodiscard" ] && ts=$(audit_mtime_utc "$d/.autodiscard" '%Y-%m-%d' 2>/dev/null || echo "?")
      printf '| %s | %s | %s |\n' "$id" "${frame:-—}" "$ts"
    done
  } > "$RESULTS_DIR/crashes-rejected/INDEX.md" 2>/dev/null || true

  # Emit HTML siblings after all report/cluster mutations for this iteration.
  # Report HTML is intentionally owned here, not by export-repro,
  # bin/reachability, or bin/cluster-crashes: those are intermediate mutators
  # of REPORT.md/report.md, while maintain_indexes runs after reachability and
  # after cluster-crashes has refreshed Cluster lines. This keeps REPORT.html
  # a single final render of the current markdown instead of a stale snapshot.
  # Best-effort: failures don't block the audit. Set INDEX_HTML_AUTO=0 to
  # disable generated HTML.
  if [ "${INDEX_HTML_AUTO:-1}" = "1" ] && command -v python3 >/dev/null 2>&1; then
    local _bin_dir _render _enrich
    _bin_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/../bin" 2>/dev/null && pwd)
    _render="$_bin_dir/render-md"
    _enrich="$_bin_dir/enrich-report"
    if [ -x "$_render" ]; then
      local _d _report _candidate
      for _d in "$RESULTS_DIR"/crashes/CRASH-*/ "$RESULTS_DIR"/crashes-rejected/CRASH-*/; do
        [ -d "$_d" ] || continue
        _report=""
        _report=$(_triage_exact_file_path "$_d" "REPORT.md" 2>/dev/null || true)
        [ -z "$_report" ] && _report=$(_triage_exact_file_path "$_d" "report.md" 2>/dev/null || true)
        [ -n "$_report" ] || continue
        # Enrich first (patch.diff inline, snippets, TL;DR) so render-md
        # picks up the augmented markdown for HTML. Best-effort; missing
        # source tree just no-ops the snippet blocks.
        if [ "${ENRICH_REPORT_AUTO:-1}" = "1" ] && [ -x "$_enrich" ]; then
          python3 "$_enrich" --quiet "$_report" >/dev/null 2>&1 || true
        fi
        python3 "$_render" "$_report" --html-sibling --title "$(basename "$_d")" >/dev/null 2>&1 || true
      done

      # Findings get the same report.md → report.html sibling treatment so
      # reviewers have a browsable HTML view alongside the markdown.
      for _d in "$RESULTS_DIR"/findings/FIND-*/; do
        [ -d "$_d" ] || continue
        _report=""
        for _candidate in REPORT.md report.md description.md analysis.md README.md; do
          if [ -s "$_d/$_candidate" ]; then
            _report="$_d/$_candidate"; break
          fi
        done
        [ -n "$_report" ] || continue
        if [ "${ENRICH_REPORT_AUTO:-1}" = "1" ] && [ -x "$_enrich" ]; then
          python3 "$_enrich" --quiet "$_report" >/dev/null 2>&1 || true
        fi
        python3 "$_render" "$_report" --html-sibling --title "$(basename "$_d")" >/dev/null 2>&1 || true
      done

      local _f
      for _f in \
        "$RESULTS_DIR/crashes/CRASH-CLUSTERS.md" \
        "$RESULTS_DIR/crashes-rejected/INDEX.md" \
        "$RESULTS_DIR/findings/FINDING-CLUSTERS.md"; do
        [ -s "$_f" ] || continue
        python3 "$_render" "$_f" --html-sibling >/dev/null 2>&1 || true
      done
    fi
  fi
  return 0
}
