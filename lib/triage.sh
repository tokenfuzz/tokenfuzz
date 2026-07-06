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

# Single ceiling for every single-shot LLM decision (crash_triage,
# crash_confirm, legit_crash, find_quality, cluster_expand, patch_review).
# `timeout` is a max, not a fixed wait — fast backends finish early, so one
# generous value costs them nothing while giving a slow model (e.g.
# claude-opus) room to answer instead of being killed (rc=124). Operators on
# an unusually slow/throttled backend can raise it in one place. The `:=`
# form is idempotent, so re-sourcing in tests is safe.
: "${LLM_DECISION_TIMEOUT:=45}"

# Byte ceiling for report/description text fed to a single-shot LLM gate
# (find_quality, crash_confirm). This is a BACKSTOP against pathological or
# adversarial report sizes, NOT a routine truncator. Measured over real
# reports: p50 ~7 KB, p99 ~19 KB, largest observed ~115 KB. At 256 KB the cap
# effectively never binds for a genuine report — so a real finding is judged on
# its WHOLE text, never a headless prefix (the old 8 KB/12 KB caps truncated
# ~26% of reports and silently dropped their Impact / Data Flow, a false-negative
# source). 256 KB is ~64K tokens, comfortably inside every backend's context
# window, so an oversize report never hard-fails the call into a silent
# `undecided`. On the rare report that still exceeds this, the gate sends a
# head+tail slice and logs a POSSIBLE-FALSE-NEGATIVE line (never a silent drop).
# Operators on a small-context local backend can lower it. `:=` is idempotent so
# re-sourcing in tests is safe.
: "${REPORT_GATE_MAX_BYTES:=262144}"

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
  # Hot helper: called per report/patch/evidence file, several times per
  # render-sig, twice per dir, every maintain_indexes pass. Two cheap wins
  # over the old `audit_sha1 | awk`:
  #   1. Skip entirely when the file is absent — render-sig probes patch.diff
  #      / .audit/patch.diff that usually don't exist, and audit_sha1 would
  #      still spawn python just to fail. A missing file yields an empty sha
  #      either way, so the signature is byte-identical.
  #   2. Strip the trailing "  <path>" in bash instead of forking awk.
  # audit_sha1 prints "<hex>  <path>"; ${out%% *} keeps the hex (the hash
  # never contains a space, so this is path-independent).
  local f="$1" out
  [ -f "$f" ] || return 1
  out=$(audit_sha1 "$f" 2>/dev/null) || return 1
  printf '%s' "${out%% *}"
}

_triage_text_sha1() {
  audit_sha1 2>/dev/null | awk '{print $1}'
}

# Read a report/description for an LLM gate, bounded by REPORT_GATE_MAX_BYTES.
# For the overwhelming majority of reports (size <= cap) this returns the file
# WHOLE — the gate sees every section, so a real finding is never judged on a
# truncated prefix. On the rare overflow it returns a head+tail slice: head-
# biased because the verdict-critical structure (Fields, Summary, Data Flow,
# Impact) sits at the top and middle while only the auto-derived severity-
# rationale boilerplate trails at the very end, and a tail slice keeps the
# closing Impact / Reproduction sections in view. The two halves are joined by
# a visible elision marker, and one POSSIBLE-FALSE-NEGATIVE line is logged to
# STDERR — stderr, not stdout, because callers capture this function's stdout as
# the verdict body and a log line there would corrupt it. Bytes are never
# dropped silently.
#
# Prints the bounded body on stdout; rc=1 if the file is missing/empty.
_triage_read_report_bounded() {
  local path="$1" cap="${REPORT_GATE_MAX_BYTES:-262144}"
  [ -s "$path" ] || return 1
  case "$cap" in ''|*[!0-9]*) cap=262144 ;; esac
  [ "$cap" -ge 1 ] || cap=262144

  local size
  size=$(wc -c < "$path" 2>/dev/null | tr -d ' ')
  case "$size" in ''|*[!0-9]*) size=0 ;; esac

  if [ "$size" -le "$cap" ]; then
    cat "$path" 2>/dev/null || return 1
    return 0
  fi

  # Overflow backstop. Reserve a quarter of the budget for the tail so the
  # closing sections survive alongside the head.
  local tail_bytes=$((cap / 4))
  local head_bytes=$((cap - tail_bytes))
  local dropped=$((size - head_bytes - tail_bytes))
  audit_log "POSSIBLE-FALSE-NEGATIVE: report '${path}' is ${size} bytes (> REPORT_GATE_MAX_BYTES=${cap}); the LLM gate saw head ${head_bytes}B + tail ${tail_bytes}B and ${dropped}B from the middle were elided. If real reports are legitimately this large, raise REPORT_GATE_MAX_BYTES so the gate sees the whole report." >&2
  {
    head -c "$head_bytes" "$path" 2>/dev/null
    printf '\n\n[... %d bytes elided by REPORT_GATE_MAX_BYTES (oversize report) ...]\n\n' "$dropped"
    tail -c "$tail_bytes" "$path" 2>/dev/null
  } || return 1
  return 0
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

_triage_confirm_cache_fields() {
  local cache="$1"
  [ -s "$cache" ] || return 1
  command -v jq >/dev/null 2>&1 || return 1
  jq -r '
    [
      (.content_sha1 // .signature_sha1 // .sha1 // ""),
      (if has("accept") then .accept else "" end),
      (.reason // ""),
      (.votes // 0),
      (.evidence_sha1 // ""),
      (.semantic_sha1 // "")
    ] | @sh
  ' "$cache" 2>/dev/null
}

_triage_crash_triage_cache_fields() {
  local cache="$1"
  [ -s "$cache" ] || return 1
  command -v jq >/dev/null 2>&1 || return 1
  jq -r '
    [
      (.content_sha1 // .signature_sha1 // .sha1 // ""),
      (if has("keep") then .keep else "" end),
      (.reason // ""),
      (.votes // 0)
    ] | @sh
  ' "$cache" 2>/dev/null
}

_triage_legit_cache_fields() {
  local cache="$1"
  [ -s "$cache" ] || return 1
  command -v jq >/dev/null 2>&1 || return 1
  jq -r '
    [
      (.evidence_sha1 // .signature_sha1 // .sha1 // ""),
      (.require_web // ""),
      (if has("legitimate") then .legitimate else "" end),
      (.reason // ""),
      (.votes // 0)
    ] | @sh
  ' "$cache" 2>/dev/null
}

_triage_find_quality_cache_fields() {
  local cache="$1"
  [ -s "$cache" ] || return 1
  command -v jq >/dev/null 2>&1 || return 1
  jq -r '
    [
      (.decision_version // ""),
      (if has("accept") then .accept else "" end),
      (.reason // ""),
      (.reject_count // 0),
      (.content_sha1 // .signature_sha1 // .sha1 // ""),
      (.accept_count // 0)
    ] | @sh
  ' "$cache" 2>/dev/null
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

# Independent multi-vote wrapper shared by the crash-promotion gates
# (trace triage, confirm, legitimacy). Takes votes from llm_decide
# back-to-back: any single POSITIVE vote (<bool-field>=true) short-circuits
# — one vote in favour keeps the crash, preserving the fail-open default —
# while a NEGATIVE verdict must be echoed by `quorum` independent votes
# before it sticks. This mirrors the in-call quorum that
# llm_find_quality_decision and triage_validate_finding already use, so a
# single hallucinated reject can no longer sink a real crash. Cost is
# unchanged on the happy path (a keep verdict returns after one call);
# only rejections pay for the extra scrutiny.
#
# Args:  <decision> <required-keys> <bool-field> <prompt>
# Tunable: CRASH_GATE_QUORUM (default 2).
# Sets globals (read by the caller after a 0/2 return):
#   _TRIAGE_GATE_VOTE   = the deciding vote's JSON object
#   _TRIAGE_GATE_VOTES  = negative votes tallied (== quorum on a reject)
# Returns: 2 positive · 0 negative-quorum-reached · 1 undecided
#          (LLM unavailable / unparseable before quorum → caller falls back)
_triage_gate_quorum_vote() {
  local decision="$1" keys="$2" field="$3" prompt="$4"
  local quorum
  quorum=$(_triage_gate_quorum)
  _TRIAGE_GATE_VOTE=""
  _TRIAGE_GATE_VOTES=0
  local rejects=0 vote_json verdict
  while :; do
    vote_json=$(printf '%s' "$prompt" | llm_decide "$decision" "$keys" "$(_triage_decision_timeout "$decision")")
    [ -n "$vote_json" ] || return 1
    verdict=$(printf '%s' "$vote_json" | jq -r --arg f "$field" '.[$f]' 2>/dev/null)
    case "$verdict" in
      true)
        _TRIAGE_GATE_VOTE="$vote_json"
        return 2
        ;;
      false)
        rejects=$((rejects + 1))
        _TRIAGE_GATE_VOTE="$vote_json"
        _TRIAGE_GATE_VOTES="$rejects"
        [ "$rejects" -ge "$quorum" ] && return 0
        ;;
      *)
        return 1
        ;;
    esac
  done
}

# Resolve the crash-gate quorum (negative votes needed to reject). Defaults
# to 2, matching FIND_GATE_QUORUM; never below 1.
_triage_gate_quorum() {
  local quorum="${CRASH_GATE_QUORUM:-2}"
  case "$quorum" in ''|*[!0-9]*) quorum=2 ;; esac
  [ "$quorum" -ge 1 ] || quorum=1
  printf '%s' "$quorum"
}

# Effective decision timeout for a gate. The agentic gates read the crash
# report or source tree before voting, so under parallel backend contention
# they can exceed the base decision timeout; a too-short cap kills and
# discards the call (the crash then retries every housekeeping pass). Floor
# those decisions to enough headroom to absorb the spikes — cluster_expand
# explores the tree and needs the most; the confirm gates read one report and
# need less. Non-reading classification gates keep the base timeout. The floor
# is a minimum, so fast calls still return early and a higher operator
# LLM_DECISION_TIMEOUT override still wins.
_triage_decision_timeout() {
  local decision="$1" base="$LLM_DECISION_TIMEOUT" floor=0
  case "$decision" in
    cluster_expand) floor=600 ;;
    crash_confirm|legit_crash) floor=180 ;;
  esac
  if [ "$base" -lt "$floor" ]; then printf '%s' "$floor"; else printf '%s' "$base"; fi
}

# How many crash/finding dirs are triaged concurrently. Each per-dir
# pipeline is independent — every artifact write lands inside its own
# CRASH-*/FIND-* dir, bin/state serializes shared JSONL via flock, and
# INDEX appends are single whole lines — but each pipeline contains
# several serial LLM gate calls (5-20s apiece), so running dirs serially
# made triage the longest stop-the-world phase between iterations.
# Mirrors RECON_TRIAGE_PARALLEL (recon's validator pool, default 6);
# default 4 keeps concurrent decision calls below the recon pool so the
# two never stack past typical backend rate limits. TRIAGE_DIR_PARALLEL=1
# restores the serial behaviour.
_triage_dir_pool_size() {
  local n="${TRIAGE_DIR_PARALLEL:-4}"
  case "$n" in ''|*[!0-9]*) n=4 ;; esac
  [ "$n" -ge 1 ] || n=1
  printf '%s' "$n"
}

# Hash of a report's agent-authored substance. Strips exactly the content
# the harness itself stamps into reports between triage passes, so
# mechanical enrichment leaves the hash unchanged while ANY edit to the
# narrative (summary, impact, root cause, data flow, reproduction) changes
# it. Inclusion criterion for the strip list: a section/line is stripped
# ONLY if it is written by harness code, never by the reporting agent:
#   ## Severity rationale            — bin/severity SEV_HEADING
#   ## Contract concern              — _triage_annotate_contract_concern
#   ## Patch                         — bin/enrich-report (sole writer)
#   <!-- enrich:name --> … fences    — bin/enrich-report idempotency blocks
#   Cluster: <id> lines + |Cluster| table rows — bin/cluster-crashes
#   Dedup frames: lines + |Dedup frames| rows  — bin/cluster-crashes
#   - **Severity**: …(auto:/CVSS…)   — bin/severity auto severity line
_triage_report_semantic_sha() {
  local report_path="$1"
  [ -s "$report_path" ] || return 1
  # Headings are matched EXACTLY (modulo trailing whitespace): a report
  # author writing e.g. "## Reachability analysis" keeps that section in
  # the hash — only the harness's own headings are stripped.
  awk '
    /^<!-- enrich:[A-Za-z0-9_-]+ -->/ { fence=1; next }
    /^<!-- \/enrich:[A-Za-z0-9_-]+ -->/ { fence=0; next }
    fence { next }
    /^## Severity rationale[[:space:]]*$/ { skip=1; next }
    /^## Contract concern[[:space:]]*$/ { skip=1; next }
    /^## Patch[[:space:]]*$/ { skip=1; next }
    skip && /^## / { skip=0 }
    skip { next }
    /^Cluster:/ { next }
    /^\|[[:space:]]*Cluster[[:space:]]*\|/ { next }
    /^Dedup frames:/ { next }
    /^\|[[:space:]]*Dedup frames[[:space:]]*\|/ { next }
    /^- \*\*Severity\*\*:.*(\(auto:|CVSS)/ { next }
    /^[[:space:]]*$/ { next }
    { print }
  ' "$report_path" 2>/dev/null | _triage_text_sha1
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
#                  The downstream severity scorer derives CVSS-BTE
#                  Environmental MAT:P when it sees the report-visible
#                  "## Contract concern" section, so contract-flagged
#                  crashes are automatically represented in Severity
#                  without being lost from the crashes/ count.
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
    printf 'contract-flag\ttrigger requires [%s] outside attacker_controls=[%s]; this out-of-boundary precondition is a robustness/hardening concern that lowers severity (CVSS AT:P/MAT:P) — the CVSS band is set by the scorer\n' \
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
  # HWAddressSanitizer is a first-class LLVM sanitizer like ASan/UBSan and
  # verdict.sh (the canonical crash classifier) already counts it; keep this
  # diagnostic gate in step with it so an HWASan-only crash dir is not read as
  # "no valid sanitizer trace" and auto-rejected by the completeness TTL.
  grep -qE 'ERROR: (AddressSanitizer|HWAddressSanitizer|UndefinedBehaviorSanitizer)|SUMMARY: (AddressSanitizer|HWAddressSanitizer|UndefinedBehaviorSanitizer)|WARNING: (ThreadSanitizer|MemorySanitizer):|SUMMARY: (ThreadSanitizer|MemorySanitizer):|^WARNING: DATA RACE$|UndefinedBehaviorSanitizer:|^[^[:space:]].*:[0-9]+:[0-9]+: runtime error:' "$f" 2>/dev/null
}

# Recoverable, low-value crash classes — single-process death with NO memory
# corruption and no controllable primitive. Split out from
# is_autodiscard_crash_output so _triage_one_crash_dir can treat them as a HARD
# reject (an LLM keep vote may NOT rescue them): both terminate one process and
# are robustness bugs, not security-class crashes. The caller guards with
# crash_dir_has_memory_safety_asan_signal so a real corruption class that merely
# also faults near null / exhausts the stack is never hard-rejected here.
_crash_is_null_deref() {
  local f="$1"
  [ -s "$f" ] || return 1
  grep -qE 'Hint: address points to the zero page|SCARINESS: [0-9]+ \(null-deref\)|SEGV on unknown address 0x0+[^0-9a-fA-F]' "$f" 2>/dev/null
}

# Plain recursion stack-overflow (stack EXHAUSTION), NOT stack-buffer-overflow.
# ASan's bare `stack-overflow` token is resource exhaustion from deep recursion;
# `stack-buffer-overflow` / `dynamic-stack-buffer-overflow` are memory
# corruption and are kept by is_autodiscard_crash_output's keep-list above. The
# trailing `( |$)` is what excludes the `-buffer-overflow` family.
_crash_is_stack_exhaustion() {
  local f="$1"
  [ -s "$f" ] || return 1
  grep -qE 'AddressSanitizer: stack-overflow( |$)' "$f" 2>/dev/null
}

is_autodiscard_crash_output() {
  local f="$1"
  [ -f "$f" ] && [ -s "$f" ] || return 1

  # Short-circuit KEEP for interesting sanitizer-visible categories.
  # The trailing `[a-z]+-param-overlap` clause catches the libc str/mem
  # copy-and-overlap family (strcpy-, strncpy-, strncat-, memcpy-,
  # memmove-param-overlap). ASan reports these when source and
  # destination overlap, which still represents a real out-of-bounds
  # write driven by attacker bytes — a previous narrow whitelist dropped
  # a confirmed bug because the agent's reproducer happened to trip the
  # overlap detector instead of the OOB-write detector.
  if grep -qE 'AddressSanitizer: (heap-buffer-overflow|use-after-free|heap-use-after-free|container-overflow|dynamic-stack-buffer-overflow|stack-buffer-overflow|stack-use-after-return|stack-use-after-scope|global-buffer-overflow|alloc-dealloc-mismatch|intra-object-overflow|double-free|negative-size-param|bad-free|calloc-overflow|new-delete-type-mismatch|invalid-pointer-pair|[a-z]+-param-overlap)' "$f" 2>/dev/null; then
    return 1
  fi

  # Null-deref (recoverable, low-value — see _crash_is_null_deref)
  if _crash_is_null_deref "$f"; then
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
  if grep -qE "^thread '[^']*'( \([^)]*\))? panicked at " "$f" 2>/dev/null; then
    return 0
  fi
  if grep -qE '\bRustMozCrash\b' "$f" 2>/dev/null; then
    return 0
  fi

  # Plain stack-overflow / recursion exhaustion (not stack-buffer-overflow)
  if _crash_is_stack_exhaustion "$f"; then
    return 0
  fi

  # OOM / allocator failure. The `rss limit (exhausted|exceeded)` arm covers the
  # generic probe RSS watchdog's host-protection kill (audit_timeout_run_rss,
  # via sanitizer_generic_rss_limit_mb) as well as ASan's own hard_rss_limit_mb
  # abort: both are host protection, not a memory-safety bug, so they autodiscard
  # in the same class as a real OOM.
  if grep -qE 'AddressSanitizer: (allocation-size-too-big|out-of-memory)|AddressSanitizer failed to allocate|requested allocation size .* exceeds maximum|rss limit (exhausted|exceeded)' "$f" 2>/dev/null; then
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
    local cache_fields="" cached_content_sha="" cached_keep="" cached_reason="" cached_votes=0
    if cache_fields=$(_triage_crash_triage_cache_fields "$cache_candidate" 2>/dev/null); then
      eval "set -- $cache_fields"
      cached_content_sha="${1:-}"
      cached_keep="${2:-}"
      cached_reason="${3:-}"
      cached_votes="${4:-0}"
    fi
    if [ -n "$hash" ] && [ "$cached_content_sha" = "$hash" ]; then
      [ "$cache_candidate" = "$cache" ] || cp "$cache_candidate" "$cache" 2>/dev/null || true
      if [ "$cached_keep" = "true" ]; then
        return 2
      fi
      # Honor a cached discard only if it was reached by the full quorum.
      # A legacy single-vote cache (no `votes`, or below quorum) is
      # re-litigated so the multi-vote gate actually applies.
      if [ "$cached_keep" = "false" ]; then
        case "$cached_votes" in ''|*[!0-9]*) cached_votes=0 ;; esac
        if [ "$cached_votes" -ge "$(_triage_gate_quorum)" ]; then
          printf '%s' "${cached_reason:-cached LLM discard}"
          return 0
        fi
      fi
    fi
  done

  # Feed the LLM up to 256 KB of trace. p99 of real sanitizer traces is
  # ~26 KB and p50 under 1 KB, so this captures the full report for all but
  # a handful of pathological deep-recursion dumps — the verdict-relevant
  # ERROR/SUMMARY line and crashing frames are no longer at risk of being
  # truncated away on the ~1/3 of traces that exceed the old 6 KB window.
  local trace
  trace=$(head -c 262144 "$asan_path" 2>/dev/null) || return 1
  [ -n "$trace" ] || return 1

  local prompt
  prompt=$(render_prompt_template triage_crash_trace.md.j2 \
    --var "trace=${trace}") || return 1

  local vrc reason
  _triage_gate_quorum_vote crash_triage "keep,reason" keep "$prompt"; vrc=$?
  reason=$(printf '%s' "$_TRIAGE_GATE_VOTE" | jq -r '.reason // ""' 2>/dev/null)
  [ "$reason" = "null" ] && reason=""
  if [ "$vrc" -eq 0 ]; then
    { jq -n --arg reason "$reason" --argjson votes "$_TRIAGE_GATE_VOTES" \
        '{keep: false, reason: $reason, votes: $votes}' \
        | _triage_cache_write_envelope "$cache" "crash_triage" "content_sha1" "$hash"; } || true
    printf '%s' "$reason"
    return 0
  fi
  if [ "$vrc" -eq 2 ]; then
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
#   - optional severity annotation
#   - caller-contract / Trigger source verdict matrix
# and looks at the finished report.md (or REPORT.md after bundling) to ask:
# is this a real, security-relevant sanitizer-class crash that an upstream
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

  # Sanitizer-evidence sha for the asymmetric accept below. The report may
  # live at the crash-dir root or under .audit/ — the evidence always sits
  # at the crash-dir root.
  local _ev_dir evidence_path evidence_sha=""
  _ev_dir=$(dirname "$report_path")
  [ "$(basename "$_ev_dir")" = ".audit" ] && _ev_dir=$(dirname "$_ev_dir")
  evidence_path=$(find_primary_asan_in_crash_dir "$_ev_dir" 2>/dev/null || true)
  [ -n "$evidence_path" ] && evidence_sha=$(_triage_file_sha1 "$evidence_path" 2>/dev/null || true)

  local cache_fields="" cached_content_sha="" cached_accept="" cached_reason="" cached_votes=0 cached_evidence_sha="" cached_semantic_sha=""
  if cache_fields=$(_triage_confirm_cache_fields "$cache" 2>/dev/null); then
    eval "set -- $cache_fields"
    cached_content_sha="${1:-}"
    cached_accept="${2:-}"
    cached_reason="${3:-}"
    cached_votes="${4:-0}"
    cached_evidence_sha="${5:-}"
    cached_semantic_sha="${6:-}"
  fi

  if [ -n "$hash" ] && [ "$cached_content_sha" = "$hash" ]; then
    if [ "$cached_accept" = "true" ]; then
      return 2
    fi
    # Honor a cached reject only if the full quorum agreed; a legacy
    # single-vote cache is re-litigated through the multi-vote gate.
    if [ "$cached_accept" = "false" ]; then
      case "$cached_votes" in ''|*[!0-9]*) cached_votes=0 ;; esac
      if [ "$cached_votes" -ge "$(_triage_gate_quorum)" ]; then
        printf '%s' "${cached_reason:-cached LLM rejection}"
        return 0
      fi
    fi
  fi

  # Asymmetric accept reuse — same rationale as llm_crash_legitimacy_decision:
  # harness enrichment (severity/cluster/contract stamps)
  # rewrites report.md between triage passes without changing what the
  # gate judges, so keying the accept on raw report content re-litigated
  # every already-confirmed crash each sweep (observed: a full second
  # round of confirm votes per run). A prior ACCEPT stays valid only while
  # BOTH the sanitizer evidence AND the report's agent-authored substance
  # (_triage_report_semantic_sha — harness-stamped sections stripped) are
  # unchanged. A substantive report edit, new evidence, or any reject goes
  # back to the gate.
  local semantic_sha=""
  semantic_sha=$(_triage_report_semantic_sha "$report_path" 2>/dev/null || true)
  if [ -n "$evidence_sha" ] && [ -n "$semantic_sha" ] \
     && [ -n "$cache_fields" ]; then
    if [ "$cached_accept" = "true" ] \
       && [ "$cached_evidence_sha" = "$evidence_sha" ] \
       && [ "$cached_semantic_sha" = "$semantic_sha" ]; then
      return 2
    fi
  fi

  local body
  body=$(_triage_read_report_bounded "$report_path") || return 1
  [ -n "$body" ] || return 1

  local prompt
  prompt=$(render_prompt_template triage_crash_confirm.md.j2 \
    --var "body=${body}") || return 1

  local vrc accept reason
  _triage_gate_quorum_vote crash_confirm "accept,reason" accept "$prompt"; vrc=$?
  reason=$(printf '%s' "$_TRIAGE_GATE_VOTE" | jq -r '.reason // ""' 2>/dev/null)
  [ "$reason" = "null" ] && reason=""
  if [ "$vrc" -eq 2 ]; then
    [ -n "$reason" ] || reason="LLM confirmed report"
    { jq -n --arg reason "$reason" --arg ev "$evidence_sha" --arg sem "$semantic_sha" \
        '{accept: true, reason: $reason}
         + (if $ev != "" then {evidence_sha1: $ev} else {} end)
         + (if $sem != "" then {semantic_sha1: $sem} else {} end)' \
        | _triage_cache_write_envelope "$cache" "crash_confirm" "content_sha1" "$hash"; } || true
    return 2
  fi
  if [ "$vrc" -eq 0 ]; then
    [ -n "$reason" ] || reason="LLM rejected report at confirm gate"
    { jq -n --arg reason "$reason" --argjson votes "$_TRIAGE_GATE_VOTES" \
        '{accept: false, reason: $reason, votes: $votes}' \
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

  # Mirror lib/crash_artifacts.is_testcase_candidate: prefer a canonically
  # named reproducer, but keep a relaxed fallback (any surviving non-artifact
  # file, including a bare `.txt`) so a real reproducer under a non-canonical
  # name like `payload.txt` is found rather than failing promotion entirely.
  local f stem lower sz prefixed relaxed=""
  while IFS= read -r -d '' f; do
    [ -s "$f" ] || continue
    stem="${f##*/}"
    lower=$(printf '%s' "$stem" | tr '[:upper:]' '[:lower:]')
    case "$stem" in
      .*|REPORT.md|REPORT.html|report.md|description.md|README.md|reproduce.sh|testcase.sh|reproducer.sh|sanitizer.txt|asan.txt|asan-output.txt|asan_output.txt|msan.txt|tsan.txt|ubsan.txt|harness.c|harness.cc|harness.cpp|harness.cxx|severity.json|promotion.log|*.sanitizer.txt|*.asan.txt|*.msan.txt|*.tsan.txt|*.ubsan.txt|*.log|*.md) continue ;;
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
      *.txt)
        if [ "$prefixed" -ne 1 ]; then
          # Hold non-canonical .txt as a relaxed fallback, but skip prose /
          # metadata stems (notes, readme, output, log, …) — those document a
          # crash, they don't reproduce it. Mirrors NONINPUT_TEXT_STEMS in
          # lib/crash_artifacts.py.
          case "${lower%.txt}" in
            notes|note|readme|description|desc|summary|comment|comments|changelog|todo|output|out|log|logs|analysis|writeup|write-up|explanation) ;;
            *) [ -n "$relaxed" ] || relaxed="$f" ;;
          esac
          continue
        fi
        ;;
    esac
    printf '%s\n' "$f"
    return 0
  done < <(find "$d" -maxdepth 1 -type f ! -name '.*' -print0 2>/dev/null | sort -z)
  if [ -n "$relaxed" ]; then
    printf '%s\n' "$relaxed"
    return 0
  fi
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
  # `[a-z]+-param-overlap` catches the libc str/mem copy-overlap family
  # (strcpy-, strncpy-, strncat-, memcpy-, memmove-). Overlap reports
  # still represent attacker-driven out-of-bounds writes.
  grep -qiE 'AddressSanitizer: (heap-buffer-overflow|use-after-free|heap-use-after-free|container-overflow|dynamic-stack-buffer-overflow|stack-buffer-overflow|stack-use-after-return|stack-use-after-scope|global-buffer-overflow|alloc-dealloc-mismatch|intra-object-overflow|double-free|negative-size-param|bad-free|calloc-overflow|new-delete-type-mismatch|invalid-pointer-pair|[a-z]+-param-overlap)' "$asan_path" 2>/dev/null && return 0
  # Wild-address SEGV. The faulting address itself is the always-present
  # signal: a dereference of a non-near-null pointer (>= 0x1000, i.e. one page)
  # is a wild-pointer access, whereas a near-null address (< 0x1000 — a null
  # pointer plus a small struct offset) is the low-value null-deref family.
  # `SCARINESS: (wild-addr` is only emitted when print_scariness=1 (ASan full
  # mode); agent-captured traces and msan/tsan/asan-minimal rows omit it, so we
  # classify from the address and treat the SCARINESS tag as a secondary
  # confirmation when present. The regex eats leading zeros after `0x`, then
  # requires >= 4 significant hex digits, which is exactly >= 0x1000.
  grep -qE 'SEGV on unknown address 0x0*[1-9a-fA-F][0-9a-fA-F]{3,}' "$asan_path" 2>/dev/null && return 0
  grep -qE 'SCARINESS: [0-9]+ \(wild-addr' "$asan_path" 2>/dev/null && return 0
  # ThreadSanitizer (data race / used after free in heap object).
  grep -qE 'WARNING: ThreadSanitizer: (data race|heap-use-after-free|thread-leak|deadlock)' "$asan_path" 2>/dev/null && return 0
  # MemorySanitizer (read of uninit memory).
  grep -qE 'WARNING: MemorySanitizer: use-of-uninitialized-value' "$asan_path" 2>/dev/null && return 0
  # Go race detector emits the same TSan banner via the runtime hook.
  grep -qE '^WARNING: DATA RACE$' "$asan_path" 2>/dev/null && return 0
  # UBSan: only the ClusterFuzz security classes (Bad-cast/vptr,
  # Index-out-of-bounds, Incorrect-function-pointer-type, Object-size,
  # Non-positive-vla-bound-value) are memory-/type-safety crashes and stay
  # in crashes/. Every other UBSan check (arithmetic overflow, shift,
  # divide-by-zero, misaligned, pointer-overflow, null, ...) is real
  # undefined behaviour but not a memory-safety crash — triage_crash_dirs
  # demotes those to findings/ rather than keeping them here. See
  # crash_dir_ubsan_class for the per-class split.
  [ "$(crash_dir_ubsan_class "$d")" = "security" ] && return 0
  return 1
}

# Classify a UBSan crash by ClusterFuzz's security taxonomy, mirroring
# google/clusterfuzz stacktraces/constants.py UBSAN_CRASH_TYPES_{SECURITY,
# NON_SECURITY}. Echoes one of:
#   security    — a memory-/type-safety UBSan class: Bad-cast (vptr),
#                 Index-out-of-bounds, Incorrect-function-pointer-type,
#                 Object-size, Non-positive-vla-bound-value. Kept in crashes/.
#   nonsecurity — any other UBSan runtime error (signed/unsigned overflow,
#                 divide-by-zero, shift, float-cast, bool, enum, misaligned,
#                 pointer-overflow, null, return, nonnull, ...). Real
#                 undefined behaviour, but not a memory-safety crash; demoted
#                 to findings/.
# Returns 1 with no output when the trace is not a UBSan report (so ASan /
# TSan / MSan callers are unaffected). The match substrings are the literal
# text clang's UBSan prints (see ClusterFuzz UBSAN_*_REGEX), so the rule
# stays stable across projects rather than enumerating per-target symbols.
crash_dir_ubsan_class() {
  local d="$1"
  local asan_path
  asan_path=$(find_primary_asan_in_crash_dir "$d" 2>/dev/null || true)
  [ -n "$asan_path" ] && [ -s "$asan_path" ] || return 1
  grep -qE 'runtime error:|UndefinedBehaviorSanitizer' "$asan_path" 2>/dev/null || return 1
  if grep -qiE 'through pointer to incorrect function type|out of bounds for type|with insufficient space for an object of type|variable length array bound evaluates to non-positive value|does not point to an object of type' "$asan_path" 2>/dev/null; then
    printf 'security\n'
  else
    printf 'nonsecurity\n'
  fi
  return 0
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
  grep -qE "^thread '.*'( \([^)]*\))? panicked at|fatal runtime error:" "$asan_path" 2>/dev/null && return 0
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
  # Contract-concern reasons (verdict=contract-flag from the structured
  # Caller contract / Parameter control / Trigger source matrix)
  # are returned with a `contract-flag:` prefix. triage_crash_dirs
  # then annotates the dir in place (.contract-flagged sidecar +
  # report block) and KEEPS it in crashes/. The downstream severity
  # scorer recomputes the same structured fields and target.toml verdict.
  # crashes-rejected/ stays reserved for non-security
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

  local evidence hash cache
  evidence=$(collect_crash_legitimacy_evidence "$d" 2>/dev/null) || evidence=""
  [ -n "$evidence" ] || return 1

  hash=$(printf '%s' "$evidence" | _triage_text_sha1 2>/dev/null || true)
  cache="$d/.llm-legit-crash.json"
  # Asymmetric cache semantics: a positive (legitimate) decision is
  # stable across idempotent reruns (auto-bundling and severity scoring can
  # mutate report fields without changing the underlying crash), so we
  # accept it on require_web match alone. A negative decision still
  # requires the exact evidence hash so a content edit can re-litigate.
  if [ -n "$hash" ]; then
    local cache_fields="" cached_evidence_sha="" cached_require="" cached_legit="" cached_reason="" cached_votes=0
    if cache_fields=$(_triage_legit_cache_fields "$cache" 2>/dev/null); then
      eval "set -- $cache_fields"
      cached_evidence_sha="${1:-}"
      cached_require="${2:-}"
      cached_legit="${3:-}"
      cached_reason="${4:-}"
      cached_votes="${5:-0}"
    fi
    if [ "$cached_require" = "$require_web_gate" ]; then
      if [ "$cached_legit" = "true" ]; then
        return 2
      fi
      if [ "$cached_legit" = "false" ] && [ "$cached_evidence_sha" = "$hash" ]; then
        # Honor a cached rejection only if the full quorum agreed; a legacy
        # single-vote cache is re-litigated through the multi-vote gate.
        case "$cached_votes" in ''|*[!0-9]*) cached_votes=0 ;; esac
        if [ "$cached_votes" -ge "$(_triage_gate_quorum)" ]; then
          printf '%s' "${cached_reason:-cached crash promotion rejection}"
          return 0
        fi
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

  local vrc reason
  _triage_gate_quorum_vote legit_crash "legitimate,reason" legitimate "$prompt"; vrc=$?
  [ "$vrc" -eq 1 ] && return 1
  reason=$(printf '%s' "$_TRIAGE_GATE_VOTE" | jq -r '.reason // ""' 2>/dev/null)
  [ -n "$reason" ] && [ "$reason" != "null" ] || reason="crash promotion gate rejected"

  if [ "$vrc" -eq 2 ]; then
    { jq -n --arg require_web "$require_web_gate" --argjson legitimate true \
         --arg reason "$reason" \
         '{require_web: $require_web, legitimate: $legitimate, reason: $reason}' \
        | _triage_cache_write_envelope "$cache" "legit_crash" "evidence_sha1" "$hash"; } || true
    return 2
  fi

  # vrc == 0: quorum of independent votes agreed the crash is illegitimate.
  { jq -n --arg require_web "$require_web_gate" --argjson legitimate false \
       --arg reason "$reason" --argjson votes "$_TRIAGE_GATE_VOTES" \
       '{require_web: $require_web, legitimate: $legitimate, reason: $reason, votes: $votes}' \
      | _triage_cache_write_envelope "$cache" "legit_crash" "evidence_sha1" "$hash"; } || true
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

# True iff a .llm_fields.json sidecar already carries every scoring-relevant
# reach field with a non-empty value. caller_controls is load-bearing: when
# it is absent, bin/severity falls back to its weakest controls gate
# (×0.4) and Reach collapses to Low, so a sidecar missing it is INCOMPLETE
# and must be re-filled rather than accepted as final. caller_contract is
# deliberately not required here — its absence scores as ×1.0 (obeyed), so
# it never collapses the side and needn't force a retry.
#
# trigger_source is required for every filled sidecar because severity scoring and
# contract scoring are derived from Trigger source ∩ attacker_controls, not from
# callback/caller-control prose.
_llm_fields_complete() {
  jq -e '
    (.surface // "")         != "" and
    (.primitive // "")       != "" and
    (.caller_controls // "") != "" and
    (.trigger_source // "")  != ""
  ' "$1" >/dev/null 2>&1
}

# Run a single-shot LLM classification pass on the report's narrative to
# fill structured fields the agent did not emit (Surface / Primitive
# class / Caller controls / Caller contract). The result is written to
# ``$d/.llm_fields.json`` so bin/severity picks it up as a fallback
# — agent-authored fields always win. Best-effort: failure leaves the
# report dir untouched.
#
# Knobs: LLM_FIELD_FILL_DISABLE=1 skips the call (also blocked by global
# LLM_DECIDE_DISABLE=1 from lib/llm_decide.sh). LLM_FIELD_FILL_MAX_ATTEMPTS
# (default 2) caps re-fills of a stubbornly incomplete sidecar.
_triage_llm_fill_fields() {
  local d="$1" id="$2"
  [ "${LLM_FIELD_FILL_DISABLE:-0}" = "1" ] && return 0
  command -v jq >/dev/null 2>&1 || return 0
  declare -f llm_decide >/dev/null 2>&1 || return 0
  # Skip only when a prior fill already captured every scoring-relevant
  # field. A PARTIAL sidecar (e.g. surface present but caller_controls
  # missing) is retried instead of cached as final — caching a partial
  # result silently pins the deterministic scorer to its missing-field
  # default (controls → ×0.4) and collapses severity to Low. The attempt
  # counter caps re-fills so a genuinely unfillable field (nothing in the
  # narrative to extract) stops re-spending budget every triage pass.
  local _sidecar="$d/.llm_fields.json"
  if [ -s "$_sidecar" ]; then
    _llm_fields_complete "$_sidecar" && return 0
    local _attempts
    _attempts=$(jq -r '._fill_attempts // 0' "$_sidecar" 2>/dev/null || echo 0)
    case "$_attempts" in ''|*[!0-9]*) _attempts=0 ;; esac
    [ "$_attempts" -ge "${LLM_FIELD_FILL_MAX_ATTEMPTS:-2}" ] && return 0
  fi

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

  # Use the shared single-shot decision timeout (default 45s), not a tight
  # hardcoded value: a slow reasoning backend (e.g. codex) routinely needs
  # >20s, and a timeout here returns empty → no sidecar → the reach fields
  # silently never get filled (severity then collapses to the missing-field
  # default). Operators raise LLM_DECISION_TIMEOUT once for all decisions.
  local out
  out=$(printf '%s' "$prompt" \
    | llm_decide reachability-fields '' "${LLM_DECISION_TIMEOUT:-45}" 2>/dev/null) || return 0
  [ -n "$out" ] || return 0
  # Validate it's a JSON object before writing.
  if printf '%s' "$out" | jq -e 'type=="object"' >/dev/null 2>&1; then
    # Merge the new non-empty fields over any prior partial sidecar (new
    # wins; previously-captured keys the new response omitted are kept) and
    # bump the attempt counter so an unfillable field eventually stops
    # retrying. On any jq failure, fall back to writing the fresh response.
    local _prev='{}'
    [ -s "$_sidecar" ] && _prev=$(cat "$_sidecar" 2>/dev/null)
    printf '%s' "$_prev" | jq -e 'type=="object"' >/dev/null 2>&1 || _prev='{}'
    printf '%s' "$out" | jq --argjson prev "$_prev" '
        ($prev * (with_entries(select(.value != null and .value != ""))))
        | ._fill_attempts = (($prev._fill_attempts // 0) + 1)
      ' > "$_sidecar.tmp" 2>/dev/null \
      && mv "$_sidecar.tmp" "$_sidecar" \
      || printf '%s' "$out" > "$_sidecar"
  fi
  return 0
}

# Run bin/severity against a crash/finding dir after the sanitizer evidence,
# testcase, and report are present. Offline, deterministic CVSS scoring that
# rewrites the report's Severity and writes severity.json; this is
# post-processing for report annotation, never a discovery or preservation
# gate. Best-effort: a failure leaves the dir preserved and unenriched, and
# other gates still apply. A fixed wall-clock cap guards a parallel worker
# against one pathological report (scoring is local and normally sub-second).
_triage_run_severity() {
  local d="$1" id="$2" bin_dir="$3"
  rm -f "$d/.severity_ok" "$d/.severity_pending" "$d/.severity_failed" 2>/dev/null || true

  if [ ! -x "$bin_dir/severity" ]; then
    printf 'bin/severity not executable: %s/severity\n' "$bin_dir" > "$d/.severity_pending" 2>/dev/null || true
    return 0
  fi
  if [ ! -s "$d/report.md" ] && [ ! -s "$d/REPORT.md" ] && [ ! -s "$d/.audit/report.md" ]; then
    printf 'report missing; severity waits for report.md or REPORT.md\n' > "$d/.severity_pending" 2>/dev/null || true
    return 0
  fi

  local audit_dir="$d/.audit"
  mkdir -p "$audit_dir" 2>/dev/null || true
  local out_log="$audit_dir/severity.out"
  local err_log="$audit_dir/severity.err"

  local rc=0
  if declare -f audit_timeout_run >/dev/null 2>&1; then
    audit_timeout_run 120 "$bin_dir/severity" --report "$d" >"$out_log" 2>"$err_log"
    rc=$?
  else
    "$bin_dir/severity" --report "$d" >"$out_log" 2>"$err_log"
    rc=$?
  fi
  if [ "$rc" -eq 0 ]; then
    printf 'ok\n' > "$d/.severity_ok" 2>/dev/null || true
    return 0
  fi
  local reason
  reason=$(grep -m1 -v '^[[:space:]]*$' "$err_log" 2>/dev/null | head -c 220 || true)
  if [ -z "$reason" ]; then
    if [ "$rc" -eq 124 ]; then
      reason="timed out after 120s"
    else
      reason="exit ${rc} with no stderr; see ${err_log}"
    fi
  fi
  printf '%s\n' "$reason" > "$d/.severity_failed" 2>/dev/null || true
  audit_log "WARN: skipped severity scoring for ${id}: ${reason} — the dir is preserved without enrichment and other gates still apply" | tee -a "$INDEX"
}

# Fill missing reach fields + score every FIND/CRASH report under a pooled
# tree, so findings produced WITHOUT the harness's per-cell triage (notably
# the benchmark's model-direct condition) reach the deterministic scorer on
# equal footing with harness findings. For each dir this runs the same
# _triage_llm_fill_fields the per-cell pass runs, then the same deterministic
# caller-only contract reconciliation (so crash and finding twins of one bug
# localise and floor identically — same scorer, now fed the same fields).
# Findings are additionally scored here via _triage_run_severity because
# bin/severity --batch only walks crashes/ (crashes are left for the
# caller's --batch step, so we don't double-score them). Reads only on-disk
# reports — no live audit
# session — so it is safe to run during a --regenerate re-derivation as well
# as a live run. Idempotent (complete sidecars skip; re-scoring is cached)
# and best-effort. Honors LLM_FIELD_FILL_DISABLE.
#
# Usage: triage_fill_reach_fields_tree <pool_dir> [bin_dir]
triage_fill_reach_fields_tree() {
  local _root="$1" _bin_dir="${2:-${SCRIPT_ROOT:-.}/bin}"
  [ -d "$_root" ] || return 0
  # _triage_run_severity logs its failure tail to $INDEX (bare). In the
  # benchmark/pool context there is no audit INDEX, so default it here — under
  # `set -u` an unset $INDEX on the severity-failure path would abort the
  # whole run. Dynamic scope makes this local visible to the callee.
  local INDEX="${INDEX:-/dev/null}"
  local _d _id
  if [ -d "$_root/findings" ]; then
    for _d in "$_root"/findings/FIND-*; do
      [ -d "$_d" ] || continue
      _id=$(basename "$_d")
      _triage_llm_fill_fields "$_d" "$_id"
      # Reconcile the deterministic caller-only contract flag from the now-final
      # fields BEFORE scoring, so a caller-only finding gets the same "## Contract
      # concern" oob annotation (and impact floor) its crash twin gets. Crashes do
      # this via _triage_reconcile_contract_flag; findings need the narrative-only
      # variant because they carry no sanitizer artifact. Must precede
      # _triage_run_severity — unlike crashes (scored later by --batch),
      # findings are scored inline right here.
      _triage_reconcile_contract_flag_finding "$_d" "$_id"
      _triage_run_severity "$_d" "$_id" "$_bin_dir"
    done
  fi
  if [ -d "$_root/crashes" ]; then
    for _d in "$_root"/crashes/CRASH-*; do
      [ -d "$_d" ] || continue
      _id=$(basename "$_d")
      _triage_llm_fill_fields "$_d" "$_id"
      # Fields are now final for this crash — reconcile its contract flag from
      # them so a flag missed at per-cell audit time (computed before the
      # fields existed) is applied before the scorer runs. Additive/idempotent.
      _triage_reconcile_contract_flag "$_d" "$_id"
    done
  fi
  return 0
}

# Ensure the rejected-crash index has a machine-readable reason. Some callers
# write richer .autodiscard details before routing; preserve those, but make
# the common move helper fill the marker when a rejection path only supplied the
# reason argument.
_triage_ensure_autodiscard_reason() {
  local d="$1" reason="$2" marker="$1/.autodiscard"
  if [ -f "$marker" ] && grep -q '^# Reason:' "$marker" 2>/dev/null; then
    return 0
  fi
  if [ -f "$marker" ]; then
    {
      echo "# Reason: $reason"
      echo "# When: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    } >> "$marker" 2>/dev/null || true
    return 0
  fi
  {
    echo "# Auto-rejected by triage"
    echo "# Reason: $reason"
    echo "# When: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  } > "$marker" 2>/dev/null || true
}

# Move a triaged dir into crashes-rejected/ with an .autodiscard marker.
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
# in crashes/; the existing severity scorer rates it lower when it
# recomputes the structured verdict from report fields and target.toml, so the
# downstream score reflects the current contract concern without losing the
# crash from the count. Used by triage_crash_dirs step 4 when the verdict matrix
# returns a `contract-flag:` reason.
#
# Writes a `.contract-flagged` sidecar (machine-readable marker) and
# prepends a "## Contract concern" block to the report (REPORT.md
# preferred, then report.md) so a reviewer opening the dir sees the
# concern in-place.
_triage_annotate_contract_concern() {
  local d="$1" id="$2" reason="$3" noun="${4:-crash}"
  local report=""
  if [ -s "$d/REPORT.md" ]; then
    report="$d/REPORT.md"
  elif [ -s "$d/report.md" ]; then
    report="$d/report.md"
  fi

  {
    echo "# Contract-flagged by triage"
    echo "# Reason: $reason"
    echo "# When: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "# Action: dir stays in place. This sidecar records the current structured contract verdict; severity rescoring recomputes the verdict from fields and target.toml."
  } > "$d/.contract-flagged" 2>/dev/null || true

  [ -n "$report" ] || return 0

  local tmp
  tmp=$(mktemp "${TMPDIR:-/tmp}/contract-flag.XXXXXX") || return 0
  awk -v reason="$reason" -v noun="$noun" '
    function emit_block() {
      print "## Contract concern"
      print ""
      print "Triage kept this " noun " and flagged a contract concern: " reason "."
      print ""
      print "The reported diagnostic is real. This section records the current structured contract verdict; downstream scoring recomputes the severity impact from the report fields and target.toml."
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

_triage_clear_contract_concern() {
  local d="$1" report=""
  rm -f "$d/.contract-flagged" 2>/dev/null || true
  if [ -s "$d/REPORT.md" ]; then
    report="$d/REPORT.md"
  elif [ -s "$d/report.md" ]; then
    report="$d/report.md"
  fi
  [ -n "$report" ] || return 0

  local tmp
  tmp=$(mktemp "${TMPDIR:-/tmp}/contract-clear.XXXXXX") || return 0
  # Terminate the skipped region on the same anchors the inserter stops the
  # block before: any "## " heading OR a bare "Summary:" line. Mirroring the
  # inserter keeps a block placed ahead of a bare "Summary:" line from
  # over-deleting that section on clear.
  awk '
    /^## Contract concern[[:space:]]*$/ { skip=1; next }
    skip && (/^## / || /^Summary:[[:space:]]*$/) { skip=0 }
    skip { next }
    { print }
  ' "$report" > "$tmp" 2>/dev/null && mv "$tmp" "$report" 2>/dev/null || {
    rm -f "$tmp" 2>/dev/null || true
  }
  return 0
}

# Reconcile a result dir's contract annotation against its FINAL structured
# fields and the active target attacker_controls. The annotation is derived
# state: if the current verdict promotes, stale .contract-flagged sidecars and
# report sections are removed before scoring/benchmark aggregation.
_triage_reconcile_contract_flag() {
  local d="$1" id="$2"
  [ -d "$d" ] || return 0
  local report line verdict reason
  report=$(find_primary_crash_narrative "$d" 2>/dev/null || true)
  [ -n "$report" ] || { _triage_clear_contract_concern "$d"; return 0; }
  line=$(evaluate_crash_verdict "$report" "${TARGET_ATTACKER_CONTROLS_CSV:-bytes}" 2>/dev/null) || line=""
  verdict="${line%%	*}"
  reason="${line#*	}"
  case "$verdict" in
    contract-flag)
      _triage_annotate_contract_concern "$d" "$id" "$reason"
      ;;
    *)
      _triage_clear_contract_concern "$d"
      ;;
  esac
  return 0
}

# Finding analogue of _triage_reconcile_contract_flag: keep the visible
# "## Contract concern" annotation in sync with the same structured verdict a
# crash twin would get.
#
# Reuses evaluate_crash_verdict (narrative-only) rather than the crash reconcile,
# whose security-evidence gate would "missing evidence"-reject a finding before
# the verdict runs. Recall-safe: flags ONLY when a trigger component is outside
# attacker_controls, so a genuine attacker-byte finding (trigger ⊆ attacker_
# controls) stays unflagged at full severity; stale flags are removed.
_triage_reconcile_contract_flag_finding() {
  local d="$1" id="$2"
  [ -d "$d" ] || return 0
  local report
  report=$(find_primary_crash_narrative "$d" 2>/dev/null || true)
  [ -n "$report" ] || { _triage_clear_contract_concern "$d"; return 0; }
  local line verdict reason
  line=$(evaluate_crash_verdict "$report" "${TARGET_ATTACKER_CONTROLS_CSV:-bytes}" 2>/dev/null) || line=""
  verdict="${line%%	*}"
  reason="${line#*	}"
  if [ "$verdict" = "contract-flag" ]; then
    _triage_annotate_contract_concern "$d" "$id" "$reason" "finding"
  else
    _triage_clear_contract_concern "$d"
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
        "$d/.promotion_pending.count" 2>/dev/null || true
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
  if declare -f audit_realpath >/dev/null 2>&1; then
    local _resolved
    _resolved=$(audit_realpath "$d" 2>/dev/null || true)
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
  _triage_ensure_autodiscard_reason "$d" "$reason"
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
#                                 Severity score absence is not a
#                                 rejection reason.
#   5. Severity                 — best-effort post-processing. Writes
#                                 severity.json + Severity into the
#                                 report and .severity_* status markers.
#                                 Failure never moves a crash out of
#                                 crashes/.
#   5.5 Trigger-provenance gate — independent source-reading reviewer;
#                                 rejects a crash whose triggering state no
#                                 attacker can reach (forged internal state,
#                                 caller self-sabotage), uniformly across
#                                 trigger kinds. Recall-safe, demote-only.
#   6. LLM confirm-agent        — final report sanity review.
# One crash dir through the step 0-6 pipeline documented above. Writes
# the dir's disposition ("rejected" / "bad" / "ok") to $outcome_file so
# triage_crash_dirs can aggregate counts across parallel workers — every
# write below lands inside this dir (or goes through flock'd bin/state),
# so concurrent invocations on DIFFERENT dirs never interfere.

# Echo the first present, non-empty report file in a crash dir (REPORT.md,
# report.md, or .audit/report.md), or nothing. Returns 1 when none exists.
_triage_crash_report_path() {
  local d="$1" f
  for f in "$d/REPORT.md" "$d/report.md" "$d/.audit/report.md"; do
    [ -s "$f" ] && { printf '%s' "$f"; return 0; }
  done
  return 1
}

_triage_one_crash_dir() {
  local d="$1" bin_dir="$2" outcome_file="$3"
  printf 'ok\n' > "$outcome_file" 2>/dev/null || true
  [ -d "$d" ] || return 0
  local id
  id=$(basename "$d")

    local asan_path
    asan_path=$(find_primary_asan_in_crash_dir "$d" 2>/dev/null || true)

    # ── 0a. Harness-rooted reject ────────────────────────────────────
    # A crash whose fault is entirely in the audit harness/driver (leaf frame
    # is the driver AND no target-library frame appears anywhere — including the
    # freed/allocated context) is not a target vulnerability. Reject it to
    # crashes-rejected/ so it leaves the crash count, not just the severity.
    # Conservative: a real library bug merely *exercised* by a harness keeps a
    # library frame in its stack and is NOT matched (see _crash_is_harness_rooted
    # in bin/severity — the single source of truth, reused here so the rule
    # is not duplicated in shell).
    if [ -n "$asan_path" ] \
       && python3 "$bin_dir/severity" --report "$d" --harness-rooted-check >/dev/null 2>&1; then
      if [ ! -f "$d/.autodiscard" ]; then
        {
          echo "# Auto-rejected by triage_crash_dirs"
          echo "# Reason: harness-rooted (fault frame in audit driver, no target-library frame)"
          echo "# Source: $(basename "${asan_path:-unknown}")"
        } > "$d/.autodiscard" 2>/dev/null || true
      fi
      _triage_move_to_rejected "$d" "$id" \
        "harness-rooted: fault frame in audit harness/driver, no target-library frame" \
        && printf 'rejected\n' > "$outcome_file"
      return 0
    fi

    # ── 0. Deterministic UBSan classification ────────────────────────
    # Non-memory-safety UBSan (signed/unsigned overflow, divide-by-zero,
    # shift, float-cast, misaligned, pointer-overflow, null, ...) is real
    # undefined behaviour but not a crash we keep in crashes/ — it belongs
    # in findings/. The 5 ClusterFuzz security UBSan classes return
    # "security" and stay in the crash pipeline. See crash_dir_ubsan_class.
    #
    # We only MARK it here (ubsan_demote=1); the actual move to findings/
    # happens after the step-2 artifact-completeness gate, so a demoted
    # finding still has report.md + a valid sanitizer trace + a testcase
    # (an incomplete dir stays promotion-pending in crashes/ exactly like any
    # other crash). Marking before step 1 keeps routing deterministic: the
    # probabilistic LLM discard is skipped, so this bug is never sent to
    # crashes-rejected/ (where a separate recon pass would re-file the same
    # bug under findings/, double-listing it).
    #
    # ASan is prioritised over UBSan: a trace carrying BOTH a UBSan
    # non-security line AND a real ASan/TSan/MSan memory-safety report (or a
    # UBSan security class) keeps the higher-severity signal and is NOT
    # marked. crash_dir_has_memory_safety_asan_signal greps the ASan family
    # first and find_primary_asan_in_crash_dir resolves asan.txt ahead of
    # ubsan.txt, so the memory-safety crash always wins.
    local ubsan_demote=0
    if [ "$(crash_dir_ubsan_class "$d")" = "nonsecurity" ] \
       && ! crash_dir_has_memory_safety_asan_signal "$d"; then
      ubsan_demote=1
    fi

    # ── 1. LLM/regex DISCARD ─────────────────────────────────────────
    # Skipped for ubsan_demote dirs: their disposition is already fixed
    # (demote-to-findings after validation), so the probabilistic discard
    # gate must not divert them to crashes-rejected/.
    # Three-valued LLM semantics:
    #   rc=0 (DISCARD) → LLM-named reason wins, UNLESS the sanitizer already
    #                    proved a memory-safety class — that veto wins.
    #   rc=2 (KEEP)    → regex bypass; do not auto-discard even if it would.
    #   rc=1 (UNDEC)   → fall through to regex.
    # The sanitizer-keep veto is the fix for the FN where an LLM (shown a
    # bounded prefix of the trace) discards a deterministically-confirmed bug.
    # crash_dir_has_memory_safety_asan_signal is the project's curated,
    # cross-sanitizer classifier — ASan, TSan, MSan, the Go race detector,
    # and the memory-safety UBSan checks all count. Deterministic sanitizer
    # proof always beats a probabilistic discard; downstream caller-contract
    # / severity gates still decide whether it promotes.
    if [ "$ubsan_demote" -eq 0 ]; then
    local llm_status=1 llm_discard_reason="" regex_says_discard=0 sanitizer_says_keep=0
    if [ -n "$asan_path" ]; then
      llm_discard_reason=$(llm_triage_crash_decision "$asan_path" 2>/dev/null)
      llm_status=$?
      is_autodiscard_crash_output "$asan_path" && regex_says_discard=1
      crash_dir_has_memory_safety_asan_signal "$d" && sanitizer_says_keep=1
    fi

    # ── Hard reject: recoverable low-value classes the LLM may NOT rescue ──
    # A null-pointer/first-page deref and a plain recursion stack-overflow both
    # terminate a single process with no memory corruption and no controllable
    # primitive — robustness crashes, not security-class bugs. Unlike
    # OOM/MOZ_CRASH/panic (still LLM-rescuable in the case below), these two are
    # rejected unconditionally so an "interesting"-leaning keep vote cannot pull
    # them back into crashes/ and inflate yield. The memory-safety veto still
    # wins: a real corruption class that merely also faults near null / exhausts
    # the stack keeps sanitizer_says_keep=1 and is exempt.
    local hard_reject_reason=""
    if [ -n "$asan_path" ] && [ "$sanitizer_says_keep" -eq 0 ]; then
      if _crash_is_null_deref "$asan_path"; then
        hard_reject_reason="null-deref (recoverable low-value crash; not a security class)"
      elif _crash_is_stack_exhaustion "$asan_path"; then
        hard_reject_reason="stack exhaustion (recursion DoS; recoverable low-value crash, not memory corruption)"
      fi
    fi

    local discard=0 discard_reason=""
    if [ -n "$hard_reject_reason" ]; then
      discard=1
      discard_reason="$hard_reject_reason"
    else
    case "$llm_status" in
      0)  if [ -n "$llm_discard_reason" ] && [ "$sanitizer_says_keep" -eq 1 ]; then
            audit_log "KEEP-VETO: ${id} — sanitizer-confirmed memory-safety class; ignoring LLM discard (${llm_discard_reason})" | tee -a "$INDEX" >/dev/null 2>&1 || true
          elif [ -n "$llm_discard_reason" ]; then
            discard=1
            discard_reason="LLM: $llm_discard_reason"
          fi ;;
      2)  discard=0 ;;
      *)  if [ "$regex_says_discard" -eq 1 ]; then
            discard=1
            discard_reason="non-finding class (null-deref/OOM/MOZ_CRASH/panic/stack-overflow)"
          fi ;;
    esac
    fi

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
      _triage_move_to_rejected "$d" "$id" "$discard_reason" && printf 'rejected\n' > "$outcome_file"
      return 0
    fi
    fi  # end: step 1 skipped when ubsan_demote=1

    # ── 2. Validate required files ─────────────────────────────────
    # Accept either lowercase audit-side report.md or capitalized bundle
    # REPORT.md (after export-repro has run). For sanitizer output: the
    # bundle has sanitizer.txt at root (legacy: asan.txt); pre-bundle
    # dirs may have *_confirm.asan.txt / *.asan.txt only.
    local missing=()
    # Judge the audit-side report.md when present (the source the agent edits);
    # a rendered REPORT.md may already exist from an earlier pass. An auto-filed
    # bin/probe skeleton still carrying the `_TODO (agent):` markers in Root
    # Cause / Data Flow is not yet enriched — hold it as promotion-pending
    # rather than let a placeholder report ship as a maintainer-facing bundle.
    if [ ! -s "$d/report.md" ] && [ ! -s "$d/REPORT.md" ]; then
      missing+=("report.md")
    elif [ -s "$d/report.md" ]; then
      # Anchor to line start: only the unreplaced Root Cause / Data Flow
      # placeholder lines begin with the marker. An instructional mention of
      # it elsewhere (e.g. the skeleton's intro note) must not keep an
      # otherwise-enriched report pending forever.
      grep -q '^_TODO (agent):' "$d/report.md" 2>/dev/null \
        && missing+=("report.md(auto-filed skeleton not yet enriched)")
    elif grep -q '^_TODO (agent):' "$d/REPORT.md" 2>/dev/null; then
      missing+=("report.md(auto-filed skeleton not yet enriched)")
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
        _triage_move_to_rejected "$d" "$id" "$ttl_reason" && printf 'rejected\n' > "$outcome_file"
        return 0
      fi
      printf 'bad\n' > "$outcome_file" 2>/dev/null || true
      audit_log_throttled "incomplete-${id}" "WARN: crashes/${id} incomplete (pass ${pending_count}/${max_pending}) — missing: ${missing[*]}" | tee -a "$INDEX"
      return 0
    fi

    # Non-memory-safety UBSan marked in step 0: demote to findings/ only now
    # that the dir has passed the SAME completeness gate as every crash —
    # report.md + valid sanitizer trace + a testcase. A reproducing testcase
    # is required for UBSan findings (the dir reached crashes/ via one, and a
    # UBSan report is only actionable upstream with a reproducer). Incomplete
    # dirs never reach here — they stay promotion-pending in crashes/ above.
    if [ "$ubsan_demote" -eq 1 ]; then
      _triage_route_rejection "$d" "$id" \
        "demote-to-findings: UBSan non-memory-safety class — real undefined behaviour, filed as a finding not a crash" \
        && printf 'rejected\n' > "$outcome_file"
      return 0
    fi

    if crash_dir_is_findings_only_target \
       && crash_dir_has_runtime_diagnostic_signal "$d" \
       && ! crash_dir_has_memory_safety_asan_signal "$d"; then
      local runtime_demote_reason="demote-to-findings: runtime diagnostic without sanitizer-class memory-safety signal"
      _triage_route_rejection "$d" "$id" "$runtime_demote_reason" && printf 'rejected\n' > "$outcome_file"
      return 0
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
        _triage_move_to_rejected "$d" "$id" "$ttl_reason" && printf 'rejected\n' > "$outcome_file"
        return 0
      fi
      printf 'bad\n' > "$outcome_file" 2>/dev/null || true
      audit_log_throttled "bundle-${id}" "WARN: crashes/${id} incomplete bundle (pass ${pending_count}/${max_pending}) — missing: ${bundle_csv}" | tee -a "$INDEX"
      return 0
    fi
    _triage_clear_promotion_sidecars "$d"

    # ── 4. Security-boundary check ─────────────────────────────────
    # This check separates three dispositions:
    #   - HARD reject (missing security evidence, web-only on browser
    #     target): move to crashes-rejected/. These are the
    #     no-sanitizer-signal / wrong-threat-boundary cases that
    #     crashes-rejected/ exists for, alongside Step 1 autodiscards
    #     (OOM / panic / null-deref).
    #   - SOFT contract-flag (verdict=contract-flag from the structured
    #     caller-contract / parameter-control / trigger-source matrix):
    #     annotate IN PLACE with a .contract-flagged sidecar
    #     + "## Contract concern" report block and KEEP in crashes/.
    #     The downstream severity scorer recomputes the same structured
    #     verdict from report fields and target.toml, so these are represented
    #     in Severity without being lost from the crashes/ count or the
    #     severity scoring pipeline.
    #   - demote-to-findings: existing path, routed through
    #     _triage_route_rejection.
    # This check must not depend on bin/severity output.
    local security_reject_reason=""
    security_reject_reason=$(crash_dir_security_rejection_reason "$d" 2>/dev/null || true)
    if [ -n "$security_reject_reason" ]; then
      case "$security_reject_reason" in
        contract-flag:*)
          local flag_reason="${security_reject_reason#contract-flag: }"
          _triage_annotate_contract_concern "$d" "$id" "$flag_reason"
          audit_log "CONTRACT-FLAG: crashes/${id} kept in crashes/ with contract-concern annotation — ${flag_reason}. The severity scorer recomputes from fields and target.toml." | tee -a "$INDEX"
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
          _triage_route_rejection "$d" "$id" "$security_reject_reason" && printf 'rejected\n' > "$outcome_file"
          return 0
          ;;
      esac
    fi

    # ── 5. Severity post-processing ───────────────────────────────
    # Best-effort severity/report enrichment only. Failure is recorded via
    # .severity_failed and never blocks crash preservation. The LLM
    # hybrid pass fills any missing structured fields before scoring.
    _triage_llm_fill_fields "$d" "$id"
    _triage_run_severity "$d" "$id" "$bin_dir"

    local crash_report=""
    crash_report=$(_triage_crash_report_path "$d") || crash_report=""

    # ── 5.5 Trigger-provenance gate ────────────────────────────────
    # Independent, source-reading reachability reviewer over the scored
    # report. Step 4's verdict matrix promotes any crash whose trigger ⊆
    # attacker_controls, which keeps a `bytes`-triggered crash at full
    # severity even when those bytes are internal state the program produces
    # itself and only a trusted caller could forge. This gate applies the
    # same reachability test to every trigger kind and routes a disproof-
    # backed Reject to crashes-rejected/ (recoverable), so a forged-state or
    # caller-self-sabotage crash can no longer inflate the crash set or its
    # severity. Recall-safe and demote-only; keeps everything else untouched.
    if [ -n "$crash_report" ] \
       && _triage_crash_trigger_provenance_gate "$d" "$id" "$crash_report" "$bin_dir"; then
      printf 'rejected\n' > "$outcome_file"
      return 0
    fi

    # ── 6. LLM confirm-agent (final pre-promotion gate) ────────────
    # Looks at the finished, bundled report.md and asks
    # whether it is genuinely fileable upstream. Cached by report SHA-1
    # so unchanged reports are free on rerun. Disabled targets / LLM
    # unavailable → undecided → fall through (existing behavior).
    if [ "${CRASH_CONFIRM_AUTO:-1}" = "1" ]; then
      local confirm_report="$crash_report"
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
          _triage_move_to_needs_review "$d" "$id" "LLM-CONFIRM: $confirm_reason" && printf 'rejected\n' > "$outcome_file"
          return 0
        fi
      fi
    fi
  return 0
}

# Worker for the crash-sweep pool: $1=crash dir, $2=1-based index. Reads
# bin_dir/outcome_dir from triage_crash_dirs via dynamic scope.
_triage_crash_pool_worker() {
  _triage_one_crash_dir "$1" "$bin_dir" "$outcome_dir/$2" || true
}

triage_crash_dirs() {
  mkdir -p "$RESULTS_DIR/crashes" "$RESULTS_DIR/crashes-rejected" 2>/dev/null || true
  _requeue_crash_needs_review_dirs

  local bin_dir
  bin_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/../bin" 2>/dev/null && pwd)

  local -a crash_dirs=()
  local d
  for d in "$RESULTS_DIR"/crashes/CRASH-*/; do
    [ -d "$d" ] || continue
    crash_dirs+=("$d")
  done
  [ "${#crash_dirs[@]}" -gt 0 ] || return 0

  # Per-dir outcome files let parallel workers report dispositions back
  # without sharing shell state. mktemp failure degrades to a PID-keyed
  # dir; concurrent sweeps can't collide because the housekeeping driver
  # waits for the previous background sweep before starting a new one.
  local pool outcome_dir
  pool=$(_triage_dir_pool_size)
  outcome_dir=$(mktemp -d "${TMPDIR:-/tmp}/triage-crash-outcomes.XXXXXX" 2>/dev/null || true)
  if [ -z "$outcome_dir" ]; then
    outcome_dir="${TMPDIR:-/tmp}/triage-crash-outcomes.$$"
    rm -rf "$outcome_dir" 2>/dev/null || true
    mkdir -p "$outcome_dir" 2>/dev/null || true
  fi

  # Each worker writes its own indexed outcome file ($outcome_dir/<n>); the
  # tally below cats them all AFTER the pool drains, so the bounded FIFO window
  # (vs an all-jobs barrier that idles on the slowest 3-gate + severity
  # chain) changes scheduling only, never a disposition.
  pool_run "$pool" _triage_crash_pool_worker "${crash_dirs[@]}"

  local bad rejected
  bad=$(cat "$outcome_dir"/* 2>/dev/null | grep -cx 'bad' 2>/dev/null || true)
  rejected=$(cat "$outcome_dir"/* 2>/dev/null | grep -cx 'rejected' 2>/dev/null || true)
  case "$bad" in ''|*[!0-9]*) bad=0 ;; esac
  case "$rejected" in ''|*[!0-9]*) rejected=0 ;; esac
  rm -rf "$outcome_dir" 2>/dev/null || true

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
  # older rubrics don't apply to the current gate. This gate is the QUALITY
  # decision only — {accept, reason, class, severity}. Finding IDENTITY is the
  # deterministic (class, file, line) site computed at cluster time
  # (lib/finding_signature.py), not anything this gate produces, so the gate
  # works the same for harness, recon, and model-direct findings. v10 dropped
  # the old dedup_key field from the verdict shape. v11 added the
  # non-product-surface reject category (reject by role when the primary
  # location is clearly non-shipping; accept on any scope doubt). v12 adds
  # explicit reject buckets for OOM-only cleanup, caller-contract misuse,
  # intentional extension surfaces, and private/internal metadata claims.
  # v13 flips the prompt default to REJECT-on-unproven-substance (a finding
  # must affirmatively show a source/control/sink/boundary chain) — paired
  # with the accept-quorum below so a single lenient vote can no longer keep
  # a weak prose finding.
  local decision_version="v13"

  # Quorum required for a verdict to stick, on BOTH sides. Each call resolves
  # the quorum IN-LINE — independent LLM votes are taken back-to-back until
  # `accept_quorum` accepts accumulate (verdict settles to accept) or `quorum`
  # rejects accumulate (verdict settles to accept=false). Acceptance is no
  # longer a single-vote veto: a lone lenient vote can no longer keep a weak
  # finding, which was the dominant false-positive path for prose findings
  # that carry no crash artifact (a confirmed bug still gets accept_quorum
  # agreement; a borderline lead that one reviewer waves through is demoted to
  # findings-rejected/, where it stays recoverable). A 1-1 split draws one
  # tiebreak vote — max_votes = accept_quorum + quorum - 1 bounds the loop.
  # This replaces the older cross-pass accumulator that depended on the audit
  # loop running validate_find_gate a second time before the cell budget ran
  # out — a finding produced near the end of a run never got the second vote
  # and stayed half-judged. The crash-promotion gates share the leaner
  # _triage_gate_quorum_vote helper (and keep single-positive-vote semantics —
  # a crash has a sanitizer artifact on disk, so it does not need the symmetric
  # quorum a prose finding does); this gate keeps its own loop because it also
  # threads class/severity out of the accepting votes and records this pass's
  # reject tally in reject_count + .find_reject_count. Each pass resolves the
  # quorum FRESH (the loop starts from accepts=0/rejects=0); the marker is NOT
  # accumulated across passes — a partial (< quorum) tally just leaves the FIND
  # pending so the next pass re-judges it from scratch. A settled (>= quorum)
  # marker is what persists, so the pool worker still quarantines on a later
  # housekeeping pass even when the decision short-circuits on the cache.
  local quorum="${FIND_GATE_QUORUM:-2}"
  case "$quorum" in ''|*[!0-9]*) quorum=2 ;; esac
  [ "$quorum" -ge 1 ] || quorum=1

  # Accept-quorum: independent accepts required to KEEP a finding. Default 2
  # mirrors the reject quorum so neither verdict can be set by a single vote.
  local accept_quorum="${FIND_GATE_ACCEPT_QUORUM:-2}"
  case "$accept_quorum" in ''|*[!0-9]*) accept_quorum=2 ;; esac
  [ "$accept_quorum" -ge 1 ] || accept_quorum=1
  local max_votes=$(( accept_quorum + quorum - 1 ))

  # content_sha1 is recorded for forensics (what the report looked like when
  # judged) but is NOT used to gate re-evaluation — see the short-circuit
  # below for why.
  local hash cache
  hash=$(_triage_file_sha1 "$desc_path" 2>/dev/null || true)
  cache="$find_dir/.llm-find-quality.json"
  local reject_marker="$find_dir/.find_reject_count"

  # Short-circuit on the cached VERDICT alone — decision_version + accept —
  # never on the report's content hash. cluster-findings, report_enrich, and
  # render-md all rewrite report.md AFTER the verdict is cached: they stamp
  # `Cluster:`/`Dedup key:` lines, inject `<!-- enrich:* -->` blocks, and
  # reformat the Fields table (column padding). Those are cosmetic — the
  # security verdict does not depend on them — but a content-keyed cache busts
  # on every one of them and re-asks the LLM on each housekeeping pass.
  # Every accept=true OR accept=false-with-quorum verdict is final; the
  # explicit way to force re-evaluation is a decision_version bump.
  local cache_fields="" cached_version="" cached_accept="" cached_reason="" cached_reject_count=0 cached_content_sha="" cached_accept_count=0
  if cache_fields=$(_triage_find_quality_cache_fields "$cache" 2>/dev/null); then
    eval "set -- $cache_fields"
    cached_version="${1:-}"
    cached_accept="${2:-}"
    cached_reason="${3:-}"
    cached_reject_count="${4:-0}"
    cached_content_sha="${5:-}"
    cached_accept_count="${6:-0}"
    case "$cached_reject_count" in ''|*[!0-9]*) cached_reject_count=0 ;; esac
    case "$cached_accept_count" in ''|*[!0-9]*) cached_accept_count=0 ;; esac
    if [ "$cached_version" = "$decision_version" ]; then
      # Short-circuit only when the cached verdict was reached under a quorum
      # at least as strict as the one in force now — otherwise a verdict
      # settled under FIND_GATE_ACCEPT_QUORUM=1 (or a lower FIND_GATE_QUORUM)
      # would be treated as final under the stricter default. Mirrors the
      # reject side: re-evaluate rather than trust an under-quorum verdict.
      if [ "$cached_accept" = "true" ] && [ "$cached_accept_count" -ge "$accept_quorum" ]; then
        return 0
      fi
      if [ "$cached_accept" = "false" ] && [ "$cached_reject_count" -ge "$quorum" ]; then
        return 0
      fi
    fi
  fi

  local body
  body=$(_triage_read_report_bounded "$desc_path") || return 1

  local prompt
  prompt=$(render_prompt_template triage_find_quality.md.j2 \
    --var "body=${body}") || return 1

  # Run independent LLM votes back-to-back until `accept_quorum` accepts or
  # `quorum` rejects accumulate. Acceptance is NO LONGER a single-vote veto:
  # a finding is kept only when accept_quorum independent reviewers agree, so
  # one stray lenient vote can no longer rescue a weak prose finding. A 1-1
  # split is resolved by a single tiebreak vote (max_votes bounds the loop).
  local accepts=0 rejects=0 votes_taken=0 vote_json
  local last_reject_reason="" last_accept_reason="" accept_class="" accept_severity=""
  while [ "$votes_taken" -lt "$max_votes" ]; do
    vote_json=$(printf '%s' "$prompt" | llm_decide find_quality "accept,reason,class,severity" "$LLM_DECISION_TIMEOUT")
    if [ -z "$vote_json" ]; then
      # llm_decide failed to produce a verdict (LLM disabled, backend budget
      # exhausted, …). Stop voting; the post-loop block records this pass's
      # reject tally so the next pass re-judges from it (it is not accumulated).
      break
    fi
    local accept reason class severity
    accept=$(printf '%s' "$vote_json" | jq -r '.accept' 2>/dev/null)
    reason=$(printf '%s' "$vote_json" | jq -r '.reason' 2>/dev/null)
    class=$(printf '%s' "$vote_json" | jq -r '.class // ""' 2>/dev/null)
    severity=$(printf '%s' "$vote_json" | jq -r '.severity // ""' 2>/dev/null)
    case "$accept" in
      true|false) ;;
      *)
        # Unparseable verdict. Treat like a missing vote: stop and let the
        # post-loop block settle on whatever tally we have.
        break
        ;;
    esac
    votes_taken=$((votes_taken + 1))
    [ "$reason" = "null" ] && reason=""
    [ "$class" = "null" ] && class=""
    [ "$severity" = "null" ] && severity=""

    if [ "$accept" = "true" ]; then
      accepts=$((accepts + 1))
      [ -n "$reason" ] && last_accept_reason="$reason"
      [ -n "$class" ] && accept_class="$class"
      [ -n "$severity" ] && accept_severity="$severity"
      if [ "$accepts" -ge "$accept_quorum" ]; then
        [ -n "$last_accept_reason" ] || last_accept_reason="LLM accepted finding"
        rm -f "$find_dir/.needs-attention" 2>/dev/null || true
        # Accept-quorum reached — clear any partial reject signal.
        rm -f "$reject_marker" 2>/dev/null || true
        { jq -n --arg reason "$last_accept_reason" --arg class "$accept_class" \
             --arg severity "$accept_severity" \
             --arg version "$decision_version" \
             --argjson accept_count "$accepts" \
             '{decision_version: $version, accept: true, accept_count: $accept_count, reason: $reason, class: $class, severity: $severity}' \
            | _triage_cache_write_envelope "$cache" "find_quality" "content_sha1" "$hash"; } || true
        return 0
      fi
      continue
    fi

    # accept=false vote: tally and continue until the reject quorum.
    rejects=$((rejects + 1))
    [ -n "$reason" ] && last_reject_reason="$reason"
    [ "$rejects" -ge "$quorum" ] && break
  done

  # Reject quorum reached, or we ran out of usable verdicts before either
  # quorum settled. Cache the verdict with this pass's reject count; the caller
  # (validate_find_gate) quarantines once reject_count reaches `quorum`. A
  # partial (< quorum) tally leaves the FIND in place and the next pass
  # re-judges from scratch — counts are not summed across passes. A pure
  # partial-accept (some accepts but below accept_quorum, no rejects) returns
  # undecided so the FIND stays in findings/ for the next pass to re-judge.
  [ "$rejects" -ge 1 ] || return 1
  [ -n "$last_reject_reason" ] || last_reject_reason="LLM marked finding as non-security"
  printf '%s\n' "$rejects" > "$reject_marker" 2>/dev/null || true
  { jq -n --arg reason "$last_reject_reason" --arg version "$decision_version" \
       --argjson reject_count "$rejects" \
       '{decision_version: $version, accept: false, reason: $reason, class: "", severity: "", reject_count: $reject_count}' \
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
#   4. Run bin/severity against surviving FIND dirs for severity
#      annotation (same helper crashes use).
#   5. report.md → report.html sibling render happens in maintain_indexes
#      so the artifact set matches crashes/.
# One FIND dir through the quality gate + severity enrichment. Same
# isolation contract as _triage_one_crash_dir: every write lands inside
# this dir or goes through flock'd bin/state, so the pool in
# validate_find_gate can run different dirs concurrently.

# Move a rejected finding to findings-rejected/ and record it. Factored so the
# quality-quorum gate and the trigger gate produce an identical on-disk shape
# (the benchmark counts findings by directory presence, so a demote MUST be a
# physical move). $4=DROP audit-log tail, $5=reason for bin/state. Returns 0 on
# move, 1 if it could not move (finding left in place).
_triage_quarantine_find_dir() {
  local d="$1" id="$2" bin_dir="$3" drop_msg="$4" state_reason="$5"
  local qroot="${FIND_GATE_QUARANTINE_DIR:-$RESULTS_DIR/findings-rejected}"
  mkdir -p "$qroot" 2>/dev/null || true
  local target="$qroot/$id"
  [ -e "$target" ] && target="${target}.$(date -u +%Y%m%dT%H%M%SZ)"
  if mv "$d" "$target" 2>/dev/null; then
    local rel_target="${target#$RESULTS_DIR/}"
    [ "$rel_target" != "$target" ] || rel_target="$(basename "$qroot")/$(basename "$target")"
    audit_log "DROP: findings/${id} → ${rel_target} — ${drop_msg}" \
      | tee -a "${INDEX:-/dev/null}" >/dev/null 2>&1 || true
    # SOFT-block linked WORK-recon cards; recoverable via
    # `bin/state update-card --status unclaimed` if the reject is wrong.
    if [ -x "${bin_dir:-bin}/state" ]; then
      "${bin_dir:-bin}/state" \
        --results-dir "$RESULTS_DIR" \
        --target-path "${TARGET_ROOT:-}" \
        --target-slug "${TARGET_SLUG:-}" \
        mark-finding-rejected --find-id "$id" --reason "$state_reason" \
        >/dev/null 2>&1 || true
    fi
    return 0
  fi
  audit_log "WARN: could not quarantine findings/${id}; leaving in place" \
    | tee -a "${INDEX:-/dev/null}" >/dev/null 2>&1 || true
  return 1
}

# Run the recall-safe trigger-provenance reviewer (`validate-finding --gate
# trigger`) over a report. The independent reviewer reads the source tree but
# not the report's own severity/verdict, and — by that tool's own rule — only
# returns a Reject when it can name the source-level invariant that blocks every
# attacker route into the triggering state; an unsupported Reject is downgraded
# to Uncertain there. So this is purely demote-only: it can remove a fake, never
# manufacture or upgrade a finding.
#   $1 report path · $2 vote-file path · $3 bin_dir
# Returns: 1 = disproof-backed Reject (caller demotes); 0 = keep
# (Promote / Uncertain); 2 = no verdict yet → caller keeps, but the artifact
# stays retryable (LLM disabled, no backend, missing report/target, or a
# transient parse/backend failure).
#
# The vote file is the resume done-marker — but ONLY a CONCLUSIVE verdict
# (Promote / Uncertain / Reject) short-circuits a re-run. validate-finding also
# writes the file on a ParseFailure (transient backend/auth/parse error); that
# is not a verdict, so it must NOT permanently disable the gate — we fall
# through and let the next pass retry instead of caching a non-decision.
_run_trigger_provenance_vote() {
  local report="$1" vote_file="$2" bin_dir="$3"
  if [ -s "$vote_file" ]; then
    case "$(jq -r '.vote // empty' "$vote_file" 2>/dev/null)" in
      Reject)            return 1 ;;          # cached verdict
      Promote|Uncertain) return 0 ;;          # cached verdict
      # ParseFailure / unparseable → not a verdict; fall through and retry.
    esac
  fi
  [ "${LLM_DECIDE_DISABLE:-0}" = "1" ] && return 2
  [ -s "$report" ] && [ -d "${TARGET_ROOT:-}" ] || return 2
  # The run's resolved single backend (a fork-inherited audit var, the same one
  # llm_find_quality_decision uses). Not AUDIT_BACKEND — that can be "all".
  local vb="${ACTIVE_BACKEND:-}"
  [ -n "$vb" ] || return 2
  # MODEL is the run's resolved model (fork-inherited, like ACTIVE_BACKEND). It
  # must be forwarded explicitly — validate-finding is a subprocess and would
  # otherwise fall back to the backend default (and oss has no usable default).
  local rc=0
  "${bin_dir:-bin}/validate-finding" --finding "$report" --target-path "$TARGET_ROOT" \
    --backend "$vb" ${MODEL:+--model "$MODEL"} --gate trigger --output "$vote_file" >/dev/null 2>&1 || rc=$?
  case "$rc" in
    1)   return 1 ;;   # disproof-backed Reject
    0|2) return 0 ;;   # Promote / Uncertain → keep
    *)   return 2 ;;   # ParseFailure (3) / usage (4) → no verdict, retry next pass
  esac
}

# Demote-only trigger-provenance gate for an already-accepted finding. Rejects
# (moves to findings-rejected/) ONLY on a disproof-backed Reject; Promote,
# Uncertain and parse-failure all KEEP. It can never promote. Returns 0 if it
# demoted the finding (caller stops), else 1 (keep).
_triage_trigger_provenance_gate() {
  local d="$1" id="$2" desc="$3" bin_dir="$4"
  local rc=0
  _run_trigger_provenance_vote "$desc" "$d/.trigger-gate.json" "$bin_dir" || rc=$?
  if [ "$rc" = 1 ]; then
    local msg="trigger-provenance: triggering state not attacker-reachable"
    _triage_quarantine_find_dir "$d" "$id" "$bin_dir" "$msg" "$msg" && return 0
  fi
  return 1
}

# Crash-side trigger-provenance gate — the same recall-safe reviewer, run on a
# KEPT crash report. It closes a scoring blind spot: evaluate_crash_verdict
# promotes any crash whose trigger ⊆ attacker_controls, so a crash whose trigger
# is labelled `bytes` stays at full severity even when those bytes are internal
# state the program produces itself (a serialized blob, a caller-owned
# descriptor) that only a trusted in-process caller could forge — never an
# external attacker. That set-difference cannot see provenance; this independent
# source-reading reviewer can, and applies the SAME reachability test to every
# trigger kind, so a `bytes`-labelled forgery is scrutinised exactly like a
# `call-sequence` one (no taxonomy asymmetry).
#
# A sanitizer-confirmed crash is higher-consequence than an unproven finding, so
# — unlike the findings gate — one validator is NOT enough to hard-remove it:
# this requires TWO independent disproof-backed Rejects before routing the crash
# to crashes-rejected/ (indexed, recoverable). A single or disagreeing Reject
# keeps the crash (recall-safe); the second vote retries until it reaches a
# conclusive verdict, so a transient backend failure can never finalise a
# one-vote rejection. The quorum guards against a single hallucinated/
# overconfident validator dropping a real bug. Opt out with CRASH_TRIGGER_GATE=0.
# Returns 0 if it rejected the crash (caller stops), else 1 (keep).
_triage_crash_trigger_provenance_gate() {
  local d="$1" id="$2" report="$3" bin_dir="$4"
  [ "${CRASH_TRIGGER_GATE:-1}" = "0" ] && return 1
  local rc1=0
  _run_trigger_provenance_vote "$report" "$d/.trigger-gate.json" "$bin_dir" || rc1=$?
  [ "$rc1" = 1 ] || return 1
  local rc2=0
  _run_trigger_provenance_vote "$report" "$d/.trigger-gate-2.json" "$bin_dir" || rc2=$?
  [ "$rc2" = 1 ] || return 1
  _triage_route_rejection "$d" "$id" \
    "trigger-provenance (2 independent rejects): triggering state not attacker-reachable from a public boundary"
}

_validate_one_find_dir() {
  local d="$1" bin_dir="$2"
  [ -d "$d" ] || return 0
  local id
  id=$(basename "$d")

    [ -f "$d/.reviewed" ] || [ -f "$d/.keep" ] && return 0

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
      return 0
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
    # Tunables: FIND_GATE_QUORUM (reject quorum, default 2),
    # FIND_GATE_ACCEPT_QUORUM (accept quorum, default 2; set to 1 to restore
    # the old single-accept-veto behavior), FIND_GATE_QUARANTINE_DIR
    # (default $RESULTS_DIR/findings-rejected).
    local cache="$d/.llm-find-quality.json"
    local cache_fields=""
    if cache_fields=$(_triage_find_quality_cache_fields "$cache" 2>/dev/null); then
      local _cached_version accept reason _cached_cache_reject_count _cached_content_sha reject_count quorum reject_marker
      eval "set -- $cache_fields"
      _cached_version="${1:-}"
      accept="${2:-}"
      reason="${3:-}"
      _cached_cache_reject_count="${4:-0}"
      _cached_content_sha="${5:-}"
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
          _triage_quarantine_find_dir "$d" "$id" "$bin_dir" \
            "non-security (${reject_count}/${quorum} reject): ${reason}" "$reason" || true
          return 0
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
          return 0
        fi
      else
        # Verdict flipped to accept (or first verdict was accept) —
        # clear any stale pending-drop marker so the FIND is normal.
        rm -f "$d/.pending-drop" 2>/dev/null || true
      fi
    fi

    # Demote-only trigger-provenance gate: the finding has passed the accept
    # gate above; this can only move it to findings-rejected/, never promote.
    _triage_trigger_provenance_gate "$d" "$id" "$desc" "$bin_dir" && return 0

    # Severity annotation (same helper crashes use). Best-effort.
    # The LLM hybrid pass fills missing structured fields beforehand so
    # the deterministic scorer can class non-memory findings (open
    # redirect, SSRF, …) instead of falling through to "unclassified".
    # Reconcile the caller-only contract flag from those final fields BEFORE
    # scoring — the same deterministic step a live crash gets in triage_crash_dirs
    # — so a caller-only finding and its crash twin localise and floor identically.
    _triage_llm_fill_fields "$d" "$id"
    _triage_reconcile_contract_flag_finding "$d" "$id"
    _triage_run_severity "$d" "$id" "$bin_dir"
  return 0
}

# Worker for the find-gate pool: $1=finding dir. Reads bin_dir from
# validate_find_gate via dynamic scope.
_validate_find_pool_worker() {
  _validate_one_find_dir "$1" "$bin_dir" || true
}

# Opt-in pause-and-resume for the find-gate drain across a provider usage limit.
# OFF by default: bin/audit runs validate_find_gate as a backgrounded
# housekeeping sweeper, and wait_for_background_housekeeping would block the next
# iteration on a multi-hour pause. Only the benchmark's post-run drain
# (drain_cell_find_gate) sets FIND_GATE_RESUME_ON_LIMIT=1, where the run has
# ended and blocking to wait out the reset — instead of leaving findings
# permanently un-adjudicated — is exactly the goal. Env-overridable for tests.
FIND_GATE_PAUSE_MAX_TOTAL="${FIND_GATE_PAUSE_MAX_TOTAL:-21600}"  # 6h cumulative cap
FIND_GATE_PAUSE_CHUNK="${FIND_GATE_PAUSE_CHUNK:-1800}"           # 30m when reset unknown
FIND_GATE_MAX_PAUSES="${FIND_GATE_MAX_PAUSES:-12}"               # hard loop bound

# Read the provider-limit reset the decide path recorded during a drain pass.
# The decide workers append one line per capacity-limited call: a reset epoch,
# or "unknown" when the backend reported no reset. pool_run barriers on all
# workers, so this reads a quiescent file. Emits the largest epoch, else
# "unknown" if a cap was seen without a parseable reset, else "" (no cap).
_find_gate_limit_reset() {
  local file="$1"
  [ -s "$file" ] || return 0
  awk '
    /^[0-9]+$/ { if ($1 + 0 > max) max = $1; seen = 1; next }
    NF         { unknown = 1 }
    END        { if (seen) print max; else if (unknown) print "unknown" }
  ' "$file" 2>/dev/null || true
}

validate_find_gate() {
  local bin_dir
  bin_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/../bin" 2>/dev/null && pwd)

  # No location-based pre-filing dedup: a recon finding and an agent's
  # re-discovery of the same bug are collapsed at cluster time like any other
  # duplicate (bin/cluster-findings → lib/finding_dedup.py), so identity is
  # computed in ONE place from each report, the same for every finding source.
  local -a find_dirs=()
  local d
  for d in "$RESULTS_DIR"/findings/FIND-*/; do
    [ -d "$d" ] || continue
    find_dirs+=("$d")
  done

  # Each FIND gate is 1-2 serial LLM calls plus an optional external
  # severity scoring, so
  # per-dir latency varies a lot. Run dirs through a bounded FIFO-windowed
  # pool: when full, wait on the OLDEST job (a specific pid — portable to
  # bash 3.2, which lacks `wait -n`) and launch the next immediately,
  # instead of an all-jobs batch barrier that would idle the whole batch on
  # its slowest member. Dirs are independent (each writes only its own
  # sidecars), so this changes scheduling only, never a verdict. Clustering
  # below stays AFTER the final wait — it reads every surviving report.
  local pool
  pool=$(_triage_dir_pool_size)
  if [ "${FIND_GATE_RESUME_ON_LIMIT:-0}" != "1" ]; then
    # Default path (bin/audit background sweeper): a single pass, never blocks.
    pool_run "$pool" _validate_find_pool_worker ${find_dirs[@]+"${find_dirs[@]}"}
  else
    # Benchmark post-run drain: re-run until no pass reports a provider usage
    # limit, pausing for the reset in between. The per-FIND cache means each
    # retry re-judges only the FINDs still lacking a verdict, so already-decided
    # findings cost no LLM calls. Bounded by FIND_GATE_MAX_PAUSES and the 6h
    # cumulative budget: if the backend never recovers the loop still exits and
    # the residual surfaces as an un-adjudicated remainder (WARN + metrics).
    local _limit_file _reset _now _wait _paused=0 _attempt=0 _remaining
    _limit_file="$RESULTS_DIR/.find-gate-limit"
    export LLM_DECIDE_LIMIT_FILE="$_limit_file"
    while : ; do
      : > "$_limit_file" 2>/dev/null || true
      pool_run "$pool" _validate_find_pool_worker ${find_dirs[@]+"${find_dirs[@]}"}
      _reset=$(_find_gate_limit_reset "$_limit_file")
      [ -z "$_reset" ] && break                       # no cap this pass → done
      _attempt=$((_attempt + 1))
      [ "$_attempt" -gt "$FIND_GATE_MAX_PAUSES" ] && break
      _remaining=$(( FIND_GATE_PAUSE_MAX_TOTAL - _paused ))
      [ "$_remaining" -le 0 ] && break
      _now=$(date +%s)
      if [ "$_reset" = "unknown" ] || ! [[ "$_reset" =~ ^[0-9]+$ ]] || [ "$_reset" -le "$_now" ]; then
        _wait="$FIND_GATE_PAUSE_CHUNK"
      else
        _wait=$(( _reset - _now + 30 ))
      fi
      [ "$_wait" -gt "$_remaining" ] && _wait="$_remaining"
      [ "$_wait" -lt 1 ] && _wait=1
      printf 'SESSION_PAUSE: find-gate drain hit a provider usage limit — pausing %ss before re-judging un-adjudicated findings (paused so far: %ss).\n' \
        "$_wait" "$_paused" >&2
      sleep "$_wait"
      _paused=$(( _paused + _wait ))
    done
    unset LLM_DECIDE_LIMIT_FILE
    rm -f "$_limit_file" 2>/dev/null || true
  fi

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

# Pure decision step: prints the cluster-expansion JSON for one crash
# dir on stdout (no state writes), so the driver below can run several
# decisions concurrently and keep the state-file appends serial.
_cluster_expand_decide() {
  local d="$1"
  local id frames source_block prompt
  id=$(basename "$d")
  frames=$(_cluster_top_frames "$d" 2>/dev/null) || return 1
  [ -n "$frames" ] || return 1
  source_block=$(_cluster_nearby_source "$d" 2>/dev/null || true)
  prompt=$(render_prompt_template triage_cluster_expand.md.j2 \
    --var "id=${id}" \
    --var "frames=${frames}" \
    --var "source_block=${source_block}") || return 1
  # cluster_expand investigates the crash tree to name siblings, so it gets the
  # widest headroom (see _triage_decision_timeout).
  printf '%s' "$prompt" | llm_decide cluster_expand "rows" "$(_triage_decision_timeout cluster_expand)"
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

  # Consume a decision pre-computed by the parallel driver when present;
  # an empty pre-computed file means the LLM was unavailable for that
  # crash — leave the dir unexpanded so the next pass retries, exactly
  # like a live llm_decide failure.
  local json="" precomputed="$d/.cluster_rows.json.tmp"
  if [ -f "$precomputed" ]; then
    json=$(cat "$precomputed" 2>/dev/null)
    rm -f "$precomputed" 2>/dev/null || true
    [ -n "$json" ] || return 0
  else
    json=$(_cluster_expand_decide "$d") || return 0
    [ -n "$json" ] || return 0
  fi

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
# expanded. Best-effort. The per-crash LLM decisions (the slow part,
# 5-20s each) are pre-computed concurrently through the shared triage
# pool; the state-file appends stay serial in expand_cluster_for_crash
# so table blocks never interleave in the shared markdown.
# Worker for the cluster-expand precompute pool: $1=crash dir. Writes its own
# per-dir temp file that the serial apply step below consumes.
_cluster_expand_pool_worker() {
  _cluster_expand_decide "$1" > "$1/.cluster_rows.json.tmp" 2>/dev/null || true
}

expand_clusters_for_new_crashes() {
  declare -f llm_decide >/dev/null 2>&1 || return 0
  [ -d "${RESULTS_DIR:-/nonexistent}/crashes" ] || return 0
  local -a dirs=()
  local d
  for d in "$RESULTS_DIR"/crashes/CRASH-*/; do
    [ -d "$d" ] || continue
    [ -f "$d/.cluster_expanded" ] && continue
    [ -f "$d/.autodiscard" ] && continue
    dirs+=("$d")
  done
  [ "${#dirs[@]}" -gt 0 ] || return 0

  # Precompute each cluster decision (5-20s LLM call) into its own per-dir temp
  # file through the shared pool, then apply serially below. Only fan out when
  # there's more than one dir; when serial, skip the temp files entirely and let
  # the apply step compute each inline (byte-identical, just unscheduled).
  local pool
  pool=$(_triage_dir_pool_size)
  if [ "$pool" -gt 1 ] && [ "${#dirs[@]}" -gt 1 ]; then
    pool_run "$pool" _cluster_expand_pool_worker "${dirs[@]}"
  fi

  for d in "${dirs[@]}"; do
    expand_cluster_for_crash "$d" 2>/dev/null || true
    rm -f "$d/.cluster_rows.json.tmp" 2>/dev/null || true
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
    json=$(printf '%s' "$prompt" | llm_decide patch_review "fixed" "$LLM_DECISION_TIMEOUT") || continue
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

# Coverage belt for the find-quality decision. validate_find_gate runs the
# gate on every FIND-* in its own pass, but maintain_indexes ALSO clusters,
# and a finding materialized after the last gate pass (e.g. recon-materialized
# FIND-RECON-*) can reach clustering with no .llm-find-quality.json — and
# therefore no accept/class/severity verdict. The gate decides quality only;
# identity is the deterministic (class, file, line) site computed at cluster
# time. This belt guarantees the quality verdict (notably the class, which is
# part of that merge key) exists for every finding before clustering. Fill
# exactly that gap: only
# findings MISSING a cache are processed. Fresh verdicts short-circuit inside
# llm_find_quality_decision, and stale-version re-evaluation stays the gate's
# job, so this adds no LLM calls for already-decided findings. Best-effort
# under set -euo pipefail.
# Worker for the find-quality pool: $1 = "dir<TAB>description-file" (the pack
# the collection loop builds, since each item carries two fields).
_find_quality_pool_worker() {
  local _d="${1%%$'\t'*}" _desc="${1#*$'\t'}"
  llm_find_quality_decision "$_desc" "$_d" >/dev/null 2>&1 || true
}

_ensure_find_quality_coverage() {
  [ -d "$RESULTS_DIR/findings" ] || return 0
  declare -f llm_find_quality_decision >/dev/null 2>&1 || return 0
  # Collect the dirs that still need a verdict, then run them through the same
  # bounded pool validate_find_gate uses. Each call writes only inside its own
  # dir (.llm-find-quality.json / .find_reject_count), so concurrency changes
  # scheduling only — never the per-finding verdict. Clustering downstream
  # already waits on this function to return.
  local -a pending=()
  local d desc c
  for d in "$RESULTS_DIR"/findings/FIND-*/; do
    [ -d "$d" ] || continue
    [ -f "$d/.llm-find-quality.json" ] && continue
    { [ -f "$d/.reviewed" ] || [ -f "$d/.keep" ]; } && continue
    desc=""
    for c in "$d/report.md" "$d/description.md" "$d/analysis.md" "$d/README.md"; do
      [ -s "$c" ] && { desc="$c"; break; }
    done
    [ -n "$desc" ] || continue
    pending+=("$d"$'\t'"$desc")
  done
  [ "${#pending[@]}" -gt 0 ] || return 0

  local pool
  pool=$(_triage_dir_pool_size)
  pool_run "$pool" _find_quality_pool_worker ${pending[@]+"${pending[@]}"}
}

# ─── Rejection-index cell helpers ─────────────────────────────────
# These render the shared ID | Site | Reason | Report rejection ledger
# (REJECTED-CRASHES.md / REJECTED-FINDINGS.md, plus INDEX.md compatibility
# aliases). lib/benchmark.py carries python equivalents for the benchmark pool;
# keep the two in sync.

# Flatten one cell to a single markdown-table-safe line: collapse
# whitespace and escape pipes. Reasons are kept in full — rejected pages
# are audit evidence — so no length cap is applied here.
_rejected_md_cell() {
  printf '%s' "$1" | tr '\n\t' '  ' | sed -e 's/|/\\|/g' -e 's/  */ /g' -e 's/^ //' -e 's/ $//'
}

# "[Link](<id>/<report>)" for a rejected dir, or an em dash when no report
# file exists. The target is relative to the index (same parent dir);
# render-md rewrites the .md target to its rendered .html sibling.
_rejected_report_link() {
  local d="$1" id rep
  id=$(basename "$d")
  rep=$(_triage_exact_file_path "$d" "REPORT.md" 2>/dev/null || true)
  [ -z "$rep" ] && rep=$(_triage_exact_file_path "$d" "report.md" 2>/dev/null || true)
  if [ -n "$rep" ]; then
    printf '[Link](%s/%s)' "$id" "$(basename "$rep")"
  else
    printf '%s' "—"
  fi
}

# First interesting crash frame ("func file:line") for a rejected crash dir.
# Prefers the shared stack-frame helper; falls back to an awk scan that
# skips sanitizer/libc/runtime frames (the helper returns nothing for UBSan
# traces, which have no recognised crash-stack header).
_rejected_crash_site() {
  local d="$1" asan_path frame="" _fbin _fhelper
  asan_path=$(find_primary_asan_in_crash_dir "$d" 2>/dev/null || true)
  [ -n "$asan_path" ] || { printf '%s' "—"; return; }
  _fbin=$(cd "$(dirname "${BASH_SOURCE[0]}")/../bin" 2>/dev/null && pwd)
  _fhelper="$_fbin/../lib/stack_frames.py"
  if [ -s "$_fhelper" ] && command -v python3 >/dev/null 2>&1; then
    frame=$(python3 "$_fhelper" --first-display "$asan_path" 2>/dev/null | head -c 70 || true)
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
  printf '%s' "${frame:-—}"
}

# Rejection rationale recorded by triage in a crash dir's .autodiscard.
_rejected_dir_reason() {
  local d="$1" reason=""
  if [ -f "$d/.autodiscard" ]; then
    reason=$(grep -m1 '^# Reason:' "$d/.autodiscard" 2>/dev/null | sed -E 's/^# Reason:[[:space:]]*//')
  fi
  printf '%s' "${reason:-—}"
}

# file:func:line for a rejected finding, read from the report's Fields table.
_rejected_finding_site() {
  local d="$1" rep file func line site=""
  rep=$(_triage_exact_file_path "$d" "report.md" 2>/dev/null || true)
  [ -z "$rep" ] && rep=$(_triage_exact_file_path "$d" "REPORT.md" 2>/dev/null || true)
  [ -n "$rep" ] || { printf '%s' "—"; return; }
  file=$(awk -F'|' 'tolower($2) ~ /^ *file *$/ {gsub(/[`[:space:]]/,"",$3); print $3; exit}' "$rep" 2>/dev/null)
  func=$(awk -F'|' 'tolower($2) ~ /^ *function *$/ {gsub(/[`[:space:]]/,"",$3); print $3; exit}' "$rep" 2>/dev/null)
  line=$(awk -F'|' 'tolower($2) ~ /^ *line *$/ {gsub(/[`[:space:]]/,"",$3); print $3; exit}' "$rep" 2>/dev/null)
  site="$file"
  [ -n "$func" ] && site="${site:+$site:}$func"
  [ -n "$line" ] && site="${site:+$site:}$line"
  printf '%s' "${site:-—}"
}

# Rejection rationale for a finding: the FIND-quality gate's reason, falling
# back to the recon triage reason.
_rejected_finding_reason() {
  local d="$1" reason="" f
  if command -v jq >/dev/null 2>&1; then
    for f in "$d/.llm-find-quality.json" "$d/.llm-triage.json"; do
      [ -s "$f" ] || continue
      reason=$(jq -r '.reason // empty' "$f" 2>/dev/null || true)
      [ -n "$reason" ] && break
    done
  fi
  printf '%s' "${reason:-—}"
}

# Stable change-key for cluster-crashes: the active + rejected crash set
# (basenames) plus, per crash, every input cluster-crashes::_signature() reads
# — NOT just the sanitizer file. The crash cluster identity comes from asan
# frames, but the table ALSO carries severity, strategy and promotion
# status, all of which are pulled from the maintainer report,
# severity.json and .promotion_pending. An earlier version keyed on asan
# files alone, so an in-place severity edit (Low -> High) left CRASH-CLUSTERS.md
# stale at the old rank. We content-hash the report (severity/strategy are
# rewritten in place, possibly at the same mtime/size, so a stat key can miss
# them) and the small sidecars; asan files are immutable once written but cost
# the same to hash. The tool identity and cluster tuning knobs are folded in so
# a harness upgrade or a changed threshold re-clusters too. Empty (and constant)
# when there are no crashes — the common findings-only target still skips the
# whole pass after the first iteration. Crash counts are small, so the per-crash
# hashes are far cheaper than re-running the Python clustering pass every time.
_maintain_crash_cluster_sig() {
  local d f out=""
  out="tool=${_cluster_statkey:-}"$'\n'
  out="${out}env=${CLUSTER_LCS_THRESHOLD:-}|${CLUSTER_FUZZY_MATCH:-}|${CLUSTER_FUZZY_THRESHOLD:-}"$'\n'
  # The "rejected crashes index" footer is unconditional in cluster-crashes, so
  # CRASH-CLUSTERS.md no longer depends on whether the rejected summary exists —
  # no rejected-index term is needed in this skip key.
  for d in "$RESULTS_DIR"/crashes/CRASH-*/ "$RESULTS_DIR"/crashes-rejected/CRASH-*/; do
    [ -d "$d" ] || continue
    d="${d%/}"; out="${out}${d##*/}|"
    for f in "$d"/sanitizer.txt "$d"/asan.txt \
             "$d"/.audit/*.asan.txt "$d"/.audit/*.msan.txt \
             "$d"/.audit/*.tsan.txt "$d"/.audit/*.ubsan.txt \
             "$d"/REPORT.md "$d"/report.md \
             "$d"/severity.json "$d"/.promotion_pending; do
      [ -f "$f" ] && out="${out}${f##*/}:$(_triage_file_sha1 "$f" 2>/dev/null || true),"
    done
    out="${out}"$'\n'
  done
  printf '%s' "$out"
}

# Build rejected summary pages. The named REJECTED-*.md reports are the
# canonical browser targets; INDEX.md is kept as a compatibility alias for
# older prompts/docs and direct links. Both share one schema — ID | Site |
# Reason | Report — so live audit pages and benchmark pool equivalents read
# identically. ID stays plain text (rejected dirs are not meant to be re-opened);
# Report is a Link to the rendered per-dir report (render-md rewrites the .md
# target to its .html sibling).
#
# Both pages are ALWAYS written, even when empty (just the header row). The
# cluster tables link to them unconditionally, so an always-present page means
# the link is never dead — and it removes every moving part the old conditional
# footer created: no build-ordering requirement, no skip-cache, no empty-set
# special case, no staleness window. The page is rebuilt from scratch each pass;
# rejected sets are small and this runs only on a dirty maintain_indexes pass,
# so the cost is bounded and the output is always current.
_maintain_rejected_index_one() {
  local parent="$1" prefix="$2" kind="$3" title="$4"
  local report_name="$5"
  local idx="$parent/$report_name"
  local d id site reason link
  mkdir -p "$parent" 2>/dev/null || true
  {
    echo "# $title"
    echo ""
    echo "| ID | Site | Reason | Report |"
    echo "| :--- | :--- | :--- | :--- |"
    for d in "$parent"/"$prefix"*/; do
      [ -d "$d" ] || continue
      id=$(basename "$d")
      if [ "$kind" = crash ]; then
        site=$(_rejected_md_cell "$(_rejected_crash_site "$d")")
        reason=$(_rejected_md_cell "$(_rejected_dir_reason "$d")")
      else
        site=$(_rejected_md_cell "$(_rejected_finding_site "$d")")
        reason=$(_rejected_md_cell "$(_rejected_finding_reason "$d")")
      fi
      link=$(_rejected_report_link "$d")
      printf '| `%s` | %s | %s | %s |\n' "$id" "${site:-—}" "${reason:-—}" "$link"
    done
  } > "$idx" 2>/dev/null || true
  cp "$idx" "$parent/INDEX.md" 2>/dev/null || true
  # Drop the now-unused skip-cache sidecar from older versions.
  rm -f "$parent/.index-sig" 2>/dev/null || true
}

_maintain_rejected_indexes() {
  _maintain_rejected_index_one "$RESULTS_DIR/crashes-rejected" "CRASH-" crash \
    "Rejected crashes — non-finding classes (DO NOT RE-FILE)" \
    "REJECTED-CRASHES.md"
  _maintain_rejected_index_one "$RESULTS_DIR/findings-rejected" "FIND-" find \
    "Rejected findings — non-actionable (DO NOT RE-FILE)" \
    "REJECTED-FINDINGS.md"
}

maintain_indexes() {
  mkdir -p "$RESULTS_DIR/crashes" "$RESULTS_DIR/crashes-rejected" \
           "$RESULTS_DIR/findings" "$RESULTS_DIR/findings-rejected" 2>/dev/null || true

  # Always (re)write the rejected indexes — they exist on every pass so the
  # cluster tables' unconditional footer links are never dead. Order vs the
  # cluster step below no longer matters (the footer doesn't depend on the
  # file), but building here keeps all index writes together.
  _maintain_rejected_indexes

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
      # Skip when the crash set is unchanged since the last cluster-crashes (and
      # the summary already exists). Empty crashes/ → empty constant sig, so a
      # findings-only target re-creates the same CRASH-CLUSTERS.md no more than
      # once. A crash added or rejected changes a basename → sig busts → recluster.
      local _cc_sig_file="$RESULTS_DIR/crashes/.cluster-crashes-sig" _cc_cur _cluster_statkey _cc_ok
      _cluster_statkey=$(audit_stat_key "$_cluster_bin" 2>/dev/null || true)
      _cc_cur=$(_maintain_crash_cluster_sig 2>/dev/null || true)
      if [ -s "$RESULTS_DIR/crashes/CRASH-CLUSTERS.md" ] && [ -f "$_cc_sig_file" ] \
         && [ "$(cat "$_cc_sig_file" 2>/dev/null)" = "$_cc_cur" ]; then
        : # crash set unchanged — CRASH-CLUSTERS.md already current
      else
        _cc_ok=1
        python3 "$_cluster_bin" "$RESULTS_DIR" >/dev/null 2>&1 \
          || { _cc_ok=0; audit_log "WARN: cluster-crashes refresh failed (CRASH-CLUSTERS.md may be stale)" \
               | tee -a "${INDEX:-/dev/null}" >/dev/null 2>&1 || true; }
        # Cross-backend aggregate at output/<slug>/CRASH-CLUSTERS.md. Concurrent
        # backends serialize internally via fcntl.flock on .cluster-lock; the
        # loser exits 0 immediately so this never stalls our audit loop.
        local _target_root="$(dirname "$RESULTS_DIR")"
        _target_root="$(dirname "$_target_root")"
        if [ -d "$_target_root" ] && [ -f "$_target_root/target.toml" ]; then
          python3 "$_cluster_bin" "$_target_root" >/dev/null 2>&1 \
            || audit_log "WARN: cluster-crashes target-root aggregate failed" \
                 | tee -a "${INDEX:-/dev/null}" >/dev/null 2>&1 || true
        fi
        mkdir -p "$RESULTS_DIR/crashes" 2>/dev/null || true
        # Persist the skip key ONLY when the per-results pass succeeded.
        # Otherwise a transient failure would freeze the now-stale table until
        # some watched input happened to change; leaving the sig unwritten makes
        # the next iteration retry the cluster.
        [ "$_cc_ok" = 1 ] && { printf '%s' "$_cc_cur" > "$_cc_sig_file" 2>/dev/null || true; }
      fi
    fi
    if [ -x "$_finding_cluster_bin" ] && command -v python3 >/dev/null 2>&1; then
      # Ensure every finding carries its semantic signals before clustering.
      _ensure_find_quality_coverage
      TARGET_ROOT="${TARGET_ROOT:-}" python3 "$_finding_cluster_bin" "$RESULTS_DIR" >/dev/null 2>&1 \
        || audit_log "WARN: cluster-findings refresh failed (FINDING-CLUSTERS.md may be stale)" \
             | tee -a "${INDEX:-/dev/null}" >/dev/null 2>&1 || true
      local _target_root="$(dirname "$RESULTS_DIR")"
      _target_root="$(dirname "$_target_root")"
      if [ -d "$_target_root" ] && [ -f "$_target_root/target.toml" ]; then
        TARGET_ROOT="${TARGET_ROOT:-}" python3 "$_finding_cluster_bin" "$_target_root" >/dev/null 2>&1 \
          || audit_log "WARN: cluster-findings target-root aggregate failed" \
               | tee -a "${INDEX:-/dev/null}" >/dev/null 2>&1 || true
      fi
    fi
  fi

  local _frame_bin_dir _frame_helper
  _frame_bin_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/../bin" 2>/dev/null && pwd)
  _frame_helper="$_frame_bin_dir/../lib/stack_frames.py"

  # Enrich + render one report dir, skipping both subprocesses when
  # nothing the render depends on changed since the last pass. Without
  # this, every housekeeping pass paid two python invocations per
  # CRASH/FIND dir (enrich-report re-reads the source tree for snippets)
  # even on fully quiescent result sets. The signature covers every
  # enrichment input, not just the markdown: patch.diff siblings (enrich
  # inlines them — a diff landing AFTER the first render must re-enrich),
  # the render/enrich tool identities, and the ENRICH_REPORT_AUTO toggle.
  # It records the POST-enrich markdown sha: enrich is idempotent, so a
  # dir converges after one pass and re-renders only when severity,
  # clustering, a new patch, or an agent actually changes an input.
  _maintain_render_sig() {
    local _d="$1" _report="$2" _render="$3" _enrich="$4"
    local _sha
    _sha=$(_triage_file_sha1 "$_report" 2>/dev/null || true)
    [ -n "$_sha" ] || return 1
    # patch.diff is small and semantically load-bearing (enrich inlines
    # it), so key it by content sha — a same-second same-size rewrite
    # must still re-enrich. Missing file → empty sha, a stable token for
    # "dependency absent". The tool scripts below stay on audit_stat_key
    # ("0:0" when missing): they only change on a harness upgrade.
    # The render/enrich tool stat-keys are identical for every dir this pass,
    # so reuse the values memoized once below ($_render_statkey/$_enrich_statkey)
    # instead of spawning `stat` per dir — that was ~4 stat processes per sig,
    # twice per dir, all returning the same two values. Fall back to a live
    # compute if the memo is unset (e.g. a direct call outside the loop).
    printf '%s|p=%s|ap=%s|render=%s|enrich=%s|auto=%s' \
      "$_sha" \
      "$(_triage_file_sha1 "$_d/patch.diff" 2>/dev/null || true)" \
      "$(_triage_file_sha1 "$_d/.audit/patch.diff" 2>/dev/null || true)" \
      "${_render_statkey:-$(audit_stat_key "$_render" 2>/dev/null || true)}" \
      "${_enrich_statkey:-$(audit_stat_key "$_enrich" 2>/dev/null || true)}" \
      "${ENRICH_REPORT_AUTO:-1}"
  }

  _maintain_render_report() {
    local _d="$1" _report="$2" _render="$3" _enrich="$4"
    local _sig_file="$_d/.audit/.render-sig" _html="${_report%.md}.html"
    local _cur
    _cur=$(_maintain_render_sig "$_d" "$_report" "$_render" "$_enrich" || true)
    if [ -n "$_cur" ] && [ -s "$_html" ] && [ -s "$_sig_file" ] \
       && [ "$(cat "$_sig_file" 2>/dev/null)" = "$_cur" ]; then
      return 0
    fi
    # Enrich first (patch.diff inline, snippets, TL;DR) so render-md
    # picks up the augmented markdown for HTML. Best-effort; missing
    # source tree just no-ops the snippet blocks.
    if [ "${ENRICH_REPORT_AUTO:-1}" = "1" ] && [ -x "$_enrich" ]; then
      python3 "$_enrich" --quiet "$_report" >/dev/null 2>&1 || true
    fi
    python3 "$_render" "$_report" --html-sibling --title "$(basename "$_d")" >/dev/null 2>&1 || true
    mkdir -p "$_d/.audit" 2>/dev/null || true
    _cur=$(_maintain_render_sig "$_d" "$_report" "$_render" "$_enrich" || true)
    [ -n "$_cur" ] && { printf '%s' "$_cur" > "$_sig_file" 2>/dev/null || true; }
  }

  # Worker for the report-render pool: $1 = "dir<TAB>report" (each item carries
  # both fields). Reads _render/_enrich from maintain_indexes via dynamic scope.
  _maintain_render_pool_worker() {
    local _d="${1%%$'\t'*}" _rep="${1#*$'\t'}"
    _maintain_render_report "$_d" "$_rep" "$_render" "$_enrich" || true
  }

  # CRASH/FINDING cluster files are now the primary review tables. Remove
  # stale legacy per-directory indexes so reviewers do not see two competing
  # summaries for the same artifacts.
  rm -f "$RESULTS_DIR/crashes/INDEX.md" "$RESULTS_DIR/crashes/INDEX.html" \
        "$RESULTS_DIR/findings/INDEX.md" "$RESULTS_DIR/findings/INDEX.html" \
        "$RESULTS_DIR/CLUSTERS.md" "$RESULTS_DIR/CLUSTERS.html" \
        "$RESULTS_DIR/CRASH-CLUSTERS.md" "$RESULTS_DIR/CRASH-CLUSTERS.html" \
        "$RESULTS_DIR/findings/FIND-CLUSTERS.md" \
        "$RESULTS_DIR/findings/FIND-CLUSTERS.html" 2>/dev/null || true

  # Emit HTML siblings after all report/cluster mutations for this iteration.
  # Report HTML is intentionally owned here, not by export-repro,
  # bin/severity, or bin/cluster-crashes: those are intermediate mutators
  # of REPORT.md/report.md, while maintain_indexes runs after severity and
  # after cluster-crashes has refreshed Cluster lines. This keeps REPORT.html
  # a single final render of the current markdown instead of a stale snapshot.
  # Best-effort: failures don't block the audit. Set INDEX_HTML_AUTO=0 to
  # disable generated HTML.
  if [ "${INDEX_HTML_AUTO:-1}" = "1" ] && command -v python3 >/dev/null 2>&1; then
    local _bin_dir _render _enrich
    _bin_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/../bin" 2>/dev/null && pwd)
    _render="$_bin_dir/render-md"
    _enrich="$_bin_dir/enrich-report"
    # Memoize the render/enrich tool stat-keys once — they are identical for
    # every dir's signature this pass, so _maintain_render_sig reuses these
    # instead of re-spawning `stat` per dir (dynamic scope makes them visible
    # to the nested function, including inside the forked render workers).
    local _render_statkey _enrich_statkey
    _render_statkey=$(audit_stat_key "$_render" 2>/dev/null || true)
    _enrich_statkey=$(audit_stat_key "$_enrich" 2>/dev/null || true)
    if [ -x "$_render" ]; then
      local _d _report _candidate
      # Render each stale dir in a bounded FIFO-windowed fork pool. Batching
      # enrich+render into 2 processes is far faster COLD (one --regenerate-style
      # pass of 100 dirs: 0.48s batched vs 7s parallel), but it serializes the
      # per-dir staleness sha1 and so REGRESSES the common quiescent/incremental
      # pass (most dirs unchanged); the parallel pool keeps that sha1 parallel.
      # maintain_indexes runs dirty-gated and mostly quiescent, so the pool wins
      # net. (The cold cluster path — the genuinely hot one — is batched in
      # lib/cluster_common.py instead.)
      # Collect (dir, report) pairs from crashes and findings into one packed
      # list, then render them all through a single shared FIFO window. Both
      # report-resolution rules differ per source, so they stay in the
      # collection loops; the pool just dispatches the resolved work.
      local _rpool
      local -a _render_items=()
      _rpool=$(_triage_dir_pool_size)
      for _d in "$RESULTS_DIR"/crashes/CRASH-*/ "$RESULTS_DIR"/crashes-rejected/CRASH-*/; do
        [ -d "$_d" ] || continue
        _report=""
        _report=$(_triage_exact_file_path "$_d" "REPORT.md" 2>/dev/null || true)
        [ -z "$_report" ] && _report=$(_triage_exact_file_path "$_d" "report.md" 2>/dev/null || true)
        [ -n "$_report" ] || continue
        _render_items+=("$_d"$'\t'"$_report")
      done

      # Findings (kept and rejected) get the same report.md → report.html
      # sibling treatment so reviewers have a browsable HTML view alongside
      # the markdown — and so the rejection index's Report links resolve.
      for _d in "$RESULTS_DIR"/findings/FIND-*/ "$RESULTS_DIR"/findings-rejected/FIND-*/; do
        [ -d "$_d" ] || continue
        _report=""
        for _candidate in REPORT.md report.md description.md analysis.md README.md; do
          if [ -s "$_d/$_candidate" ]; then
            _report="$_d/$_candidate"; break
          fi
        done
        [ -n "$_report" ] || continue
        _render_items+=("$_d"$'\t'"$_report")
      done
      pool_run "$_rpool" _maintain_render_pool_worker ${_render_items[@]+"${_render_items[@]}"}

      # Render the cluster/index summary tables in ONE render-md process
      # (it accepts multiple inputs) instead of one python start per file.
      # These use --html-sibling with default per-file stem titles, so no
      # per-file flags are needed.
      local _f
      local -a _summary_md=()
      for _f in \
        "$RESULTS_DIR/crashes/CRASH-CLUSTERS.md" \
        "$RESULTS_DIR/crashes-rejected/REJECTED-CRASHES.md" \
        "$RESULTS_DIR/crashes-rejected/INDEX.md" \
        "$RESULTS_DIR/findings/FINDING-CLUSTERS.md" \
        "$RESULTS_DIR/findings-rejected/REJECTED-FINDINGS.md" \
        "$RESULTS_DIR/findings-rejected/INDEX.md"; do
        [ -s "$_f" ] && _summary_md+=("$_f")
      done
      [ "${#_summary_md[@]}" -gt 0 ] \
        && python3 "$_render" "${_summary_md[@]}" --html-sibling >/dev/null 2>&1 || true
    fi
  fi
  return 0
}
