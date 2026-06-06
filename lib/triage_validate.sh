#!/usr/bin/env bash
# lib/triage_validate.sh — Independent-validator promotion gate for non-ASan
# findings.
#
# Sourced by bin/audit and bin/audit-recon. Provides:
#
#   triage_validate_finding <finding-path> <target-path> [<results-dir>]
#       Runs bin/validate-finding twice (and a tiebreak if needed). Writes
#       all votes next to the finding. Returns 0 if the quorum is Promote,
#       1 if Reject, 2 if Uncertain.
#
# Design:
#   - ASan-validated CRASH-* artifacts keep the existing crash promotion path —
#     the sanitizer is the objective oracle there.
#   - FIND reports, including source-only memory-safety claims, need an
#     independent vote because the originating agent's confidence and chosen
#     class label are not oracles.
#   - Two Promote votes required to promote. One Reject is fatal. One
#     Uncertain triggers a tiebreak validator that defaults skeptical.
#
# This helper does NOT decide where promoted findings end up — bin/audit
# and the triage caller route them to crashes/, findings/CONFIRMED-*, or
# findings-rejected/ based on the return code.

# Set this to 1 to short-circuit the validator (useful for unit tests).
: "${TRIAGE_VALIDATE_NOOP:=0}"

# Run validators and write vote files. Echo a single line:
#   "verdict=<Promote|Reject|Uncertain> votes=<promote-count>/<total> path=<vote-dir>"
# Return code matches verdict (0=Promote, 1=Reject, 2=Uncertain).
triage_validate_finding() {
  local finding="$1"
  local target_path="$2"
  local results_dir="${3:-}"
  local validator_bin="${SCRIPT_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}/bin/validate-finding"

  if [ "$TRIAGE_VALIDATE_NOOP" = "1" ]; then
    echo "verdict=Promote votes=2/2 path=- (noop)"
    return 0
  fi

  if [ ! -x "$validator_bin" ]; then
    echo "verdict=Uncertain votes=0/0 path=- (validator missing: $validator_bin)"
    return 2
  fi

  local finding_dir
  finding_dir=$(dirname "$finding")

  # Backend the audit was launched with. Fixes a class of bugs where the
  # validator silently ran a different backend than the audit (e.g. audit
  # codex + validator defaulting to claude → 100% ParseFailure because
  # claude wasn't authenticated in the container).
  local backend="${TRIAGE_VALIDATE_BACKEND:-${ACTIVE_BACKEND:-${BACKEND:-claude}}}"
  local -a backend_args=(--backend "$backend")

  # One in-place retry on rc=3 (ParseFailure): the validator returns 3
  # when the LLM produced no parseable vote JSON. In practice that's
  # often a transient format hiccup (a stray fence, a runaway prose
  # turn), so a single immediate re-attempt recovers most of them
  # without ballooning the per-finding cost. Encapsulated so both
  # validator calls (and the tiebreak) get the same behaviour.
  _triage_run_validator() {
    local out_path="$1"; shift
    local -a extra_args=("$@")
    local rc
    # bash 3.2 (macOS) under `set -u` treats "${empty_array[@]}" as an
    # unbound-variable error and aborts the function — which silently
    # collapsed the whole validator stage (v1/v2 are called with no
    # extra args). The "${arr[@]+"${arr[@]}"}" form expands to nothing
    # when the array is empty without tripping nounset.
    "$validator_bin" \
      "${backend_args[@]}" \
      --finding "$finding" \
      --target-path "$target_path" \
      --output "$out_path" \
      ${extra_args[@]+"${extra_args[@]}"} \
      >/dev/null 2>&1
    rc=$?
    if [ "$rc" -eq 3 ]; then
      # A timed-out validator is not a formatting hiccup. Retrying it
      # usually repeats the same long-running tool call and doubles recon
      # latency without adding signal.
      if jq -e '(.timed_out == true) or (.backend_rc == 124)' "$out_path" >/dev/null 2>&1; then
        return "$rc"
      fi
      "$validator_bin" \
        "${backend_args[@]}" \
        --finding "$finding" \
        --target-path "$target_path" \
        --output "$out_path" \
        ${extra_args[@]+"${extra_args[@]}"} \
        >/dev/null 2>&1
      rc=$?
    fi
    return "$rc"
  }

  # First validator (default skepticism)
  local v1_out="$finding_dir/validator-vote-1.json"
  _triage_run_validator "$v1_out"
  local v1_rc=$?

  # Single-validator mode (TRIAGE_VALIDATE_VOTES=1): the caller has already
  # filtered candidates through a cheaper batched triage pass and wants
  # exactly one independent deep check per survivor, not a two-vote quorum.
  # Map the lone vote straight through. Used by bin/audit-recon's batched
  # validation gate; the default (2) keeps the quorum path for bin/audit.
  if [ "${TRIAGE_VALIDATE_VOTES:-2}" = "1" ]; then
    case "$v1_rc" in
      0) echo "verdict=Promote votes=1/1 path=$finding_dir"; return 0 ;;
      1) echo "verdict=Reject votes=0/1 path=$finding_dir"; return 1 ;;
      3) echo "verdict=Uncertain votes=0/1 (parse-failure backend=$backend) path=$finding_dir"; return 2 ;;
      *) echo "verdict=Uncertain votes=0/1 path=$finding_dir"; return 2 ;;
    esac
  fi

  # Second validator (default skepticism)
  local v2_out="$finding_dir/validator-vote-2.json"
  _triage_run_validator "$v2_out"
  local v2_rc=$?

  # Tally promotes / rejects / uncertains / parse-failures. rc=3 is
  # validate-finding's ParseFailure signal. Two of those means the
  # validator backend itself is broken (auth, sandbox, model name) —
  # a tiebreak would just burn budget and return rc=3 again, so
  # short-circuit to Uncertain with a clear marker.
  local promotes=0 rejects=0 uncertains=0 parse_failures=0
  for rc in "$v1_rc" "$v2_rc"; do
    case "$rc" in
      0) promotes=$((promotes + 1)) ;;
      1) rejects=$((rejects + 1)) ;;
      2) uncertains=$((uncertains + 1)) ;;
      3) parse_failures=$((parse_failures + 1)) ;;
    esac
  done

  if [ "$parse_failures" -ge 2 ]; then
    echo "verdict=Uncertain votes=0/2 (parse-failure backend=$backend) path=$finding_dir"
    return 2
  fi

  # Quorum: 2 Promotes → Promote. Any Reject → Reject. Mixed Uncertain
  # → run a third (tiebreak) validator with stricter prompt.
  if [ "$promotes" -ge 2 ]; then
    echo "verdict=Promote votes=2/2 path=$finding_dir"
    return 0
  fi
  if [ "$rejects" -ge 1 ]; then
    echo "verdict=Reject votes=$promotes/2 (reject=$rejects) path=$finding_dir"
    return 1
  fi
  # Mixed or all-Uncertain: tiebreak (same ParseFailure-retry treatment)
  local v3_out="$finding_dir/validator-vote-3.json"
  _triage_run_validator "$v3_out" --tiebreak
  local v3_rc=$?
  case "$v3_rc" in
    0)
      promotes=$((promotes + 1))
      if [ "$promotes" -ge 2 ]; then
        echo "verdict=Promote votes=$promotes/3 (tiebreak) path=$finding_dir"
        return 0
      fi
      echo "verdict=Uncertain votes=$promotes/3 (tiebreak agreed but lone Promote) path=$finding_dir"
      return 2
      ;;
    1)
      echo "verdict=Reject votes=$promotes/3 (tiebreak Reject) path=$finding_dir"
      return 1
      ;;
    3)
      echo "verdict=Uncertain votes=$promotes/3 (tiebreak parse-failure backend=$backend) path=$finding_dir"
      return 2
      ;;
    *)
      echo "verdict=Uncertain votes=$promotes/3 (tiebreak Uncertain) path=$finding_dir"
      return 2
      ;;
  esac
}


# triage_validate_confirm_findings <findings-dir> <target-path> [<quarantine-dir>]
#
# Validate every findings/FIND-*/ candidate under <findings-dir> through the
# independent-validator quorum and route each by verdict: a Promote stays in
# place; a Reject / Uncertain (or a candidate with no report file at all)
# moves to <quarantine-dir> (default: <findings-dir>/../findings-rejected).
#
# This is the "proof, not assertion" gate for non-ASan findings — the same
# rule the crash side enforces with a sanitizer oracle. Any caller sitting
# on a tree of raw, unvalidated FIND-* candidates (the benchmark's
# model-direct baseline; an external import) gets harness-grade finding
# confirmation by reusing this rather than reimplementing the move.
#
# Echoes one summary line: "confirmed=<n> rejected=<n> of=<total>".
# Always returns 0 — the per-finding routing on disk is the result.
triage_validate_confirm_findings() {
  local findings_dir="$1"
  local target_path="$2"
  local quarantine="${3:-$(dirname "$findings_dir")/findings-rejected}"
  [ -d "$findings_dir" ] || { echo "confirmed=0 rejected=0 of=0"; return 0; }

  local confirmed=0 rejected=0 total=0
  local d id report c rc target
  for d in "$findings_dir"/FIND-*/; do
    [ -d "$d" ] || continue
    total=$((total + 1))
    id=$(basename "$d")

    # validate-finding judges a narrative; a FIND dir with none is an
    # empty assertion. Reject it without spending a validator call.
    report=""
    for c in "$d/report.md" "$d/description.md" "$d/REPORT.md" "$d/analysis.md"; do
      [ -s "$c" ] && { report="$c"; break; }
    done
    if [ -n "$report" ]; then
      triage_validate_finding "$report" "$target_path" "$d" >/dev/null 2>&1
      rc=$?
    else
      rc=1
    fi

    if [ "$rc" = "0" ]; then
      confirmed=$((confirmed + 1))
    else
      rejected=$((rejected + 1))
      mkdir -p "$quarantine" 2>/dev/null || true
      target="$quarantine/$id"
      [ -e "$target" ] && target="${target}.$(date -u +%Y%m%dT%H%M%SZ)"
      mv "$d" "$target" 2>/dev/null || true
    fi
  done
  echo "confirmed=$confirmed rejected=$rejected of=$total"
  return 0
}
