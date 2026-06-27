#!/usr/bin/env bash
# lib/crash_bundle.sh — materialize a maintainer-facing crash bundle the
# instant bin/probe confirms a sanitizer diagnostic.
#
# Why this exists: bin/probe records verdict=CRASH in structured state and
# advances the queue, but historically created no bundle and reported no
# location. Agents then hand-grepped the crashes/ tree to find where their
# crash went — uncapped `find|xargs rg` sweeps that replay on every later turn
# — and a distinct confirmed reproducer sometimes never got a bundle at all,
# stranding in scratch-N/ and violating the product invariant that every
# accepted crash has a maintainer-facing bundle on disk.
#
# This helper closes both gaps: it copies the reproducer, sanitizer trace, and
# harness into the next CRASH-<n>-<agent> slot, writes a report.md skeleton
# with the required gate fields, and prints the bundle id. It only ever ADDS a
# bundle; it never suppresses or dedups away a distinct reproducer
# (recall-safe). Dedup keys on the full EXECUTION IDENTITY — testcase bytes,
# sanitizer, mode, harness bytes, and trailing args — so a re-probe of the same
# probe (e.g. probe followed by probe --confirm) reuses the bundle, while the
# same testcase under a different sanitizer/mode/harness/args is a distinct
# crash and gets its own bundle (precision- and recall-safe). Slots and the
# dedup index are per-agent (CRASH-*-<agent>, .probe-filed-<agent>.tsv); a
# single agent runs probes sequentially, so no cross-process lock is needed.

# crash_bundle_should_file VERDICT SANITIZER_SELECTED ASAN_RUNS
#
# Policy gate for auto-filing: true only for a sanitizer crash confirmed across
# multiple runs. A single exploratory run (ASAN_RUNS=1, the default) must not
# auto-file an unconfirmed flake, and runner / findings-only mode never produces
# crash bundles (those route to findings/). Confirmation is the agent running
# `bin/probe --confirm`, which sets ASAN_RUNS=5.
crash_bundle_should_file() {
  local verdict="${1:-}" san="${2:-}" runs="${3:-1}"
  [ "$verdict" = "CRASH" ] || return 1
  [ "$san" != "runner" ] || return 1
  case "$runs" in ''|*[!0-9]*) return 1 ;; esac
  [ "$runs" -ge 2 ]
}

# crash_bundle_materialize --results-dir D --agent N --testcase T --sanitizer S
#                          [--san-name asan|ubsan|...] [--mode generic|...]
#                          [--harness H] [--args "trailing args"]
#                          [--target "f:fn:line"] [--hyp ID] [--card ID]
#                          [--strategy SN]
#
# Prints one machine-readable line on success:
#   FILED <crash-id>   a new bundle was created
#   DUP   <crash-id>   same execution identity already filed; bundle reused
# Returns non-zero (printing nothing) on a usage/IO error so the caller can
# fall open without failing the probe.
crash_bundle_materialize() {
  local results_dir="" agent="" testcase="" sanitizer="" san_name="" mode="" \
        harness="" args="" target="" hyp="" card="" strategy=""
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --results-dir) results_dir="${2:-}"; shift 2 ;;
      --agent)       agent="${2:-}";       shift 2 ;;
      --testcase)    testcase="${2:-}";    shift 2 ;;
      --sanitizer)   sanitizer="${2:-}";   shift 2 ;;
      --san-name)    san_name="${2:-}";    shift 2 ;;
      --mode)        mode="${2:-}";        shift 2 ;;
      --harness)     harness="${2:-}";     shift 2 ;;
      --args)        args="${2:-}";        shift 2 ;;
      --target)      target="${2:-}";      shift 2 ;;
      --hyp)         hyp="${2:-}";         shift 2 ;;
      --card)        card="${2:-}";        shift 2 ;;
      --strategy)    strategy="${2:-}";    shift 2 ;;
      *) shift ;;
    esac
  done

  [ -n "$results_dir" ] && [ -n "$agent" ] || return 2
  [ -f "$testcase" ] || return 2
  [ -f "$sanitizer" ] || return 2
  command -v audit_sha1 >/dev/null 2>&1 || return 2

  local crashes_dir="$results_dir/crashes"
  mkdir -p "$crashes_dir" 2>/dev/null || return 2

  local sha1
  sha1="$(audit_sha1 "$testcase" 2>/dev/null | awk '{print $1}')"
  [ -n "$sha1" ] || return 2

  # Execution identity = what makes two probes "the same crash". The same
  # testcase bytes under a different sanitizer, mode, harness, or trailing args
  # is a genuinely distinct diagnostic and must get its own bundle — keying on
  # testcase bytes alone would suppress it as a false duplicate.
  local harness_sha1=""
  if [ -n "$harness" ] && [ -f "$harness" ]; then
    harness_sha1="$(audit_sha1 "$harness" 2>/dev/null | awk '{print $1}')"
  fi
  local args_clean identity
  args_clean="$(printf '%s' "$args" | tr '\t\n' '  ')"   # keep the TSV one-line
  identity="${sha1}:${san_name}:${mode}:${harness_sha1}:${args_clean}"

  # Same-identity dedup: a re-probe of the same probe (probe then --confirm)
  # must reuse the bundle, not spawn a second one.
  local index="$crashes_dir/.probe-filed-${agent}.tsv"
  if [ -f "$index" ]; then
    local prev
    prev="$(awk -F'\t' -v s="$identity" '$1==s {print $2; exit}' "$index" 2>/dev/null)"
    if [ -n "$prev" ] && [ -d "$crashes_dir/$prev" ]; then
      printf 'DUP %s\n' "$prev"
      return 0
    fi
  fi

  # Next per-agent slot = max existing CRASH-<n>-<agent> + 1.
  local max=0 d base num
  for d in "$crashes_dir"/CRASH-*-"$agent"; do
    [ -d "$d" ] || continue
    base="${d##*/}"                        # CRASH-006-2
    num="${base#CRASH-}"; num="${num%-*}"  # 006
    case "$num" in ''|*[!0-9]*) continue ;; esac
    num=$((10#$num))
    [ "$num" -gt "$max" ] && max="$num"
  done
  local id dir tc_name
  id="$(printf 'CRASH-%03d-%s' "$((max + 1))" "$agent")"
  dir="$crashes_dir/$id"
  tc_name="$(basename "$testcase")"
  mkdir -p "$dir" 2>/dev/null || return 2

  # Bundle creation is all-or-nothing: if any copy/write fails, remove the
  # half-built dir so triage never scans a partial CRASH-* bundle.
  # Preserve the testcase basename; the canonical `sanitizer.txt` name is what
  # triage discovers (lib/triage.sh).
  cp "$testcase" "$dir/$tc_name" 2>/dev/null || { rm -rf "$dir"; return 2; }
  cp "$sanitizer" "$dir/sanitizer.txt" 2>/dev/null || { rm -rf "$dir"; return 2; }
  # A supplied harness is REQUIRED to reproduce — a bundle missing it would
  # export as non-runnable. So if one was given, its copy is part of the
  # all-or-nothing guarantee, not best-effort.
  local harness_name=""
  if [ -n "$harness" ] && [ -f "$harness" ]; then
    harness_name="$(basename "$harness")"
    cp "$harness" "$dir/$harness_name" 2>/dev/null || { rm -rf "$dir"; return 2; }
  fi

  # Crash class straight from the sanitizer trace (deterministic, no LLM).
  local san_type
  san_type="$(grep -oE '(AddressSanitizer|UndefinedBehaviorSanitizer|MemorySanitizer|ThreadSanitizer|LeakSanitizer): [a-zA-Z0-9-]+' "$sanitizer" 2>/dev/null | head -1)"
  [ -n "$san_type" ] || san_type="sanitizer diagnostic"

  # report.md skeleton. The bare-label fields must be present (even if blank)
  # so the triage trigger/contract parser finds them; the agent enriches the
  # prose. The `_TODO (agent):` markers in Root Cause / Data Flow are the
  # completeness sentinel: triage's crash gate holds a report that still
  # contains them as promotion-pending (not exported, not dropped), so an
  # un-enriched skeleton can never ship as a maintainer-facing bundle. Writing
  # the real Root Cause / Data Flow naturally removes the markers.
  {
    printf '# %s: %s (auto-filed by bin/probe)\n\n' "$id" "$san_type"
    printf '> AUTO-FILED skeleton. bin/probe confirmed this sanitizer diagnostic for\n'
    printf '> hypothesis `%s`. Triage holds this as promotion-pending until you\n' "${hyp:-?}"
    printf '> REPLACE the TODO Root Cause / Data Flow sections and fill the\n'
    printf '> bare-label fields below. The reproducer and sanitizer trace are already\n'
    printf '> on disk here — do not re-file or leave this stub in scratch.\n\n'
    printf '## Summary\n%s reproduced via hypothesis `%s`%s.\n\n' \
      "$san_type" "${hyp:-?}" "${target:+ at $target}"
    printf '## Reproduction\n'
    printf -- '- Reproducer: `%s`\n' "$tc_name"
    printf -- '- Sanitizer output: `sanitizer.txt`\n'
    if [ -n "$harness_name" ]; then printf -- '- Harness: `%s`\n' "$harness_name"; fi
    printf '\n## Root Cause\n_TODO (agent): describe the defect and why the sanitizer fires._\n\n'
    printf '## Data Flow\n_TODO (agent): step: func (file:line) — desc._\n\n'
    printf 'Boundary:\n'
    printf 'Caller controls:\n'
    printf 'Trusted caller actions:\n'
    printf 'Caller contract:\n'
    printf 'Trigger source:\n'
    printf 'Strategy: %s\n' "${strategy:-}"
    if [ -n "$card" ]; then printf 'CARD-ID: %s\n' "$card"; fi
  } > "$dir/report.md" 2>/dev/null || { rm -rf "$dir"; return 2; }

  # Record the execution identity for dedup on the next (--confirm) probe.
  printf '%s\t%s\n' "$identity" "$id" >> "$index" 2>/dev/null || true

  printf 'FILED %s\n' "$id"
  return 0
}
