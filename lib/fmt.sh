#!/usr/bin/env bash
# lib/fmt.sh — small, dependency-free human-friendly formatters for log lines.
#
# All helpers are pure (no globals, no I/O) and tolerate empty / non-numeric
# inputs by echoing "?" so log lines never break on missing telemetry.

# fmt_count <n>
#   1234        -> 1.2k
#   1500000     -> 1.5M
#   1810622     -> 1.81M
#   1234567890  -> 1.23B
fmt_count() {
  local n="${1:-}"
  case "$n" in
    ''|*[!0-9-]*) printf '?\n'; return ;;
  esac
  if [ "$n" -lt 0 ]; then printf '%s\n' "$n"; return; fi
  if [ "$n" -lt 1000 ]; then
    printf '%d\n' "$n"
  elif [ "$n" -lt 10000 ]; then
    awk -v v="$n" 'BEGIN{printf "%.1fk\n", v/1000}'
  elif [ "$n" -lt 1000000 ]; then
    awk -v v="$n" 'BEGIN{printf "%dk\n", v/1000}'
  elif [ "$n" -lt 10000000 ]; then
    awk -v v="$n" 'BEGIN{printf "%.2fM\n", v/1000000}'
  elif [ "$n" -lt 1000000000 ]; then
    awk -v v="$n" 'BEGIN{printf "%.1fM\n", v/1000000}'
  else
    awk -v v="$n" 'BEGIN{printf "%.2fB\n", v/1000000000}'
  fi
}

# fmt_ms <milliseconds>
#   850          -> 850ms
#   12345        -> 12.3s
#   99231        -> 1m39s
#   405123       -> 6m45s
#   3700000      -> 1h01m
fmt_ms() {
  local ms="${1:-}"
  case "$ms" in
    ''|*[!0-9-]*) printf '?\n'; return ;;
  esac
  if [ "$ms" -lt 1000 ]; then
    printf '%dms\n' "$ms"
  elif [ "$ms" -lt 60000 ]; then
    awk -v v="$ms" 'BEGIN{printf "%.1fs\n", v/1000}'
  elif [ "$ms" -lt 3600000 ]; then
    local s=$((ms / 1000))
    printf '%dm%02ds\n' "$((s / 60))" "$((s % 60))"
  else
    local s=$((ms / 1000))
    printf '%dh%02dm\n' "$((s / 3600))" "$(((s % 3600) / 60))"
  fi
}

# fmt_secs <seconds>
fmt_secs() {
  local s="${1:-}"
  case "$s" in
    ''|*[!0-9-]*) printf '?\n'; return ;;
  esac
  fmt_ms "$((s * 1000))"
}

# strategy_tag <Sn>  — turn a bare strategy code into a self-describing tag
# so a reader who doesn't already know the codebook can guess what the
# agent is doing. Output format: "S1(prior-fix)".
strategy_tag() {
  local s="${1:-}"
  case "$s" in
    S1) printf 'Strategy1(Prior-fix-review)\n' ;;
    S2) printf 'Strategy2(Invariant-negation)\n' ;;
    S3) printf 'Strategy3(Spec-vs-impl)\n' ;;
    S4) printf 'Strategy4(Differential-build)\n' ;;
    S5) printf 'Strategy5(Lifetime-and-state)\n' ;;
    S6) printf 'Strategy6(Cross-project-mining)\n' ;;
    S7) printf 'Strategy7(Adversarial-input)\n' ;;
    S8) printf 'Strategy8(Property-oracle)\n' ;;
    *)  printf '%s\n' "${s:-?}" ;;
  esac
}

# fmt_histogram <histogram-string>  — input "S1:62 S7:31 S6:18", output
# "S1(prior-fix):62 S7(adversarial):31 S6(peer-mining):18" so log readers
# don't have to mentally decode strategy codes inline. Pass-through for
# any token that isn't a strategy code.
fmt_strategy_histogram() {
  local in="${1:-}" out="" tok code count tagged
  # Read tokens from a here-string so we don't depend on shell-specific
  # word-splitting behaviour for unquoted $in (zsh doesn't split by default;
  # bash does — this helper is exercised under both).
  set -- $(printf '%s' "$in")
  for tok in "$@"; do
    code="${tok%%:*}"
    count="${tok#*:}"
    if [ "$code" != "$tok" ]; then
      tagged=$(strategy_tag "$code")
      out="${out}${out:+ }${tagged}:${count}"
    else
      out="${out}${out:+ }${tok}"
    fi
  done
  printf '%s\n' "$out"
}

# fmt_strategy_list <list>  — input "S1 S7 S6", output "S1(prior-fix)
# S7(adversarial) S6(peer-mining)". Used when a space-separated list of
# strategy codes appears in a log line and the reader needs to see what
# each one does.
fmt_strategy_list() {
  local in="${1:-}" out="" tok
  for tok in $in; do
    out="${out}${out:+ }$(strategy_tag "$tok")"
  done
  printf '%s\n' "$out"
}
