#!/usr/bin/env bash
# Tests for the CVSS-aligned hybrid severity formula in bin/reachability.
#
#   I  (Impact)     additive       primitive class + caller-controlled mods
#   R  (Reach)      multiplicative surface × callers × contract × controls
#   CF (Confidence) × multiplier   on whole score; flaky reports get derated
#
#   score = clamp(round((I + R) × CF), 0, 100)
#
# Each axis is exercised independently so a regression pinpoints which
# dimension drifted. The most important property under test: a high-impact
# primitive in a non-shipping (test/maint) tool stays Low — this is the
# calibration that aligns with Microsoft Bug Bar / Project Zero practice.
#
# Strategy: drive bin/reachability through --report mode with a fully-mocked
# reachability backend (REACHABILITY_MOCK_DIR), so the only thing under test
# is the scoring formula.
set -o pipefail
source "$(dirname "$0")/helpers.sh"
setup_test_env

REACH="$SCRIPT_ROOT/bin/reachability"
[ -x "$REACH" ] || { echo "FATAL: $REACH not executable"; exit 1; }

mkdir -p "$TEST_TMPDIR/mock" "$TEST_TMPDIR/cache"
export REACHABILITY_MOCK_DIR="$TEST_TMPDIR/mock"
export REACHABILITY_CACHE_DIR="$TEST_TMPDIR/cache"

sha1_short() {
  printf '%s' "$1" | shasum -a 1 | awk '{print substr($1,1,16)}'
}

seed_hits() {
  local sym="$1" hits="$2"
  local h; h=$(sha1_short "$sym")
  {
    printf '{"status":"ok","hits":['
    local sep="" i
    for ((i=0; i<hits; i++)); do
      printf '%s{"repo":"sg-r%d","path":"sg-p%d"}' "$sep" "$i" "$i"; sep=","
    done
    printf ']}'
  } > "$REACHABILITY_MOCK_DIR/sourcegraph-${h}.json"
  printf '{"status":"unavailable","error":"n/a"}' > "$REACHABILITY_MOCK_DIR/gh-${h}.json"
}

seed_unavailable() {
  local sym="$1"; local h; h=$(sha1_short "$sym")
  for svc in sourcegraph gh; do
    printf '{"status":"unavailable","error":"down"}' > "$REACHABILITY_MOCK_DIR/${svc}-${h}.json"
  done
}

# Build a synthetic crash dir whose REPORT.md carries the structured Fields
# table so the reach axis gets real values. Args:
#   $1 sym (snake_case, must match the seed_hits symbol),
#   $2 id, $3 primitive_prose, $4 surface, $5 contract,
#   $6 controls, $7 reproduction_rate, $8 cluster_cell, $9 extra (optional)
make_crash() {
  local SYM="$1" id="$2" prim="$3" surface="$4" contract="$5" controls="$6"
  local repro="$7" cluster_cell="$8" extra="${9:-}"
  local dir="$TEST_TMPDIR/crashes/$id"
  mkdir -p "$dir"
  {
    echo "# $id"
    echo
    echo "## Fields"
    echo
    echo "| Field             | Value |"
    echo "|:------------------|:------|"
    echo "| Surface           | $surface |"
    echo "| Caller contract   | $contract |"
    echo "| Caller controls   | $controls |"
    echo "| Reproduction rate | $repro |"
    echo "| Cluster           | $cluster_cell |"
    echo
    echo "## Trigger Surface"
    echo "- Entry: \`${SYM}()\`"
    echo "- $prim"
    [ -n "$extra" ] && echo "- $extra"
    echo
    echo "## Classification"
    echo "- **Severity**: TBD"
  } > "$dir/report.md"
  printf '%s\n' "$dir"
}

# Run --report and pluck severity components from JSON output.
get_severity() {
  local dir="$1"
  python3 "$REACH" --report "$dir" --json --no-cache 2>/dev/null \
    | python3 -c '
import json, sys
d = json.load(sys.stdin)["severity"]
print(d["level"], d["score"], d["primitive_key"],
      d["impact"], d["reach"], d["confidence_factor"])
'
}

# ───────────────────────────────────────────────────────────────────
# IMPACT axis (additive)
# ───────────────────────────────────────────────────────────────────

# All impact tests hold R and CF roughly constant: library-api/obeyed/bytes/5/5/singleton.
seed_hits "demo_imp_uafw" 0
dir=$(make_crash "demo_imp_uafw" CRASH-IMP-UAFW \
  "heap-use-after-free WRITE of size 8" "library-api" "obeyed" "bytes" "5/5" "CL-x (singleton)")
_CURRENT_TEST="impact: UAF WRITE base 40"
read level score key i r cf <<< "$(get_severity "$dir")"
assert_eq "uaf_write" "$key" "uaf_write detected"
assert_eq "40" "$i" "I=40 for UAF WRITE"

seed_hits "demo_imp_wildw" 0
dir=$(make_crash "demo_imp_wildw" CRASH-IMP-WILDW \
  "wild-addr-write of size 8" "library-api" "obeyed" "bytes" "5/5" "CL-x (singleton)" \
  "caller-controlled offset")
_CURRENT_TEST="impact: wild-addr WRITE base 37 + offset modifier +3 = 40"
read level score key i r cf <<< "$(get_severity "$dir")"
assert_eq "wild_write" "$key" "wild_write detected"
assert_eq "40" "$i" "I=37+3"

seed_hits "demo_imp_heapw" 0
dir=$(make_crash "demo_imp_heapw" CRASH-IMP-HEAPW \
  "heap-buffer-overflow WRITE of size 8" "library-api" "obeyed" "bytes" "5/5" "CL-x (singleton)")
_CURRENT_TEST="impact: heap WRITE base 32"
read level score key i r cf <<< "$(get_severity "$dir")"
assert_eq "heap_write" "$key" "heap_write detected"
assert_eq "32" "$i" "I=32"

seed_hits "demo_imp_heapr_big" 0
dir=$(make_crash "demo_imp_heapr_big" CRASH-IMP-HEAPR-BIG \
  "heap-buffer-overflow READ of size 4096" "library-api" "obeyed" "bytes" "5/5" "CL-x (singleton)")
_CURRENT_TEST="impact: heap READ ≥16 base 24 (info-disclosure tier)"
read level score key i r cf <<< "$(get_severity "$dir")"
assert_eq "heap_read_big" "$key" "heap_read_big detected"
assert_eq "24" "$i" "I=24"

seed_hits "demo_imp_heapr_small" 0
dir=$(make_crash "demo_imp_heapr_small" CRASH-IMP-HEAPR-SMALL \
  "heap-buffer-overflow READ of size 1" "library-api" "obeyed" "bytes" "5/5" "CL-x (singleton)")
_CURRENT_TEST="impact: 1-byte heap READ base 16"
read level score key i r cf <<< "$(get_severity "$dir")"
assert_eq "heap_read_small" "$key" "heap_read_small detected"
assert_eq "16" "$i" "I=16"

seed_hits "demo_imp_bus" 0
dir=$(make_crash "demo_imp_bus" CRASH-IMP-BUS \
  "BUS error" "cli" "obeyed" "bytes" "5/5" "CL-x (singleton)")
_CURRENT_TEST="impact: BUS base 5 (DoS-only tier)"
read level score key i r cf <<< "$(get_severity "$dir")"
assert_eq "bus" "$key" "bus detected"
assert_eq "5" "$i" "I=5"

# ── ClusterFuzz-aligned sanitizer classes ──────────────────────────

# ASan's hyphenated `stack-overflow` is recursion exhaustion (DoS), not a
# stack-buffer-overflow — must not inherit the stack_write/read tier.
seed_hits "demo_imp_stackexh" 0
dir=$(make_crash "demo_imp_stackexh" CRASH-IMP-STACKEXH \
  "AddressSanitizer: stack-overflow on address 0x7ffd4232fff8" \
  "library-api" "obeyed" "bytes" "5/5" "CL-x (singleton)")
_CURRENT_TEST="impact: ASan stack-overflow → stack_exhaustion base 8"
read level score key i r cf <<< "$(get_severity "$dir")"
assert_eq "stack_exhaustion" "$key" "stack_exhaustion detected"
assert_eq "8" "$i" "I=8 for recursion exhaustion"

# LeakSanitizer memory leaks are resource DoS — must NOT be scored as the
# info_leak (data disclosure) class via the generic 'leaks' fallback.
seed_hits "demo_imp_lsan" 0
dir=$(make_crash "demo_imp_lsan" CRASH-IMP-LSAN \
  "LeakSanitizer: detected memory leaks — Direct leak of 128 byte(s)" \
  "library-api" "obeyed" "bytes" "5/5" "CL-x (singleton)")
_CURRENT_TEST="impact: LeakSanitizer → memory_leak base 5 (not info_leak 24)"
read level score key i r cf <<< "$(get_severity "$dir")"
assert_eq "memory_leak" "$key" "memory_leak detected"
assert_eq "5" "$i" "I=5 for memory leak"

# SEGV discrimination by faulting address (ClusterFuzz practice): near-null
# (< 0x1000) is a null deref; a wild address with a WRITE access is
# wild_write-tier; with a READ access it is the wild_read info/DoS tier.
seed_hits "demo_imp_segv_null" 0
dir=$(make_crash "demo_imp_segv_null" CRASH-IMP-SEGV-NULL \
  "SEGV on unknown address 0x000000000018" \
  "library-api" "obeyed" "bytes" "5/5" "CL-x (singleton)")
_CURRENT_TEST="impact: SEGV at near-null address → null_deref base 8"
read level score key i r cf <<< "$(get_severity "$dir")"
assert_eq "null_deref" "$key" "near-null SEGV is null_deref"
assert_eq "8" "$i" "I=8"

seed_hits "demo_imp_segv_wildr" 0
dir=$(make_crash "demo_imp_segv_wildr" CRASH-IMP-SEGV-WILDR \
  "SEGV on unknown address 0x612000000040 — The signal is caused by a READ memory access" \
  "library-api" "obeyed" "bytes" "5/5" "CL-x (singleton)")
_CURRENT_TEST="impact: SEGV READ at wild address → wild_read base 20"
read level score key i r cf <<< "$(get_severity "$dir")"
assert_eq "wild_read" "$key" "wild_read detected"
assert_eq "20" "$i" "I=20"

seed_hits "demo_imp_segv_wildw" 0
dir=$(make_crash "demo_imp_segv_wildw" CRASH-IMP-SEGV-WILDW \
  "SEGV on unknown address 0x612000000040 — The signal is caused by a WRITE memory access" \
  "library-api" "obeyed" "bytes" "5/5" "CL-x (singleton)")
_CURRENT_TEST="impact: SEGV WRITE at wild address → wild_write base 37"
read level score key i r cf <<< "$(get_severity "$dir")"
assert_eq "wild_write" "$key" "wild_write detected"
assert_eq "37" "$i" "I=37"

seed_hits "demo_imp_race" 0
dir=$(make_crash "demo_imp_race" CRASH-IMP-RACE \
  "WARNING: ThreadSanitizer: data race (pid=123)" \
  "library-api" "obeyed" "bytes" "5/5" "CL-x (singleton)")
_CURRENT_TEST="impact: TSan data race → data_race base 22 (not heap_write 32)"
read level score key i r cf <<< "$(get_severity "$dir")"
assert_eq "data_race" "$key" "data_race detected"
assert_eq "22" "$i" "I=22"

seed_hits "demo_imp_intovf" 0
dir=$(make_crash "demo_imp_intovf" CRASH-IMP-INTOVF \
  "x.c:12:5: runtime error: signed integer overflow: 2147483647 + 1 cannot be represented" \
  "library-api" "obeyed" "bytes" "5/5" "CL-x (singleton)")
_CURRENT_TEST="impact: UBSan signed integer overflow → integer_overflow base 12"
read level score key i r cf <<< "$(get_severity "$dir")"
assert_eq "integer_overflow" "$key" "integer_overflow detected"
assert_eq "12" "$i" "I=12"

seed_hits "demo_imp_invfree" 0
dir=$(make_crash "demo_imp_invfree" CRASH-IMP-INVFREE \
  "attempting free on address which was not malloc()-ed" \
  "library-api" "obeyed" "bytes" "5/5" "CL-x (singleton)")
_CURRENT_TEST="impact: invalid free → double_free family base 38"
read level score key i r cf <<< "$(get_severity "$dir")"
assert_eq "double_free" "$key" "invalid free maps to double_free"
assert_eq "38" "$i" "I=38"

# A crash report quoting raw input bytes containing ../../ must NOT be
# misread as a path-traversal web vuln — the named phrase is required.
seed_hits "demo_imp_dotdot" 0
dir=$(make_crash "demo_imp_dotdot" CRASH-IMP-DOTDOT \
  "SEGV with testcase bytes ../../etc/passwd quoted from the corpus" \
  "library-api" "obeyed" "bytes" "5/5" "CL-x (singleton)")
_CURRENT_TEST="impact: quoted ../../ input does not classify as path_traversal"
read level score key i r cf <<< "$(get_severity "$dir")"
assert_eq "null_deref" "$key" "SEGV wins; ../../ alone is not traversal"

# ── Negation guard ─────────────────────────────────────────────────
# Narrative-driven classes must not fire on sentences that rule the class
# OUT. A negated mention falls through to "unknown" — where the structured
# Primitive field (if any) takes over, so a guard false-positive degrades
# gracefully instead of inventing a finding class.
seed_hits "demo_imp_negated" 0
dir=$(make_crash "demo_imp_negated" CRASH-IMP-NEGATED \
  "Reviewed the session layer; no SQL injection or authentication bypass was observed, and this rules out cache poisoning" \
  "library-api" "obeyed" "bytes" "5/5" "CL-x (singleton)")
_CURRENT_TEST="impact: negated web-vuln mentions do not classify"
read level score key i r cf <<< "$(get_severity "$dir")"
assert_eq "unknown" "$key" "negated mentions fall through to unknown"

# Positive control: the negation lives in a *previous* comma-clause, so the
# class itself is still asserted and must classify.
seed_hits "demo_imp_negpos" 0
dir=$(make_crash "demo_imp_negpos" CRASH-IMP-NEGPOS \
  "input is not sanitized, leading to SQL injection in the id parameter" \
  "library-api" "obeyed" "bytes" "5/5" "CL-x (singleton)")
_CURRENT_TEST="impact: comma-clause negation does not suppress a real finding"
read level score key i r cf <<< "$(get_severity "$dir")"
assert_eq "sqli" "$key" "sqli still detected past unrelated 'not' clause"

# Graceful degradation: when the guard suppresses the narrative, an
# agent-authored Primitive field is adopted (detector returned unknown).
seed_hits "demo_imp_negfield" 0
dir=$(make_crash "demo_imp_negfield" CRASH-IMP-NEGFIELD \
  "no SQL injection was directly observed in the harness run" \
  "library-api" "obeyed" "bytes" "5/5" "CL-x (singleton)")
echo "Primitive: sqli" >> "$dir/report.md"
_CURRENT_TEST="impact: structured Primitive field wins when narrative is negated"
read level score key i r cf <<< "$(get_severity "$dir")"
assert_eq "sqli" "$key" "Primitive field adopted after negation fallthrough"
assert_eq "36" "$i" "I=36 from the structured field"

# Negation AFTER the class name must also suppress — the negation token sits
# on the right of the phrase ("X is not possible", "X was ruled out").
seed_hits "demo_imp_negpost" 0
dir=$(make_crash "demo_imp_negpost" CRASH-IMP-NEGPOST \
  "We checked carefully: SQL injection is not possible and cache poisoning was ruled out" \
  "library-api" "obeyed" "bytes" "5/5" "CL-x (singleton)")
_CURRENT_TEST="impact: post-phrase negation ('is not possible'/'ruled out') suppresses"
read level score key i r cf <<< "$(get_severity "$dir")"
assert_eq "unknown" "$key" "trailing negation suppresses the class"

# But a trailing MECHANISM word ('without escaping', 'without validation') is
# not a class negation — it describes how the bug works, so the class stands.
# (Also exercises the colon: the class name is followed by ': <mechanism>'.)
seed_hits "demo_imp_mech" 0
dir=$(make_crash "demo_imp_mech" CRASH-IMP-MECH \
  "command injection: user input reaches shell exec without escaping" \
  "library-api" "obeyed" "bytes" "5/5" "CL-x (singleton)")
_CURRENT_TEST="impact: trailing 'without escaping' does not suppress command_injection"
read level score key i r cf <<< "$(get_severity "$dir")"
assert_eq "command_injection" "$key" "mechanism 'without' keeps the class"

# Colon-introduced denial: a colon directly after the class name introduces a
# qualifier, not a new statement, so 'SQL injection: not possible' / 'SSRF:
# ruled out' must be read as negated (the post-fix walked over the colon).
seed_hits "demo_imp_colon" 0
dir=$(make_crash "demo_imp_colon" CRASH-IMP-COLON \
  "Assessment — SQL injection: not possible. SSRF: ruled out after review" \
  "library-api" "obeyed" "bytes" "5/5" "CL-x (singleton)")
_CURRENT_TEST="impact: colon-introduced denial ('X: not possible') suppresses"
read level score key i r cf <<< "$(get_severity "$dir")"
assert_eq "unknown" "$key" "colon-introduced negation suppresses the class"

# Structured Primitive field outranks a prose-regex (web/recon) narrative
# match, but NOT a sanitizer-class match.
seed_hits "demo_imp_fieldwin" 0
dir=$(make_crash "demo_imp_fieldwin" CRASH-IMP-FIELDWIN \
  "open redirect via startsWith on the referrer parameter" \
  "library-api" "obeyed" "bytes" "5/5" "CL-x (singleton)")
echo "Primitive: sqli" >> "$dir/report.md"
_CURRENT_TEST="impact: structured field outranks prose-regex narrative class"
read level score key i r cf <<< "$(get_severity "$dir")"
assert_eq "sqli" "$key" "structured sqli beats narrative open_redirect"

seed_hits "demo_imp_fieldnosan" 0
dir=$(make_crash "demo_imp_fieldnosan" CRASH-IMP-FIELDNOSAN \
  "heap-use-after-free WRITE of size 8" \
  "library-api" "obeyed" "bytes" "5/5" "CL-x (singleton)")
echo "Primitive: open_redirect" >> "$dir/report.md"
_CURRENT_TEST="impact: sanitizer-class match is NOT overridden by structured field"
read level score key i r cf <<< "$(get_severity "$dir")"
assert_eq "uaf_write" "$key" "sanitizer uaf_write beats structured open_redirect"

seed_hits "demo_imp_cap" 0
dir=$(make_crash "demo_imp_cap" CRASH-IMP-CAP \
  "heap-buffer-overflow WRITE of size 8" "library-api" "obeyed" "bytes" "5/5" "CL-x (singleton)" \
  "caller-controlled offset, caller-controlled value, caller-controlled size, SCARINESS: 60")
_CURRENT_TEST="impact: modifier cap at +6 (3+3+2+2 → cap 6)"
read level score key i r cf <<< "$(get_severity "$dir")"
# I = 32 (heap_write) + cap 6 = 38
assert_eq "38" "$i" "I=32+6 (modifiers capped at +6)"

# ── Web/application vulnerability classes ──────────────────────────
# These exercise detect_web_vuln(): a non-memory-safety finding (no
# ASan/UBSan output) carries a Type line like "open redirect" or a
# narrative phrase ("SSRF", "SQL injection"). The detector must pick
# the right primitive_key so the score is not stuck at base=8.

seed_hits "demo_imp_openred" 0
dir=$(make_crash "demo_imp_openred" CRASH-IMP-OPENRED \
  "open redirect via startsWith prefix check on referrer parameter" \
  "library-api" "obeyed" "bytes" "5/5" "CL-x (singleton)")
_CURRENT_TEST="impact: open-redirect web-vuln primitive"
read level score key i r cf <<< "$(get_severity "$dir")"
assert_eq "open_redirect" "$key" "open_redirect detected"
assert_eq "14" "$i" "I=14 for open-redirect"

seed_hits "demo_imp_ssrf" 0
dir=$(make_crash "demo_imp_ssrf" CRASH-IMP-SSRF \
  "server-side request forgery via unvalidated callback URL" \
  "library-api" "obeyed" "bytes" "5/5" "CL-x (singleton)")
_CURRENT_TEST="impact: SSRF web-vuln primitive"
read level score key i r cf <<< "$(get_severity "$dir")"
assert_eq "ssrf" "$key" "ssrf detected"
assert_eq "28" "$i" "I=28 for SSRF"

seed_hits "demo_imp_sqli" 0
dir=$(make_crash "demo_imp_sqli" CRASH-IMP-SQLI \
  "SQL injection in users.id query parameter — concatenated into raw SQL" \
  "library-api" "obeyed" "bytes" "5/5" "CL-x (singleton)")
_CURRENT_TEST="impact: SQLi web-vuln primitive"
read level score key i r cf <<< "$(get_severity "$dir")"
assert_eq "sqli" "$key" "sqli detected"
assert_eq "36" "$i" "I=36 for SQLi"

seed_hits "demo_imp_cmdinj" 0
dir=$(make_crash "demo_imp_cmdinj" CRASH-IMP-CMDINJ \
  "command injection — user input passed to shell exec without escaping" \
  "library-api" "obeyed" "bytes" "5/5" "CL-x (singleton)")
_CURRENT_TEST="impact: command-injection web-vuln primitive (RCE-tier)"
read level score key i r cf <<< "$(get_severity "$dir")"
assert_eq "command_injection" "$key" "command_injection detected"
assert_eq "40" "$i" "I=40 for command injection"

seed_hits "demo_imp_xss" 0
dir=$(make_crash "demo_imp_xss" CRASH-IMP-XSS \
  "stored XSS in profile bio rendered without escape" \
  "library-api" "obeyed" "bytes" "5/5" "CL-x (singleton)")
_CURRENT_TEST="impact: XSS web-vuln primitive"
read level score key i r cf <<< "$(get_severity "$dir")"
assert_eq "xss" "$key" "xss detected"
assert_eq "18" "$i" "I=18 for XSS"

seed_hits "demo_imp_authn" 0
dir=$(make_crash "demo_imp_authn" CRASH-IMP-AUTHN \
  "authentication bypass — session fixation lets attacker reuse signed cookie" \
  "library-api" "obeyed" "bytes" "5/5" "CL-x (singleton)")
_CURRENT_TEST="impact: authentication-bypass web-vuln primitive"
read level score key i r cf <<< "$(get_severity "$dir")"
assert_eq "authn_bypass" "$key" "authn_bypass detected"
assert_eq "32" "$i" "I=32 for authn bypass"

# Memory-safety wins over web-vuln when both keywords appear: ASan
# output is the precise signal, web-vuln narrative is secondary.
seed_hits "demo_imp_priority" 0
dir=$(make_crash "demo_imp_priority" CRASH-IMP-PRIORITY \
  "heap-buffer-overflow WRITE of size 8 — see SSRF discussion below" \
  "library-api" "obeyed" "bytes" "5/5" "CL-x (singleton)")
_CURRENT_TEST="impact: memory-safety primitive wins over web-vuln narrative"
read level score key i r cf <<< "$(get_severity "$dir")"
assert_eq "heap_write" "$key" "heap_write wins (ASan is the precise signal)"

# ───────────────────────────────────────────────────────────────────
# REACH axis (multiplicative: surface × callers × contract × controls)
# ───────────────────────────────────────────────────────────────────

# Hold I and CF roughly constant: heap-READ size 1 (I=16), 5/5 repro singleton (CF≈0.90).

# library + 0 callers + obeyed + bytes: 16 × 0.90 × 1.00 × 1.00 = 14.4 → 14
seed_hits "demo_e_lib_0" 0
dir=$(make_crash "demo_e_lib_0" CRASH-E-LIB-0 \
  "heap-buffer-overflow READ" "library-api" "obeyed" "bytes" "5/5" "CL-x (singleton)")
_CURRENT_TEST="reach: library + 0 callers / obeyed / bytes ≈ 14"
read level score key i r cf <<< "$(get_severity "$dir")"
assert_eq "14" "$r" "R=14 (16×0.90×1.00×1.00 — 0 callers gets the narrow-band low end)"

# library + 100 callers (popular tier) + obeyed + bytes
# 22 × clamp(0.90+0.05·log10(101),0.90,1.10)≈1.00 × 1.00 × 1.00 = 22
seed_hits "demo_e_libpop" 100
dir=$(make_crash "demo_e_libpop" CRASH-E-LIBPOP \
  "heap-buffer-overflow READ" "library-api" "obeyed" "bytes" "5/5" "CL-x (singleton)")
_CURRENT_TEST="reach: popular library tier kicks in at ≥50 callers (no double-count)"
read level score key i r cf <<< "$(get_severity "$dir")"
# 22 × ~1.00 × 1.00 × 1.00 ≈ 22 — popularity expressed only by tier upgrade now
assert_eq "22" "$r" "R=22 (popular library tier, single popularity signal)"

# Popularity counts distinct REPOS, not files: one repo carrying 100 matching
# files is a single dependent project and must NOT trigger the
# library_popular tier upgrade.
seed_hits_single_repo() {
  local sym="$1" hits="$2"
  local h; h=$(sha1_short "$sym")
  {
    printf '{"status":"ok","hits":['
    local sep="" i
    for ((i=0; i<hits; i++)); do
      printf '%s{"repo":"sg-mono","path":"sg-p%d"}' "$sep" "$i"; sep=","
    done
    printf ']}'
  } > "$REACHABILITY_MOCK_DIR/sourcegraph-${h}.json"
  printf '{"status":"unavailable","error":"n/a"}' > "$REACHABILITY_MOCK_DIR/gh-${h}.json"
}
seed_hits_single_repo "demo_e_monorepo" 100
dir=$(make_crash "demo_e_monorepo" CRASH-E-MONOREPO \
  "heap-buffer-overflow READ" "library-api" "obeyed" "bytes" "5/5" "CL-x (singleton)")
_CURRENT_TEST="reach: 100 files in ONE repo stays plain library tier"
read level score key i r cf <<< "$(get_severity "$dir")"
# 16 (library) × ~1.00 (file-count tilt) × 1.00 × 1.00 = 16 — no tier upgrade
assert_eq "16" "$r" "R=16 (single-repo hits do not impersonate popularity)"

# network + 1000 callers + obeyed + bytes: 28 × 1.05 × 1.00 × 1.00 = 29.4 → 29
seed_hits "demo_e_net" 1000
dir=$(make_crash "demo_e_net" CRASH-E-NET \
  "heap-buffer-overflow READ" "network — TLS handler" "obeyed" "bytes" "5/5" "CL-x (singleton)")
_CURRENT_TEST="reach: network surface with high reach ≈ 29"
read level score key i r cf <<< "$(get_severity "$dir")"
assert_eq "29" "$r" "R=29 (28×1.05×1.00×1.00 — narrow callers tilt only)"

# dev_tool tier (Surface field says "maint-tool"): 1 × ~1.0 × 1.10 × 1.00 ≈ 1
seed_hits "demo_e_devsurf" 75
dir=$(make_crash "demo_e_devsurf" CRASH-E-DEVSURF \
  "heap-buffer-overflow WRITE" "maint-tool — maintenance/test program" "obeyed" "bytes" "5/5" "CL-x (singleton)")
_CURRENT_TEST="reach: maint-tool Surface → dev_tool tier (R≈1)"
read level score key i r cf <<< "$(get_severity "$dir")"
assert_eq "1" "$r" "R=1 for dev_tool surface"

# False-positive guard: a clear production Surface tier ("cli — shipped tool")
# must NOT be overridden by Boundary or narrative mentions of a test harness
# used as the input mechanism. The bug lives where the Surface says it lives.
seed_hits "demo_e_cli_test_input" 100
dir=$(make_crash "demo_e_cli_test_input" CRASH-E-CLI-TESTIN \
  "heap-buffer-overflow READ" "cli — ASan frames are inside a shipped CLI" \
  "obeyed" "bytes" "5/5" "CL-x (singleton)" \
  "Boundary mentions: pcre2test input file (the test driver)")
_CURRENT_TEST="reach: production cli Surface trumps test-driver Boundary mention"
read level score key i r cf <<< "$(get_severity "$dir")"
# 8 (cli_production) × 1.00 × 1.00 × 1.00 = 8
assert_eq "8" "$r" "R=8 (cli_production tier preserved, not collapsed)"

# False-positive guard: "library-api — C harness calls public API" describes
# a LIBRARY bug exercised BY a harness — it must NOT classify as dev_tool just
# because the prose mentions "harness". Type prefix anchoring is what saves it.
seed_hits "demo_e_lib_harness_prose" 100
dir=$(make_crash "demo_e_lib_harness_prose" CRASH-E-LIB-HARNESS \
  "heap-buffer-overflow READ" \
  "library-api — C harness calls a public library entry point" \
  "obeyed" "bytes" "5/5" "CL-x (singleton)")
_CURRENT_TEST="reach: 'harness' in description doesn't trigger dev_tool"
read level score key i r cf <<< "$(get_severity "$dir")"
# Should classify as library_popular (100 callers ≥ threshold) → R ≈ 22
assert_eq "22" "$r" "R=22, library_popular tier (not collapsed to dev_tool)"

# Same primitive, no Surface mention but path "maint/" in narrative
seed_hits "demo_e_devpath" 75
dir=$(make_crash "demo_e_devpath" CRASH-E-DEVPATH \
  "heap-buffer-overflow WRITE in \`maint/ucptest.c:823\`" "unspecified" "obeyed" "bytes" "5/5" "CL-x (singleton)")
_CURRENT_TEST="reach: maint/ path in narrative → dev_tool tier"
read level score key i r cf <<< "$(get_severity "$dir")"
assert_eq "1" "$r" "R=1 for dev/test path detection"

# False-positive guard: a URL hostname like "attacker.example/path" must NOT
# be misread as a path under the "examples/" directory. The dev-tool path
# regex requires a path-like prefix (start/whitespace/slash/quote) and
# explicitly excludes '.' to avoid matching the example component of a
# fully-qualified domain name. This was the FIND-001 open-redirect false
# positive — the URL `http://localhost:2368@attacker.example/after-otc`
# kept collapsing the surface to dev_tool.
seed_hits "demo_e_url_example" 100
dir=$(make_crash "demo_e_url_example" CRASH-E-URL-EXAMPLE \
  "open-redirect via startsWith on http://localhost:2368@attacker.example/after-otc" \
  "library-api" "obeyed" "bytes" "5/5" "CL-x (singleton)")
_CURRENT_TEST="reach: URL hostname '.example/' does NOT trigger dev_tool"
read level score key i r cf <<< "$(get_severity "$dir")"
# 22 (library_popular at 100 callers) × 1.00 × 1.00 × 1.00 = 22
assert_eq "22" "$r" "R=22 (URL hostname did not collapse surface to dev_tool)"

# False-positive guard: ordinary English words ending in "test" ("latest",
# "fastest", "greatest", "contest", "attestation") in the Boundary field must
# NOT trip the test-binary name detector and collapse the surface to dev_tool.
seed_hits "demo_e_latest_word" 10
dir=$(make_crash "demo_e_latest_word" CRASH-E-LATEST-WORD \
  "heap-buffer-overflow READ" "unspecified" "obeyed" "bytes" "5/5" "CL-x (singleton)")
echo "Boundary: the latest attestation grammar via the fastest contest path" >> "$dir/report.md"
_CURRENT_TEST="reach: English -test words in Boundary do NOT demote to dev_tool"
read level score key i r cf <<< "$(get_severity "$dir")"
# unknown surface (6pt) × ~0.95 (10 callers) × 1.00 × 1.00 ≈ 6 — not 1
assert_eq "6" "$r" "R=6 (English -test words did not collapse surface)"

# True-negative restored: real bare driver names (libxml2's runtest/testapi,
# pcre2's ucptest) must STILL demote to dev_tool when cited in Boundary, even
# though they carry no digit/underscore. They are in the documented inclusion
# list precisely because the digit/delimiter shapes cannot catch them.
seed_hits "demo_e_runtest" 75
dir=$(make_crash "demo_e_runtest" CRASH-E-RUNTEST \
  "heap-buffer-overflow WRITE" "unspecified" "obeyed" "bytes" "5/5" "CL-x (singleton)")
echo "Boundary: crash reached only through the runtest driver harness" >> "$dir/report.md"
_CURRENT_TEST="reach: bare driver name 'runtest' in Boundary demotes to dev_tool"
read level score key i r cf <<< "$(get_severity "$dir")"
assert_eq "1" "$r" "R=1 (runtest recognised as a dev/test driver)"

# Explicit dev/test/fuzz PHRASE in Boundary prose (no binary name, no path)
# must demote — a Surface-less report whose Boundary says "fuzz harness bytes
# only" is non-shipping even when the crashing symbol is popular.
seed_hits "demo_e_fuzzphrase" 75
dir=$(make_crash "demo_e_fuzzphrase" CRASH-E-FUZZPHRASE \
  "heap-buffer-overflow WRITE" "unspecified" "obeyed" "bytes" "5/5" "CL-x (singleton)")
echo "Boundary: fuzz harness bytes only — not reachable from any shipped entry point" >> "$dir/report.md"
_CURRENT_TEST="reach: explicit 'fuzz harness' Boundary phrase demotes to dev_tool"
read level score key i r cf <<< "$(get_severity "$dir")"
assert_eq "1" "$r" "R=1 (fuzz-harness Boundary phrase recognised)"

# False-positive guard preserved: a library-api Surface whose description
# mentions a 'harness' (the exercise mechanism, not the bug location) must NOT
# be demoted by the new Boundary-phrase rule — the production Surface wins first.
seed_hits "demo_e_libharness2" 100
dir=$(make_crash "demo_e_libharness2" CRASH-E-LIBHARNESS2 \
  "heap-buffer-overflow READ" "library-api — C harness calls a public library entry point" \
  "obeyed" "bytes" "5/5" "CL-x (singleton)")
echo "Boundary: a C harness calls the public API" >> "$dir/report.md"
_CURRENT_TEST="reach: 'harness' in a library-api report is not demoted by phrase rule"
read level score key i r cf <<< "$(get_severity "$dir")"
assert_eq "22" "$r" "R=22 (library_popular preserved; bare 'harness' not a dev phrase)"

# All backends down → reach factor ×1.0 (neutral, no penalty)
seed_unavailable "demo_e_outage"
dir=$(make_crash "demo_e_outage" CRASH-E-OUTAGE \
  "heap-buffer-overflow READ" "library-api" "obeyed" "bytes" "5/5" "CL-x (singleton)")
_CURRENT_TEST="reach: all backends down → callers×1.0 (neutral)"
read level score key i r cf <<< "$(get_severity "$dir")"
# library-tier 16 × 1.0 (neutral) × 1.0 (obeyed baseline) × 1.0 = 16
assert_eq "16" "$r" "R=16 with neutral reach (no contract bonus)"

# Violated contract collapses R
seed_hits "demo_e_violated" 100
dir=$(make_crash "demo_e_violated" CRASH-E-VIOLATED \
  "heap-buffer-overflow READ" "library-api" "violated" "bytes" "5/5" "CL-x (singleton)")
_CURRENT_TEST="reach: contract violated factor (×0.7)"
read level score key i r cf <<< "$(get_severity "$dir")"
# 22 (popular) × 1.00 × 0.7 × 1.0 = 15.4 → 15
assert_eq "15" "$r" "R=15 with violated contract"

# Contract-flagged crashes can keep the authored Caller contract value
# (for example, "unspecified") while triage records the broader reach concern
# in a report-visible section. The scorer must apply the same reach penalty
# from that section without requiring the field to be rewritten to "violated".
seed_hits "demo_e_contract_concern" 100
dir=$(make_crash "demo_e_contract_concern" CRASH-E-CONTRACT-CONCERN \
  "heap-buffer-overflow READ" "library-api" "unspecified" "bytes" "5/5" "CL-x (singleton)")
cat >> "$dir/report.md" <<'EOF'

## Contract concern

Triage kept this crash in `crashes/` and flagged a contract concern: trigger shape outside the declared input boundary.
EOF
_CURRENT_TEST="reach: Contract concern section factor (×0.7)"
read level score key i r cf <<< "$(get_severity "$dir")"
# 22 (popular) × 1.00 × 0.7 × 1.0 = 15.4 → 15
assert_eq "15" "$r" "R=15 from Contract concern section with Caller contract unspecified"
python3 "$REACH" --report "$dir" --no-cache >/dev/null 2>&1
assert_file_contains "$dir/report.md" "contract concern flagged \(×0\\.7\)" \
  "rationale names Contract concern section penalty"

# Sidecar-only contract flag: triage may write a `.contract-flagged` marker
# without (or before) injecting the report-visible `## Contract concern`
# section — older triage versions did exactly this, and a later report
# regeneration can drop the section. The scorer must honour the sidecar so
# such bundles are not silently scored as if no concern existed. This is the
# CRASH-0031 regression: sidecar present, no section, Caller contract
# "unspecified" → must still apply the ×0.7 reach penalty.
seed_hits "demo_e_contract_sidecar" 100
dir=$(make_crash "demo_e_contract_sidecar" CRASH-E-CONTRACT-SIDECAR \
  "heap-buffer-overflow READ" "library-api" "unspecified" "bytes" "5/5" "CL-x (singleton)")
# Baseline: without the sidecar, an "unspecified" contract is the ×1.0 case.
_CURRENT_TEST="reach: no sidecar, unspecified contract scores neutral (×1.0)"
read level score key i r cf <<< "$(get_severity "$dir")"
# 22 (popular) × 1.00 × 1.00 × 1.0 = 22
assert_eq "22" "$r" "R=22 with no contract flag (×1.0 baseline)"
# Now drop the sidecar marker — the section is still absent from the report.
printf '# Contract-flagged by triage_crash_dirs\n# Reason: trigger requires [call-sequence] outside attacker_controls=[bytes]\n' \
  > "$dir/.contract-flagged"
_CURRENT_TEST="reach: .contract-flagged sidecar applies ×0.7 without report section"
read level score key i r cf <<< "$(get_severity "$dir")"
# 22 (popular) × 1.00 × 0.7 × 1.0 = 15.4 → 15
assert_eq "15" "$r" "R=15 from .contract-flagged sidecar (section absent)"
assert_file_not_contains "$dir/report.md" "^## Contract concern" \
  "sidecar derate does not require injecting the report section"
python3 "$REACH" --report "$dir" --no-cache >/dev/null 2>&1
assert_file_contains "$dir/report.md" "contract concern flagged \(×0\\.7\)" \
  "rationale names the sidecar-driven contract penalty"
# Removing the sidecar restores neutral scoring (no permanent derate baked in).
rm -f "$dir/.contract-flagged"
_CURRENT_TEST="reach: removing sidecar restores neutral scoring"
read level score key i r cf <<< "$(get_severity "$dir")"
assert_eq "22" "$r" "R back to 22 once the sidecar is removed"

# NEW: unknown surface + popular caller count gets promoted to library_popular.
# Reachability is a stronger signal than a missing Surface field — punishing
# the bug because the report author left Surface blank/"unknown" is the bug
# we just fixed.
seed_hits "demo_e_unkn_pop" 100
dir=$(make_crash "demo_e_unkn_pop" CRASH-E-UNKN-POP \
  "heap-buffer-overflow READ" "unknown" "obeyed" "bytes" "5/5" "CL-x (singleton)")
_CURRENT_TEST="reach: unknown surface promoted to library_popular when ≥50 callers"
read level score key i r cf <<< "$(get_severity "$dir")"
# Without promotion (old): 6 × 1.00 × 1.00 × 1.00 = 6
# With promotion:          22 × 1.00 × 1.00 × 1.00 = 22
assert_eq "22" "$r" "R=22 (promoted from unknown to library_popular by reachability)"

# Unknown surface with FEW callers stays unknown — promotion requires the
# POPULAR_LIBRARY_THRESHOLD signal.
seed_hits "demo_e_unkn_few" 5
dir=$(make_crash "demo_e_unkn_few" CRASH-E-UNKN-FEW \
  "heap-buffer-overflow READ" "unknown" "obeyed" "bytes" "5/5" "CL-x (singleton)")
_CURRENT_TEST="reach: unknown surface stays unknown when callers<threshold"
read level score key i r cf <<< "$(get_severity "$dir")"
# 6 × ~0.94 (n=5, narrow-band low end) × 1.00 × 1.00 ≈ 5.6 → 6
assert_eq "6" "$r" "R=6 (unknown stays unknown without popular-caller signal)"

# ───────────────────────────────────────────────────────────────────
# CONFIDENCE factor (multiplier on whole score)
# ───────────────────────────────────────────────────────────────────

# 5/5 + singleton: 0.7 + 0.20 = 0.90
seed_hits "demo_cf_55" 0
dir=$(make_crash "demo_cf_55" CRASH-CF-55 \
  "heap-buffer-overflow READ" "library-api" "obeyed" "bytes" "5/5" "CL-x (singleton)")
_CURRENT_TEST="confidence: 5/5 + singleton = 0.90"
read level score key i r cf <<< "$(get_severity "$dir")"
assert_eq "0.9" "$cf" "CF=0.90"

# 5/5 + 4-cluster + SCARINESS≥50: capped at 1.0
seed_hits "demo_cf_max" 0
dir=$(make_crash "demo_cf_max" CRASH-CF-MAX \
  "heap-buffer-overflow READ" "library-api" "obeyed" "bytes" "5/5" \
  "CL-x (4 reports: a, b, c, d)" \
  "SCARINESS: 60 (massive)")
_CURRENT_TEST="confidence: 5/5 + 4-cluster + SCARINESS = 1.0"
read level score key i r cf <<< "$(get_severity "$dir")"
assert_eq "1.0" "$cf" "CF=1.00 (max)"

# Flaky 1/5 + singleton: 0.7 − 0.20 = 0.50 — a report that fails most
# reruns is the documented "derated by half" floor case (CVSS RC:Unknown).
seed_hits "demo_cf_flaky" 0
dir=$(make_crash "demo_cf_flaky" CRASH-CF-FLAKY \
  "heap-buffer-overflow READ" "library-api" "obeyed" "bytes" "1/5" "CL-x (singleton)")
_CURRENT_TEST="confidence: flaky 1/5 + singleton = 0.50"
read level score key i r cf <<< "$(get_severity "$dir")"
assert_eq "0.5" "$cf" "CF=0.50 (flaky penalty −0.20)"

# ───────────────────────────────────────────────────────────────────
# LEVEL BUCKETING — verify the user's key cases land in the right band
# ───────────────────────────────────────────────────────────────────

# THE USER'S COMPLAINT: stack-WRITE in maint/ucptest.c MUST be Low,
# not Medium, even with a high-impact primitive. This is the calibration
# that distinguishes shipped-binary bugs from dev/test/maint code.
seed_hits "demo_ucptest_like" 75
dir=$(make_crash "demo_ucptest_like" CRASH-UCPTEST-LIKE \
  "stack-buffer-overflow WRITE of size 1" "maint-tool — maintenance/test program" \
  "obeyed" "bytes" "5/5" "CL-x (singleton)")
_CURRENT_TEST="bucket: maint-tool stack-WRITE → Low (industry standard)"
read level score key i r cf <<< "$(get_severity "$dir")"
assert_eq "Low" "$level" "Maint-tool stack-WRITE = Low"

# Same surface but with caller-controlled-bytes modifiers (the real
# CRASH-004-1 case) — even with I=36, the dev_tool surface cap kicks in.
seed_hits "demo_ucptest_modified" 75
dir=$(make_crash "demo_ucptest_modified" CRASH-UCPTEST-MOD \
  "stack-buffer-overflow WRITE of size 1" "maint-tool — maintenance/test program" \
  "obeyed" "bytes" "5/5" "CL-x (singleton)" \
  "caller-controlled offset, caller-controlled value, caller-controlled size, SCARINESS: 60")
_CURRENT_TEST="bucket: maint-tool with all modifiers — surface cap forces Low"
read level score key i r cf <<< "$(get_severity "$dir")"
assert_eq "Low" "$level" "Maint-tool stays Low even with caller-ctrl mods"
# Score must be at or below SURFACE_SCORE_CAP[dev_tool] = 24
[ "$score" -le 24 ] && pass "score ≤ 24 (cap held)" \
                   || fail "score ≤ 24 (cap held)" "score=$score exceeded cap"

# pcre2grep BUS / production CLI / 50 callers — Low (DoS only, local)
seed_hits "demo_pcre2grep_bus" 50
dir=$(make_crash "demo_pcre2grep_bus" CRASH-LVL-LOW \
  "BUS error" "cli — pcre2grep tool" "obeyed" "bytes" "5/5" "CL-x (singleton)")
_CURRENT_TEST="bucket: production CLI BUS / 50 callers → Low"
read level score key i r cf <<< "$(get_severity "$dir")"
assert_eq "Low" "$level" "CLI BUS = Low"

# pcre2 library-API singleton heap-READ / 116 callers — Medium
seed_hits "demo_pcre2_typical" 116
dir=$(make_crash "demo_pcre2_typical" CRASH-LVL-MED \
  "heap-buffer-overflow READ of size 1" "library-api" "obeyed" "bytes" "5/5" "CL-x (singleton)")
_CURRENT_TEST="bucket: pcre2-shape library-API heap-READ → Medium"
read level score key i r cf <<< "$(get_severity "$dir")"
assert_eq "Medium" "$level" "Library READ = Medium"

# UAF WRITE / library popular / 1000 callers / 4-cluster — High
seed_hits "demo_uaf_pop" 1000
dir=$(make_crash "demo_uaf_pop" CRASH-LVL-HIGH \
  "heap-use-after-free WRITE of size 8" "library-api" "obeyed" "bytes" "5/5" \
  "CL-x (4 reports: a, b, c, d)")
_CURRENT_TEST="bucket: UAF-WRITE / popular library / clustered → High"
read level score key i r cf <<< "$(get_severity "$dir")"
assert_eq "High" "$level" "UAF library = High"

# UAF WRITE / network-facing daemon / 1000 callers / 4-cluster /
# caller-controlled offset+size+value modifiers — Critical.
#
# Under the CVSS-3-proportional bucket scale (Critical ≥ ~91% of the
# realistic 77-point max), Critical is reserved for the worst-case "perfect
# storm": top-tier primitive, network surface, broad reach, AND
# caller-controlled offset/size/value modifiers. The unmodified case lands
# in High — that's the tighter calibration we want.
seed_hits "demo_uaf_net" 1000
dir=$(make_crash "demo_uaf_net" CRASH-LVL-CRIT \
  "heap-use-after-free WRITE of size 8" "network — TLS handshake handler" \
  "obeyed" "bytes" "5/5" "CL-x (4 reports: a, b, c, d)" \
  "caller-controlled offset, caller-controlled size, caller-controlled value")
_CURRENT_TEST="bucket: UAF-WRITE / network / clustered / caller-ctrl mods → Critical"
read level score key i r cf <<< "$(get_severity "$dir")"
assert_eq "Critical" "$level" "UAF network + full modifiers = Critical"

# ───────────────────────────────────────────────────────────────────
# REPORT LINE SHAPE + RATIONALE SECTION
# ───────────────────────────────────────────────────────────────────

_CURRENT_TEST="severity line carries (I, E, CF) breakdown + score=N"
seed_hits "demo_breakdown" 5
dir=$(make_crash "demo_breakdown" CRASH-BREAKDOWN \
  "heap-buffer-overflow WRITE of size 8" "library-api" "obeyed" "bytes" "5/5" "CL-x (singleton)" \
  "caller-controlled offset")
python3 "$REACH" --report "$dir" --no-cache >/dev/null 2>&1
assert_file_contains "$dir/report.md" "Severity\*\*: (High|Critical|Medium|Low) \(auto: I=" "I= breakdown present"
assert_file_contains "$dir/report.md" "R=[0-9]+/[0-9]+" "R= breakdown present"
assert_file_contains "$dir/report.md" "×CF=[0-9]" "×CF= multiplier present"
assert_file_contains "$dir/report.md" "score=" "score=N field present"
assert_file_contains "$dir/report.md" "reach\[" "reach breakdown present"

_CURRENT_TEST="rationale section: heading + axis table + bucket ladder"
assert_file_contains "$dir/report.md" "^## Severity rationale"  "rationale heading present"
assert_file_contains "$dir/report.md" "^\| I — impact" "I row present"
assert_file_contains "$dir/report.md" "^\| R — reach" "R row present"
assert_file_contains "$dir/report.md" "^\| CF — confidence factor" "CF row present"
assert_file_contains "$dir/report.md" "Critical ≥ 70, High ≥ 55, Medium ≥ 30, Low < 30" "bucket ladder present"
assert_file_contains "$dir/report.md" "CVSS-3 proportional" "CVSS-proportional rationale present"
assert_file_contains "$dir/report.md" "\*\*Bucket: (Critical|High|Medium|Low)\*\*" "bucket call-out present"
assert_file_contains "$dir/report.md" "Microsoft Bug Bar" "industry calibration cited"

_CURRENT_TEST="rationale section is idempotent across re-runs"
python3 "$REACH" --report "$dir" --no-cache >/dev/null 2>&1
python3 "$REACH" --report "$dir" --no-cache >/dev/null 2>&1
n=$(grep -c "^## Severity rationale" "$dir/report.md")
assert_eq "1" "$n" "rationale heading appears exactly once after 3 runs"

# Legacy "attacker-controlled" wording in the parsed text must still raise
# the impact modifier (real-world ASan SCARINESS lines literally use it).
_CURRENT_TEST="legacy attacker-controlled wording still parses"
seed_hits "demo_legacy_wording" 0
dir=$(make_crash "demo_legacy_wording" CRASH-LEGACY \
  "heap-buffer-overflow WRITE of size 8" "library-api" "obeyed" "bytes" "5/5" "CL-x (singleton)" \
  "attacker-controlled offset, attacker-controlled value")
read level score key i r cf <<< "$(get_severity "$dir")"
# 32 (heap_write) + 3 (offset) + 2 (value) = 37
assert_eq "37" "$i" "I=32+3+2 with legacy wording"

# ───────────────────────────────────────────────────────────────────
# LLM hybrid field-fill: .llm_fields.json sidecar fills missing fields
# ───────────────────────────────────────────────────────────────────
#
# Build a finding-shaped report with NO Surface/Caller-controls/Primitive
# fields, drop a sidecar carrying classifier output, and assert the
# scorer picks them up. This mirrors the production flow where
# lib/triage.sh writes the sidecar before invoking bin/reachability.

# Sidecar-less baseline: open-redirect narrative, no fields → score is
# small because reach falls through to "unknown" surface and controls.
make_finding_no_fields() {
  local id="$1" narrative="$2"
  local dir="$TEST_TMPDIR/findings/$id"
  mkdir -p "$dir"
  {
    echo "# $id"
    echo
    echo "## Summary"
    echo "$narrative"
    echo
    echo "## Classification"
    echo "- **Severity**: TBD"
  } > "$dir/report.md"
  printf '%s\n' "$dir"
}

seed_unavailable "_no_sym"  # no symbols → neutral callers factor
dir=$(make_finding_no_fields FIND-LLMFILL-BASE \
  "Open redirect via startsWith on http://localhost:2368@attacker.example/")
_CURRENT_TEST="llm-fill: baseline (no sidecar) — open-redirect classified by narrative, surface stays unknown"
read level score key i r cf <<< "$(get_severity "$dir")"
assert_eq "open_redirect" "$key" "open_redirect detected from narrative"
# Reach: surface=unknown (6pt) × ~1.0 × 1.0 × controls=0.4 ≈ 2 → 2
[ "$r" -le 6 ] && pass "$_CURRENT_TEST: R≤6 without sidecar (surface=unknown, controls=unspecified)" \
              || fail "$_CURRENT_TEST" "R=$r expected ≤6 baseline"

# With sidecar: surface=library-api, caller_controls=bytes, contract=obeyed
_CURRENT_TEST="llm-fill: sidecar fills missing fields — Surface + Controls drive R up"
dir=$(make_finding_no_fields FIND-LLMFILL-FULL \
  "Open redirect via startsWith on http://localhost:2368@attacker.example/")
cat > "$dir/.llm_fields.json" <<'JSON'
{
  "surface":         "library-api — public members signin redirect handler",
  "primitive":       "open_redirect",
  "caller_contract": "obeyed",
  "caller_controls": "bytes"
}
JSON
read level score key i r cf <<< "$(get_severity "$dir")"
assert_eq "open_redirect" "$key" "primitive still open_redirect"
# Reach now: library-api (16pt) × 1.0 × 1.0 × 1.0 = 16
assert_eq "16" "$r" "R=16 after sidecar fills Surface=library-api + Controls=bytes"

# Sidecar must NEVER override an agent-authored field.
_CURRENT_TEST="llm-fill: sidecar does NOT override existing agent fields"
seed_unavailable "demo_llm_override"
dir=$(make_crash "demo_llm_override" CRASH-LLMFILL-OVR \
  "heap-buffer-overflow READ" "library-api" "obeyed" "bytes" "5/5" "CL-x (singleton)")
# Sidecar tries to demote Surface to dev-tool. It must lose to the
# agent-authored Surface field.
cat > "$dir/.llm_fields.json" <<'JSON'
{
  "surface": "dev-tool — maintenance script",
  "primitive": "unknown",
  "caller_controls": "flags"
}
JSON
read level score key i r cf <<< "$(get_severity "$dir")"
# Surface stays library-api (16pt) × 1.0 (callers neutral) × 1.0 × 1.0 = 16 (not 1)
assert_eq "16" "$r" "R=16 (agent Surface preserved, sidecar dev-tool ignored)"

# Sidecar primitive is only adopted when the narrative detector returns
# "unknown". An ASan/web-vuln narrative match takes precedence.
_CURRENT_TEST="llm-fill: narrative primitive wins over sidecar primitive"
seed_hits "demo_llm_prim" 0
dir=$(make_crash "demo_llm_prim" CRASH-LLMFILL-PRIM \
  "heap-use-after-free WRITE of size 8" "library-api" "obeyed" "bytes" "5/5" "CL-x (singleton)")
cat > "$dir/.llm_fields.json" <<'JSON'
{
  "surface": "library-api",
  "primitive": "open_redirect"
}
JSON
read level score key i r cf <<< "$(get_severity "$dir")"
assert_eq "uaf_write" "$key" "uaf_write wins over sidecar open_redirect"

# Malformed sidecar must not break scoring.
_CURRENT_TEST="llm-fill: malformed sidecar JSON is ignored"
seed_unavailable "demo_llm_bad"
dir=$(make_crash "demo_llm_bad" CRASH-LLMFILL-BAD \
  "heap-buffer-overflow READ" "library-api" "obeyed" "bytes" "5/5" "CL-x (singleton)")
printf 'not valid json{' > "$dir/.llm_fields.json"
read level score key i r cf <<< "$(get_severity "$dir")"
assert_eq "heap_read_small" "$key" "primitive detected despite bad sidecar"
# Reach: library-api × 1.0 (neutral) × 1.0 × 1.0 = 16
assert_eq "16" "$r" "R=16 unchanged by malformed sidecar"

teardown_test_env
summary
