#!/usr/bin/env bash
# Tests for the CVSS v4.0 severity scorer in bin/reachability.
#
# Severity is the CVSS v4.0 B/BT/BE/BTE score — one industry-standard metric.
# The pipeline is pure mappings followed by the vendored reference scorer:
#   crash report  → primitive class                  (detect_primitive)
#   report fields → surface tier                      (classify_surface)
#                 → CVSS Base/Threat/Env metrics      (_cvss4_metrics)
#                 → 0–10 CVSS v4.0 score              (lib/cvss4)
# Reachability, reproducibility, caller-control, and non-shipping context are
# represented through CVSS Threat/Environmental metrics, not a custom formula.
#
# Coverage is split into: (1) primitive classification, (2) surface → AV/UI
# and caller-control → MAT derivation, (3) CVSS scores/ratings on canonical
# shapes, (4) non-shipping Environmental impact, (5) report line + rationale
# shape, (6) the LLM sidecar field-fill. Cluster size is not part of severity.
#
# Strategy: drive bin/reachability --report with a fully-mocked reachability
# backend (REACHABILITY_MOCK_DIR), so only the scorer is under test.
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
# table. Args:
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

# Run --report and pluck the severity contract from JSON output. Prints:
#   <level> <score> <primitive_key> <surface_label> <rating> <vector>
# Unclassified crashes print: Unknown None unknown <surface> None -
get_severity() {
  local dir="$1"
  python3 "$REACH" --report "$dir" --json --no-cache 2>/dev/null \
    | python3 -c '
import json, sys
d = json.load(sys.stdin)["severity"]
cv = d.get("cvss") or {}
print(d["level"], d.get("score"), d["primitive_key"], d["surface_label"],
      cv.get("rating", "None"), cv.get("vector", "-"))
'
}

# Extract a single CVSS metric (AV/AT/UI/VC/MAT/...) from the scored vector.
metric() {
  local vector="$1" name="$2"
  printf '%s' "$vector" | tr '/' '\n' | awk -F: -v n="$name" '$1==n {print $2}'
}

# ───────────────────────────────────────────────────────────────────
# 1. PRIMITIVE CLASSIFICATION (detect_primitive)
# ───────────────────────────────────────────────────────────────────
# These pin the crash → class mapping. The CVSS score follows from the class.

seed_hits "demo_uafw" 0
dir=$(make_crash "demo_uafw" CRASH-UAFW \
  "heap-use-after-free WRITE of size 8" "library-api" "obeyed" "bytes" "5/5" "CL-x (singleton)")
_CURRENT_TEST="class: UAF WRITE"
read level score key surface rating vector <<< "$(get_severity "$dir")"
assert_eq "uaf_write" "$key" "uaf_write detected"

seed_hits "demo_wildw" 0
dir=$(make_crash "demo_wildw" CRASH-WILDW \
  "wild-addr-write of size 8" "library-api" "obeyed" "bytes" "5/5" "CL-x (singleton)")
_CURRENT_TEST="class: wild-addr WRITE"
read level score key surface rating vector <<< "$(get_severity "$dir")"
assert_eq "wild_write" "$key" "wild_write detected"

seed_hits "demo_heapw" 0
dir=$(make_crash "demo_heapw" CRASH-HEAPW \
  "heap-buffer-overflow WRITE of size 8" "library-api" "obeyed" "bytes" "5/5" "CL-x (singleton)")
_CURRENT_TEST="class: heap WRITE"
read level score key surface rating vector <<< "$(get_severity "$dir")"
assert_eq "heap_write" "$key" "heap_write detected"

seed_hits "demo_heapr_big" 0
dir=$(make_crash "demo_heapr_big" CRASH-HEAPR-BIG \
  "heap-buffer-overflow READ of size 4096" "library-api" "obeyed" "bytes" "5/5" "CL-x (singleton)")
_CURRENT_TEST="class: heap READ ≥16 (info-disclosure shaped)"
read level score key surface rating vector <<< "$(get_severity "$dir")"
assert_eq "heap_read_big" "$key" "heap_read_big detected"

seed_hits "demo_heapr_small" 0
dir=$(make_crash "demo_heapr_small" CRASH-HEAPR-SMALL \
  "heap-buffer-overflow READ of size 1" "library-api" "obeyed" "bytes" "5/5" "CL-x (singleton)")
_CURRENT_TEST="class: 1-byte heap READ"
read level score key surface rating vector <<< "$(get_severity "$dir")"
assert_eq "heap_read_small" "$key" "heap_read_small detected"

seed_hits "demo_bus" 0
dir=$(make_crash "demo_bus" CRASH-BUS \
  "BUS error" "cli" "obeyed" "bytes" "5/5" "CL-x (singleton)")
_CURRENT_TEST="class: BUS (DoS-only)"
read level score key surface rating vector <<< "$(get_severity "$dir")"
assert_eq "bus" "$key" "bus detected"

# ASan hyphenated stack-overflow is recursion exhaustion, not a buffer overflow.
seed_hits "demo_stackexh" 0
dir=$(make_crash "demo_stackexh" CRASH-STACKEXH \
  "AddressSanitizer: stack-overflow on address 0x7ffd4232fff8" \
  "library-api" "obeyed" "bytes" "5/5" "CL-x (singleton)")
_CURRENT_TEST="class: ASan stack-overflow → stack_exhaustion"
read level score key surface rating vector <<< "$(get_severity "$dir")"
assert_eq "stack_exhaustion" "$key" "stack_exhaustion detected"

# LeakSanitizer leaks are resource DoS, not data disclosure.
seed_hits "demo_lsan" 0
dir=$(make_crash "demo_lsan" CRASH-LSAN \
  "LeakSanitizer: detected memory leaks — Direct leak of 128 byte(s)" \
  "library-api" "obeyed" "bytes" "5/5" "CL-x (singleton)")
_CURRENT_TEST="class: LeakSanitizer → memory_leak (not info_leak)"
read level score key surface rating vector <<< "$(get_severity "$dir")"
assert_eq "memory_leak" "$key" "memory_leak detected"

# SEGV discrimination by faulting address.
seed_hits "demo_segv_null" 0
dir=$(make_crash "demo_segv_null" CRASH-SEGV-NULL \
  "SEGV on unknown address 0x000000000018" \
  "library-api" "obeyed" "bytes" "5/5" "CL-x (singleton)")
_CURRENT_TEST="class: near-null SEGV → null_deref"
read level score key surface rating vector <<< "$(get_severity "$dir")"
assert_eq "null_deref" "$key" "near-null SEGV is null_deref"

seed_hits "demo_segv_wildr" 0
dir=$(make_crash "demo_segv_wildr" CRASH-SEGV-WILDR \
  "SEGV on unknown address 0x612000000040 — The signal is caused by a READ memory access" \
  "library-api" "obeyed" "bytes" "5/5" "CL-x (singleton)")
_CURRENT_TEST="class: wild-address SEGV READ → wild_read"
read level score key surface rating vector <<< "$(get_severity "$dir")"
assert_eq "wild_read" "$key" "wild_read detected"

seed_hits "demo_segv_wildw" 0
dir=$(make_crash "demo_segv_wildw" CRASH-SEGV-WILDW \
  "SEGV on unknown address 0x612000000040 — The signal is caused by a WRITE memory access" \
  "library-api" "obeyed" "bytes" "5/5" "CL-x (singleton)")
_CURRENT_TEST="class: wild-address SEGV WRITE → wild_write"
read level score key surface rating vector <<< "$(get_severity "$dir")"
assert_eq "wild_write" "$key" "wild_write detected"

seed_hits "demo_race" 0
dir=$(make_crash "demo_race" CRASH-RACE \
  "WARNING: ThreadSanitizer: data race (pid=123)" \
  "library-api" "obeyed" "bytes" "5/5" "CL-x (singleton)")
_CURRENT_TEST="class: TSan data race → data_race"
read level score key surface rating vector <<< "$(get_severity "$dir")"
assert_eq "data_race" "$key" "data_race detected"

seed_hits "demo_intovf" 0
dir=$(make_crash "demo_intovf" CRASH-INTOVF \
  "x.c:12:5: runtime error: signed integer overflow: 2147483647 + 1 cannot be represented" \
  "library-api" "obeyed" "bytes" "5/5" "CL-x (singleton)")
_CURRENT_TEST="class: UBSan signed integer overflow → integer_overflow"
read level score key surface rating vector <<< "$(get_severity "$dir")"
assert_eq "integer_overflow" "$key" "integer_overflow detected"

seed_hits "demo_invfree" 0
dir=$(make_crash "demo_invfree" CRASH-INVFREE \
  "attempting free on address which was not malloc()-ed" \
  "library-api" "obeyed" "bytes" "5/5" "CL-x (singleton)")
_CURRENT_TEST="class: invalid free → double_free family"
read level score key surface rating vector <<< "$(get_severity "$dir")"
assert_eq "double_free" "$key" "invalid free maps to double_free"

# Type confusion (CWE-843): ClusterFuzz Bad-cast / CFI / UBSan vptr.
seed_hits "demo_badcast" 0
dir=$(make_crash "demo_badcast" CRASH-BADCAST \
  "AddressSanitizer: Bad-cast to app::Node from app::Leaf" \
  "library-api" "obeyed" "bytes" "5/5" "CL-x (singleton)")
_CURRENT_TEST="class: Bad-cast → type_confusion"
read level score key surface rating vector <<< "$(get_severity "$dir")"
assert_eq "type_confusion" "$key" "type_confusion detected from Bad-cast"

seed_hits "demo_vptr" 0
dir=$(make_crash "demo_vptr" CRASH-VPTR \
  "x.cc:10:5: runtime error: member access within address 0x60b000000040 which does not point to an object — invalid vptr" \
  "library-api" "obeyed" "bytes" "5/5" "CL-x (singleton)")
_CURRENT_TEST="class: UBSan vptr → type_confusion"
read level score key surface rating vector <<< "$(get_severity "$dir")"
assert_eq "type_confusion" "$key" "vptr maps to type_confusion"

# MSan use-of-uninitialized-value — diagnostic token wins over prose web mention.
seed_hits "demo_msan" 0
dir=$(make_crash "demo_msan" CRASH-MSAN \
  "WARNING: MemorySanitizer: use-of-uninitialized-value — unrelated note: the SSRF audit is tracked separately" \
  "library-api" "obeyed" "bytes" "5/5" "CL-x (singleton)")
_CURRENT_TEST="class: MSan token → info_leak (wins over prose web mention)"
read level score key surface rating vector <<< "$(get_severity "$dir")"
assert_eq "info_leak" "$key" "MSan token classifies as info_leak"

# Bare tool-name mention is triage prose, not a diagnostic.
seed_hits "demo_msan_neg" 0
dir=$(make_crash "demo_msan_neg" CRASH-MSAN-NEG \
  "SEGV on unknown address 0x000000000018; no MemorySanitizer diagnostic was produced and the KMSAN build is unavailable" \
  "library-api" "obeyed" "bytes" "5/5" "CL-x (singleton)")
_CURRENT_TEST="class: bare MSan/KMSAN tool mention does NOT classify as info_leak"
read level score key surface rating vector <<< "$(get_severity "$dir")"
assert_eq "null_deref" "$key" "tool-name prose ignored; SEGV classifies"

# Quoted ../../ input bytes are not path traversal.
seed_hits "demo_dotdot" 0
dir=$(make_crash "demo_dotdot" CRASH-DOTDOT \
  "SEGV with testcase bytes ../../etc/passwd quoted from the corpus" \
  "library-api" "obeyed" "bytes" "5/5" "CL-x (singleton)")
_CURRENT_TEST="class: quoted ../../ input is not path_traversal"
read level score key surface rating vector <<< "$(get_severity "$dir")"
assert_eq "null_deref" "$key" "SEGV wins; ../../ alone is not traversal"

# ── Web/application classes ──
seed_hits "demo_openred" 0
dir=$(make_crash "demo_openred" CRASH-OPENRED \
  "open redirect via startsWith prefix check on referrer parameter" \
  "library-api" "obeyed" "bytes" "5/5" "CL-x (singleton)")
_CURRENT_TEST="class: open redirect"
read level score key surface rating vector <<< "$(get_severity "$dir")"
assert_eq "open_redirect" "$key" "open_redirect detected"

seed_hits "demo_ssrf" 0
dir=$(make_crash "demo_ssrf" CRASH-SSRF \
  "server-side request forgery via unvalidated callback URL" \
  "library-api" "obeyed" "bytes" "5/5" "CL-x (singleton)")
_CURRENT_TEST="class: SSRF"
read level score key surface rating vector <<< "$(get_severity "$dir")"
assert_eq "ssrf" "$key" "ssrf detected"

seed_hits "demo_sqli" 0
dir=$(make_crash "demo_sqli" CRASH-SQLI \
  "SQL injection in users.id query parameter — concatenated into raw SQL" \
  "library-api" "obeyed" "bytes" "5/5" "CL-x (singleton)")
_CURRENT_TEST="class: SQLi"
read level score key surface rating vector <<< "$(get_severity "$dir")"
assert_eq "sqli" "$key" "sqli detected"

seed_hits "demo_cmdinj" 0
dir=$(make_crash "demo_cmdinj" CRASH-CMDINJ \
  "command injection — user input passed to shell exec without escaping" \
  "library-api" "obeyed" "bytes" "5/5" "CL-x (singleton)")
_CURRENT_TEST="class: command injection (mechanism 'without' keeps class)"
read level score key surface rating vector <<< "$(get_severity "$dir")"
assert_eq "command_injection" "$key" "command_injection detected"

seed_hits "demo_xss" 0
dir=$(make_crash "demo_xss" CRASH-XSS \
  "stored XSS in profile bio rendered without escape" \
  "library-api" "obeyed" "bytes" "5/5" "CL-x (singleton)")
_CURRENT_TEST="class: XSS"
read level score key surface rating vector <<< "$(get_severity "$dir")"
assert_eq "xss" "$key" "xss detected"

# Memory-safety wins over an incidental web-vuln mention.
seed_hits "demo_priority" 0
dir=$(make_crash "demo_priority" CRASH-PRIORITY \
  "heap-buffer-overflow WRITE of size 8 — see SSRF discussion below" \
  "library-api" "obeyed" "bytes" "5/5" "CL-x (singleton)")
_CURRENT_TEST="class: memory-safety wins over web-vuln narrative"
read level score key surface rating vector <<< "$(get_severity "$dir")"
assert_eq "heap_write" "$key" "heap_write wins (ASan is precise)"

# ── Negation guard ──
seed_hits "demo_negated" 0
dir=$(make_crash "demo_negated" CRASH-NEGATED \
  "Reviewed the session layer; no SQL injection or authentication bypass was observed, and this rules out cache poisoning" \
  "library-api" "obeyed" "bytes" "5/5" "CL-x (singleton)")
_CURRENT_TEST="negation: negated web-vuln mentions do not classify"
read level score key surface rating vector <<< "$(get_severity "$dir")"
assert_eq "unknown" "$key" "negated mentions fall through to unknown"

seed_hits "demo_negpos" 0
dir=$(make_crash "demo_negpos" CRASH-NEGPOS \
  "input is not sanitized, leading to SQL injection in the id parameter" \
  "library-api" "obeyed" "bytes" "5/5" "CL-x (singleton)")
_CURRENT_TEST="negation: comma-clause negation does not suppress a real finding"
read level score key surface rating vector <<< "$(get_severity "$dir")"
assert_eq "sqli" "$key" "sqli still detected past unrelated 'not' clause"

seed_hits "demo_negpost" 0
dir=$(make_crash "demo_negpost" CRASH-NEGPOST \
  "We checked carefully: SQL injection is not possible and cache poisoning was ruled out" \
  "library-api" "obeyed" "bytes" "5/5" "CL-x (singleton)")
_CURRENT_TEST="negation: post-phrase ('is not possible'/'ruled out') suppresses"
read level score key surface rating vector <<< "$(get_severity "$dir")"
assert_eq "unknown" "$key" "trailing negation suppresses the class"

seed_hits "demo_colon" 0
dir=$(make_crash "demo_colon" CRASH-COLON \
  "Assessment — SQL injection: not possible. SSRF: ruled out after review" \
  "library-api" "obeyed" "bytes" "5/5" "CL-x (singleton)")
_CURRENT_TEST="negation: colon-introduced denial ('X: not possible') suppresses"
read level score key surface rating vector <<< "$(get_severity "$dir")"
assert_eq "unknown" "$key" "colon-introduced negation suppresses the class"

seed_hits "demo_prevent" 0
dir=$(make_crash "demo_prevent" CRASH-PREVENT \
  "the tagged-union check prevents type confusion; parameterized queries mitigate SQL injection and the loader is hardened against XXE" \
  "library-api" "obeyed" "bytes" "5/5" "CL-x (singleton)")
_CURRENT_TEST="negation: prevention/mitigation wording does not mint a class"
read level score key surface rating vector <<< "$(get_severity "$dir")"
assert_eq "unknown" "$key" "prevention prose suppressed for all classes"

# Prose-only type confusion stays in the conservative small-read tier.
seed_hits "demo_tc_prose" 0
dir=$(make_crash "demo_tc_prose" CRASH-TC-PROSE \
  "the parser exhibits type confusion between node kinds" \
  "library-api" "obeyed" "bytes" "5/5" "CL-x (singleton)")
_CURRENT_TEST="class: prose-only type confusion stays heap_read_small"
read level score key surface rating vector <<< "$(get_severity "$dir")"
assert_eq "heap_read_small" "$key" "prose type confusion stays conservative"

# ───────────────────────────────────────────────────────────────────
# 2. STRUCTURED Primitive field precedence
# ───────────────────────────────────────────────────────────────────
# A structured `Primitive:` field outranks a prose-regex (web/recon) class but
# never a precise sanitizer-class match.

seed_hits "demo_negfield" 0
dir=$(make_crash "demo_negfield" CRASH-NEGFIELD \
  "no SQL injection was directly observed in the harness run" \
  "library-api" "obeyed" "bytes" "5/5" "CL-x (singleton)")
echo "Primitive: sqli" >> "$dir/report.md"
_CURRENT_TEST="field: structured Primitive wins when narrative is negated"
read level score key surface rating vector <<< "$(get_severity "$dir")"
assert_eq "sqli" "$key" "Primitive field adopted after negation fallthrough"

seed_hits "demo_fieldwin" 0
dir=$(make_crash "demo_fieldwin" CRASH-FIELDWIN \
  "open redirect via startsWith on the referrer parameter" \
  "library-api" "obeyed" "bytes" "5/5" "CL-x (singleton)")
echo "Primitive: sqli" >> "$dir/report.md"
_CURRENT_TEST="field: structured field outranks prose-regex narrative class"
read level score key surface rating vector <<< "$(get_severity "$dir")"
assert_eq "sqli" "$key" "structured sqli beats narrative open_redirect"

seed_hits "demo_fieldnosan" 0
dir=$(make_crash "demo_fieldnosan" CRASH-FIELDNOSAN \
  "heap-use-after-free WRITE of size 8" \
  "library-api" "obeyed" "bytes" "5/5" "CL-x (singleton)")
echo "Primitive: open_redirect" >> "$dir/report.md"
_CURRENT_TEST="field: sanitizer-class match is NOT overridden by structured field"
read level score key surface rating vector <<< "$(get_severity "$dir")"
assert_eq "uaf_write" "$key" "sanitizer uaf_write beats structured open_redirect"

seed_hits "demo_tc_field" 0
dir=$(make_crash "demo_tc_field" CRASH-TC-FIELD \
  "validator-confirmed object reinterpretation across union arms" \
  "library-api" "obeyed" "bytes" "5/5" "CL-x (singleton)")
echo "Primitive: type_confusion" >> "$dir/report.md"
_CURRENT_TEST="field: structured Primitive type_confusion adopted"
read level score key surface rating vector <<< "$(get_severity "$dir")"
assert_eq "type_confusion" "$key" "structured type_confusion adopted"

# ───────────────────────────────────────────────────────────────────
# 3. CVSS DERIVATION — surface → AV/UI, contract/control → MAT
# ───────────────────────────────────────────────────────────────────

# Network surface → AV:N, UI:N.
seed_hits "demo_net" 0
dir=$(make_crash "demo_net" CRASH-NET \
  "heap-buffer-overflow READ of size 1" "network — TLS handler" "obeyed" "bytes" "5/5" "CL-x (singleton)")
_CURRENT_TEST="derive: network surface → AV:N/UI:N"
read level score key surface rating vector <<< "$(get_severity "$dir")"
assert_eq "network" "$surface" "network surface classified"
assert_eq "N" "$(metric "$vector" AV)" "AV:N for network"
assert_eq "N" "$(metric "$vector" UI)" "UI:N for network"

# Library surface → AV:N, UI:N: scored for the reasonable worst-case
# embedding per the CVSS v4.0 user-guide library guidance (an automated
# consumer feeds attacker bytes; no human user participates).
seed_hits "demo_lib" 0
dir=$(make_crash "demo_lib" CRASH-LIB \
  "heap-buffer-overflow READ of size 1" "library-api" "obeyed" "bytes" "5/5" "CL-x (singleton)")
_CURRENT_TEST="derive: library surface → AV:N/UI:N"
read level score key surface rating vector <<< "$(get_severity "$dir")"
assert_eq "N" "$(metric "$vector" AV)" "AV:N for library"
assert_eq "N" "$(metric "$vector" UI)" "UI:N for library (worst-case embedding)"

# Production CLI → AV:L.
seed_hits "demo_cli" 0
dir=$(make_crash "demo_cli" CRASH-CLI \
  "heap-buffer-overflow READ of size 1" "cli — shipped tool" "obeyed" "bytes" "5/5" "CL-x (singleton)")
_CURRENT_TEST="derive: production CLI → AV:L"
read level score key surface rating vector <<< "$(get_severity "$dir")"
assert_eq "cli_production" "$surface" "cli_production classified"
assert_eq "L" "$(metric "$vector" AV)" "AV:L for CLI"

# Obeyed contract leaves AT:N/MAT:X; violated contract derives MAT:P.
seed_hits "demo_at_obeyed" 0
dir=$(make_crash "demo_at_obeyed" CRASH-AT-OBEYED \
  "heap-buffer-overflow WRITE of size 8" "library-api" "obeyed" "bytes" "5/5" "CL-x (singleton)")
_CURRENT_TEST="derive: obeyed contract → AT:N"
read level score key surface rating vector <<< "$(get_severity "$dir")"
assert_eq "N" "$(metric "$vector" AT)" "AT:N for obeyed contract"

seed_hits "demo_at_violated" 0
dir=$(make_crash "demo_at_violated" CRASH-AT-VIOLATED \
  "heap-buffer-overflow WRITE of size 8" "library-api" "violated" "bytes" "5/5" "CL-x (singleton)")
_CURRENT_TEST="derive: violated contract → MAT:P"
read level score key surface rating vector <<< "$(get_severity "$dir")"
assert_eq "N" "$(metric "$vector" AT)" "base AT remains intrinsic"
assert_eq "P" "$(metric "$vector" MAT)" "MAT:P for violated contract"

# A triage Contract concern section also yields MAT:P.
seed_hits "demo_at_concern" 0
dir=$(make_crash "demo_at_concern" CRASH-AT-CONCERN \
  "heap-buffer-overflow WRITE of size 8" "library-api" "unspecified" "bytes" "5/5" "CL-x (singleton)")
cat >> "$dir/report.md" <<'EOF'

## Contract concern

Triage flagged a contract concern: trigger shape outside the declared input boundary.
EOF
_CURRENT_TEST="derive: triage Contract concern section → MAT:P"
read level score key surface rating vector <<< "$(get_severity "$dir")"
assert_eq "N" "$(metric "$vector" AT)" "base AT remains intrinsic"
assert_eq "P" "$(metric "$vector" MAT)" "MAT:P from Contract concern section"

# Caller controls narrower than arbitrary bytes also derive MAT:P.
seed_hits "demo_mat_number" 0
dir=$(make_crash "demo_mat_number" CRASH-MAT-NUMBER \
  "heap-buffer-overflow WRITE of size 8" "library-api" "obeyed" "number" "5/5" "CL-x (singleton)")
_CURRENT_TEST="derive: limited caller controls → MAT:P"
read level score key surface rating vector <<< "$(get_severity "$dir")"
assert_eq "P" "$(metric "$vector" MAT)" "MAT:P for limited caller-controlled shape"

# Indirect/trusted parameter control is a local environmental precondition,
# even when the trigger payload itself is attacker-shaped bytes.
seed_hits "demo_mat_param" 0
dir=$(make_crash "demo_mat_param" CRASH-MAT-PARAM \
  "heap-buffer-overflow WRITE of size 8" "library-api" "obeyed" "bytes" "5/5" "CL-x (singleton)")
echo "Parameter control: application-supplied" >> "$dir/report.md"
_CURRENT_TEST="derive: application-supplied parameter → MAT:P"
read level score key surface rating vector <<< "$(get_severity "$dir")"
assert_eq "P" "$(metric "$vector" MAT)" "MAT:P for application-supplied parameter"

# Private/internal trusted actions are likewise local environmental
# preconditions; normal public calls are handled by the caller_controls field.
seed_hits "demo_mat_trusted" 0
dir=$(make_crash "demo_mat_trusted" CRASH-MAT-TRUSTED \
  "heap-buffer-overflow WRITE of size 8" "library-api" "obeyed" "bytes" "5/5" "CL-x (singleton)")
echo "Trusted caller actions: private struct mutation" >> "$dir/report.md"
_CURRENT_TEST="derive: trusted private action → MAT:P"
read level score key surface rating vector <<< "$(get_severity "$dir")"
assert_eq "P" "$(metric "$vector" MAT)" "MAT:P for private trusted caller action"

# XSS sets subsequent-system impact (SC:L/SI:L).
seed_hits "demo_xss_sub" 0
dir=$(make_crash "demo_xss_sub" CRASH-XSS-SUB \
  "stored XSS in profile bio rendered without escape" "library-api" "obeyed" "bytes" "5/5" "CL-x (singleton)")
_CURRENT_TEST="derive: XSS → subsequent-system SC:L/SI:L"
read level score key surface rating vector <<< "$(get_severity "$dir")"
assert_eq "L" "$(metric "$vector" SC)" "SC:L for XSS"
assert_eq "L" "$(metric "$vector" SI)" "SI:L for XSS"

# Threat Exploit Maturity: no evidence is E:U; saved reproducer/testcase
# artifacts are proof-of-concept availability (E:P).
seed_hits "demo_e_unreported" 0
dir=$(make_crash "demo_e_unreported" CRASH-E-U \
  "heap-buffer-overflow READ of size 1" "library-api" "obeyed" "bytes" "?" "CL-x (singleton)")
_CURRENT_TEST="derive: no exploit/reproducer evidence → E:U"
read level score key surface rating vector <<< "$(get_severity "$dir")"
assert_eq "U" "$(metric "$vector" E)" "E:U when no exploit/reproducer evidence recorded"

seed_hits "demo_e_poc" 0
dir=$(make_crash "demo_e_poc" CRASH-E-P \
  "heap-buffer-overflow READ of size 1" "library-api" "obeyed" "bytes" "?" "CL-x (singleton)")
printf 'payload\n' > "$dir/input.txt"
_CURRENT_TEST="derive: reproducer artifact → E:P"
read level score key surface rating vector <<< "$(get_severity "$dir")"
assert_eq "P" "$(metric "$vector" E)" "E:P from saved reproducer/testcase artifact"

# An affirmative exploitation claim is E:A; the same phrase NEGATED
# ("no evidence ... exploited in the wild") must NOT be — it is the
# opposite claim and previously inflated the score past the E:P reading.
seed_hits "demo_e_wild" 0
dir=$(make_crash "demo_e_wild" CRASH-E-WILD \
  "heap-buffer-overflow WRITE of size 8" "library-api" "obeyed" "bytes" "5/5" "CL-x (singleton)" \
  "Vendor advisory confirms this is actively exploited.")
_CURRENT_TEST="derive: affirmed exploitation → E:A"
read level score key surface rating vector <<< "$(get_severity "$dir")"
assert_eq "A" "$(metric "$vector" E)" "E:A from affirmed exploitation evidence"

seed_hits "demo_e_notwild" 0
dir=$(make_crash "demo_e_notwild" CRASH-E-NOTWILD \
  "heap-buffer-overflow WRITE of size 8" "library-api" "obeyed" "bytes" "5/5" "CL-x (singleton)" \
  "There is no evidence this bug has been exploited in the wild.")
_CURRENT_TEST="derive: negated exploitation claim stays E:P"
read level score key surface rating vector <<< "$(get_severity "$dir")"
assert_eq "P" "$(metric "$vector" E)" "negated in-the-wild claim does not derive E:A"

# Full byte control dominates an accompanying shape word: a caller who
# controls "document contents and length" shapes the whole input, so no
# MAT:P (the limited-shape reading applies only without byte control).
seed_hits "demo_mat_bytes_len" 0
dir=$(make_crash "demo_mat_bytes_len" CRASH-MAT-BYTESLEN \
  "heap-buffer-overflow WRITE of size 8" "library-api" "obeyed" \
  "Document contents and length." "5/5" "CL-x (singleton)")
_CURRENT_TEST="derive: byte control + length prose → no MAT"
read level score key surface rating vector <<< "$(get_severity "$dir")"
assert_eq "" "$(metric "$vector" MAT)" "byte control dominates length mention (no MAT:P)"

# ───────────────────────────────────────────────────────────────────
# 4. CVSS SCORES / RATINGS on canonical shapes
# ───────────────────────────────────────────────────────────────────
# These pin the standard against textbook NVD anchors.

# Pre-auth network memory corruption with a proof-of-concept reproducer.
seed_hits "demo_score_netuaf" 0
dir=$(make_crash "demo_score_netuaf" CRASH-SCORE-NETUAF \
  "heap-use-after-free WRITE of size 8" "network — TLS handler" "obeyed" "bytes" "5/5" "CL-x (singleton)")
_CURRENT_TEST="score: network UAF WRITE → 8.9 High BTE"
read level score key surface rating vector <<< "$(get_severity "$dir")"
assert_eq "8.9" "$score" "score 8.9"
assert_eq "High" "$level" "level High"
assert_eq "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:P/CR:H/IR:H/AR:H" "$vector" "BTE vector"

# Library OOB small read — Medium: low impacts (VC:L/VA:L) tempered by the
# ordinary-library environment (CR/IR/AR:M), not by a UI discount.
seed_hits "demo_score_libread" 0
dir=$(make_crash "demo_score_libread" CRASH-SCORE-LIBREAD \
  "heap-buffer-overflow READ of size 1" "library-api" "obeyed" "bytes" "5/5" "CL-x (singleton)")
_CURRENT_TEST="score: library 1-byte OOB read → Medium band"
read level score key surface rating vector <<< "$(get_severity "$dir")"
assert_eq "5.5" "$score" "library small read score 5.5"
assert_eq "Medium" "$level" "library small read is Medium (low impacts, M environment)"

# XSS — subsequent-system-only impacts stay mid-band under the local BTE
# environment.
seed_hits "demo_score_xss" 0
dir=$(make_crash "demo_score_xss" CRASH-SCORE-XSS \
  "stored XSS in profile bio rendered without escape" "library-api" "obeyed" "bytes" "5/5" "CL-x (singleton)")
_CURRENT_TEST="score: XSS → Medium"
read level score key surface rating vector <<< "$(get_severity "$dir")"
assert_eq "Medium" "$level" "XSS is Medium"

# Unclassified crash → Unknown, no score, no vector.
seed_hits "demo_score_unknown" 0
dir=$(make_crash "demo_score_unknown" CRASH-SCORE-UNKNOWN \
  "process exited abnormally with no sanitizer output" "library-api" "obeyed" "bytes" "5/5" "CL-x (singleton)")
_CURRENT_TEST="score: unclassified crash → Unknown, no vector"
read level score key surface rating vector <<< "$(get_severity "$dir")"
assert_eq "Unknown" "$level" "unclassified → Unknown level"
assert_eq "None" "$score" "no score for unclassified"
assert_eq "-" "$vector" "no vector for unclassified"

# Determinism: same input twice → identical score.
seed_hits "demo_determ" 0
dir=$(make_crash "demo_determ" CRASH-DETERM \
  "heap-use-after-free WRITE of size 8" "network — TLS handler" "obeyed" "bytes" "5/5" "CL-x (singleton)")
read _ s1 _ _ _ _ <<< "$(get_severity "$dir")"
read _ s2 _ _ _ _ <<< "$(get_severity "$dir")"
_CURRENT_TEST="score: deterministic across runs"
assert_eq "$s1" "$s2" "same input → same score"

# ───────────────────────────────────────────────────────────────────
# 5. NON-SHIPPING ENVIRONMENTAL IMPACT
# ───────────────────────────────────────────────────────────────────
# THE PRODUCT INVARIANT: a bug in non-shipping code (test/maint/internal) is
# still represented in one CVSS vector. Modified Environmental impacts reduce
# the BTE score without a custom post-score cap.

seed_hits "demo_devtool" 0
dir=$(make_crash "demo_devtool" CRASH-DEVTOOL \
  "stack-buffer-overflow WRITE of size 1" "maint-tool — maintenance/test program" \
  "obeyed" "bytes" "5/5" "CL-x (singleton)")
_CURRENT_TEST="env: maint-tool memory WRITE → modified impacts, Low"
read level score key surface rating vector <<< "$(get_severity "$dir")"
assert_eq "dev_tool" "$surface" "maint-tool classified as dev_tool"
assert_eq "Low" "$level" "modified impacts lower the BTE level"
assert_eq "L" "$(metric "$vector" MVA)" "modified availability impact lowered"
[ "$score" != "None" ] && pass "CVSS score retained ($score)" \
  || fail "CVSS score retained" "score dropped"

# maint/ path in narrative also demotes.
seed_hits "demo_devpath" 0
dir=$(make_crash "demo_devpath" CRASH-DEVPATH \
  "heap-buffer-overflow WRITE in \`maint/ucptest.c:823\`" "unspecified" "obeyed" "bytes" "5/5" "CL-x (singleton)")
_CURRENT_TEST="env: maint/ path in narrative → dev_tool → Low"
read level score key surface rating vector <<< "$(get_severity "$dir")"
assert_eq "dev_tool" "$surface" "maint/ path → dev_tool"
assert_eq "Low" "$level" "narrative dev path lowers to Low"

# Internal harness → None/0.0 when all modified impacts are N.
seed_hits "demo_internal" 0
dir=$(make_crash "demo_internal" CRASH-INTERNAL \
  "heap-use-after-free WRITE of size 8" "internal — audit harness" "obeyed" "bytes" "5/5" "CL-x (singleton)")
_CURRENT_TEST="env: internal harness → None"
read level score key surface rating vector <<< "$(get_severity "$dir")"
assert_eq "internal" "$surface" "internal surface classified"
assert_eq "None" "$level" "internal harness has no local environmental impact"

# False-positive guard: a real library-api whose description mentions a
# 'harness' (exercise mechanism, not bug location) must NOT be demoted.
seed_hits "demo_lib_harness" 0
dir=$(make_crash "demo_lib_harness" CRASH-LIB-HARNESS \
  "heap-buffer-overflow READ of size 1" \
  "library-api — C harness calls a public library entry point" \
  "obeyed" "bytes" "5/5" "CL-x (singleton)")
_CURRENT_TEST="cap guard: 'harness' in a library-api description is not demoted"
read level score key surface rating vector <<< "$(get_severity "$dir")"
assert_eq "library" "$surface" "library surface preserved (not dev_tool)"

# ───────────────────────────────────────────────────────────────────
# 6. REPORT LINE + RATIONALE SECTION SHAPE
# ───────────────────────────────────────────────────────────────────

_CURRENT_TEST="line: severity bullet carries level + CVSS-BTE 4.0 score + vector"
seed_hits "demo_line" 0
dir=$(make_crash "demo_line" CRASH-LINE \
  "heap-use-after-free WRITE of size 8" "network — TLS handler" "obeyed" "bytes" "5/5" "CL-x (singleton)")
python3 "$REACH" --report "$dir" --no-cache >/dev/null 2>&1
assert_file_contains "$dir/report.md" "Severity\*\*: (Critical|High|Medium|Low|None) \(CVSS(-[A-Z]+)? 4\\.0:" "CVSS v4.0 severity bullet"
assert_file_contains "$dir/report.md" "CVSS:4\\.0/AV:N/AC:L" "vector rendered in the bullet"

_CURRENT_TEST="section: CVSS vector + metric table + bands"
assert_file_contains "$dir/report.md" "^## Severity rationale" "rationale heading present"
assert_file_contains "$dir/report.md" "CVSS(-[A-Z]+)? v4\\.0\\*\\*: \`CVSS:4\\.0/" "CVSS vector line present"
assert_file_contains "$dir/report.md" "Attack Vector \\(AV\\)" "metric table present"
assert_file_contains "$dir/report.md" "Attack Requirements \\(AT\\).*intrinsic attack preconditions" "AT rationale is intrinsic"
assert_file_contains "$dir/report.md" "Critical ≥ 9.0, High ≥ 7.0, Medium ≥ 4.0" "CVSS bands present"

_CURRENT_TEST="section: verification facts labelled as priority, not severity"
assert_file_contains "$dir/report.md" "Verification facts" "verification facts present"
assert_file_contains "$dir/report.md" "not part of severity" "facts disclaimed from severity"

_CURRENT_TEST="rationale section is idempotent across re-runs"
python3 "$REACH" --report "$dir" --no-cache >/dev/null 2>&1
python3 "$REACH" --report "$dir" --no-cache >/dev/null 2>&1
n=$(grep -c "^## Severity rationale" "$dir/report.md")
assert_eq "1" "$n" "rationale heading appears exactly once after 3 runs"

_CURRENT_TEST="section: non-shipping environmental call-out rendered"
seed_hits "demo_capnote" 0
dir=$(make_crash "demo_capnote" CRASH-CAPNOTE \
  "stack-buffer-overflow WRITE of size 1" "maint-tool — maintenance/test program" \
  "obeyed" "bytes" "5/5" "CL-x (singleton)")
python3 "$REACH" --report "$dir" --no-cache >/dev/null 2>&1
assert_file_contains "$dir/report.md" "Non-shipping surface" "non-shipping note present"
assert_file_contains "$dir/report.md" "without a custom cap" "environmental explanation present"

# ───────────────────────────────────────────────────────────────────
# 7. LLM hybrid field-fill: .llm_fields.json sidecar
# ───────────────────────────────────────────────────────────────────

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

# Sidecar fills Surface + Primitive when the report omits them.
_CURRENT_TEST="llm-fill: sidecar fills missing Surface/Primitive"
seed_unavailable "_no_sym"
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
read level score key surface rating vector <<< "$(get_severity "$dir")"
assert_eq "open_redirect" "$key" "primitive filled from sidecar"
assert_eq "library" "$surface" "surface filled from sidecar"

# Sidecar must NEVER override an agent-authored field.
_CURRENT_TEST="llm-fill: sidecar does NOT override agent Surface"
seed_unavailable "demo_llm_override"
dir=$(make_crash "demo_llm_override" CRASH-LLMFILL-OVR \
  "heap-buffer-overflow READ of size 1" "library-api" "obeyed" "bytes" "5/5" "CL-x (singleton)")
cat > "$dir/.llm_fields.json" <<'JSON'
{ "surface": "dev-tool — maintenance script", "primitive": "unknown", "caller_controls": "flags" }
JSON
read level score key surface rating vector <<< "$(get_severity "$dir")"
assert_eq "library" "$surface" "agent Surface preserved, sidecar dev-tool ignored"

# Narrative sanitizer-class wins over a sidecar primitive.
_CURRENT_TEST="llm-fill: narrative sanitizer-class wins over sidecar primitive"
seed_hits "demo_llm_prim" 0
dir=$(make_crash "demo_llm_prim" CRASH-LLMFILL-PRIM \
  "heap-use-after-free WRITE of size 8" "library-api" "obeyed" "bytes" "5/5" "CL-x (singleton)")
cat > "$dir/.llm_fields.json" <<'JSON'
{ "surface": "library-api", "primitive": "open_redirect" }
JSON
read level score key surface rating vector <<< "$(get_severity "$dir")"
assert_eq "uaf_write" "$key" "uaf_write wins over sidecar open_redirect"

# Malformed sidecar must not break scoring.
_CURRENT_TEST="llm-fill: malformed sidecar JSON is ignored"
seed_unavailable "demo_llm_bad"
dir=$(make_crash "demo_llm_bad" CRASH-LLMFILL-BAD \
  "heap-buffer-overflow READ of size 1" "library-api" "obeyed" "bytes" "5/5" "CL-x (singleton)")
printf 'not valid json{' > "$dir/.llm_fields.json"
read level score key surface rating vector <<< "$(get_severity "$dir")"
assert_eq "heap_read_small" "$key" "primitive detected despite bad sidecar"

# Recon-class sidecar primitive is a valid enum and gets a CVSS vector.
_CURRENT_TEST="llm-fill: recon-class sidecar primitive (protocol_state) scored"
seed_unavailable "demo_llm_recon"
dir=$(make_crash "demo_llm_recon" CRASH-LLMFILL-RECON \
  "validator quorum promoted a state-handling flaw in the session layer" \
  "library-api" "obeyed" "bytes" "5/5" "CL-x (singleton)")
cat > "$dir/.llm_fields.json" <<'JSON'
{ "surface": "library-api", "primitive": "protocol_state" }
JSON
read level score key surface rating vector <<< "$(get_severity "$dir")"
assert_eq "protocol_state" "$key" "sidecar protocol_state adopted"
[ "$score" != "None" ] && pass "protocol_state scored a CVSS vector ($score)" \
  || fail "protocol_state scored" "no score"

teardown_test_env
summary
