#!/usr/bin/env bash
# Tests for the CVSS v4.0 severity scorer in bin/severity.
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
# shape, (6) conservative handling of omitted reach fields. Cluster size is not
# part of severity.
#
# Strategy: drive bin/severity --report on synthetic crash dirs. The scorer is
# fully offline and deterministic, so no mocks or network are involved.
set -o pipefail
source "$(dirname "$0")/helpers.sh"
setup_test_env

REACH="$SCRIPT_ROOT/bin/severity"
[ -x "$REACH" ] || { echo "FATAL: $REACH not executable"; exit 1; }

# Build a synthetic crash dir whose REPORT.md carries the structured Fields
# table. Args:
#   $1 sym (snake_case; written into the report Entry line),
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
  python3 "$REACH" --report "$dir" --json 2>/dev/null \
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

dir=$(make_crash "demo_uafw" CRASH-UAFW \
  "heap-use-after-free WRITE of size 8" "library-api" "obeyed" "bytes" "5/5" "CL-x (singleton)")
_CURRENT_TEST="class: UAF WRITE"
read level score key surface rating vector <<< "$(get_severity "$dir")"
assert_eq "uaf_write" "$key" "uaf_write detected"

dir=$(make_crash "demo_wildw" CRASH-WILDW \
  "wild-addr-write of size 8" "library-api" "obeyed" "bytes" "5/5" "CL-x (singleton)")
_CURRENT_TEST="class: wild-addr WRITE"
read level score key surface rating vector <<< "$(get_severity "$dir")"
assert_eq "wild_write" "$key" "wild_write detected"

dir=$(make_crash "demo_heapw" CRASH-HEAPW \
  "heap-buffer-overflow WRITE of size 8" "library-api" "obeyed" "bytes" "5/5" "CL-x (singleton)")
_CURRENT_TEST="class: heap WRITE"
read level score key surface rating vector <<< "$(get_severity "$dir")"
assert_eq "heap_write" "$key" "heap_write detected"

dir=$(make_crash "demo_heapr_big" CRASH-HEAPR-BIG \
  "heap-buffer-overflow READ of size 4096" "library-api" "obeyed" "bytes" "5/5" "CL-x (singleton)")
_CURRENT_TEST="class: heap READ ≥16 (info-disclosure shaped)"
read level score key surface rating vector <<< "$(get_severity "$dir")"
assert_eq "heap_read_big" "$key" "heap_read_big detected"

dir=$(make_crash "demo_heapr_small" CRASH-HEAPR-SMALL \
  "heap-buffer-overflow READ of size 1" "library-api" "obeyed" "bytes" "5/5" "CL-x (singleton)")
_CURRENT_TEST="class: 1-byte heap READ"
read level score key surface rating vector <<< "$(get_severity "$dir")"
assert_eq "heap_read_small" "$key" "heap_read_small detected"

# libc copy-overlap family (strcpy/memcpy-param-overlap): a WRITE into the copy
# destination. ASan prints no "WRITE of size N" line for these, so without a
# dedicated branch the direction heuristic defaults the overflow to the READ
# tier and under-scores a write-class corruption as a disclosure (High → Low).
# Fixtures write a real sanitizer.txt (severity appends it) so the match is
# anchored to the canonical ==N==ERROR:/SUMMARY: line, not report prose. A
# stack-region marker routes this one to stack_write.
dir=$(make_crash "demo_overlap_stack" CRASH-OVERLAP-STACK \
  "copy-overlap crash" "cli" "obeyed" "bytes" "5/5" "CL-x (singleton)")
cat > "$dir/sanitizer.txt" <<'EOF'
==1==ERROR: AddressSanitizer: strcpy-param-overlap: memory ranges [0x10,0x41) and [0x30, 0x61) overlap
Address 0x10 is located in stack of thread T0 at offset 32 in frame
EOF
_CURRENT_TEST="class: strcpy-param-overlap (stack) → stack_write, not read tier"
read level score key surface rating vector <<< "$(get_severity "$dir")"
assert_eq "stack_write" "$key" "strcpy-param-overlap classifies as a stack WRITE"
assert_eq "High" "$rating" "copy-overlap stack WRITE scores High, not Low"

# A SUMMARY-line diagnostic with no region marker defaults to the heap write
# class (all three write classes carry identical H/H/H impact; region only
# labels) — and proves the SUMMARY: anchor works, not just the ERROR: headline.
dir=$(make_crash "demo_overlap_heap" CRASH-OVERLAP-HEAP \
  "copy-overlap crash" "library-api" "obeyed" "bytes" "5/5" "CL-x (singleton)")
cat > "$dir/sanitizer.txt" <<'EOF'
SUMMARY: AddressSanitizer: memcpy-param-overlap app.c:42 in app_copy
EOF
_CURRENT_TEST="class: memcpy-param-overlap (SUMMARY, no region) → heap_write"
read level score key surface rating vector <<< "$(get_severity "$dir")"
assert_eq "heap_write" "$key" "memcpy-param-overlap defaults to heap WRITE"

# A comparison-function overlap is a READ, not a copy write. ASan never emits
# one (only copy/concat interceptors check overlap), but the write branch must
# not blindly claim any `*-param-overlap` token: a name ending in `cmp` must
# NOT classify as a write. It carries no other class, so it stays unclassified.
dir=$(make_crash "demo_overlap_cmp" CRASH-OVERLAP-CMP \
  "copy-overlap crash" "library-api" "obeyed" "bytes" "5/5" "CL-x (singleton)")
cat > "$dir/sanitizer.txt" <<'EOF'
==1==ERROR: AddressSanitizer: strcmp-param-overlap: memory ranges [0x10,0x41) and [0x30, 0x61) overlap
Address 0x10 is located in stack of thread T0 at offset 32 in frame
EOF
_CURRENT_TEST="class: strcmp-param-overlap must NOT be a write"
read level score key surface rating vector <<< "$(get_severity "$dir")"
assert_eq "unknown" "$key" "a comparison overlap (cmp) is not classified as a copy write"

# Prose that only *quotes* the token while ruling it out — even with the exact
# `AddressSanitizer:` prefix — must not mint a write primitive. The branch is
# anchored to the canonical ==N==ERROR:/SUMMARY: line shape, not the substring,
# so a FIND/triage report that references the token in prose stays unclassified.
dir=$(make_crash "demo_overlap_prose" CRASH-OVERLAP-PROSE \
  "No AddressSanitizer: strcpy-param-overlap was observed; open-redirect lead only" \
  "library-api" "obeyed" "bytes" "5/5" "CL-x (singleton)")
_CURRENT_TEST="class: negated prefixed prose strcpy-param-overlap does not classify as write"
read level score key surface rating vector <<< "$(get_severity "$dir")"
assert_neq "heap_write" "$key" "prose-only overlap mention is not an authoritative write"
assert_neq "stack_write" "$key" "prose-only overlap mention is not an authoritative write"

dir=$(make_crash "demo_bus" CRASH-BUS \
  "BUS error" "cli" "obeyed" "bytes" "5/5" "CL-x (singleton)")
_CURRENT_TEST="class: BUS (DoS-only)"
read level score key surface rating vector <<< "$(get_severity "$dir")"
assert_eq "bus" "$key" "bus detected"

# ASan hyphenated stack-overflow is recursion exhaustion, not a buffer overflow.
dir=$(make_crash "demo_stackexh" CRASH-STACKEXH \
  "AddressSanitizer: stack-overflow on address 0x7ffd4232fff8" \
  "library-api" "obeyed" "bytes" "5/5" "CL-x (singleton)")
_CURRENT_TEST="class: ASan stack-overflow → stack_exhaustion"
read level score key surface rating vector <<< "$(get_severity "$dir")"
assert_eq "stack_exhaustion" "$key" "stack_exhaustion detected"

# LeakSanitizer leaks are resource DoS, not data disclosure.
dir=$(make_crash "demo_lsan" CRASH-LSAN \
  "LeakSanitizer: detected memory leaks — Direct leak of 128 byte(s)" \
  "library-api" "obeyed" "bytes" "5/5" "CL-x (singleton)")
_CURRENT_TEST="class: LeakSanitizer → memory_leak (not info_leak)"
read level score key surface rating vector <<< "$(get_severity "$dir")"
assert_eq "memory_leak" "$key" "memory_leak detected"

# SEGV discrimination by faulting address.
dir=$(make_crash "demo_segv_null" CRASH-SEGV-NULL \
  "SEGV on unknown address 0x000000000018" \
  "library-api" "obeyed" "bytes" "5/5" "CL-x (singleton)")
_CURRENT_TEST="class: near-null SEGV → null_deref"
read level score key surface rating vector <<< "$(get_severity "$dir")"
assert_eq "null_deref" "$key" "near-null SEGV is null_deref"

dir=$(make_crash "demo_segv_wildr" CRASH-SEGV-WILDR \
  "SEGV on unknown address 0x612000000040 — The signal is caused by a READ memory access" \
  "library-api" "obeyed" "bytes" "5/5" "CL-x (singleton)")
_CURRENT_TEST="class: wild-address SEGV READ → wild_read"
read level score key surface rating vector <<< "$(get_severity "$dir")"
assert_eq "wild_read" "$key" "wild_read detected"

dir=$(make_crash "demo_segv_wildw" CRASH-SEGV-WILDW \
  "SEGV on unknown address 0x612000000040 — The signal is caused by a WRITE memory access" \
  "library-api" "obeyed" "bytes" "5/5" "CL-x (singleton)")
_CURRENT_TEST="class: wild-address SEGV WRITE → wild_write"
read level score key surface rating vector <<< "$(get_severity "$dir")"
assert_eq "wild_write" "$key" "wild_write detected"

# SIGBUS authority: a bus error whose faulting frame is a libc memmove logs a
# "WRITE of size N" line and a SCARINESS wild-addr-write tag, but the headline
# is BUS. The sanitizer class must win → bus (N,N,H), not wild_write (H,H,H).
dir=$(make_crash "demo_bus_summary" CRASH-BUS-SUMMARY \
  "ERROR: AddressSanitizer: BUS on unknown address; WRITE of size 8; SCARINESS: 10 (wild-addr-write)" \
  "library-api" "obeyed" "bytes" "5/5" "CL-x (singleton)")
_CURRENT_TEST="class: ASan BUS headline beats stray WRITE/wild-addr → bus"
read level score key surface rating vector <<< "$(get_severity "$dir")"
assert_eq "bus" "$key" "BUS headline classifies as bus despite a stray WRITE frame"

# Near-null SEGV with a stray "READ of size N" frame must stay null_deref
# (N,N,H), not be down-routed to a heap read (L,N,L) by the direction fallback.
dir=$(make_crash "demo_segv_null_strayread" CRASH-SEGV-NULL-READ \
  "SEGV on unknown address 0x000000000000; READ of size 8 in frame" \
  "library-api" "obeyed" "bytes" "5/5" "CL-x (singleton)")
_CURRENT_TEST="class: near-null SEGV + stray READ → null_deref"
read level score key surface rating vector <<< "$(get_severity "$dir")"
assert_eq "null_deref" "$key" "near-null SEGV stays null_deref despite a stray READ-of-size line"

dir=$(make_crash "demo_race" CRASH-RACE \
  "WARNING: ThreadSanitizer: data race (pid=123)" \
  "library-api" "obeyed" "bytes" "5/5" "CL-x (singleton)")
_CURRENT_TEST="class: TSan data race → data_race"
read level score key surface rating vector <<< "$(get_severity "$dir")"
assert_eq "data_race" "$key" "data_race detected"

dir=$(make_crash "demo_intovf" CRASH-INTOVF \
  "x.c:12:5: runtime error: signed integer overflow: 2147483647 + 1 cannot be represented" \
  "library-api" "obeyed" "bytes" "5/5" "CL-x (singleton)")
_CURRENT_TEST="class: UBSan signed integer overflow → integer_overflow"
read level score key surface rating vector <<< "$(get_severity "$dir")"
assert_eq "integer_overflow" "$key" "integer_overflow detected"

dir=$(make_crash "demo_invfree" CRASH-INVFREE \
  "attempting free on address which was not malloc()-ed" \
  "library-api" "obeyed" "bytes" "5/5" "CL-x (singleton)")
_CURRENT_TEST="class: invalid free → double_free family"
read level score key surface rating vector <<< "$(get_severity "$dir")"
assert_eq "double_free" "$key" "invalid free maps to double_free"

# Type confusion (CWE-843): ClusterFuzz Bad-cast / CFI / UBSan vptr.
dir=$(make_crash "demo_badcast" CRASH-BADCAST \
  "AddressSanitizer: Bad-cast to app::Node from app::Leaf" \
  "library-api" "obeyed" "bytes" "5/5" "CL-x (singleton)")
_CURRENT_TEST="class: Bad-cast → type_confusion"
read level score key surface rating vector <<< "$(get_severity "$dir")"
assert_eq "type_confusion" "$key" "type_confusion detected from Bad-cast"

dir=$(make_crash "demo_vptr" CRASH-VPTR \
  "x.cc:10:5: runtime error: member access within address 0x60b000000040 which does not point to an object — invalid vptr" \
  "library-api" "obeyed" "bytes" "5/5" "CL-x (singleton)")
_CURRENT_TEST="class: UBSan vptr → type_confusion"
read level score key surface rating vector <<< "$(get_severity "$dir")"
assert_eq "type_confusion" "$key" "vptr maps to type_confusion"

# MSan use-of-uninitialized-value — diagnostic token wins over prose web mention.
dir=$(make_crash "demo_msan" CRASH-MSAN \
  "WARNING: MemorySanitizer: use-of-uninitialized-value — unrelated note: the SSRF audit is tracked separately" \
  "library-api" "obeyed" "bytes" "5/5" "CL-x (singleton)")
_CURRENT_TEST="class: MSan token → info_leak (wins over prose web mention)"
read level score key surface rating vector <<< "$(get_severity "$dir")"
assert_eq "info_leak" "$key" "MSan token classifies as info_leak"

# Bare tool-name mention is triage prose, not a diagnostic.
dir=$(make_crash "demo_msan_neg" CRASH-MSAN-NEG \
  "SEGV on unknown address 0x000000000018; no MemorySanitizer diagnostic was produced and the KMSAN build is unavailable" \
  "library-api" "obeyed" "bytes" "5/5" "CL-x (singleton)")
_CURRENT_TEST="class: bare MSan/KMSAN tool mention does NOT classify as info_leak"
read level score key surface rating vector <<< "$(get_severity "$dir")"
assert_eq "null_deref" "$key" "tool-name prose ignored; SEGV classifies"

# Quoted ../../ input bytes are not path traversal.
dir=$(make_crash "demo_dotdot" CRASH-DOTDOT \
  "SEGV with testcase bytes ../../etc/passwd quoted from the corpus" \
  "library-api" "obeyed" "bytes" "5/5" "CL-x (singleton)")
_CURRENT_TEST="class: quoted ../../ input is not path_traversal"
read level score key surface rating vector <<< "$(get_severity "$dir")"
assert_eq "null_deref" "$key" "SEGV wins; ../../ alone is not traversal"

# ── Web/application classes ──
dir=$(make_crash "demo_openred" CRASH-OPENRED \
  "open redirect via startsWith prefix check on referrer parameter" \
  "library-api" "obeyed" "bytes" "5/5" "CL-x (singleton)")
_CURRENT_TEST="class: open redirect"
read level score key surface rating vector <<< "$(get_severity "$dir")"
assert_eq "open_redirect" "$key" "open_redirect detected"

dir=$(make_crash "demo_ssrf" CRASH-SSRF \
  "server-side request forgery via unvalidated callback URL" \
  "library-api" "obeyed" "bytes" "5/5" "CL-x (singleton)")
_CURRENT_TEST="class: SSRF"
read level score key surface rating vector <<< "$(get_severity "$dir")"
assert_eq "ssrf" "$key" "ssrf detected"

dir=$(make_crash "demo_sqli" CRASH-SQLI \
  "SQL injection in users.id query parameter — concatenated into raw SQL" \
  "library-api" "obeyed" "bytes" "5/5" "CL-x (singleton)")
_CURRENT_TEST="class: SQLi"
read level score key surface rating vector <<< "$(get_severity "$dir")"
assert_eq "sqli" "$key" "sqli detected"

dir=$(make_crash "demo_cmdinj" CRASH-CMDINJ \
  "command injection — user input passed to shell exec without escaping" \
  "library-api" "obeyed" "bytes" "5/5" "CL-x (singleton)")
_CURRENT_TEST="class: command injection (mechanism 'without' keeps class)"
read level score key surface rating vector <<< "$(get_severity "$dir")"
assert_eq "command_injection" "$key" "command_injection detected"

dir=$(make_crash "demo_xss" CRASH-XSS \
  "stored XSS in profile bio rendered without escape" \
  "library-api" "obeyed" "bytes" "5/5" "CL-x (singleton)")
_CURRENT_TEST="class: XSS"
read level score key surface rating vector <<< "$(get_severity "$dir")"
assert_eq "xss" "$key" "xss detected"

# Memory-safety wins over an incidental web-vuln mention.
dir=$(make_crash "demo_priority" CRASH-PRIORITY \
  "heap-buffer-overflow WRITE of size 8 — see SSRF discussion below" \
  "library-api" "obeyed" "bytes" "5/5" "CL-x (singleton)")
_CURRENT_TEST="class: memory-safety wins over web-vuln narrative"
read level score key surface rating vector <<< "$(get_severity "$dir")"
assert_eq "heap_write" "$key" "heap_write wins (ASan is precise)"

# ── Negation guard ──
dir=$(make_crash "demo_negated" CRASH-NEGATED \
  "Reviewed the session layer; no SQL injection or authentication bypass was observed, and this rules out cache poisoning" \
  "library-api" "obeyed" "bytes" "5/5" "CL-x (singleton)")
_CURRENT_TEST="negation: negated web-vuln mentions do not classify"
read level score key surface rating vector <<< "$(get_severity "$dir")"
assert_eq "unknown" "$key" "negated mentions fall through to unknown"

dir=$(make_crash "demo_negpos" CRASH-NEGPOS \
  "input is not sanitized, leading to SQL injection in the id parameter" \
  "library-api" "obeyed" "bytes" "5/5" "CL-x (singleton)")
_CURRENT_TEST="negation: comma-clause negation does not suppress a real finding"
read level score key surface rating vector <<< "$(get_severity "$dir")"
assert_eq "sqli" "$key" "sqli still detected past unrelated 'not' clause"

dir=$(make_crash "demo_negpost" CRASH-NEGPOST \
  "We checked carefully: SQL injection is not possible and cache poisoning was ruled out" \
  "library-api" "obeyed" "bytes" "5/5" "CL-x (singleton)")
_CURRENT_TEST="negation: post-phrase ('is not possible'/'ruled out') suppresses"
read level score key surface rating vector <<< "$(get_severity "$dir")"
assert_eq "unknown" "$key" "trailing negation suppresses the class"

dir=$(make_crash "demo_colon" CRASH-COLON \
  "Assessment — SQL injection: not possible. SSRF: ruled out after review" \
  "library-api" "obeyed" "bytes" "5/5" "CL-x (singleton)")
_CURRENT_TEST="negation: colon-introduced denial ('X: not possible') suppresses"
read level score key surface rating vector <<< "$(get_severity "$dir")"
assert_eq "unknown" "$key" "colon-introduced negation suppresses the class"

dir=$(make_crash "demo_prevent" CRASH-PREVENT \
  "the tagged-union check prevents type confusion; parameterized queries mitigate SQL injection and the loader is hardened against XXE" \
  "library-api" "obeyed" "bytes" "5/5" "CL-x (singleton)")
_CURRENT_TEST="negation: prevention/mitigation wording does not mint a class"
read level score key surface rating vector <<< "$(get_severity "$dir")"
assert_eq "unknown" "$key" "prevention prose suppressed for all classes"

# Prose-only type confusion stays in the conservative small-read tier.
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

dir=$(make_crash "demo_negfield" CRASH-NEGFIELD \
  "no SQL injection was directly observed in the harness run" \
  "library-api" "obeyed" "bytes" "5/5" "CL-x (singleton)")
echo "Primitive: sqli" >> "$dir/report.md"
_CURRENT_TEST="field: structured Primitive wins when narrative is negated"
read level score key surface rating vector <<< "$(get_severity "$dir")"
assert_eq "sqli" "$key" "Primitive field adopted after negation fallthrough"

dir=$(make_crash "demo_fieldwin" CRASH-FIELDWIN \
  "open redirect via startsWith on the referrer parameter" \
  "library-api" "obeyed" "bytes" "5/5" "CL-x (singleton)")
echo "Primitive: sqli" >> "$dir/report.md"
_CURRENT_TEST="field: structured field outranks prose-regex narrative class"
read level score key surface rating vector <<< "$(get_severity "$dir")"
assert_eq "sqli" "$key" "structured sqli beats narrative open_redirect"

dir=$(make_crash "demo_fieldnosan" CRASH-FIELDNOSAN \
  "heap-use-after-free WRITE of size 8" \
  "library-api" "obeyed" "bytes" "5/5" "CL-x (singleton)")
echo "Primitive: open_redirect" >> "$dir/report.md"
_CURRENT_TEST="field: sanitizer-class match is NOT overridden by structured field"
read level score key surface rating vector <<< "$(get_severity "$dir")"
assert_eq "uaf_write" "$key" "sanitizer uaf_write beats structured open_redirect"

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
dir=$(make_crash "demo_lib" CRASH-LIB \
  "heap-buffer-overflow READ of size 1" "library-api" "obeyed" "bytes" "5/5" "CL-x (singleton)")
_CURRENT_TEST="derive: library surface → AV:N/UI:N"
read level score key surface rating vector <<< "$(get_severity "$dir")"
assert_eq "N" "$(metric "$vector" AV)" "AV:N for library"
assert_eq "N" "$(metric "$vector" UI)" "UI:N for library (worst-case embedding)"

# Production CLI → AV:L.
dir=$(make_crash "demo_cli" CRASH-CLI \
  "heap-buffer-overflow READ of size 1" "cli — shipped tool" "obeyed" "bytes" "5/5" "CL-x (singleton)")
_CURRENT_TEST="derive: production CLI → AV:L"
read level score key surface rating vector <<< "$(get_severity "$dir")"
assert_eq "cli_production" "$surface" "cli_production classified"
assert_eq "L" "$(metric "$vector" AV)" "AV:L for CLI"

# Obeyed contract leaves AT:N/MAT:X; violated contract derives MAT:P.
dir=$(make_crash "demo_at_obeyed" CRASH-AT-OBEYED \
  "heap-buffer-overflow WRITE of size 8" "library-api" "obeyed" "bytes" "5/5" "CL-x (singleton)")
_CURRENT_TEST="derive: obeyed contract → AT:N"
read level score key surface rating vector <<< "$(get_severity "$dir")"
assert_eq "N" "$(metric "$vector" AT)" "AT:N for obeyed contract"

dir=$(make_crash "demo_at_violated" CRASH-AT-VIOLATED \
  "heap-buffer-overflow WRITE of size 8" "library-api" "violated" "bytes" "5/5" "CL-x (singleton)")
_CURRENT_TEST="derive: violated contract → MAT:P"
read level score key surface rating vector <<< "$(get_severity "$dir")"
assert_eq "N" "$(metric "$vector" AT)" "base AT remains intrinsic"
assert_eq "P" "$(metric "$vector" MAT)" "MAT:P for violated contract"

# A Contract concern annotation alone is not severity input. MAT:P is derived
# from structured fields (violated contract, harness-only parameter, or
# trigger_source outside target.toml attacker_controls), not from stale prose.
dir=$(make_crash "demo_at_concern" CRASH-AT-CONCERN \
  "heap-buffer-overflow WRITE of size 8" "library-api" "unspecified" "bytes" "5/5" "CL-x (singleton)")
cat >> "$dir/report.md" <<'EOF'

## Contract concern

Triage flagged a contract concern: trigger shape outside the declared input boundary.
EOF
_CURRENT_TEST="derive: Contract concern section alone does not alter MAT"
read level score key surface rating vector <<< "$(get_severity "$dir")"
assert_eq "N" "$(metric "$vector" AT)" "base AT remains intrinsic"
assert_eq "" "$(metric "$vector" MAT)" "no MAT:P from annotation prose alone"

# Caller controls narrower than arbitrary bytes also derive MAT:P.
dir=$(make_crash "demo_mat_number" CRASH-MAT-NUMBER \
  "heap-buffer-overflow WRITE of size 8" "library-api" "obeyed" "number" "5/5" "CL-x (singleton)")
_CURRENT_TEST="derive: limited caller controls → MAT:P"
read level score key surface rating vector <<< "$(get_severity "$dir")"
assert_eq "P" "$(metric "$vector" MAT)" "MAT:P for limited caller-controlled shape"

# Indirect/trusted parameter control is a local environmental precondition,
# even when the trigger payload itself is attacker-shaped bytes.
dir=$(make_crash "demo_mat_param" CRASH-MAT-PARAM \
  "heap-buffer-overflow WRITE of size 8" "library-api" "obeyed" "bytes" "5/5" "CL-x (singleton)")
echo "Parameter control: application-supplied" >> "$dir/report.md"
_CURRENT_TEST="derive: application-supplied parameter → MAT:P"
read level score key surface rating vector <<< "$(get_severity "$dir")"
assert_eq "P" "$(metric "$vector" MAT)" "MAT:P for application-supplied parameter"

# Private/internal trusted actions are likewise local environmental
# preconditions; normal public calls are handled by the caller_controls field.
dir=$(make_crash "demo_mat_trusted" CRASH-MAT-TRUSTED \
  "heap-buffer-overflow WRITE of size 8" "library-api" "obeyed" "bytes" "5/5" "CL-x (singleton)")
echo "Trusted caller actions: private struct mutation" >> "$dir/report.md"
_CURRENT_TEST="derive: trusted private action → MAT:P"
read level score key surface rating vector <<< "$(get_severity "$dir")"
assert_eq "P" "$(metric "$vector" MAT)" "MAT:P for private trusted caller action"

# ── Attack Vector localisation: a library bug whose trigger is a trusted
# local API/call-sequence (no attacker byte path) is reached only by a local
# in-process caller → AV:L, and the required setup is an intrinsic AT:P. The
# surface worst-case AV:N embedding does not apply. This is the cJSON bad-free
# / DetachItemViaPointer shape: install hooks, reorder public calls, delete.
# Reachability is a hard gate, not a one-band nudge: with no attacker crossing
# a trust boundary, attacker-facing impact floors via MVC:N/MVI:N, so even a
# code-execution double_free lands Low (a local caller crashing its own
# process), NOT Medium. A genuine parse-the-bytes bug keeps AV:N and full
# impact (asserted by the byte-guard case just below).
dir=$(make_crash "demo_av_callseq" CRASH-AV-CALLSEQ \
  "attempting free on address which was not malloc()-ed" \
  "library-api" "unspecified" "call-sequence" "5/5" "CL-x (singleton)")
cat >> "$dir/report.md" <<'EOF'

## Contract concern

Triage flagged a contract concern: trigger requires [call-sequence] outside attacker_controls=[bytes].
EOF
_CURRENT_TEST="derive: local call-sequence trigger (no byte path) → AV:L/AT:P, impact floored"
read level score key surface rating vector <<< "$(get_severity "$dir")"
assert_eq "double_free" "$key" "bad-free classified as double_free"
assert_eq "L" "$(metric "$vector" AV)" "AV:L for local-only call-sequence trigger"
assert_eq "P" "$(metric "$vector" AT)" "AT:P intrinsic precondition for local call sequence"
assert_eq "N" "$(metric "$vector" MVC)" "MVC:N — caller-only reachable floors confidentiality"
assert_eq "N" "$(metric "$vector" MVI)" "MVI:N — caller-only reachable floors integrity"
assert_eq "Low" "$level" "caller-only double-free floors to Low (reachability is a hard gate, not a one-band nudge)"

# Byte-guard: the SAME contract concern over a crash the caller triggers with
# attacker-controlled BYTES keeps AV:N (an external boundary can reach it).
# The contract concern still yields Environmental MAT:P, but not localisation.
dir=$(make_crash "demo_av_bytesguard" CRASH-AV-BYTESGUARD \
  "attempting free on address which was not malloc()-ed" \
  "library-api" "unspecified" "bytes" "5/5" "CL-x (singleton)")
cat >> "$dir/report.md" <<'EOF'

## Contract concern

Triage flagged a contract concern: trigger shape outside the declared input boundary.
EOF
_CURRENT_TEST="derive: byte-controlled trigger keeps AV:N despite contract concern"
read level score key surface rating vector <<< "$(get_severity "$dir")"
assert_eq "N" "$(metric "$vector" AV)" "AV:N preserved when attacker controls bytes"
assert_eq "" "$(metric "$vector" MAT)" "no MAT:P from stale contract concern prose"
# Recall guard: the caller-only impact floor must NOT fire on a byte-reachable
# bug. No MVC override, and a genuine attacker-reachable double_free stays High.
assert_eq "" "$(metric "$vector" MVC)" "no MVC floor when attacker controls bytes"
assert_eq "High" "$level" "byte-reachable double_free keeps full impact (not floored)"

# Content-word guard: "JSON string" is an attacker-controlled content path even
# though it lacks the literal word "bytes". A call-sequence wrapper around
# caller-supplied content must NOT localise — the content reaches the primitive,
# so the surface AV:N (worst-case embedding) still applies.
dir=$(make_crash "demo_av_jsonstr" CRASH-AV-JSONSTR \
  "attempting free on address which was not malloc()-ed" \
  "library-api" "unspecified" "JSON string and public call sequence" "5/5" "CL-x (singleton)")
_CURRENT_TEST="derive: caller-controlled JSON string + call-sequence keeps AV:N"
read level score key surface rating vector <<< "$(get_severity "$dir")"
assert_eq "N" "$(metric "$vector" AV)" "AV:N — JSON string is an attacker content path"

# A STRUCTURED `call-sequence` trigger_source is authoritative: it localises
# (AV:L/AT:P) even when the free-prose caller_controls incidentally lists
# "subject bytes" — the re-entrancy/callback UAF shape (caller's own callout
# frees the live object). The bytes are present in the data flow but the call
# ordering is the proximate trigger. Regression for the codex pcre2 re-entrancy
# UAFs scored AV:N High instead of AV:L Medium.
dir=$(make_crash "demo_callseq_trigger" CRASH-CALLSEQ-TRIGGER \
  "heap-use-after-free WRITE of size 8" \
  "library-api" "unspecified" "subject bytes, match-context callback, callback data pointer" \
  "5/5" "CL-x (singleton)")
printf '\nTrigger source: call-sequence\n' >> "$dir/report.md"
_CURRENT_TEST="derive: structured call-sequence trigger localises despite byte prose"
read level score key surface rating vector <<< "$(get_severity "$dir")"
assert_eq "L" "$(metric "$vector" AV)" "AV:L — structured call-sequence trigger overrides incidental 'subject bytes' prose"
assert_eq "P" "$(metric "$vector" AT)" "AT:P for the localised call-sequence trigger"

# Scoring is structured-only: callback NARRATIVE, a generated `## Contract
# concern` section, and a `.contract-flagged` sidecar must NOT move severity.
# Only the structured trigger ∩ attacker_controls (localisation) and
# caller_contract/parameter_control (MAT:P) score. A byte-driven callback report
# whose trigger ⊆ the declared attacker_controls stays attacker-reachable (AV:N,
# High) no matter what the prose says — guarding against any prose-driven
# callback heuristic. Placeholder symbols only (see docs/development.md).
src=$(make_crash "demo_callback_prose_no_score" CRASH-CB-PROSE \
  "heap-use-after-free WRITE of size 4" \
  "library-api" "unspecified" "both" "5/5" "CL-x (singleton)")
mkdir -p "$TEST_TMPDIR/output/cbprose/backend/results/crashes" "$TEST_TMPDIR/output/cbprose"
cat > "$TEST_TMPDIR/output/cbprose/target.toml" <<'TOML'
[threat_model]
attacker_controls = ["bytes", "call-sequence"]
TOML
dir="$TEST_TMPDIR/output/cbprose/backend/results/crashes/CRASH-CB-PROSE"
cp -R "$src" "$dir"
printf '\nTrigger source: both\n' >> "$dir/report.md"
cat >> "$dir/report.md" <<'EOF'

## Bug

A public structured error callback frees the active parser context while the library is still using it.

## Contract concern

Triage kept this crash and flagged a contract concern: callback releases active target object.
EOF
cat > "$dir/.contract-flagged" <<'EOF'
# Contract-flagged by triage
# Reason: callback releases active target object
EOF
_CURRENT_TEST="structured-only: callback prose/annotation/sidecar do not change severity"
read level score key surface rating vector <<< "$(get_severity "$dir")"
assert_eq "N" "$(metric "$vector" AV)" "AV:N — trigger ⊆ attacker_controls; prose does not localise"
assert_eq "" "$(metric "$vector" MAT)" "no MAT:P — callback prose/annotation are not scoring inputs"
assert_eq "High" "$level" "byte-reachable callback UAF stays High; only structure scores"

# The structured de-rate path: a violated caller contract yields MAT:P (the same
# byte-reachable crash, environmentally de-rated) — this is how a caller-contract
# concern is represented, not via callback narrative.
dir=$(make_crash "demo_caller_contract_violated" CRASH-CC-VIOLATED \
  "heap-use-after-free WRITE of size 4" \
  "library-api" "violated" "both" "5/5" "CL-x (singleton)")
printf '\nTrigger source: both\n' >> "$dir/report.md"
_CURRENT_TEST="structured: caller_contract=violated derives MAT:P"
read level score key surface rating vector <<< "$(get_severity "$dir")"
assert_eq "P" "$(metric "$vector" MAT)" "MAT:P from structured Caller contract: violated"

# Active target.toml beats stale report prose. A benchmark pool may carry an
# older Contract concern line saying call-sequence was outside
# attacker_controls=[bytes]. If the current target model declares both bytes and
# call-sequence attacker-controlled, rescoring must not localise.
src=$(make_crash "demo_stale_oob_allowed" CRASH-STALE-OOB-ALLOWED \
  "attempting free on address which was not malloc()-ed" \
  "library-api" "unspecified" "both" "5/5" "CL-x (singleton)")
mkdir -p "$TEST_TMPDIR/output/allowed/backend/results/crashes" "$TEST_TMPDIR/output/allowed"
cat > "$TEST_TMPDIR/output/allowed/target.toml" <<'TOML'
[threat_model]
attacker_controls = ["bytes", "call-sequence"]
TOML
dir="$TEST_TMPDIR/output/allowed/backend/results/crashes/CRASH-STALE-OOB-ALLOWED"
cp -R "$src" "$dir"
printf '\nTrigger source: both\n' >> "$dir/report.md"
cat >> "$dir/report.md" <<'EOF'

## Contract concern

Triage flagged a contract concern: trigger requires [call-sequence] outside attacker_controls=[bytes].
EOF
_CURRENT_TEST="recall: current target.toml prevents stale call-sequence localisation"
read level score key surface rating vector <<< "$(get_severity "$dir")"
assert_eq "N" "$(metric "$vector" AV)" "AV:N — active attacker_controls include call-sequence"
assert_eq "" "$(metric "$vector" MVC)" "no MVC floor when active model makes trigger attacker-controlled"
assert_eq "High" "$level" "stale report prose does not push attacker-reachable crash down"

# Conversely, when the active target model controls only bytes, Trigger source:
# both leaves call-sequence outside attacker control and the local-only gate
# applies. This is the same structured rule as lib/triage.py, not a callback
# reason heuristic.
src=$(make_crash "demo_current_oob_local" CRASH-CURRENT-OOB-LOCAL \
  "attempting free on address which was not malloc()-ed" \
  "library-api" "unspecified" "both" "5/5" "CL-x (singleton)")
mkdir -p "$TEST_TMPDIR/output/localonly/backend/results/crashes" "$TEST_TMPDIR/output/localonly"
cat > "$TEST_TMPDIR/output/localonly/target.toml" <<'TOML'
[threat_model]
attacker_controls = ["bytes"]
TOML
dir="$TEST_TMPDIR/output/localonly/backend/results/crashes/CRASH-CURRENT-OOB-LOCAL"
cp -R "$src" "$dir"
printf '\nTrigger source: both\n' >> "$dir/report.md"
_CURRENT_TEST="derive: current target.toml localises call-sequence outside attacker_controls"
read level score key surface rating vector <<< "$(get_severity "$dir")"
assert_eq "L" "$(metric "$vector" AV)" "AV:L — call-sequence is outside active attacker_controls"
assert_eq "P" "$(metric "$vector" AT)" "AT:P for active call-sequence precondition"
assert_eq "Low" "$level" "current structured model still floors local-only trigger"

# Fix #5: with no discoverable target.toml, scoring defaults to attacker_controls
# {bytes}, so a
# `Trigger source: both` still derives the call-sequence set-difference and
# localises — instead of silently scoring as if nothing were out of bounds.
dir=$(make_crash "demo_default_bytes_oob" CRASH-DEFAULT-BYTES \
  "attempting free on address which was not malloc()-ed" \
  "library-api" "unspecified" "both" "5/5" "CL-x (singleton)")
printf '\nTrigger source: both\n' >> "$dir/report.md"
_CURRENT_TEST="derive: no target.toml defaults to {bytes}, so call-sequence localises"
read level score key surface rating vector <<< "$(get_severity "$dir")"
assert_eq "L" "$(metric "$vector" AV)" "AV:L — default {bytes} leaves call-sequence outside"
assert_eq "P" "$(metric "$vector" AT)" "AT:P from the defaulted set-difference"

# Fix #4: the Python trigger parser accepts the same aliases as shell
# parse_trigger_source. `sequence` canonicalises to call-sequence, so with a
# bytes-only model it localises just like the literal token would.
src=$(make_crash "demo_trigger_alias" CRASH-TRIGGER-ALIAS \
  "attempting free on address which was not malloc()-ed" \
  "library-api" "unspecified" "sequence" "5/5" "CL-x (singleton)")
mkdir -p "$TEST_TMPDIR/output/aliasmodel/backend/results/crashes" "$TEST_TMPDIR/output/aliasmodel"
cat > "$TEST_TMPDIR/output/aliasmodel/target.toml" <<'TOML'
[threat_model]
attacker_controls = ["bytes"]
TOML
dir="$TEST_TMPDIR/output/aliasmodel/backend/results/crashes/CRASH-TRIGGER-ALIAS"
cp -R "$src" "$dir"
printf '\nTrigger source: sequence\n' >> "$dir/report.md"
_CURRENT_TEST="derive: trigger alias 'sequence' canonicalises to call-sequence and localises"
read level score key surface rating vector <<< "$(get_severity "$dir")"
assert_eq "L" "$(metric "$vector" AV)" "AV:L — 'sequence' alias treated as call-sequence, outside {bytes}"

# ── Caller-only IMPACT FLOOR scope (codex review #2): EVERY _local_caller_only
# path floors attacker-facing C/I, not just the explicit call-sequence case.
# Each path is paired with a byte-veto case proving a genuine attacker-reachable
# bug is NOT floored (the recall guard).

# (a) application-supplied parameter → AV:L → C/I floored → Low.
dir=$(make_crash "demo_floor_param" CRASH-FLOOR-PARAM \
  "heap-use-after-free WRITE of size 8" \
  "library-api" "unspecified" "application configuration parameter" "5/5" "CL-x (singleton)")
echo "Parameter control: application-supplied" >> "$dir/report.md"
_CURRENT_TEST="floor: application-supplied parameter floors C/I → Low"
read level score key surface rating vector <<< "$(get_severity "$dir")"
assert_eq "L" "$(metric "$vector" AV)" "AV:L for application-supplied parameter"
assert_eq "N" "$(metric "$vector" MVC)" "MVC:N — application-supplied parameter floors confidentiality"
assert_eq "Low" "$level" "application-supplied caller-only UAF floors to Low"

# (a-veto) same report but attacker controls bytes → NOT floored, stays High.
dir=$(make_crash "demo_floor_param_bytes" CRASH-FLOOR-PARAM-BYTES \
  "heap-use-after-free WRITE of size 8" \
  "library-api" "unspecified" "input bytes" "5/5" "CL-x (singleton)")
echo "Parameter control: application-supplied" >> "$dir/report.md"
_CURRENT_TEST="floor: byte path vetoes the application-supplied floor"
read level score key surface rating vector <<< "$(get_severity "$dir")"
assert_eq "" "$(metric "$vector" MVC)" "no MVC floor when attacker controls bytes (param path)"
assert_eq "High" "$level" "byte-reachable UAF keeps full impact (param path)"

# (b) trusted private action → AV:L → C/I floored → Low.
dir=$(make_crash "demo_floor_trusted" CRASH-FLOOR-TRUSTED \
  "heap-use-after-free WRITE of size 8" \
  "library-api" "unspecified" "private internal state" "5/5" "CL-x (singleton)")
echo "Trusted caller actions: private struct mutation" >> "$dir/report.md"
_CURRENT_TEST="floor: trusted private action floors C/I → Low"
read level score key surface rating vector <<< "$(get_severity "$dir")"
assert_eq "L" "$(metric "$vector" AV)" "AV:L for trusted private action"
assert_eq "N" "$(metric "$vector" MVC)" "MVC:N — trusted private action floors confidentiality"
assert_eq "Low" "$level" "trusted-action caller-only UAF floors to Low"

# (b-veto) trusted action but attacker controls bytes → NOT floored.
dir=$(make_crash "demo_floor_trusted_bytes" CRASH-FLOOR-TRUSTED-BYTES \
  "heap-use-after-free WRITE of size 8" \
  "library-api" "unspecified" "input bytes" "5/5" "CL-x (singleton)")
echo "Trusted caller actions: private struct mutation" >> "$dir/report.md"
_CURRENT_TEST="floor: byte path vetoes the trusted-action floor"
read level score key surface rating vector <<< "$(get_severity "$dir")"
assert_eq "" "$(metric "$vector" MVC)" "no MVC floor when attacker controls bytes (trusted path)"
assert_eq "High" "$level" "byte-reachable UAF keeps full impact (trusted path)"

# (c) Subsequent-system impact (ssrf, SC:L) must ALSO floor when caller-only,
# else "no attacker crosses a trust boundary" contradicts a scored SC. Regression
# for codex review #1 (floor both systems' C/I, not only VC/VI).
dir=$(make_crash "demo_floor_ssrf" CRASH-FLOOR-SSRF \
  "server-side request forgery via unvalidated callback URL" \
  "library-api" "unspecified" "public call sequence" "5/5" "CL-x (singleton)")
printf '\nTrigger source: call-sequence\n' >> "$dir/report.md"
_CURRENT_TEST="floor: caller-only ssrf floors subsequent-system confidentiality"
read level score key surface rating vector <<< "$(get_severity "$dir")"
assert_eq "ssrf" "$key" "ssrf classified"
assert_eq "L" "$(metric "$vector" AV)" "AV:L for caller-only ssrf"
assert_eq "N" "$(metric "$vector" MSC)" "MSC:N — caller-only floors subsequent confidentiality (not just VC/VI)"
# Lock the resulting band: with no attacker crossing the boundary, a caller-only
# subsequent-impact class collapses to None (0.0) — a material M+ count change,
# pinned here so it can't drift silently.
assert_eq "None" "$level" "caller-only ssrf → None (no attacker crosses a trust boundary)"

# (c-veto) byte-reachable ssrf: attacker controls the URL bytes → NOT floored,
# stays a scored Medium. Proves the subsequent-impact floor never under-rates a
# genuinely attacker-reachable web bug.
dir=$(make_crash "demo_ssrf_bytes" CRASH-SSRF-BYTES \
  "server-side request forgery via unvalidated callback URL" \
  "library-api" "obeyed" "bytes" "5/5" "CL-x (singleton)")
_CURRENT_TEST="floor: byte-reachable ssrf is not floored"
read level score key surface rating vector <<< "$(get_severity "$dir")"
assert_eq "ssrf" "$key" "ssrf classified (byte path)"
assert_eq "" "$(metric "$vector" MSC)" "no MSC floor when attacker controls bytes (ssrf)"
assert_eq "Medium" "$level" "byte-reachable ssrf keeps its scored Medium band"

# (d) caller-only xss carries BOTH SC and SI → both must floor (MSC:N/MSI:N).
dir=$(make_crash "demo_floor_xss" CRASH-FLOOR-XSS \
  "stored XSS in profile bio rendered without escape" \
  "library-api" "unspecified" "public call sequence" "5/5" "CL-x (singleton)")
printf '\nTrigger source: call-sequence\n' >> "$dir/report.md"
_CURRENT_TEST="floor: caller-only xss floors both subsequent C and I"
read level score key surface rating vector <<< "$(get_severity "$dir")"
assert_eq "xss" "$key" "xss classified"
assert_eq "N" "$(metric "$vector" MSC)" "MSC:N — caller-only floors subsequent confidentiality (xss)"
assert_eq "N" "$(metric "$vector" MSI)" "MSI:N — caller-only floors subsequent integrity (xss)"
assert_eq "None" "$level" "caller-only xss → None"

# (d-veto) byte-reachable xss → NOT floored, stays scored Medium.
dir=$(make_crash "demo_xss_bytes" CRASH-XSS-BYTES \
  "stored XSS in profile bio rendered without escape" \
  "library-api" "obeyed" "bytes" "5/5" "CL-x (singleton)")
_CURRENT_TEST="floor: byte-reachable xss is not floored"
read level score key surface rating vector <<< "$(get_severity "$dir")"
assert_eq "xss" "$key" "xss classified (byte path)"
assert_eq "" "$(metric "$vector" MSC)" "no MSC floor when attacker controls bytes (xss)"
assert_eq "Medium" "$level" "byte-reachable xss keeps its scored Medium band"

# Guard: a genuine parse-the-bytes crash carries trigger_source=bytes and must
# NOT be localised even with the identical caller_controls prose → AV:N.
dir=$(make_crash "demo_bytes_trigger" CRASH-BYTES-TRIGGER \
  "heap-use-after-free WRITE of size 8" \
  "library-api" "unspecified" "subject bytes, match-context callback, callback data pointer" \
  "5/5" "CL-x (singleton)")
printf '\nTrigger source: bytes\n' >> "$dir/report.md"
_CURRENT_TEST="derive: trigger_source=bytes keeps AV:N (no localisation)"
read level score key surface rating vector <<< "$(get_severity "$dir")"
assert_eq "N" "$(metric "$vector" AV)" "AV:N — trigger_source=bytes is a real attacker-byte path, not localised"

# Free-prose call-sequence phrasing must localise the same as the literal
# token: "the sequence of public API calls" (no byte path) is a trusted local
# call-ordering trigger → AV:L/AT:P. Regression for a real cJSON UAF whose
# caller-controls prose avoided the exact word "call-sequence".
dir=$(make_crash "demo_av_seqprose" CRASH-AV-SEQPROSE \
  "heap-use-after-free WRITE of size 8" "library-api" "unspecified" \
  "the sequence of public API calls and which (parent, item) pairing" "5/5" "CL-x (singleton)")
_CURRENT_TEST="derive: free-prose 'sequence of public API calls' localises to AV:L"
read level score key surface rating vector <<< "$(get_severity "$dir")"
assert_eq "L" "$(metric "$vector" AV)" "AV:L for prose call-sequence phrasing"
assert_eq "P" "$(metric "$vector" AT)" "AT:P for prose call-sequence phrasing"

# The structured Trigger source field carries the call-sequence signal even when
# caller-controls prose is vague. trigger_source=call-sequence (no byte path) →
# AV:L. (A byte path in any field would still veto via the content guard.)
dir=$(make_crash "demo_av_trigseq" CRASH-AV-TRIGSEQ \
  "attempting free on address which was not malloc()-ed" "library-api" "unspecified" \
  "which (parent, item) pairing is used" "5/5" "CL-x (singleton)")
echo "Trigger source: call-sequence" >> "$dir/report.md"
_CURRENT_TEST="derive: trigger_source call-sequence localises even with vague controls"
read level score key surface rating vector <<< "$(get_severity "$dir")"
assert_eq "L" "$(metric "$vector" AV)" "AV:L from structured trigger_source=call-sequence"

# Generic `Trigger source: api` is not local-caller proof by itself. A public API
# can still be reached through a worst-case external embedding, and limited
# caller control is already represented as MAT:P rather than AV localisation.
dir=$(make_crash "demo_av_api_length" CRASH-AV-API-LENGTH \
  "heap-buffer-overflow WRITE of size 8" \
  "library-api" "obeyed" "length" "5/5" "CL-x (singleton)")
echo "Trigger source: api" >> "$dir/report.md"
_CURRENT_TEST="derive: trigger_source api + limited control keeps AV:N"
read level score key surface rating vector <<< "$(get_severity "$dir")"
assert_eq "N" "$(metric "$vector" AV)" "AV:N — api alone is not local-caller proof"
assert_eq "P" "$(metric "$vector" MAT)" "MAT:P carries the limited-control precondition"

# A contract concern with NO positive local/API evidence must NOT localise the
# vector: "not pure bytes" (e.g. a timing/race shape) is true of remotely
# reachable bugs too, so it stays AV:N and is represented only as MAT:P. A bare
# concern is not proof that only a trusted local caller can reach the bug.
dir=$(make_crash "demo_av_concern_only" CRASH-AV-CONCERN-ONLY \
  "heap-buffer-overflow WRITE of size 8" "library-api" "unspecified" "timing" "5/5" "CL-x (singleton)")
cat >> "$dir/report.md" <<'EOF'

## Contract concern

Triage flagged a contract concern: trigger shape outside the declared input boundary.
EOF
_CURRENT_TEST="derive: contract concern without local/API evidence stays AV:N"
read level score key surface rating vector <<< "$(get_severity "$dir")"
assert_eq "N" "$(metric "$vector" AV)" "AV:N kept — bare concern is not local-caller proof"
assert_eq "P" "$(metric "$vector" MAT)" "MAT:P still derived from contract concern"

# AT:P follows the local trigger independently of the AV override: when the
# surface is already AV:L (production CLI), a privileged local call-sequence
# still imposes an intrinsic Attack Requirement (AT:P).
dir=$(make_crash "demo_av_cli_seq" CRASH-AV-CLI-SEQ \
  "attempting free on address which was not malloc()-ed" \
  "cli — shipped tool" "unspecified" "call-sequence" "5/5" "CL-x (singleton)")
_CURRENT_TEST="derive: surface AV:L + local call-sequence → AT:P (no AV override needed)"
read level score key surface rating vector <<< "$(get_severity "$dir")"
assert_eq "cli_production" "$surface" "cli_production classified"
assert_eq "L" "$(metric "$vector" AV)" "AV:L from surface (unchanged)"
assert_eq "P" "$(metric "$vector" AT)" "AT:P from local call-sequence even when AV already L"

# `both` is the triage trigger token that expands to bytes + call-sequence
# (lib/triage.py trigger evaluation). When the target model declares
# BOTH components attacker-controlled, the trigger ⊆ attacker_controls: the bug
# is genuinely byte-reachable and must NOT localise — AV:N stays. (When call-
# sequence is OUTSIDE the model, the set-difference localises instead; that is
# the demo_current_oob_local case.)
src=$(make_crash "demo_av_both" CRASH-AV-BOTH \
  "heap-use-after-free WRITE of size 8" "library-api" "unspecified" \
  "call-sequence" "5/5" "CL-x (singleton)")
mkdir -p "$TEST_TMPDIR/output/bothmodel/backend/results/crashes" "$TEST_TMPDIR/output/bothmodel"
cat > "$TEST_TMPDIR/output/bothmodel/target.toml" <<'TOML'
[threat_model]
attacker_controls = ["bytes", "call-sequence"]
TOML
dir="$TEST_TMPDIR/output/bothmodel/backend/results/crashes/CRASH-AV-BOTH"
cp -R "$src" "$dir"
echo "Trigger source: both" >> "$dir/report.md"
_CURRENT_TEST="derive: trigger_source=both fully in attacker_controls keeps AV:N"
read level score key surface rating vector <<< "$(get_severity "$dir")"
assert_eq "N" "$(metric "$vector" AV)" "AV:N — both components attacker-controlled, trigger ⊆ model"

# The `both` veto is scoped to the structured trigger_source token. In free-prose
# caller_controls, "both" is the ordinary English word and must NOT veto: a
# genuine local call-sequence bug whose prose happens to say "both calls" still
# localises to AV:L. Regression for over-localising the byte veto to prose fields.
dir=$(make_crash "demo_av_both_prose" CRASH-AV-BOTH-PROSE \
  "heap-use-after-free WRITE of size 8" "library-api" "unspecified" \
  "both of the public API calls the harness issues, in order" "5/5" "CL-x (singleton)")
echo "Trigger source: call-sequence" >> "$dir/report.md"
_CURRENT_TEST="derive: prose 'both' in controls does not veto a call-sequence localisation"
read level score key surface rating vector <<< "$(get_severity "$dir")"
assert_eq "L" "$(metric "$vector" AV)" "AV:L — prose 'both' is not the trigger token, localisation holds"
assert_eq "P" "$(metric "$vector" AT)" "AT:P for the local call-sequence trigger"

# Policy lock: non-byte trigger tokens that are NOT call-sequence (env, fs-state,
# timing, race, protocol-state) are deliberately NOT localised — they are
# remotely reachable whenever attacker content flows through them (CGI maps HTTP
# headers to env vars; upload-then-parse for fs-state; concurrent remote requests
# for race/timing). The conservative classification is AV:N; the extra
# precondition is carried as MAT:P, not an AV downgrade. `env` stands in here.
dir=$(make_crash "demo_av_env" CRASH-AV-ENV \
  "heap-buffer-overflow WRITE of size 8" "library-api" "unspecified" \
  "environment variable state" "5/5" "CL-x (singleton)")
echo "Trigger source: env" >> "$dir/report.md"
_CURRENT_TEST="derive: env trigger is not localised — stays AV:N (policy lock)"
read level score key surface rating vector <<< "$(get_severity "$dir")"
assert_eq "N" "$(metric "$vector" AV)" "AV:N — env is not unambiguously local, stays surface AV"

# Policy lock (the strong case): a remote-capable trigger token must veto
# localisation even when a TRUSTED parameter/action is also present. Without the
# trigger_source veto, env/race/etc. + parameter_control=trusted localised to
# AV:L and under-rated a remotely-driveable bug (Shellshock-style env, server
# race). The trigger veto takes precedence over the trusted-caller signals.
dir=$(make_crash "demo_av_env_trusted" CRASH-AV-ENV-TRUSTED \
  "heap-buffer-overflow WRITE of size 8" "library-api" "unspecified" \
  "process environment state" "5/5" "CL-x (singleton)")
{ echo "Trigger source: env"; echo "Parameter control: trusted"; } >> "$dir/report.md"
_CURRENT_TEST="derive: env trigger + trusted parameter still stays AV:N (veto wins)"
read level score key surface rating vector <<< "$(get_severity "$dir")"
assert_eq "N" "$(metric "$vector" AV)" "AV:N — remote-capable trigger vetoes the trusted-parameter localisation"

dir=$(make_crash "demo_av_race_trusted" CRASH-AV-RACE-TRUSTED \
  "heap-use-after-free WRITE of size 8" "library-api" "unspecified" \
  "thread scheduling window" "5/5" "CL-x (singleton)")
{ echo "Trigger source: race"; echo "Trusted caller actions: private struct mutation"; } >> "$dir/report.md"
_CURRENT_TEST="derive: race trigger + trusted action still stays AV:N (veto wins)"
read level score key surface rating vector <<< "$(get_severity "$dir")"
assert_eq "N" "$(metric "$vector" AV)" "AV:N — remote-capable race trigger vetoes trusted-action localisation"

# Guard the opposite over-veto: the legitimate trusted-parameter localisation
# (no byte path, no remote-capable trigger token) must STILL localise to AV:L.
# This is the genuine API-misuse shape — application-supplied parameters with no
# attacker bytes — and the remote-capable veto must not swallow it.
dir=$(make_crash "demo_av_trusted_local" CRASH-AV-TRUSTED-LOCAL \
  "attempting free on address which was not malloc()-ed" "library-api" "unspecified" \
  "which internal handle is passed" "5/5" "CL-x (singleton)")
echo "Parameter control: application-supplied" >> "$dir/report.md"
_CURRENT_TEST="derive: trusted/application-supplied parameter (no byte, no remote trigger) → AV:L"
read level score key surface rating vector <<< "$(get_severity "$dir")"
assert_eq "L" "$(metric "$vector" AV)" "AV:L — trusted-parameter localisation preserved when no remote trigger"
assert_eq "P" "$(metric "$vector" AT)" "AT:P for the local trusted-parameter trigger"

# OOM / allocation-failure exploitation is inherently conditional on the
# allocator being in a failing state — a precondition outside attacker byte
# control — so the primitive carries Attack Requirements Present (AT:P).
dir=$(make_crash "demo_oom_at" CRASH-OOM-AT \
  "ERROR: AddressSanitizer: out-of-memory: allocator is out of memory" \
  "library-api" "obeyed" "bytes" "5/5" "CL-x (singleton)")
_CURRENT_TEST="derive: oom primitive → AT:P"
read level score key surface rating vector <<< "$(get_severity "$dir")"
assert_eq "oom" "$key" "out-of-memory classifies as oom"
assert_eq "P" "$(metric "$vector" AT)" "AT:P — oom allocation-failure precondition is inherent"

# Harness-rooted crash: fault #0 is the audit harness/driver and NO target
# frame appears anywhere (the harness freed its own buffer) → internal surface
# (impacts floored), not a shipped-library AV:N crash.
dir=$(make_crash "demo_harness_rooted" CRASH-HARNESS-ROOTED \
  "heap-use-after-free READ of size 8" "library-api" "obeyed" "bytes" "5/5" "CL-x (singleton)")
{
  echo '```'
  echo '==1==ERROR: AddressSanitizer: heap-use-after-free on address 0x60d000000058'
  echo '    #0 0x100 in main error_ptr_heap_lifetime_harness.c:84'
  echo '    #1 0x188 in start+0x1b4c (dyld:arm64e+0x1fdfc)'
  echo 'freed by thread T0 here:'
  echo '    #0 0x101 in free (libclang_rt.asan_osx_dynamic.dylib:arm64e+0x41258)'
  echo '    #1 0x102 in main error_ptr_heap_lifetime_harness.c:76'
  echo '```'
} >> "$dir/report.md"
_CURRENT_TEST="harness-rooted crash → internal surface"
read level score key surface rating vector <<< "$(get_severity "$dir")"
assert_eq "internal" "$surface" "harness-rooted crash (no target frame) is tiered internal"
# The --harness-rooted-check flag (used by triage to REJECT these) agrees.
_CURRENT_TEST="flag: --harness-rooted-check exits 0 for a harness-rooted crash"
"$REACH" --report "$dir" --harness-rooted-check >/dev/null 2>&1 \
  && pass "--harness-rooted-check exits 0 (reject) for the harness-rooted crash" \
  || fail "--harness-rooted-check on harness-rooted dir" "expected exit 0"

# Control: a genuine library bug merely *exercised* by a harness — #0 is the
# library, the harness only appears deeper — must keep normal library scoring.
dir=$(make_crash "demo_lib_via_harness" CRASH-LIB-VIA-HARNESS \
  "heap-use-after-free READ of size 8" "library-api" "obeyed" "bytes" "5/5" "CL-x (singleton)")
{
  echo '```'
  echo '==1==ERROR: AddressSanitizer: heap-use-after-free on address 0x60d000000058'
  echo '    #0 0x100 in cJSON_Delete cJSON.c:261'
  echo '    #1 0x180 in main harness.c:70'
  echo '```'
} >> "$dir/report.md"
_CURRENT_TEST="library bug via harness → NOT harness-rooted"
read level score key surface rating vector <<< "$(get_severity "$dir")"
assert_neq "internal" "$surface" "a library faulting frame keeps the normal (non-internal) surface"
_CURRENT_TEST="flag: --harness-rooted-check exits non-zero for a library crash"
if "$REACH" --report "$dir" --harness-rooted-check >/dev/null 2>&1; then
  fail "--harness-rooted-check on library crash" "wrongly matched a real library bug"
else
  pass "--harness-rooted-check exits non-zero (keep) for a library faulting frame"
fi

# CLI target whose bug lives in (or is inlined into) `main`: the fault leaf is
# `main <target>.c` with no other frame. `main` is the shipped tool's own entry,
# NOT the audit driver (which is named harness.c / *_harness.c), so this is a
# real target bug and must keep its shipping surface — not be zeroed to internal.
# Regression: a hard-coded `main`-is-harness rule mis-tiered this to internal,
# floored its impacts (MVC:N/MVI:N/MVA:N) and scored it None.
dir=$(make_crash "demo_cli_main" CRASH-CLI-MAIN \
  "stack-buffer-overflow WRITE of size 1" "cli — shipped CLI tool" "obeyed" "bytes" "5/5" "CL-x (singleton)")
{
  echo '```'
  echo '==1==ERROR: AddressSanitizer: stack-buffer-overflow on address 0x16d000058'
  echo '    #2 0x104 in main main.c:28'
  echo '```'
} >> "$dir/report.md"
_CURRENT_TEST="CLI-target bug in main (only frame) → NOT harness-rooted, stays shipping"
read level score key surface rating vector <<< "$(get_severity "$dir")"
assert_eq "cli_production" "$surface" "a CLI target's own main is target code, not the audit driver"
assert_neq "0.0" "$score" "a confirmed CLI stack overflow is not zeroed to None"
_CURRENT_TEST="flag: --harness-rooted-check exits non-zero (keep) for a CLI-main crash"
if "$REACH" --report "$dir" --harness-rooted-check >/dev/null 2>&1; then
  fail "--harness-rooted-check on CLI-main crash" "wrongly zeroed a real CLI target bug"
else
  pass "--harness-rooted-check exits non-zero (keep) for a CLI target's own main"
fi

# Target-owned `main` in a CONTEXT stack: the leaf is the harness, but the
# freed/allocated-by stack faults in the shipped tool's own `main <target>.c`.
# That target frame must count — a UAF whose freed memory is target-owned is a
# real bug, not harness-rooted. Regression: is_ignored_frame's `^main` dedup
# rule dropped the context `main` frame, so the report zeroed to internal.
dir=$(make_crash "demo_ctx_main" CRASH-CTX-MAIN \
  "heap-use-after-free WRITE of size 8" "cli — shipped CLI tool" "obeyed" "bytes" "5/5" "CL-x (singleton)")
{
  echo '```'
  echo '==1==ERROR: AddressSanitizer: heap-use-after-free on address 0x60d000000058'
  echo '    #0 0x100 in main harness.c:84'
  echo 'freed by thread T0 here:'
  echo '    #1 0x188 in main main.c:40'
  echo '```'
} >> "$dir/report.md"
_CURRENT_TEST="target main in freed-by context → NOT harness-rooted"
read level score key surface rating vector <<< "$(get_severity "$dir")"
assert_neq "internal" "$surface" "a target-owned main frame in the context stack keeps shipping scoring"

# A sanitizer/runtime frame in a context stack is NOT target source: on Linux
# ASan symbolizes it WITH a real source path (`free` in compiler-rt), so a bare
# location check would count it as library and wrongly keep a harness-only crash.
# It is excluded by PATH (_SYSTEM_SOURCE_RE), not by function name → harness-rooted.
dir=$(make_crash "demo_runtime_ctx" CRASH-RUNTIME-CTX \
  "heap-use-after-free READ of size 8" "library-api" "obeyed" "bytes" "5/5" "CL-x (singleton)")
{
  echo '```'
  echo '==1==ERROR: AddressSanitizer: heap-use-after-free on address 0x60d000000058'
  echo '    #0 0x100 in main lib_fuzz_harness.c:84'
  echo 'freed by thread T0 here:'
  echo '    #1 0x188 in free /src/llvm-project/compiler-rt/lib/asan/asan_malloc_linux.cpp:52:3'
  echo '    #2 0x190 in main lib_fuzz_harness.c:70'
  echo '```'
} >> "$dir/report.md"
_CURRENT_TEST="Linux runtime frame in context is not target source → harness-rooted"
read level score key surface rating vector <<< "$(get_severity "$dir")"
assert_eq "internal" "$surface" "a compiler-rt runtime frame is not counted as target library"

# A target can itself be glibc/compiler-rt/libc++; shared severity code must not
# hard-code those path segments as non-target when the frame is under the active
# TARGET_ROOT. The same stack shape as above is kept because the context frame is
# target-owned, not sanitizer runtime boilerplate.
target_root="$TEST_TMPDIR/targets/glibc"
mkdir -p "$target_root"
mkdir -p "$TEST_TMPDIR/output/rootmatch/backend/results"
# A real target root always carries target.toml alongside its session (see
# session discovery in lib/target_config.py); write it so this behaves like a
# genuine target when severity resolves the session from an ancestor path.
echo '[meta]' > "$TEST_TMPDIR/output/rootmatch/target.toml"
cat > "$TEST_TMPDIR/output/rootmatch/backend/results/.session-env" <<EOF
TARGET_ROOT=$target_root
TARGET_SLUG=rootmatch
RESULTS_DIR=$TEST_TMPDIR/output/rootmatch/backend/results
EOF
dir=$(make_crash "demo_target_named_glibc" CRASH-TARGET-NAMED-GLIBC \
  "heap-use-after-free READ of size 8" "library-api" "obeyed" "bytes" "5/5" "CL-x (singleton)")
{
  echo '```'
  echo '==1==ERROR: AddressSanitizer: heap-use-after-free on address 0x60d000000058'
  echo '    #0 0x100 in main lib_fuzz_harness.c:84'
  echo 'freed by thread T0 here:'
  echo "    #1 0x188 in app_release ${target_root}/malloc/malloc.c:40"
  echo '```'
} >> "$dir/report.md"
_CURRENT_TEST="target-root glibc path in context is target source → kept"
read level score key surface rating vector <<< "$(get_severity "$dir")"
assert_neq "internal" "$surface" "a target checked out under glibc is not dropped as runtime"
_CURRENT_TEST="flag: target-root glibc context exits non-zero (keep)"
if "$REACH" --report "$dir" --harness-rooted-check >/dev/null 2>&1; then
  fail "--harness-rooted-check on target-root glibc context" "wrongly zeroed a target-owned runtime-named path"
else
  pass "--harness-rooted-check exits non-zero (keep) for target-root glibc context"
fi

# Conversely, an installed C++ standard-library header in the context stack is
# still external runtime/stdlib code. Counting it as target source would inflate
# a harness-only report into a shipped library crash.
dir=$(make_crash "demo_libstdcxx_ctx" CRASH-LIBSTDCXX-CTX \
  "heap-use-after-free READ of size 8" "library-api" "obeyed" "bytes" "5/5" "CL-x (singleton)")
{
  echo '```'
  echo '==1==ERROR: AddressSanitizer: heap-use-after-free on address 0x60d000000058'
  echo '    #0 0x100 in main lib_fuzz_harness.c:84'
  echo 'freed by thread T0 here:'
  echo '    #1 0x188 in std::vector<int>::~vector() /usr/include/c++/12/bits/stl_vector.h:735:7'
  echo '    #2 0x190 in main lib_fuzz_harness.c:70'
  echo '```'
} >> "$dir/report.md"
_CURRENT_TEST="external libstdc++ header in context is not target source → harness-rooted"
read level score key surface rating vector <<< "$(get_severity "$dir")"
assert_eq "internal" "$surface" "an installed libstdc++ header is not counted as target library"

# A REAL target frame whose function name merely shares an ignored crash-state
# prefix (`free_node` vs `^free`, `operator delete` vs `^operator`) must still
# count as target. Ownership is judged by path, not name — else a harness-leaf
# UAF freed inside `free_node src/tree.c` would be wrongly zeroed to internal.
dir=$(make_crash "demo_prefix_target" CRASH-PREFIX-TARGET \
  "heap-use-after-free READ of size 8" "library-api" "obeyed" "bytes" "5/5" "CL-x (singleton)")
{
  echo '```'
  echo '==1==ERROR: AddressSanitizer: heap-use-after-free on address 0x60d000000058'
  echo '    #0 0x100 in main lib_fuzz_harness.c:84'
  echo 'freed by thread T0 here:'
  echo '    #1 0x188 in free_node src/tree.c:40'
  echo '```'
} >> "$dir/report.md"
_CURRENT_TEST="target free_node src/tree.c (^free prefix) is target, not runtime → kept"
read level score key surface rating vector <<< "$(get_severity "$dir")"
assert_neq "internal" "$surface" "a target function sharing an ignore-rule prefix is not dropped as runtime"

# libFuzzer's entrypoint symbolized WITH its parameter list is still the harness:
# match the normalized state_function, not the raw `func(args)` spelling.
dir=$(make_crash "demo_libfuzzer_args" CRASH-LIBFUZZER-ARGS \
  "heap-buffer-overflow READ of size 1" "library-api" "obeyed" "bytes" "5/5" "CL-x (singleton)")
{
  echo '```'
  echo '==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000058'
  echo '    #0 0x100 in LLVMFuzzerTestOneInput(unsigned char const*, unsigned long) FuzzerMain.cpp:20'
  echo '```'
} >> "$dir/report.md"
_CURRENT_TEST="LLVMFuzzerTestOneInput with param list → harness-rooted"
read level score key surface rating vector <<< "$(get_severity "$dir")"
assert_eq "internal" "$surface" "libFuzzer entrypoint matches on the normalized name despite its argument list"

# XSS sets subsequent-system impact (SC:L/SI:L).
dir=$(make_crash "demo_xss_sub" CRASH-XSS-SUB \
  "stored XSS in profile bio rendered without escape" "library-api" "obeyed" "bytes" "5/5" "CL-x (singleton)")
_CURRENT_TEST="derive: XSS → subsequent-system SC:L/SI:L"
read level score key surface rating vector <<< "$(get_severity "$dir")"
assert_eq "L" "$(metric "$vector" SC)" "SC:L for XSS"
assert_eq "L" "$(metric "$vector" SI)" "SI:L for XSS"

# Threat Exploit Maturity: no evidence is E:U; saved reproducer/testcase
# artifacts are proof-of-concept availability (E:P).
dir=$(make_crash "demo_e_unreported" CRASH-E-U \
  "heap-buffer-overflow READ of size 1" "library-api" "obeyed" "bytes" "?" "CL-x (singleton)")
_CURRENT_TEST="derive: no exploit/reproducer evidence → E:U"
read level score key surface rating vector <<< "$(get_severity "$dir")"
assert_eq "U" "$(metric "$vector" E)" "E:U when no exploit/reproducer evidence recorded"

dir=$(make_crash "demo_e_poc" CRASH-E-P \
  "heap-buffer-overflow READ of size 1" "library-api" "obeyed" "bytes" "?" "CL-x (singleton)")
printf 'payload\n' > "$dir/input.txt"
_CURRENT_TEST="derive: reproducer artifact → E:P"
read level score key surface rating vector <<< "$(get_severity "$dir")"
assert_eq "P" "$(metric "$vector" E)" "E:P from saved reproducer/testcase artifact"

# A recorded 0/N reverification (reproduction failed) overrides a stale
# artifact still on disk: a reproducer that no longer fires is not
# proof-of-concept maturity, so E:U — not E:P.
dir=$(make_crash "demo_e_failed_reverify" CRASH-E-FAILED \
  "heap-buffer-overflow READ of size 1" "library-api" "obeyed" "bytes" "0/5" "CL-x (singleton)")
printf 'payload\n' > "$dir/input.txt"
_CURRENT_TEST="derive: 0/N reverify overrides artifact → E:U"
read level score key surface rating vector <<< "$(get_severity "$dir")"
assert_eq "U" "$(metric "$vector" E)" "E:U when reverification failed (0/5), even with an artifact on disk"

# A bare PROSE mention of "reproducer/PoC" with no artifact and no positive
# reproduction is a claim, not evidence — it must NOT grant E:P (this was the
# dominant source of inflated Exploit-Maturity on prose-only findings).
dir=$(make_crash "demo_e_prose_only" CRASH-E-PROSE \
  "heap-buffer-overflow READ of size 1" "library-api" "obeyed" "bytes" "?" "CL-x (singleton)" \
  "A reproducer and proof-of-concept could be constructed from this testcase.")
_CURRENT_TEST="derive: prose-only PoC mention (no artifact) → E:U"
read level score key surface rating vector <<< "$(get_severity "$dir")"
assert_eq "U" "$(metric "$vector" E)" "prose mention of reproducer/PoC without an artifact does not grant E:P"

# Probe-native CLEAN evidence embedded in the report BODY (verdict=CLEAN /
# NO CRASHES / CRASH_RATE 0/N) is a failed reproduction → E:U, overriding a
# stale testcase artifact — AND a BUDGET counter in the same log
# ("BUDGET: 21/60 sanitizer invocations") must NOT be misread as a 21/60
# reproduction rate that would grant E:P. Regression for gemini FIND-0011.
dir=$(make_crash "demo_e_probe_clean" CRASH-E-PROBECLEAN \
  "heap-buffer-overflow WRITE of size 8" "library-api" "obeyed" "bytes" "?" "CL-x (singleton)")
printf 'payload\n' > "$dir/input.txt"
cat >> "$dir/report.md" <<'EOF'

```
[run-sanitizer-multi] BUDGET: 21/60 sanitizer invocations used this iteration
CRASH_RATE: 0/1
[run-sanitizer-multi] NO CRASHES in 1 runs (1 completed cleanly, 1 reached target)
[probe] verdict=CLEAN
```
EOF
_CURRENT_TEST="derive: embedded probe verdict=CLEAN → E:U (BUDGET not a repro rate)"
read level score key surface rating vector <<< "$(get_severity "$dir")"
assert_eq "U" "$(metric "$vector" E)" "embedded probe CLEAN / CRASH_RATE 0/N overrides artifact → E:U (BUDGET 21/60 ignored)"

# An affirmative exploitation claim is E:A; the same phrase NEGATED
# ("no evidence ... exploited in the wild") must NOT be — it is the
# opposite claim and previously inflated the score past the E:P reading.
dir=$(make_crash "demo_e_wild" CRASH-E-WILD \
  "heap-buffer-overflow WRITE of size 8" "library-api" "obeyed" "bytes" "5/5" "CL-x (singleton)" \
  "Vendor advisory confirms this is actively exploited.")
_CURRENT_TEST="derive: affirmed exploitation → E:A"
read level score key surface rating vector <<< "$(get_severity "$dir")"
assert_eq "A" "$(metric "$vector" E)" "E:A from affirmed exploitation evidence"

dir=$(make_crash "demo_e_notwild" CRASH-E-NOTWILD \
  "heap-buffer-overflow WRITE of size 8" "library-api" "obeyed" "bytes" "5/5" "CL-x (singleton)" \
  "There is no evidence this bug has been exploited in the wild.")
_CURRENT_TEST="derive: negated exploitation claim stays E:P"
read level score key surface rating vector <<< "$(get_severity "$dir")"
assert_eq "P" "$(metric "$vector" E)" "negated in-the-wild claim does not derive E:A"

# Full byte control dominates an accompanying shape word: a caller who
# controls "document contents and length" shapes the whole input, so no
# MAT:P (the limited-shape reading applies only without byte control).
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
dir=$(make_crash "demo_score_netuaf" CRASH-SCORE-NETUAF \
  "heap-use-after-free WRITE of size 8" "network — TLS handler" "obeyed" "bytes" "5/5" "CL-x (singleton)")
_CURRENT_TEST="score: network UAF WRITE → 8.9 High BTE"
read level score key surface rating vector <<< "$(get_severity "$dir")"
assert_eq "8.9" "$score" "score 8.9"
assert_eq "High" "$level" "level High"
assert_eq "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:P" "$vector" "BTE vector"

# Library OOB small read — Medium: held down by the low impacts (VC:L/VA:L)
# themselves, not by any environmental discount (CR/IR/AR are Not Defined).
dir=$(make_crash "demo_score_libread" CRASH-SCORE-LIBREAD \
  "heap-buffer-overflow READ of size 1" "library-api" "obeyed" "bytes" "5/5" "CL-x (singleton)")
_CURRENT_TEST="score: library 1-byte OOB read → Medium band"
read level score key surface rating vector <<< "$(get_severity "$dir")"
assert_eq "5.5" "$score" "library small read score 5.5"
assert_eq "Medium" "$level" "library small read is Medium (low impacts, M environment)"

# XSS — subsequent-system-only impacts stay mid-band under the local BTE
# environment.
dir=$(make_crash "demo_score_xss" CRASH-SCORE-XSS \
  "stored XSS in profile bio rendered without escape" "library-api" "obeyed" "bytes" "5/5" "CL-x (singleton)")
_CURRENT_TEST="score: XSS → Medium"
read level score key surface rating vector <<< "$(get_severity "$dir")"
assert_eq "Medium" "$level" "XSS is Medium"

# Unclassified crash → Unknown, no score, no vector.
dir=$(make_crash "demo_score_unknown" CRASH-SCORE-UNKNOWN \
  "process exited abnormally with no sanitizer output" "library-api" "obeyed" "bytes" "5/5" "CL-x (singleton)")
_CURRENT_TEST="score: unclassified crash → Unknown, no vector"
read level score key surface rating vector <<< "$(get_severity "$dir")"
assert_eq "Unknown" "$level" "unclassified → Unknown level"
assert_eq "None" "$score" "no score for unclassified"
assert_eq "-" "$vector" "no vector for unclassified"

# Determinism: same input twice → identical score.
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
dir=$(make_crash "demo_devpath" CRASH-DEVPATH \
  "heap-buffer-overflow WRITE in \`maint/ucptest.c:823\`" "unspecified" "obeyed" "bytes" "5/5" "CL-x (singleton)")
_CURRENT_TEST="env: maint/ path in narrative → dev_tool → Low"
read level score key surface rating vector <<< "$(get_severity "$dir")"
assert_eq "dev_tool" "$surface" "maint/ path → dev_tool"
assert_eq "Low" "$level" "narrative dev path lowers to Low"

# Internal harness → None/0.0 when all modified impacts are N.
dir=$(make_crash "demo_internal" CRASH-INTERNAL \
  "heap-use-after-free WRITE of size 8" "internal — audit harness" "obeyed" "bytes" "5/5" "CL-x (singleton)")
_CURRENT_TEST="env: internal harness → None"
read level score key surface rating vector <<< "$(get_severity "$dir")"
assert_eq "internal" "$surface" "internal surface classified"
assert_eq "None" "$level" "internal harness has no local environmental impact"

# False-positive guard: a real library-api whose description mentions a
# 'harness' (exercise mechanism, not bug location) must NOT be demoted.
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
dir=$(make_crash "demo_line" CRASH-LINE \
  "heap-use-after-free WRITE of size 8" "network — TLS handler" "obeyed" "bytes" "5/5" "CL-x (singleton)")
python3 "$REACH" --report "$dir" >/dev/null 2>&1
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
python3 "$REACH" --report "$dir" >/dev/null 2>&1
python3 "$REACH" --report "$dir" >/dev/null 2>&1
n=$(grep -c "^## Severity rationale" "$dir/report.md")
assert_eq "1" "$n" "rationale heading appears exactly once after 3 runs"

_CURRENT_TEST="section: non-shipping environmental call-out rendered"
dir=$(make_crash "demo_capnote" CRASH-CAPNOTE \
  "stack-buffer-overflow WRITE of size 1" "maint-tool — maintenance/test program" \
  "obeyed" "bytes" "5/5" "CL-x (singleton)")
python3 "$REACH" --report "$dir" >/dev/null 2>&1
assert_file_contains "$dir/report.md" "Non-shipping surface" "non-shipping note present"
assert_file_contains "$dir/report.md" "without a custom cap" "environmental explanation present"

# Transient-crash DoS (stack_exhaustion/null_deref/bus) carries a supplemental
# Recovery=Automatic (R:A) note: score-unchanged, operational-severity context.
_CURRENT_TEST="section: stack-overflow carries supplemental R:A recovery note"
dir=$(make_crash "demo_recover" CRASH-RECOVER \
  "stack-overflow on address 0xfeed (deep recursion)" \
  "library-api — C harness calls a public library entry point" \
  "obeyed" "bytes" "5/5" "CL-x (singleton)")
read level score key surface rating vector <<< "$(get_severity "$dir")"
assert_eq "stack_exhaustion" "$key" "stack-overflow classifies as stack_exhaustion"
# A byte-reachable DoS-only stack-exhaustion (AV:N/VA:H, E:P) scores High (7.7) —
# the CVSS-B reading for a remote availability impact, the same band NVD applies
# to remote-DoS CVEs (no environmental discount: CR/IR/AR are Not Defined). The
# R:A supplemental note still does not change the score — it is the score's
# invariance under the note, not the band itself, that this case pins.
assert_eq "High" "$level" "stack_exhaustion DoS scored High (remote availability impact, CVSS-B reading)"
python3 "$REACH" --report "$dir" >/dev/null 2>&1
assert_file_contains "$dir/report.md" "Recovery: Automatic" "R:A supplemental note present"
assert_file_contains "$dir/report.md" "score unchanged" "note disclaims any score effect"
assert_file_contains "$dir/report.md" "one band lighter" "note gives operational-severity read"

# A non-transient crash class (heap WRITE) must NOT carry the R:A note — the
# damage is persistent corruption, not an auto-recovering process restart.
_CURRENT_TEST="section: heap-write crash does not carry R:A recovery note"
dir=$(make_crash "demo_norecover" CRASH-NORECOVER \
  "heap-buffer-overflow WRITE of size 8" \
  "library-api — C harness calls a public library entry point" \
  "obeyed" "bytes" "5/5" "CL-x (singleton)")
python3 "$REACH" --report "$dir" >/dev/null 2>&1
assert_file_not_contains "$dir/report.md" "Recovery: Automatic" "no R:A note on persistent-corruption class"

# ───────────────────────────────────────────────────────────────────
# 7. Report fields are the sole scoring input
# ───────────────────────────────────────────────────────────────────

# RC#4: an unenriched bin/probe skeleton (Root Cause / Data Flow still carry the
# `_TODO (agent):` placeholders) fails closed to Unknown — its structured fields
# are placeholders, so a band scored off them is scored off junk — even though
# the pasted ASan text would otherwise classify a heap-use-after-free. The crash
# stays counted/pooled elsewhere; here we assert it is not granted a real band.
dir="$TEST_TMPDIR/crashes/CRASH-SKEL"
mkdir -p "$dir"
cat > "$dir/report.md" <<'RPT'
# CRASH-SKEL: heap-use-after-free in app_free

> AUTO-FILED skeleton. bin/probe confirmed this sanitizer diagnostic.

## Fields

| Field             | Value |
|:------------------|:------|
| Surface           | library-api |
| Caller contract   | violated |
| Caller controls   | bytes |
| Reproduction rate | 5/5 |

## Root Cause
_TODO (agent): describe the defect and why the sanitizer fires._

## Data Flow
_TODO (agent): step: func (file:line) — desc._

```
==1==ERROR: AddressSanitizer: heap-use-after-free on address 0x602000000010
    #0 app_free child.c:91
```

## Classification
- **Severity**: TBD
RPT
read level score key surface rating vector <<< "$(get_severity "$dir")"
assert_eq "Unknown" "$level" "unenriched _TODO skeleton crash fails closed to Unknown"
assert_eq "None" "$score" "no CVSS score for an unenriched skeleton crash"

# Accepted finding classes are structured evidence, not prose. Severity owns
# their single canonical mapping and ignores the gate's advisory severity.
validated="$TEST_TMPDIR/findings/FIND-VALIDATED-CLASS"
mkdir -p "$validated"
cat > "$validated/report.md" <<'RPT'
# Repeated work consumes unbounded resources

## Fields

| Field | Value |
|:------|:------|
| Class | dos |
| Severity | Unknown |
| Surface | library-api |

The accepted report names concrete attacker-controlled repeated work.
RPT
cat > "$validated/.llm-find-quality.json" <<'JSON'
{"decision_version":"v13-python","accept":true,"accept_count":2,"class":"dos:algorithmic","severity":"critical","reason":"measured superlinear work"}
JSON
validated_json=$(python3 "$REACH" --report "$validated" --json)
assert_eq "dos_amplification" "$(jq -r '.severity.primitive_key' <<<"$validated_json")" \
  "accepted dos:algorithmic class maps centrally to availability-only primitive"
assert_neq "Critical" "$(jq -r '.severity.level' <<<"$validated_json")" \
  "quality gate's advisory severity cannot become the CVSS result"

high_impact="$TEST_TMPDIR/findings/FIND-VALIDATED-HIGH"
mkdir -p "$high_impact"
cat > "$high_impact/report.md" <<'RPT'
# Accepted high-impact state flaw

Class: state
Surface: library-api

The accepted report establishes an input-shaped unsafe object reconstruction.
RPT
cat > "$high_impact/.llm-find-quality.json" <<'JSON'
{"decision_version":"v13-python","accept":true,"accept_count":2,"class":"deserialization:unsafe","severity":"critical"}
JSON
high_json=$(python3 "$REACH" --report "$high_impact" --json)
assert_eq "deserialization" "$(jq -r '.severity.primitive_key' <<<"$high_json")" \
  "accepted high-impact class maps to its existing central primitive"
assert_eq "High" "$(jq -r '.severity.level' <<<"$high_json")" \
  "unreproduced H/H/H finding is tempered by E:U and cannot become Critical"
assert_file_contains "$high_impact/report.md" 'E:U' \
  "validated high-impact finding records unreported exploit maturity"

# Classification is not an acceptance gate. Ambiguous or non-terminal caches
# remain visible with an explicit terminal review state and no fabricated score.
review="$TEST_TMPDIR/findings/FIND-NEEDS-REVIEW"
mkdir -p "$review"
cat > "$review/report.md" <<'RPT'
# Ambiguous accepted boundary issue

## Fields

| Field | Value |
|:------|:------|
| Class | boundary |
| Severity | Unknown |

The report is substantive but its impact primitive is not specific enough.
RPT
cat > "$review/.llm-find-quality.json" <<'JSON'
{"decision_version":"v13-python","accept":true,"accept_count":2,"class":"boundary:new-unmapped-kind","severity":"high","reason":"concrete boundary crossing"}
JSON
review_json=$(python3 "$REACH" --report "$review" --json)
assert_eq "Needs review" "$(jq -r '.severity.level' <<<"$review_json")" \
  "unmapped accepted class is explicit Needs review, not generic Unknown"
assert_eq "null" "$(jq -r '.severity.score|tostring' <<<"$review_json")" \
  "Needs review carries no invented CVSS score"
assert_file_contains "$review/report.md" 'Severity.*Needs review' \
  "report persists the explicit Needs review state"

unaccepted="$TEST_TMPDIR/findings/FIND-NONTERMINAL-CLASS"
cp -R "$validated" "$unaccepted"
cat > "$unaccepted/.llm-find-quality.json" <<'JSON'
{"decision_version":"v13-python","accept":true,"accept_count":1,"class":"dos:algorithmic","severity":"medium"}
JSON
nonterminal_json=$(python3 "$REACH" --report "$unaccepted" --json)
assert_eq "Needs review" "$(jq -r '.severity.level' <<<"$nonterminal_json")" \
  "one validator vote cannot mint a primitive or severity"

malformed_cache="$TEST_TMPDIR/findings/FIND-NONDICT-CACHE"
cp -R "$review" "$malformed_cache"
printf '%s\n' '[]' > "$malformed_cache/.llm-find-quality.json"
malformed_json=$(python3 "$REACH" --report "$malformed_cache" --json)
assert_eq "Needs review" "$(jq -r '.severity.level' <<<"$malformed_json")" \
  "valid non-object cache JSON fails open instead of crashing severity"

# Sanitizer evidence and an authored Primitive retain precedence over the
# validator class, preventing structured hints from overriding proof.
authoritative="$TEST_TMPDIR/findings/FIND-AUTHORITATIVE"
mkdir -p "$authoritative"
cat > "$authoritative/report.md" <<'RPT'
# Sanitizer-proved write

Primitive: heap_write
Surface: library-api

==1==ERROR: AddressSanitizer: heap-buffer-overflow
WRITE of size 8
RPT
cat > "$authoritative/.llm-find-quality.json" <<'JSON'
{"decision_version":"v13-python","accept":true,"accept_count":2,"class":"dos:algorithmic","severity":"medium"}
JSON
authoritative_json=$(python3 "$REACH" --report "$authoritative" --json)
assert_eq "heap_write" "$(jq -r '.severity.primitive_key' <<<"$authoritative_json")" \
  "sanitizer/authored primitive outranks validator class"

batch_finding="$TEST_TMPDIR/findings/FIND-BATCH"
mkdir -p "$batch_finding"
cat > "$batch_finding/report.md" <<'RPT'
# Concrete path traversal

Primitive: path_traversal
Surface: cli
Caller contract: obeyed
Caller controls: bytes
Trigger source: bytes
RPT
python3 "$REACH" --batch "$TEST_TMPDIR" >/dev/null
assert_file_exists "$batch_finding/severity.json" \
  "severity batch scores findings and crashes in one interpreter"

teardown_test_env
summary
