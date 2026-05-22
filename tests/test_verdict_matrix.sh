#!/usr/bin/env bash
# Unit tests for the Caller-contract / Trigger-source verdict matrix.
# Covers parse_caller_contract, parse_trigger_source, evaluate_crash_verdict,
# and the wiring into crash_dir_static_legitimacy_rejection_reason.
set -o pipefail
source "$(dirname "$0")/helpers.sh"
setup_test_env
source "$SCRIPT_ROOT/lib/triage.sh"

# A crash-dir builder, used by every section below. Writes the supplied
# report body into report.md plus a heap-buffer-overflow asan.txt so the
# memory-safety signal check passes when we want it to.
make_crash_dir() {
  local d="$1"; shift
  local report_body="$1"
  mkdir -p "$d"
  cat > "$d/asan.txt" <<'EOF'
==12345==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x60200000abcd
READ of size 4 at 0x60200000abcd
EOF
  printf '%s\n' "$report_body" > "$d/report.md"
}

# ───────────────────────────────────────────────────────────────────
# 1. parse_caller_contract — new 2-field form
# ───────────────────────────────────────────────────────────────────

mkdir -p "$TEST_TMPDIR/cc_obeyed"
cat > "$TEST_TMPDIR/cc_obeyed/r.md" <<'EOF'
Caller contract: obeyed
EOF
assert_eq "obeyed" "$(parse_caller_contract "$TEST_TMPDIR/cc_obeyed/r.md")" "contract: obeyed"

cat > "$TEST_TMPDIR/cc_obeyed/r.md" <<'EOF'
Caller contract: violated
EOF
assert_eq "violated" "$(parse_caller_contract "$TEST_TMPDIR/cc_obeyed/r.md")" "contract: violated"

cat > "$TEST_TMPDIR/cc_obeyed/r.md" <<'EOF'
Caller contract: unspecified
EOF
assert_eq "unspecified" "$(parse_caller_contract "$TEST_TMPDIR/cc_obeyed/r.md")" "contract: unspecified"

cat > "$TEST_TMPDIR/cc_obeyed/r.md" <<'EOF'
Caller contract:   OBEYED
EOF
assert_eq "obeyed" "$(parse_caller_contract "$TEST_TMPDIR/cc_obeyed/r.md")" "contract: case + whitespace tolerant"

cat > "$TEST_TMPDIR/cc_obeyed/r.md" <<'EOF'
Caller contract: garbage
EOF
assert_eq "" "$(parse_caller_contract "$TEST_TMPDIR/cc_obeyed/r.md")" "contract: unknown value treated as missing"

cat > "$TEST_TMPDIR/cc_obeyed/r.md" <<'EOF'
# No fields at all
Just a heap-buffer-overflow somewhere.
EOF
assert_eq "" "$(parse_caller_contract "$TEST_TMPDIR/cc_obeyed/r.md")" "no contract field → empty"

# ───────────────────────────────────────────────────────────────────
# 2. parse_trigger_source
# ───────────────────────────────────────────────────────────────────

p="$TEST_TMPDIR/trigger.md"

cat > "$p" <<'EOF'
Trigger source: bytes
EOF
assert_eq "bytes" "$(parse_trigger_source "$p")" "trigger: bytes"

cat > "$p" <<'EOF'
Trigger source: data
EOF
assert_eq "bytes" "$(parse_trigger_source "$p")" "trigger: 'data' alias normalized to bytes"

cat > "$p" <<'EOF'
Trigger source: call-sequence
EOF
assert_eq "call-sequence" "$(parse_trigger_source "$p")" "trigger: call-sequence"

cat > "$p" <<'EOF'
Trigger source: call-order
EOF
assert_eq "call-sequence" "$(parse_trigger_source "$p")" "trigger: call-order alias → call-sequence"

cat > "$p" <<'EOF'
Trigger source: bytes, call-sequence
EOF
assert_eq "bytes,call-sequence" "$(parse_trigger_source "$p")" "trigger: csv list parsed"

cat > "$p" <<'EOF'
Trigger source: bytes, BYTES, data
EOF
assert_eq "bytes" "$(parse_trigger_source "$p")" "trigger: aliases + duplicates collapsed"

cat > "$p" <<'EOF'
# missing field
EOF
assert_eq "" "$(parse_trigger_source "$p")" "trigger: missing field → empty"

# ───────────────────────────────────────────────────────────────────
# 3. evaluate_crash_verdict — verdict matrix from the docs
# Each row of the docs table is exercised here.
# ───────────────────────────────────────────────────────────────────

run_verdict() {
  local body="$1" controls="$2"
  local p="$TEST_TMPDIR/eval.md"
  printf '%s\n' "$body" > "$p"
  evaluate_crash_verdict "$p" "$controls" | awk -F'\t' '{print $1}'
}

# Row 1: libxml2 / bytes / data → security
verdict=$(run_verdict 'Caller contract: obeyed
Trigger source: bytes' 'bytes')
assert_eq "promote" "$verdict" "matrix: libxml2 + bytes/bytes → promote"

# Row 2: libxml2 / bytes / call-sequence → contract-flag (was 'robustness')
# Trigger has a component outside the threat model; the crash is kept in
# crashes/ with a low-severity flag rather than moved to crashes-rejected/.
verdict=$(run_verdict 'Caller contract: unspecified
Trigger source: call-sequence' 'bytes')
assert_eq "contract-flag" "$verdict" "matrix: libxml2 + call-sequence → contract-flag (kept in crashes/, low severity)"

# Row 3: firefox / bytes,call-sequence,timing / call-sequence → security
verdict=$(run_verdict 'Caller contract: obeyed
Trigger source: call-sequence' 'bytes,call-sequence,timing')
assert_eq "promote" "$verdict" "matrix: firefox + call-sequence → promote (security)"

# Row 4: firefox / bytes,call-sequence,timing / bytes → security
verdict=$(run_verdict 'Caller contract: obeyed
Trigger source: bytes' 'bytes,call-sequence,timing')
assert_eq "promote" "$verdict" "matrix: firefox + bytes → promote"

# Row 5: openssl-parser / bytes / bytes → security
verdict=$(run_verdict 'Caller contract: obeyed
Trigger source: bytes' 'bytes')
assert_eq "promote" "$verdict" "matrix: openssl + bytes → promote"

# Row 6: openssl-parser / bytes / race → contract-flag (was 'robustness')
verdict=$(run_verdict 'Caller contract: obeyed
Trigger source: race' 'bytes')
assert_eq "contract-flag" "$verdict" "matrix: openssl + race → contract-flag (kept in crashes/, low severity)"

# contract=violated now emits contract-flag (kept in crashes/, scored low)
# rather than the old 'violated' verdict (which moved to crashes-rejected/).
verdict=$(run_verdict 'Caller contract: violated
Trigger source: bytes' 'bytes')
assert_eq "contract-flag" "$verdict" "matrix: contract=violated → contract-flag (kept in crashes/, low severity)"

# ───────────────────────────────────────────────────────────────────
# 4. evaluate_crash_verdict — "both" expansion
# ───────────────────────────────────────────────────────────────────

# both = bytes + call-sequence. libxml2 only allows bytes → contract-flag.
verdict=$(run_verdict 'Caller contract: obeyed
Trigger source: both' 'bytes')
assert_eq "contract-flag" "$verdict" "both expands to call-sequence too → contract-flag for libxml2"

# Same trigger, firefox threat model includes call-sequence → security.
verdict=$(run_verdict 'Caller contract: obeyed
Trigger source: both' 'bytes,call-sequence,timing')
assert_eq "promote" "$verdict" "both fits firefox threat model → promote"

# ───────────────────────────────────────────────────────────────────
# 5. evaluate_crash_verdict — partial subset (mixed in/out)
# ───────────────────────────────────────────────────────────────────

# bytes is in, race is not. ANY out-of-set component → contract-flag.
verdict=$(run_verdict 'Caller contract: obeyed
Trigger source: bytes, race' 'bytes')
assert_eq "contract-flag" "$verdict" "partial subset (one out) → contract-flag"

# Reason mentions the missing component, not the satisfied one.
reason_line=$(run_verdict 'Caller contract: obeyed
Trigger source: bytes, race' 'bytes' >/dev/null; \
              p="$TEST_TMPDIR/eval.md"; \
              evaluate_crash_verdict "$p" "bytes" | awk -F'\t' '{print $2}')
assert_match "race" "$reason_line" "contract-flag reason names the offending component"

# ───────────────────────────────────────────────────────────────────
# 6. evaluate_crash_verdict — contract-only report defaults trigger=bytes
# ───────────────────────────────────────────────────────────────────

# Contract present without an explicit Trigger source falls back to bytes.
verdict=$(run_verdict 'Caller contract: obeyed' 'bytes')
assert_eq "promote" "$verdict" "contract-only report → promote (default trigger=bytes)"

verdict=$(run_verdict 'Caller contract: violated' 'bytes')
assert_eq "contract-flag" "$verdict" "contract=violated → contract-flag (kept in crashes/, low severity)"

# ───────────────────────────────────────────────────────────────────
# 7. evaluate_crash_verdict — incomplete report
# ───────────────────────────────────────────────────────────────────

verdict=$(run_verdict '# No relevant fields here.' 'bytes')
assert_eq "incomplete" "$verdict" "no contract or trigger field → incomplete (defer to other gates)"

# ───────────────────────────────────────────────────────────────────
# 8. evaluate_crash_verdict — controls argument defaulting
# ───────────────────────────────────────────────────────────────────

# Empty controls argument → defaults to "bytes".
verdict=$(run_verdict 'Caller contract: obeyed
Trigger source: bytes' '')
assert_eq "promote" "$verdict" "empty controls argument defaults to bytes"

verdict=$(run_verdict 'Caller contract: obeyed
Trigger source: timing' '')
assert_eq "contract-flag" "$verdict" "empty controls argument: timing not in default {bytes} → contract-flag"

# ───────────────────────────────────────────────────────────────────
# 9. crash_dir_static_legitimacy_rejection_reason wiring — libxml2 case
# This is the real-world libxml2 catalog UAF that motivated the change.
# ───────────────────────────────────────────────────────────────────

IS_BROWSER_TARGET=0
TARGET_ATTACKER_CONTROLS_CSV="bytes"

# libxml2-shape: contract=unspecified + trigger=call-sequence under bytes
# threat model → contract-flag (kept in crashes/ with low-severity flag,
# not moved to crashes-rejected/).
make_crash_dir "$TEST_TMPDIR/libxml2_call_seq" "Boundary: file bytes
Caller controls: catalog file contents
Trusted caller actions: load catalog, resolve, cleanup, resolve again
Caller contract: unspecified
Trigger source: call-sequence"
reason=$(crash_dir_static_legitimacy_rejection_reason "$TEST_TMPDIR/libxml2_call_seq" 2>/dev/null || true)
assert_match "contract-flag" "$reason" "libxml2 + call-sequence → static gate emits contract-flag prefix"

# Same crash report, but now under the firefox threat model. Expectation:
# the static gate stays silent (verdict=promote) and lets downstream
# gates decide.
TARGET_ATTACKER_CONTROLS_CSV="bytes,call-sequence,timing"
reason=$(crash_dir_static_legitimacy_rejection_reason "$TEST_TMPDIR/libxml2_call_seq" 2>/dev/null || true)
# The dir lacks web-reachability evidence; under IS_BROWSER_TARGET=0 that
# does not matter, so reason should be empty.
assert_eq "" "$reason" "same crash + firefox threat model + non-browser flag → static gate clean"

# ───────────────────────────────────────────────────────────────────
# 10. crash_dir_static_legitimacy_rejection_reason wiring — violated
# ───────────────────────────────────────────────────────────────────

TARGET_ATTACKER_CONTROLS_CSV="bytes,call-sequence,timing"

make_crash_dir "$TEST_TMPDIR/violated_2field" "Boundary: file bytes
Caller controls: input bytes
Trusted caller actions: parse
Caller contract: violated
Trigger source: bytes"
reason=$(crash_dir_static_legitimacy_rejection_reason "$TEST_TMPDIR/violated_2field" 2>/dev/null || true)
assert_match "contract-flag" "$reason" "contract=violated → contract-flag (kept in crashes/, low severity)"
assert_match "violated" "$reason" "contract-flag reason still names the violation"

make_crash_dir "$TEST_TMPDIR/harness_only_parameter" "Boundary: JSON text input file
Caller controls: data array bytes and index numeric bytes
Parameter control: harness-only
Trusted caller actions: parse JSON, then pass parsed index as iterator offset
Caller contract: obeyed
Trigger source: bytes"
reason=$(crash_dir_static_legitimacy_rejection_reason "$TEST_TMPDIR/harness_only_parameter" 2>/dev/null || true)
assert_match "contract-flag" "$reason" "parameter control=harness-only → contract-flag"
assert_match "harness-only parameter" "$reason" "contract-flag reason names harness-only parameter concern"

# ───────────────────────────────────────────────────────────────────
# 11. Regression: undocumented-contract / library re-entrancy crash
# This is the curl share_easy_link UAF scenario. CURLSHOPT_LOCKFUNC is
# silent on re-entrancy; the report fills Caller contract: unspecified.
# call-sequence is in curl's threat model. The deterministic verdict
# must PROMOTE (not reject) — the LLM legitimacy gate is then
# responsible for not over-ruling this. Test pins the matrix output so
# a future regression in evaluate_crash_verdict can't silently demote
# this class of bug back to "violated".
# ───────────────────────────────────────────────────────────────────

TARGET_ATTACKER_CONTROLS_CSV="bytes,call-sequence,protocol-state"

verdict=$(run_verdict 'Boundary: public libcurl API (curl_easy_setopt, CURLSHOPT_LOCKFUNC callback, curl_share_cleanup)
Caller controls: ordering of share/easy API calls; body of the LOCKFUNC callback
Trusted caller actions: only documented public API
Caller contract: unspecified
Trigger source: call-sequence' 'bytes,call-sequence,protocol-state')
assert_eq "promote" "$verdict" "regression: undocumented contract + call-sequence + curl threat model → promote (library re-entrancy bug)"

make_crash_dir "$TEST_TMPDIR/lib_reentrancy_uaf" "Boundary: public libcurl API (curl_easy_setopt, CURLSHOPT_LOCKFUNC callback, curl_share_cleanup)
Caller controls: ordering of share/easy API calls; body of the LOCKFUNC callback
Trusted caller actions: only documented public API: curl_easy_init, curl_share_init, curl_share_setopt, curl_easy_setopt, curl_share_cleanup, curl_easy_cleanup
Caller contract: unspecified
Trigger source: call-sequence"
reason=$(crash_dir_static_legitimacy_rejection_reason "$TEST_TMPDIR/lib_reentrancy_uaf" 2>/dev/null || true)
assert_eq "" "$reason" "regression: undocumented contract + library re-entrancy + curl threat model → static gate clean (no reject reason)"

teardown_test_env
summary
