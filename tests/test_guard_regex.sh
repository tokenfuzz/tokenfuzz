#!/usr/bin/env bash
# tests/test_guard_regex.sh — bin/audit:GUARD_DIAGNOSTIC_REGEX coverage.
#
# Verifies the comprehensive guard-line regex matches real diagnostic
# shapes from major target families and rejects benign prose.

set -uo pipefail
TESTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$TESTS_DIR/helpers.sh"

setup_test_env

# Pull just the regex constant out of bin/audit.
GUARD_DIAGNOSTIC_REGEX=$(awk -F"'" '/^GUARD_DIAGNOSTIC_REGEX=/{print $2; exit}' "$SCRIPT_ROOT/bin/audit")
[ -n "$GUARD_DIAGNOSTIC_REGEX" ] || { echo "✗ failed to extract regex"; exit 1; }

# extract_guard mirrors record_iteration_guard_chain's pipeline.
extract_guard() {
  local f="$1"
  head -n 200 "$f" 2>/dev/null \
    | grep -vE '^[[:space:]]*(#|//)' \
    | grep -oE "$GUARD_DIAGNOSTIC_REGEX" \
    | head -1 || true
}

# ── 1. Firefox / JS engine: named exception types ─────────────────
f="$TEST_TMPDIR/ff_typeerror.txt"
cat > "$f" <<'EOF'
=== Run 1/1 ===
TypeError: invalid range in regex character class
    at <anonymous>:1:1
EOF
out=$(extract_guard "$f")
assert_match "^TypeError: " "$out" "JS TypeError matches"

f="$TEST_TMPDIR/ff_referror.txt"
cat > "$f" <<'EOF'
ReferenceError: foo is not defined
EOF
out=$(extract_guard "$f")
assert_match "^ReferenceError" "$out" "JS ReferenceError matches (broader than old regex)"

f="$TEST_TMPDIR/ff_quota.txt"
cat > "$f" <<'EOF'
QuotaExceededError: persistent storage quota exceeded
EOF
out=$(extract_guard "$f")
assert_match "QuotaExceededError" "$out" "DOM QuotaExceededError matches"

# ── 2. Mozilla NS_ERROR_ macros ───────────────────────────────────
f="$TEST_TMPDIR/ff_nserror.txt"
cat > "$f" <<'EOF'
WebIDL: throwing NS_ERROR_DOM_INVALID_STATE_ERR from caller
EOF
out=$(extract_guard "$f")
assert_match "NS_ERROR_DOM_INVALID_STATE_ERR" "$out" "NS_ERROR_ macro matches"

# ── 3. PCRE2 numeric error ────────────────────────────────────────
f="$TEST_TMPDIR/pcre2_err.txt"
cat > "$f" <<'EOF'
PCRE2 version 10.48-DEV
/(?:abc/B
error 128 at offset 24: atomic assertion expected after (?( or (?(?C)
EOF
out=$(extract_guard "$f")
assert_match "^error 128 at offset 24" "$out" "pcre2 numeric error matches"

f="$TEST_TMPDIR/pcre2_neg.txt"
cat > "$f" <<'EOF'
error -42: pattern contains an item that is not supported for DFA matching
EOF
out=$(extract_guard "$f")
assert_match "^error -42" "$out" "pcre2 negative numeric error matches"

# ── 4. OpenSSL hex stack errors ───────────────────────────────────
f="$TEST_TMPDIR/openssl_stack.txt"
cat > "$f" <<'EOF'
00080EBC0A7F0000:error:0A000086:SSL routines:tls_post_process_server_certificate:certificate verify failed:ssl/statem/statem_clnt.c:2105:
EOF
out=$(extract_guard "$f")
assert_match "error:0A000086:SSL routines" "$out" "OpenSSL hex-stack error matches"

f="$TEST_TMPDIR/openssl_macro.txt"
cat > "$f" <<'EOF'
SSL handshake failed: SSL_ERROR_WANT_READ during read
EOF
out=$(extract_guard "$f")
assert_match "SSL_ERROR_WANT_READ" "$out" "OpenSSL SSL_ERROR_ macro matches"

# ── 5. zlib / expat / xml macro errors ────────────────────────────
f="$TEST_TMPDIR/zlib_err.txt"
cat > "$f" <<'EOF'
inflate result: Z_DATA_ERROR (incorrect header check)
EOF
out=$(extract_guard "$f")
assert_match "Z_DATA_ERROR" "$out" "zlib Z_DATA_ERROR matches"

f="$TEST_TMPDIR/expat_err.txt"
cat > "$f" <<'EOF'
XML_ERROR_NO_MEMORY at byte 4096
EOF
out=$(extract_guard "$f")
assert_match "XML_ERROR_NO_MEMORY" "$out" "expat XML_ERROR_ macro matches"

# ── 6. Encoding / format errors ───────────────────────────────────
f="$TEST_TMPDIR/utf8_err.txt"
cat > "$f" <<'EOF'
UTF-8 error: byte 2 top bits not 0x80
EOF
out=$(extract_guard "$f")
assert_match "^UTF-8 error: byte 2 top bits not 0x80" "$out" "UTF-8 error specialised prefix wins over generic"

f="$TEST_TMPDIR/pat_conv.txt"
cat > "$f" <<'EOF'
Pattern conversion error: invalid syntax near offset 17
EOF
out=$(extract_guard "$f")
assert_match "^Pattern conversion error" "$out" "pcre2 Pattern conversion error matches with prefix"

# ── 7. Generic error: prefix (clang/llvm/sqlite/libpng style) ─────
f="$TEST_TMPDIR/clang_err.txt"
cat > "$f" <<'EOF'
input.c:42:7: error: use of undeclared identifier 'foo'
EOF
out=$(extract_guard "$f")
assert_match "^error: use of undeclared" "$out" "clang error: prefix matches"

f="$TEST_TMPDIR/sqlite_err.txt"
cat > "$f" <<'EOF'
Error: near "SELEC": syntax error
EOF
out=$(extract_guard "$f")
assert_match "^Error: near" "$out" "sqlite Error: prefix matches"

f="$TEST_TMPDIR/fatal_err.txt"
cat > "$f" <<'EOF'
FATAL: division by zero in numeric_div()
EOF
out=$(extract_guard "$f")
assert_match "^FATAL: division by zero" "$out" "FATAL: prefix matches"

# ── 8. Diagnostic verbs ───────────────────────────────────────────
f="$TEST_TMPDIR/curl_failed.txt"
cat > "$f" <<'EOF'
Failed to connect to example.com port 443: Connection refused
EOF
out=$(extract_guard "$f")
assert_match "^Failed to connect" "$out" "Failed to verb matches"

f="$TEST_TMPDIR/pcre2_unrec.txt"
cat > "$f" <<'EOF'
Unrecognized modifier 'T' in modifier string "TARGET: pcre2"
EOF
out=$(extract_guard "$f")
assert_match "^Unrecognized modifier" "$out" "Unrecognized verb matches"

f="$TEST_TMPDIR/libxml2_invalid.txt"
cat > "$f" <<'EOF'
Invalid attribute value at xmlValidateOneAttribute
EOF
out=$(extract_guard "$f")
assert_match "^Invalid attribute" "$out" "Invalid verb matches"

# ── 9. Bare emergency phrases ─────────────────────────────────────
f="$TEST_TMPDIR/oom.txt"
cat > "$f" <<'EOF'
allocation request failed: out of memory
EOF
out=$(extract_guard "$f")
assert_match "out of memory" "$out" "out of memory bare phrase matches"

f="$TEST_TMPDIR/recursion.txt"
cat > "$f" <<'EOF'
script execution aborted: too much recursion
EOF
out=$(extract_guard "$f")
assert_match "too much recursion" "$out" "too much recursion bare phrase matches"

# ── 10. Negative cases: benign output must NOT match ──────────────
f="$TEST_TMPDIR/clean_pcre2.txt"
cat > "$f" <<'EOF'
PCRE2 version 10.48-DEV 2025-10-21 (8-bit)
# TARGET: src/pcre2_match.c:match_ref
# CATEGORY: bounds
# Probing back-reference edge cases — exercising error_handling path.
/(..)\1*+/B
------------------------------------------------------------------
        Bra
        CBra 1
        Ket
        End
------------------------------------------------------------------
  ab
 0: ab
 1: ab
EOF
out=$(extract_guard "$f")
assert_eq "" "$out" "clean pcre2 run with 'error' in a comment yields no guard"

f="$TEST_TMPDIR/clean_summary.txt"
cat > "$f" <<'EOF'
=== Run 1/1 ===
test summary: 0 errors, 0 warnings, 17 matches
EOF
out=$(extract_guard "$f")
assert_eq "" "$out" "summary line '0 errors, 0 warnings' yields no guard"

f="$TEST_TMPDIR/clean_asan_frames.txt"
cat > "$f" <<'EOF'
=== Run 1/1 ===
    #0 0x55edc8 in app_parse_doc /src/parser.c:9999
    #1 0x55ee1c in main /src/main.c:42
EOF
out=$(extract_guard "$f")
assert_eq "" "$out" "ASan stack frames (lines starting with #) yield no guard"

# ── 11. ASan crash files are skipped upstream — sanity check that
#       the regex still matches if such a file slipped through. The
#       upstream `grep -q "ERROR: AddressSanitizer"` skip in
#       record_iteration_guard_chain handles real-world filtering;
#       here we just verify the regex doesn't strangely fail. ──
f="$TEST_TMPDIR/asan_crash.txt"
cat > "$f" <<'EOF'
==12345==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x...
EOF
out=$(extract_guard "$f")
[ -n "$out" ] && pass "ASan crash line still extractable (upstream filter handles skip)" \
              || fail "ASan crash line still extractable (upstream filter handles skip)"

# ── 12. Length cap: long matches bounded near 160 chars ───────────
long_msg=$(printf 'X%.0s' {1..400})
f="$TEST_TMPDIR/long.txt"
echo "TypeError: $long_msg" > "$f"
out=$(extract_guard "$f")
# Pattern bounds the match to 160 chars after the prefix word; total length
# stays bounded to a reasonable upper limit (well under 200).
[ "${#out}" -le 200 ] && pass "long match length-bounded (got ${#out})" \
                      || fail "long match length-bounded (got ${#out})"

teardown_test_env
summary
