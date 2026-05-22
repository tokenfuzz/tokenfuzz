#!/usr/bin/env bash
# Advanced triage tests — security impact evidence, web reachability heuristics,
# nonweb markers, FIND scoring rubric, use-after-poison, edge cases
set -o pipefail
source "$(dirname "$0")/helpers.sh"
setup_test_env
source "$SCRIPT_ROOT/lib/triage.sh"

# ═══════════════════════════════════════════════════════════════
# 1. crash_dir_has_memory_safety_asan_signal — comprehensive types
# ═══════════════════════════════════════════════════════════════

# use-after-poison → memory safety
mkdir -p "$TEST_TMPDIR/uap_crash"
cat > "$TEST_TMPDIR/uap_crash/asan.txt" <<'EOF'
==12345==ERROR: AddressSanitizer: use-after-poison on address 0x60200000abcd
EOF
# use-after-poison is not in the list — verifying classifier behavior
crash_dir_has_memory_safety_asan_signal "$TEST_TMPDIR/uap_crash" 2>/dev/null
uap_rc=$?
# use-after-poison is NOT in the keep list for memory-safety signal
# (it IS in is_autodiscard keep list but not crash_dir_has_memory_safety_asan_signal)
assert_neq 0 $uap_rc "use-after-poison: not classified as memory-safety signal"

# negative-size-param → memory safety signal
mkdir -p "$TEST_TMPDIR/neg_crash"
cat > "$TEST_TMPDIR/neg_crash/asan.txt" <<'EOF'
==12345==ERROR: AddressSanitizer: negative-size-param on address 0x60200000abcd
EOF
crash_dir_has_memory_safety_asan_signal "$TEST_TMPDIR/neg_crash"
assert_eq 0 $? "negative-size-param → memory safety signal"

# bad-free → memory safety signal
mkdir -p "$TEST_TMPDIR/badfree_crash"
cat > "$TEST_TMPDIR/badfree_crash/asan.txt" <<'EOF'
==12345==ERROR: AddressSanitizer: bad-free on address 0x60200000abcd
EOF
crash_dir_has_memory_safety_asan_signal "$TEST_TMPDIR/badfree_crash"
assert_eq 0 $? "bad-free → memory safety signal"

# new-delete-type-mismatch → memory safety signal
mkdir -p "$TEST_TMPDIR/ndtm_crash"
cat > "$TEST_TMPDIR/ndtm_crash/asan.txt" <<'EOF'
==12345==ERROR: AddressSanitizer: new-delete-type-mismatch on address 0x60200000abcd
EOF
crash_dir_has_memory_safety_asan_signal "$TEST_TMPDIR/ndtm_crash"
assert_eq 0 $? "new-delete-type-mismatch → memory safety signal"

# calloc-overflow → memory safety signal
mkdir -p "$TEST_TMPDIR/calloc_crash"
cat > "$TEST_TMPDIR/calloc_crash/asan.txt" <<'EOF'
==12345==ERROR: AddressSanitizer: calloc-overflow on address 0x60200000abcd
EOF
crash_dir_has_memory_safety_asan_signal "$TEST_TMPDIR/calloc_crash"
assert_eq 0 $? "calloc-overflow → memory safety signal"

# invalid-pointer-pair → memory safety signal
mkdir -p "$TEST_TMPDIR/ipp_crash"
cat > "$TEST_TMPDIR/ipp_crash/asan.txt" <<'EOF'
==12345==ERROR: AddressSanitizer: invalid-pointer-pair on address 0x60200000abcd
EOF
crash_dir_has_memory_safety_asan_signal "$TEST_TMPDIR/ipp_crash"
assert_eq 0 $? "invalid-pointer-pair → memory safety signal"

# intra-object-overflow → memory safety signal
mkdir -p "$TEST_TMPDIR/ioo_crash"
cat > "$TEST_TMPDIR/ioo_crash/asan.txt" <<'EOF'
==12345==ERROR: AddressSanitizer: intra-object-overflow on address 0x60200000abcd
EOF
crash_dir_has_memory_safety_asan_signal "$TEST_TMPDIR/ioo_crash"
assert_eq 0 $? "intra-object-overflow → memory safety signal"

# No ASan file → no signal
mkdir -p "$TEST_TMPDIR/no_asan"
crash_dir_has_memory_safety_asan_signal "$TEST_TMPDIR/no_asan"
assert_eq 1 $? "no asan file → no memory safety signal"

# ═══════════════════════════════════════════════════════════════
# 2. crash_dir_has_web_reachability_evidence — various signals
# ═══════════════════════════════════════════════════════════════

# MutationObserver mention → web
mkdir -p "$TEST_TMPDIR/web1"
echo "This triggers via MutationObserver callback" > "$TEST_TMPDIR/web1/report.md"
crash_dir_has_web_reachability_evidence "$TEST_TMPDIR/web1"
assert_eq 0 $? "MutationObserver → web reachable"

# postMessage → web
mkdir -p "$TEST_TMPDIR/web2"
echo "Via postMessage from cross-origin frame" > "$TEST_TMPDIR/web2/report.md"
crash_dir_has_web_reachability_evidence "$TEST_TMPDIR/web2"
assert_eq 0 $? "postMessage → web reachable"

# fetch() → web
mkdir -p "$TEST_TMPDIR/web3"
echo "Triggered by fetch() request" > "$TEST_TMPDIR/web3/report.md"
crash_dir_has_web_reachability_evidence "$TEST_TMPDIR/web3"
assert_eq 0 $? "fetch() → web reachable"

# Service Worker → web
mkdir -p "$TEST_TMPDIR/web4"
echo "Via Service Worker intercepting requests" > "$TEST_TMPDIR/web4/report.md"
crash_dir_has_web_reachability_evidence "$TEST_TMPDIR/web4"
assert_eq 0 $? "Service Worker → web reachable"

# HTMLTestcase > 16B → web
mkdir -p "$TEST_TMPDIR/web5"
echo '<html><body>This is large enough content to count</body></html>' > "$TEST_TMPDIR/web5/testcase.html"
crash_dir_has_web_reachability_evidence "$TEST_TMPDIR/web5"
assert_eq 0 $? "HTML testcase > 16B → web reachable"

# SVG file > 16B → web
mkdir -p "$TEST_TMPDIR/web6"
echo '<svg xmlns="http://www.w3.org/2000/svg" width="100" height="100"><rect/></svg>' > "$TEST_TMPDIR/web6/test.svg"
crash_dir_has_web_reachability_evidence "$TEST_TMPDIR/web6"
assert_eq 0 $? "SVG file > 16B → web reachable"

# Tiny HTML file (≤16B) — NOT web
mkdir -p "$TEST_TMPDIR/web7"
echo "<html></html>" > "$TEST_TMPDIR/web7/tiny.html"
echo "no web signals here" > "$TEST_TMPDIR/web7/report.md"
crash_dir_has_web_reachability_evidence "$TEST_TMPDIR/web7"
assert_eq 1 $? "tiny HTML ≤16B + no signals → not web reachable"

# XMLHttpRequest → web
mkdir -p "$TEST_TMPDIR/web8"
echo "Uses XMLHttpRequest to load data" > "$TEST_TMPDIR/web8/report.md"
crash_dir_has_web_reachability_evidence "$TEST_TMPDIR/web8"
assert_eq 0 $? "XMLHttpRequest → web reachable"

# ═══════════════════════════════════════════════════════════════
# 3. crash_dir_has_nonweb_only_markers
# ═══════════════════════════════════════════════════════════════

# Services.prefs → nonweb
mkdir -p "$TEST_TMPDIR/nw1"
echo "Requires Services.prefs access" > "$TEST_TMPDIR/nw1/report.md"
crash_dir_has_nonweb_only_markers "$TEST_TMPDIR/nw1"
assert_eq 0 $? "Services.prefs → nonweb marker"

# Cc["@mozilla.org/ → nonweb
mkdir -p "$TEST_TMPDIR/nw2"
echo 'Uses Cc["@mozilla.org/observer-service;1"]' > "$TEST_TMPDIR/nw2/report.md"
crash_dir_has_nonweb_only_markers "$TEST_TMPDIR/nw2"
assert_eq 0 $? 'Cc["@mozilla.org → nonweb marker'

# privileged-API-only → nonweb
mkdir -p "$TEST_TMPDIR/nw3"
echo "privileged API only access" > "$TEST_TMPDIR/nw3/report.md"
crash_dir_has_nonweb_only_markers "$TEST_TMPDIR/nw3"
assert_eq 0 $? "privileged-API-only → nonweb marker"

# Normal web → no marker
mkdir -p "$TEST_TMPDIR/nw4"
echo "Triggered by document.createElement" > "$TEST_TMPDIR/nw4/report.md"
crash_dir_has_nonweb_only_markers "$TEST_TMPDIR/nw4"
assert_eq 1 $? "normal web code → no nonweb marker"

# ═══════════════════════════════════════════════════════════════
# 4. crash_dir_has_security_impact_evidence — via text, not ASan
# ═══════════════════════════════════════════════════════════════

# Text-based: "type confusion" → security impact
mkdir -p "$TEST_TMPDIR/sec1"
echo "This is a type confusion in the JIT" > "$TEST_TMPDIR/sec1/report.md"
crash_dir_has_security_impact_evidence "$TEST_TMPDIR/sec1"
assert_eq 0 $? "type confusion text → security impact"

# Text-based: "sandbox escape" → security impact
mkdir -p "$TEST_TMPDIR/sec2"
echo "This causes a sandbox escape" > "$TEST_TMPDIR/sec2/report.md"
crash_dir_has_security_impact_evidence "$TEST_TMPDIR/sec2"
assert_eq 0 $? "sandbox escape text → security impact"

# Text-based: "cross-origin" → security impact
mkdir -p "$TEST_TMPDIR/sec3"
echo "This is a cross-origin bypass" > "$TEST_TMPDIR/sec3/report.md"
crash_dir_has_security_impact_evidence "$TEST_TMPDIR/sec3"
assert_eq 0 $? "cross-origin text → security impact"

# No impact text → no security impact (without ASan)
mkdir -p "$TEST_TMPDIR/sec4"
echo "Pure logic error in layout engine" > "$TEST_TMPDIR/sec4/report.md"
crash_dir_has_security_impact_evidence "$TEST_TMPDIR/sec4"
assert_eq 1 $? "logic error → no security impact"

# ═══════════════════════════════════════════════════════════════
# 5. crash_dir_security_rejection_reason — combined checks (browser target)
# ═══════════════════════════════════════════════════════════════

IS_BROWSER_TARGET=1

# Impact + web → no rejection
mkdir -p "$TEST_TMPDIR/rej1"
cat > "$TEST_TMPDIR/rej1/asan.txt" <<'EOF'
==12345==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x60200000abcd
EOF
echo '<html><body>Triggers via <canvas> element rendering path with large enough content</body></html>' > "$TEST_TMPDIR/rej1/testcase.html"
export LLM_DECIDE_MOCK_LEGIT_CRASH='{"legitimate":true,"reason":"web content input boundary"}'
reason=$(crash_dir_security_rejection_reason "$TEST_TMPDIR/rej1" || true)
unset LLM_DECIDE_MOCK_LEGIT_CRASH
assert_eq "" "$reason" "impact + web → no rejection"

# Impact but no web → rejected for web
mkdir -p "$TEST_TMPDIR/rej2"
cat > "$TEST_TMPDIR/rej2/asan.txt" <<'EOF'
==12345==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x60200000abcd
EOF
cat > "$TEST_TMPDIR/rej2/report.md" <<'EOF'
Boundary: CLI input
Internal engine path
EOF
export LLM_DECIDE_MOCK_LEGIT_CRASH='{"legitimate":false,"reason":"missing plausible web/content reachability evidence"}'
reason=$(crash_dir_security_rejection_reason "$TEST_TMPDIR/rej2" || true)
unset LLM_DECIDE_MOCK_LEGIT_CRASH
assert_match "web" "$reason" "impact but no web → rejected for web"

# No impact + web → rejected for impact
mkdir -p "$TEST_TMPDIR/rej3"
cat > "$TEST_TMPDIR/rej3/asan.txt" <<'EOF'
==12345==ERROR: AddressSanitizer: stack-overflow on address 0x7fff12345678
EOF
echo "Via <canvas> web content but stack overflow" > "$TEST_TMPDIR/rej3/report.md"
export LLM_DECIDE_MOCK_LEGIT_CRASH='{"legitimate":false,"reason":"missing memory-safety impact"}'
reason=$(crash_dir_security_rejection_reason "$TEST_TMPDIR/rej3" || true)
unset LLM_DECIDE_MOCK_LEGIT_CRASH
assert_match "memory-safety" "$reason" "no impact → rejected for impact"

# xpcshell-only + impact → rejected with xpcshell reason
mkdir -p "$TEST_TMPDIR/rej4"
cat > "$TEST_TMPDIR/rej4/asan.txt" <<'EOF'
==12345==ERROR: AddressSanitizer: heap-use-after-free on address 0x60300000dcba
EOF
cat > "$TEST_TMPDIR/rej4/report.md" <<'EOF'
Boundary: CLI input
Only reachable from xpcshell. Uses heap-use-after-free.
EOF
export LLM_DECIDE_MOCK_LEGIT_CRASH='{"legitimate":false,"reason":"xpcshell-only trigger without web/content reachability"}'
reason=$(crash_dir_security_rejection_reason "$TEST_TMPDIR/rej4" || true)
unset LLM_DECIDE_MOCK_LEGIT_CRASH
assert_match "xpcshell" "$reason" "xpcshell-only → xpcshell rejection reason"

IS_BROWSER_TARGET=0

# ═══════════════════════════════════════════════════════════════
# 6. is_autodiscard_crash_output — additional edge cases
# ═══════════════════════════════════════════════════════════════

# Allocation size too big + ASan error → discard (OOM is checked before KEEP)
cat > "$TEST_TMPDIR/alloc_asan.txt" <<'EOF'
==12345==ERROR: AddressSanitizer: allocation-size-too-big
==12345==ERROR: attempted to allocate 999999999999 bytes
EOF
is_autodiscard_crash_output "$TEST_TMPDIR/alloc_asan.txt"
assert_eq 0 $? "allocation-size-too-big → autodiscard"

# Stack-use-after-scope → keep
cat > "$TEST_TMPDIR/suar.txt" <<'EOF'
==12345==ERROR: AddressSanitizer: stack-use-after-scope on address 0x7fff12345678
EOF
is_autodiscard_crash_output "$TEST_TMPDIR/suar.txt"
assert_eq 1 $? "stack-use-after-scope → keep"

# NS assertion (###!!! format with extra whitespace)
cat > "$TEST_TMPDIR/ns_assert2.txt" <<'EOF'
###!!! ASSERTION: Some invariant violated: 'ptr != nullptr', file /src/foo.cpp, line 42
EOF
is_autodiscard_crash_output "$TEST_TMPDIR/ns_assert2.txt"
assert_eq 0 $? "###!!! ASSERTION (ptr) → autodiscard"

# Multiple crash types — KEEP type takes priority over DISCARD
cat > "$TEST_TMPDIR/multi_crash.txt" <<'EOF'
==12345==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x60200000abcd
Hit MOZ_CRASH(some diagnostic) at /src/foo.cpp:42
EOF
is_autodiscard_crash_output "$TEST_TMPDIR/multi_crash.txt"
assert_eq 1 $? "heap-OOB + MOZ_CRASH → keep (KEEP short-circuits)"

# ═══════════════════════════════════════════════════════════════
# 7. validate_find_gate — every FIND stays in findings/.
#
# A real report file means the FIND is kept untouched. An empty FIND
# gets a .needs-content marker but is NOT moved. The LLM substance +
# classification path is covered separately in
# test_decision_find_quality.sh.
# ═══════════════════════════════════════════════════════════════

LLM_DECIDE_DISABLE=1
REACHABILITY_AUTO=0

# Memory-safety FIND with reproducer → kept.
mkdir -p "$RESULTS_DIR/findings/FIND-T01-rich"
cat > "$RESULTS_DIR/findings/FIND-T01-rich/description.md" <<'EOF'
# Heap buffer overflow in glyph renderer via <svg>

CATEGORY: bounds
heap-buffer-overflow in render/glyph/GlyphRenderer.cpp:process_glyph:234
Triggered by crafted <svg> filter chain via web content.
EOF
echo '<svg xmlns="http://www.w3.org/2000/svg"><filter><feTurbulence/></filter></svg>' > "$RESULTS_DIR/findings/FIND-T01-rich/testcase.svg"

validate_find_gate 2>/dev/null
assert_dir_exists "$RESULTS_DIR/findings/FIND-T01-rich" "FIND with full memory-safety report kept"

# Non-memory-safety FIND (logic / boundary) → also kept.
mkdir -p "$RESULTS_DIR/findings/FIND-T02-logic"
cat > "$RESULTS_DIR/findings/FIND-T02-logic/description.md" <<'EOF'
# CSP bypass via crafted <canvas> reflow

ui/canvas/Canvas2DContext.cpp:reset_transform:910 emits raw
caller-controlled drawImage URLs that bypass the document's CSP.
Issue class: boundary / security policy bypass.
EOF

validate_find_gate 2>/dev/null
assert_dir_exists "$RESULTS_DIR/findings/FIND-T02-logic" "non-memory-safety FIND kept"

# Auth / privilege FIND without sanitizer evidence → kept.
mkdir -p "$RESULTS_DIR/findings/FIND-T03-auth"
cat > "$RESULTS_DIR/findings/FIND-T03-auth/description.md" <<'EOF'
# Privilege boundary bypass in IPC actor

ipc/ParentChannel.cpp:on_message:100 trusts a content-process-supplied
session token without re-checking the parent-side capability map.
Issue class: privilege boundary violation.
EOF

validate_find_gate 2>/dev/null
assert_dir_exists "$RESULTS_DIR/findings/FIND-T03-auth" "auth/privilege FIND kept without sanitizer evidence"

# Empty FIND directory → kept in place with .needs-content marker.
mkdir -p "$RESULTS_DIR/findings/FIND-T04-empty"
: > "$RESULTS_DIR/findings/FIND-T04-empty/description.md"

validate_find_gate 2>/dev/null
assert_dir_exists "$RESULTS_DIR/findings/FIND-T04-empty" "empty FIND stays in findings/"
assert_file_exists "$RESULTS_DIR/findings/FIND-T04-empty/.needs-content" \
  "empty FIND gets .needs-content marker"
assert_file_contains "$RESULTS_DIR/findings/FIND-T04-empty/.needs-content" "no report file" \
  ".needs-content marker explains the issue"
[ ! -d "$RESULTS_DIR/findings-rejected" ] \
  && pass "no findings-rejected/ created for empty FIND" \
  || fail "no findings-rejected/ created for empty FIND" "findings-rejected/ exists"

unset LLM_DECIDE_DISABLE
unset REACHABILITY_AUTO

# ═══════════════════════════════════════════════════════════════
# 9. Wild-address SEGV → memory safety signal
# ═══════════════════════════════════════════════════════════════

mkdir -p "$TEST_TMPDIR/wild2"
cat > "$TEST_TMPDIR/wild2/asan.txt" <<'EOF'
SEGV on unknown address 0x414141414141
SCARINESS: 80 (wild-addr-write)
EOF
crash_dir_has_memory_safety_asan_signal "$TEST_TMPDIR/wild2"
assert_eq 0 $? "wild-addr-write SEGV → memory safety signal"

# Non-wild SEGV (close to zero but not zero page) → no memory safety
mkdir -p "$TEST_TMPDIR/near_null"
cat > "$TEST_TMPDIR/near_null/asan.txt" <<'EOF'
SEGV on unknown address 0x0000000000000008
SCARINESS: 20 (near-null-deref)
EOF
crash_dir_has_memory_safety_asan_signal "$TEST_TMPDIR/near_null"
assert_eq 1 $? "near-null SEGV without wild-addr → no memory safety signal"

teardown_test_env
summary
