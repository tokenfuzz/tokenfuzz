#!/usr/bin/env bash
# Unit tests for lib/triage.sh — crash classification, FIND validation, index regen
set -o pipefail
source "$(dirname "$0")/helpers.sh"
setup_test_env
source "$SCRIPT_ROOT/lib/triage.sh"

# ═══════════════════════════════════════════════════════════════
# 1. is_autodiscard_crash_output — crash classifier
# ═══════════════════════════════════════════════════════════════

# Null deref → discard (exit 0)
cat > "$TEST_TMPDIR/null_deref.txt" <<'EOF'
==12345==ERROR: AddressSanitizer: SEGV on unknown address 0x000000000000 (pc 0x7fff12345678 bp 0x7fff12345680)
Hint: address points to the zero page
SCARINESS: 10 (null-deref)
EOF
is_autodiscard_crash_output "$TEST_TMPDIR/null_deref.txt"
assert_eq 0 $? "null-deref → autodiscard"

# Heap buffer overflow → KEEP (exit 1)
cat > "$TEST_TMPDIR/heap_oob.txt" <<'EOF'
==12345==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x60200000abcd
READ of size 4 at 0x60200000abcd
#0 0x7fff12345678 in Foo::Bar()
EOF
is_autodiscard_crash_output "$TEST_TMPDIR/heap_oob.txt"
assert_eq 1 $? "heap-buffer-overflow → keep"

# Use after free → KEEP
cat > "$TEST_TMPDIR/uaf.txt" <<'EOF'
==12345==ERROR: AddressSanitizer: heap-use-after-free on address 0x60300000dcba
READ of size 8 at 0x60300000dcba
#0 0x7fff12345678 in Foo::Baz()
EOF
is_autodiscard_crash_output "$TEST_TMPDIR/uaf.txt"
assert_eq 1 $? "heap-use-after-free → keep"

# Container overflow → KEEP
cat > "$TEST_TMPDIR/container.txt" <<'EOF'
==12345==ERROR: AddressSanitizer: container-overflow on address 0x60200000abcd
EOF
is_autodiscard_crash_output "$TEST_TMPDIR/container.txt"
assert_eq 1 $? "container-overflow → keep"

# Stack buffer overflow → KEEP (not stack-overflow)
cat > "$TEST_TMPDIR/stack_bof.txt" <<'EOF'
==12345==ERROR: AddressSanitizer: stack-buffer-overflow on address 0x7fff12345678
EOF
is_autodiscard_crash_output "$TEST_TMPDIR/stack_bof.txt"
assert_eq 1 $? "stack-buffer-overflow → keep"

# Dynamic stack buffer overflow → KEEP
cat > "$TEST_TMPDIR/dynamic_stack.txt" <<'EOF'
==12345==ERROR: AddressSanitizer: dynamic-stack-buffer-overflow on address 0x7fff12345678
EOF
is_autodiscard_crash_output "$TEST_TMPDIR/dynamic_stack.txt"
assert_eq 1 $? "dynamic-stack-buffer-overflow → keep"

# Double free → KEEP
cat > "$TEST_TMPDIR/double_free.txt" <<'EOF'
==12345==ERROR: AddressSanitizer: double-free on address 0x60200000abcd
EOF
is_autodiscard_crash_output "$TEST_TMPDIR/double_free.txt"
assert_eq 1 $? "double-free → keep"

# Global buffer overflow → KEEP
cat > "$TEST_TMPDIR/global_oob.txt" <<'EOF'
==12345==ERROR: AddressSanitizer: global-buffer-overflow on address 0x12345678
EOF
is_autodiscard_crash_output "$TEST_TMPDIR/global_oob.txt"
assert_eq 1 $? "global-buffer-overflow → keep"

# Alloc-dealloc mismatch → KEEP
cat > "$TEST_TMPDIR/mismatch.txt" <<'EOF'
==12345==ERROR: AddressSanitizer: alloc-dealloc-mismatch on address 0x60200000abcd
EOF
is_autodiscard_crash_output "$TEST_TMPDIR/mismatch.txt"
assert_eq 1 $? "alloc-dealloc-mismatch → keep"

# Stack use after return → KEEP
cat > "$TEST_TMPDIR/stack_uar.txt" <<'EOF'
==12345==ERROR: AddressSanitizer: stack-use-after-return on address 0x7fff12345678
EOF
is_autodiscard_crash_output "$TEST_TMPDIR/stack_uar.txt"
assert_eq 1 $? "stack-use-after-return → keep"

# Use-after-poison → KEEP
cat > "$TEST_TMPDIR/uap.txt" <<'EOF'
==12345==ERROR: AddressSanitizer: use-after-poison on address 0x60200000abcd
EOF
is_autodiscard_crash_output "$TEST_TMPDIR/uap.txt"
assert_eq 1 $? "use-after-poison → keep"

# MOZ_CRASH → discard
cat > "$TEST_TMPDIR/moz_crash.txt" <<'EOF'
Hit MOZ_CRASH(diagnostic is over) at /src/foo.cpp:123
EOF
is_autodiscard_crash_output "$TEST_TMPDIR/moz_crash.txt"
assert_eq 0 $? "MOZ_CRASH → autodiscard"

# MOZ_ASSERT → discard
cat > "$TEST_TMPDIR/moz_assert.txt" <<'EOF'
Assertion failure: x > 0, at /src/foo.cpp:55
EOF
is_autodiscard_crash_output "$TEST_TMPDIR/moz_assert.txt"
assert_eq 0 $? "Assertion failure → autodiscard"

# ###!!! ASSERTION → discard
cat > "$TEST_TMPDIR/ns_assertion.txt" <<'EOF'
###!!! ASSERTION: Unexpected null pointer: 'some assertion text', file /src/bar.cpp, line 99
EOF
is_autodiscard_crash_output "$TEST_TMPDIR/ns_assertion.txt"
assert_eq 0 $? "NS ASSERTION → autodiscard"

# Rust panic → discard
cat > "$TEST_TMPDIR/rust_panic.txt" <<'EOF'
thread 'main' panicked at 'called unwrap() on a None value', src/foo.rs:42
EOF
is_autodiscard_crash_output "$TEST_TMPDIR/rust_panic.txt"
assert_eq 0 $? "Rust panic → autodiscard"

cat > "$TEST_TMPDIR/rust_panic_thread_id.txt" <<'EOF'
thread 'main' (4734029) panicked at src/record.rs:16:35:
unsafe precondition(s) violated
EOF
is_autodiscard_crash_output "$TEST_TMPDIR/rust_panic_thread_id.txt"
assert_eq 0 $? "Rust panic with thread id → autodiscard"

# RustMozCrash → discard
cat > "$TEST_TMPDIR/rust_moz.txt" <<'EOF'
some trace with RustMozCrash in it
EOF
is_autodiscard_crash_output "$TEST_TMPDIR/rust_moz.txt"
assert_eq 0 $? "RustMozCrash → autodiscard"

# Plain stack-overflow → discard
cat > "$TEST_TMPDIR/stack_overflow.txt" <<'EOF'
==12345==ERROR: AddressSanitizer: stack-overflow on address 0x7fff12345678
EOF
is_autodiscard_crash_output "$TEST_TMPDIR/stack_overflow.txt"
assert_eq 0 $? "stack-overflow → autodiscard"

# OOM → discard
cat > "$TEST_TMPDIR/oom.txt" <<'EOF'
==12345==ERROR: AddressSanitizer: out-of-memory
EOF
is_autodiscard_crash_output "$TEST_TMPDIR/oom.txt"
assert_eq 0 $? "out-of-memory → autodiscard"

# Allocation size too big → discard
cat > "$TEST_TMPDIR/alloc_big.txt" <<'EOF'
==12345==ERROR: AddressSanitizer: allocation-size-too-big
EOF
is_autodiscard_crash_output "$TEST_TMPDIR/alloc_big.txt"
assert_eq 0 $? "allocation-size-too-big → autodiscard"

# SIGABRT without ASan error → discard
cat > "$TEST_TMPDIR/sigabrt.txt" <<'EOF'
Process crashed: SIGABRT
abort()
EOF
is_autodiscard_crash_output "$TEST_TMPDIR/sigabrt.txt"
assert_eq 0 $? "SIGABRT without ASan → autodiscard"

# SIGABRT WITH ASan error → keep (ASan error takes priority)
cat > "$TEST_TMPDIR/sigabrt_asan.txt" <<'EOF'
==12345==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x60200000abcd
SIGABRT
EOF
is_autodiscard_crash_output "$TEST_TMPDIR/sigabrt_asan.txt"
assert_eq 1 $? "SIGABRT with ASan heap-buffer-overflow → keep"

# Empty file → keep (not a crash, return 1)
touch "$TEST_TMPDIR/empty.txt"
is_autodiscard_crash_output "$TEST_TMPDIR/empty.txt"
assert_eq 1 $? "empty file → keep (not a crash)"

# Non-existent file → keep
is_autodiscard_crash_output "$TEST_TMPDIR/missing.txt"
assert_eq 1 $? "missing file → keep"

# ═══════════════════════════════════════════════════════════════
# 2. find_primary_asan_in_crash_dir
# ═══════════════════════════════════════════════════════════════

mkdir -p "$TEST_TMPDIR/crash1"
echo "crash data" > "$TEST_TMPDIR/crash1/asan.txt"
result=$(find_primary_asan_in_crash_dir "$TEST_TMPDIR/crash1")
assert_match "asan.txt" "$result" "finds asan.txt"

mkdir -p "$TEST_TMPDIR/crash2"
echo "crash data" > "$TEST_TMPDIR/crash2/asan-output.txt"
result=$(find_primary_asan_in_crash_dir "$TEST_TMPDIR/crash2")
assert_match "asan-output.txt" "$result" "finds asan-output.txt"

mkdir -p "$TEST_TMPDIR/crash3"
echo "crash data" > "$TEST_TMPDIR/crash3/tc_H1.asan.txt"
result=$(find_primary_asan_in_crash_dir "$TEST_TMPDIR/crash3")
assert_match "tc_H1.asan.txt" "$result" "finds *.asan.txt pattern"

mkdir -p "$TEST_TMPDIR/crash4"
echo "crash data" > "$TEST_TMPDIR/crash4/asan_output.txt"
result=$(find_primary_asan_in_crash_dir "$TEST_TMPDIR/crash4")
assert_match "asan_output.txt" "$result" "finds asan_output.txt (underscore variant)"

mkdir -p "$TEST_TMPDIR/crash_empty"
result=$(find_primary_asan_in_crash_dir "$TEST_TMPDIR/crash_empty" || echo "none")
assert_eq "none" "$result" "empty dir returns failure"

# ═══════════════════════════════════════════════════════════════
# 3. crash_dir_has_memory_safety_asan_signal
# ═══════════════════════════════════════════════════════════════

mkdir -p "$TEST_TMPDIR/ms_crash"
cat > "$TEST_TMPDIR/ms_crash/asan.txt" <<'EOF'
==12345==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x60200000abcd
READ of size 4 at 0x60200000abcd
EOF
crash_dir_has_memory_safety_asan_signal "$TEST_TMPDIR/ms_crash"
assert_eq 0 $? "heap-buffer-overflow dir → has memory safety signal"

mkdir -p "$TEST_TMPDIR/no_ms_crash"
cat > "$TEST_TMPDIR/no_ms_crash/asan.txt" <<'EOF'
==12345==ERROR: AddressSanitizer: stack-overflow on address 0x7fff12345678
EOF
crash_dir_has_memory_safety_asan_signal "$TEST_TMPDIR/no_ms_crash"
assert_eq 1 $? "stack-overflow dir → no memory safety signal"

# Wild address SEGV → memory safety signal
mkdir -p "$TEST_TMPDIR/wild_crash"
cat > "$TEST_TMPDIR/wild_crash/asan.txt" <<'EOF'
SEGV on unknown address 0xdeadbeef1234
SCARINESS: 50 (wild-addr-read)
EOF
crash_dir_has_memory_safety_asan_signal "$TEST_TMPDIR/wild_crash"
assert_eq 0 $? "wild-addr SEGV → has memory safety signal"

# ═══════════════════════════════════════════════════════════════
# 4. crash_dir_has_web_reachability_evidence
# ═══════════════════════════════════════════════════════════════

mkdir -p "$TEST_TMPDIR/web_crash"
cat > "$TEST_TMPDIR/web_crash/report.md" <<'EOF'
This crash occurs when loading web content with an <iframe> tag.
EOF
crash_dir_has_web_reachability_evidence "$TEST_TMPDIR/web_crash"
assert_eq 0 $? "iframe mention → web reachable"

mkdir -p "$TEST_TMPDIR/web_crash2"
echo '<html><body><canvas id="c"></canvas></body></html>' > "$TEST_TMPDIR/web_crash2/testcase.html"
crash_dir_has_web_reachability_evidence "$TEST_TMPDIR/web_crash2"
assert_eq 0 $? "HTML testcase >16B → web reachable"

mkdir -p "$TEST_TMPDIR/no_web_crash"
echo "pure js engine crash" > "$TEST_TMPDIR/no_web_crash/report.md"
crash_dir_has_web_reachability_evidence "$TEST_TMPDIR/no_web_crash"
assert_eq 1 $? "no web evidence → not web reachable"

# ═══════════════════════════════════════════════════════════════
# 5. crash_dir_has_nonweb_only_markers
# ═══════════════════════════════════════════════════════════════

mkdir -p "$TEST_TMPDIR/xpc_crash"
cat > "$TEST_TMPDIR/xpc_crash/report.md" <<'EOF'
Only reachable from xpcshell
EOF
crash_dir_has_nonweb_only_markers "$TEST_TMPDIR/xpc_crash"
assert_eq 0 $? "xpcshell marker detected"

mkdir -p "$TEST_TMPDIR/jit_crash"
cat > "$TEST_TMPDIR/jit_crash/testcase.js" <<'EOF'
// TARGET: js/src/jit/WarpBuilder.cpp:BuildJIT:123
var x = getSelfHostedValue("ArrayIteratorNext");
EOF
crash_dir_has_nonweb_only_markers "$TEST_TMPDIR/jit_crash"
assert_eq 0 $? "getSelfHostedValue → nonweb marker"

mkdir -p "$TEST_TMPDIR/web_normal"
cat > "$TEST_TMPDIR/web_normal/report.md" <<'EOF'
Crashes via MutationObserver on page load
EOF
crash_dir_has_nonweb_only_markers "$TEST_TMPDIR/web_normal"
assert_eq 1 $? "web-normal → no nonweb marker"

# ═══════════════════════════════════════════════════════════════
# 6. crash_dir_security_rejection_reason (browser target — web gate active)
# ═══════════════════════════════════════════════════════════════

IS_BROWSER_TARGET=1

# Good crash: memory safety + web reachable → no rejection
mkdir -p "$TEST_TMPDIR/good_crash"
cat > "$TEST_TMPDIR/good_crash/asan.txt" <<'EOF'
==12345==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x60200000abcd
READ of size 4 at 0x60200000abcd
EOF
cat > "$TEST_TMPDIR/good_crash/report.md" <<'EOF'
Crash occurs via web content <canvas> rendering path
EOF
export LLM_DECIDE_MOCK_LEGIT_CRASH='{"legitimate":true,"reason":"valid input boundary"}'
reason=$(crash_dir_security_rejection_reason "$TEST_TMPDIR/good_crash" || true)
unset LLM_DECIDE_MOCK_LEGIT_CRASH
assert_eq "" "$reason" "good crash → no rejection reason"

# No memory safety → rejected
mkdir -p "$TEST_TMPDIR/no_impact"
cat > "$TEST_TMPDIR/no_impact/asan.txt" <<'EOF'
==12345==ERROR: AddressSanitizer: stack-overflow on address 0x7fff12345678
EOF
cat > "$TEST_TMPDIR/no_impact/report.md" <<'EOF'
Crash via web content
EOF
export LLM_DECIDE_MOCK_LEGIT_CRASH='{"legitimate":false,"reason":"missing memory-safety impact"}'
reason=$(crash_dir_security_rejection_reason "$TEST_TMPDIR/no_impact" || true)
unset LLM_DECIDE_MOCK_LEGIT_CRASH
assert_match "missing memory-safety" "$reason" "no impact → rejected for missing impact"

# Memory safety but no web → rejected (browser target)
mkdir -p "$TEST_TMPDIR/no_web"
cat > "$TEST_TMPDIR/no_web/asan.txt" <<'EOF'
==12345==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x60200000abcd
EOF
cat > "$TEST_TMPDIR/no_web/report.md" <<'EOF'
Boundary: CLI input
pure engine crash, no web path
EOF
export LLM_DECIDE_MOCK_LEGIT_CRASH='{"legitimate":false,"reason":"missing plausible web/content reachability evidence"}'
reason=$(crash_dir_security_rejection_reason "$TEST_TMPDIR/no_web" || true)
unset LLM_DECIDE_MOCK_LEGIT_CRASH
assert_match "missing plausible web" "$reason" "no web → rejected for missing web"

# Missing web/content evidence is not a static rejection anymore. A later
# legitimacy reviewer may still reject it, but reachability must not be a
# hard precondition before the testcase and ASan evidence are preserved.
mkdir -p "$TEST_TMPDIR/no_web_static_only"
cat > "$TEST_TMPDIR/no_web_static_only/asan.txt" <<'EOF'
==12345==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x60200000abcd
READ of size 4 at 0x60200000abcd
EOF
cat > "$TEST_TMPDIR/no_web_static_only/report.md" <<'EOF'
Caller contract: obeyed
Trigger source: bytes
Boundary: file bytes
EOF
unset LLM_DECIDE_MOCK_LEGIT_CRASH
reason=$(crash_dir_security_rejection_reason "$TEST_TMPDIR/no_web_static_only" || true)
assert_eq "" "$reason" "no web alone → no static rejection when LLM unavailable"

# xpcshell-only with impact → rejected
mkdir -p "$TEST_TMPDIR/xpc_only"
cat > "$TEST_TMPDIR/xpc_only/asan.txt" <<'EOF'
==12345==ERROR: AddressSanitizer: heap-use-after-free on address 0x60300000dcba
EOF
cat > "$TEST_TMPDIR/xpc_only/report.md" <<'EOF'
Boundary: CLI input
heap-use-after-free only reachable from xpcshell
EOF
export LLM_DECIDE_MOCK_LEGIT_CRASH='{"legitimate":false,"reason":"xpcshell-only trigger without web/content reachability"}'
reason=$(crash_dir_security_rejection_reason "$TEST_TMPDIR/xpc_only" || true)
unset LLM_DECIDE_MOCK_LEGIT_CRASH
assert_match "xpcshell" "$reason" "xpcshell-only → rejected with xpcshell reason"

# 6b. crash_dir_security_rejection_reason (generic target — web gate skipped)
# ═══════════════════════════════════════════════════════════════

IS_BROWSER_TARGET=0

# Memory safety but no web + generic target → accepted (no web gate)
mkdir -p "$TEST_TMPDIR/generic_noweb"
cat > "$TEST_TMPDIR/generic_noweb/asan.txt" <<'EOF'
==12345==ERROR: AddressSanitizer: heap-use-after-free on address 0x60300000dcba
EOF
cat > "$TEST_TMPDIR/generic_noweb/report.md" <<'EOF'
Boundary: file bytes
heap-use-after-free in library API, no web path
EOF
export LLM_DECIDE_MOCK_LEGIT_CRASH='{"legitimate":true,"reason":"generic file input boundary"}'
reason=$(crash_dir_security_rejection_reason "$TEST_TMPDIR/generic_noweb" || true)
unset LLM_DECIDE_MOCK_LEGIT_CRASH
assert_eq "" "$reason" "generic target + impact → no rejection (web gate skipped)"

# Same generic memory-safety candidate should be kept when the LLM is unavailable.
mkdir -p "$TEST_TMPDIR/generic_noweb_no_llm"
cat > "$TEST_TMPDIR/generic_noweb_no_llm/asan.txt" <<'EOF'
==12345==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x60200000abcd
READ of size 4 at 0x60200000abcd
EOF
cat > "$TEST_TMPDIR/generic_noweb_no_llm/report.md" <<'EOF'
Boundary: file bytes
Caller controls: malformed image bytes
Trusted caller actions: public decoder API parses caller-provided bytes
Caller contract: obeyed
Trigger source: bytes
EOF
reason=$(crash_dir_security_rejection_reason "$TEST_TMPDIR/generic_noweb_no_llm" || true)
assert_eq "" "$reason" "generic target + impact accepted when LLM unavailable"

# No impact + generic target → still rejected for missing impact
mkdir -p "$TEST_TMPDIR/generic_noimpact"
cat > "$TEST_TMPDIR/generic_noimpact/asan.txt" <<'EOF'
==12345==ERROR: AddressSanitizer: stack-overflow on address 0x7fff12345678
EOF
cat > "$TEST_TMPDIR/generic_noimpact/report.md" <<'EOF'
stack overflow in library
EOF
export LLM_DECIDE_MOCK_LEGIT_CRASH='{"legitimate":false,"reason":"missing memory-safety impact"}'
reason=$(crash_dir_security_rejection_reason "$TEST_TMPDIR/generic_noimpact" || true)
unset LLM_DECIDE_MOCK_LEGIT_CRASH
assert_match "missing memory-safety" "$reason" "generic target + no impact → still rejected"

IS_BROWSER_TARGET=0

# ═══════════════════════════════════════════════════════════════
# 7. find_primary_crash_narrative
# ═══════════════════════════════════════════════════════════════

mkdir -p "$TEST_TMPDIR/narr1"
echo "report" > "$TEST_TMPDIR/narr1/report.md"
result=$(find_primary_crash_narrative "$TEST_TMPDIR/narr1")
assert_match "report.md" "$result" "finds report.md"

mkdir -p "$TEST_TMPDIR/narr2"
echo "desc" > "$TEST_TMPDIR/narr2/description.md"
result=$(find_primary_crash_narrative "$TEST_TMPDIR/narr2")
assert_match "description.md" "$result" "finds description.md"

mkdir -p "$TEST_TMPDIR/narr3"
result=$(find_primary_crash_narrative "$TEST_TMPDIR/narr3" || echo "none")
assert_eq "none" "$result" "empty dir → no narrative"

# ═══════════════════════════════════════════════════════════════
# 8. triage_crash_dirs — exclusion-based testcase detection
# ═══════════════════════════════════════════════════════════════

IS_BROWSER_TARGET=0

# .c reproducer should be recognized as a valid testcase
mkdir -p "$RESULTS_DIR/crashes/CRASH-TC-C"
cat > "$RESULTS_DIR/crashes/CRASH-TC-C/asan_output.txt" <<'EOF'
==12345==ERROR: AddressSanitizer: heap-use-after-free on address 0x60300000dcba
READ of size 8 at 0x60300000dcba
#0 0x7fff12345678 in xmlListCopy list.c:702
EOF
cat > "$RESULTS_DIR/crashes/CRASH-TC-C/report.md" <<'EOF'
# UAF in xmlListCopy
Boundary: file bytes
Caller controls: testcase payload bytes
Trusted caller actions: public list parser entry point
Caller contract: obeyed
Trigger source: bytes
heap-use-after-free via xmlListSort
EOF
cat > "$RESULTS_DIR/crashes/CRASH-TC-C/reproducer.c" <<'EOF'
#include <libxml/list.h>
int main() {
    xmlListPtr l = xmlListCreate(NULL, NULL);
    xmlListAppend(l, (void*)1);
    xmlListSort(l);
    return 0;
}
EOF
export LLM_DECIDE_MOCK_LEGIT_CRASH='{"legitimate":true,"reason":"valid input boundary"}'
triage_crash_dirs
unset LLM_DECIDE_MOCK_LEGIT_CRASH
# The pre-bundle testcase gate should accept the C reproducer; the exact
# maintainer-bundle gate still keeps this dir pending until REPORT.md,
# reproduce.sh, exact asan.txt, and input.* exist.
if grep -q 'testcase' "$RESULTS_DIR/crashes/CRASH-TC-C/.promotion_pending" 2>/dev/null; then
  fail "triage: .c reproducer recognized as testcase" "testcase still marked missing: $(cat "$RESULTS_DIR/crashes/CRASH-TC-C/.promotion_pending")"
else
  pass "triage: .c reproducer recognized as testcase"
fi

# .py reproducer should also work
mkdir -p "$RESULTS_DIR/crashes/CRASH-TC-PY"
cat > "$RESULTS_DIR/crashes/CRASH-TC-PY/asan.txt" <<'EOF'
==12345==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x60200000abcd
#0 0x7fff12345678 in foo bar.c:42
EOF
cat > "$RESULTS_DIR/crashes/CRASH-TC-PY/report.md" <<'EOF'
Boundary: file bytes
Caller controls: testcase payload bytes
Trusted caller actions: public parser entry point
Caller contract: obeyed
Trigger source: bytes
EOF
cat > "$RESULTS_DIR/crashes/CRASH-TC-PY/reproducer.py" <<'EOF'
import ctypes
lib = ctypes.CDLL("libfoo.so")
lib.vulnerable_function(b"A" * 256)
EOF
export LLM_DECIDE_MOCK_LEGIT_CRASH='{"legitimate":true,"reason":"valid input boundary"}'
triage_crash_dirs
unset LLM_DECIDE_MOCK_LEGIT_CRASH
if grep -q 'testcase' "$RESULTS_DIR/crashes/CRASH-TC-PY/.promotion_pending" 2>/dev/null; then
  fail "triage: .py reproducer recognized as testcase" "testcase still marked missing"
else
  pass "triage: .py reproducer recognized as testcase"
fi

# Metadata-only dir should still be flagged as incomplete
mkdir -p "$RESULTS_DIR/crashes/CRASH-TC-META"
cat > "$RESULTS_DIR/crashes/CRASH-TC-META/asan.txt" <<'EOF'
==12345==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x60200000abcd
EOF
cat > "$RESULTS_DIR/crashes/CRASH-TC-META/report.md" <<'EOF'
Boundary: file bytes
Caller controls: testcase payload bytes
Trusted caller actions: public parser entry point
Caller contract: obeyed
Trigger source: bytes
EOF
echo "short" > "$RESULTS_DIR/crashes/CRASH-TC-META/notes.txt"
export LLM_DECIDE_MOCK_LEGIT_CRASH='{"legitimate":true,"reason":"valid input boundary"}'
triage_crash_dirs
unset LLM_DECIDE_MOCK_LEGIT_CRASH
if [ -f "$RESULTS_DIR/crashes/CRASH-TC-META/.promotion_pending" ]; then
  pass "triage: metadata-only dir flagged incomplete (no testcase)"
else
  fail "triage: metadata-only dir flagged incomplete (no testcase)" "missing .promotion_pending"
fi

# Canonical text inputs should be accepted, but helper binaries must not
# satisfy testcase promotion by themselves.
mkdir -p "$RESULTS_DIR/crashes/CRASH-TC-TXT"
cat > "$RESULTS_DIR/crashes/CRASH-TC-TXT/asan.txt" <<'EOF'
ASAN_RUN_HEADER: runs=5 mode=generic testcase=/does/not/matter started=x
==12345==ERROR: AddressSanitizer: stack-buffer-overflow on address 0x60200000abcd
EOF
cat > "$RESULTS_DIR/crashes/CRASH-TC-TXT/report.md" <<'EOF'
Boundary: file bytes
Caller controls: testcase payload bytes
Trusted caller actions: public parser entry point
Caller contract: obeyed
Trigger source: bytes
EOF
printf 'input-shaped text payload %080d\n' 1 > "$RESULTS_DIR/crashes/CRASH-TC-TXT/input.txt"
export LLM_DECIDE_MOCK_LEGIT_CRASH='{"legitimate":true,"reason":"valid input boundary"}'
triage_crash_dirs
unset LLM_DECIDE_MOCK_LEGIT_CRASH
if grep -qE 'testcase|input\.\*' "$RESULTS_DIR/crashes/CRASH-TC-TXT/.promotion_pending" 2>/dev/null; then
  fail "triage: input.txt recognized as testcase" "testcase/input still marked missing: $(cat "$RESULTS_DIR/crashes/CRASH-TC-TXT/.promotion_pending")"
else
  pass "triage: input.txt recognized as testcase"
fi

mkdir -p "$RESULTS_DIR/crashes/CRASH-TC-BINONLY"
cat > "$RESULTS_DIR/crashes/CRASH-TC-BINONLY/asan.txt" <<'EOF'
==12345==ERROR: AddressSanitizer: stack-buffer-overflow on address 0x60200000abcd
EOF
cat > "$RESULTS_DIR/crashes/CRASH-TC-BINONLY/report.md" <<'EOF'
Boundary: file bytes
Caller controls: testcase payload bytes
Trusted caller actions: public parser entry point
Caller contract: obeyed
Trigger source: bytes
EOF
cp /bin/echo "$RESULTS_DIR/crashes/CRASH-TC-BINONLY/helper_binary" 2>/dev/null || printf '#!/bin/sh\necho helper\n' > "$RESULTS_DIR/crashes/CRASH-TC-BINONLY/helper_binary"
chmod +x "$RESULTS_DIR/crashes/CRASH-TC-BINONLY/helper_binary"
export LLM_DECIDE_MOCK_LEGIT_CRASH='{"legitimate":true,"reason":"valid input boundary"}'
triage_crash_dirs
unset LLM_DECIDE_MOCK_LEGIT_CRASH
if [ -f "$RESULTS_DIR/crashes/CRASH-TC-BINONLY/.promotion_pending" ]; then
  pass "triage: helper binary alone does not satisfy testcase"
else
  fail "triage: helper binary alone does not satisfy testcase" "missing .promotion_pending"
fi

# ═══════════════════════════════════════════════════════════════
# 8b. Deterministic sanitizer KEEP veto over an LLM discard
# A sanitizer-confirmed memory-safety class (ASan/TSan/MSan/UBSan) must not
# be auto-rejected just because llm_triage_crash_decision returned DISCARD —
# the LLM only sees the first 6 KB of trace and can be wrong.
# ═══════════════════════════════════════════════════════════════

IS_BROWSER_TARGET=0

# Simulate an LLM that wrongly discards (rc=0 + reason on stdout).
_orig_llm_triage_crash_decision=$(declare -f llm_triage_crash_decision)
llm_triage_crash_decision() { echo "looks like a benign null-deref to me"; return 0; }

# Strong keep class: LLM discard must be vetoed → NOT moved to crashes-rejected.
mkdir -p "$RESULTS_DIR/crashes/CRASH-KEEPVETO"
cat > "$RESULTS_DIR/crashes/CRASH-KEEPVETO/asan.txt" <<'EOF'
==12345==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x60200000abcd
WRITE of size 8 at 0x60200000abcd
#0 0x7fff12345678 in app_parse parser.c:42
EOF
echo "AAAAAAAAAAAAAAAAAAAA" > "$RESULTS_DIR/crashes/CRASH-KEEPVETO/input.bin"
triage_crash_dirs >/dev/null 2>&1
if [ -d "$RESULTS_DIR/crashes/CRASH-KEEPVETO" ] && [ ! -f "$RESULTS_DIR/crashes/CRASH-KEEPVETO/.autodiscard" ]; then
  pass "triage: strong sanitizer class vetoes LLM discard"
else
  fail "triage: strong sanitizer class vetoes LLM discard" "dir was auto-discarded despite heap-buffer-overflow"
fi

# TSan data race: a non-ASan sanitizer class must also veto the LLM discard.
mkdir -p "$RESULTS_DIR/crashes/CRASH-TSAN-VETO"
cat > "$RESULTS_DIR/crashes/CRASH-TSAN-VETO/asan.txt" <<'EOF'
==12345==WARNING: ThreadSanitizer: data race (pid=123)
  Write of size 4 at 0x7b04 by thread T1:
    #0 app_parse parser.c:42
EOF
echo "AAAAAAAAAAAAAAAAAAAA" > "$RESULTS_DIR/crashes/CRASH-TSAN-VETO/input.bin"
triage_crash_dirs >/dev/null 2>&1
if [ -d "$RESULTS_DIR/crashes/CRASH-TSAN-VETO" ] && [ ! -f "$RESULTS_DIR/crashes/CRASH-TSAN-VETO/.autodiscard" ]; then
  pass "triage: TSan data race vetoes LLM discard"
else
  fail "triage: TSan data race vetoes LLM discard" "dir was auto-discarded despite data race"
fi

# MSan use-of-uninitialized-value must also veto the LLM discard.
mkdir -p "$RESULTS_DIR/crashes/CRASH-MSAN-VETO"
cat > "$RESULTS_DIR/crashes/CRASH-MSAN-VETO/asan.txt" <<'EOF'
==12345==WARNING: MemorySanitizer: use-of-uninitialized-value
    #0 0x4a1b2c in app_parse parser.c:42
EOF
echo "AAAAAAAAAAAAAAAAAAAA" > "$RESULTS_DIR/crashes/CRASH-MSAN-VETO/input.bin"
triage_crash_dirs >/dev/null 2>&1
if [ -d "$RESULTS_DIR/crashes/CRASH-MSAN-VETO" ] && [ ! -f "$RESULTS_DIR/crashes/CRASH-MSAN-VETO/.autodiscard" ]; then
  pass "triage: MSan uninit-value vetoes LLM discard"
else
  fail "triage: MSan uninit-value vetoes LLM discard" "dir was auto-discarded despite uninit-value"
fi

# Control: a non-keep class (null-deref) with the same LLM discard is still
# rejected — the veto must be class-specific, not a blanket override.
mkdir -p "$RESULTS_DIR/crashes/CRASH-NOVETO"
cat > "$RESULTS_DIR/crashes/CRASH-NOVETO/asan.txt" <<'EOF'
==12345==ERROR: AddressSanitizer: SEGV on unknown address 0x000000000000 (pc 0x7fff12345678 bp 0x7fff12345680)
Hint: address points to the zero page
SCARINESS: 10 (null-deref)
EOF
echo "AAAAAAAAAAAAAAAAAAAA" > "$RESULTS_DIR/crashes/CRASH-NOVETO/input.bin"
triage_crash_dirs >/dev/null 2>&1
if [ -f "$RESULTS_DIR/crashes-rejected/CRASH-NOVETO/.autodiscard" ] || [ ! -d "$RESULTS_DIR/crashes/CRASH-NOVETO" ]; then
  pass "triage: non-keep class still honors LLM discard"
else
  fail "triage: non-keep class still honors LLM discard" "null-deref was not rejected"
fi

# Restore the real function for any later tests.
eval "$_orig_llm_triage_crash_decision"

# ═══════════════════════════════════════════════════════════════
# 9. validate_find_gate — accepts any FIND with a report, regardless of
# target type. No sanitizer / web-reachability gate. The LLM substance
# path is covered separately in test_decision_find_quality.sh.
# ═══════════════════════════════════════════════════════════════

LLM_DECIDE_DISABLE=1
REACHABILITY_AUTO=0

IS_BROWSER_TARGET=0
mkdir -p "$RESULTS_DIR/findings/FIND-GENERIC-1"
cat > "$RESULTS_DIR/findings/FIND-GENERIC-1/description.md" <<'EOF'
# heap-buffer-overflow in libfoo parser
CATEGORY: bounds
heap-buffer-overflow in parse_input at parser.c:123
Testcase triggers OOB read via malformed input.
EOF
echo "AAAAAAAAAAAAAAAAAAA" > "$RESULTS_DIR/findings/FIND-GENERIC-1/testcase.bin"
validate_find_gate
if [ -d "$RESULTS_DIR/findings/FIND-GENERIC-1" ]; then
  pass "validate_find_gate: generic target FIND with report kept"
else
  fail "validate_find_gate: generic target FIND with report kept" "was moved"
fi

# Same FIND under browser target — no web-gate, still kept.
IS_BROWSER_TARGET=1
mkdir -p "$RESULTS_DIR/findings/FIND-BROWSER-NOWEB"
cat > "$RESULTS_DIR/findings/FIND-BROWSER-NOWEB/description.md" <<'EOF'
# heap-buffer-overflow in renderer
CATEGORY: bounds
heap-buffer-overflow in render_frame at gfx.cpp:456
EOF
echo "AAAAAAAAAAAAAAAAAAA" > "$RESULTS_DIR/findings/FIND-BROWSER-NOWEB/testcase.bin"
validate_find_gate
if [ -d "$RESULTS_DIR/findings/FIND-BROWSER-NOWEB" ]; then
  pass "validate_find_gate: browser target FIND with report kept (no web-gate)"
else
  fail "validate_find_gate: browser target FIND with report kept" "was moved"
fi

IS_BROWSER_TARGET=0
unset LLM_DECIDE_DISABLE
unset REACHABILITY_AUTO

# ═══════════════════════════════════════════════════════════════
# 10. crash_dir_contains_regex scans .c files
# ═══════════════════════════════════════════════════════════════

mkdir -p "$TEST_TMPDIR/cdir_c"
cat > "$TEST_TMPDIR/cdir_c/reproducer.c" <<'EOF'
/* UAF via xmlListSort - use-after-free */
int main() { return 0; }
EOF
crash_dir_contains_regex "$TEST_TMPDIR/cdir_c" 'use-after-free'
assert_eq 0 $? "crash_dir_contains_regex: scans .c files"

# ═══════════════════════════════════════════════════════════════
# 11. legitimate crash caller model gate
# ═══════════════════════════════════════════════════════════════

mkdir -p "$TEST_TMPDIR/legit_crash_good"
cat > "$TEST_TMPDIR/legit_crash_good/asan.txt" <<'EOF'
==12345==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x60200000abcd
EOF
cat > "$TEST_TMPDIR/legit_crash_good/report.md" <<'EOF'
Boundary: file bytes
Caller controls: PNG chunk bytes
Trusted caller actions: public decoder API reads a file buffer
Caller contract: obeyed
Trigger source: bytes
EOF
export LLM_DECIDE_MOCK_LEGIT_CRASH='{"legitimate":true,"reason":"valid input boundary"}'
crash_dir_security_rejection_reason "$TEST_TMPDIR/legit_crash_good" >/tmp/legit_crash_reason.$$ 2>/dev/null || true
unset LLM_DECIDE_MOCK_LEGIT_CRASH
assert_eq "" "$(cat /tmp/legit_crash_reason.$$)" "legitimate crash gate: valid caller + boundary accepted"
rm -f /tmp/legit_crash_reason.$$

mkdir -p "$TEST_TMPDIR/legit_crash_missing_boundary"
cat > "$TEST_TMPDIR/legit_crash_missing_boundary/asan.txt" <<'EOF'
==12345==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x60200000abcd
EOF
cat > "$TEST_TMPDIR/legit_crash_missing_boundary/report.md" <<'EOF'
# heap-buffer-overflow
Caller contract: obeyed
Trigger source: bytes
EOF
export LLM_DECIDE_MOCK_LEGIT_CRASH='{"legitimate":false,"reason":"missing untrusted input boundary evidence"}'
reason=$(crash_dir_security_rejection_reason "$TEST_TMPDIR/legit_crash_missing_boundary" || true)
unset LLM_DECIDE_MOCK_LEGIT_CRASH
assert_match "input boundary" "$reason" "legitimate crash gate: missing input boundary rejected"

mkdir -p "$TEST_TMPDIR/legit_crash_bad_callback"
cat > "$TEST_TMPDIR/legit_crash_bad_callback/asan.txt" <<'EOF'
==12345==ERROR: AddressSanitizer: heap-use-after-free on address 0x60300000dcba
EOF
cat > "$TEST_TMPDIR/legit_crash_bad_callback/report.md" <<'EOF'
Boundary: file bytes
The callback releases the active parser context before parsing continues.
EOF
export LLM_DECIDE_MOCK_LEGIT_CRASH='{"legitimate":false,"reason":"callback releases active target object"}'
reason=$(crash_dir_security_rejection_reason "$TEST_TMPDIR/legit_crash_bad_callback" || true)
unset LLM_DECIDE_MOCK_LEGIT_CRASH
# Callback-releases-active is now a contract-flag (kept in crashes/ with
# .contract-flagged sidecar) rather than a hard reject. The reason text
# is still emitted so downstream annotation can quote it, but it
# carries the contract-flag: prefix that signals annotate-in-place.
assert_match "contract-flag" "$reason" "legitimate crash gate: callback-releases-active emits contract-flag prefix"
assert_match "callback" "$reason" "legitimate crash gate: callback-releases-active reason still names the pattern"

mkdir -p "$TEST_TMPDIR/legit_crash_private"
cat > "$TEST_TMPDIR/legit_crash_private/asan.txt" <<'EOF'
==12345==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x60200000abcd
EOF
cat > "$TEST_TMPDIR/legit_crash_private/report.md" <<'EOF'
Boundary: file bytes
EOF
cat > "$TEST_TMPDIR/legit_crash_private/reproducer.c" <<'EOF'
#include "private/buf.h"
int main(void) { return 0; }
EOF
export LLM_DECIDE_MOCK_LEGIT_CRASH='{"legitimate":false,"reason":"private/internal target API used"}'
reason=$(crash_dir_security_rejection_reason "$TEST_TMPDIR/legit_crash_private" || true)
unset LLM_DECIDE_MOCK_LEGIT_CRASH
# Same: private/internal-include match is now a contract-flag, not a
# hard reject.
assert_match "contract-flag" "$reason" "legitimate crash gate: private include emits contract-flag prefix"
assert_match "private" "$reason" "legitimate crash gate: private include reason still names the concern"

# ═══════════════════════════════════════════════════════════════
# _triage_reconcile_contract_flag — re-derive a contract flag missed
# at audit time from the crash's FINAL fields (write-once staleness)
# ═══════════════════════════════════════════════════════════════
export TARGET_ATTACKER_CONTROLS_CSV="bytes"

# A crash whose finalized Trigger source sits outside the attacker boundary
# ("both" → bytes,call-sequence; call-sequence is outside [bytes]) but which
# carries NO sidecar (the flag was missed at audit time) gets flagged.
mkdir -p "$TEST_TMPDIR/reconcile_add/crashes/CRASH-RC-ADD"
cat > "$TEST_TMPDIR/reconcile_add/crashes/CRASH-RC-ADD/asan.txt" <<'EOF'
==1==ERROR: AddressSanitizer: heap-use-after-free on address 0x602000000010
EOF
cat > "$TEST_TMPDIR/reconcile_add/crashes/CRASH-RC-ADD/report.md" <<'EOF'
# heap-use-after-free
Boundary: public API callback during match
Caller controls: pattern bytes, subject bytes, and public callback call sequence
Caller contract: unspecified
Trigger source: both
EOF
d="$TEST_TMPDIR/reconcile_add/crashes/CRASH-RC-ADD"
_triage_reconcile_contract_flag "$d" CRASH-RC-ADD
if [ -f "$d/.contract-flagged" ]; then
  pass "reconcile: missed contract flag applied from final fields"
else
  fail "reconcile: missed contract flag applied from final fields" "no .contract-flagged sidecar"
fi
assert_file_contains "$d/report.md" "^## Contract concern" \
  "reconcile: Contract concern section injected"

# Idempotent / sticky: re-running does not append a second sidecar block.
_triage_reconcile_contract_flag "$d" CRASH-RC-ADD
blocks=$(grep -c "Contract-flagged by triage_crash_dirs" "$d/.contract-flagged")
assert_eq 1 "$blocks" "reconcile: idempotent — sidecar not duplicated on re-run"

# A benign crash whose trigger is fully within the attacker boundary is NOT
# flagged (additive-only: never invents a flag, no false positives).
mkdir -p "$TEST_TMPDIR/reconcile_benign/crashes/CRASH-RC-OK"
cat > "$TEST_TMPDIR/reconcile_benign/crashes/CRASH-RC-OK/asan.txt" <<'EOF'
==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000010
EOF
cat > "$TEST_TMPDIR/reconcile_benign/crashes/CRASH-RC-OK/report.md" <<'EOF'
# heap-buffer-overflow
Boundary: file bytes
Caller controls: input bytes
Caller contract: obeyed
Trigger source: bytes
EOF
d2="$TEST_TMPDIR/reconcile_benign/crashes/CRASH-RC-OK"
_triage_reconcile_contract_flag "$d2" CRASH-RC-OK
if [ -f "$d2/.contract-flagged" ]; then
  fail "reconcile: benign in-boundary crash left unflagged" "unexpected .contract-flagged"
else
  pass "reconcile: benign in-boundary crash left unflagged"
fi

# Wiring: triage_fill_reach_fields_tree reconciles every pooled crash, so a
# stale flag is restored before the scorer runs (LLM fill disabled to keep the
# test deterministic/offline).
mkdir -p "$TEST_TMPDIR/reconcile_tree/crashes/CRASH-RC-TREE"
cat > "$TEST_TMPDIR/reconcile_tree/crashes/CRASH-RC-TREE/asan.txt" <<'EOF'
==1==ERROR: AddressSanitizer: heap-use-after-free on address 0x602000000010
EOF
cat > "$TEST_TMPDIR/reconcile_tree/crashes/CRASH-RC-TREE/report.md" <<'EOF'
# heap-use-after-free
Boundary: public API callback during match
Caller controls: pattern bytes and public callback call sequence
Caller contract: unspecified
Trigger source: call-sequence
EOF
LLM_FIELD_FILL_DISABLE=1 triage_fill_reach_fields_tree "$TEST_TMPDIR/reconcile_tree" "$SCRIPT_ROOT/bin" >/dev/null 2>&1 || true
if [ -f "$TEST_TMPDIR/reconcile_tree/crashes/CRASH-RC-TREE/.contract-flagged" ]; then
  pass "reconcile: triage_fill_reach_fields_tree flags a stale pooled crash"
else
  fail "reconcile: triage_fill_reach_fields_tree flags a stale pooled crash" "no sidecar after tree run"
fi

teardown_test_env
summary
