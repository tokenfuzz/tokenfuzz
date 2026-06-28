#!/usr/bin/env bash
# Integration tests — triage_crash_dirs end-to-end
# Verifies correct classification and movement of crash directories.
set -o pipefail
source "$(dirname "$0")/helpers.sh"
setup_test_env
source "$SCRIPT_ROOT/lib/triage.sh"

# This suite verifies crash movement/classification. Reachability scoring and
# the final confirm-agent have dedicated tests; leaving them on here makes each
# scenario pay unrelated post-processing cost and causes preserved fixtures to
# be revisited on later triage passes.
export REACHABILITY_AUTO=0
export CRASH_CONFIRM_AUTO=0

# ═══════════════════════════════════════════════════════════════
# 1. triage_crash_dirs — null-deref crash → rejected
# ═══════════════════════════════════════════════════════════════

mkdir -p "$RESULTS_DIR/crashes/CRASH-001-1"
cat > "$RESULTS_DIR/crashes/CRASH-001-1/asan.txt" <<'EOF'
==12345==ERROR: AddressSanitizer: SEGV on unknown address 0x000000000000
Hint: address points to the zero page
SCARINESS: 10 (null-deref)
#0 0x7fff12345678 in Foo::Bar()
EOF
echo "report" > "$RESULTS_DIR/crashes/CRASH-001-1/report.md"
echo '<html><body>test testcase content here</body></html>' > "$RESULTS_DIR/crashes/CRASH-001-1/testcase.html"

triage_crash_dirs 2>/dev/null

assert_dir_not_exists "$RESULTS_DIR/crashes/CRASH-001-1" "null-deref removed from crashes/"
assert_dir_exists "$RESULTS_DIR/crashes-rejected/CRASH-001-1" "null-deref moved to crashes-rejected/"
assert_file_exists "$RESULTS_DIR/crashes-rejected/CRASH-001-1/.autodiscard" ".autodiscard marker created"

# ═══════════════════════════════════════════════════════════════
# 2. triage_crash_dirs — MOZ_CRASH → rejected
# ═══════════════════════════════════════════════════════════════

mkdir -p "$RESULTS_DIR/crashes/CRASH-002-1"
cat > "$RESULTS_DIR/crashes/CRASH-002-1/asan.txt" <<'EOF'
Hit MOZ_CRASH(too many things) at /src/foo.cpp:42
#0 0x7fff12345678 in nsWidget::Destroy()
EOF
echo "report" > "$RESULTS_DIR/crashes/CRASH-002-1/report.md"
echo '<html><body>test testcase content here</body></html>' > "$RESULTS_DIR/crashes/CRASH-002-1/testcase.html"

triage_crash_dirs 2>/dev/null

assert_dir_not_exists "$RESULTS_DIR/crashes/CRASH-002-1" "MOZ_CRASH removed"
assert_dir_exists "$RESULTS_DIR/crashes-rejected/CRASH-002-1" "MOZ_CRASH → rejected"

# ═══════════════════════════════════════════════════════════════
# 3. triage_crash_dirs — OOM → rejected
# ═══════════════════════════════════════════════════════════════

mkdir -p "$RESULTS_DIR/crashes/CRASH-003-1"
cat > "$RESULTS_DIR/crashes/CRASH-003-1/asan.txt" <<'EOF'
==12345==ERROR: AddressSanitizer: out-of-memory (malloc-ing 4294967296 bytes)
EOF
echo "report" > "$RESULTS_DIR/crashes/CRASH-003-1/report.md"
echo '<html><body>test testcase content here</body></html>' > "$RESULTS_DIR/crashes/CRASH-003-1/testcase.html"

export LLM_DECIDE_MOCK_LEGIT_CRASH='{"legitimate":false,"reason":"missing plausible web/content reachability evidence"}'
triage_crash_dirs 2>/dev/null
unset LLM_DECIDE_MOCK_LEGIT_CRASH

assert_dir_not_exists "$RESULTS_DIR/crashes/CRASH-003-1" "OOM removed"
assert_dir_exists "$RESULTS_DIR/crashes-rejected/CRASH-003-1" "OOM → rejected"

# ═══════════════════════════════════════════════════════════════
# 4. triage_crash_dirs — real heap-buffer-overflow + web → KEPT
# ═══════════════════════════════════════════════════════════════

IS_BROWSER_TARGET=1

mkdir -p "$RESULTS_DIR/crashes/CRASH-004-1"
cat > "$RESULTS_DIR/crashes/CRASH-004-1/asan.txt" <<'EOF'
==12345==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x60200000abcd
READ of size 4 at 0x60200000abcd thread T0
#0 0x7fff12345678 in image::Decoder::ProcessChunk()
#1 0x7fff12345688 in image::ImageRequest::OnData()
EOF
cat > "$RESULTS_DIR/crashes/CRASH-004-1/REPORT.md" <<'EOF'
# Heap buffer overflow in image decoder
Triggered by loading an <img> tag with a crafted PNG.
Category: bounds
EOF
echo '<html><body><img src="test.png">large enough testcase content</body></html>' > "$RESULTS_DIR/crashes/CRASH-004-1/input.html"
cat > "$RESULTS_DIR/crashes/CRASH-004-1/reproduce.sh" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF

export LLM_DECIDE_MOCK_LEGIT_CRASH='{"legitimate":true,"reason":"web image input boundary"}'
triage_crash_dirs 2>/dev/null
unset LLM_DECIDE_MOCK_LEGIT_CRASH

assert_dir_exists "$RESULTS_DIR/crashes/CRASH-004-1" "real heap-buffer-overflow kept in crashes/"
assert_file_not_exists "$RESULTS_DIR/crashes/CRASH-004-1/.promotion_pending" "complete crash has no promotion_pending"
assert_file_not_exists "$RESULTS_DIR/crashes/CRASH-004-1/.autodiscard" "no autodiscard on real crash"
mkdir -p "$TEST_TMPDIR/kept-crashes"
mv "$RESULTS_DIR/crashes/CRASH-004-1" "$TEST_TMPDIR/kept-crashes/"

# Audit-side crash dirs already use the canonical neutral sanitizer
# filename (sanitizer.txt). export-repro keeps it as the bundle's
# canonical sanitizer artifact; the legacy asan.txt alias is no longer
# emitted (readers still accept it as a fallback).
mkdir -p "$RESULTS_DIR/crashes/CRASH-004-SAN"
cat > "$RESULTS_DIR/crashes/CRASH-004-SAN/sanitizer.txt" <<'EOF'
ASAN_RUN_HEADER: runs=5 mode=generic testcase=/does/not/matter started=x
==12345==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x60200000abcd
READ of size 4 at 0x60200000abcd thread T0
#0 0x7fff12345678 in image::Decoder::ProcessChunk()
EOF
cat > "$RESULTS_DIR/crashes/CRASH-004-SAN/REPORT.md" <<'EOF'
# Heap buffer overflow in image decoder
Triggered by loading an <img> tag with a crafted PNG.
Category: bounds
EOF
echo '<html><body><img src="test.png">large enough testcase content</body></html>' > "$RESULTS_DIR/crashes/CRASH-004-SAN/input.html"
cat > "$RESULTS_DIR/crashes/CRASH-004-SAN/reproduce.sh" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF

export LLM_DECIDE_MOCK_LEGIT_CRASH='{"legitimate":true,"reason":"web image input boundary"}'
triage_crash_dirs 2>/dev/null
unset LLM_DECIDE_MOCK_LEGIT_CRASH

assert_dir_exists "$RESULTS_DIR/crashes/CRASH-004-SAN" "sanitizer.txt-only crash kept in crashes/"
assert_file_exists "$RESULTS_DIR/crashes/CRASH-004-SAN/sanitizer.txt" "sanitizer.txt-only crash keeps canonical sanitizer output"
assert_file_not_exists "$RESULTS_DIR/crashes/CRASH-004-SAN/asan.txt" "no legacy asan.txt alias is emitted for new bundles"
assert_file_not_exists "$RESULTS_DIR/crashes/CRASH-004-SAN/.promotion_pending" "sanitizer.txt-only crash is not promotion-pending"
mv "$RESULTS_DIR/crashes/CRASH-004-SAN" "$TEST_TMPDIR/kept-crashes/"

# ═══════════════════════════════════════════════════════════════
# 5. triage_crash_dirs — incomplete crash (missing report)
# ═══════════════════════════════════════════════════════════════

mkdir -p "$RESULTS_DIR/crashes/CRASH-005-1"
cat > "$RESULTS_DIR/crashes/CRASH-005-1/asan.txt" <<'EOF'
==12345==ERROR: AddressSanitizer: heap-use-after-free on address 0x60300000dcba
#0 0x7fff12345678 in dom::Element::Destroy()
EOF
# No report.md!
echo '<html><body>Content to trigger the UAF via MutationObserver</body></html>' > "$RESULTS_DIR/crashes/CRASH-005-1/testcase.html"
# But has web reachability + memory safety → kept but incomplete
cat > "$RESULTS_DIR/crashes/CRASH-005-1/description.md" <<'EOF'
heap-use-after-free via MutationObserver
web content triggers this UAF
EOF

export LLM_DECIDE_MOCK_LEGIT_CRASH='{"legitimate":true,"reason":"web content input boundary"}'
triage_crash_dirs 2>/dev/null
unset LLM_DECIDE_MOCK_LEGIT_CRASH

assert_dir_exists "$RESULTS_DIR/crashes/CRASH-005-1" "incomplete crash still in crashes/"
assert_file_exists "$RESULTS_DIR/crashes/CRASH-005-1/.promotion_pending" "incomplete → .promotion_pending"
mv "$RESULTS_DIR/crashes/CRASH-005-1" "$TEST_TMPDIR/kept-crashes/"

# ═══════════════════════════════════════════════════════════════
# 6. triage_crash_dirs — security rejection (no web reachability, browser target)
# ═══════════════════════════════════════════════════════════════

mkdir -p "$RESULTS_DIR/crashes/CRASH-006-1"
cat > "$RESULTS_DIR/crashes/CRASH-006-1/asan.txt" <<'EOF'
==12345==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x60200000abcd
#0 0x7fff12345678 in js::jit::WarpBuilder::Build()
EOF
cat > "$RESULTS_DIR/crashes/CRASH-006-1/REPORT.md" <<'EOF'
# Heap buffer overflow in JIT compiler
Pure engine-level crash in warp compiler internals.
Not reachable from any known input path.
EOF
echo 'function f(){ for (var i=0;i<1000;i++) eval("x="+i); } f();' > "$RESULTS_DIR/crashes/CRASH-006-1/input.js"
cat > "$RESULTS_DIR/crashes/CRASH-006-1/reproduce.sh" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF

export LLM_DECIDE_MOCK_LEGIT_CRASH='{"legitimate":false,"reason":"missing plausible web/content reachability evidence"}'
triage_crash_dirs 2>/dev/null
unset LLM_DECIDE_MOCK_LEGIT_CRASH

assert_dir_not_exists "$RESULTS_DIR/crashes/CRASH-006-1" "no-web crash removed"
assert_dir_exists "$RESULTS_DIR/crashes-rejected/CRASH-006-1" "no-web crash → rejected"
assert_file_contains "$RESULTS_DIR/crashes-rejected/CRASH-006-1/.autodiscard" "web" "rejection reason mentions web"

IS_BROWSER_TARGET=0

# ═══════════════════════════════════════════════════════════════
# 7. triage_crash_dirs — stack-overflow → rejected
# ═══════════════════════════════════════════════════════════════

mkdir -p "$RESULTS_DIR/crashes/CRASH-007-1"
cat > "$RESULTS_DIR/crashes/CRASH-007-1/asan.txt" <<'EOF'
==12345==ERROR: AddressSanitizer: stack-overflow on address 0x7fff12345678
EOF
echo "report" > "$RESULTS_DIR/crashes/CRASH-007-1/report.md"
echo '<html><body>test testcase content here content</body></html>' > "$RESULTS_DIR/crashes/CRASH-007-1/testcase.html"

export LLM_DECIDE_MOCK_LEGIT_CRASH='{"legitimate":true,"reason":"web content input boundary"}'
triage_crash_dirs 2>/dev/null
unset LLM_DECIDE_MOCK_LEGIT_CRASH

assert_dir_not_exists "$RESULTS_DIR/crashes/CRASH-007-1" "stack-overflow removed"
assert_dir_exists "$RESULTS_DIR/crashes-rejected/CRASH-007-1" "stack-overflow → rejected"

# ═══════════════════════════════════════════════════════════════
# 8. triage_crash_dirs — Rust panic → rejected
# ═══════════════════════════════════════════════════════════════

mkdir -p "$RESULTS_DIR/crashes/CRASH-008-1"
cat > "$RESULTS_DIR/crashes/CRASH-008-1/asan.txt" <<'EOF'
thread 'main' panicked at 'index out of bounds', src/lib.rs:42
EOF
echo "report" > "$RESULTS_DIR/crashes/CRASH-008-1/report.md"
echo '<html><body>test testcase content here content</body></html>' > "$RESULTS_DIR/crashes/CRASH-008-1/testcase.html"

export LLM_DECIDE_MOCK_LEGIT_CRASH='{"legitimate":true,"reason":"web content input boundary"}'
triage_crash_dirs 2>/dev/null
unset LLM_DECIDE_MOCK_LEGIT_CRASH

assert_dir_not_exists "$RESULTS_DIR/crashes/CRASH-008-1" "Rust panic removed"
assert_dir_exists "$RESULTS_DIR/crashes-rejected/CRASH-008-1" "Rust panic → rejected"

# ═══════════════════════════════════════════════════════════════
# 8b. triage_crash_dirs — findings-only runtime diagnostic → FIND
# ═══════════════════════════════════════════════════════════════

mkdir -p "$RESULTS_DIR/crashes/CRASH-008-FIND"
cat > "$RESULTS_DIR/crashes/CRASH-008-FIND/asan.txt" <<'EOF'
Traceback (most recent call last):
  File "reproducer.py", line 2, in <module>
    parser.handle(payload)
IndexError: list index out of range
EOF
cat > "$RESULTS_DIR/crashes/CRASH-008-FIND/report.md" <<'EOF'
# Runtime diagnostic in parser authorization state
Boundary: file bytes
Caller controls: testcase payload bytes
Trusted caller actions: public parser entry point
Caller contract: obeyed
Trigger source: crafted input
Strategy: S2

The testcase reaches an authorization-state exception through the documented
file parser boundary. In findings-only mode this is not a sanitizer crash
bundle, but it is a concrete runtime diagnostic that belongs under findings/.
EOF
cat > "$RESULTS_DIR/crashes/CRASH-008-FIND/reproducer.py" <<'EOF'
payload = b"caller-controlled parser state"
raise IndexError("list index out of range")
EOF

TARGET_SANITIZERS_EXPLICITLY_DISABLED=1 triage_crash_dirs 2>/dev/null

assert_dir_not_exists "$RESULTS_DIR/crashes/CRASH-008-FIND" "findings-only runtime diagnostic removed from crashes/"
assert_dir_exists "$RESULTS_DIR/findings/FIND-008-FIND" "findings-only runtime diagnostic demoted to findings/"
assert_dir_not_exists "$RESULTS_DIR/crashes-rejected/CRASH-008-FIND" "findings-only runtime diagnostic not rejected"
assert_file_not_exists "$RESULTS_DIR/findings/FIND-008-FIND/.promotion_pending" "findings-only runtime diagnostic not blocked by bundle gate"
assert_file_contains "$RESULTS_DIR/findings/FIND-008-FIND/report.md" "^## Triage decision" "demoted FIND carries triage decision"

# ═══════════════════════════════════════════════════════════════
# 9. triage_crash_dirs — trigger outside attacker_controls is a CONTRACT-FLAG.
# The dir STAYS in crashes/ with a .contract-flagged sidecar +
# "## Contract concern" report block. The reachability scorer recomputes the
# same verdict from Trigger source and target.toml. crashes-rejected/ is
# reserved for non-security classes (OOM/panic/null-deref/no-signal/TTL).
# ═══════════════════════════════════════════════════════════════

mkdir -p "$RESULTS_DIR/crashes/CRASH-009-1"
cat > "$RESULTS_DIR/crashes/CRASH-009-1/asan.txt" <<'EOF'
==12345==ERROR: AddressSanitizer: heap-use-after-free on address 0x60300000dcba
EOF
cat > "$RESULTS_DIR/crashes/CRASH-009-1/REPORT.md" <<'EOF'
Boundary: file bytes
Caller controls: file bytes and public API call sequence
Caller contract: unspecified
Trigger source: both
EOF
cat > "$RESULTS_DIR/crashes/CRASH-009-1/input.c" <<'EOF'
static void callback(void *ctx) { free(ctx); }
int main(void) { return 0; }
EOF
cat > "$RESULTS_DIR/crashes/CRASH-009-1/reproduce.sh" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF

triage_crash_dirs 2>/dev/null

assert_dir_exists "$RESULTS_DIR/crashes/CRASH-009-1" "contract-flagged crash stays in crashes/"
assert_dir_not_exists "$RESULTS_DIR/crashes-rejected/CRASH-009-1" "contract-flagged crash is NOT moved to crashes-rejected/"
assert_file_exists "$RESULTS_DIR/crashes/CRASH-009-1/.contract-flagged" "contract-flag sidecar created in crashes/"
assert_file_contains "$RESULTS_DIR/crashes/CRASH-009-1/.contract-flagged" "call-sequence" "contract-flag sidecar names the concern"
assert_file_contains "$RESULTS_DIR/crashes/CRASH-009-1/REPORT.md" "^## Contract concern" "report carries Contract concern section"

# ═══════════════════════════════════════════════════════════════
# 10. Index log gets entries for rejected crashes and contract flags
# ═══════════════════════════════════════════════════════════════

assert_file_contains "$INDEX" "REJECT" "index log has REJECT entries"
assert_file_contains "$INDEX" "CONTRACT-FLAG" "index log has CONTRACT-FLAG entries for contract-concerned crashes kept in crashes/"

teardown_test_env
summary
