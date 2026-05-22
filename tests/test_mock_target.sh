#!/usr/bin/env bash
# Integration tests — verify mock target repo structure and bug patterns
# Tests that the audit framework's grep-based analysis can find planted bugs
set -o pipefail
source "$(dirname "$0")/helpers.sh"
setup_test_env

MOCK_TARGET="$SCRIPT_ROOT/tests/fixtures/mock-target"

# ═══════════════════════════════════════════════════════════════
# 1. Directory structure exists (Firefox-like layout)
# ═══════════════════════════════════════════════════════════════

assert_dir_exists "$MOCK_TARGET/dom/canvas" "dom/canvas exists"
assert_dir_exists "$MOCK_TARGET/dom/html/parser" "dom/html/parser exists"
assert_dir_exists "$MOCK_TARGET/js/src/jit" "js/src/jit exists"
assert_dir_exists "$MOCK_TARGET/js/src/wasm" "js/src/wasm exists"
assert_dir_exists "$MOCK_TARGET/js/src/gc" "js/src/gc exists"
assert_dir_exists "$MOCK_TARGET/image/decoders/png" "image/decoders/png exists"
assert_dir_exists "$MOCK_TARGET/gfx/layers" "gfx/layers exists"
assert_dir_exists "$MOCK_TARGET/netwerk/protocol/http" "netwerk/protocol/http exists"
assert_dir_exists "$MOCK_TARGET/dom/svg" "dom/svg exists"
assert_dir_exists "$MOCK_TARGET/mfbt" "mfbt exists"

# ═══════════════════════════════════════════════════════════════
# 2. Source files with bug patterns are grep-detectable
# ═══════════════════════════════════════════════════════════════

# Pattern: unchecked overflow in size calculations
overflow_files=$(grep -rl 'overflow\|unchecked\|truncat' "$MOCK_TARGET" --include='*.cpp' 2>/dev/null | wc -l | tr -d ' ')
assert_neq "0" "$overflow_files" "overflow bug patterns found in mock target"

# Pattern: use-after-free (free then use)
uaf_files=$(grep -rl 'freed\|UAF\|use-after-free\|stale' "$MOCK_TARGET" --include='*.cpp' 2>/dev/null | wc -l | tr -d ' ')
assert_neq "0" "$uaf_files" "UAF bug patterns found in mock target"

# Pattern: OOB reads
oob_files=$(grep -rl 'OOB\|out-of-bounds\|overflow\|past.*allocation' "$MOCK_TARGET" --include='*.cpp' 2>/dev/null | wc -l | tr -d ' ')
assert_neq "0" "$oob_files" "OOB bug patterns found in mock target"

# ═══════════════════════════════════════════════════════════════
# 3. Specific bug classes per subsystem
# ═══════════════════════════════════════════════════════════════

# dom/canvas — heap-buffer-overflow + UAF
assert_file_contains "$MOCK_TARGET/dom/canvas/CanvasRenderingContext2D.cpp" "overflow" "canvas: overflow pattern"
assert_file_contains "$MOCK_TARGET/dom/canvas/CanvasRenderingContext2D.cpp" "UAF" "canvas: UAF pattern"

# js/src/jit — type confusion + integer truncation
assert_file_contains "$MOCK_TARGET/js/src/jit/WarpBuilder.cpp" "type" "jit: type confusion pattern"
assert_file_contains "$MOCK_TARGET/js/src/jit/WarpBuilder.cpp" "truncat" "jit: truncation pattern"

# image/decoders — palette index OOB
assert_file_contains "$MOCK_TARGET/image/decoders/png/nsPNGDecoder.cpp" "OOB" "png: OOB pattern"

# js/src/gc — use-after-free (stale pointer)
assert_file_contains "$MOCK_TARGET/js/src/gc/Nursery.cpp" "stale" "gc: stale pointer pattern"

# dom/html/parser — re-entrancy double-free
assert_file_contains "$MOCK_TARGET/dom/html/parser/nsHtml5TreeBuilder.cpp" "double-free" "parser: double-free pattern"
assert_file_contains "$MOCK_TARGET/dom/html/parser/nsHtml5TreeBuilder.cpp" "re-enter" "parser: re-entrancy pattern"

# js/src/wasm — stack-buffer-overflow
assert_file_contains "$MOCK_TARGET/js/src/wasm/WasmValidate.cpp" "stack" "wasm: stack overflow pattern"

# netwerk — integer truncation
assert_file_contains "$MOCK_TARGET/netwerk/protocol/http/nsHttpChannel.cpp" "truncat" "http: truncation pattern"

# dom/svg — use-after-free
assert_file_contains "$MOCK_TARGET/dom/svg/SVGPathElement.cpp" "UAF" "svg: UAF pattern"

# ═══════════════════════════════════════════════════════════════
# 4. Clean files exist (no false positives)
# ═══════════════════════════════════════════════════════════════

# gfx/layers — intentionally clean
assert_file_not_contains "$MOCK_TARGET/gfx/layers/Compositor.cpp" "BUG" "compositor: no bug markers"

# media/libvpx — intentionally clean with good bounds checks
assert_file_contains "$MOCK_TARGET/media/libvpx/vp9_decoder.cpp" "return false" "vp9: has bounds checks"
assert_file_not_contains "$MOCK_TARGET/media/libvpx/vp9_decoder.cpp" "BUG" "vp9: no bug markers"

# ═══════════════════════════════════════════════════════════════
# 5. Guard functions exist (audit should not flag these)
# ═══════════════════════════════════════════════════════════════

assert_file_contains "$MOCK_TARGET/dom/canvas/CanvasRenderingContext2D.cpp" "ValidateRect" "canvas: guard function present"
assert_file_contains "$MOCK_TARGET/image/decoders/png/nsPNGDecoder.cpp" "ValidateIDATChecksum" "png: guard function present"
assert_file_contains "$MOCK_TARGET/js/src/wasm/WasmValidate.cpp" "ValidateBlockType" "wasm: guard function present"

# ═══════════════════════════════════════════════════════════════
# 6. Blocklisted directories exist (audit should skip these)
# ═══════════════════════════════════════════════════════════════

assert_dir_exists "$MOCK_TARGET/dom/encoding" "blocklisted: dom/encoding exists"
assert_dir_exists "$MOCK_TARGET/third_party/rust/encoding_rs" "blocklisted: third_party/rust/encoding_rs exists"

# ═══════════════════════════════════════════════════════════════
# 7. Header files present for multi-file analysis
# ═══════════════════════════════════════════════════════════════

assert_file_exists "$MOCK_TARGET/dom/canvas/CanvasRenderingContext2D.h" "canvas header exists"
assert_file_exists "$MOCK_TARGET/mfbt/Assertions.h" "mfbt assertions header exists"

teardown_test_env
summary
