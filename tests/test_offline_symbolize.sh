#!/usr/bin/env bash
# Tests for decoupled (symbolize=0 + offline) sanitizer symbolization:
#   - lib/clusterfuzz_symbolizer.py  (borrowed ClusterFuzz/LLVM symbolizer)
#   - lib/sanitizer.sh               (sanitizer_symbolize_file / _path helpers)
#
# Why this exists: on macOS the in-process ASan symbolizer (atos) can hang or
# run long while building a report, so under the run timeout the report is
# killed after the "ERROR:" header but before any frames print. A frameless
# report has no crash_state, so bin/cluster-crashes drops the crash into a
# per-crash `pending:<id>` cluster and dedup silently stops. Running with
# symbolize=0 emits raw `#N 0xpc (module+0xoffset)` frames immediately, and we
# resolve them offline. These tests pin that the offline pass (a) resolves user
# frames, (b) keeps the module suffix on source-less runtime frames so the
# existing ignore rules still drop them, (c) strips the arm64e arch suffix, and
# (d) falls open to the raw frames when no symbolizer is available.
#
# Fixtures use neutral placeholder symbols (app_parse / apptool), never a real
# target's symbols.

set -o pipefail
source "$(dirname "$0")/helpers.sh"
setup_test_env

SYM_PY="$SCRIPT_ROOT/lib/clusterfuzz_symbolizer.py"
assert_file_exists "$SYM_PY" "fixture: symbolizer module present"

python3 -m py_compile "$SYM_PY" 2>/dev/null
assert_eq 0 $? "clusterfuzz_symbolizer.py: compiles"

# ── A stub llvm-symbolizer ───────────────────────────────────────────────────
# Speaks the llvm-symbolizer pipe protocol: for each `"<binary>" <offset>` line
# on stdin it emits `function\nfile:line:col\n\n`. Keyed on the module offset so
# the test is deterministic and needs neither a real binary nor a real LLVM.
# Lives under bin/ so it can be injected via LLVM_PREFIX (which audit_llvm_tool
# checks ahead of PATH and the system Homebrew toolchain).
mkdir -p "$TEST_TMPDIR/bin"
STUB="$TEST_TMPDIR/bin/llvm-symbolizer"
cat > "$STUB" <<'PY'
#!/usr/bin/env python3
import sys
# Ignore the flags ASan-style callers pass (--default-arch, --inlining, ...).
for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    off = line.rsplit(' ', 1)[-1]
    if off == '0x100000934':          # a user frame with source
        sys.stdout.write('app_parse\n/src/app/parse.c:42:10\n\n')
    elif off == '0x3aa1c':            # sanitizer runtime: function, no source
        sys.stdout.write('wrap_strcpy\n??:0:0\n\n')
    else:                             # unresolved
        sys.stdout.write('??\n??:0:0\n\n')
    sys.stdout.flush()
PY
chmod +x "$STUB"

# ── Raw report as emitted with symbolize=0 (neutral placeholders) ────────────
RAW="$TEST_TMPDIR/raw.txt"
cat > "$RAW" <<'EOF'
=================================================================
==12345==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000010 at pc 0x000102d08934 bp 0x16d0f6ad0 sp 0x16d0f6280
WRITE of size 4 at 0x602000000010 thread T0
    #0 0x00010342aa1c  (/build/asan/libclang_rt.asan_osx_dynamic.dylib:arm64e+0x3aa1c)
    #1 0x000102d08934  (/build/asan/apptool:arm64+0x100000934)
SUMMARY: AddressSanitizer: heap-buffer-overflow (/build/asan/apptool:arm64+0x100000934)
EOF

# ── Symbolize through the stub ───────────────────────────────────────────────
OUT="$TEST_TMPDIR/out.txt"
python3 "$SYM_PY" --llvm-symbolizer "$STUB" < "$RAW" > "$OUT" 2>/dev/null
assert_eq 0 $? "symbolize: exits 0"

out="$(cat "$OUT")"
assert_match '#1 0x000102d08934 in app_parse /src/app/parse\.c:42:10' "$out" \
  "user frame resolved to function + source location"

# DIVERGENCE under test: source-less runtime frame keeps its (module) suffix so
# the `.*asan_osx_dynamic\.dylib` ignore rule still fires.
assert_match '#0 0x00010342aa1c in wrap_strcpy \(libclang_rt\.asan_osx_dynamic\.dylib\)' \
  "$out" "runtime frame keeps module basename for ignore matching"

# arm64e arch suffix is stripped from the module (is_valid_arch divergence).
assert_not_match ':arm64e' "$out" "arm64e arch suffix stripped from module path"

# Non-frame lines (header, SUMMARY) pass through untouched.
assert_match 'AddressSanitizer: heap-buffer-overflow' "$out" "ERROR header preserved"

# ── crash_state: the whole point — a real state, runtime frame ignored ───────
sig="$(python3 - "$OUT" <<PY
import sys
sys.path.insert(0, "$SCRIPT_ROOT/lib")
import stack_frames
print(stack_frames.crash_signature(open(sys.argv[1]).read()))
PY
)"
assert_match 'app_parse' "$sig" "crash_state contains the user frame"
assert_not_match 'wrap_strcpy' "$sig" "crash_state excludes the sanitizer runtime frame"
assert_not_match 'pending' "$sig" "crash_state is real, not a pending fallback"

# ── arm64e is recognised as a valid arch ─────────────────────────────────────
arch_ok="$(python3 - <<PY
import sys
sys.path.insert(0, "$SCRIPT_ROOT/lib")
import clusterfuzz_symbolizer as s
print(s.is_valid_arch('arm64e') and s.is_valid_arch('arm64'))
PY
)"
assert_eq "True" "$arch_ok" "is_valid_arch accepts arm64e"

# ── platform fallback: no llvm-symbolizer, resolve via the OS tool ───────────
# Why we keep ClusterFuzz's whole symbolizer chain rather than requiring
# llvm-symbolizer: when it is absent the chain falls back to the platform tool
# — atos on macOS (Apple clang ships it, not llvm-symbolizer), addr2line on
# Linux (SystemSymbolizerFactory picks by platform). Stub whichever tool this
# host's symbolizer will actually invoke, so the fallback path has real coverage
# on both. The two tools speak different pipe protocols, hence the two stubs.
FALLBACKDIR="$TEST_TMPDIR/fallbackbin"
mkdir -p "$FALLBACKDIR"
if audit_is_darwin; then
  cat > "$FALLBACKDIR/atos" <<'PY'
#!/usr/bin/env python3
# atos pipe protocol: read "0x<offset>" lines, emit "func (in module) (file:line)".
import sys
for line in sys.stdin:
    off = line.strip()
    if not off:
        continue
    if off == '0x100000934':
        sys.stdout.write('app_parse (in apptool) (parse.c:42)\n')
    else:
        sys.stdout.write('0x0 (in apptool) (??:0)\n')
    sys.stdout.flush()
PY
  chmod +x "$FALLBACKDIR/atos"
else
  cat > "$FALLBACKDIR/addr2line" <<'PY'
#!/usr/bin/env python3
# addr2line -f protocol: per offset line, emit "function\nfile:line\n".
import sys
for line in sys.stdin:
    off = line.strip()
    if not off:
        continue
    if off == '0x100000934':
        sys.stdout.write('app_parse\nparse.c:42\n')
    else:
        sys.stdout.write('??\n??:0\n')
    sys.stdout.flush()
PY
  chmod +x "$FALLBACKDIR/addr2line"
fi
FB_OUT="$TEST_TMPDIR/fallback_out.txt"
# No llvm-symbolizer on PATH (only the platform stub); --llvm-symbolizer "" empty.
env -u LLVM_SYMBOLIZER PATH="$FALLBACKDIR:/usr/bin:/bin" \
  python3 "$SYM_PY" --llvm-symbolizer "" < "$RAW" > "$FB_OUT" 2>/dev/null
assert_eq 0 $? "platform fallback: exits 0"
assert_file_contains "$FB_OUT" 'in app_parse parse\.c:42' \
  "platform fallback: user frame resolved via the OS symbolizer (no llvm-symbolizer)"

# ── Shell helpers ────────────────────────────────────────────────────────────
source "$SCRIPT_ROOT/lib/timeout.sh"
source "$SCRIPT_ROOT/lib/platform.sh"
source "$SCRIPT_ROOT/lib/sanitizer.sh"

# Gate: symbolize=0 is only enabled when some offline symbolizer is reachable.
# With the stub llvm-symbolizer injected via LLVM_PREFIX it must report true.
LLVM_PREFIX="$TEST_TMPDIR" sanitizer_symbolize_available
assert_eq 0 $? "sanitizer_symbolize_available: true when a symbolizer exists"

# Gate must be FALSE when the offline symbolizer module itself is missing, even
# if a symbolizer binary is reachable. Otherwise a tree that shipped the
# sanitizer.sh change but not clusterfuzz_symbolizer.py would enable symbolize=0
# and then never re-symbolize (sanitizer_symbolize_file falls open), leaking raw
# frames into clustering.
rc=0
LLVM_PREFIX="$TEST_TMPDIR" _SANITIZER_SYMBOLIZER_PY="$TEST_TMPDIR/no-such-helper.py" \
  sanitizer_symbolize_available || rc=$?
assert_eq 1 "$rc" "sanitizer_symbolize_available: false when the helper module is absent"

INPLACE="$TEST_TMPDIR/inplace.txt"
cp "$RAW" "$INPLACE"
LLVM_PREFIX="$TEST_TMPDIR" sanitizer_symbolize_file "$INPLACE"
assert_eq 0 $? "sanitizer_symbolize_file: returns 0"
assert_file_contains "$INPLACE" 'in app_parse /src/app/parse\.c:42:10' \
  "sanitizer_symbolize_file: rewrote file in place"

# Empty file: best-effort no-op, never errors.
EMPTY="$TEST_TMPDIR/empty.txt"
: > "$EMPTY"
LLVM_PREFIX="$TEST_TMPDIR" sanitizer_symbolize_file "$EMPTY"
assert_eq 0 $? "sanitizer_symbolize_file: no-op on empty file"

# A binary the symbolizer can't resolve leaves the raw frames in place (fall
# open) and still returns 0 — the stub only knows the fixture offsets, so an
# unknown module stays as captured.
UNTOUCHED="$TEST_TMPDIR/untouched.txt"
cat > "$UNTOUCHED" <<'EOF'
    #0 0x000109999999  (/build/asan/unknownmod:arm64+0xfeed)
EOF
LLVM_PREFIX="$TEST_TMPDIR" sanitizer_symbolize_file "$UNTOUCHED"
assert_eq 0 $? "sanitizer_symbolize_file: returns 0 on unresolvable frames"
assert_file_contains "$UNTOUCHED" 'in unknownmod' \
  "sanitizer_symbolize_file: unresolved frame degrades to module name"

teardown_test_env
summary