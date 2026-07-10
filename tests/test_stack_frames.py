#!/usr/bin/env python3
"""Regression tests for ClusterFuzz-style interesting frame selection."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "lib"))

import stack_frames  # noqa: E402

PASSED = 0
FAILED = 0


def ok(cond: bool, name: str, detail: str = "") -> None:
    global PASSED, FAILED
    if cond:
        PASSED += 1
        print(f"  \033[0;32m✓\033[0m {name}")
    else:
        FAILED += 1
        print(f"  \033[0;31m✗\033[0m {name}")
        if detail:
            print(f"    {detail}")


def assert_eq(expected: str, actual: str, name: str) -> None:
    ok(expected == actual, name, f"expected={expected!r} actual={actual!r}")


strlen_first = """\
==111==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x1 at pc 0x2
READ of size 2 at 0x1 thread T0
    #0 0x0001038fec80 in strlen+0x400 (libclang_rt.asan_osx_dynamic.dylib:arm64e+0x3ec80)
    #1 0x000102dc5044 in app_pack_part part_io.c:1304
    #2 0x000102d14c64 in app_collect_form form_data.c
    #3 0x000102d14c28 in main harness.c:116

0x1 is located 0 bytes after 1-byte region [0x0,0x1)
allocated by thread T0 here:
    #0 0x000103901164 in malloc+0x78 (libclang_rt.asan_osx_dynamic.dylib:arm64e+0x41164)
    #1 0x000102d14aaa in make_buffer harness.c:41

SUMMARY: AddressSanitizer: heap-buffer-overflow part_io.c:1304 in app_pack_part
"""

frame = stack_frames.first_interesting_frame(strlen_first)
assert_eq("app_pack_part", frame.function if frame else "", "skips ClusterFuzz-ignored strlen frame")
assert_eq("part_io.c:1304", frame.location if frame else "", "keeps source location for first interesting frame")

frames = stack_frames.interesting_frames(strlen_first, want=5)
assert_eq("2", str(len(frames)), "only crashing stack frames are considered before allocation stack")
assert_eq("app_collect_form", frames[1].function, "keeps next interesting caller")

all_ignored = """\
==222==ERROR: AddressSanitizer: heap-buffer-overflow
    #0 0x1 in __asan_memcpy+0x20 (libclang_rt.asan_osx_dynamic.dylib:arm64e+0x123)
    #1 0x2 in main harness.c:1

allocated by thread T0 here:
    #0 0x3 in malloc+0x20 (libclang_rt.asan_osx_dynamic.dylib:arm64e+0x456)
    #1 0x4 in product_allocator alloc.c:7
SUMMARY: AddressSanitizer: heap-buffer-overflow
"""
ok(stack_frames.first_interesting_frame(all_ignored) is None,
   "does not fall through into allocation stack when crash stack is all ignored")

uaf_short_stacks = """\
==444==ERROR: AddressSanitizer: heap-use-after-free on address 0x1 at pc 0x2
READ of size 4 at 0x1 thread T0
    #0 0x10 in consume_stale src/uaf.c:10

freed by thread T0 here:
    #0 0x20 in free+0x40 (libclang_rt.asan_osx_dynamic.dylib:arm64e+0x222)
    #1 0x21 in release_node src/lifetime.c:20
    #2 0x22 in drop_owner src/lifetime.c:30

previously allocated by thread T0 here:
    #0 0x30 in malloc+0x40 (libclang_rt.asan_osx_dynamic.dylib:arm64e+0x333)
    #1 0x31 in allocate_node src/lifetime.c:40
SUMMARY: AddressSanitizer: heap-use-after-free src/uaf.c:10 in consume_stale
"""
frames = stack_frames.interesting_frames(uaf_short_stacks, want=5)
assert_eq("3", str(len(frames)), "fills top-3 crash state across UAF freed stack")
assert_eq("consume_stale,release_node,drop_owner",
          ",".join(frame.function for frame in frames),
          "uses crash stack then freed stack before allocation stop marker")
ok(all(frame.function != "allocate_node" for frame in frames),
   "does not include previously allocated stack in top-3 crash state")

two_crash_one_free = """\
==555==ERROR: AddressSanitizer: heap-use-after-free on address 0x1 at pc 0x2
READ of size 4 at 0x1 thread T0
    #0 0x10 in consume_stale src/uaf.c:10
    #1 0x11 in caller src/uaf.c:11

freed by thread T0 here:
    #0 0x20 in free+0x40 (libclang_rt.asan_osx_dynamic.dylib:arm64e+0x222)
    #1 0x21 in release_node src/lifetime.c:20
    #2 0x22 in drop_owner src/lifetime.c:30

previously allocated by thread T0 here:
    #0 0x30 in malloc+0x40 (libclang_rt.asan_osx_dynamic.dylib:arm64e+0x333)
    #1 0x31 in allocate_node src/lifetime.c:40
SUMMARY: AddressSanitizer: heap-use-after-free src/uaf.c:10 in consume_stale
"""
frames = stack_frames.interesting_frames(two_crash_one_free, want=5)
assert_eq("consume_stale,caller,release_node",
          ",".join(frame.function for frame in frames),
          "caps at three interesting frames across crash and freed stacks")

symbolized_variant = """\
==333==ERROR: AddressSanitizer: heap-buffer-overflow
    #0: 0xabc in __memcpy_avx_unaligned
    #1: 0xdef in parse_record src/parser.c:88
SUMMARY: AddressSanitizer: heap-buffer-overflow
"""
frame = stack_frames.first_interesting_frame(symbolized_variant)
assert_eq("parse_record", frame.function if frame else "", "parses colon-style ASan frame numbers")
assert_eq("src/parser.c:88", frame.location if frame else "", "parses colon-style frame location")


# macOS symbolizer strips paths and reports libc++ headers as bare basenames
# ("string:2095"), so ClusterFuzz's path-based ``.*/libc\\+\\+`` rule never
# fires. We filter the libc++ / libstdc++ inline-namespace symbol prefixes
# (``std::__1::`` / ``std::__cxx11::``) as a local divergence — see the
# module docstring.
macos_libcxx_uaf = """\
==18351==ERROR: AddressSanitizer: heap-use-after-free on address 0x1 at pc 0x2
READ of size 1 at 0x1 thread T0
    #0 0x10 in std::__1::basic_string<char>::__is_long[abi:nqe210106]() const string:2095
    #1 0x11 in std::__1::basic_string<char>::size[abi:nqe210106]() const string:1280
    #2 0x12 in nlohmann::detail::serializer::dump_escaped(...) serializer.hpp:401
    #3 0x13 in nlohmann::detail::serializer::dump(...) serializer.hpp:250
    #4 0x14 in nlohmann::basic_json::dump(...) const json.hpp:1323
    #5 0x15 in main harness.cpp:70
SUMMARY: AddressSanitizer: heap-use-after-free
"""
sig = stack_frames.crash_signature(macos_libcxx_uaf)
ok(not any("basic_string" in line for line in sig),
   "skips macOS bare-basename libc++ frames (std::__1::basic_string)",
   detail=f"signature={sig!r}")
ok(sig and "dump_escaped" in sig[0],
   "top frame after filtering is the application-level dump_escaped",
   detail=f"top={sig[0] if sig else None!r}")

macos_libstdcxx_uaf = """\
==18352==ERROR: AddressSanitizer: heap-use-after-free
READ of size 1 at 0x1 thread T0
    #0 0x10 in std::__cxx11::basic_string<char>::size() const basic_string.h:932
    #1 0x11 in app::serialize(std::__cxx11::basic_string<char> const&) serializer.cc:42
SUMMARY: AddressSanitizer: heap-use-after-free
"""
sig = stack_frames.crash_signature(macos_libstdcxx_uaf)
ok(sig and sig[0].startswith("app::serialize"),
   "skips libstdc++ __cxx11 inline-namespace frames",
   detail=f"top={sig[0] if sig else None!r}")

# Symbols with a leading return type (free templates, operator overloads,
# allocator deallocate functions) must still be caught — `void std::__1::…`
# and `bool std::__1::operator==<…>` should be filtered the same as
# `std::__1::basic_string::__is_long`.
return_type_libcxx = """\
==18353==ERROR: AddressSanitizer: heap-use-after-free
READ of size 1 at 0x1 thread T0
    #0 0x10 in bool std::__1::operator==<char>(std::__1::basic_string<char> const&, char const*) string:1234
    #1 0x11 in void std::__1::allocator<int>::deallocate(int*, unsigned long) allocator.h:120
    #2 0x12 in app::compare(std::__1::basic_string<char> const&) compare.cc:99
SUMMARY: AddressSanitizer: heap-use-after-free
"""
sig = stack_frames.crash_signature(return_type_libcxx)
ok(sig and sig[0].startswith("app::compare"),
   "skips libc++ frames with leading return type (void/bool prefixed)",
   detail=f"top={sig[0] if sig else None!r}")

# Application code that takes a std::__1 type as an argument must NOT be
# filtered — the `std::__1::` appears inside the parameter list, not as the
# function's own namespace.
app_takes_libcxx_arg = """\
==18354==ERROR: AddressSanitizer: heap-buffer-overflow
READ of size 1 at 0x1 thread T0
    #0 0x10 in app::serialize(std::__1::vector<int> const&) serialize.cc:42
SUMMARY: AddressSanitizer: heap-buffer-overflow
"""
frame = stack_frames.first_interesting_frame(app_takes_libcxx_arg)
ok(frame is not None and frame.function.startswith("app::serialize"),
   "does NOT filter application functions that take std::__1 types as args",
   detail=f"function={frame.function if frame else None!r}")

# A frame whose source lives under a `maint/` directory must NOT be dropped.
# The ignore list has a bare-identifier `^main` function rule; the file path
# `maint/utf8.c` starts with "main", so matching the rule against the location
# path used to silently swallow the frame. The ignore check now runs against
# the function name + raw line only (raw starts with `#<n> 0x…`, so `^main`
# cannot false-match it), keeping path-based rules working via `raw`.
maint_path_frame = """\
==18355==ERROR: AddressSanitizer: stack-buffer-overflow
WRITE of size 1 at 0x1 thread T0
    #0 0x10 in utf8_tool_main maint/utf8.c:361
    #1 0x11 in main utf8_cli_harness.c:27
SUMMARY: AddressSanitizer: stack-buffer-overflow
"""
frame = stack_frames.first_interesting_frame(maint_path_frame)
ok(frame is not None and frame.function == "utf8_tool_main",
   "does NOT drop a frame whose source lives under maint/ (^main vs maint/ path)",
   detail=f"function={frame.function if frame else None!r}")

macos_start_only = """\
==18355==ERROR: AddressSanitizer: stack-buffer-overflow
WRITE of size 1 at 0x1 thread T0
    #0 0x10 in main+0x1aac (testbin:arm64+0x100002f94)
    #1 0x11 in start+0x1b4c (dyld:arm64e+0x1fda0)
SUMMARY: AddressSanitizer: stack-buffer-overflow (testbin:arm64+0x100002f94) in main+0x1aac
"""
ok(stack_frames.first_interesting_frame(macos_start_only) is None,
   "skips macOS dyld start+ tail frames instead of using them as dedup keys")

# Offline symbolization (symbolize=0 + atos/llvm) renders the same dyld entry
# frame as the bare symbol `start (dyld)` — no `+offset` — which the native
# `^start\+0x` rule does NOT catch. Without the `\bstart \(dyld\)` rule this
# frame becomes the crash state and over-merges unrelated main-only CLI crashes.
macos_start_only_offline = """\
==18355==ERROR: AddressSanitizer: stack-buffer-overflow
WRITE of size 1 at 0x1 thread T0
    #0 0x10 in main (testbin)
    #1 0x11 in start (dyld)
SUMMARY: AddressSanitizer: stack-buffer-overflow (testbin:arm64+0x100002f94) in main
"""
ok(stack_frames.first_interesting_frame(macos_start_only_offline) is None,
   "skips offline-symbolized `start (dyld)` dyld tail frame (no +offset spelling)")

# Precision: a target function genuinely named `start` (with its own source or
# module, never `(dyld)`) must survive — the rule keys on the dyld module.
user_start_fn = """\
==18355==ERROR: AddressSanitizer: heap-buffer-overflow
WRITE of size 1 at 0x1 thread T0
    #0 0x10 in start /src/app/run.c:42
    #1 0x11 in main (testbin)
SUMMARY: AddressSanitizer: heap-buffer-overflow
"""
_usf = stack_frames.first_interesting_frame(user_start_fn)
ok(_usf is not None and _usf.function == "start",
   "keeps a real target function named `start` (dyld rule keys on the module)",
   detail=f"function={_usf.function if _usf else None!r}")

# ClusterFuzz _filter_stack_frame port: the function name that enters the
# crash state has its parameter list, [abi:...] / [clone] suffixes, and
# anonymous-namespace markers stripped. Template args in <...> are kept.
assert_eq(
    "sampledb::Engine::Store::set_blob",
    stack_frames.filter_function_name(
        "sampledb::Engine::Store::set_blob(unsigned int, "
        "std::__1::vector<unsigned char, std::__1::allocator<unsigned char>>)"
    ),
    "filter_function_name drops the C++ parameter list",
)
assert_eq("foo", stack_frames.filter_function_name("foo[abi:cxx11]()"),
          "filter_function_name drops [abi:...] demangler suffix")
assert_eq("app::compare<int>",
          stack_frames.filter_function_name("app::compare<int>(int)"),
          "filter_function_name keeps template args, drops params")
assert_eq("mod::func", stack_frames.filter_function_name("module!mod::func(int)"),
          "filter_function_name takes the segment after the last '!'")
assert_eq("ns::g", stack_frames.filter_function_name("(anonymous namespace)::ns::g()"),
          "filter_function_name strips the anonymous-namespace marker")
assert_eq("check_opcode_types",
          stack_frames.filter_function_name("check_opcode_types+0xc4"),
          "filter_function_name strips trailing +0x{hex} symbol offset (no parens)")
assert_eq("check_opcode_types",
          stack_frames.filter_function_name("check_opcode_types+0xC4"),
          "filter_function_name strips trailing +0x{HEX} (uppercase hex digits)")
assert_eq("foo",
          stack_frames.filter_function_name("foo+0x1aac(int)"),
          "filter_function_name strips +0x{hex} when followed by a parameter list")
# Operator-overload symbols end in `+`, `++`, `+=` — the `+0x{hex}` stripper
# must not eat them. `+` is not in the `[xX0-9a-fA-F]` class and the `+{hex}`
# pattern requires at least one hex char, so a bare trailing `+` survives.
assert_eq("Foo::operator+",
          stack_frames.filter_function_name("Foo::operator+(int)"),
          "filter_function_name preserves operator+ (single +) after stripping params")
assert_eq("Foo::operator++",
          stack_frames.filter_function_name("Foo::operator++()"),
          "filter_function_name preserves operator++ (no false offset strip)")
assert_eq("Foo::operator+=",
          stack_frames.filter_function_name("Foo::operator+=(int)"),
          "filter_function_name preserves operator+= (no false offset strip)")
assert_eq("std::operator+<char>",
          stack_frames.filter_function_name("std::operator+<char>(...)"),
          "filter_function_name preserves operator+<T> template-overload form")

# End-to-end: an un-symbolicated module-form frame from ASan must NOT carry
# `+0x{hex}` into the crash state. Mirrors what CRASH-0006 was filing into
# REPORT.html before the fix (`check_opcode_types+0xc4 (...)`).
module_form_with_offset = """\
==40839==ERROR: AddressSanitizer: heap-use-after-free on address 0x1 at pc 0x2
READ of size 1 at 0x1 thread T0
    #0 0x0001043637e0 in check_opcode_types+0xc4 (apptool.bin:arm64+0x1000677e0)
    #1 0x00010435b2c4 in tool_resolve_entry+0x213c (apptool.bin:arm64+0x10005f2c4)
SUMMARY: AddressSanitizer: heap-use-after-free
"""
sig = stack_frames.crash_signature(module_form_with_offset)
# After both fixes (function-name offset strip + ClusterFuzz address scrub),
# the signature for an un-symbolicated frame is ASLR-stable: hex addresses
# ≥ 4 hex digits collapse to `ADDRESS`, and the function name has no
# `+0x{hex}` offset. Source line numbers (`file.cc:1234`) are deliberately
# preserved by upstream's `(?<![:0-9.])` lookbehind.
ok(sig and "+0x" not in sig[0].split(" (", 1)[0],
   "crash signature function-name half carries no +0x{hex} offset",
   detail=f"sig={sig!r}")
ok(sig and sig[0] == "check_opcode_types (apptool.bin:arm64+ADDRESS)",
   "module-form frame normalizes to bare function + module location with ASLR-scrubbed offset",
   detail=f"top={sig[0] if sig else None!r}")

# ASLR-stability: two runs of the same crash with different PCs / module
# offsets must produce identical crash_signature lists. The hex addresses
# collapse to `ADDRESS` so cluster keys match.
module_form_run_a = """\
==1==ERROR: AddressSanitizer: heap-use-after-free on address 0x60f0000001c8 at pc 0x0001043637e4
READ of size 1 at 0x60f0000001c8 thread T0
    #0 0x0001043637e0 in check_opcode_types+0xc4 (apptool.bin:arm64+0x1000677e0)
    #1 0x00010435b2c4 in tool_resolve_entry+0x213c (apptool.bin:arm64+0x10005f2c4)
SUMMARY: AddressSanitizer: heap-use-after-free
"""
module_form_run_b = """\
==2==ERROR: AddressSanitizer: heap-use-after-free on address 0x71a0000003d8 at pc 0x000201abcd00
READ of size 1 at 0x71a0000003d8 thread T0
    #0 0x000201abccfc in check_opcode_types+0xd0 (apptool.bin:arm64+0x2000abcd0)
    #1 0x000201ab1208 in tool_resolve_entry+0x2200 (apptool.bin:arm64+0x2000a1200)
SUMMARY: AddressSanitizer: heap-use-after-free
"""
sig_a = stack_frames.crash_signature(module_form_run_a)
sig_b = stack_frames.crash_signature(module_form_run_b)
ok(sig_a == sig_b and sig_a,
   "two ASLR-different runs of the same crash collapse to the same signature",
   detail=f"a={sig_a!r} b={sig_b!r}")

# Architectural invariant: `frame.display` is the dedup/signature line and
# gets address/number-scrubbed; `frame.function` / `frame.location` stay
# RAW so render-md's triage card (which reads them directly, not via
# display) keeps the real addresses for forensic display.
frame = stack_frames.first_interesting_frame(module_form_run_a)
ok(frame is not None and frame.function == "check_opcode_types+0xc4",
   "frame.function preserves the raw symbol with +0x{hex} offset for forensic use",
   detail=f"function={frame.function if frame else None!r}")
ok(frame is not None and frame.location == "(apptool.bin:arm64+0x1000677e0)",
   "frame.location preserves the raw module+address for forensic use",
   detail=f"location={frame.location if frame else None!r}")
ok(frame is not None and "0x1000677e0" not in frame.display,
   "frame.display is the scrubbed dedup form (no raw ASLR address)",
   detail=f"display={frame.display if frame else None!r}")
# `libfoo-1.0.so` version-suffix preservation — upstream deliberately avoids
# turning these into `libfooNUMBERso`. Our verbatim port inherits the fix.
assert_eq("crash in libssl-1.0.2k.so",
          stack_frames.filter_addresses_and_numbers("crash in libssl-1.0.2k.so"),
          "filter_addresses_and_numbers preserves libfoo-X.Y.Z.so version strings")

# End-to-end: a frame whose own params mention std::__1 types must keep the
# real (param-stripped) name in the crash state, not be ignored as stdlib and
# not carry the parameter list into the signature.
param_heavy = """\
==43458==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x1 at pc 0x2
WRITE of size 1 at 0x1 thread T0
    #0 0x10 in sampledb::Engine::Store::set_blob(unsigned int, std::__1::vector<unsigned char, std::__1::allocator<unsigned char>>) sampledb.cpp:213
    #1 0x11 in sampledb::Engine::apply_line(std::__1::basic_string<char> const&) sampledb.cpp:367
    #2 0x12 in main main.cpp:13
SUMMARY: AddressSanitizer: heap-buffer-overflow sampledb.cpp:213 in sampledb::Engine::Store::set_blob(unsigned int, std::__1::vector<unsigned char, std::__1::allocator<unsigned char>>)
"""
frame = stack_frames.first_interesting_frame(param_heavy)
ok(frame is not None and frame.state_function == "sampledb::Engine::Store::set_blob",
   "crash-state function name has no parameter list",
   detail=f"state_function={frame.state_function if frame else None!r}")
ok(frame is not None and "(" not in frame.display,
   "frame.display carries no '(' parameter list into the signature",
   detail=f"display={frame.display if frame else None!r}")
sig = stack_frames.crash_signature(param_heavy)
ok(sig and sig[0] == "sampledb::Engine::Store::set_blob sampledb.cpp:213",
   "crash_signature top line is normalized func + location (source line numbers preserved by upstream's `(?<![:0-9.])` lookbehind)",
   detail=f"sig={sig!r}")
ok(all("std::__1::" not in line for line in sig),
   "no std::__1 parameter types leak into the crash signature",
   detail=f"sig={sig!r}")
# The raw function is preserved for the ignore step.
ok(frame is not None and frame.function.startswith(
        "sampledb::Engine::Store::set_blob("),
   "frame.function keeps the raw name (with params) for ignore matching",
   detail=f"function={frame.function if frame else None!r}")

# Go race-detector reports carry no `#N 0x..` frames, so they fall through to
# the dedicated parser. `main.<func>` frames must survive the ignore step (the
# `main.` package prefix is not the C `main` entrypoint), and the conflicting
# access pair is canonicalized so read/write vs write/read ordering — which the
# scheduler picks nondeterministically — does not look like two crashes.
go_race = """\
==================
WARNING: DATA RACE
Write at 0x00c000010 by goroutine 7:
  main.writer()
      /app/auth.go:53 +0x44
  main.run.func1()
      /app/auth.go:43 +0x88

Previous read at 0x00c000010 by goroutine 6:
  main.reader()
      /app/auth.go:62 +0x30

Goroutine 7 (running) created at:
  main.run()
      /app/auth.go:40 +0x120
Goroutine 6 (finished) created at:
  main.main()
      /app/auth.go:31 +0x90
==================
"""
go_race_swapped = """\
==================
WARNING: DATA RACE
Read at 0x00c000010 by goroutine 6:
  main.reader()
      /app/auth.go:62 +0x30

Previous write at 0x00c000010 by goroutine 7:
  main.writer()
      /app/auth.go:53 +0x44
  main.run.func1()
      /app/auth.go:43 +0x88

Goroutine 6 (running) created at:
  main.main()
      /app/auth.go:31 +0x90
Goroutine 7 (finished) created at:
  main.run()
      /app/auth.go:40 +0x120
==================
"""
go_frames = stack_frames.iter_go_race_frames(go_race)
ok(len(go_frames) == 2 and go_frames[0].function == "main.reader()",
   "iter_go_race_frames keeps only the two racing sites (not call-chain or creation frames)",
   detail=f"frames={[f.display for f in go_frames]!r}")
go_sig = stack_frames.crash_signature(go_race)
ok(go_sig and go_sig[0] == "main.reader /app/auth.go:62",
   "crash_signature falls back to Go race frames with the main. prefix kept",
   detail=f"sig={go_sig!r}")
ok(stack_frames.crash_signature(go_race) == stack_frames.crash_signature(go_race_swapped),
   "Go race signature is stable across read/write vs write/read ordering",
   detail=f"a={stack_frames.crash_signature(go_race)!r} b={stack_frames.crash_signature(go_race_swapped)!r}")

# ── Canonical sanitizer-diagnostic signature (shared with benchmark + reachability).
# Every sanitizer the harness builds must be recognised, and harness/probe
# footers (which an agent can echo in prose) must NOT be mistaken for a crash.
for _line, _want, _why in [
    ("ERROR: AddressSanitizer: heap-buffer-overflow on address 0x..", True, "ASan"),
    ("ERROR: HWAddressSanitizer: tag-mismatch on address 0x..", True, "HWASan (was the benchmark drift)"),
    ("WARNING: ThreadSanitizer: data race", True, "TSan"),
    ("SUMMARY: MemorySanitizer: use-of-uninitialized-value foo.c:1", True, "MSan"),
    ("foo.c:9:5: runtime error: signed integer overflow", True, "UBSan runtime error"),
    ("panic: runtime error: index out of range", False, "Go panic is not UBSan"),
    ("SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior foo.c:9:5", True, "UBSan summary"),
    ("CRASH_RATE: 0/1", False, "clean probe footer is not a crash"),
    ("NO CRASHES in 1 runs (1 completed cleanly)", False, "clean run footer is not a crash"),
    ("I built a reproducer that triggers a heap overflow", False, "prose claim is not a crash"),
]:
    ok(stack_frames.has_sanitizer_diagnostic(_line) is _want,
       f"has_sanitizer_diagnostic: {_why}",
       detail=f"line={_line!r} want={_want}")

if FAILED:
    print(f"\033[0;31m{FAILED} failed, {PASSED} passed\033[0m")
    sys.exit(1)
print(f"\033[0;32m{PASSED}/{PASSED} passed\033[0m")
