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

macos_start_only = """\
==18355==ERROR: AddressSanitizer: stack-buffer-overflow
WRITE of size 1 at 0x1 thread T0
    #0 0x10 in main+0x1aac (testbin:arm64+0x100002f94)
    #1 0x11 in start+0x1b4c (dyld:arm64e+0x1fda0)
SUMMARY: AddressSanitizer: stack-buffer-overflow (testbin:arm64+0x100002f94) in main+0x1aac
"""
ok(stack_frames.first_interesting_frame(macos_start_only) is None,
   "skips macOS dyld start+ tail frames instead of using them as dedup keys")

if FAILED:
    print(f"\033[0;31m{FAILED} failed, {PASSED} passed\033[0m")
    sys.exit(1)
print(f"\033[0;32m{PASSED}/{PASSED} passed\033[0m")
