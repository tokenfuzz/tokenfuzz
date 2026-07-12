#!/usr/bin/env python3
"""tests/test_crash_artifacts_py.py — unit tests for lib/crash_artifacts.py.

Regression focus: scan helpers must tolerate scan dirs that do not exist.
Callers routinely pass speculative paths (benchmark scoring passes
`crash_dir / ".audit"` for every crash dir, present or not). On Python
<= 3.12, Path.iterdir() is a lazy generator, so a missing directory only
raises FileNotFoundError when the iterator is consumed — which used to
happen outside _visible_files' try/except and crashed `benchmark.py score`
on CI (Python 3.12) while passing locally on 3.13+, where iterdir() raises
eagerly inside the try.
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "lib"))

import crash_artifacts as ca

# ─── Pass/fail bookkeeping (same ✓/✗ marks as helpers.sh) ─────────

_PASSED = 0
_FAILED = 0
_GREEN = "\033[0;32m"
_RED = "\033[0;31m"
_NC = "\033[0m"


def passed(name: str) -> None:
    global _PASSED
    _PASSED += 1
    print(f"  {_GREEN}✓{_NC} {name}")


def failed(name: str, detail: str = "") -> None:
    global _FAILED
    _FAILED += 1
    print(f"  {_RED}✗{_NC} {name}")
    if detail:
        print(f"    {detail}")


def assert_eq(expected, actual, name: str) -> None:
    if expected == actual:
        passed(name)
    else:
        failed(name, f"expected={expected!r} actual={actual!r}")


# ─── Missing scan dirs must not raise ───────────────────────────────

with tempfile.TemporaryDirectory() as td:
    crash_dir = Path(td) / "crashes" / "C-0001"
    crash_dir.mkdir(parents=True)
    missing = crash_dir / ".audit"

    try:
        assert_eq([], ca._visible_files(missing),
                  "_visible_files: missing dir → [] (no FileNotFoundError)")
    except FileNotFoundError as e:
        failed("_visible_files: missing dir → [] (no FileNotFoundError)",
               f"raised {e!r}")

    # The exact call shape benchmark.py uses: a real crash dir plus a
    # speculative .audit subdir that was never created.
    try:
        assert_eq(None, ca.find_primary_sanitizer([crash_dir, missing]),
                  "find_primary_sanitizer: missing .audit scan dir tolerated")
    except FileNotFoundError as e:
        failed("find_primary_sanitizer: missing .audit scan dir tolerated",
               f"raised {e!r}")

    # And the canonical artifact is still found when present.
    san = crash_dir / "sanitizer.txt"
    san.write_text("==1==ERROR: AddressSanitizer: heap-buffer-overflow\n",
                   encoding="utf-8")
    assert_eq(san, ca.find_primary_sanitizer([crash_dir, missing]),
              "find_primary_sanitizer: preferred name found beside missing .audit")

    # Suffix-named fallback artifacts go through _visible_files too.
    san.unlink()
    suffixed = crash_dir / "run-1.asan.txt"
    suffixed.write_text("==1==ERROR: AddressSanitizer: heap-buffer-overflow\n",
                        encoding="utf-8")
    assert_eq(suffixed, ca.find_primary_sanitizer([crash_dir, missing]),
              "find_primary_sanitizer: suffix fallback scan tolerates missing dir")


# ─── find_harness_source: shared C/C++ harness detection ────────────

with tempfile.TemporaryDirectory() as td:
    cd = Path(td)
    missing = cd / "missing"
    (cd / "input.bin").write_bytes(b"\x00\x01")
    (cd / "helper.c").write_text("void helper(void) {}\n", encoding="utf-8")
    assert_eq(None, ca.find_harness_source([missing, cd]),
              "find_harness_source: no main() source → None, missing dir tolerated")

    harness = cd / "api_harness.cpp"
    harness.write_text("#include <stdio.h>\nint main(int argc, char **argv){return 0;}\n",
                       encoding="utf-8")
    assert_eq(harness, ca.find_harness_source([missing, cd]),
              "find_harness_source: detects C++ source harness with main()")

# A testcase-named C source (a compiler/parser target's reproducer) defines
# main() but is an input, not a harness: it must NOT shadow a real harness,
# and on its own must read as "no harness" so the CLI reverify path runs.
with tempfile.TemporaryDirectory() as td:
    cd = Path(td)
    (cd / "input.c").write_text("int main(void){return 0;}\n", encoding="utf-8")
    (cd / "harness.c").write_text("int main(void){return 0;}\n", encoding="utf-8")
    assert_eq("harness.c", ca.find_harness_source([cd]).name,
              "find_harness_source: harness.c wins over a main()-bearing input.c")

with tempfile.TemporaryDirectory() as td:
    cd = Path(td)
    (cd / "input.c").write_text("int main(void){return 0;}\n", encoding="utf-8")
    assert_eq(None, ca.find_harness_source([cd]),
              "find_harness_source: lone input.c is a testcase, not a harness")

with tempfile.TemporaryDirectory() as td:
    cd = Path(td)
    (cd / "reproducer.c").write_text("int main(void){return 0;}\n", encoding="utf-8")
    assert_eq(None, ca.find_harness_source([cd]),
              "find_harness_source: lone reproducer.c is a testcase, not a harness")

# Harness-named source wins even when an unrelated main()-bearing source sorts
# first and lives in an earlier scan dir.
with tempfile.TemporaryDirectory() as td:
    cd = Path(td)
    audit = cd / ".audit"; audit.mkdir()
    (audit / "aaa_driver.c").write_text("int main(void){return 0;}\n", encoding="utf-8")
    (cd / "fuzz_harness.cc").write_text("int main(void){return 0;}\n", encoding="utf-8")
    assert_eq("fuzz_harness.cc", ca.find_harness_source([audit, cd]).name,
              "find_harness_source: a *harness* name wins over an incidental main() source")

# An explicit `harness` in the name overrides a testcase prefix, and BOTH
# classifiers must agree (else export-repro double-stages the file as harness
# AND input). `repro-harness.c` reads as a harness; `is_testcase_candidate`
# must reject it for the same reason.
with tempfile.TemporaryDirectory() as td:
    cd = Path(td)
    rh = cd / "repro-harness.c"
    rh.write_text("int main(void){return 0;}\n", encoding="utf-8")
    assert_eq(rh, ca.find_harness_source([cd]),
              "find_harness_source: *-harness name beats a repro- testcase prefix")
    assert_eq(False, ca.is_testcase_candidate(rh),
              "is_testcase_candidate: repro-harness.c is a harness, not a testcase")
    # but an ASan-recorded testcase path always wins (explicit input signal).
    assert_eq(True, ca.is_testcase_candidate(rh, from_asan_header=True),
              "is_testcase_candidate: ASAN_RUN_HEADER overrides the harness name")

# When the ASAN_RUN_HEADER records a harness-named source AS the input, that
# recorded testcase is ground truth: it must be the testcase, NOT also the
# harness. The caller passes the resolved testcase as `exclude` so one file is
# never classified as both (which would skip CLI reverify and double-stage it).
with tempfile.TemporaryDirectory() as td:
    cd = Path(td)
    f = cd / "input_harness.c"
    f.write_text("int main(void){return 0;}\n", encoding="utf-8")
    asan = cd / "sanitizer.txt"
    asan.write_text("ASAN_RUN_HEADER sanitizer=asan testcase=input_harness.c\n"
                    "ERROR: AddressSanitizer: heap-buffer-overflow\n", encoding="utf-8")
    tc = ca.find_testcase([cd], sanitizer_files=[asan])
    assert_eq("input_harness.c", tc.name if tc else None,
              "find_testcase: ASAN-recorded harness-named source is the input")
    assert_eq(None, ca.find_harness_source([cd], exclude=tc),
              "find_harness_source: the recorded testcase is excluded from harness discovery")
    # Without the exclusion it would (wrongly) double-classify — guards the contract.
    assert_eq("input_harness.c", ca.find_harness_source([cd]).name,
              "find_harness_source: filename-only would double-classify (why exclude is needed)")


# ─── find_repro_args: argv recovery for flag-dependent CLI crashes ──

with tempfile.TemporaryDirectory() as td:
    cd = Path(td)
    (cd / "input.txt").write_bytes(b"x")

    # No repro.cmd / report.md → no extra args, callers keep bare invocation.
    assert_eq([], ca.find_repro_args([cd], bin_names=["app"],
                                     testcase_name="input.txt"),
              "find_repro_args: absent sources → []")

    # repro.cmd, args-only with {TESTCASE} → returned verbatim.
    (cd / "repro.cmd").write_text("--flag -n ANY -o '(?<=a)(?=b)' {TESTCASE}\n",
                                  encoding="utf-8")
    assert_eq(["--flag", "-n", "ANY", "-o", "(?<=a)(?=b)", ca.TESTCASE_TOKEN],
              ca.find_repro_args([cd], bin_names=["app"],
                                 testcase_name="input.txt"),
              "find_repro_args: repro.cmd args-only with token")

    # args-only repro.cmd is used VERBATIM: a positional that itself looks like
    # a NAME=value env assignment must NOT be stripped.
    (cd / "repro.cmd").write_text("MODE=parse PATTERN=a=b {TESTCASE}\n",
                                  encoding="utf-8")
    assert_eq(["MODE=parse", "PATTERN=a=b", ca.TESTCASE_TOKEN],
              ca.find_repro_args([cd], bin_names=["app"],
                                 testcase_name="input.txt"),
              "find_repro_args: repro.cmd NAME=value positional preserved")

    # A literal input filename (no token) is rewritten and kept in position.
    (cd / "repro.cmd").write_text("--flag input.txt\n", encoding="utf-8")
    assert_eq(["--flag", ca.TESTCASE_TOKEN],
              ca.find_repro_args([cd], bin_names=["app"],
                                 testcase_name="input.txt"),
              "find_repro_args: repro.cmd literal input rewritten to token")

    # A bare `BIN input` (no real flags) reads as [] so behaviour is unchanged.
    (cd / "repro.cmd").write_text("{TESTCASE}\n", encoding="utf-8")
    assert_eq([], ca.find_repro_args([cd], bin_names=["app"],
                                     testcase_name="input.txt"),
              "find_repro_args: token-only → []")

    # Grok-style full bare invocation in the args-only file: strip the binary
    # only for exact `BIN {TESTCASE}`. Other backends' flags and positional
    # arguments must remain untouched.
    (cd / "repro.cmd").write_text("app {TESTCASE}\n", encoding="utf-8")
    assert_eq([], ca.find_repro_args([cd], bin_names=["app"],
                                     testcase_name="input.txt"),
              "find_repro_args: exact leading configured binary is normalized")
    (cd / "repro.cmd").write_text("app --mode {TESTCASE}\n", encoding="utf-8")
    assert_eq(["app", "--mode", ca.TESTCASE_TOKEN],
              ca.find_repro_args([cd], bin_names=["app"],
                                 testcase_name="input.txt"),
              "find_repro_args: non-bare argv beginning with binary-like positional is preserved")
    (cd / "repro.cmd").write_text("other {TESTCASE}\n", encoding="utf-8")
    assert_eq(["other", ca.TESTCASE_TOKEN],
              ca.find_repro_args([cd], bin_names=["app"],
                                 testcase_name="input.txt"),
              "find_repro_args: unmatched leading command is preserved")

with tempfile.TemporaryDirectory() as td:
    cd = Path(td)
    (cd / "input.txt").write_bytes(b"x")
    # Fallback: no repro.cmd, recover the fenced command block from report.md.
    # The full command has its env prefix + binary + a spaced redirection
    # stripped, a line-continuation joined, and the literal input → token.
    (cd / "report.md").write_text(
        "## Reproduction\n\n```sh\nenv ASAN_OPTIONS=x \\\n"
        "  build/app --flag -o '(?<=a)(?=b)' input.txt 2> san.txt\n```\n",
        encoding="utf-8")
    assert_eq(["--flag", "-o", "(?<=a)(?=b)", ca.TESTCASE_TOKEN],
              ca.find_repro_args([cd], bin_names=["app"],
                                 testcase_name="input.txt"),
              "find_repro_args: report.md fallback strips env/binary/redirect")

    # Binary match is token-based: a substring like `apple` must not match.
    (cd / "report.md").write_text(
        "```sh\n./apple --x input.txt\n```\n", encoding="utf-8")
    assert_eq([], ca.find_repro_args([cd], bin_names=["app"],
                                     testcase_name="input.txt"),
              "find_repro_args: report.md binary match is token-anchored")

    # repro.cmd wins over report.md when both exist.
    (cd / "repro.cmd").write_text("--from-cmd {TESTCASE}\n", encoding="utf-8")
    assert_eq(["--from-cmd", ca.TESTCASE_TOKEN],
              ca.find_repro_args([cd], bin_names=["app"],
                                 testcase_name="input.txt"),
              "find_repro_args: repro.cmd precedence over report.md")

# repro.cmd must not be mistaken for the reproducing testcase.
with tempfile.TemporaryDirectory() as td:
    cd = Path(td)
    (cd / "repro.cmd").write_text("--flag {TESTCASE}\n", encoding="utf-8")
    real = cd / "input.bin"
    real.write_bytes(b"\x00\x01\x02payload")
    assert_eq(real, ca.find_testcase([cd]),
              "find_testcase: repro.cmd excluded, real input chosen")


total = _PASSED + _FAILED
if _FAILED == 0:
    print(f"  {_GREEN}{_PASSED}/{total} passed{_NC}")
    sys.exit(0)
else:
    print(f"  {_RED}{_PASSED}/{total} passed, {_FAILED} failed{_NC}")
    sys.exit(1)
