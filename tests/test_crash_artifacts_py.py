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
        assert_eq(None, ca.find_primary_asan([crash_dir, missing]),
                  "find_primary_asan: missing .audit scan dir tolerated")
    except FileNotFoundError as e:
        failed("find_primary_asan: missing .audit scan dir tolerated",
               f"raised {e!r}")

    # And the canonical artifact is still found when present.
    san = crash_dir / "sanitizer.txt"
    san.write_text("==1==ERROR: AddressSanitizer: heap-buffer-overflow\n",
                   encoding="utf-8")
    assert_eq(san, ca.find_primary_asan([crash_dir, missing]),
              "find_primary_asan: preferred name found beside missing .audit")

    # Suffix-named fallback artifacts go through _visible_files too.
    san.unlink()
    suffixed = crash_dir / "run-1.asan.txt"
    suffixed.write_text("==1==ERROR: AddressSanitizer: heap-buffer-overflow\n",
                        encoding="utf-8")
    assert_eq(suffixed, ca.find_primary_asan([crash_dir, missing]),
              "find_primary_asan: suffix fallback scan tolerates missing dir")


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
