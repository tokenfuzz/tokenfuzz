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

total = _PASSED + _FAILED
if _FAILED == 0:
    print(f"  {_GREEN}{_PASSED}/{total} passed{_NC}")
    sys.exit(0)
else:
    print(f"  {_RED}{_PASSED}/{total} passed, {_FAILED} failed{_NC}")
    sys.exit(1)
