#!/usr/bin/env python3
"""tests/test_auto_build_script_py.py — exercise the toolchain-missing
short-circuit in bin/auto-build-script.

The script's LLM revision loop is the wrong tool for a missing
toolchain: the safety rails in ``validate_proposed_script`` block sudo /
apt-get / curl|sh, and a recipe that installed packages would be
unshippable in reproduce.sh anyway. So we expect iter 1 to detect
``command not found`` in the build log and exit 3 with an actionable
diagnostic, without ever calling the LLM.

Output matches helpers.sh (✓/✗) so tests/run-tests.sh's pass/fail
counter still works.
"""

from __future__ import annotations

import importlib.machinery
import importlib.util
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ABS = ROOT / "bin" / "auto-build-script"

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
    suffix = f" — {detail}" if detail else ""
    print(f"  {_RED}✗{_NC} {name}{suffix}")


def ok(cond: bool, name: str, detail: str = "") -> None:
    if cond:
        passed(name)
    else:
        failed(name, detail)


# ─── Load bin/auto-build-script as a module ─────────────────────────

sys.path.insert(0, str(ROOT / "lib"))
loader = importlib.machinery.SourceFileLoader("abs_mod", str(ABS))
spec = importlib.util.spec_from_loader("abs_mod", loader)
abs_mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(abs_mod)


# ─── detect_missing_commands ────────────────────────────────────────

ok(abs_mod.detect_missing_commands("") == [],
   "detect: empty log returns empty list")

ok(abs_mod.detect_missing_commands(
    "/tmp/auto-build-script-xyz/build.candidate.sh: line 7: cmake: command not found\n"
) == ["cmake"],
   "detect: bash 'line N: <cmd>: command not found' captured")

ok(abs_mod.detect_missing_commands(
    "cmake: command not found\n"
) == ["cmake"],
   "detect: bare '<cmd>: command not found' captured")

ok(abs_mod.detect_missing_commands(
    "sh: 1: ninja: not found\n"
) == ["ninja"],
   "detect: dash-style '<cmd>: not found' captured")

ok(abs_mod.detect_missing_commands(
    "line 3: cmake: command not found\n"
    "line 7: ninja: command not found\n"
    "line 9: cmake: command not found\n"
) == ["cmake", "ninja"],
   "detect: distinct commands deduped, order preserved")

# Path-shaped 'not found' lines must NOT be interpreted as missing
# commands. configure logs often contain "/usr/lib/foo.so: not found"
# meaning a library file, not a binary.
ok(abs_mod.detect_missing_commands(
    "/usr/local/lib/libfoo.so: not found\n"
) == [],
   "detect: path-shaped 'not found' ignored (not a command)")

# A real build log mixes both. The command name still gets surfaced.
ok(abs_mod.detect_missing_commands(
    "checking for /usr/bin/ld... /usr/bin/ld: not found\n"
    "/tmp/build.sh: line 4: meson: command not found\n"
) == ["meson"],
   "detect: command name extracted, path 'not found' lines ignored")


# ─── End-to-end: iter 1 detects missing toolchain, exits 3 ──────────
#
# We can't run a real cmake build inside the test harness portably, so
# instead we run auto-build-script against a fake source tree whose
# build.candidate.sh execution will fail with "command not found" by
# running the script under a PATH that excludes cmake. The script's
# initial cmake template is what we feed it; we don't need a real
# CMakeLists.txt because the cmake invocation fails before reading it.

with tempfile.TemporaryDirectory() as tmpd:
    src = Path(tmpd) / "src"
    src.mkdir()
    (src / "CMakeLists.txt").write_text(
        "cmake_minimum_required(VERSION 3.0)\nproject(fake C)\n",
        encoding="utf-8",
    )
    out_path = Path(tmpd) / "build.sh"

    # PATH that contains bash + coreutils but NOT cmake. /usr/bin is
    # enough for the script's own runtime; cmake will be unresolvable.
    minimal_path = "/usr/bin:/bin"
    env = os.environ.copy()
    env["PATH"] = minimal_path
    # Confirm cmake is genuinely absent from the test PATH. If a host
    # has cmake at /usr/bin/cmake, skip the e2e test (still meaningful
    # because the unit cases above already covered the detector).
    try:
        which = subprocess.run(
            ["bash", "-c", "command -v cmake"],
            env=env, capture_output=True, text=True, check=False,
        )
        cmake_present = which.returncode == 0
    except OSError:
        cmake_present = True  # be conservative: skip if anything weird

    if cmake_present:
        passed("e2e: cmake present on host PATH — skipping toolchain-missing e2e (detector unit tests still cover the logic)")
    else:
        proc = subprocess.run(
            [sys.executable, str(ABS),
             "--src", str(src),
             "--sanitizer", "asan",
             "--out", str(out_path),
             "--max-iters", "5",
             "--build-timeout-secs", "30"],
            env=env, capture_output=True, text=True, check=False,
        )
        ok(proc.returncode == 3,
           f"e2e: exits 3 on missing toolchain (got {proc.returncode})",
           detail=f"stderr tail: {proc.stderr[-400:]!r}")
        ok("toolchain missing" in proc.stderr,
           "e2e: stderr names the failure as 'toolchain missing'",
           detail=f"stderr tail: {proc.stderr[-400:]!r}")
        ok("cmake" in proc.stderr,
           "e2e: stderr names the missing command",
           detail=f"stderr tail: {proc.stderr[-400:]!r}")
        ok("apt-get install" in proc.stderr or "install-container-deps" in proc.stderr,
           "e2e: stderr points operator at an install path",
           detail=f"stderr tail: {proc.stderr[-400:]!r}")
        ok("asking LLM for revision" not in proc.stderr,
           "e2e: LLM revision loop is skipped",
           detail=f"stderr tail: {proc.stderr[-400:]!r}")


# ─── summary ────────────────────────────────────────────────────────

if _FAILED:
    print(f"  {_RED}{_PASSED + _FAILED} tests, {_FAILED} failed{_NC}")
    sys.exit(1)
print(f"  {_GREEN}{_PASSED}/{_PASSED} passed{_NC}")
