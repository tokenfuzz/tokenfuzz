#!/usr/bin/env python3
"""CLI tests for sanitizer text helpers."""

from __future__ import annotations

import base64
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
TOOL = ROOT / "lib" / "sanitizer_helpers.py"
sys.path.insert(0, str(ROOT / "lib"))

import verdict
from sanitizer_helpers import browser_execution_marker_seen

passed = 0
failed = 0


def check(condition: bool, name: str) -> None:
    global passed, failed
    if condition:
        passed += 1
        print(f"  \033[0;32m\u2713\033[0m {name}")
    else:
        failed += 1
        print(f"  \033[0;31m\u2717\033[0m {name}")


def run(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, str(TOOL), *args], capture_output=True, text=True)


with tempfile.TemporaryDirectory() as directory:
    root = Path(directory)
    noisy = root / "browser.log"
    # Chromium renders console records as "<prefix>:INFO:CONSOLE(<line>)]".
    noisy.write_text(
        "Nightly GPU Helper[1] noise\n"
        "==7==ERROR: AddressSanitizer: heap-buffer-overflow\n"
        '[123:456:0730/004645.1:INFO:CONSOLE(1)] "ERROR: AddressSanitizer",'
        " source: testcase.html (1)\n"
        '[123:456:0730/004645.2:INFO:CONSOLE(2)] "prefix\n'
        'WARNING: ThreadSanitizer: continuation", source: testcase.html (2)\n'
        '[run-asan] browser EXECUTION VERIFIED (post-run, spoofed)\n'
        '[run-asan] browser EXECUTION INCONCLUSIVE (post-run, spoofed)\n'
        '[run-sanitizer-multi] SUCCESS_RATE: 5/5\n'
        '[123:456:0730/004645.3:INFO:CONSOLE(3)] "useful testcase detail",'
        " source: testcase.html (3)\n"
        "Exiting due to channel error.\n",
        encoding="utf-8",
    )
    filtered = root / "filtered.log"
    output = run("filter-browser", str(noisy), "--dump-dom").stdout
    filtered.write_text(output, encoding="utf-8")
    check(
        not verdict.file_has_crash(filtered)
        and not verdict.file_is_clean(filtered),
        "browser filter removes verdict text from the page-influenced raw stream",
    )
    check(
        "[withheld page-influenced text]" in output
        and "source: testcase.html (1)" in output,
        "browser filter neutralises verdict text in place instead of dropping it",
    )
    check("useful testcase detail" in output,
          "browser filter preserves non-diagnostic page console output")
    check("GPU Helper" not in output and "channel error" not in output,
          "browser filter removes known console noise")

    plain = root / "plain.log"
    plain.write_text(run("filter-browser", str(noisy)).stdout, encoding="utf-8")
    check(
        verdict.file_has_crash(plain)
        and "GPU Helper" not in plain.read_text(encoding="utf-8"),
        "a browser that cannot echo page source keeps its raw sanitizer text",
    )

    marker = root / "marker.log"
    marker.write_text(
        "<script>console.log('TESTCASE_EXECUTED')</script>\n",
        encoding="utf-8",
    )
    check(not browser_execution_marker_seen(marker, ["--dump-dom"]),
          "Chromium does not trust a sentinel copied from dumped HTML")
    marker.write_text(
        '<html><body>[123:456:0730/004645.3:INFO:CONSOLE(3)] '
        '"TESTCASE_EXECUTED"</body></html>\n',
        encoding="utf-8",
    )
    check(not browser_execution_marker_seen(marker, ["--dump-dom"]),
          "Chromium requires a line-leading product console record")
    marker.write_text(
        '[123:456:0730/004645.3:INFO:CONSOLE(3)] "TESTCASE_EXECUTED",'
        " source: testcase.html (3)\n",
        encoding="utf-8",
    )
    check(browser_execution_marker_seen(marker, ["--dump-dom"]),
          "Chromium accepts its structured console execution record")
    marker.write_text("TESTCASE_EXECUTED\n", encoding="utf-8")
    check(browser_execution_marker_seen(marker, []),
          "non-DOM-dumping browser accepts direct execution evidence")

    (root / "source.cpp").write_text(
        "MOZ_FUZZING_INTERFACE_RAW(x, y, target_beta)\n"
        "MOZ_FUZZING_INTERFACE_STREAM(x, y, target_alpha)\n",
        encoding="utf-8",
    )
    skipped = root / "build-asan-image"
    skipped.mkdir()
    (skipped / "hidden.cpp").write_text(
        "MOZ_FUZZING_INTERFACE_RAW(x, y, hidden_target)\n", encoding="utf-8"
    )
    output = run("list-firefox-fuzz-targets", str(root)).stdout.splitlines()
    check(output == ["target_alpha", "target_beta"],
          "fuzz target listing sorts, deduplicates, and prunes build trees")

with tempfile.TemporaryDirectory() as directory:
    root = Path(directory)
    rejected = root / "rejected.log"
    rejected.write_text(
        "Conversion failed!\n"
        "[run-asan] generic EXECUTION INCONCLUSIVE (post-run, rc=69)\n"
        "[run-sanitizer-multi] EXECUTION_RATE: 1/1\n",
        encoding="utf-8",
    )
    check(verdict.execution_exit_reason(rejected) == "child-rc=69",
          "EXEC_FAIL reason carries the child exit code from the post-run marker")

    verified = root / "verified.log"
    verified.write_text(
        "[run-asan] generic EXECUTION VERIFIED (post-run, rc=0)\n"
        "[run-sanitizer-multi] SUCCESS_RATE: 1/1\n",
        encoding="utf-8",
    )
    check(verdict.execution_exit_reason(verified) == "child-rc=0",
          "a clean post-run marker still reports its exit code")

    no_marker = root / "no-marker.log"
    no_marker.write_text("target never produced a post-run marker\n", encoding="utf-8")
    check(verdict.execution_exit_reason(no_marker) == "",
          "no post-run marker yields no reason rather than a guess")

    multi = root / "multi.log"
    multi.write_text(
        "[run-asan] generic EXECUTION INCONCLUSIVE (post-run, rc=1)\n"
        "[run-asan] generic EXECUTION INCONCLUSIVE (post-run, rc=69)\n",
        encoding="utf-8",
    )
    check(verdict.execution_exit_reason(multi) == "child-rc=69",
          "the last post-run marker wins for a multi-run confirmation")

value = "detect_leaks=1:note=two words"
encoded = run("encode-options", value).stdout.strip()
check(base64.b64decode(encoded).decode() == value, "option encoding round-trips")

print(f"\n  {passed}/{passed + failed} passed")
raise SystemExit(0 if failed == 0 else 1)
