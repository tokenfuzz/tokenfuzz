#!/usr/bin/env python3
"""A filed crash report is symbolized once for its human-facing report.

The in-probe symbolizer can time out on a very large library, and nothing
re-symbolized later, so promoted reports kept raw `module+0x…` frames. The
filed sanitizer.txt must stay as filed: its frames are the bundle's crash
state, the dedup identity later probes are matched against.
"""

from __future__ import annotations

import contextlib
import importlib.machinery
import importlib.util
import io
import os
import re
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent

sys.path.insert(0, str(ROOT / "lib"))

import crash_bundle  # noqa: E402
import sanitizer  # noqa: E402

RAW_REPORT = """\
==4242==ERROR: AddressSanitizer: heap-buffer-overflow on address 0xbeef at pc 0xcafe
READ of size 4 at 0xbeef thread T0
    #0 0x1000 in app_parse+0x10 ({module}:arm64+0x1000)
    #1 0x2000 in app_read+0x20 ({module}:arm64+0x2000)
    #2 0x3000 in main /src/main.c:9

0xbeef is located 0 bytes after 4-byte region [0xbeeb,0xbeef)
allocated by thread T0 here:
    #0 0x4000 in malloc /src/alloc.c:1
    #1 0x5000 in app_alloc /src/alloc.c:7
SUMMARY: AddressSanitizer: heap-buffer-overflow in app_parse
"""


def _fake_symbolize(path, *, full_path=False, timeout=0):
    """Resolve the two raw frames the way a working symbolizer would."""
    report = Path(path)
    text = report.read_text()
    text = re.sub(r"in (app_\w+)\+0x\w+ \([^)]*\)", r"in \1 /src/child.c:91", text)
    report.write_text(text)
    return True


class SymbolizedCopyTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="report-symbolize-")
        self.root = Path(self._tmp.name)
        self.module = self.root / "libsample.dylib"
        self.module.write_bytes(b"\0")
        past = time.time() - 100
        os.utime(self.module, (past, past))
        self.report = self.root / "sanitizer.txt"
        self.report.write_text(RAW_REPORT.format(module=self.module))
        self.cache = self.root / ".audit"

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_the_copy_is_symbolized_once_and_the_report_is_untouched(self) -> None:
        before = self.report.read_bytes()
        with mock.patch.object(sanitizer, "symbolize_file", side_effect=_fake_symbolize) as run:
            first = sanitizer.symbolized_copy(self.report, self.cache)
            second = sanitizer.symbolized_copy(self.report, self.cache)
        self.assertEqual(self.report.read_bytes(), before)
        self.assertEqual(first, second)
        self.assertIn("app_parse /src/child.c:91", first.read_text())
        self.assertEqual(run.call_count, 1)
        self.assertEqual(
            run.call_args.kwargs["timeout"], sanitizer.REPORT_SYMBOLIZE_TIMEOUT_SECONDS,
        )
        # Hidden, so no artifact scan mistakes it for the bundle's diagnostic.
        self.assertTrue(first.name.startswith("."))

    def test_a_module_rebuilt_after_the_report_is_not_symbolized(self) -> None:
        # Addresses from the old build would resolve to different code.
        os.utime(self.module, None)
        past = time.time() - 50
        os.utime(self.report, (past, past))
        with mock.patch.object(sanitizer, "symbolize_file") as run, \
             contextlib.redirect_stderr(io.StringIO()) as stderr:
            copy = sanitizer.symbolized_copy(self.report, self.cache)
        run.assert_not_called()
        self.assertEqual(copy.read_bytes(), self.report.read_bytes())
        self.assertIn("rebuilt", stderr.getvalue())

    def test_a_failure_under_a_cut_budget_is_retried_later(self) -> None:
        # Triage caps the pass at what is left of the audit wall; a timeout
        # there must not pin the bundle to raw frames for good.
        with mock.patch.object(sanitizer, "symbolize_file", return_value=False):
            cut = sanitizer.symbolized_copy(self.report, self.cache, budget=5)
        self.assertEqual(cut, self.report)
        self.assertEqual(list(self.cache.glob(".symbolized-*")), [])
        with mock.patch.object(sanitizer, "symbolize_file", side_effect=_fake_symbolize):
            later = sanitizer.symbolized_copy(self.report, self.cache)
        self.assertIn("child.c:91", later.read_text())

    def test_triage_caps_the_pass_at_the_remaining_wall(self) -> None:
        import triage

        self.assertEqual(triage._symbolize_budget_args(None), [])
        near = time.monotonic() + 30
        budget = int(triage._symbolize_budget_args(near)[1])
        self.assertTrue(25 <= budget <= 30, budget)
        far = time.monotonic() + 10 * sanitizer.REPORT_SYMBOLIZE_TIMEOUT_SECONDS
        self.assertEqual(
            triage._symbolize_budget_args(far),
            ["--symbolize-budget", str(sanitizer.REPORT_SYMBOLIZE_TIMEOUT_SECONDS)],
        )

    def test_a_symbolized_report_is_used_as_is(self) -> None:
        self.report.write_text(_fake_symbolize_text(self.report.read_text()))
        with mock.patch.object(sanitizer, "symbolize_file") as run:
            self.assertEqual(sanitizer.symbolized_copy(self.report, self.cache), self.report)
        run.assert_not_called()


def _fake_symbolize_text(text: str) -> str:
    return re.sub(r"in (app_\w+)\+0x\w+ \([^)]*\)", r"in \1 /src/child.c:91", text)


class ExportTitleTests(unittest.TestCase):
    """The exported report reads symbols; the dedup identity does not move."""

    def test_export_titles_from_symbols_and_keeps_the_filed_crash_state(self) -> None:
        loader = importlib.machinery.SourceFileLoader(
            "export_repro_symbolize", str(ROOT / "bin" / "export-repro"),
        )
        spec = importlib.util.spec_from_loader(loader.name, loader)
        export = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(export)
        with tempfile.TemporaryDirectory(prefix="export-symbolize-") as temp:
            root = Path(temp)
            target = root / "target"
            target.mkdir()
            output = root / "output" / "sampleproj"
            output.mkdir(parents=True)
            (output / "target.toml").write_text(
                'slug = "sampleproj"\nupstream_url = "https://example.com/repo"\n'
                'build_system = "cmake"\nasan_bin = "build-asan/demo"\n'
                'is_browser = "0"\n\n[threat_model]\nattacker_controls = ["bytes"]\n',
                encoding="utf-8",
            )
            results = output / "codex" / "results"
            crash = results / "crashes" / "CRASH-S-1"
            crash.mkdir(parents=True)
            (results / ".session-env").write_text(
                f"RESULTS_DIR={results}\nTARGET_ROOT={target}\n"
                f"TARGET_SLUG=sampleproj\nTARGET_REV=abc123\nLOGDIR={root}/logs\n",
                encoding="utf-8",
            )
            module = root / "libsample.dylib"
            module.write_bytes(b"\0")
            past = time.time() - 100
            os.utime(module, (past, past))
            (crash / "sanitizer.txt").write_text(RAW_REPORT.format(module=module))
            (crash / "report.md").write_text(
                "# CRASH-S-1\n\n## Summary\nTest crash.\n\nTrigger source: bytes\n"
                "Boundary: input file\nCaller controls: bytes\n"
                "Caller contract: obeyed\n",
                encoding="utf-8",
            )
            (crash / "input.bin").write_bytes(b"ABC")
            filed_state = crash_bundle.bundle_crash_state(crash)
            self.assertIsNotNone(filed_state)
            filed_raw = (crash / "sanitizer.txt").read_text()

            cwd = os.getcwd()
            os.chdir(output)
            try:
                with mock.patch.object(
                    export.sanitizer_policy, "symbolize_file", side_effect=_fake_symbolize,
                ), contextlib.redirect_stdout(io.StringIO()), \
                        contextlib.redirect_stderr(io.StringIO()):
                    rc = export.main(["CRASH-S-1"])
            finally:
                os.chdir(cwd)

            self.assertIn(rc, (0, None))
            title = (crash / "report.md").read_text().splitlines()[0]
            self.assertIn("app_parse", title)
            self.assertIn("child.c:91", (crash / "report.md").read_text())
            self.assertEqual((crash / "sanitizer.txt").read_text(), filed_raw)
            self.assertEqual(crash_bundle.bundle_crash_state(crash), filed_state)


if __name__ == "__main__":
    unittest.main()
