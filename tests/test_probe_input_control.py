#!/usr/bin/env python3
"""A crash the route reproduces on an empty input is not testcase evidence."""

from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
PROBE = ROOT / "bin" / "probe"

REPORT = (
    "==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x1\n"
    "READ of size 1 at 0x1 thread T0\n"
    "    #0 0x1 in app_parse /src/parser.c:{line}\n"
    "    #1 0x2 in main /src/cli.c:9\n"
    "SUMMARY: AddressSanitizer: heap-buffer-overflow /src/parser.c:{line} in app_parse\n"
)


class ProbeInputControlTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="probe-control-test-")
        self.root = Path(self.temporary.name)
        self.target = self.root / "target"
        self.results = self.root / "results"
        self.logs = self.root / "logs"
        for path in (
            self.target / "build-asan" / "bin", self.results / "scratch-1",
            self.results / "crashes", self.results / "crashes-rejected",
            self.results / "findings", self.logs,
        ):
            path.mkdir(parents=True)
        self.binary = self.target / "build-asan" / "bin" / "sampleproj"
        (self.target / "target.toml").write_text(
            'target = "sampleproj"\n'
            'upstream_url = "https://example.invalid/sampleproj"\n'
            'build_system = "make"\n'
            'asan_bin = "build-asan/bin/sampleproj"\n'
            'is_browser = "0"\n'
            '[threat_model]\nattacker_controls = ["bytes"]\n'
            '[sanitizer]\nenabled = ["asan"]\n',
            encoding="utf-8",
        )
        (self.results / ".session-env").write_text(
            f'export RESULTS_DIR="{self.results}"\n'
            f'export TARGET_ROOT="{self.target}"\n'
            'export TARGET_SLUG="sampleproj"\n',
            encoding="utf-8",
        )
        self.testcase = self.results / "scratch-1" / "tc.txt"
        self.testcase.write_text(
            "// TARGET: src/parser.c:app_parse:91\n"
            "// HYPOTHESIS-ID: H-control\n// CATEGORY: bounds\n// MODE: generic\n"
            "BOOM\n",
            encoding="utf-8",
        )
        self.env = os.environ.copy()
        self.env.update(
            RESULTS_DIR=str(self.results), TARGET_ROOT=str(self.target),
            TARGET_SLUG="sampleproj", LOGDIR=str(self.logs),
            ASAN_GENERIC_BIN=str(self.binary), PROBE_SANITIZER="asan",
            LLM_DECIDE_DISABLE="1",
        )
        for key in ("AUDIT_BUILD_SUFFIX", "SANITIZER_RUN_BUDGET", "ASAN_RUN_BUDGET"):
            self.env.pop(key, None)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write_binary(self, body: str) -> None:
        self.binary.write_text(
            f"#!{sys.executable}\nimport pathlib, sys\nREPORT = {REPORT!r}\n{body}",
            encoding="utf-8",
        )
        self.binary.chmod(self.binary.stat().st_mode | stat.S_IXUSR)

    def probe(self) -> tuple[str, dict]:
        proc = subprocess.run(
            [str(PROBE), str(self.testcase)], capture_output=True, text=True,
            env=self.env,
        )
        rows = [
            json.loads(line) for line in
            (self.results / "state" / "runs.jsonl").read_text(encoding="utf-8").splitlines()
        ]
        self.assertEqual(len(rows), 1, proc.stdout + proc.stderr)
        return proc.stdout + proc.stderr, rows[0]

    def test_a_startup_crash_is_not_credited(self) -> None:
        # Faults while starting up, before it opens anything.
        self.write_binary(
            "sys.stderr.write(REPORT.format(line=91))\nraise SystemExit(1)\n"
        )
        output, row = self.probe()
        self.assertIn("[probe] verdict=NO_EXEC", output)
        self.assertIn("NO_EXEC class=input-independent", output)
        self.assertEqual(row["verdict"], "NO_EXEC")
        self.assertIn("class=input-independent", row["reason"])
        # The diagnostic stays as route evidence; nothing is filed.
        self.assertIn("app_parse", Path(row["asan_output"]).read_text(encoding="utf-8"))
        self.assertEqual(list((self.results / "crashes").glob("CRASH-*")), [])
        # The control run is not an agent run.
        tried = (self.results / "tried-inputs-1.log").read_text(encoding="utf-8")
        self.assertEqual(len(tried.splitlines()), 1)

    def test_a_crash_after_opening_any_input_is_not_credited(self) -> None:
        # Opens its input first and faults while setting up, whatever it holds.
        self.write_binary(
            "pathlib.Path(sys.argv[1]).read_bytes()\n"
            "sys.stderr.write(REPORT.format(line=91))\nraise SystemExit(1)\n"
        )
        output, row = self.probe()
        self.assertIn("[probe] verdict=NO_EXEC", output)
        self.assertIn("class=input-independent", row["reason"])

    def test_a_startup_crash_that_moves_with_argv_is_still_matched(self) -> None:
        # A layout-sensitive startup fault lands where the argv length puts
        # it; the control input must not move it.
        self.write_binary(
            "sys.stderr.write(REPORT.format(line=len(sys.argv[1])))\n"
            "raise SystemExit(1)\n"
        )
        output, row = self.probe()
        self.assertIn("class=input-independent", row["reason"], output)
        self.assertEqual(
            sorted(path.name for path in self.testcase.parent.iterdir()
                   if not path.name.startswith("tc.")),
            [], "the control input is removed",
        )

    def test_a_crash_that_needs_the_input_stays_a_crash(self) -> None:
        self.write_binary(
            "path = pathlib.Path(sys.argv[1])\n"
            "if b'BOOM' in path.read_bytes():\n"
            "    sys.stderr.write(REPORT.format(line=91))\n"
            "raise SystemExit(1)\n"
        )
        output, row = self.probe()
        self.assertIn("[probe] verdict=CRASH", output)
        self.assertNotIn("input-independent", output)
        self.assertEqual(row["verdict"], "CRASH")

    def test_a_different_crash_on_an_empty_input_keeps_the_crash(self) -> None:
        # Both runs fault, at different sites: only an identical state shows
        # the testcase did not matter.
        self.write_binary(
            "line = 91 if pathlib.Path(sys.argv[1]).read_bytes() else 12\n"
            "sys.stderr.write(REPORT.format(line=line))\nraise SystemExit(1)\n"
        )
        output, row = self.probe()
        self.assertIn("[probe] verdict=CRASH", output)
        self.assertEqual(row["verdict"], "CRASH")


if __name__ == "__main__":
    unittest.main(verbosity=2)
