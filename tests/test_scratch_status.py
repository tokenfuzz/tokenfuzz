#!/usr/bin/env python3
"""Digest, family aggregation, verdict, and bounded-file coverage."""

from __future__ import annotations

import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
COMMAND = ROOT / "bin" / "scratch-status"


class ScratchStatusTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="scratch-status-")
        self.results = Path(self.temporary.name) / "results"
        self.one = self.results / "scratch-1"
        self.two = self.results / "scratch-2"
        self.one.mkdir(parents=True)
        self.two.mkdir()
        clean_output = (
            "ASAN_RUN_HEADER: runs=1 mode=generic\n"
            "[run-sanitizer-multi] EXECUTION_RATE: 1/1\n"
            "[run-asan] generic EXECUTION VERIFIED (post-run, rc=0)\n"
        )
        for number in range(1, 4):
            (self.one / f"altsvc-expire-size-{number}.bin").write_bytes(b"GET / HTTP/1.1\r\n")
            (self.one / f"altsvc-expire-size-{number}.asan.txt").write_text(clean_output)
            (self.two / f"version_string_{number}.conf").write_text(f"cfg {number}\n")
            (self.two / f"version_string_{number}.asan.txt").write_text(
                "[run-sanitizer-multi] EXECUTION_RATE: 1/1\n"
            )
        (self.one / "aws-sigv4-size-1.bin").write_text("crash input\n")
        (self.one / "aws-sigv4-size-1.asan.txt").write_text(
            "ASAN_RUN_HEADER: runs=1\n"
            "==1234==ERROR: AddressSanitizer: heap-buffer-overflow on address 0xdead\n"
        )
        (self.one / "socks5-gss-len-1.bin").write_text("orphan one\n")
        (self.one / "socks5-gss-token-1.bin").write_text("orphan two\n")
        (self.one / "altsvc_file_harness.c").write_text(
            "int main(int argc, char **argv) { return 0; }\n"
        )
        (self.one / "README.md").write_text("notes\n")
        (self.one / "build.log").write_text("compile note\n")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def run_status(self, *args, results=None, **env):
        command_env = os.environ.copy()
        command_env["RESULTS_DIR"] = str(results or self.results)
        command_env.update({key: str(value) for key, value in env.items()})
        return subprocess.run(
            [sys.executable, str(COMMAND), *map(str, args)],
            capture_output=True, text=True, env=command_env,
        )

    def test_help_totals_orphans_and_family_aggregation(self) -> None:
        self.assertIn("scratch-status", self.run_status("--help").stdout)
        proc = self.run_status("--agent", "1")
        output = proc.stdout + proc.stderr
        self.assertEqual(proc.returncode, 0, output)
        for pattern in (
            r"\[scratch-1\] 6 testcases", r"3 CLEAN", r"1 CRASH", r"2 ORPHAN",
            r"1 harness sources", r"ORPHANS", r"socks5-gss-len-1.bin",
            r"socks5-gss-token-1.bin", r"aws-sigv4-size.*CRASH",
        ):
            with self.subTest(pattern=pattern):
                self.assertRegex(output, pattern)
        self.assertEqual(len(re.findall(
            r"(?m)^    altsvc-expire-size *3 testcase", output
        )), 1)
        self.assertNotIn("[scratch-1] 12 testcases", output)
        self.assertLess(len(output.encode()), 2048)
        self.assertRegex(self.run_status("--agent", "2").stdout, r"version_string *3 testcase")

    def test_platform_commands_on_path_cannot_affect_python_stat_logic(self) -> None:
        fake = Path(self.temporary.name) / "fake-platform-bin"
        fake.mkdir()
        for name in ("uname", "stat"):
            path = fake / name
            path.write_text("not an executable format\n")
            path.chmod(0o755)
        output = self.run_status(
            "--agent", "1", PATH=str(fake) + os.pathsep + os.environ.get("PATH", "")
        ).stdout
        self.assertNotRegex(output, r"syntax error|operand expected")
        self.assertIn("ago", output)

    def test_harness_only_terse_and_missing_views(self) -> None:
        three = self.results / "scratch-3"
        three.mkdir()
        (three / "harness.c").write_text("int main(void) { return 0; }\n")
        output = self.run_status("--agent", "3", "--files").stdout
        self.assertRegex(output, r"\[scratch-3\] 0 testcases .* 1 harness sources")
        terse = self.run_status("--agent", "1", "--terse").stdout
        self.assertIn("[scratch-1]", terse)
        for forbidden in ("families:", "newest 5", "recent files"):
            self.assertNotIn(forbidden, terse)
        self.assertIn("(missing)", self.run_status("--agent", "99").stdout)
        empty = Path(self.temporary.name) / "empty"
        empty.mkdir()
        proc = self.run_status(results=empty)
        self.assertIn("no scratch dirs found", proc.stdout + proc.stderr)

    def test_files_view_is_bounded_and_labels_artifacts(self) -> None:
        for number in range(1, 26):
            (self.one / f"artifact-{number}.tmp").write_text(f"artifact {number}\n")
        output = self.run_status(
            "--agent", "1", "--files", "--file-limit", "5"
        ).stdout
        self.assertRegex(output, r"recent files \(newest 5 of [0-9]+\)")
        self.assertRegex(output, r"artifact-[0-9]+\.tmp")
        self.assertIn("[artifact]", output)
        self.assertIn("more files; narrow by name with bin/scratch-search PATTERN", output)
        rows = [line for line in output.splitlines() if re.match(r"^    .* B  ", line)]
        self.assertEqual(len(rows), 5)
        wide = self.run_status(
            "--agent", "1", "--files", "--file-limit", "80"
        ).stdout
        self.assertIn("[testcase]", wide)
        self.assertIn("[sanitizer-output]", wide)


if __name__ == "__main__":
    unittest.main(verbosity=2)
