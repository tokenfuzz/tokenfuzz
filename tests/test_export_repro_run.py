#!/usr/bin/env python3
"""End-to-end generated reproducer build, argv replay, and ASan coverage."""

from __future__ import annotations

import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
EXPORT = ROOT / "bin" / "export-repro"


@unittest.skipUnless(
    all(shutil.which(tool) for tool in ("clang", "cmake", "git", "bash")),
    "clang, cmake, git, and bash are required for generated reproducer execution",
)
class ExportReproducerRunTests(unittest.TestCase):
    def test_generated_reproducer_builds_replays_argv_and_surfaces_asan(self) -> None:
        with tempfile.TemporaryDirectory(prefix="export-repro-run-") as temporary:
            root = Path(temporary)
            source = root / "fake-src"
            (source / ".git").mkdir(parents=True)
            (source / "CMakeLists.txt").write_text(
                "cmake_minimum_required(VERSION 3.10)\nproject(fake_target C)\n"
            )
            output = root / "output" / "exr-run-test"
            results = output / "codex" / "results"
            crash = results / "crashes" / "CRASH-RUN-1"
            crash.mkdir(parents=True)
            (output / "target.toml").write_text(
                'slug = "exr-run-test"\nupstream_url = "https://example.com/fake"\n'
                'build_system = "cmake"\npinned_rev = "deadbeef"\n'
                'asan_bin = "build-asan/unused"\nasan_lib = ""\n'
                'includes = []\nlink_libs = []\nis_browser = "0"\n\n'
                '[threat_model]\nattacker_controls = ["bytes"]\n'
            )
            (results / ".session-env").write_text(
                f"RESULTS_DIR={results}\nTARGET_ROOT={source}\nTARGET_SLUG=exr-run-test\n"
                f"TARGET_REV=deadbeef\nLOGDIR={root / 'logs'}\n"
            )
            (crash / "harness.c").write_text(
                "#include <stdio.h>\n#include <stdlib.h>\n#include <string.h>\n"
                "int main(int argc, char **argv) {\n"
                "  if (argc < 2) { fprintf(stderr, \"usage: %s <input>\\n\", argv[0]); return 2; }\n"
                "  if (argc < 3 || strcmp(argv[2], \"--needed\") != 0) { fprintf(stderr, \"missing recorded flag\\n\"); return 0; }\n"
                "  FILE *f = fopen(argv[1], \"rb\"); if (!f) return 3;\n"
                "  char buf[16]; size_t n = fread(buf, 1, sizeof(buf), f); fclose(f);\n"
                "  char *small = (char *)malloc(4); memcpy(small, buf, 4);\n"
                "  volatile size_t offset = 4 + (n & 3); char c = small[offset];\n"
                "  free(small); return c == 0 ? 0 : 1;\n}\n"
            )
            (crash / "sanitizer.txt").write_text(
                "ASAN_RUN_HEADER: runs=5 mode=generic testcase=output/sample/scratch/missing.bin started=x\n"
                "==99999==ERROR: AddressSanitizer: heap-buffer-overflow on address 0xdead\n"
                "READ of size 1 at 0xdead thread T0\n    #0 0xdead in main harness.c:10\n"
                "SUMMARY: AddressSanitizer: heap-buffer-overflow harness.c:10 in main\nCRASH_RATE: 5/5\n"
            )
            (crash / "report.md").write_text(
                "# CRASH-RUN-1\n\n## Summary\n\nEnd-to-end fixture.\n\n"
                "Trigger source: bytes\nCaller contract: obeyed\nBoundary: input file\nCaller controls: bytes\n"
            )
            (crash / "input.bin").write_bytes(b"AAAAAAAA")
            (crash / "repro.cmd").write_text("{TESTCASE} --needed\n")
            (crash / ".audit").mkdir()
            (crash / ".audit" / "severity.out").write_text("Severity: fixture\n")

            proc = subprocess.run(
                [str(EXPORT), "CRASH-RUN-1"], cwd=str(output),
                capture_output=True, text=True,
            )
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            reproduce = crash / "reproduce.sh"
            self.assertTrue(reproduce.is_file())
            self.assertTrue((crash / "sanitizer.txt").is_file())
            self.assertTrue((crash / "input.bin").is_file())
            self.assertFalse((crash / "input.out").exists())
            self.assertFalse((crash / "severity.out").exists())
            self.assertTrue((crash / ".audit" / "severity.out").is_file())
            script = reproduce.read_text(encoding="utf-8")
            for expected in (
                'echo "=== running ASan repro:', "quarantine_size_mb=256:redzone=64",
                'echo "[repro] exit=', '"$build/repro" "$here/input.bin" --needed',
                "git clone --recurse-submodules", "submodule update --init --recursive",
                "input.bin",
            ):
                self.assertIn(expected, script)
            self.assertNotRegex(script, r'(?m)^exec "\$build/repro"')
            self.assertNotRegex(script, r"input\.out\b")

            run = subprocess.run(
                ["bash", str(reproduce), str(source)], capture_output=True, text=True
            )
            runtime = run.stdout + run.stderr
            self.assertNotEqual(run.returncode, 0, runtime[-2000:])
            self.assertIn("AddressSanitizer: heap-buffer-overflow", runtime)
            self.assertIn("=== running ASan repro:", runtime)
            self.assertIn("[repro] exit=", runtime)


if __name__ == "__main__":
    unittest.main(verbosity=2)
