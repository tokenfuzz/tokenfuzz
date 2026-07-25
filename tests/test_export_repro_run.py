#!/usr/bin/env python3
"""End-to-end generated reproducer build, argv replay, and ASan coverage."""

from __future__ import annotations

import importlib.machinery
import importlib.util
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
EXPORT = ROOT / "bin" / "export-repro"
loader = importlib.machinery.SourceFileLoader("export_repro_run", str(EXPORT))
spec = importlib.util.spec_from_loader(loader.name, loader)
export_repro = importlib.util.module_from_spec(spec)
loader.exec_module(export_repro)


@unittest.skipUnless(
    all(shutil.which(tool) for tool in ("clang", "cmake", "git", "bash")),
    "clang, cmake, git, and bash are required for generated reproducer execution",
)
class ExportReproducerRunTests(unittest.TestCase):
    def test_source_without_submodules_passes_revision_check(self) -> None:
        with tempfile.TemporaryDirectory(prefix="export-repro-no-submodule-") as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            subprocess.run(["git", "-C", str(source), "init", "-q"], check=True)
            subprocess.run(
                ["git", "-C", str(source), "config", "user.email", "test@example.invalid"],
                check=True,
            )
            subprocess.run(
                ["git", "-C", str(source), "config", "user.name", "Test"],
                check=True,
            )
            subprocess.run(
                ["git", "-C", str(source), "commit", "--allow-empty", "-qm", "fixture"],
                check=True,
            )
            revision = subprocess.run(
                ["git", "-C", str(source), "rev-parse", "HEAD"],
                check=True, capture_output=True, text=True,
            ).stdout.strip()
            reproduce = root / "reproduce.sh"
            reproduce.write_text(
                export_repro.emit_preamble(
                    "cmake", "https://example.invalid/sample", revision,
                    "sample", "build-asan/sample",
                )
                + "\nexit 0\n",
                encoding="utf-8",
            )
            process = subprocess.run(
                ["bash", str(reproduce), str(source)],
                capture_output=True, text=True,
            )
            self.assertEqual(process.returncode, 0, process.stdout + process.stderr)

    def test_an_unrecorded_revision_builds_a_git_checkout_as_it_stands(self) -> None:
        # "norev" is a sentinel for "the audit recorded no revision", not a
        # commit. Checking it out fails on a pathspec that never existed, which
        # would refuse to build every bundle from a run that recorded none.
        with tempfile.TemporaryDirectory(prefix="export-repro-norev-") as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            subprocess.run(["git", "-C", str(source), "init", "-q"], check=True)
            subprocess.run(
                ["git", "-C", str(source), "config", "user.email", "test@example.invalid"],
                check=True,
            )
            subprocess.run(
                ["git", "-C", str(source), "config", "user.name", "Test"], check=True,
            )
            subprocess.run(
                ["git", "-C", str(source), "commit", "--allow-empty", "-qm", "fixture"],
                check=True,
            )
            reproduce = root / "reproduce.sh"
            reproduce.write_text(
                export_repro.emit_preamble(
                    "cmake", "https://example.invalid/sample", "norev",
                    "sample", "build-asan/sample",
                )
                + "\necho REACHED_BUILD\nexit 0\n",
                encoding="utf-8",
            )
            process = subprocess.run(
                ["bash", str(reproduce), str(source)], capture_output=True, text=True,
            )
            self.assertEqual(process.returncode, 0, process.stdout + process.stderr)
            self.assertIn("REACHED_BUILD", process.stdout)
            self.assertIn("recorded no revision", process.stderr)

    def test_submodule_status_failure_is_not_treated_as_clean(self) -> None:
        with tempfile.TemporaryDirectory(prefix="export-repro-submodule-") as temporary:
            root = Path(temporary)
            source = root / "source"
            (source / ".git").mkdir(parents=True)
            fake_bin = root / "bin"
            fake_bin.mkdir()
            fake_git = fake_bin / "git"
            fake_git.write_text(
                f"#!{sys.executable}\n"
                "import sys\n"
                "args = sys.argv[1:]\n"
                "if 'submodule' in args and 'status' in args:\n"
                "    print('fatal: cannot read submodule configuration', file=sys.stderr)\n"
                "    raise SystemExit(128)\n"
                "if 'rev-parse' in args:\n"
                "    print('.git')\n",
                encoding="utf-8",
            )
            fake_git.chmod(0o755)
            reproduce = root / "reproduce.sh"
            reproduce.write_text(
                export_repro.emit_preamble(
                    "cmake", "https://example.invalid/sample", "deadbeef",
                    "sample", "build-asan/sample",
                )
                + "\nexit 0\n",
                encoding="utf-8",
            )
            environment = os.environ.copy()
            environment["PATH"] = str(fake_bin) + os.pathsep + environment["PATH"]
            process = subprocess.run(
                ["bash", str(reproduce), str(source)],
                env=environment, capture_output=True, text=True,
            )
            self.assertEqual(process.returncode, 3)
            self.assertIn(
                "cannot verify submodule revisions",
                process.stdout + process.stderr,
            )

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
                'build_system = "cmake"\n'
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
