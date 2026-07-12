#!/usr/bin/env python3
"""End-to-end generated library and header discovery coverage."""

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
class ExportReproducerLibraryDiscoveryTests(unittest.TestCase):
    def test_unconfigured_library_and_generated_headers_are_discovered(self) -> None:
        with tempfile.TemporaryDirectory(prefix="export-repro-lib-") as temporary:
            root = Path(temporary)
            source = root / "fake-src"
            (source / ".git").mkdir(parents=True)
            (source / "CMakeLists.txt").write_text(
                "cmake_minimum_required(VERSION 3.10)\nproject(tgt C)\n"
                "add_library(tgt tgt.c)\nadd_library(aaux STATIC aaux.c)\n"
                "set_target_properties(aaux PROPERTIES ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/tests)\n"
                "file(MAKE_DIRECTORY ${CMAKE_BINARY_DIR}/interface ${CMAKE_BINARY_DIR}/conf)\n"
                "configure_file(${CMAKE_SOURCE_DIR}/api.h.in ${CMAKE_BINARY_DIR}/interface/api.h)\n"
                "configure_file(${CMAKE_SOURCE_DIR}/config.h.in ${CMAKE_BINARY_DIR}/conf/config.h)\n"
            )
            (source / "config.h.in").write_text("#define WIDGET_OK 1\n")
            (source / "api.h.in").write_text(
                "#if defined HAVE_CONFIG_H\n#include \"config.h\"\n#endif\n"
                "#ifndef WIDGET_OK\n#error \"build config not applied\"\n#endif\nint boom(void);\n"
            )
            (source / "aaux.c").write_text("int aaux_unused(void) { return 0; }\n")
            (source / "tgt.h").write_text("int boom(void);\n")
            (source / "tgt.c").write_text(
                "#include \"tgt.h\"\n#include <stdlib.h>\n#include <string.h>\n"
                "int boom(void) { volatile int n = 8; char *p = (char *)malloc(4);"
                " memset(p, 'A', n); int r = p[0]; free(p); return r; }\n"
            )
            output = root / "output" / "exr-libdisc"
            results = output / "codex" / "results"
            crash = results / "crashes" / "CRASH-LIB-1"
            crash.mkdir(parents=True)
            (output / "target.toml").write_text(
                'slug = "exr-libdisc"\nupstream_url = "https://example.com/fake"\n'
                'build_system = "cmake"\npinned_rev = "deadbeef"\n'
                'asan_bin = "build-asan/unused"\nasan_lib = ""\n'
                'includes = []\nlink_libs = []\nis_browser = "0"\n\n'
                '[threat_model]\nattacker_controls = ["bytes"]\n'
            )
            (results / ".session-env").write_text(
                f"RESULTS_DIR={results}\nTARGET_ROOT={source}\nTARGET_SLUG=exr-libdisc\n"
                f"TARGET_REV=deadbeef\nLOGDIR={root / 'logs'}\n"
            )
            (crash / "harness.c").write_text(
                '#include "api.h"\nint main(void) { return boom(); }\n'
            )
            (crash / "sanitizer.txt").write_text(
                "ASAN_RUN_HEADER: runs=1 mode=generic testcase= started=x\n"
                "==99999==ERROR: AddressSanitizer: heap-buffer-overflow on address 0xdead\n"
                "READ of size 1 at 0xdead thread T0\n    #0 0xdead in boom tgt.c:7\n"
                "SUMMARY: AddressSanitizer: heap-buffer-overflow tgt.c:7 in boom\n"
            )
            (crash / "report.md").write_text(
                "# CRASH-LIB-1\n\n## Summary\n\nEnd-to-end fixture.\n\n"
                "Trigger source: bytes\nCaller contract: obeyed\nBoundary: library API\nCaller controls: bytes\n"
            )
            proc = subprocess.run(
                [str(EXPORT), "CRASH-LIB-1"], cwd=str(output),
                capture_output=True, text=True,
            )
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            reproduce = crash / "reproduce.sh"
            self.assertTrue(reproduce.is_file())
            script = reproduce.read_text(encoding="utf-8")
            patterns = (
                "linking auto-discovered library", r"-iname tests .*-prune",
                r"-type f -name '\*\.a'", r'san_lib:\+"\$san_lib"',
                r'gen_inc="\$gen_inc -I\$d"', r"-O1.*\$gen_inc",
                r'have_config=" -DHAVE_CONFIG_H"', r"\$gen_inc\$have_config",
            )
            for pattern in patterns:
                with self.subTest(pattern=pattern):
                    self.assertRegex(script, pattern)
            run = subprocess.run(
                ["bash", str(reproduce), str(source)], capture_output=True, text=True
            )
            runtime = run.stdout + run.stderr
            self.assertNotEqual(run.returncode, 0, runtime[-2000:])
            self.assertIn("linking auto-discovered library", runtime)
            self.assertIn("AddressSanitizer: heap-buffer-overflow", runtime)
            self.assertNotRegex(runtime.casefold(), r"undefined symbol|symbol.* not found")


if __name__ == "__main__":
    unittest.main(verbosity=2)
