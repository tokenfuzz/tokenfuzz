#!/usr/bin/env python3
"""Pin export root resolution inside a symlinked benchmark-cell facade."""

from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
import uuid
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent


class ExportReproducerFacadeTests(unittest.TestCase):
    def test_facade_local_target_configuration_is_used(self) -> None:
        with tempfile.TemporaryDirectory(prefix="export-repro-facade-") as temporary:
            root = Path(temporary)
            facade = root / "facade"
            facade.mkdir()
            for name in ("bin", "lib", ".agents", "docs", "schema", "targets"):
                source = ROOT / name
                if source.exists():
                    (facade / name).symlink_to(source, target_is_directory=True)
            slug = "exr-facade-" + uuid.uuid4().hex
            slug_dir = facade / "output" / slug
            results = slug_dir / "backend" / "results"
            crash = results / "crashes" / "CRASH-FACADE-1"
            crash.mkdir(parents=True)
            source = root / "fake-src"
            (source / ".git").mkdir(parents=True)
            url = "https://example.com/facade-cell-url"
            (slug_dir / "target.toml").write_text(
                f'slug = "{slug}"\nupstream_url = "{url}"\n'
                'build_system = "cmake"\npinned_rev = "facadebeef"\n'
                'asan_bin = "build-asan/unused"\nasan_lib = ""\n'
                'includes = ["sentinel-include-only-in-facade"]\nlink_libs = []\n'
                'is_browser = "0"\n\n[threat_model]\nattacker_controls = ["bytes"]\n'
            )
            (results / ".session-env").write_text(
                f"RESULTS_DIR={results}\nTARGET_ROOT={source}\nTARGET_SLUG={slug}\n"
                f"TARGET_REV=facadebeef\nLOGDIR={root / 'logs'}\n"
            )
            (crash / "harness.c").write_text(
                "#include <stdio.h>\nint main(int argc, char **argv) { return argc && argv ? 0 : 1; }\n"
            )
            (crash / "input.bin").write_bytes(b"AAAA")
            (crash / "sanitizer.txt").write_text(
                "ASAN_RUN_HEADER: runs=1 mode=generic testcase=output/x/scratch/x.bin started=x\n"
                "==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0xdead\n"
                "READ of size 1 at 0xdead thread T0\n    #0 0xdead in main harness.c:2\n"
                "SUMMARY: AddressSanitizer: heap-buffer-overflow harness.c:2 in main\nCRASH_RATE: 1/1\n"
            )
            (crash / "report.md").write_text(
                "# CRASH-FACADE-1\n\n## Summary\n\nFixture.\n\n"
                "Trigger source: bytes\nCaller contract: obeyed\nBoundary: input file\nCaller controls: bytes\n"
            )
            env = os.environ.copy()
            env.update(
                RESULTS_DIR=str(results), TARGET_ROOT=str(source), TARGET_SLUG=slug,
                TARGET_REV="facadebeef", LOGDIR=str(root / "logs"),
            )
            proc = subprocess.run(
                [str(facade / "bin" / "export-repro"), "CRASH-FACADE-1",
                 "--slug", slug, "--crash-dir", str(crash)],
                cwd=str(facade), env=env, capture_output=True, text=True,
            )
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            script = (crash / "reproduce.sh").read_text(encoding="utf-8")
            self.assertIn("URL=" + url, script)
            self.assertNotIn("URL=FILL_ME", script)
            self.assertIn("sentinel-include-only-in-facade", script)


if __name__ == "__main__":
    unittest.main(verbosity=2)
