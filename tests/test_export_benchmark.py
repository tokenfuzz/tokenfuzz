#!/usr/bin/env python3
"""Self-contained benchmark bundle selection and sanitization coverage."""

from __future__ import annotations

import json
import re
import subprocess
import tempfile
import unittest
import urllib.parse
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
COMMAND = ROOT / "bin" / "export-benchmark"


class ExportBenchmarkTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="export-benchmark-")
        self.root = Path(self.temporary.name)
        self.bench = self.root / "bench"
        self.make_run("codex", "20260101-000000", "sampleproj")
        self.make_run("gemini", "20260101-000001", "sampleproj")
        self.make_run("gemini", "20260102-000000", "apptool")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def make_run(self, backend, run_id, target):
        run = self.bench / backend / run_id
        crash = run / "pool" / "crashes" / "CRASH-0001"
        (crash / ".audit").mkdir(parents=True)
        (run / "pool" / "codeqcrashes").mkdir(parents=True)
        (run / "cells" / "harness-r1").mkdir(parents=True)
        (run / "run.json").write_text(json.dumps({
            "runid": run_id, "target": target, "backend": backend,
            "conditions": ["harness"],
        }) + "\n")
        (run / "report.json").write_text(json.dumps({
            "bench_dir": f"/Users/someone/src/tokenfuzz/output/benchmark/{backend}/{run_id}",
            "run": {"runid": run_id, "target": target, "backend": backend},
            "conditions": [],
        }) + "\n")
        (crash / "report.md").write_text(
            f"# CRASH-0001\nTestcase at {ROOT}/output/benchmark/{backend}/{run_id}/x.tc\n"
        )
        (crash / "sanitizer.txt").write_text("sanitizer output\n")
        (crash / ".audit" / "promotion.log").write_text(f"internal {ROOT}/secret\n")
        executable = crash / "testcase_bin"
        executable.write_bytes(b"\x7fELF\x00compiled exe build path " + str(ROOT).encode())
        executable.chmod(0o755)
        (crash / "input.bin").write_bytes(b"crash\x00input\x00bytes\x00")
        (run / "cells" / "harness-r1" / "log").write_text(f"cell {ROOT}/cell\n")

    def export(self, output, *args):
        return subprocess.run(
            [str(COMMAND), "--bench-root", str(self.bench), "--format", "dir",
             *map(str, args), "--out", str(output)],
            capture_output=True, text=True,
        )

    def assert_links_resolve(self, root):
        html = root / "benchmark-result.html"
        for href in re.findall(r'href="([^"]+)"', html.read_text(encoding="utf-8")):
            if href.startswith(("#", "http", "mailto")):
                continue
            target = html.parent / urllib.parse.unquote(href.split("#", 1)[0])
            self.assertTrue(target.exists(), href)

    def test_full_export_excludes_internal_and_executable_artifacts(self) -> None:
        output = self.root / "all"
        proc = self.export(output)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertTrue((output / "benchmark-result.html").is_file())
        self.assertTrue((output / "benchmark-result.md").is_file())
        self.assertTrue((output / "codex").is_dir())
        self.assertTrue((output / "gemini").is_dir())
        crash = output / "codex" / "20260101-000000" / "pool" / "crashes" / "CRASH-0001"
        self.assertFalse((output / "codex" / "20260101-000000" / "cells").exists())
        self.assertFalse((crash / ".audit").exists())
        self.assertTrue((crash / "report.md").is_file())
        self.assertFalse((crash / "testcase_bin").exists())
        self.assertTrue((crash / "input.bin").is_file())
        leaks = []
        for path in output.rglob("*"):
            if not path.is_file():
                continue
            try:
                if str(ROOT) in path.read_text(encoding="utf-8"):
                    leaks.append(path)
            except UnicodeDecodeError:
                pass
        self.assertEqual(leaks, [])

    def test_backend_and_target_filters_scope_runs_and_crosstab(self) -> None:
        backend = self.root / "codex-only"
        self.assertEqual(self.export(backend, "--backend", "codex").returncode, 0)
        self.assertTrue((backend / "codex").is_dir())
        self.assertFalse((backend / "gemini").exists())
        target = self.root / "sampleproj-only"
        proc = self.export(target, "--target", "sampleproj")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertTrue((target / "codex" / "20260101-000000").is_dir())
        self.assertTrue((target / "gemini" / "20260101-000001").is_dir())
        self.assertFalse((target / "gemini" / "20260102-000000").exists())
        self.assertNotIn("apptool", (target / "benchmark-result.md").read_text(encoding="utf-8"))
        self.assert_links_resolve(target)

    def test_invalid_and_empty_selections_fail(self) -> None:
        self.assertNotEqual(self.export(
            self.root / "err1", "--run-id", "20260101-000000"
        ).returncode, 0)
        self.assertNotEqual(self.export(
            self.root / "err2", "--target", "nope"
        ).returncode, 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
