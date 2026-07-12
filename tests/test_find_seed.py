#!/usr/bin/env python3
"""Discovery, cache, ranking, and CLI coverage for seed lookup."""

from __future__ import annotations

import importlib.machinery
import importlib.util
import os
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
COMMAND = ROOT / "bin" / "find-seed"
loader = importlib.machinery.SourceFileLoader("find_seed_command", str(COMMAND))
spec = importlib.util.spec_from_loader(loader.name, loader)
find_seed = importlib.util.module_from_spec(spec)
loader.exec_module(find_seed)


class FindSeedTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="find-seed-")
        self.root = Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def run_command(self, target, *args, results=None):
        env = os.environ.copy()
        env["TARGET_ROOT"] = str(target)
        if results is not None:
            env["RESULTS_DIR"] = str(results)
        return subprocess.run(
            [str(COMMAND), *map(str, args)], capture_output=True, text=True, env=env
        )

    def test_help_missing_target_and_size_parser(self) -> None:
        self.assertIn("find-seed", self.run_command(self.root, "--help").stdout)
        self.assertIn("find-seed", self.run_command(self.root).stdout)
        proc = self.run_command(self.root / "missing", "test.cpp")
        self.assertEqual(proc.returncode, 2)
        self.assertIn("not set or not a directory", proc.stderr)
        self.assertEqual(find_seed.parse_size("64M"), 64 * 1024 * 1024)
        self.assertEqual(find_seed.parse_size("2k"), 2048)
        with self.assertRaises(ValueError):
            find_seed.parse_size("not-a-size")

    def test_ranked_output_and_literal_function_filename_fallback(self) -> None:
        target = self.root / "target"
        seeds = target / "testing" / "web-platform" / "tests" / "nested"
        seeds.mkdir(parents=True)
        (seeds / "canvas.html").write_text(
            "drawImage test in <canvas>\n", encoding="utf-8"
        )
        (seeds / "decode[thing]-case.html").write_text(
            "seed file without the function body\n", encoding="utf-8"
        )
        results = self.root / "results"
        proc = self.run_command(
            target, "dom/canvas/CanvasRenderingContext2D.cpp:drawImage", "5", results=results
        )
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        fields = proc.stdout.splitlines()[0].split("\t")
        self.assertEqual(fields[0], "FUNC")
        self.assertEqual(len(fields), 3)
        proc = self.run_command(
            target, "dom/codec/Codec.cpp:Decode[Thing]", "5", results=results
        )
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertRegex(proc.stdout, r"NAME\t.*/decode\[thing\]-case\.html\t\(filename match\)")

    def make_curl_like_target(self):
        target = self.root / "curl-like"
        data = target / "tests" / "data"
        data.mkdir(parents=True)
        for number in range(1, 26):
            (data / f"test{number}").write_bytes(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
        (target / "docs").mkdir()
        (target / "docs" / "sample.1").write_text("manpage stub\n")
        return target

    def test_generic_layout_discovery_and_cache_reuse(self) -> None:
        target = self.make_curl_like_target()
        results = self.root / "results"
        proc = self.run_command(target, "lib/test.c", "5", results=results)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("tests/data/test", proc.stdout)
        cache = next(results.glob(".seed-roots.*"))
        cache_text = cache.read_text(encoding="utf-8")
        self.assertIn("tests/data", cache_text)
        self.assertNotRegex(cache_text, r"/docs$")
        sentinel = self.root / "cache-sentinel-does-not-exist"
        with cache.open("a", encoding="utf-8") as stream:
            stream.write(str(sentinel) + "\n")
        os.utime(str(cache), None)
        proc = self.run_command(target, "lib/test.c", "1", results=results)
        self.assertIn(str(sentinel), cache.read_text(encoding="utf-8"))

    def test_explicit_root_override_wins_without_temp_leaks(self) -> None:
        target = self.root / "override-target"
        bad = target / "bad" / "tests"
        good = target / "curated" / "seeds"
        bad.mkdir(parents=True)
        good.mkdir(parents=True)
        (bad / "test_bad.txt").write_text("SHOULD_NOT_APPEAR test body\n")
        (good / "test_good.txt").write_text("needle from curated override\n")
        results = self.root / "results"
        results.mkdir()
        (results / ".seed-roots").write_text(str(good) + "\n")
        proc = self.run_command(target, "lib/test.c", "5", results=results)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("curated/seeds/test_good", proc.stdout)
        self.assertNotIn("bad/tests/test_bad", proc.stdout)
        self.assertEqual(list(results.glob(".seed-roots.*.tmp")), [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
