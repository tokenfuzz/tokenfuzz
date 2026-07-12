#!/usr/bin/env python3
"""Git context, bounds, error, target-root, and memoization coverage."""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
COMMAND = ROOT / "bin" / "show-patch"


@unittest.skipIf(shutil.which("git") is None, "git is unavailable")
class ShowPatchTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.temporary = tempfile.TemporaryDirectory(prefix="show-patch-")
        cls.root = Path(cls.temporary.name)
        cls.repo = cls.root / "repo"
        cls.repo.mkdir()
        cls.git(cls.repo, "init", "-q")
        cls.git(cls.repo, "config", "user.email", "test@example.com")
        cls.git(cls.repo, "config", "user.name", "Test")
        source = cls.repo / "big.c"
        source.write_text("".join(
            f"middle line {number} ORIGINAL\n" if number == 100 else f"context line {number}\n"
            for number in range(1, 201)
        ))
        cls.git(cls.repo, "add", "big.c")
        cls.git(cls.repo, "commit", "-qm", "initial big.c")
        source.write_text(source.read_text().replace("ORIGINAL", "MODIFIED"))
        cls.git(cls.repo, "add", "big.c")
        cls.git(cls.repo, "commit", "-qm", "tweak middle line")
        cls.commit = cls.git(cls.repo, "rev-parse", "HEAD").stdout.strip()

        cls.big_repo = cls.root / "big-repo"
        cls.big_repo.mkdir()
        cls.git(cls.big_repo, "init", "-q")
        cls.git(cls.big_repo, "config", "user.email", "test@example.com")
        cls.git(cls.big_repo, "config", "user.name", "Test")
        table = cls.big_repo / "tab.txt"
        table.write_text("".join(f"{number}\n" for number in range(1, 3001)))
        cls.git(cls.big_repo, "add", "tab.txt")
        cls.git(cls.big_repo, "commit", "-qm", "initial table")
        table.write_text("".join(f"MODIFIED {number}\n" for number in range(1, 3001)))
        cls.git(cls.big_repo, "add", "tab.txt")
        cls.git(cls.big_repo, "commit", "-qm", "rewrite every line")
        cls.big_commit = cls.git(cls.big_repo, "rev-parse", "HEAD").stdout.strip()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.temporary.cleanup()

    @staticmethod
    def git(repo, *args):
        proc = subprocess.run(
            ["git", *args], cwd=str(repo), capture_output=True, text=True
        )
        if proc.returncode != 0:
            raise RuntimeError(proc.stdout + proc.stderr)
        return proc

    def run_patch(self, *args, cwd=None, unset_results=True, **env):
        command_env = os.environ.copy()
        if unset_results:
            command_env.pop("RESULTS_DIR", None)
        command_env.update({key: str(value) for key, value in env.items()})
        return subprocess.run(
            [str(COMMAND), *map(str, args)], cwd=str(cwd or self.repo),
            capture_output=True, text=True, env=command_env,
        )

    def test_context_defaults_and_overrides(self) -> None:
        output = self.run_patch(self.commit).stdout
        self.assertIn("middle line 100 MODIFIED", output)
        self.assertIn("context line 90", output)
        self.assertIn("context line 110", output)
        self.assertNotIn("context line 80\n", output)
        self.assertNotIn("context line 120\n", output)
        self.assertEqual(len([line for line in output.splitlines() if line.startswith("@@")]), 1)
        wide = self.run_patch(self.commit, PATCH_CONTEXT=80).stdout
        self.assertIn("context line 30", wide)
        self.assertIn("context line 170", wide)
        caller = self.run_patch("--unified=60", self.commit, PATCH_CONTEXT=20).stdout
        self.assertIn("context line 50", caller)
        short = self.run_patch("-U40", self.commit, PATCH_CONTEXT=10).stdout
        self.assertIn("context line 70", short)

    def test_git_options_path_filter_and_target_root(self) -> None:
        stat_output = self.run_patch("--stat", self.commit).stdout
        self.assertRegex(stat_output, r"big\.c +\| +[0-9]+ +[+-]+")
        self.assertNotIn("context line", stat_output)
        no_patch = self.run_patch("--no-patch", self.commit).stdout
        self.assertIn("tweak middle line", no_patch)
        self.assertNotIn("context line", no_patch)
        for args in ((self.commit, "--no-pager"), ("--no-pager", self.commit)):
            self.assertIn("middle line 100 MODIFIED", self.run_patch(*args).stdout)
        self.assertIn("middle line 100 MODIFIED", self.run_patch(
            self.commit, "--", "big.c"
        ).stdout)
        self.assertIn("middle line 100 MODIFIED", self.run_patch(
            self.commit, "--", "big.c", cwd=self.root, TARGET_ROOT=self.repo
        ).stdout)

    def test_usage_invalid_context_and_unknown_revisions(self) -> None:
        proc = self.run_patch()
        self.assertEqual(proc.returncode, 2)
        self.assertIn("Usage:", proc.stdout + proc.stderr)
        invalid_context = self.run_patch(self.commit, PATCH_CONTEXT="abc")
        self.assertIn("non-numeric PATCH_CONTEXT", self.combined(invalid_context))
        for revision in ("deadbeefdeadbeef", "not-a-ref-and-not-a-path"):
            with self.subTest(revision=revision):
                proc = self.run_patch(revision)
                output = proc.stdout + proc.stderr
                self.assertEqual(proc.returncode, 128)
                self.assertIn("unknown revision", output)
                self.assertNotIn("ambiguous argument", output)
                self.assertNotIn("Use '--' to separate", output)
        self.assertIn("middle line 100 MODIFIED", self.run_patch(self.commit[:12]).stdout)

    def test_line_byte_and_combined_caps(self) -> None:
        output = self.run_patch(self.big_commit, cwd=self.big_repo, PATCH_MAX_BYTES=0).stdout
        self.assertEqual(len(output.splitlines()), 1505)
        for expected in (
            "clipped at 1500 of", "Tree of this commit", "tab.txt", "1 file changed",
            "Drill in:", "PATCH_MAX_LINES=0 PATCH_MAX_BYTES=0",
        ):
            self.assertIn(expected, output)
        custom = self.run_patch(
            self.big_commit, cwd=self.big_repo, PATCH_MAX_BYTES=0, PATCH_MAX_LINES=200
        ).stdout
        self.assertEqual(len(custom.splitlines()), 205)
        unbounded = self.run_patch(
            self.big_commit, cwd=self.big_repo, PATCH_MAX_LINES=0, PATCH_MAX_BYTES=0
        ).stdout
        self.assertGreater(len(unbounded.splitlines()), 1500)
        self.assertNotIn("clipped at", unbounded)
        self.assertIn("non-numeric PATCH_MAX_LINES", self.combined(
            self.run_patch(self.big_commit, cwd=self.big_repo, PATCH_MAX_LINES="abc")
        ))
        self.assertIn("non-numeric PATCH_MAX_BYTES", self.combined(
            self.run_patch(self.big_commit, cwd=self.big_repo, PATCH_MAX_BYTES="xyz")
        ))
        byte_only = self.run_patch(
            self.big_commit, cwd=self.big_repo, PATCH_MAX_LINES=0
        ).stdout
        self.assertIn("clipped at 32768 of", byte_only)
        self.assertIn("bytes", byte_only)
        self.assertNotIn("lines AND", byte_only)
        combined = self.run_patch(
            self.big_commit, cwd=self.big_repo, PATCH_MAX_LINES=1500, PATCH_MAX_BYTES=4000
        ).stdout
        self.assertRegex(combined, r"lines AND .* bytes")
        no_bytes = self.run_patch(
            self.big_commit, cwd=self.big_repo, PATCH_MAX_BYTES=0, PATCH_NO_CACHE=1
        ).stdout
        self.assertNotRegex(no_bytes, r"clipped at .* bytes")
        small = self.run_patch(self.commit).stdout
        self.assertNotIn("clipped at", small)
        self.assertNotIn("Tree of this commit", small)
        self.assertNotIn("Drill in:", small)

    @staticmethod
    def combined(proc):
        return proc.stdout + proc.stderr

    def test_cache_keys_hits_bypass_and_no_results_behavior(self) -> None:
        result_bytes = self.root / "results-bytes"
        result_bytes.mkdir(exist_ok=True)
        first = self.run_patch(
            self.big_commit, cwd=self.big_repo, unset_results=False,
            RESULTS_DIR=result_bytes, PATCH_MAX_BYTES=32768,
        ).stdout
        second = self.run_patch(
            self.big_commit, cwd=self.big_repo, unset_results=False,
            RESULTS_DIR=result_bytes, PATCH_MAX_BYTES=8192,
        ).stdout
        self.assertGreater(len(first.splitlines()), 100)
        self.assertGreater(len(second.splitlines()), 100)
        repeated = self.run_patch(
            self.big_commit, cwd=self.big_repo, unset_results=False,
            RESULTS_DIR=result_bytes, PATCH_MAX_BYTES=32768,
        ).stdout
        self.assertIn("cached at", repeated)

        memo = self.root / "results-memo"
        memo.mkdir(exist_ok=True)
        first = self.run_patch(
            self.big_commit, cwd=self.big_repo, unset_results=False, RESULTS_DIR=memo
        ).stdout
        second = self.run_patch(
            self.big_commit, cwd=self.big_repo, unset_results=False, RESULTS_DIR=memo
        ).stdout
        third = self.run_patch(
            self.big_commit, cwd=self.big_repo, unset_results=False, RESULTS_DIR=memo
        ).stdout
        self.assertGreater(len(first.splitlines()), 100)
        self.assertIn("cached at", second)
        self.assertIn("call #2", second)
        self.assertLessEqual(len(second.splitlines()), 50)
        self.assertIn("call #3", third)
        forced = self.run_patch(
            self.big_commit, cwd=self.big_repo, unset_results=False,
            RESULTS_DIR=memo, PATCH_NO_CACHE=1,
        ).stdout
        self.assertGreater(len(forced.splitlines()), 100)
        different = self.run_patch(
            self.big_commit, "--", "tab.txt", cwd=self.big_repo,
            unset_results=False, RESULTS_DIR=memo,
        ).stdout
        self.assertGreater(len(different.splitlines()), 100)
        no_cache_a = self.run_patch(self.big_commit, cwd=self.big_repo).stdout
        no_cache_b = self.run_patch(self.big_commit, cwd=self.big_repo).stdout
        self.assertEqual(len(no_cache_a.splitlines()), len(no_cache_b.splitlines()))
        self.assertGreater(len(no_cache_a.splitlines()), 100)
        self.assertNotIn("cached at", no_cache_b)


if __name__ == "__main__":
    unittest.main(verbosity=2)
