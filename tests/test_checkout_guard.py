#!/usr/bin/env python3
"""Checkout isolation checks using real temporary Git repositories."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

GUARD = Path(__file__).with_name("checkout_guard.py")


class CheckoutGuardTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name) / "checkout"
        self.root.mkdir()
        self.saved = self.root.parent / "snapshot.json"
        self.tracked = self.root / "tracked file.txt"
        self.tracked.write_text("original")
        subprocess.run(["git", "init", "-q", str(self.root)], check=True)
        subprocess.run(["git", "-C", str(self.root), "add", "."], check=True)

    def run_guard(self, operation):
        return subprocess.run(
            [sys.executable, str(GUARD), operation, str(self.root), str(self.saved)],
            capture_output=True, text=True, check=False,
        )

    def record(self):
        result = self.run_guard("record")
        self.assertEqual(result.returncode, 0, result.stderr)

    def assert_changed(self):
        result = self.run_guard("check")
        self.assertEqual(result.returncode, 3, result.stderr)
        self.assertIn(self.tracked.name, result.stdout)

    def test_dirty_baseline_and_reads_are_not_mutations(self):
        self.tracked.write_text("already dirty")
        self.record()
        self.tracked.read_bytes()
        (self.root / "untracked.txt").write_text("ignored")
        self.assertEqual(self.run_guard("check").returncode, 0)

    def test_restore_bytes_and_mtime_is_detected(self):
        self.record()
        before = self.tracked.stat()
        self.tracked.write_text("modified")
        self.tracked.write_text("original")
        os.utime(self.tracked, ns=(before.st_atime_ns, before.st_mtime_ns))
        self.assert_changed()

    def test_deletion_is_detected(self):
        self.record()
        self.tracked.unlink()
        self.assert_changed()

    def test_missing_tracked_path_reappearing_is_detected(self):
        self.tracked.unlink()
        self.record()
        self.tracked.write_text("original")
        self.assert_changed()

    def test_replacement_with_preserved_mtime_is_detected(self):
        self.record()
        before = self.tracked.stat()
        replacement = self.root / "replacement"
        replacement.write_text("original")
        os.utime(replacement, ns=(before.st_atime_ns, before.st_mtime_ns))
        replacement.replace(self.tracked)
        self.assert_changed()

    def test_git_failure_is_not_reported_as_an_archive(self):
        (self.root / ".git" / "index").write_bytes(b"invalid index")
        result = self.run_guard("record")
        self.assertEqual(result.returncode, 2)
        self.assertIn("checkout guard:", result.stderr)
        self.assertFalse(self.saved.exists())

    def test_archive_explicitly_skips(self):
        (self.root / ".git").rename(self.root.parent / "git-metadata")
        result = self.run_guard("record")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("skipped", result.stderr)
        self.assertEqual(self.run_guard("check").returncode, 0)

    def test_missing_snapshot_is_an_error(self):
        self.assertEqual(self.run_guard("check").returncode, 2)


if __name__ == "__main__":
    unittest.main()
