#!/usr/bin/env python3
"""Filesystem preservation when a package installation fails."""

from __future__ import annotations

import os
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "lib"))
import languages


class BootstrapFileTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="bootstrap-files-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name) / "checkout"
        self.root.mkdir()
        self.outside = self.root.parent / "outside.txt"
        self.outside.write_text("unrelated\n")
        self.lock = self.root / "package-lock.json"
        self.lock.write_text("original\n")
        self.lock.chmod(0o640)

    def fail_install(self, body: str) -> int:
        return languages.execute_bootstrap_plan(
            self.root,
            {"language": "javascript", "cmds": [[
                sys.executable, "-c",
                "from pathlib import Path; import os; " + body + "; raise SystemExit(7)",
            ]]},
            self.root / ".audit" / "bootstrap.log",
            self.root / ".audit" / "bootstrap.sh",
        )

    def test_rollback_replaces_installer_links_without_writing_through_them(self) -> None:
        for operation in ("symlink_to", "hardlink_to"):
            with self.subTest(operation=operation):
                result = self.fail_install(
                    "lock = Path('package-lock.json'); lock.unlink(); "
                    f"lock.{operation}('../outside.txt')"
                )
                self.assertEqual(result, 7)
                self.assertEqual(self.outside.read_text(), "unrelated\n")
                self.assertEqual(self.lock.read_text(), "original\n")
                self.assertFalse(self.lock.is_symlink())
                self.assertNotEqual(self.lock.stat().st_ino, self.outside.stat().st_ino)
                self.assertEqual(self.lock.stat().st_mode & 0o777, 0o640)

    def test_rollback_preserves_original_and_dangling_metadata_symlinks(self) -> None:
        self.lock.unlink()
        self.lock.symlink_to("../outside.txt")
        workspace = self.root / "pnpm-workspace.yaml"
        workspace.symlink_to("missing-workspace.yaml")
        result = self.fail_install(
            "lock = Path('package-lock.json'); lock.unlink(); lock.write_text('new'); "
            "workspace = Path('pnpm-workspace.yaml'); workspace.unlink(); "
            "workspace.write_text('new')"
        )
        self.assertEqual(result, 7)
        self.assertTrue(self.lock.is_symlink())
        self.assertEqual(os.readlink(self.lock), "../outside.txt")
        self.assertEqual(self.outside.read_text(), "unrelated\n")
        self.assertTrue(workspace.is_symlink())
        self.assertEqual(os.readlink(workspace), "missing-workspace.yaml")

    def test_failed_install_does_not_remove_a_linked_dependency_directory(self) -> None:
        dependencies = self.root.parent / "dependencies"
        dependencies.mkdir()
        (dependencies / "keep.txt").write_text("keep\n")
        result = self.fail_install(
            "Path('node_modules').symlink_to('../dependencies', target_is_directory=True); "
            "Path('package-lock.json').write_text('changed')"
        )
        self.assertEqual(result, 7)
        self.assertEqual((dependencies / "keep.txt").read_text(), "keep\n")
        self.assertFalse((self.root / "node_modules").is_symlink())
        self.assertEqual(self.lock.read_text(), "original\n")

    def test_failed_install_removes_a_non_directory_node_modules_entry(self) -> None:
        result = self.fail_install(
            "Path('node_modules').write_text('partial'); "
            "Path('package-lock.json').write_text('changed')"
        )
        self.assertEqual(result, 7)
        self.assertFalse((self.root / "node_modules").exists())
        self.assertEqual(self.lock.read_text(), "original\n")

    def test_rollback_replaces_directories_at_metadata_paths(self) -> None:
        workspace = self.root / "pnpm-workspace.yaml"
        result = self.fail_install(
            "lock = Path('package-lock.json'); lock.unlink(); lock.mkdir(); "
            "workspace = Path('pnpm-workspace.yaml'); workspace.mkdir()"
        )
        self.assertEqual(result, 7)
        self.assertTrue(self.lock.is_file())
        self.assertEqual(self.lock.read_text(), "original\n")
        self.assertFalse(workspace.exists())

    def test_cleanup_cannot_follow_a_link_into_other_audit_state(self) -> None:
        audit = self.root / ".audit"
        audit.mkdir()
        kept = audit / "kept"
        kept.mkdir()
        sentinel = kept / "keep.txt"
        sentinel.write_text("keep\n")
        generated = audit / "generated-release"
        generated.symlink_to("kept", target_is_directory=True)
        for relative in (".audit", ".audit/generated-release"):
            with self.subTest(relative=relative):
                result = languages.execute_bootstrap_plan(
                    self.root, {"clean_dirs": [relative]},
                    audit / "bootstrap.log", audit / "bootstrap.sh",
                )
                self.assertEqual(result, 2)
                self.assertEqual(sentinel.read_text(), "keep\n")

    def test_cleanup_cannot_delete_the_audit_root(self) -> None:
        audit = self.root / ".audit"
        audit.mkdir()
        sentinel = audit / "keep.txt"
        sentinel.write_text("keep\n")
        generated = audit / "generated-release"
        generated.symlink_to(".", target_is_directory=True)
        result = languages.execute_bootstrap_plan(
            self.root, {"clean_dirs": [".audit/generated-release"]},
            audit / "bootstrap.log", audit / "bootstrap.sh",
        )
        self.assertEqual(result, 2)
        self.assertEqual(sentinel.read_text(), "keep\n")


if __name__ == "__main__":
    unittest.main()
