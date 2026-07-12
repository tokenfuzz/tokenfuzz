#!/usr/bin/env python3
"""Safe scoped cleanup coverage for generated state and logs."""

from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
CLEAN_STATE = ROOT / "bin" / "cleanup_state"
CLEAN_LOGS = ROOT / "bin" / "cleanup_logs"


class CleanupTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="cleanup-state-")
        self.root = Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def make_target(self, output, target):
        root = output / target
        for backend in ("codex", "claude"):
            (root / backend / "results" / "scratch-1").mkdir(parents=True)
            (root / backend / "logs").mkdir()
            (root / backend / "results" / "work-cards.jsonl").write_text("{}\n")
            (root / backend / "results" / "scratch-1" / "tc.input").write_text("tc\n")
            (root / backend / "logs" / "index.log").write_text("log\n")
        (root / "target.toml").write_text("[meta]\n")
        (root / "CRASH-CLUSTERS.html").write_text("<html>\n")
        (root / "CRASH-CLUSTERS.md").write_text("# crash\n")
        (root / "FINDING-CLUSTERS.html").write_text("<html>\n")
        (root / "FINDING-CLUSTERS.md").write_text("# find\n")
        (root / ".target-state").write_text("state\n")
        return root

    def run_command(self, command, output, *args):
        return subprocess.run(
            [str(command), "--output-root", str(output), *map(str, args)],
            capture_output=True, text=True,
        )

    def test_default_preserves_only_metadata_and_ground_truth(self) -> None:
        output = self.root / "out"
        for target in ("libxml2", "cjson"):
            self.make_target(output, target)
        proc = self.run_command(CLEAN_STATE, output)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("cleaned=2", proc.stdout)
        self.assertIn("failed=0", proc.stdout)
        for target in ("libxml2", "cjson"):
            root = output / target
            self.assertTrue((root / "target.toml").is_file())
            self.assertFalse((root / "codex").exists())
            self.assertFalse((root / "claude").exists())
            self.assertFalse((root / "CRASH-CLUSTERS.md").exists())
            self.assertFalse((root / "FINDING-CLUSTERS.md").exists())
            self.assertFalse((root / ".target-state").exists())
        canary_output = self.root / "canary-output"
        canary = self.make_target(canary_output, "canary")
        (canary / ".ground-truth.json").write_text("{}\n")
        proc = self.run_command(CLEAN_STATE, canary_output, "--target", "canary")
        self.assertEqual(proc.returncode, 0)
        self.assertIn("removed 7 entries, 2 preserved", proc.stdout)
        self.assertTrue((canary / "target.toml").is_file())
        self.assertTrue((canary / ".ground-truth.json").is_file())

    def test_dry_run_target_backend_keep_and_keep_only_scopes(self) -> None:
        dry_output = self.root / "dry"
        target = self.make_target(dry_output, "libxml2")
        proc = self.run_command(CLEAN_STATE, dry_output, "--dry-run")
        self.assertEqual(proc.returncode, 0)
        self.assertIn("would remove", proc.stdout)
        self.assertTrue((target / "codex").is_dir())
        self.assertTrue((target / "CRASH-CLUSTERS.md").is_file())

        filtered = self.root / "filtered"
        selected = self.make_target(filtered, "libxml2")
        other = self.make_target(filtered, "cjson")
        self.assertEqual(self.run_command(
            CLEAN_STATE, filtered, "--target", "libxml2", "--quiet"
        ).returncode, 0)
        self.assertFalse((selected / "codex").exists())
        self.assertTrue((other / "codex").is_dir())

        for flag in ("--backend", "--backends"):
            scoped = self.root / flag[2:]
            target = self.make_target(scoped, "libxml2")
            self.assertEqual(self.run_command(
                CLEAN_STATE, scoped, "--target", "libxml2", flag, "codex", "--quiet"
            ).returncode, 0)
            self.assertFalse((target / "codex").exists())
            self.assertTrue((target / "claude").is_dir())
            self.assertTrue((target / "CRASH-CLUSTERS.md").is_file())

        keep_output = self.root / "keep"
        kept = self.make_target(keep_output, "libxml2")
        self.run_command(CLEAN_STATE, keep_output, "--target", "libxml2", "--keep", "codex", "--quiet")
        self.assertTrue((kept / "codex").is_dir())
        self.assertFalse((kept / "claude").exists())
        self.assertFalse((kept / "CRASH-CLUSTERS.md").exists())
        only_output = self.root / "only"
        only = self.make_target(only_output, "libxml2")
        self.run_command(CLEAN_STATE, only_output, "--target", "libxml2", "--keep-only", "codex", "--quiet")
        self.assertTrue((only / "target.toml").is_file())
        self.assertTrue((only / "codex").is_dir())
        self.assertFalse((only / "claude").exists())
        empty_output = self.root / "empty-only"
        empty = self.make_target(empty_output, "libxml2")
        proc = self.run_command(CLEAN_STATE, empty_output, "--target", "libxml2", "--keep-only", "")
        self.assertEqual(proc.returncode, 0)
        self.assertIn("cleaned=1", proc.stdout)
        self.assertTrue((empty / "target.toml").is_file())
        self.assertFalse((empty / "codex").exists())

    def test_invalid_components_missing_root_orphan_and_idempotency(self) -> None:
        output = self.root / "validation"
        target = self.make_target(output, "libxml2")
        for invalid in ("../etc", "/etc", ".git", "."):
            with self.subTest(keep=invalid):
                proc = self.run_command(CLEAN_STATE, output, "--keep", invalid)
                self.assertEqual(proc.returncode, 2)
                self.assertIn("invalid --keep", proc.stdout + proc.stderr)
        self.assertTrue((target / "codex").is_dir())
        proc = self.run_command(CLEAN_STATE, self.root / "missing")
        self.assertEqual(proc.returncode, 2)
        self.assertIn("output root not found", proc.stdout + proc.stderr)
        orphan_output = self.root / "orphan-output"
        (orphan_output / "orphan" / "codex" / "logs").mkdir(parents=True)
        (orphan_output / "orphan" / "codex" / "logs" / "index.log").write_text("log\n")
        self.assertEqual(self.run_command(
            CLEAN_STATE, orphan_output, "--target", "orphan", "--quiet"
        ).returncode, 0)
        self.assertTrue((orphan_output / "orphan").is_dir())
        self.assertFalse((orphan_output / "orphan" / "codex").exists())
        repeat_output = self.root / "repeat"
        self.make_target(repeat_output, "libxml2")
        self.run_command(CLEAN_STATE, repeat_output, "--quiet")
        proc = self.run_command(CLEAN_STATE, repeat_output)
        self.assertEqual(proc.returncode, 0)
        self.assertIn("already clean", proc.stdout)

    def test_symlinks_are_unlinked_without_following_and_traversal_is_rejected(self) -> None:
        output = self.root / "symlink-output"
        target = self.make_target(output, "libxml2")
        sentinel = self.root / "sentinel.keep"
        sentinel.write_text("must-survive\n")
        (target / "escape-link").symlink_to(sentinel)
        self.run_command(CLEAN_STATE, output, "--target", "libxml2", "--quiet")
        self.assertFalse((target / "escape-link").exists())
        self.assertTrue(sentinel.is_file())
        backend_output = self.root / "backend-symlink"
        backend_target = backend_output / "libxml2"
        backend_target.mkdir(parents=True)
        (backend_target / "target.toml").write_text("[meta]\n")
        backend_sentinel = self.root / "backend.keep"
        backend_sentinel.write_text("must-survive\n")
        (backend_target / "codex").symlink_to(backend_sentinel)
        self.run_command(CLEAN_STATE, backend_output, "--target", "libxml2", "--backend", "codex", "--quiet")
        self.assertFalse((backend_target / "codex").exists())
        self.assertTrue(backend_sentinel.is_file())
        traversal = self.root / "traversal"
        target = self.make_target(traversal, "libxml2")
        for args, message in (
            (("--target", "../libxml2"), "invalid target component"),
            (("--target", "libxml2", "--backends", "../codex"), "invalid backend component"),
        ):
            proc = self.run_command(CLEAN_STATE, traversal, *args)
            self.assertEqual(proc.returncode, 1)
            self.assertIn(message, proc.stdout + proc.stderr)
            self.assertTrue((target / "codex").is_dir())

    def test_cleanup_logs_scopes_defaults_and_guards(self) -> None:
        output = self.root / "logs-output"
        target = self.make_target(output, "libxml2")
        proc = self.run_command(CLEAN_LOGS, output, "--target", "libxml2", "--backend", "codex", "--quiet")
        self.assertEqual(proc.returncode, 0)
        self.assertFalse((target / "codex" / "logs" / "index.log").exists())
        self.assertTrue((target / "claude" / "logs" / "index.log").is_file())
        defaults = self.root / "default-logs"
        target = self.make_target(defaults, "libxml2")
        for backend in ("gemini", "grok", "oss"):
            (target / backend / "logs").mkdir(parents=True)
            (target / backend / "logs" / "index.log").write_text("log\n")
        self.run_command(CLEAN_LOGS, defaults, "--target", "libxml2", "--quiet")
        for backend in ("claude", "codex", "gemini", "grok", "oss"):
            self.assertFalse((target / backend / "logs" / "index.log").exists())
        guarded = self.root / "guarded-logs"
        target = self.make_target(guarded, "libxml2")
        proc = self.run_command(CLEAN_LOGS, guarded, "--target", "../libxml2")
        self.assertEqual(proc.returncode, 1)
        self.assertIn("invalid target component", proc.stdout + proc.stderr)
        self.assertTrue((target / "codex" / "logs" / "index.log").is_file())

    def test_nested_targets_are_discovered_without_benchmark_facades(self) -> None:
        output = self.root / "nested"
        nested = self.make_target(output, "samples/sample-x")
        facade = output / "benchmark/codex/run-1/cells/harness-r1/repo-root/output/cjson"
        (facade / "claude/results/scratch-1").mkdir(parents=True)
        (facade / "target.toml").write_text("[meta]\n")
        facade_state = facade / "claude/results/scratch-1/tc.input"
        facade_state.write_text("tc\n")
        dry = self.run_command(CLEAN_STATE, output, "--dry-run").stdout
        self.assertIn("samples/sample-x", dry)
        self.assertNotIn("benchmark/", dry)
        self.run_command(CLEAN_STATE, output, "--quiet")
        self.assertFalse((nested / "codex/results/scratch-1/tc.input").exists())
        self.assertTrue((nested / "target.toml").is_file())
        self.assertTrue(facade_state.is_file())

        log_output = self.root / "nested-logs"
        nested = self.make_target(log_output, "samples/sample-x")
        log_facade = log_output / "benchmark/codex/run-1/cells/harness-r1/repo-root/output/cjson"
        (log_facade / "codex/logs").mkdir(parents=True)
        (log_facade / "target.toml").write_text("[meta]\n")
        facade_log = log_facade / "codex/logs/index.log"
        facade_log.write_text("facade\n")
        self.run_command(CLEAN_LOGS, log_output, "--target", "samples/sample-x", "--backend", "codex", "--quiet")
        self.assertFalse((nested / "codex/logs/index.log").exists())
        self.assertTrue((nested / "claude/logs/index.log").is_file())
        (nested / "codex/logs/index.log").write_text("log\n")
        dry = self.run_command(CLEAN_LOGS, log_output, "--dry-run").stdout
        self.assertIn("samples/sample-x", dry)
        self.assertNotIn("benchmark/", dry)
        self.run_command(CLEAN_LOGS, log_output, "--quiet")
        self.assertFalse((nested / "claude/logs/index.log").exists())
        self.assertTrue(facade_log.is_file())

    def test_nested_gitkeep_is_preserved_and_unreadable_target_fails_loud(self) -> None:
        output = self.root / "gitkeep"
        logs = output / "libxml2/codex/logs"
        (logs / "archive").mkdir(parents=True)
        (output / "libxml2/target.toml").write_text("[meta]\n")
        marker = logs / "archive/.gitkeep"
        marker.write_text("keep\n")
        index = logs / "index.log"
        index.write_text("log\n")
        dry = self.run_command(
            CLEAN_LOGS, output, "--target", "libxml2", "--backend", "codex", "--dry-run"
        ).stdout
        self.assertIn("1 entries", dry)
        self.assertEqual(self.run_command(
            CLEAN_LOGS, output, "--target", "libxml2", "--backend", "codex", "--quiet"
        ).returncode, 0)
        self.assertTrue(marker.is_file())
        self.assertFalse(index.exists())

        unreadable_output = self.root / "unreadable"
        target = unreadable_output / "sample"
        (target / "generated").mkdir(parents=True)
        (target / "target.toml").write_text("[meta]\n")
        generated = target / "generated/value"
        generated.write_text("state\n")
        target.chmod(0o311)
        try:
            try:
                list(target.iterdir())
                bypasses_read_bit = True
            except PermissionError:
                bypasses_read_bit = False
            if bypasses_read_bit:
                self.skipTest("reader bypasses directory read bit")
            proc = self.run_command(CLEAN_STATE, unreadable_output, "--target", "sample")
            self.assertEqual(proc.returncode, 1)
            self.assertIn("failed to inspect", proc.stdout + proc.stderr)
            self.assertTrue(generated.is_file())
        finally:
            target.chmod(0o700)


if __name__ == "__main__":
    unittest.main(verbosity=2)
