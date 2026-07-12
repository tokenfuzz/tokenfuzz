#!/usr/bin/env python3
"""Pin root resolution for peer-fix cards inside symlinked cell facades."""

from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
import uuid
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent


class PeerFixCardsFacadeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="peer-facade-")
        self.root = Path(self.temporary.name)
        self.facade = self.root / "facade"
        self.facade.mkdir()
        for name in ("bin", "lib", ".agents", "docs", "schema", "targets"):
            source = ROOT / name
            if source.exists():
                (self.facade / name).symlink_to(source, target_is_directory=True)
        self.slug = "pfc-facade-" + uuid.uuid4().hex
        self.slug_dir = self.facade / "output" / self.slug
        self.results = self.slug_dir / "backend" / "results"
        self.results.mkdir(parents=True)
        self.source = self.root / "fake-src"
        (self.source / ".git").mkdir(parents=True)
        (self.slug_dir / "target.toml").write_text(
            f'slug = "{self.slug}"\n'
            'upstream_url = "https://example.com/facade-cell-url"\n'
            'build_system = "cmake"\n'
            'pinned_rev = "facadebeef"\nincludes = []\nlink_libs = []\n'
            'is_browser = "0"\n\n[threat_model]\nattacker_controls = ["bytes"]\n',
            encoding="utf-8",
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def run_command(self, script_root):
        output = self.results / "s6-peer-cards.jsonl"
        if output.exists():
            output.unlink()
        env = os.environ.copy()
        env.update(
            TARGET_ROOT=str(self.source), TARGET_SLUG=self.slug,
            LLM_DECIDE_DISABLE="1",
        )
        if script_root is None:
            env.pop("SCRIPT_ROOT", None)
        else:
            env["SCRIPT_ROOT"] = str(script_root)
        proc = subprocess.run(
            [
                str(self.facade / "bin" / "peer-fix-cards"),
                "--target-path", str(self.source), "--target-slug", self.slug,
                "--results-dir", str(self.results), "--output", str(output),
            ],
            cwd=str(self.facade), env=env, capture_output=True, text=True,
        )
        return proc, output

    def assert_facade_config_used(self, proc, output):
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn(f"facade/output/{self.slug}/target.toml", proc.stderr)
        self.assertNotIn("target.toml not found", proc.stderr)
        self.assertTrue(output.is_file())

    def test_file_based_root_does_not_chase_bin_symlink(self) -> None:
        proc, output = self.run_command(None)
        self.assert_facade_config_used(proc, output)

    def test_script_root_environment_override_wins(self) -> None:
        proc, output = self.run_command(self.facade)
        self.assert_facade_config_used(proc, output)

    def test_audit_exports_script_root_to_children(self) -> None:
        source = (ROOT / "lib" / "audit_runner.py").read_text(encoding="utf-8")
        self.assertIn('os.environ["SCRIPT_ROOT"] = str(root)', source)


if __name__ == "__main__":
    unittest.main(verbosity=2)
