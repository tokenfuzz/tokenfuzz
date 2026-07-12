#!/usr/bin/env python3
"""Behavior tests for the Python MkDocs helper."""

from __future__ import annotations

import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
COMMAND = ROOT / "bin" / "docs"


class DocsCommandTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="docs-command-")
        self.root = Path(self.temporary.name)
        self.log = self.root / "docs-helper.log"
        self.venv = self.root / "docs-venv"
        (self.venv / "bin").mkdir(parents=True)
        self._write_fake("python", "PY")
        self._write_fake("mkdocs", "MK")
        self.env = os.environ.copy()
        self.env.update(DOCS_VENV=str(self.venv), DOCS_TEST_LOG=str(self.log))

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _write_fake(self, name: str, prefix: str) -> None:
        path = self.venv / "bin" / name
        path.write_text(
            f"#!{sys.executable}\n"
            "import os, sys\n"
            f"with open(os.environ['DOCS_TEST_LOG'], 'a') as stream:\n"
            f"    stream.write({prefix!r} + ' ' + ' '.join(sys.argv[1:]) + '\\n')\n",
            encoding="utf-8",
        )
        path.chmod(path.stat().st_mode | stat.S_IXUSR)

    def run_docs(self, *args: str, **env: str) -> subprocess.CompletedProcess:
        command_env = self.env.copy()
        command_env.update(env)
        return subprocess.run(
            [str(COMMAND), *args], capture_output=True, text=True, env=command_env
        )

    def log_text(self) -> str:
        return self.log.read_text(encoding="utf-8") if self.log.exists() else ""

    def test_no_arguments_print_help_without_installing(self) -> None:
        proc = self.run_docs()
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("bin/docs serve", proc.stdout)
        self.assertEqual(self.log_text(), "")

    def test_serve_installs_builds_when_needed_and_previews(self) -> None:
        site = self.root / "missing-site"
        proc = self.run_docs(
            "serve", "--dev-addr", "127.0.0.1:4100", DOCS_SITE_DIR=str(site)
        )
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertEqual(proc.stdout + proc.stderr, "")
        log = self.log_text()
        self.assertIn(f"PY -m pip install -r {ROOT / 'requirements.txt'}", log)
        self.assertIn("MK build --strict", log)
        self.assertIn("MK serve --dev-addr 127.0.0.1:4100", log)

    def test_option_leading_serve_skips_existing_site_build(self) -> None:
        site = self.root / "existing-site"
        site.mkdir()
        (site / "index.html").touch()
        proc = self.run_docs(
            "--dev-addr", "127.0.0.1:4101", DOCS_SITE_DIR=str(site)
        )
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertNotIn("MK build --strict", self.log_text())
        self.assertIn("MK serve --dev-addr 127.0.0.1:4101", self.log_text())

    def test_build_is_strict(self) -> None:
        site = self.root / "site"
        proc = self.run_docs("build", "--site-dir", str(site))
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn(f"MK build --strict --site-dir {site}", self.log_text())

    def test_help_and_unknown_command(self) -> None:
        proc = self.run_docs("--help")
        self.assertIn("bin/docs serve", proc.stdout)
        self.assertIn("bin/docs build", proc.stdout)
        proc = self.run_docs("nope")
        self.assertEqual(proc.returncode, 2)
        self.assertIn("unknown command: nope", proc.stdout + proc.stderr)
        self.assertIn("bin/docs", (ROOT / "docs" / "development.md").read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
