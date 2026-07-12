#!/usr/bin/env python3
"""Behavior tests for bounded, allowlisted target.toml auto-repair."""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
COMMAND = ROOT / "bin" / "auto-repair-target-toml"


class TargetTomlAutoRepairTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="target-toml-repair-")
        self.root = Path(self.temporary.name)
        self.fixture = self.root / "fixture"
        self.fixture.mkdir()
        self.toml = self.fixture / "target.toml"
        self.build_log = self.fixture / "H-stub-harness.c.deadbeefdeadbeefdeadbeef.build.log"
        self.logs = self.root / "logs"
        self.write_base()
        self.build_log.write_text(
            "/usr/bin/ld: /tmp/fixture.o: undefined reference to `sample_alloc'\n"
            "clang: error: linker command failed with exit code 1\n",
            encoding="utf-8",
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write_base(self) -> None:
        self.toml.write_text(
            'target = "sampleproj"\nupstream_url = "https://example.invalid/sampleproj"\n'
            'build_system = "cmake"\npinned_rev = "deadbeef"\n\n'
            'includes = [".", "include"]\nlink_libs = ["/path/to/sample.c"]\n'
            'defines = ["-DNOCRYPT"]\n\n[sanitizer]\nenabled = ["asan"]\n',
            encoding="utf-8",
        )

    def run_repair(self, proposal=None, **env):
        command_env = os.environ.copy()
        command_env.update(LLM_DECIDE_DISABLE="1")
        if proposal is not None:
            command_env["LLM_DECIDE_MOCK_TARGET_TOML_REPAIR"] = json.dumps(proposal)
        else:
            command_env.pop("LLM_DECIDE_MOCK_TARGET_TOML_REPAIR", None)
        command_env.update({key: str(value) for key, value in env.items()})
        return subprocess.run(
            [str(COMMAND), "--toml", str(self.toml), "--build-log", str(self.build_log),
             "--logdir", str(self.logs)],
            capture_output=True, text=True, env=command_env,
        )

    def test_disabled_and_unavailable_paths_do_not_write(self) -> None:
        before = self.toml.read_bytes()
        proc = self.run_repair(TARGET_TOML_AUTO_REPAIR=0)
        self.assertEqual(proc.returncode, 1)
        self.assertEqual(self.toml.read_bytes(), before)
        proc = self.run_repair()
        self.assertEqual(proc.returncode, 1)
        self.assertEqual(self.toml.read_bytes(), before)

    def test_safe_additions_create_backup_marker_and_audit_log(self) -> None:
        proposal = {"link_libs": ["sample_util.c", "sample_back.c"], "defines": ["-DSAMPLE_INTERNAL"]}
        proc = self.run_repair(proposal)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        text = self.toml.read_text(encoding="utf-8")
        self.assertIn("sample_util.c", text)
        self.assertIn("SAMPLE_INTERNAL", text)
        self.assertEqual(len(list(self.fixture.glob("target.toml.bak.*"))), 1)
        self.assertEqual(len(list(self.logs.glob(".target-toml-auto-repair-*"))), 1)
        self.assertIn("APPLY:", (self.logs / "target-toml-auto-repair.log").read_text(encoding="utf-8"))

        backup_count = len(list(self.fixture.glob("target.toml.bak.*")))
        proc = self.run_repair(proposal)
        self.assertIn(proc.returncode, (0, 1), proc.stdout + proc.stderr)
        self.assertEqual(len(list(self.fixture.glob("target.toml.bak.*"))), backup_count)

    def test_unsafe_entries_are_filtered_while_safe_entries_apply(self) -> None:
        proc = self.run_repair({
            "link_libs": ["`touch /tmp/PWN`", "-fno-something"],
            "defines": ["/abs/path", "-DGOOD"],
        })
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        text = self.toml.read_text(encoding="utf-8")
        self.assertIn("DGOOD", text)
        self.assertNotIn("`touch /tmp/PWN`", text)
        self.assertNotIn("/abs/path", text)

    def test_empty_proposal_leaves_file_unchanged(self) -> None:
        before = self.toml.read_bytes()
        self.assertEqual(self.run_repair({}).returncode, 1)
        self.assertEqual(self.toml.read_bytes(), before)

    def test_over_cap_proposal_leaves_file_unchanged(self) -> None:
        before = self.toml.read_bytes()
        proposal = {
            "includes": [f"inc_{number}" for number in range(9)],
            "link_libs": [f"extra_{number}" for number in range(9)],
            "defines": [f"-Dflag{number}" for number in range(9)],
        }
        proc = self.run_repair(proposal)
        self.assertEqual(proc.returncode, 2, proc.stdout + proc.stderr)
        self.assertEqual(self.toml.read_bytes(), before)

    def test_absolute_paths_are_relativized_only_under_target_root(self) -> None:
        target = self.root / "fake-target-root"
        library = target / "build-asan" / "lib" / "libsample.a"
        library.parent.mkdir(parents=True)
        proc = self.run_repair(
            {"link_libs": [str(library), "/etc/passwd"]}, TARGET_ROOT=target
        )
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        text = self.toml.read_text(encoding="utf-8")
        self.assertIn("build-asan/lib/libsample.a", text)
        self.assertNotIn(str(target), text)
        self.assertNotIn("/etc/passwd", text)


if __name__ == "__main__":
    unittest.main(verbosity=2)
