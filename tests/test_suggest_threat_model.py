#!/usr/bin/env python3
"""Integration coverage for threat-model suggestion and safe TOML updates."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
COMMAND = ROOT / "bin" / "suggest-threat-model"
sys.path.insert(0, str(ROOT / "lib"))

import target_config


class SuggestThreatModelTests(unittest.TestCase):
    DEFAULT = {
        "attacker_controls": ["bytes", "call-sequence"],
        "reasoning": "stateful parser API",
    }

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="suggest-threat-model-")
        self.sandbox = Path(self.temporary.name)
        self.target_toml = self.sandbox / "output" / "demo" / "target.toml"
        target = self.sandbox / "targets" / "demo"
        (target / "include").mkdir(parents=True)
        self.target_toml.parent.mkdir(parents=True)
        (target / "README.md").write_text(
            "demo — a stateful XML parser library with a public push/pull API.\n",
            encoding="utf-8",
        )
        (target / "include" / "demo.h").write_text("// demo public api\n")
        for name in ("lib", "bin", ".agents"):
            (self.sandbox / name).symlink_to(ROOT / name, target_is_directory=True)
        self.seed()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def seed(self, threat_model: bool = True) -> None:
        text = 'target = "demo"\nupstream_url = "https://example.com/demo"\n'
        if threat_model:
            text += (
                "\n# ── Threat model (drives lib/triage.py verdict matrix) ──\n"
                "[threat_model]\nattacker_controls = [\"bytes\"]\n"
            )
        self.target_toml.write_text(text, encoding="utf-8")

    def run_command(self, *args: str, mock=None, disable: bool = False) -> subprocess.CompletedProcess:
        env = os.environ.copy()
        env["SCRIPT_ROOT"] = str(self.sandbox)
        if mock is not None:
            env["LLM_DECIDE_MOCK_THREAT_MODEL_SUGGEST"] = json.dumps(mock)
        else:
            env.pop("LLM_DECIDE_MOCK_THREAT_MODEL_SUGGEST", None)
        if disable:
            env["LLM_DECIDE_DISABLE"] = "1"
        return subprocess.run(
            [sys.executable, str(COMMAND), "demo", *args],
            capture_output=True,
            text=True,
            env=env,
        )

    def controls(self):
        config = target_config.Config()
        target_config.load_toml_into(config, self.target_toml)
        return config.attacker_controls

    def test_print_mode_does_not_modify_file(self) -> None:
        before = self.target_toml.read_bytes()
        proc = self.run_command(mock=self.DEFAULT)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("[threat_model]", proc.stdout)
        self.assertIn("call-sequence", proc.stdout)
        self.assertEqual(self.target_toml.read_bytes(), before)

    def test_apply_replaces_placeholder_and_round_trips(self) -> None:
        proc = self.run_command("--apply", mock=self.DEFAULT)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        text = self.target_toml.read_text(encoding="utf-8")
        self.assertIn('attacker_controls = ["bytes", "call-sequence"]', text)
        self.assertIn("── Threat model", text)
        self.assertEqual(self.controls(), ["bytes", "call-sequence"])

    def test_overwrite_requires_force_and_replaces_marker_once(self) -> None:
        self.assertEqual(self.run_command("--apply", mock=self.DEFAULT).returncode, 0)
        self.assertEqual(self.run_command("--apply", mock=self.DEFAULT).returncode, 4)
        alternate = {
            "attacker_controls": ["bytes", "protocol-state"],
            "reasoning": "network protocol",
        }
        proc = self.run_command("--apply", "--force", mock=alternate)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        text = self.target_toml.read_text(encoding="utf-8")
        self.assertIn("protocol-state", text)
        self.assertEqual(text.count("set by bin/suggest-threat-model"), 1)

    def test_tokens_are_normalized_and_unknown_values_dropped(self) -> None:
        proc = self.run_command("--apply", mock={
            "attacker_controls": ["bytes", "call-order", "magic-pony"],
            "reasoning": "x",
        })
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertEqual(self.controls(), ["bytes", "call-sequence"])

    def test_apply_appends_missing_section(self) -> None:
        self.seed(threat_model=False)
        proc = self.run_command("--apply", mock=self.DEFAULT)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("[threat_model]", self.target_toml.read_text(encoding="utf-8"))

    def test_unavailable_invalid_and_unknown_inputs_have_distinct_statuses(self) -> None:
        self.assertEqual(self.run_command(disable=True).returncode, 2)
        self.assertEqual(self.run_command(mock={
            "attacker_controls": ["magic-pony"], "reasoning": "x",
        }).returncode, 3)
        env = os.environ.copy()
        env["SCRIPT_ROOT"] = str(self.sandbox)
        proc = subprocess.run(
            [sys.executable, str(COMMAND), "nonexistent-slug"], env=env,
            capture_output=True, text=True,
        )
        self.assertEqual(proc.returncode, 1)

    def test_hostile_and_empty_reasoning_cannot_corrupt_toml(self) -> None:
        hostile = {
            "attacker_controls": ["bytes", "race"],
            "reasoning": 'line one\nline two with "quote" and \\ backslash\n[fake_section]\nkey = "boom"',
        }
        proc = self.run_command("--apply", mock=hostile)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertEqual(self.controls(), ["bytes", "race"])
        self.assertNotIn("\n[fake_section]\n", self.target_toml.read_text(encoding="utf-8"))
        self.seed()
        proc = self.run_command("--apply", mock={
            "attacker_controls": ["bytes"], "reasoning": "",
        })
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertEqual(self.controls(), ["bytes"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
