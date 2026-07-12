#!/usr/bin/env python3
"""Integration coverage for peer suggestions and safe TOML updates."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
COMMAND = ROOT / "bin" / "suggest-peers"
sys.path.insert(0, str(ROOT / "lib"))

import target_config


class SuggestPeersTests(unittest.TestCase):
    DEFAULT = {
        "domain": "JSON", "peers": ["rapidjson", "simdjson", "json-c"],
        "reasoning": "all parse JSON",
    }

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="suggest-peers-")
        self.sandbox = Path(self.temporary.name)
        self.toml = self.sandbox / "output" / "demo" / "target.toml"
        target = self.sandbox / "targets" / "demo"
        self.toml.parent.mkdir(parents=True)
        target.mkdir(parents=True)
        (target / "README.md").write_text(
            "demo — toy JSON parser, for testing the s6_peers helper.\n", encoding="utf-8"
        )
        for name in ("lib", "bin", ".agents"):
            (self.sandbox / name).symlink_to(ROOT / name, target_is_directory=True)
        self.seed()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def seed(self) -> None:
        self.toml.write_text(
            'target = "demo"\nupstream_url = "https://example.com/demo"\n',
            encoding="utf-8",
        )

    def run_command(self, *args, mock=None, slug="demo", disable=False):
        env = os.environ.copy()
        env["SCRIPT_ROOT"] = str(self.sandbox)
        if mock is not None:
            env["LLM_DECIDE_MOCK_S6_PEER_SUGGEST"] = json.dumps(mock)
        else:
            env.pop("LLM_DECIDE_MOCK_S6_PEER_SUGGEST", None)
        if disable:
            env["LLM_DECIDE_DISABLE"] = "1"
        return subprocess.run(
            [sys.executable, str(COMMAND), slug, *args],
            capture_output=True, text=True, env=env,
        )

    def parse(self):
        config = target_config.Config()
        target_config.load_toml_into(config, self.toml)
        return config

    def test_print_mode_is_non_mutating(self) -> None:
        before = self.toml.read_bytes()
        proc = self.run_command(mock=self.DEFAULT)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("[s6_peers]", proc.stdout)
        self.assertIn("rapidjson", proc.stdout)
        self.assertEqual(self.toml.read_bytes(), before)

    def test_apply_writes_parseable_section(self) -> None:
        proc = self.run_command("--apply", mock=self.DEFAULT)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        text = self.toml.read_text(encoding="utf-8")
        self.assertIn("[s6_peers]", text)
        self.assertIn("rapidjson", text)
        self.parse()

    def test_no_peer_responses_are_explicit_successes(self) -> None:
        reasons = (
            "demo is a synthetic harness fixture with a custom packet format, not a shared spec, format, or algorithm suitable for S6 peer mining.",
            "demo is a synthetic local harness parsing a custom length-prefixed record, not a named spec/format/algorithm with independent peer implementations.",
            "demo appears to be a synthetic harness fixture rather than an implementation of a shared spec, format, or algorithm.",
            "This target stands alone; nothing else implements the same thing.",
        )
        for reason in reasons:
            with self.subTest(reason=reason):
                self.seed()
                proc = self.run_command("--apply", mock={
                    "domain": "", "peers": [], "reasoning": reason,
                })
                self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
                self.assertNotIn("warning", (proc.stdout + proc.stderr).casefold())
                self.assertIn("peers  = []", self.toml.read_text(encoding="utf-8"))
                self.parse()

    def test_placeholder_peers_are_discarded(self) -> None:
        proc = self.run_command("--apply", mock={
            "domain": "Compression — DEFLATE",
            "peers": ["zlib", "libdeflate", "miniz"],
            "reasoning": "no real spec row applies; these are placeholder peers and S6 is not applicable",
        })
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("explicit empty peers", proc.stdout + proc.stderr)
        text = self.toml.read_text(encoding="utf-8")
        self.assertIn("peers  = []", text)
        self.assertNotIn("zlib", text)

    def test_empty_peer_list_blanks_a_stray_domain(self) -> None:
        proc = self.run_command("--apply", mock={
            "domain": "XML / SGML", "peers": [],
            "reasoning": "no independent peers identified",
        })
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        text = self.toml.read_text(encoding="utf-8")
        self.assertIn("peers  = []", text)
        self.assertIn('domain = ""', text)

    def test_hostile_structured_text_cannot_escape_toml(self) -> None:
        proc = self.run_command("--apply", mock={
            "domain": 'JSON"with"quotes',
            "peers": ["rapidjson", 'simd"json', "json-c"],
            "reasoning": 'first line\n[bogus_section]\nkey = "boom"\ntrailing \\ and "quote"',
        })
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.parse()
        self.assertNotIn("\n[bogus_section]\n", self.toml.read_text(encoding="utf-8"))

    def test_overwrite_requires_force(self) -> None:
        self.assertEqual(self.run_command("--apply", mock=self.DEFAULT).returncode, 0)
        self.assertEqual(self.run_command("--apply", mock=self.DEFAULT).returncode, 4)
        alternate = {
            "domain": "JSON", "peers": ["yyjson", "sajson", "picojson"],
            "reasoning": "v2",
        }
        proc = self.run_command("--apply", "--force", mock=alternate)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("yyjson", self.toml.read_text(encoding="utf-8"))

    def test_unavailable_and_unknown_target_statuses(self) -> None:
        self.assertEqual(self.run_command(disable=True).returncode, 2)
        self.assertEqual(self.run_command(slug="nonexistent-slug").returncode, 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
