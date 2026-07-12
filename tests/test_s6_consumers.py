#!/usr/bin/env python3
"""Integration coverage for S6 peer-fix card generation and caching."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "lib"))

from llm_invoke import default_model


class PeerFixCardTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="s6-consumers-")
        self.sandbox = Path(self.temporary.name)
        self.results = self.sandbox / "output" / "myxml" / "results"
        self.target = self.sandbox / "targets" / "myxml"
        self.results.mkdir(parents=True)
        self.target.mkdir(parents=True)
        for name in ("lib", "bin", ".agents"):
            (self.sandbox / name).symlink_to(ROOT / name, target_is_directory=True)
        for name in ("parser.c", "SAX2.c", "encoding.c"):
            (self.target / name).write_text("// stub\n", encoding="utf-8")
        (self.target / "README.md").write_text(
            "myxml — a toy XML library used for harness integration tests.\n",
            encoding="utf-8",
        )
        peers = ROOT / "targets" / "PEERS.toml"
        if peers.is_file():
            shutil.copy2(str(peers), str(self.sandbox / "targets" / "PEERS.toml"))
        self.toml = self.sandbox / "output" / "myxml" / "target.toml"
        self.card_file = self.results / "s6-peer-cards.jsonl"
        self.shim = self.sandbox / "peer-fix-cards-shim.py"
        self.shim.write_text(
            "import os, runpy, sys\n"
            "root = os.environ['SCRIPT_ROOT']\n"
            "sys.path.insert(0, root + '/lib')\n"
            "import peer_sources\n"
            "def fake_osv_query(peer, **kwargs):\n"
            "    return [{'source':'osv','id':'CVE-2099-0001','fix_hash':'deadbeef'*5,"
            "'summary':'fix bounds check in entity parser','url':'https://osv.dev/vulnerability/CVE-2099-0001',"
            "'modified':'2099-01-01T00:00:00Z'}]\n"
            "peer_sources.osv_query = fake_osv_query\n"
            "sys.argv = ['peer-fix-cards', '--target-slug', 'myxml', '--quiet']\n"
            "runpy.run_path(root + '/bin/peer-fix-cards', run_name='__main__')\n",
            encoding="utf-8",
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write_config(self, peers=False) -> None:
        text = 'target = "myxml"\n'
        if peers:
            text += '\n[s6_peers]\ndomain = "XML / SGML"\npeers = ["expat"]\n'
        self.toml.write_text(text, encoding="utf-8")

    def environment(self, mapped_file="parser.c", log=None, model=None):
        env = os.environ.copy()
        env.update(
            SCRIPT_ROOT=str(self.sandbox), RESULTS_DIR=str(self.results),
            TARGET_ROOT=str(self.target), TARGET_SLUG="myxml",
            LLM_DECIDE_MOCK_S6_PEER_DISTILL=json.dumps({
                "class": "bounds", "summary": "entity expansion writes past buffer",
                "shape": "adds bounds check",
            }),
            LLM_DECIDE_MOCK_S6_PEER_MAP=json.dumps({
                "file": mapped_file, "reason": "target equivalent of entity parser",
            }),
        )
        if log is not None:
            env["LLM_DECIDE_LOG"] = str(log)
        if model is not None:
            env.update(ACTIVE_BACKEND="codex", MODEL=model)
        return env

    def run_shim(self, **kwargs):
        return subprocess.run(
            [sys.executable, str(self.shim)], env=self.environment(**kwargs),
            capture_output=True, text=True,
        )

    def test_empty_peer_configuration_writes_empty_jsonl(self) -> None:
        self.write_config()
        env = os.environ.copy()
        env.update(
            SCRIPT_ROOT=str(self.sandbox), RESULTS_DIR=str(self.results),
            TARGET_ROOT=str(self.target), TARGET_SLUG="myxml", LLM_DECIDE_DISABLE="1",
        )
        proc = subprocess.run(
            [sys.executable, str(ROOT / "bin" / "peer-fix-cards"),
             "--target-slug", "myxml", "--quiet"],
            env=env, capture_output=True, text=True,
        )
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertTrue(self.card_file.is_file())
        self.assertEqual(self.card_file.read_text(encoding="utf-8"), "")

    def test_osv_and_llm_results_produce_a_structured_card(self) -> None:
        self.write_config(peers=True)
        proc = self.run_shim()
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        rows = [json.loads(line) for line in self.card_file.read_text(encoding="utf-8").splitlines()]
        self.assertEqual(len(rows), 1)
        card = rows[0]
        self.assertEqual(card["strategy"], "S6")
        self.assertEqual(card["kind"], "s6-peer-fix")
        self.assertEqual(card["peer_project"], "expat")
        self.assertEqual(card["file"], "parser.c")
        self.assertIn("bounds", json.dumps(card))

    def test_mapped_file_outside_source_listing_is_dropped(self) -> None:
        self.write_config(peers=True)
        proc = self.run_shim(mapped_file="fictitious-file-does-not-exist.c")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertTrue(self.card_file.is_file())
        self.assertEqual(self.card_file.read_text(encoding="utf-8"), "")

    def test_identical_refresh_replays_both_llm_decisions_from_cache(self) -> None:
        self.write_config(peers=True)
        log = self.sandbox / "s6-decisions.log"
        for _ in range(2):
            proc = self.run_shim(log=log)
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        text = log.read_text(encoding="utf-8")
        self.assertEqual(text.count("s6-peer-distill MOCK"), 1)
        self.assertEqual(text.count("s6-peer-map MOCK"), 1)
        self.assertEqual(json.loads(self.card_file.read_text(encoding="utf-8"))["file"], "parser.c")

    def test_cache_key_uses_resolved_default_model(self) -> None:
        self.write_config(peers=True)
        log = self.sandbox / "s6-model-decisions.log"
        for model in ("", default_model("codex"), "some-other-model"):
            proc = self.run_shim(log=log, model=model)
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        text = log.read_text(encoding="utf-8")
        self.assertEqual(text.count("s6-peer-distill MOCK"), 2)
        self.assertEqual(text.count("s6-peer-map MOCK"), 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
