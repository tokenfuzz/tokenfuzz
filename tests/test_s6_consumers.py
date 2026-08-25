#!/usr/bin/env python3
"""Integration coverage for evidence-bearing S6 peer-fix cards."""

from __future__ import annotations

import hashlib
import json
import os
import runpy
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "lib"))

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
            "    if peer == os.environ.get('S6_TEST_EMPTY_PEER'): return []\n"
            "    if peer == os.environ.get('S6_TEST_UNAVAILABLE_PEER'):\n"
            "        kwargs.get('source_errors', []).append('OSV unavailable: TimeoutError')\n"
            "        return []\n"
            "    return [{'source':'osv','id':f'CVE-2099-{index:04d}','fix_hash':(peer + str(index)).encode().hex().ljust(40, '0')[:40],"
            "'summary':f'fix bounds check in {peer} entity parser {index}','url':f'https://osv.dev/vulnerability/CVE-2099-{index:04d}',"
            "'repo_url':f'https://example.test/{peer}.git',"
            "'range_start_hash':('' if peer == os.environ.get('S6_TEST_ENDPOINT_PEER') else 'b' * 40),'evidence_url':f'https://example.test/{peer}/compare/{index}.diff','evidence_kind':('endpoint' if peer == os.environ.get('S6_TEST_ENDPOINT_PEER') else 'fixed-range'),"
            "'modified':'2099-01-01T00:00:00Z'} for index in range(1, int(os.environ.get('S6_TEST_FIXES', '1')) + 1)]\n"
            "peer_sources.osv_query = fake_osv_query\n"
            "_real_gather = peer_sources.gather_peer_fixes\n"
            "def fake_gather(peer, **kwargs):\n"
            "    if peer == os.environ.get('S6_TEST_FAIL_PEER'): raise RuntimeError('feed unavailable')\n"
            "    return _real_gather(peer, **kwargs)\n"
            "peer_sources.gather_peer_fixes = fake_gather\n"
            "peer_sources.fetch_patch_excerpt = lambda url, **kwargs: 'Subject: endpoint patch evidence\\n+guard;'\n"
            "if os.environ.get('S6_TEST_VCS'):\n"
            "    _n = int(os.environ['S6_TEST_VCS'])\n"
            "    peer_sources.gather_peer_fixes = lambda peer, **kwargs: "
            "([{'source':'vcs','id':f'{peer}-commit{i}','fix_hash':(peer+'vcs'+str(i)).encode().hex().ljust(40, '0')[:40],"
            "'summary':'fix use-after-free in '+peer,'url':'','modified':'2099-01-02T00:00:00Z'} for i in range(_n)] if peer == 'libxml' else []) + fake_osv_query(peer)\n"
            "sys.argv = ['peer-fix-cards', '--target-slug', 'myxml', '--quiet']\n"
            "runpy.run_path(root + '/bin/peer-fix-cards', run_name='__main__')\n",
            encoding="utf-8",
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write_config(self, peers: list[str] | None = None) -> None:
        text = 'target = "myxml"\n'
        if peers:
            rendered = ", ".join(json.dumps(peer) for peer in peers)
            text += f'\n[s6_peers]\ndomain = "XML / SGML"\npeers = [{rendered}]\n'
        self.toml.write_text(text, encoding="utf-8")

    def environment(self, log=None, fixes=1):
        env = os.environ.copy()
        env.update(
            SCRIPT_ROOT=str(self.sandbox), RESULTS_DIR=str(self.results),
            TARGET_ROOT=str(self.target), TARGET_SLUG="myxml",
            S6_TEST_FIXES=str(fixes),
        )
        if log is not None:
            env["LLM_DECIDE_LOG"] = str(log)
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

    def test_osv_result_produces_a_structured_card(self) -> None:
        self.write_config(peers=["expat"])
        proc = self.run_shim()
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        rows = [json.loads(line) for line in self.card_file.read_text(encoding="utf-8").splitlines()]
        self.assertEqual(len(rows), 1)
        card = rows[0]
        self.assertEqual(card["strategy"], "S6")
        self.assertEqual(card["kind"], "s6-peer-fix")
        self.assertEqual(card["peer_project"], "expat")
        self.assertEqual(card["file"], "")
        self.assertEqual(card["mode"], "auto")
        self.assertEqual(card["peer_fix_id"], "CVE-2099-0001")
        self.assertEqual(len(card["peer_fix_hash"]), 40)
        self.assertEqual(card["peer_fix_source"], "osv")
        self.assertEqual(card["peer_repo_url"], "https://example.test/expat.git")
        self.assertEqual(
            card["peer_fix_evidence_url"],
            "https://example.test/expat/compare/1.diff",
        )
        self.assertEqual(card["peer_range_start_hash"], "b" * 40)
        self.assertEqual(card["peer_fix_evidence_kind"], "fixed-range")
        self.assertIn("osv range endpoint", card["reason"])
        self.assertIn("fix bounds check", card["peer_fix_summary"])
        self.assertNotIn("fix bounds check", card["reason"])

    def test_generation_reads_the_sessions_pinned_config(self) -> None:
        self.write_config(peers=["expat"])
        snapshot = 'target = "myxml"\n[s6_peers]\npeers = ["libxml"]\n'
        (self.results / ".target.toml").write_text(snapshot, encoding="utf-8")
        digest = hashlib.sha256(snapshot.encode()).hexdigest()
        (self.results / ".session-env").write_text(
            f"TARGET_CONFIG_SHA256={digest}\n", encoding="utf-8",
        )

        proc = self.run_shim()

        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        card = json.loads(self.card_file.read_text(encoding="utf-8"))
        self.assertEqual(card["peer_project"], "libxml")

    def test_card_is_not_dropped_when_no_target_file_is_preselected(self) -> None:
        self.write_config(peers=["expat"])
        proc = self.run_shim()
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        card = json.loads(self.card_file.read_text(encoding="utf-8"))
        self.assertEqual(card["file"], "")
        self.assertEqual(card["subsystem"], "root")

    def test_generation_uses_no_llm_decisions(self) -> None:
        self.write_config(peers=["expat"])
        log = self.sandbox / "s6-decisions.log"
        proc = self.run_shim(log=log)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertFalse(log.exists())

    def test_cards_are_interleaved_across_peers(self) -> None:
        self.write_config(peers=["expat", "libxml"])

        proc = self.run_shim(fixes=2)

        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        cards = [json.loads(line) for line in self.card_file.read_text().splitlines()]
        self.assertEqual(
            [card["peer_project"] for card in cards],
            ["expat", "libxml", "expat", "libxml"],
        )

    def test_a_source_silent_peer_gets_one_bounded_discovery_card(self) -> None:
        self.write_config(peers=["expat", "libxml"])
        env = self.environment()
        env["S6_TEST_EMPTY_PEER"] = "libxml"

        proc = subprocess.run(
            [sys.executable, str(self.shim)], env=env,
            capture_output=True, text=True,
        )

        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        cards = [json.loads(line) for line in self.card_file.read_text().splitlines()]
        self.assertEqual(
            [(card["peer_project"], card["peer_fix_source"]) for card in cards],
            [("expat", "osv"), ("libxml", "discovery")],
        )
        discovery = cards[1]
        self.assertEqual(discovery["file"], "")
        self.assertIn(
            "resolve one exact security-relevant fix",
            discovery["peer_fix_summary"].lower(),
        )
        self.assertNotIn("source unavailable", discovery["reason"])

    def test_a_source_failure_falls_open_to_peer_discovery(self) -> None:
        self.write_config(peers=["expat"])
        env = self.environment()
        env["S6_TEST_FAIL_PEER"] = "expat"

        proc = subprocess.run(
            [sys.executable, str(self.shim)], env=env,
            capture_output=True, text=True,
        )

        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        card = json.loads(self.card_file.read_text())
        self.assertEqual(card["peer_project"], "expat")
        self.assertEqual(card["peer_fix_source"], "discovery")
        # A dead feed and an empty one both fall open to this card, and the
        # audit discards this generator's stderr, so the card carries which.
        self.assertIn("source unavailable", card["reason"])
        self.assertIn("feed unavailable", card["reason"])

    def test_an_osv_outage_is_not_reported_as_an_empty_feed(self) -> None:
        self.write_config(peers=["expat"])
        env = self.environment()
        env["S6_TEST_UNAVAILABLE_PEER"] = "expat"

        proc = subprocess.run(
            [sys.executable, str(self.shim)], env=env,
            capture_output=True, text=True,
        )

        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        card = json.loads(self.card_file.read_text())
        self.assertEqual(card["peer_fix_source"], "discovery")
        self.assertIn("source unavailable", card["reason"])
        self.assertIn("OSV unavailable: TimeoutError", card["reason"])

    def test_endpoint_only_peer_keeps_one_exact_fix_discovery_route(self) -> None:
        self.write_config(peers=["expat"])
        env = self.environment(fixes=8)
        env["S6_TEST_ENDPOINT_PEER"] = "expat"

        proc = subprocess.run(
            [sys.executable, str(self.shim)], env=env,
            capture_output=True, text=True,
        )

        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        cards = [json.loads(line) for line in self.card_file.read_text().splitlines()]
        self.assertEqual(
            [card["peer_fix_source"] for card in cards],
            ["discovery", "osv", "osv", "osv", "osv", "osv"],
        )
        self.assertEqual([card["score"] for card in cards], [20, 15, 15, 15, 15, 15])

    def test_local_commits_do_not_crowd_out_a_peers_advisories(self) -> None:
        self.write_config(peers=["libxml"])
        env = self.environment(fixes=6)
        env["S6_TEST_VCS"] = "6"

        proc = subprocess.run(
            [sys.executable, str(self.shim)], env=env,
            capture_output=True, text=True,
        )

        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        cards = [json.loads(line) for line in self.card_file.read_text().splitlines()]
        sources = [card["peer_fix_source"] for card in cards]
        # Keyword-matched local commits are exact but not necessarily
        # security-relevant; OSV entries are vulnerability-scoped. Neither
        # source may consume the whole per-peer cap.
        self.assertIn("osv", sources)
        self.assertIn("vcs", sources)

    def test_an_advisory_ships_a_labeled_resolution_excerpt(self) -> None:
        # An OSS-Fuzz `fixed` event bisects to a range boundary, not the
        # repair. Its excerpt is resolution evidence and must remain visibly
        # distinct from a mined VCS fix.
        self.write_config(peers=["libxml"])
        env = self.environment(fixes=1)
        env["S6_TEST_VCS"] = "1"

        proc = subprocess.run(
            [sys.executable, str(self.shim)], env=env,
            capture_output=True, text=True,
        )

        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        cards = [json.loads(line) for line in self.card_file.read_text().splitlines()]
        by_source = {card["peer_fix_source"]: card for card in cards}
        self.assertIn("endpoint patch evidence", by_source["osv"]["peer_fix_diff_excerpt"])
        self.assertTrue(by_source["osv"]["peer_fix_hash"])

    def test_exact_commits_precede_advisory_only_leads(self) -> None:
        self.write_config(peers=["expat", "libxml"])
        env = self.environment(fixes=1)
        env["S6_TEST_VCS"] = "1"

        proc = subprocess.run(
            [sys.executable, str(self.shim)], env=env,
            capture_output=True, text=True,
        )

        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        cards = [json.loads(line) for line in self.card_file.read_text().splitlines()]
        self.assertEqual(
            [card["peer_fix_source"] for card in cards],
            ["vcs", "osv", "osv"],
        )

    def test_fixed_range_and_peer_discovery_precede_endpoint_only_leads(self) -> None:
        self.write_config(peers=["expat", "libxml", "otherxml"])
        env = self.environment(fixes=1)
        env["S6_TEST_ENDPOINT_PEER"] = "expat"
        env["S6_TEST_EMPTY_PEER"] = "otherxml"

        proc = subprocess.run(
            [sys.executable, str(self.shim)], env=env,
            capture_output=True, text=True,
        )

        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        cards = [json.loads(line) for line in self.card_file.read_text().splitlines()]
        self.assertEqual(
            [(card["peer_project"], card["peer_fix_source"]) for card in cards],
            [
                ("libxml", "osv"),
                ("expat", "discovery"),
                ("otherxml", "discovery"),
                ("expat", "osv"),
            ],
        )
        self.assertEqual([card["score"] for card in cards], [40, 20, 20, 15])


if __name__ == "__main__":
    unittest.main(verbosity=2)
