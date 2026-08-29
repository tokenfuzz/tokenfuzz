#!/usr/bin/env python3
"""Delta mode: `--since REV` audits the change, never silently the tree.

The cards are the files changed in REV..HEAD plus their one-hop callers from
the call-neighbourhood graph's certain edges, and S1 cards exist for exactly
the commits in that range. A REV the checkout cannot resolve — a shallow
clone, a typo — stops the run loudly, and a resumed tree refuses another
--since the way it refuses any changed pinned setting.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "lib"))

import audit_runner  # noqa: E402
import callgraph  # noqa: E402
import target_config  # noqa: E402
import workqueue  # noqa: E402


def _git(root: Path, *args: str, **kwargs) -> str:
    return subprocess.check_output(
        ["git", "-C", str(root), *args], text=True, timeout=10,
        stderr=subprocess.DEVNULL, **kwargs,
    ).strip()


def _commit_all(root: Path, message: str) -> str:
    _git(root, "add", "-A")
    _git(root, "commit", "-q", "-m", message)
    return _git(root, "rev-parse", "HEAD")


class DeltaFixture(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="delta-mode-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.target = self.root / "target"
        self.results = self.root / "results"
        (self.target / "src").mkdir(parents=True)
        self.results.mkdir()
        _git(self.target, "init", "-q")
        for key, value in (
            ("user.email", "test@example.invalid"), ("user.name", "Test User"),
        ):
            _git(self.target, "config", key, value)
        self._write("src/parse.c",
                    "void app_parse(char *dst, const char *src, unsigned n) {\n"
                    "  memcpy(dst, src, n);\n"
                    "}\n")
        self._write("src/main.c", "int main(void) { return 0; }\n")
        self._write("src/util.c", "int util;\n")
        self._write("src/quiet.c", "int quiet;\n")
        self.base = _commit_all(self.target, "Initial import")
        self._write("src/new.c", "int fresh;\n")
        self.mid = _commit_all(self.target, "Adjust code formatting")
        self._write("src/parse.c",
                    "void app_parse(char *dst, const char *src, unsigned n) {\n"
                    "  memcpy(dst, src, n + 1);\n"
                    "}\n")
        self.head = _commit_all(self.target, "Fix out-of-bounds read in parser")
        self.ctx = workqueue.Context(ROOT, self.target, "sample", self.results, "git")

    def _write(self, rel: str, text: str) -> None:
        (self.target / rel).write_text(text, encoding="utf-8")

    def write_graph(self) -> None:
        """A neutral call-neighbourhood artifact: main.c calls parse.c."""
        (self.results / "state").mkdir(exist_ok=True)
        (self.results / "state" / "callgraph.json").write_text(json.dumps({
            "version": callgraph.SCHEMA_VERSION,
            "signature": "fixture",
            "entry": {}, "coverage": {},
            "files": {
                "src/parse.c": {"functions": 1, "reachable": 0,
                                "callers": [["src/main.c", 2]],
                                "callees": [], "paths": []},
                "src/main.c": {"functions": 1, "reachable": 0, "callers": [],
                               "callees": [["src/parse.c", 2]], "paths": []},
                "src/util.c": {"functions": 1, "reachable": 0,
                               "callers": [["src/quiet.c", 1]],
                               "callees": [], "paths": []},
            },
        }), encoding="utf-8")


class DeltaScopeTests(DeltaFixture):
    def test_scope_is_the_range_and_its_auditable_files(self) -> None:
        scope = workqueue.delta_scope(self.ctx, self.base)
        self.assertEqual(scope.base_rev, self.base)
        self.assertEqual(scope.head_rev, self.head)
        self.assertEqual(scope.commits, (self.head, self.mid))
        self.assertEqual(scope.files, ("src/new.c", "src/parse.c"))
        # The operator's spelling is preserved beside the resolved base.
        short = workqueue.delta_scope(self.ctx, self.base[:10])
        self.assertEqual(short.since, self.base[:10])
        self.assertEqual(short.base_rev, self.base)

    def test_an_unresolvable_revision_is_a_loud_error(self) -> None:
        with self.assertRaises(ValueError):
            workqueue.delta_scope(self.ctx, "no-such-rev")
        with self.assertRaises(ValueError):
            workqueue.delta_scope(self.ctx, "")
        plain = workqueue.Context(
            ROOT, self.root / "plain", "plain", self.results, "none",
        )
        with self.assertRaises(ValueError):
            workqueue.delta_scope(plain, self.base)

    def test_a_shallow_clone_degrades_loudly_not_to_a_full_audit(self) -> None:
        shallow = self.root / "shallow"
        subprocess.run(
            ["git", "clone", "-q", "--depth", "1",
             f"file://{self.target}", str(shallow)],
            check=True, timeout=30, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        results = self.root / "results-shallow"
        results.mkdir()
        ctx = workqueue.Context(ROOT, shallow, "sample", results, "git")
        with self.assertRaises(ValueError) as caught:
            workqueue.delta_scope(ctx, self.base)
        self.assertIn("shallow", str(caught.exception))
        proc = subprocess.run(
            [sys.executable, str(ROOT / "bin" / "rank-work"),
             "--target-path", str(shallow), "--target-slug", "sample",
             "--results-dir", str(results), "--llm-top-n", "0",
             "--since", self.base],
            capture_output=True, text=True, check=False,
            env={**os.environ, "LLM_DECIDE_DISABLE": "1"},
        )
        self.assertEqual(proc.returncode, 2, proc.stdout + proc.stderr)
        self.assertIn("shallow", proc.stderr)
        self.assertFalse(
            (results / "work-cards.jsonl").is_file(),
            "an unresolvable --since must not leave a full-audit queue behind",
        )

    @unittest.skipUnless(shutil.which("hg"), "Mercurial is not installed")
    def test_mercurial_scope_matches_the_git_semantics(self) -> None:
        target = self.root / "hg-target"
        (target / "src").mkdir(parents=True)
        env = os.environ | {"HGUSER": "Test User <test@example.invalid>"}

        def commit(message: str) -> str:
            subprocess.run(["hg", "-R", str(target), "addremove", "-q"],
                           check=True, timeout=10, env=env)
            subprocess.run(["hg", "-R", str(target), "commit", "-m", message],
                           check=True, timeout=10, env=env)
            return subprocess.check_output(
                ["hg", "-R", str(target), "log", "-r", ".",
                 "--template", "{node}"], text=True, timeout=10, env=env,
            ).strip()

        subprocess.run(["hg", "init", str(target)], check=True, timeout=10)
        (target / "src" / "parse.c").write_text("int parse;\n", encoding="utf-8")
        base = commit("Initial import")
        (target / "src" / "parse.c").write_text("int parse2;\n", encoding="utf-8")
        (target / "src" / "new.c").write_text("int fresh;\n", encoding="utf-8")
        head = commit("Fix use-after-free in decoder")
        ctx = workqueue.Context(ROOT, target, "sample", self.results, "hg")
        scope = workqueue.delta_scope(ctx, base)
        self.assertEqual((scope.base_rev, scope.head_rev), (base, head))
        self.assertEqual(scope.commits, (head,))
        self.assertEqual(scope.files, ("src/new.c", "src/parse.c"))
        with self.assertRaises(ValueError):
            workqueue.delta_scope(ctx, "no-such-rev")


class DeltaCardTests(DeltaFixture):
    def test_callers_come_one_hop_from_the_recorded_certain_edges(self) -> None:
        self.assertIsNone(
            callgraph.callers_of(self.results, ("src/parse.c",)),
            "no graph means no caller expansion, not a failure",
        )
        self.write_graph()
        self.assertEqual(
            callgraph.callers_of(self.results, ("src/parse.c", "src/new.c")),
            {"src/main.c"},
        )

    def test_cards_are_changed_files_union_callers_and_nothing_else(self) -> None:
        self.write_graph()
        scope = workqueue.delta_scope(self.ctx, self.base)
        patch_path = self.results / "patch-cards.jsonl"
        workqueue.write_cards(
            patch_path,
            workqueue.build_patch_cards(self.ctx, 5, 5, delta=scope),
        )
        delta_files = {rel: f"changed since {scope.since}" for rel in scope.files}
        for rel in sorted(callgraph.callers_of(self.results, scope.files) or ()):
            delta_files.setdefault(rel, "calls a changed file")
        # limit=1 proves the bounded window does not apply in delta mode.
        cards = workqueue.rank_target(
            self.ctx, 1, patch_path, delta_files=delta_files,
        )
        ranked = {
            card["file"] for card in cards if card["kind"] == "ranked-source"
        }
        self.assertEqual(ranked, {"src/parse.c", "src/new.c", "src/main.c"})
        # A quiet changed file whose commit mints no S1 card is carried on
        # the ranked fallback lane, not dropped and not floored.
        quiet = [
            card for card in cards
            if card.get("file") == "src/new.c" and card["kind"] == "ranked-source"
        ]
        self.assertEqual(len(quiet), 1)
        self.assertGreaterEqual(quiet[0]["score"], 1)
        self.assertEqual(quiet[0]["strategy"], "S1")
        self.assertIn("changed since", quiet[0]["reason"])
        self.assertNotIn(
            "diversity floor", " ".join(str(c.get("reason")) for c in cards),
        )

    def test_s1_cards_exist_for_exactly_the_range_commits(self) -> None:
        scope = workqueue.delta_scope(self.ctx, self.base)
        cards = workqueue.build_patch_cards(self.ctx, 10, 10, delta=scope)
        self.assertEqual(len(cards), 1,
                         "range commits only, and churn is still filtered")
        self.assertEqual(cards[0]["fix_hashes"], [self.head])
        self.assertIn("out-of-bounds", cards[0]["description"])
        self.assertEqual(cards[0]["touched_files"], ["src/parse.c"])
        # An empty range yields no S1 cards rather than a window scan.
        empty = workqueue.delta_scope(self.ctx, self.head)
        self.assertEqual(
            workqueue.build_patch_cards(self.ctx, 10, 10, delta=empty), [],
        )

    def test_rank_work_cli_restricts_the_queue_and_names_the_delta(self) -> None:
        for command in (
            [sys.executable, str(ROOT / "bin" / "patch-cards"),
             "--target-path", str(self.target), "--target-slug", "sample",
             "--results-dir", str(self.results), "--quiet",
             "--since", self.base],
            [sys.executable, str(ROOT / "bin" / "rank-work"),
             "--target-path", str(self.target), "--target-slug", "sample",
             "--results-dir", str(self.results), "--llm-top-n", "0",
             "--since", self.base],
        ):
            proc = subprocess.run(
                command, capture_output=True, text=True, check=False,
                env={**os.environ, "LLM_DECIDE_DISABLE": "1"},
            )
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("rank-work: delta", proc.stdout)
        cards = workqueue.read_jsonl(self.results / "work-cards.jsonl")
        self.assertTrue(cards)
        ranked = {c["file"] for c in cards if c["kind"] == "ranked-source"}
        self.assertLessEqual(
            ranked, {"src/parse.c", "src/new.c", "src/main.c"},
            "no card outside the delta and its callers",
        )
        self.assertLessEqual({"src/parse.c", "src/new.c"}, ranked)
        for kind in ("s4-campaign", "s6-peer-fix"):
            self.assertNotIn(kind, {c.get("kind") for c in cards})
        s1_hashes = {
            h for c in cards if c.get("kind") == "s1-patch"
            for h in c.get("fix_hashes", [])
        }
        self.assertEqual(s1_hashes, {self.head})


class DeltaRuntimeTests(DeltaFixture):
    def _runtime(self, delta) -> SimpleNamespace:
        logs = self.root / "logs"
        logs.mkdir(exist_ok=True)
        return SimpleNamespace(
            root=ROOT, target_root=self.target, target_slug="sample",
            target_rev=self.head, repo_type="git", results=self.results,
            logs=logs, backend="codex", model="fixture-model",
            config=target_config.Config(target_root=str(self.target)),
            index=logs / "index.log", decision_timeout=0,
            agent_security="sandboxed", delta=delta,
        )

    def test_refresh_forwards_since_and_skips_peer_mining(self) -> None:
        scope = workqueue.delta_scope(self.ctx, self.base)
        runtime = self._runtime(scope)
        with mock.patch.object(
            audit_runner.target_config, "vcs_source_signature",
            return_value="tracked-source",
        ), mock.patch.object(
            audit_runner.callgraph, "cache_signature", return_value="",
        ), mock.patch.object(
            audit_runner.housekeeping, "should_run", return_value=True,
        ), mock.patch.object(audit_runner.housekeeping, "mark_clean"), \
                mock.patch.object(
                    audit_runner.subprocess, "run",
                    return_value=SimpleNamespace(returncode=0),
                ) as launched:
            self.assertTrue(audit_runner.refresh_work_cards(runtime))
        commands = {
            Path(call.args[0][0]).name: call.args[0]
            for call in launched.call_args_list
            if Path(call.args[0][0]).name in
            ("patch-cards", "peer-fix-cards", "rank-work")
        }
        self.assertEqual(sorted(commands), ["patch-cards", "rank-work"],
                         "peer mining is outside the delta")
        for name in ("patch-cards", "rank-work"):
            argv = list(commands[name])
            self.assertIn("--since", argv, name)
            self.assertEqual(argv[argv.index("--since") + 1], self.base, name)
        self.assertIn(
            "DELTA: ", (runtime.logs / "index.log").read_text(encoding="utf-8"),
        )
        self.assertFalse(
            audit_runner.expand_work_cards_if_exhausted(runtime),
            "the window is the delta; nothing wider may be ranked",
        )

    def test_a_resumed_tree_refuses_a_changed_since(self) -> None:
        root = self.root / "harness-root"
        (root / "targets").mkdir(parents=True)
        def prepare(since: str) -> audit_runner.Runtime:
            return audit_runner.prepare_runtime(
                root, self.target, "sample", "sample", "codex", "", "", 1,
                None, True, "sandboxed", since,
            )

        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("NUM_AGENTS", None)
            runtime = prepare(self.base)
            self.assertEqual(runtime.delta.base_rev, self.base)
            recorded = json.loads(
                (root / "output" / "sample" / "codex" / "results" / "state" /
                 "run-config.json").read_text(encoding="utf-8")
            )
            self.assertEqual(recorded["delta"]["base_rev"], self.base)
            self.assertEqual(
                recorded["delta"]["changed_files"],
                ["src/new.c", "src/parse.c"],
            )
            # Same --since resumes; a changed or dropped one is refused.
            prepare(self.base)
            with self.assertRaises(ValueError):
                prepare(self.head)
            with self.assertRaises(ValueError):
                prepare("")
            # A tree started without --since refuses to become a delta.
            full_target = self.target
            full = audit_runner.prepare_runtime(
                root, full_target, "full", "full", "codex", "", "", 1,
                None, True, "sandboxed", "",
            )
            self.assertIsNone(full.delta)
            with self.assertRaises(ValueError):
                audit_runner.prepare_runtime(
                    root, full_target, "full", "full", "codex", "", "", 1,
                    None, True, "sandboxed", self.base,
                )

    def test_since_refuses_the_unranked_campaign_and_peer_lanes(self) -> None:
        root = self.root / "lane-root"
        (root / "targets").mkdir(parents=True)
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("NUM_AGENTS", None)
            for lane in ("S4", "S6"):
                with self.subTest(lane=lane), self.assertRaises(ValueError):
                    # These lanes' cards do not come from the range, so a
                    # delta queue cannot honour them.
                    audit_runner.prepare_runtime(
                        root, self.target, "sample", f"sample-{lane}",
                        "codex", "", lane, 1, None, True, "sandboxed",
                        self.base,
                    )
            # A source-ranked pin (S3) is compatible: it still ranks the
            # delta's files, restricted to that strategy.
            runtime = audit_runner.prepare_runtime(
                root, self.target, "sample", "sample-S3", "codex", "",
                "S3", 1, None, True, "sandboxed", self.base,
            )
            self.assertEqual(runtime.delta.base_rev, self.base)
            self.assertEqual(runtime.fixed_strategy, "S3")

    def test_a_corrupt_run_config_stops_a_delta_rather_than_widening(self) -> None:
        root = self.root / "corrupt-root"
        (root / "targets").mkdir(parents=True)
        config = (root / "output" / "sample" / "codex" / "results"
                  / "state" / "run-config.json")
        config.parent.mkdir(parents=True)
        config.write_text("{ this is not json", encoding="utf-8")
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("NUM_AGENTS", None)
            with self.assertRaises(ValueError):
                audit_runner.prepare_runtime(
                    root, self.target, "sample", "sample", "codex", "",
                    "", 1, None, True, "sandboxed", self.base,
                )


if __name__ == "__main__":
    unittest.main(verbosity=2)
