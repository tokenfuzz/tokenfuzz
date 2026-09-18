#!/usr/bin/env python3
"""The budgeted sweep: unit planning, reply checking, spend, and pickup."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "lib"))

import callgraph
import coverage_ledger
import llm_decide
import sweep
import target_config
import workqueue


def _body(count: int) -> str:
    return "\n".join(f"int line_{n}(void) {{ return {n}; }}" for n in range(1, count + 1)) + "\n"


class PlanningTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="sweep-plan-")
        self.root = Path(self.temporary.name)
        self.target = self.root / "target"
        self.results = self.root / "results"
        (self.target / "src").mkdir(parents=True)
        self.ctx = workqueue.Context(ROOT, self.target, "sampleproj", self.results, "")
        workqueue.init_state(self.ctx)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write_callgraph(self, files: dict) -> None:
        (self.results / "state" / callgraph.ARTIFACT_NAME).write_text(json.dumps({
            "version": callgraph.SCHEMA_VERSION, "signature": "s", "root": str(self.target),
            "languages": ["c"], "entry": {}, "coverage": {},
            "files": {rel: {"functions": len(defs), "reachable": 0, "callers": [], "callees": [],
                            "paths": [], "definitions": defs} for rel, defs in files.items()},
        }), encoding="utf-8")

    def test_units_follow_definitions_where_parsed_and_windows_elsewhere(self) -> None:
        (self.target / "src" / "parsed.c").write_text(_body(300), encoding="utf-8")
        (self.target / "src" / "plain.c").write_text(_body(250), encoding="utf-8")
        self.write_callgraph({"src/parsed.c": [["open", 10], ["parse", 40], ["huge", 60]]})
        workqueue.rank_target(self.ctx, 10)
        units = {u.key: u for u in sweep.plan_units(self.ctx, unit_lines=100)}
        self.assertEqual(units["src/parsed.c:1-9"].functions, [])
        self.assertEqual(units["src/parsed.c:10-39"].functions, ["open"])
        self.assertEqual(units["src/parsed.c:40-59"].functions, ["parse"])
        self.assertEqual(units["src/parsed.c:60-300"].functions, ["huge"], "241 lines fits four windows")
        self.assertEqual(
            [k for k in units if k.startswith("src/plain.c")],
            ["src/plain.c:1-100", "src/plain.c:101-200", "src/plain.c:201-250"],
        )

    def test_a_long_function_is_split_and_receipted_units_are_skipped(self) -> None:
        (self.target / "src" / "parsed.c").write_text(_body(600), encoding="utf-8")
        self.write_callgraph({"src/parsed.c": [["huge", 1]]})
        workqueue.rank_target(self.ctx, 10)
        self.assertEqual(
            [u.key for u in sweep.plan_units(self.ctx, unit_lines=100)],
            [f"src/parsed.c:{s}-{s + 99}" for s in range(1, 600, 100)],
        )
        coverage_ledger.record_receipt(self.ctx, "1", "src/parsed.c", lines="1-250")
        self.assertEqual(
            [u.key for u in sweep.plan_units(self.ctx, unit_lines=100)],
            ["src/parsed.c:201-300", "src/parsed.c:301-400", "src/parsed.c:401-500", "src/parsed.c:501-600"],
        )

    def test_gap_order_puts_unoffered_and_least_read_files_first(self) -> None:
        for name, lines in (("hot", 40), ("cold", 40), ("half", 40)):
            (self.target / "src" / f"{name}.c").write_text(_body(lines), encoding="utf-8")
        coverage_ledger.write_manifest(self.ctx, [
            (self.target / "src" / n, f"src/{n}") for n in ("hot.c", "cold.c", "half.c")
        ], {"src/hot.c", "src/half.c"})
        coverage_ledger.record_receipt(self.ctx, "1", "src/half.c", lines="1-20")
        coverage_ledger.record_receipt(self.ctx, "1", "src/hot.c", lines="1-40")
        keys = [u.key for u in sweep.plan_units(self.ctx, unit_lines=100)]
        self.assertEqual(keys, ["src/cold.c:1-40", "src/half.c:1-40"], "a fully receipted file has no unit")
        self.assertEqual(sweep.plan_units(self.ctx, 100)[0].reason, "never offered")


class ReplyTests(unittest.TestCase):
    UNIT = sweep.Unit("src/a.c", 40, 79, ["parse"])

    def test_ranges_are_held_inside_the_unit(self) -> None:
        ranges, _, _ = sweep.parse_reply(self.UNIT, {"examined": [[40, 60], [55, 79]], "verdicts": [], "leads": []})
        self.assertEqual(ranges, [(40, 79)])
        for bad in ([[30, 60]], [[60, 90]], [[70, 60]], [[1]], ["x"]):
            with self.assertRaises(sweep.ReplyError):
                sweep.parse_reply(self.UNIT, {"examined": bad, "verdicts": [], "leads": []})
        with self.assertRaises(sweep.ReplyError):
            sweep.parse_reply(self.UNIT, ["not", "an", "object"])

    def test_leads_are_kept_only_when_verifiable(self) -> None:
        good = {"function": "parse", "line": 50, "hypothesis": "h", "input_shape": "i",
                "guard_gap": "g", "diagnostic": "bounds", "strategy": "S7"}
        _, _, leads = sweep.parse_reply(self.UNIT, {"examined": [], "verdicts": [], "leads": [
            good,
            {**good, "function": "invented"},
            {**good, "line": 200},
            {**good, "diagnostic": "vibes"},
            {**good, "hypothesis": ""},
            {**good, "strategy": "S1"},
        ]})
        self.assertEqual([(l["function"], l["strategy"]) for l in leads], [("parse", "S7"), ("parse", "S3")])


class RunTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="sweep-run-")
        self.root = Path(self.temporary.name)
        self.target = self.root / "target"
        self.results = self.root / "results"
        (self.target / "src").mkdir(parents=True)
        (self.target / "src" / "a.c").write_text(_body(50), encoding="utf-8")
        (self.target / "src" / "b.c").write_text(_body(50), encoding="utf-8")
        self.ctx = workqueue.Context(ROOT, self.target, "sampleproj", self.results, "")
        workqueue.init_state(self.ctx)
        workqueue.rank_target(self.ctx, 10)
        self.env = {"LLM_DECIDE_DISABLE": "1", "LLM_DECIDE_MOCK": ""}

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def mock(self, reply: dict | None) -> dict:
        env = dict(self.env)
        if reply is not None:
            env["LLM_DECIDE_MOCK_SWEEP_UNIT"] = json.dumps(reply)
        return env

    def test_a_mocked_reply_becomes_a_receipt_and_a_lead(self) -> None:
        reply = {"examined": [[1, 50]], "verdicts": [{"function": "lines 1-50", "verdict": "suspicious"}],
                 "leads": [{"function": "", "line": 7, "hypothesis": "copy overruns", "input_shape": "long",
                            "guard_gap": "no length check", "diagnostic": "bounds", "strategy": "S7"}]}
        with mock.patch.dict(os.environ, self.mock(reply), clear=False):
            state = sweep.run(self.ctx, token_budget=10**6, unit_lines=100, log=lambda m: None)
        self.assertEqual((state["units"], state["receipts"], state["leads"], state["stop"]), (2, 2, 2, "exhausted"))
        self.assertGreater(state["spent_tokens"], 0)
        self.assertEqual(state["units_remaining"], 0)
        receipts = workqueue.read_jsonl(coverage_ledger.receipts_path(self.results))
        self.assertEqual({r["source"] for r in receipts}, {"sweep"})
        self.assertEqual(coverage_ledger.examined_fraction_by_file(self.results), {"src/a.c": 1.0, "src/b.c": 1.0})
        rows = workqueue.read_jsonl(workqueue.state_dir(self.results) / "hypotheses.jsonl")
        self.assertEqual([(r["agent"], r["status"], r["file"]) for r in rows][0], ("sweep", "NEEDS_TESTCASE", "src/a.c:lines 1-50:7"))
        self.assertEqual(workqueue.read_jsonl(workqueue.state_dir(self.results) / "claims.jsonl"), [],
                         "a lead never claims a card against real agents")
        self.assertEqual(sweep.read_state(self.results)["stop"], "exhausted")
        self.assertIn("2 lead(s)", coverage_ledger.render_coverage(coverage_ledger.coverage_report(self.ctx)))

    def test_the_budget_stops_the_sweep_and_carries_across_runs(self) -> None:
        reply = {"examined": [[1, 50]], "verdicts": [], "leads": []}
        with mock.patch.dict(os.environ, self.mock(reply), clear=False):
            first = sweep.run(self.ctx, token_budget=1, unit_lines=100)
            self.assertEqual((first["units"], first["stop"]), (1, "budget"))
            self.assertEqual(first["units_remaining"], 1)
            second = sweep.run(self.ctx, token_budget=1, unit_lines=100)
        self.assertEqual((second["units"], second["stop"]), (1, "budget"), "spend persists; nothing more is bought")
        self.assertEqual(second["spent_tokens"], first["spent_tokens"])

    def test_unusable_replies_count_against_the_budget_and_stop_after_a_streak(self) -> None:
        for name in ("c", "d", "e"):
            (self.target / "src" / f"{name}.c").write_text(_body(50), encoding="utf-8")
        workqueue.rank_target(self.ctx, 10)
        with mock.patch.dict(os.environ, self.mock({"examined": [[1, 999]], "verdicts": [], "leads": []}), clear=False):
            state = sweep.run(self.ctx, token_budget=10**6, unit_lines=100)
        self.assertEqual((state["units"], state["failures"], state["receipts"], state["stop"]), (3, 3, 0, "backend"))
        self.assertGreater(state["spent_tokens"], 0)
        with mock.patch.dict(os.environ, self.mock(None), clear=False):
            disabled = sweep.run(self.ctx, token_budget=10**6, unit_lines=100)
        self.assertEqual(disabled["stop"], "backend")

    def test_prompt_carries_the_numbered_unit_and_the_shape_validator_accepts_it(self) -> None:
        unit = sweep.plan_units(self.ctx, 100)[0]
        text = sweep.build_prompt(self.ctx, unit, "bytes")
        self.assertIn("File: `src/a.c` lines 1-50 of 50", text)
        self.assertIn(" 7  int line_7(void)", text)
        self.assertIn('"examined":[[1,50]]', text)
        self.assertTrue(llm_decide._validate_decision_shape("sweep_unit", {"examined": [[1, 2]], "verdicts": [], "leads": []}))
        self.assertFalse(llm_decide._validate_decision_shape("sweep_unit", {"examined": "1-2", "verdicts": [], "leads": []}))

    def test_cli_dry_run_lists_units_and_refuses_to_spend_without_a_budget(self) -> None:
        base = [str(ROOT / "bin" / "sweep"), "--target-path", str(self.target),
                "--target-slug", "sampleproj", "--results-dir", str(self.results)]
        listing = subprocess.run([*base, "--dry-run", "--unit-lines", "100"], capture_output=True, text=True, check=False)
        self.assertEqual(listing.returncode, 0, listing.stderr)
        self.assertEqual(listing.stdout.splitlines(), ["src/a.c:1-50 - (0% receipted)", "src/b.c:1-50 - (0% receipted)"])
        refused = subprocess.run(base, capture_output=True, text=True, check=False)
        self.assertEqual(refused.returncode, 2)
        self.assertIn("no token budget", refused.stderr)


class ConfigTests(unittest.TestCase):
    def load(self, text: str) -> target_config.Config:
        with tempfile.TemporaryDirectory() as tmp:
            toml = Path(tmp) / "target.toml"
            toml.write_text('target = "sampleproj"\n' + text, encoding="utf-8")
            config = target_config.Config(target_root=tmp)
            target_config.load_toml_into(config, toml)
            return config

    def test_sweep_section_is_off_by_default_and_validated(self) -> None:
        config = self.load("")
        self.assertEqual((config.sweep_token_budget, config.sweep_model, config.sweep_unit_lines), (0, "", 120))
        config = self.load('[sweep]\ntoken_budget = 5000\nmodel = " m "\nunit_lines = 80\n')
        self.assertEqual((config.sweep_token_budget, config.sweep_model, config.sweep_unit_lines), (5000, "m", 80))
        for bad in ("token_budget = -1", 'token_budget = "lots"', "unit_lines = 5", "model = 3"):
            with self.assertRaises(ValueError):
                self.load(f"[sweep]\n{bad}\n")


if __name__ == "__main__":
    unittest.main()
