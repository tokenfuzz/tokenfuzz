#!/usr/bin/env python3
"""The budgeted sweep: unit planning, reply checking, spend, and pickup."""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import tempfile
import unittest
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "lib"))

import callgraph
import audit_runner
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
        self.assertEqual(
            [key for key in units if key.startswith("src/parsed.c:") and units[key].functions == ["huge"]],
            ["src/parsed.c:60-159", "src/parsed.c:160-259", "src/parsed.c:260-300"],
        )
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

    def test_ninety_nine_point_nine_percent_is_not_complete(self) -> None:
        source = self.target / "src" / "almost.c"
        source.write_text(_body(1000), encoding="utf-8")
        workqueue.rank_target(self.ctx, 10)
        coverage_ledger.record_receipt(self.ctx, "1", "src/almost.c", lines="1-999")
        units = [unit for unit in sweep.plan_units(self.ctx, unit_lines=100)
                 if unit.file == "src/almost.c"]
        self.assertEqual([unit.key for unit in units], ["src/almost.c:901-1000"])

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
    VERDICT = [{"function": "parse", "verdict": "suspicious"}]

    def test_ranges_are_held_inside_the_unit(self) -> None:
        ranges, _, _ = sweep.parse_reply(self.UNIT, {
            "examined": [[40, 60], [55, 79]], "verdicts": self.VERDICT, "leads": [],
        })
        self.assertEqual(ranges, [(40, 79)])
        for bad in ([[30, 60]], [[60, 90]], [[70, 60]], [[1]], ["x"]):
            with self.assertRaises(sweep.ReplyError):
                sweep.parse_reply(self.UNIT, {"examined": bad, "verdicts": [], "leads": []})
        with self.assertRaises(sweep.ReplyError):
            sweep.parse_reply(self.UNIT, ["not", "an", "object"])

    def test_leads_are_kept_only_when_verifiable(self) -> None:
        good = {"function": "parse", "line": 50, "hypothesis": "h", "input_shape": "i",
                "guard_gap": "g", "diagnostic": "bounds", "strategy": "S7"}
        _, _, leads = sweep.parse_reply(self.UNIT, {"examined": [[40, 79]], "verdicts": self.VERDICT, "leads": [
            good,
            {**good, "function": "invented"},
            {**good, "line": 200},
            {**good, "diagnostic": "vibes"},
            {**good, "hypothesis": ""},
            {**good, "strategy": "S1"},
            {**good, "line": 60, "strategy": ""},
            {**good, "function": "parse()", "line": 70},
        ]})
        self.assertEqual(
            [(l["function"], l["line"], l["strategy"]) for l in leads],
            [("parse", 50, "S7"), ("parse", 60, "S3"), ("parse", 70, "S7")],
            "a repeat at one site is dropped; an absent or unknown strategy label "
            "defaults, since it routes the lead and is not evidence; `parse()` is parse",
        )

        _, _, clean_leads = sweep.parse_reply(self.UNIT, {
            "examined": [[40, 79]],
            "verdicts": [{"function": "parse", "verdict": "clean"}],
            "leads": [good],
        })
        self.assertEqual(clean_leads, [])

    def test_line_window_leads_use_the_exact_window_label(self) -> None:
        unit = sweep.Unit("src/a.c", 1, 20)
        base = {"line": 7, "hypothesis": "h", "input_shape": "i",
                "guard_gap": "g", "diagnostic": "bounds", "strategy": "S7"}
        reply = {"examined": [[1, 20]],
                 "verdicts": [{"function": "lines 1-20", "verdict": "suspicious"}],
                 "leads": [{**base, "function": "invented"},
                           {**base, "function": "lines 1-20"},
                           {**base, "function": "lines 1-20"}]}
        _, _, leads = sweep.parse_reply(unit, reply)
        self.assertEqual([(lead["function"], lead["line"]) for lead in leads], [("lines 1-20", 7)])

    def test_reply_needs_a_receipt_and_leads_must_be_inside_it(self) -> None:
        with self.assertRaisesRegex(sweep.ReplyError, "no examined ranges"):
            sweep.parse_reply(self.UNIT, {"examined": [], "verdicts": [], "leads": []})
        lead = {"function": "parse", "line": 70, "hypothesis": "h", "input_shape": "i",
                "guard_gap": "g", "diagnostic": "bounds", "strategy": "S7"}
        with self.assertRaisesRegex(sweep.ReplyError, "whole unit"):
            sweep.parse_reply(
                self.UNIT, {"examined": [[40, 60]], "verdicts": self.VERDICT, "leads": [lead]},
            )
        with self.assertRaisesRegex(sweep.ReplyError, "verdicts do not cover"):
            sweep.parse_reply(
                self.UNIT, {"examined": [[40, 79]], "verdicts": [], "leads": []},
            )


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

    def test_run_holds_one_owner_lock_around_the_complete_state_machine(self) -> None:
        events: list[str] = []

        @contextmanager
        def owner(results_dir):
            self.assertEqual(results_dir, self.results)
            events.append("acquired")
            try:
                yield
            finally:
                events.append("released")

        def run_locked(*args, **kwargs):
            self.assertEqual(events, ["acquired"])
            events.append("ran")
            return {"stop": "test"}

        with mock.patch.object(sweep, "_owner_lock", owner), \
                mock.patch.object(sweep, "_run_locked", run_locked):
            self.assertEqual(sweep.run(self.ctx, token_budget=1), {"stop": "test"})
        self.assertEqual(events, ["acquired", "ran", "released"])

    def test_a_second_sweep_is_refused_rather_than_queued(self) -> None:
        with sweep._owner_lock(self.results):
            with self.assertRaisesRegex(sweep.SweepStateError, "another sweep holds"):
                sweep.run(self.ctx, token_budget=1)

    def test_a_mocked_reply_becomes_a_receipt_and_a_lead(self) -> None:
        reply = {"examined": [[1, 50]], "verdicts": [{"function": "lines 1-50", "verdict": "suspicious"}],
                 "leads": [{"function": "lines 1-50", "line": 7, "hypothesis": "copy overruns", "input_shape": "long",
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
        # Leads reach the reproduce lane through the ordinary handoff.
        import prompt
        references = self.root / "references"
        (references / "strategies").mkdir(parents=True)
        (references / "session-rules.digest.md").write_text("digest\n", encoding="utf-8")
        context = prompt.PromptContext(self.results, self.target, "sampleproj", references, 1)
        self.assertEqual(context.role(1), "reproduce")
        handed = prompt.handoff_rows(context, 1)
        self.assertEqual([row["agent"] for row in handed], ["sweep", "sweep"])
        self.assertIn("HANDOFF FROM ANALYSIS", prompt.handoff_directive(context, 1))
        self.assertIn("2 lead(s)", coverage_ledger.render_coverage(coverage_ledger.coverage_report(self.ctx)))

    def test_the_budget_stops_the_sweep_and_carries_across_runs(self) -> None:
        reply = {"examined": [[1, 50]],
                 "verdicts": [{"function": "lines 1-50", "verdict": "clean"}], "leads": []}
        with mock.patch.dict(os.environ, self.mock(reply), clear=False):
            first = sweep.run(self.ctx, token_budget=1, unit_lines=100)
            self.assertEqual((first["units"], first["stop"]), (0, "budget"))
            self.assertEqual(first["units_remaining"], 2)
            second = sweep.run(self.ctx, token_budget=1, unit_lines=100)
        self.assertEqual((second["units"], second["stop"]), (0, "budget"), "the known prompt cannot overspend")
        self.assertEqual(second["spent_tokens"], first["spent_tokens"])

    def test_an_interrupted_provider_call_keeps_its_prompt_spend(self) -> None:
        def interrupted(*args, **kwargs):
            signal.getsignal(signal.SIGTERM)(signal.SIGTERM, None)
            return None

        with mock.patch.object(llm_decide, "llm_decide", side_effect=interrupted):
            state = sweep.run(self.ctx, token_budget=10**6, unit_lines=100)
        self.assertEqual((state["units"], state["receipts"], state["stop"]), (1, 0, "interrupted"))
        self.assertEqual(state["failures"], 0, "shutdown is not a backend failure")
        self.assertGreater(state["spent_tokens"], 0)
        self.assertEqual(sweep.read_state(self.results), state)

    def test_sigterm_before_dispatch_does_not_buy_or_start_a_call(self) -> None:
        real_write = sweep._write_state
        requested = False

        def request_stop(results_dir, state):
            nonlocal requested
            real_write(results_dir, state)
            if not requested and state["units"] == 1:
                requested = True
                signal.getsignal(signal.SIGTERM)(signal.SIGTERM, None)

        with mock.patch.object(sweep, "_write_state", side_effect=request_stop), \
                mock.patch.object(llm_decide, "llm_decide") as decide:
            state = sweep.run(self.ctx, token_budget=10**6, unit_lines=100)
        decide.assert_not_called()
        self.assertEqual(
            (state["units"], state["spent_tokens"], state["units_remaining"], state["stop"]),
            (0, 0, 2, "interrupted"),
        )

    def test_sigterm_after_a_valid_reply_commits_its_receipt_and_lead(self) -> None:
        reply = {
            "examined": [[1, 50]],
            "verdicts": [{"function": "lines 1-50", "verdict": "suspicious"}],
            "leads": [{"function": "lines 1-50", "line": 3, "hypothesis": "h",
                       "input_shape": "i", "guard_gap": "g", "diagnostic": "bounds",
                       "strategy": "S7"}],
        }

        def interrupted(*args, **kwargs):
            signal.getsignal(signal.SIGTERM)(signal.SIGTERM, None)
            return reply

        with mock.patch.object(llm_decide, "llm_decide", side_effect=interrupted):
            state = sweep.run(self.ctx, token_budget=10**6, unit_lines=100)
        self.assertEqual(
            (state["units"], state["receipts"], state["leads"], state["failures"], state["stop"]),
            (1, 1, 1, 0, "interrupted"),
        )
        rows = workqueue.read_jsonl(workqueue.state_dir(self.results) / "hypotheses.jsonl")
        self.assertEqual([(row["strategy"], row["status"]) for row in rows], [("S7", "NEEDS_TESTCASE")])
        self.assertEqual(state["units_remaining"], 1)
        self.assertEqual(
            audit_runner.progress(SimpleNamespace(results=self.results, num_agents=1)).active, 1,
            "iteration progress counts the sweep's open lead as live work",
        )

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

    def test_state_is_written_after_every_unit_and_a_bad_receipt_is_a_failure(self) -> None:
        # The audit ends the sweep with SIGTERM; spend written only at the end
        # would be spent again on the next resume.
        reply = {"examined": [[1, 50]],
                 "verdicts": [{"function": "lines 1-50", "verdict": "clean"}], "leads": []}
        seen: list[int] = []
        real_receipt = coverage_ledger.record_receipt

        def flaky(ctx, agent, file, **kwargs):
            seen.append(len(seen))
            if len(seen) == 1:
                raise coverage_ledger.ReceiptError("file changed under the plan")
            return real_receipt(ctx, agent, file, **kwargs)

        with mock.patch.dict(os.environ, self.mock(reply), clear=False), \
                mock.patch.object(coverage_ledger, "record_receipt", flaky):
            state = sweep.run(self.ctx, token_budget=10**6, unit_lines=100)
        self.assertEqual((state["units"], state["failures"], state["receipts"], state["stop"]), (2, 1, 1, "incomplete"))
        self.assertEqual(state["units_remaining"], 1)

    def test_units_receipted_by_a_session_since_the_plan_are_not_bought(self) -> None:
        reply = {"examined": [[1, 50]],
                 "verdicts": [{"function": "lines 1-50", "verdict": "clean"}], "leads": []}
        calls: list[str] = []
        real_prompt = sweep.build_prompt

        def spy(ctx, unit, controls, graph=None):
            calls.append(unit.key)
            if len(calls) == 1:
                coverage_ledger.record_receipt(ctx, "1", "src/b.c", lines="1-50")
            return real_prompt(ctx, unit, controls, graph=graph)

        with mock.patch.dict(os.environ, self.mock(reply), clear=False), \
                mock.patch.object(sweep, "build_prompt", spy):
            state = sweep.run(self.ctx, token_budget=10**6, unit_lines=100)
        self.assertEqual(calls, ["src/a.c:1-50"])
        self.assertEqual((state["units"], state["units_remaining"]), (1, 0))

    def test_prompt_carries_the_numbered_unit_and_the_shape_validator_accepts_it(self) -> None:
        unit = sweep.plan_units(self.ctx, 100)[0]
        text = sweep.build_prompt(self.ctx, unit, "bytes")
        self.assertIn("File: `src/a.c` lines 1-50 of 50", text)
        self.assertIn(" 7  int line_7(void)", text)
        self.assertIn('"examined":[[1,50]]', text)
        self.assertTrue(llm_decide._validate_decision_shape("sweep_unit", {"examined": [[1, 2]], "verdicts": [], "leads": []}))
        self.assertFalse(llm_decide._validate_decision_shape("sweep_unit", {"examined": "1-2", "verdicts": [], "leads": []}))

    def test_prompt_does_not_hide_long_line_content(self) -> None:
        marker = "tail-marker"
        (self.target / "src" / "long.c").write_text("x" * 500 + marker + "\n", encoding="utf-8")
        workqueue.rank_target(self.ctx, 10)
        text = sweep.build_prompt(self.ctx, sweep.Unit("src/long.c", 1, 1), "bytes")
        self.assertIn(marker, text)
        self.assertIn("untrusted", text.lower())

    def test_prompt_refuses_source_that_changed_after_the_manifest(self) -> None:
        unit = sweep.plan_units(self.ctx, 100)[0]
        (self.target / unit.file).write_text("changed\n" * 50, encoding="utf-8")
        with self.assertRaisesRegex(OSError, "changed after the sweep plan"):
            sweep.build_prompt(self.ctx, unit, "bytes")

    def test_invalid_state_is_not_silently_reset(self) -> None:
        sweep.state_path(self.results).write_text("not-json\n", encoding="utf-8")
        with self.assertRaises(sweep.SweepStateError):
            sweep.read_state(self.results)

    def test_launch_uses_its_runtime_backend_in_an_ensemble(self) -> None:
        config = target_config.Config(target_root=str(self.target))
        config.sweep_token_budget = 100
        runtime = SimpleNamespace(
            root=ROOT, target_root=self.target, target_slug="sampleproj", results=self.results,
            logs=self.root / "logs", backend="codex", model="gpt-test", target_rev="abc",
            repo_type="git", agent_security="workspace-write", decision_timeout=17,
            config=config, delta=None, fixed_strategy="",
        )
        runtime.logs.mkdir()
        fake = SimpleNamespace(pid=123)
        with mock.patch.dict(os.environ, {"ACTIVE_BACKEND": "gemini", "BACKEND": "gemini", "MODEL": "wrong",
                                                   "RESULTS_DIR": "/wrong", "LLM_DECIDE_LOG": "/wrong/log"}, clear=False), \
                mock.patch.object(audit_runner.subprocess, "Popen", return_value=fake) as popen, \
                mock.patch.object(audit_runner, "index_log"):
            self.assertIs(audit_runner.launch_sweep(runtime), fake)
        environment = popen.call_args.kwargs["env"]
        self.assertEqual((environment["ACTIVE_BACKEND"], environment["BACKEND"], environment["MODEL"]),
                         ("codex", "codex", "gpt-test"))
        self.assertEqual(environment["RESULTS_DIR"], str(self.results))
        self.assertEqual(environment["LLM_DECIDE_LOG"], str(runtime.logs / "llm-decisions.log"))

    def test_stop_signals_the_sweep_before_reaping_its_provider(self) -> None:
        events: list[str] = []

        class RunningSweep:
            pid = 123
            returncode = None

            def poll(self):
                return self.returncode

            def terminate(self):
                events.append("sweep")

            def wait(self, timeout=None):
                self.returncode = 0
                return 0

            def kill(self):
                self.returncode = -9

        runtime = SimpleNamespace(results=self.results)
        with mock.patch.object(
            audit_runner.process_tree, "kill_descendants",
            side_effect=lambda *args: events.append("provider"),
        ), mock.patch.object(audit_runner, "index_log"):
            audit_runner.stop_sweep(runtime, RunningSweep())
        self.assertEqual(events, ["sweep", "provider"])

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
