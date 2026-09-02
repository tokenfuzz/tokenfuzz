#!/usr/bin/env python3
"""CLI regression coverage for resilient usage extraction."""

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
COMMAND = ROOT / "lib" / "llm_usage.py"
sys.path.insert(0, str(ROOT / "lib"))

import llm_usage


class UsageExtractionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="llm-usage-")
        self.root = Path(self.temporary.name)
        self.claude = self.fixture("claude.raw", [
            {"type": "assistant", "message": {"content": [{"type": "text", "text": "hi"}]},
             "usage": {"input_tokens": 500, "cache_read_input_tokens": 300,
                       "cache_creation_input_tokens": 100, "output_tokens": 25, "duration_ms": 1200}},
            {"type": "assistant", "message": {"content": [{"type": "text", "text": "more"}]},
             "usage": {"input_tokens": 1500, "cache_read_input_tokens": 1000,
                       "cache_creation_input_tokens": 100, "output_tokens": 80, "duration_ms": 3400}},
            {"type": "result", "duration_ms": 3400},
        ])
        self.codex = self.fixture("codex.raw", [
            {"type": "item.completed", "item": {"type": "command_execution"},
             "usage": {"input_tokens": 900, "output_tokens": 42}},
        ])
        self.gemini = self.fixture("gemini.raw", [
            {"type": "message", "role": "assistant", "content": "hi"},
            {"type": "result", "stats": {"input_tokens": 2000, "output_tokens": 150, "cached": 800}},
        ])
        self.grok = self.fixture("grok.raw", [
            {"type": "text", "data": "First output chunk. "},
            {"type": "text", "data": "Second output chunk."},
            {"type": "end", "stopReason": "EndTurn", "sessionId": "session-1"},
        ])
        self.plain = self.root / "agy.raw"
        self.plain.write_text(
            "I'll start by inspecting the parser. Read main.c lines 1-120. The\n"
            "function parse_input reads up to 4096 bytes into a fixed buffer. I\n"
            "filed FIND-001 documenting an unchecked memcpy. End of session.\n",
            encoding="utf-8",
        )
        self.empty = self.root / "empty.raw"
        self.empty.touch()
        self.missing = self.root / "does-not-exist.raw"
        self.prompt = self.root / "prompt.md"
        self.prompt.write_text("Pretend this is the rendered prompt — 64 chars roughly here.\n")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def fixture(self, name, rows):
        path = self.root / name
        path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
        return path

    def cli(self, *args):
        return subprocess.run(
            [sys.executable, str(COMMAND), *map(str, args)], capture_output=True, text=True
        )

    def field(self, field, backend, raw, *args):
        proc = self.cli("extract-field", field, backend, raw, *args)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        return proc.stdout.strip()

    def fields(self, backend, raw, *args):
        proc = self.cli("extract-fields", backend, raw, *args)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        return dict(line.split("=", 1) for line in proc.stdout.splitlines())

    def test_claude_running_max_and_fields_cli(self) -> None:
        expected = {
            "input_tokens": "1500", "output_tokens": "80",
            "cached_input_tokens": "1000", "cache_creation_input_tokens": "100",
            "total_tokens": "1580", "duration_ms": "3400",
        }
        for field, value in expected.items():
            with self.subTest(field=field):
                self.assertEqual(self.field(field, "claude", self.claude), value)
        rendered = self.fields("claude", self.claude)
        for field, value in expected.items():
            with self.subTest(fields_cli=field):
                self.assertEqual(rendered[field], value)

    def test_codex_and_gemini_measured_fields(self) -> None:
        self.assertEqual(self.field("input_tokens", "codex", self.codex), "900")
        self.assertEqual(self.field("output_tokens", "codex", self.codex), "42")
        self.assertEqual(self.field("cached_input_tokens", "codex", self.codex), "0")
        self.assertEqual(self.field("input_tokens", "gemini", self.gemini), "2000")
        self.assertEqual(self.field("output_tokens", "gemini", self.gemini), "150")
        self.assertEqual(self.field("cached_input_tokens", "gemini", self.gemini), "800")

    def test_plain_text_and_grok_estimates(self) -> None:
        self.assertGreater(int(self.field("output_tokens", "gemini", self.plain)), 0)
        self.assertEqual(self.field("input_tokens", "gemini", self.plain), "0")
        self.assertGreater(
            int(self.field("input_tokens", "gemini", self.plain, "--prompt", self.prompt)), 0
        )
        plain_fields = self.fields("gemini", self.plain, "--prompt", self.prompt)
        self.assertGreater(int(plain_fields["input_tokens"]), 0)
        self.assertGreater(int(plain_fields["output_tokens"]), 0)
        grok_fields = self.fields("grok", self.grok, "--prompt", self.prompt)
        self.assertGreater(int(grok_fields["input_tokens"]), 0)
        self.assertGreater(int(grok_fields["output_tokens"]), 0)

    def test_empty_missing_unknown_and_incomplete_cli_are_fail_open(self) -> None:
        self.assertEqual(self.field("input_tokens", "claude", self.empty), "")
        self.assertEqual(self.field("output_tokens", "codex", self.empty), "")
        self.assertEqual(self.field("output_tokens", "gemini", self.empty), "0")
        self.assertEqual(self.field("input_tokens", "claude", self.missing), "")
        self.assertEqual(self.field("output_tokens", "gemini", self.missing), "")
        missing = self.fields("gemini", self.missing)
        self.assertEqual(missing["input_tokens"], "")
        self.assertEqual(missing["duration_ms"], "")
        self.assertEqual(self.field("this_field_does_not_exist", "claude", self.claude), "")
        for args in (("extract-field",), ("extract-field", "output_tokens")):
            proc = self.cli(*args)
            self.assertEqual(proc.returncode, 0)
            self.assertEqual(proc.stdout.strip(), "")
        proc = self.cli("some-unknown-subcommand", "foo", "bar")
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(proc.stdout.strip(), "{}")

    def test_multiple_terminal_events_are_summed_without_assistant_double_count(self) -> None:
        raw = self.fixture("multi.raw", [
            {"type": "assistant", "usage": {"input_tokens": 5, "output_tokens": 10}},
            {"type": "result", "usage": {"input_tokens": 100, "cache_read_input_tokens": 1000,
                                          "cache_creation_input_tokens": 50, "output_tokens": 900}},
            {"type": "assistant", "usage": {"input_tokens": 2, "output_tokens": 3}},
            {"type": "result", "usage": {"input_tokens": 10, "cache_read_input_tokens": 200,
                                          "cache_creation_input_tokens": 5, "output_tokens": 30}},
        ])
        expected = {
            "output_tokens": "930", "input_tokens": "110",
            "cached_input_tokens": "1200", "cache_creation_input_tokens": "55",
        }
        for field, value in expected.items():
            with self.subTest(field=field):
                self.assertEqual(self.field(field, "claude", raw), value)

    def test_claude_model_usage_uses_largest_session_snapshot(self) -> None:
        snapshot = {
            "claude-opus": {"inputTokens": 100, "cacheCreationInputTokens": 200,
                            "cacheReadInputTokens": 300, "outputTokens": 400},
            "claude-haiku": {"inputTokens": 1, "cacheCreationInputTokens": 2,
                             "cacheReadInputTokens": 3, "outputTokens": 4},
        }
        raw = self.fixture("model-usage.raw", [
            {"type": "result", "usage": {"input_tokens": 10}, "modelUsage": snapshot},
            {"type": "result", "usage": {"input_tokens": 10}, "modelUsage": snapshot},
        ])
        for field, value in {
            "input_tokens": "101", "cached_input_tokens": "303",
            "cache_creation_input_tokens": "202", "output_tokens": "404",
        }.items():
            with self.subTest(field=field):
                self.assertEqual(self.field(field, "claude", raw), value)
        max_raw = self.fixture("model-usage-max.raw", [
            {"type": "result", "modelUsage": {"claude-opus": {"inputTokens": 900, "outputTokens": 100}}},
            {"type": "result", "modelUsage": {"claude-opus": {"inputTokens": 5, "outputTokens": 5}}},
        ])
        self.assertEqual(self.field("input_tokens", "claude", max_raw), "900")

    def test_claude_one_hour_cache_bucket_and_cost_survive(self) -> None:
        raw = self.fixture("claude-1h.raw", [{
            "type": "result", "total_cost_usd": 0.123456,
            "usage": {"input_tokens": 10, "cache_creation_input_tokens": 200,
                      "cache_read_input_tokens": 30, "output_tokens": 40,
                      "cache_creation": {"ephemeral_1h_input_tokens": 200,
                                         "ephemeral_5m_input_tokens": 0}},
            "modelUsage": {"claude-opus": {"inputTokens": 100,
                                            "cacheCreationInputTokens": 200,
                                            "cacheReadInputTokens": 300,
                                            "outputTokens": 400}},
        }])
        row = llm_usage.extract_usage(str(raw), backend="claude")
        self.assertEqual(row["tokens"]["cache_creation_1h"], 200)
        self.assertEqual(row["cost_usd"], 0.123456)

    def test_capped_claude_session_sums_every_request(self) -> None:
        # A session ended by the turn cap or the wall clock never emits its
        # terminal event. Taking only the last per-request usage reported one
        # request's tokens and made a long, expensive session look cheap.
        def request(identifier: str, cache_read: int) -> dict:
            return {
                "type": "assistant",
                "message": {
                    "id": identifier,
                    "content": [{"type": "tool_use", "name": "Bash"}],
                    "usage": {
                        "input_tokens": 2,
                        "cache_read_input_tokens": cache_read,
                        "cache_creation_input_tokens": 100,
                        "output_tokens": 50,
                        "cache_creation": {"ephemeral_1h_input_tokens": 100},
                    },
                },
            }

        repeated = request("msg_2", 41_000)
        repeated["message"]["usage"]["cache_creation_input_tokens"] = 50
        repeated["message"]["usage"]["output_tokens"] = 40
        raw = self.fixture("capped.raw", [
            request("msg_1", 17_000),
            # The streamed event for one request repeats with growing
            # counters. Merge buckets independently so a larger cache snapshot
            # cannot discard an earlier non-cache counter.
            request("msg_2", 40_000),
            repeated,
            request("msg_3", 90_000),
        ])
        row = llm_usage.extract_usage(str(raw), backend="claude")
        self.assertEqual(row["tokens"]["cached_input"], 148_000)
        self.assertEqual(row["tokens"]["cache_creation"], 300)
        self.assertEqual(row["tokens"]["output"], 150)
        self.assertTrue(row["estimated"])
        self.assertTrue(llm_usage.usage_is_complete(row, 0))

        # Claude reports a request's usage as the message begins, so its
        # output_tokens is a stub. Billed generated content — thinking blocks
        # especially — is the better floor, and taking it marks the row
        # estimated rather than reporting a stub as measured.
        thinking = request("msg_4", 1_000)
        thinking["message"]["content"] = [
            {"type": "thinking", "thinking": "y" * 8_000},
        ]
        tool = request("msg_4", 1_000)
        tool["message"]["content"] = [
            {"type": "tool_use", "name": "Bash", "input": {"command": "z" * 2_000}},
        ]
        raw = self.fixture("thinking.raw", [thinking, tool])
        row = llm_usage.extract_usage(str(raw), backend="claude")
        self.assertEqual(row["tokens"]["cached_input"], 1_000)
        self.assertGreater(row["tokens"]["output"], 2_000)
        self.assertTrue(row["estimated"])

    def rollout(self, home: Path, tid: str, *totals: dict) -> Path:
        path = home / "sessions" / "2026" / "08" / "16" / f"rollout-2026-08-16T01-02-03-{tid}.jsonl"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("".join(
            json.dumps({"type": "event_msg", "payload": {
                "type": "token_count", "info": {"total_token_usage": total},
            }}) + "\n" for total in totals
        ), encoding="utf-8")
        return path

    def test_interrupted_codex_session_recovers_usage_from_its_rollout(self) -> None:
        # Codex reports usage only in `turn.completed`, which a session
        # stopped at the turn cap or the wall deadline never emits. Scoring
        # those zero priced a model-direct cell's entire audit as free.
        raw = self.fixture("codex-capped.raw", [
            {"type": "thread.started", "thread_id": "thread-a"},
            {"type": "turn.started"},
            {"type": "item.completed", "item": {"type": "command_execution"}},
        ])
        home = self.root / "codex-home"
        consumed = self.rollout(
            home, "thread-a",
            {"input_tokens": 10, "cached_input_tokens": 4, "output_tokens": 1},
            {"input_tokens": 900, "cached_input_tokens": 700,
             "cache_write_input_tokens": 50, "output_tokens": 42},
        )
        untouched = self.rollout(
            home, "thread-b", {"input_tokens": 1, "output_tokens": 1},
        )

        with mock.patch.dict(os.environ, {"CODEX_HOME": str(home)}):
            row = llm_usage.extract_usage(str(raw), backend="codex")

        # The last token_count is the thread's cumulative total, not a delta.
        self.assertEqual(row["tokens"]["input"], 900)
        self.assertEqual(row["tokens"]["cached_input"], 700)
        self.assertEqual(row["tokens"]["cache_creation"], 50)
        self.assertEqual(row["tokens"]["output"], 42)
        self.assertFalse(row["estimated"], "rollout counters are measured")
        self.assertFalse(consumed.exists(), "the rollout is deleted once read")
        self.assertTrue(untouched.exists(), "another thread's rollout is left alone")

    def test_delegation_events_are_read_from_the_codex_rollout(self) -> None:
        # Codex surfaces a subagent spawn only in its rollout, as a
        # `spawn_agent` function call; the parent's --json stream shows one
        # thread and nothing else. The count has to be taken in the same pass
        # that consumes (and deletes) the rollout.
        raw = self.fixture("codex-spawn.raw", [
            {"type": "thread.started", "thread_id": "thread-s"},
            {"type": "turn.started"},
        ])
        home = self.root / "codex-home"
        path = self.rollout(
            home, "thread-s", {"input_tokens": 50, "output_tokens": 5},
        )
        with path.open("a", encoding="utf-8") as stream:
            for _ in range(2):
                stream.write(json.dumps({"type": "response_item", "payload": {
                    "type": "function_call", "name": "spawn_agent",
                    "namespace": "collaboration", "arguments": "{}",
                }}) + "\n")
            stream.write(json.dumps({"type": "response_item", "payload": {
                "type": "function_call", "name": "exec", "arguments": "{}",
            }}) + "\n")
        with mock.patch.dict(os.environ, {"CODEX_HOME": str(home)}):
            row = llm_usage.extract_usage(str(raw), backend="codex")
        self.assertEqual(row["delegation_events"], 2)
        self.assertEqual(row["tokens"]["input"], 50)
        self.assertTrue(row["spend_lower_bound"], "a spawned codex thread's rollout is not linkable")
        self.assertTrue(row["estimated"])

    def test_opencode_delegation_is_a_spend_floor_counted_once_per_call(self) -> None:
        # OpenCode repeats a tool part as its state changes, and its `task`
        # subagent runs in a separate session the parent's stream never shows
        # (measured: one session id in a delegating transcript), so the row
        # counts distinct call ids and is marked a floor.
        raw = self.fixture("oss-task.raw", [
            {"type": "tool_use", "part": {"id": "p1", "callID": "c1", "tool": "task",
                                          "state": {"status": "running"}}},
            {"type": "tool_use", "part": {"id": "p1", "callID": "c1", "tool": "task",
                                          "state": {"status": "completed"}}},
            {"type": "tool_use", "part": {"id": "p2", "callID": "c2", "tool": "task"}},
            {"type": "tool_use", "part": {"id": "p3", "callID": "c3", "tool": "bash"}},
            {"type": "step_finish", "usage": {"input_tokens": 30, "output_tokens": 4}},
        ])
        row = llm_usage.extract_usage(str(raw), backend="oss")
        self.assertEqual(row["delegation_events"], 2)
        self.assertTrue(row["spend_lower_bound"])
        self.assertTrue(row["estimated"], "unseen child spend makes the row a floor")

    def test_gemini_cli_invoke_agent_is_recognised_and_not_a_floor(self) -> None:
        raw = self.fixture("gemini-agent.raw", [
            {"type": "tool_call", "tool_name": "invoke_agent", "tool_call_id": "t1"},
            {"type": "tool_call", "tool_name": "invoke_agent", "tool_call_id": "t1"},
            {"type": "result", "stats": {"input_tokens": 9, "output_tokens": 2}},
        ])
        row = llm_usage.extract_usage(str(raw), backend="gemini")
        self.assertEqual(row["delegation_events"], 1)
        self.assertFalse(row.get("spend_lower_bound", False),
                         "gemini-cli runs subagents in-process; its stats cover them")

    def test_grok_subagent_events_are_counted_and_a_floor(self) -> None:
        # Grok streams one lifecycle event per spawned subagent and reports no
        # usage at all, so the spawn is counted by its id and the row is a
        # spend floor. Event names come from the CLI binary; a live Grok
        # transcript with a subagent has not yet been read.
        raw = self.fixture("grok-subagent.raw", [
            {"type": "subagent_start", "subagent_id": "s1", "subagent_type": "explore"},
            {"type": "subagent_start", "subagent_id": "s1"},
            {"type": "subagent_end", "subagent_id": "s1", "tool_calls": 3},
            {"type": "subagent_start", "subagent_id": "s2"},
            {"type": "text", "data": "done"},
        ])
        row = llm_usage.extract_usage(str(raw), backend="grok")
        self.assertEqual(row["delegation_events"], 2)
        self.assertTrue(row["spend_lower_bound"])
        self.assertFalse(row["delegation_observable"],
                         "Grok's fan-out is disclosed as unobservable whatever was counted")
        plain = self.fixture("grok-plain.raw", [{"type": "text", "data": "done"}])
        self.assertFalse(llm_usage.extract_usage(str(plain), backend="grok")["delegation_observable"])

    def test_delegation_events_count_claude_agent_calls_only(self) -> None:
        raw = self.fixture("claude-agent.raw", [
            {"type": "assistant", "message": {"id": "m1", "usage": {"input_tokens": 4, "output_tokens": 1},
             "content": [{"type": "tool_use", "name": "Agent", "input": {}},
                         {"type": "tool_use", "name": "Bash", "input": {}},
                         {"type": "tool_use", "name": "Task", "input": {}}]}},
            {"type": "result", "usage": {"input_tokens": 4, "output_tokens": 1},
             "modelUsage": {"m": {"inputTokens": 4, "outputTokens": 1}}},
        ])
        row = llm_usage.extract_usage(str(raw), backend="claude")
        self.assertEqual(row["delegation_events"], 2)
        plain = self.fixture("claude-plain.raw", [
            {"type": "result", "usage": {"input_tokens": 4, "output_tokens": 1},
             "modelUsage": {"m": {"inputTokens": 4, "outputTokens": 1}}},
        ])
        self.assertEqual(llm_usage.extract_usage(str(plain), backend="claude")["delegation_events"], 0)

    def test_codex_sums_every_thread_including_the_interrupted_one(self) -> None:
        # One transcript, two threads: A finished and reported a terminal
        # event, B was interrupted and exists only in its rollout. Preferring
        # the terminal events dropped B's spend AND deleted the only record
        # of it, so the rollout outranks them and every thread is summed.
        raw = self.fixture("codex-mixed.raw", [
            {"type": "thread.started", "thread_id": "thread-a"},
            {"type": "turn.completed", "usage": {"input_tokens": 100}},
            {"type": "thread.started", "thread_id": "thread-b"},
            {"type": "item.completed", "item": {"type": "command_execution"}},
        ])
        home = self.root / "codex-home-mixed"
        a = self.rollout(home, "thread-a", {"input_tokens": 100, "output_tokens": 5})
        b = self.rollout(home, "thread-b", {"input_tokens": 200, "output_tokens": 7})

        with mock.patch.dict(os.environ, {"CODEX_HOME": str(home)}):
            row = llm_usage.extract_usage(str(raw), backend="codex")

        self.assertEqual(row["tokens"]["input"], 300)
        self.assertEqual(row["tokens"]["output"], 12)
        self.assertFalse(a.exists())
        self.assertFalse(b.exists())

    def test_partial_rollout_coverage_keeps_the_stream_and_destroys_nothing(self) -> None:
        # Half the threads resolved cannot be added to stream totals without
        # double-counting, and a rollout read but unused is the last record of
        # that thread — so nothing is consumed and nothing is deleted.
        raw = self.fixture("codex-partial.raw", [
            {"type": "thread.started", "thread_id": "thread-a"},
            {"type": "turn.completed", "usage": {"input_tokens": 100}},
            {"type": "thread.started", "thread_id": "thread-missing"},
        ])
        home = self.root / "codex-home-partial"
        kept = self.rollout(home, "thread-a", {"input_tokens": 100, "output_tokens": 5})

        with mock.patch.dict(os.environ, {"CODEX_HOME": str(home)}):
            row = llm_usage.extract_usage(str(raw), backend="codex")

        self.assertEqual(row["tokens"]["input"], 100)
        self.assertTrue(kept.exists(), "an unused rollout is evidence, not litter")

    def test_unreadable_rollout_is_not_silently_consumed(self) -> None:
        raw = self.fixture("codex-bad-rollout.raw", [
            {"type": "thread.started", "thread_id": "thread-x"},
        ])
        home = self.root / "codex-home-bad"
        bad = self.rollout(home, "thread-x")   # no token_count events at all
        bad.write_text("not json at all\n", encoding="utf-8")

        with mock.patch.dict(os.environ, {"CODEX_HOME": str(home)}):
            row = llm_usage.extract_usage(str(raw), backend="codex")

        self.assertEqual(sum(row["tokens"].values()), 0)
        self.assertTrue(bad.exists(), "a rollout we could not read is left in place")

    def test_missing_codex_rollout_leaves_the_session_unknown(self) -> None:
        raw = self.fixture("codex-norollout.raw", [
            {"type": "thread.started", "thread_id": "thread-d"},
            {"type": "item.completed", "item": {"type": "command_execution"}},
        ])
        with mock.patch.dict(os.environ, {"CODEX_HOME": str(self.root / "absent")}):
            row = llm_usage.extract_usage(str(raw), backend="codex")
        self.assertEqual(row["tokens"]["input"], 0)
        self.assertFalse(llm_usage.usage_is_complete(row, 0))

    def test_nonterminal_counters_are_a_floor_not_a_measurement(self) -> None:
        # One turn's counters standing in for a whole session can undercount
        # by orders of magnitude; reporting that as measured publishes it as
        # an exact total.
        raw = self.fixture("gemini-partial.raw", [
            {"type": "message", "usage": {"input_tokens": 10, "output_tokens": 1}},
            {"type": "message", "usage": {"input_tokens": 20, "output_tokens": 3}},
        ])
        row = llm_usage.extract_usage(str(raw), backend="gemini")
        self.assertEqual(row["tokens"]["input"], 20)
        self.assertTrue(row["estimated"], "partial coverage is not a measurement")

    def test_codex_flags_persist_the_rollout_but_not_prompt_history(self) -> None:
        import llm_invoke

        for flags in (llm_invoke.agent_flags("codex", max_turns=0),
                      llm_invoke.decide_flags("codex")):
            self.assertNotIn("--ephemeral", flags, "the rollout is the usage source")
            self.assertIn('history.persistence="none"', flags)

    def test_terminal_model_usage_still_wins_over_per_request_sum(self) -> None:
        raw = self.fixture("complete.raw", [
            {"type": "assistant", "message": {
                "id": "msg_1", "content": [],
                "usage": {"cache_read_input_tokens": 10, "output_tokens": 1}}},
            {"type": "result", "modelUsage": {"claude-opus": {
                "inputTokens": 5, "cacheCreationInputTokens": 6,
                "cacheReadInputTokens": 10, "outputTokens": 1}}},
        ])
        row = llm_usage.extract_usage(str(raw), backend="claude")
        self.assertEqual(row["tokens"]["cached_input"], 10)
        self.assertEqual(row["tokens"]["cache_creation"], 6)

    def test_malformed_native_counters_fail_open(self) -> None:
        raw = self.fixture("malformed.raw", [{
            "type": "result", "total_cost_usd": float("inf"),
            "usage": {
                "input_tokens": float("inf"), "prompt_tokens": 7,
                "output_tokens": -5, "completion_tokens": 9,
                "cache_read_input_tokens": True, "total_cached_tokens": 3,
                "cache_creation_input_tokens": float("nan"),
                "cache_write_input_tokens": 4,
                "cache_creation": {"ephemeral_1h_input_tokens": -1},
            },
        }])
        row = llm_usage.extract_usage(str(raw), backend="claude")
        self.assertEqual(
            row["tokens"],
            {"input": 7, "cached_input": 3, "cache_creation": 4,
             "cache_creation_1h": 0, "output": 9},
        )
        self.assertNotIn("cost_usd", row)
        self.assertTrue(llm_usage.usage_is_complete(row, 0))
        self.assertFalse(llm_usage.usage_is_complete({
            "tokens": {"input": float("inf"), "output": -1},
        }, 0))
        self.assertFalse(llm_usage.usage_is_complete({"tokens": []}, 0))


class ServedModelTests(unittest.TestCase):
    """A CLI that answers a wrong --model with a cheerful success."""

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="served-model-")
        self.root = Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write(self, name: str, rows: list) -> Path:
        path = self.root / name
        path.write_text(
            "".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8"
        )
        return path

    def test_substitution_is_reported_with_the_model_that_actually_ran(self) -> None:
        raw = self.write("gemini.raw", [{"type": "result", "stats": {
            "models": {
                "gemini-3.5-flash": {"total_tokens": 10_099_986},
                "gemini-3-flash-preview": {"total_tokens": 69_625},
            },
        }}])
        self.assertEqual(
            llm_usage.served_models(raw),
            {"gemini-3.5-flash": 10_099_986, "gemini-3-flash-preview": 69_625},
        )
        # The busiest served model, so the operator message names what ran.
        self.assertEqual(
            llm_usage.substituted_model(raw, "gemini-3.7-flash"),
            "gemini-3.5-flash",
        )

    def test_the_requested_model_doing_the_work_is_not_substitution(self) -> None:
        raw = self.write("ok.raw", [{"type": "result", "stats": {"models": {
            "gemini-3.7-flash": {"total_tokens": 42},
        }}}])
        self.assertEqual(llm_usage.substituted_model(raw, "gemini-3.7-flash"), "")

    def test_a_token_of_the_requested_model_does_not_excuse_the_rest(self) -> None:
        # "Did the requested model appear at all?" waves through a row whose
        # traffic is almost entirely another model's, priced at the requested
        # model's rate.
        raw = self.write("mixed.raw", [{"type": "result", "stats": {"models": {
            "gemini-3.7-flash": {"total_tokens": 1},
            "gemini-3.5-flash": {"total_tokens": 1_000_000},
        }}}])
        self.assertEqual(
            llm_usage.substituted_model(raw, "gemini-3.7-flash"), "gemini-3.5-flash"
        )

    def test_a_small_helper_model_beside_the_requested_one_is_healthy(self) -> None:
        # Claude Code bills a helper model in modelUsage next to the one it was
        # asked for, and this harness prices those rows. Refusing every session
        # that shows a second model would reject healthy runs.
        raw = self.write("helper.raw", [{"modelUsage": {
            "claude-opus-5": {"inputTokens": 900_000},
            "claude-haiku-4-5": {"inputTokens": 500},
        }}])
        self.assertEqual(llm_usage.substituted_model(raw, "claude-opus-5"), "")

    def test_served_totals_count_tokens_not_the_blocks_constants(self) -> None:
        # Claude Code reports contextWindow and maxOutputTokens beside the
        # counters; summed in, a 200k constant outranked every real token and
        # the model preflight refused a healthy session as substituted.
        raw = self.write("constants.raw", [{"type": "result", "modelUsage": {
            "claude-opus-5": {
                "inputTokens": 3, "outputTokens": 60,
                "cacheCreationInputTokens": 18_000, "costUSD": 0.1,
                "contextWindow": 200_000, "maxOutputTokens": 32_000,
            },
            "claude-haiku-4-5": {
                "inputTokens": 400, "outputTokens": 40, "costUSD": 0.001,
                "contextWindow": 200_000, "maxOutputTokens": 64_000,
            },
        }}])
        self.assertEqual(
            llm_usage.served_models(raw),
            {"claude-opus-5": 18_063, "claude-haiku-4-5": 440},
        )
        self.assertEqual(llm_usage.substituted_model(raw, "claude-opus-5"), "")

    def test_a_dated_snapshot_of_the_requested_model_is_not_substitution(self) -> None:
        raw = self.write("dated.raw", [
            {"modelUsage": {"claude-opus-5-20260101": {"inputTokens": 10}}},
        ])
        self.assertEqual(llm_usage.substituted_model(raw, "claude-opus-5"), "")

    def test_a_cli_reporting_no_served_model_falls_open(self) -> None:
        # Absence of telemetry is not evidence of substitution; oss reports
        # none, and refusing every oss run would be a worse failure.
        raw = self.write("quiet.raw", [{"type": "step_finish", "tokens": {"input": 5}}])
        self.assertEqual(llm_usage.served_models(raw), {})
        self.assertEqual(llm_usage.substituted_model(raw, "opencode/x-free"), "")

    def test_a_cache_ttl_decoration_is_the_same_model(self) -> None:
        # Claude Code keys modelUsage by model plus billed cache TTL, so a
        # 1h-cache session reports claude-opus-5[1m]. Reading that as a
        # substitution would refuse every such run.
        raw = self.write("ttl.raw", [
            {"modelUsage": {"claude-opus-5[1m]": {"inputTokens": 2, "outputTokens": 9}}},
        ])
        self.assertEqual(llm_usage.substituted_model(raw, "claude-opus-5"), "")

    def test_only_a_ttl_shaped_bracket_is_treated_as_decoration(self) -> None:
        raw = self.write("bracket.raw", [
            {"modelUsage": {"claude-opus-5[other]": {"inputTokens": 10}}},
        ])
        self.assertEqual(
            llm_usage.substituted_model(raw, "claude-opus-5"), "claude-opus-5[other]"
        )

    def test_a_sibling_model_is_still_a_substitution(self) -> None:
        # The decoration is stripped exactly, never as an arbitrary suffix:
        # flash and flash-lite are different models at different prices.
        raw = self.write("lite.raw", [{"type": "result", "stats": {"models": {
            "gemini-3.5-flash-lite": {"total_tokens": 40},
        }}}])
        self.assertEqual(
            llm_usage.substituted_model(raw, "gemini-3.5-flash"),
            "gemini-3.5-flash-lite",
        )

    def test_a_models_object_in_tool_output_is_not_billing_telemetry(self) -> None:
        # An agent that curls an API returning its own "models" object must not
        # be read as the provider substituting a model and killing the run.
        raw = self.write("toolout.raw", [{"type": "tool_use", "part": {"state": {
            "output": json.dumps({"models": {"someone-elses-model": {"total_tokens": 999}}}),
        }}}])
        self.assertEqual(llm_usage.served_models(raw), {})
        self.assertEqual(llm_usage.substituted_model(raw, "gemini-3.7-flash"), "")

    def test_a_zero_token_model_entry_is_not_a_served_model(self) -> None:
        raw = self.write("zero.raw", [{"type": "result", "stats": {"models": {
            "gemini-3.7-flash": {"total_tokens": 0},
            "gemini-3.5-flash": {"total_tokens": 900},
        }}}])
        self.assertEqual(
            llm_usage.substituted_model(raw, "gemini-3.7-flash"), "gemini-3.5-flash"
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
