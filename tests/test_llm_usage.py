#!/usr/bin/env python3
"""CLI regression coverage for resilient usage extraction."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


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


if __name__ == "__main__":
    unittest.main(verbosity=2)
