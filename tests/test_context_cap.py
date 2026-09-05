"""The context-size rollover: a session ends once a request's reported prompt
tokens reach CONTEXT_SOFT_CAP, at a completed tool call, marked like a turn cap."""
import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "lib"))

import audit_helpers  # noqa: E402
import audit_runner  # noqa: E402
import llm_invoke  # noqa: E402
import prompt  # noqa: E402


def _assistant(context: int, with_tool: bool = True) -> str:
    content = [{"type": "text", "text": "step"}]
    if with_tool:
        content.append({"type": "tool_use", "name": "Bash", "id": "u"})
    return json.dumps({"type": "assistant", "message": {
        "id": "m", "content": content,
        "usage": {"input_tokens": 3, "cache_creation_input_tokens": 1000,
                  "cache_read_input_tokens": context - 1003},
    }})


def _tool_result() -> str:
    return json.dumps({"type": "user", "message": {"content": [
        {"type": "tool_result", "tool_use_id": "u", "content": "done"},
    ]}})


class ContextTokensTests(unittest.TestCase):
    def test_delta_reports_the_largest_context_in_new_complete_lines(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            raw = Path(tmp) / "session.raw"
            raw.write_text(
                _assistant(50_000) + "\n" + _tool_result() + "\n"
                + json.dumps({"type": "system", "subtype": "init"}) + "\n"
                + _assistant(120_000) + "\n" + "{\"type\": \"assistant\", \"partial",
                encoding="utf-8",
            )
            largest, inflight, offset = audit_helpers.context_tokens_delta(raw, 0)
            self.assertEqual(largest, 120_000)
            # Two dispatches, one result: one tool still running.
            self.assertEqual(inflight, 1)
            # The unfinished last line is not consumed.
            self.assertEqual(offset, len(raw.read_bytes()) - len(b"{\"type\": \"assistant\", \"partial"))
            again, change, offset2 = audit_helpers.context_tokens_delta(raw, offset)
            self.assertEqual((again, change, offset2), (0, 0, offset))

    def test_grok_usage_events_and_tool_updates_are_read(self) -> None:
        # Shapes measured on grok CLI: one `usage` per request, `tool_call`
        # dispatches, `tool_call_update` rows until a terminal status.
        with tempfile.TemporaryDirectory() as tmp:
            raw = Path(tmp) / "grok.raw"
            rows = [
                {"type": "usage", "usage": {"input_tokens": 11733, "output_tokens": 70,
                 "cache_read_input_tokens": 1664, "cache_creation_input_tokens": 0}},
                {"type": "tool_call", "toolCallId": "c1", "status": "pending",
                 "toolName": "run_terminal_command"},
                {"type": "tool_call_update", "toolCallId": "c1", "status": None},
                {"type": "tool_call_update", "toolCallId": "c1", "status": "in_progress"},
            ]
            raw.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")
            largest, inflight, offset = audit_helpers.context_tokens_delta(raw, 0)
            self.assertEqual((largest, inflight), (13397, 1))
            self.assertEqual(audit_helpers.tool_call_delta(raw, 0)[0], 0)
            with raw.open("a", encoding="utf-8") as stream:
                stream.write(json.dumps({"type": "tool_call_update", "toolCallId": "c1",
                                         "status": "completed"}) + "\n")
            _largest, change, _offset = audit_helpers.context_tokens_delta(raw, offset)
            self.assertEqual(change, -1)
            self.assertEqual(audit_helpers.tool_call_delta(raw, 0)[0], 1)

    def test_dialects_without_per_request_usage_report_nothing(self) -> None:
        self.assertEqual(audit_helpers._event_context_tokens(
            {"type": "item.completed", "item": {"type": "command_execution"}}), 0)
        self.assertEqual(audit_helpers._event_context_tokens(
            {"type": "result", "usage": {"input_tokens": 9}}), 0)


class RolloverTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="context-cap-")
        self.root = Path(self.temp.name)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _fake_claude(self, contexts: list[int]) -> Path:
        script = self.root / "fake_claude.py"
        lines = ["import json,time", "steps = %r" % contexts]
        lines += [
            "for ctx in steps:",
            "    print(json.dumps({'type':'assistant','message':{'id':'m','content':[{'type':'text','text':'s'},{'type':'tool_use','name':'Bash','id':'u'}],'usage':{'input_tokens':3,'cache_creation_input_tokens':1000,'cache_read_input_tokens':ctx-1003}}}), flush=True)",
            "    time.sleep(0.3)",
            "    print(json.dumps({'type':'user','message':{'content':[{'type':'tool_result','tool_use_id':'u','content':'done'}]}}), flush=True)",
            "    time.sleep(0.1)",
            "time.sleep(10)",
        ]
        script.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return script

    def test_a_session_past_the_cap_ends_at_the_next_completed_tool_call(self) -> None:
        script = self._fake_claude([40_000, 150_000, 260_000, 270_000])
        raw = self.root / "session.raw"
        started = time.monotonic()
        rc = llm_invoke._run_agent_process(
            [sys.executable, str(script)], None, raw, self.root, os.environ.copy(),
            turn_cap=0, context_cap=200_000,
        )
        text = raw.read_text(encoding="utf-8")
        self.assertEqual(rc, 0)
        self.assertLess(time.monotonic() - started, 8)
        self.assertRegex(text, r"TURN_SOFT_CAP reached at 2[67]0000 context tokens")
        self.assertTrue(llm_invoke.session_turn_capped(raw))
        # It waited for the crossing turn's tool result rather than killing
        # mid-command; the poll cadence decides whether one more landed.
        self.assertGreaterEqual(text.count('"type": "user"'), 3)
        self.assertLess(text.count('"type": "user"'), 5)

    def test_a_tool_dispatched_by_the_over_cap_request_is_never_killed(self) -> None:
        # The reviewer's scenario: an earlier tool completed, then the request
        # that crossed the cap dispatched a slow tool. Killing at the earlier
        # completion lands mid-command; the session must wait for the slow
        # tool's result.
        script = self.root / "slow_tool.py"
        script.write_text(
            "import json,time\n"
            f"print({_assistant(40_000)!r}, flush=True)\n"
            f"print({_tool_result()!r}, flush=True)\n"
            f"print({_assistant(260_000)!r}, flush=True)\n"
            "time.sleep(2.5)\n"
            "open('tool-finished', 'w').write('yes')\n"
            f"print({_tool_result()!r}, flush=True)\n"
            "time.sleep(10)\n",
            encoding="utf-8",
        )
        raw = self.root / "session.raw"
        rc = llm_invoke._run_agent_process(
            [sys.executable, str(script)], None, raw, self.root, os.environ.copy(),
            turn_cap=0, context_cap=200_000,
        )
        self.assertEqual(rc, 0)
        self.assertTrue((self.root / "tool-finished").is_file(), "killed mid-command")
        self.assertTrue(llm_invoke.session_turn_capped(raw))

    def test_a_session_under_the_cap_runs_to_its_natural_end(self) -> None:
        script = self.root / "quick.py"
        script.write_text(
            "import json\n"
            + "print(json.dumps(%s))\n" % repr(json.loads(_assistant(90_000)))
            + "print(json.dumps(%s))\n" % repr(json.loads(_tool_result())),
            encoding="utf-8",
        )
        raw = self.root / "session.raw"
        rc = llm_invoke._run_agent_process(
            [sys.executable, str(script)], None, raw, self.root, os.environ.copy(),
            turn_cap=0, context_cap=200_000,
        )
        self.assertEqual(rc, 0)
        self.assertFalse(llm_invoke.session_turn_capped(raw))

    def test_the_cap_is_armed_only_for_dialects_that_report_usage(self) -> None:
        raw = self.root / "session.raw"
        raw.touch()
        seen = {}

        def fake_process(*_args, **kwargs):
            seen.update(kwargs)
            return 0
        for backend, expected in (("claude", 200_000), ("codex", 0), ("gemini", 0), ("grok", 200_000), ("oss", 0)):
            with mock.patch.object(llm_invoke, "backend_bin", return_value="/bin/true"), \
                 mock.patch.object(llm_invoke, "_run_agent_process", side_effect=fake_process), \
                 mock.patch.object(llm_invoke, "agent_security_problem", return_value=""):
                llm_invoke.run_agent_prompt(
                    backend, "prompt", 0, raw, model="m", max_turns=8,
                    turn_cap=8, context_cap=200_000, cwd=self.root,
                )
            self.assertEqual(seen["context_cap"], expected, backend)

    def test_the_operator_setting_reaches_the_launch_and_the_prompt(self) -> None:
        with mock.patch.dict(os.environ, {"CONTEXT_SOFT_CAP": "150000"}):
            self.assertEqual(audit_runner._context_cap(), 150_000)
        with mock.patch.dict(os.environ):
            os.environ.pop("CONTEXT_SOFT_CAP", None)
            self.assertEqual(audit_runner._context_cap(), 0, "off unless an operator sets it")
        with mock.patch.dict(os.environ, {"CONTEXT_SOFT_CAP": "lots"}):
            with self.assertRaises(ValueError):
                audit_runner._context_cap()
        context = prompt.PromptContext(
            results_dir=self.root / "results", target_root=self.root,
            target_slug="sampleproj", reference_dir=ROOT / ".agents" / "references",
            num_agents=1, context_soft_cap=150_000,
        )
        self.assertIn("150,000 prompt tokens", prompt.turn_budget_section(context))
        context.context_soft_cap = 0
        self.assertNotIn("prompt tokens", prompt.turn_budget_section(context))


if __name__ == "__main__":
    unittest.main()
