#!/usr/bin/env python3
"""Fast subprocess smoke test for the complete audit startup chain."""

from __future__ import annotations

import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
import uuid
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent


class AuditStartupTests(unittest.TestCase):
    def test_fake_backend_completes_preflight_and_one_iteration(self) -> None:
        slug = "audit-startup-" + uuid.uuid4().hex
        target = ROOT / "targets" / slug
        output = ROOT / "output" / slug
        temporary = tempfile.TemporaryDirectory(prefix="audit-startup-")
        try:
            target.mkdir(parents=True)
            output.mkdir(parents=True)
            (target / "src").mkdir()
            (target / "src" / "sample.c").write_text(
                "int sample_parse(void) { return 0; }\n", encoding="utf-8"
            )
            (output / "target.toml").write_text(
                'target = "audit-startup"\nis_browser = "0"\n\n'
                '[sanitizer]\nenabled = []\n\n[runner]\n'
                f'bin = "{sys.executable}"\nargs = ["-c", "raise SystemExit(0)"]\n',
                encoding="utf-8",
            )
            work = Path(temporary.name)
            fake_codex = work / "fake-codex"
            trace = work / "fake-codex.trace"
            fake_codex.write_text(
                f"#!{sys.executable}\n"
                "import json, os, sys\n"
                "if sys.argv[1:3] == ['login', 'status']:\n    raise SystemExit(0)\n"
                "prompt = sys.stdin.read()\n"
                "with open(os.environ['FAKE_CODEX_TRACE'], 'a') as stream:\n"
                "    stream.write(' '.join(sys.argv[1:]) + '\\n')\n"
                "events = [\n"
                " {'type':'thread.started','thread_id':'startup-smoke'},\n"
                " {'type':'item.completed','item':{'type':'command_execution','command':'fixture-read','exit_code':0}},\n"
                " {'type':'item.completed','item':{'type':'agent_message','text':'MODEL_PREFLIGHT_OK' if 'MODEL_PREFLIGHT_OK' in prompt else 'done'}},\n"
                " {'type':'turn.completed','usage':{'input_tokens':1,'cached_input_tokens':0,'output_tokens':1}},\n"
                "]\n"
                "for event in events:\n    print(json.dumps(event))\n",
                encoding="utf-8",
            )
            fake_codex.chmod(fake_codex.stat().st_mode | stat.S_IXUSR)
            env = os.environ.copy()
            env.update(
                FAKE_CODEX_TRACE=str(trace), AUDIT_MODEL_PREFLIGHT_ATTEMPTS="1",
                AUDIT_MODEL_PREFLIGHT_TIMEOUT="10", COOLDOWN="0",
                LLM_DECIDE_DISABLE="1", NUM_AGENTS="1",
            )
            proc = subprocess.run(
                [
                    str(ROOT / "bin" / "audit"), "--target", slug,
                    "--backend", "codex", "--model", "fixture-model",
                    "--codex-bin", str(fake_codex), "1",
                ],
                capture_output=True, text=True, env=env,
            )
            log = proc.stdout + proc.stderr
            self.assertEqual(proc.returncode, 0, log[-4000:])
            for expected in (
                "Model preflight passed", "Iteration 1 starting",
                "Agent 1 cold-start finished rc=0",
            ):
                with self.subTest(expected=expected):
                    self.assertIn(expected, log)
            self.assertNotIn("Traceback", log)
            self.assertNotIn("AttributeError", log)
            self.assertEqual(len(trace.read_text(encoding="utf-8").splitlines()), 2)
        finally:
            shutil.rmtree(str(target), ignore_errors=True)
            shutil.rmtree(str(output), ignore_errors=True)
            temporary.cleanup()


if __name__ == "__main__":
    unittest.main(verbosity=2)
