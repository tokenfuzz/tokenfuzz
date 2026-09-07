#!/usr/bin/env python3
"""Public audit CLI contract: help, required target, rejected arguments."""

from __future__ import annotations

import io
import sys
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tests"))
sys.path.insert(0, str(ROOT / "lib"))

import audit_runner
from python_test_helpers import invoke_main


def run_main(*arguments: str) -> tuple[int, str]:
    output = io.StringIO()
    with redirect_stdout(output), redirect_stderr(output):
        code = invoke_main(audit_runner.main, arguments, argv0=str(ROOT / "bin" / "audit"))
    return code, output.getvalue()


class AuditCliTests(unittest.TestCase):
    def test_bare_launch_prints_help_instead_of_auditing_a_default_target(self) -> None:
        code, output = run_main()
        self.assertEqual(code, 2, output)
        self.assertIn("usage: audit", output)
        self.assertIn("--target-path", output)
        self.assertNotIn("FATAL", output)

    def test_every_option_documents_itself(self) -> None:
        for action in audit_runner.build_parser()._actions:
            with self.subTest(option=action.dest):
                self.assertTrue(action.help, f"{action.dest} has no help text")

    def test_rejected_arguments_name_the_problem(self) -> None:
        cases = (
            (("--backend", "codex"), "one of --target or --target-path is required"),
            (("--target", "sample", "-1"), "must be >= 0"),
            (("--target", "sample", "--strategy", "S9"), "invalid choice"),
            (("--target", "sample", "--new-target"), "unrecognized arguments"),
        )
        for arguments, expected in cases:
            with self.subTest(arguments=arguments):
                code, output = run_main(*arguments)
                self.assertEqual(code, 2, output)
                self.assertIn(expected, output)


if __name__ == "__main__":
    unittest.main()
