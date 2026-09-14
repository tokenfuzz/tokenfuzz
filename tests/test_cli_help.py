#!/usr/bin/env python3
"""Behavior tests: operator commands state their defaults and requirements."""

from __future__ import annotations

import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# What --help must say for each command: the defaults an operator has to
# know before the first run, and the requirements the usage line cannot show.
EXPECTED = {
    ("audit",): (
        "(required unless --target-path)",
        "continuously (default: 0)",
        "(default: AUDIT_BACKEND or",
        "(default: True)",
    ),
    ("benchmark",): (
        "(required except with --reset, --regenerate",
        "required for oss",
        "(default: codex)",
        "(default: 3)",
        "(default: 10800)",
        "(default: 4)",
        "(default: model-direct,harness)",
        "under output/ in the repository root (default: benchmark)",
    ),
    ("setup-target",): (
        "omit it to re-inspect an existing checkout",
        "(default: auto)",
        "(default: the clone's default branch",
        "do not pull or fetch",
    ),
    ("fuzz",): (
        "(default: RESULTS_DIR, else walk up",
        "first enabled native sanitizer",
    ),
    ("fuzz", "run"): ("(default: 300)", "(default: 60)"),
    ("state",): ("(default: TARGET_NAME)", "(default: RESULTS_DIR, else derived"),
    ("state", "list-cards"): ("(default: 20)",),
    ("probe",): ("--mode defaults to auto", "the default is one run, or SANITIZER_RUNS"),
    ("export-benchmark",): ("under output/ in the repository root (default: benchmark)", "(default: zip)"),
    ("hits",): ("(default: browser)", "(default: 20)"),
    ("cleanup_state",): ("(default: reset the whole target)", "default: every target under the output root)"),
    ("audit-container-shell",): ("(default: node:lts-bookworm)", "(default: /root/work)"),
    ("rank-work",): ("(default: 80)", "(default: boost)"),
    ("validate-finding",): ("(required unless a batch manifest is supplied)", "(default: 300)"),
}

# Defaults that carry no information and must never reach an operator.
NOISE = ("(default: None)", "(default: )", "(default: False)")


class CliHelpTests(unittest.TestCase):
    def help_text(self, command: str, *verbs: str) -> str:
        process = subprocess.run(
            [sys.executable, str(ROOT / "bin" / command), *verbs, "--help"],
            cwd=ROOT, text=True, capture_output=True, timeout=120, check=False,
        )
        self.assertEqual(process.returncode, 0, process.stdout + process.stderr)
        return process.stdout

    def test_help_states_defaults_and_requirements(self) -> None:
        for (command, *verbs), expected in EXPECTED.items():
            with self.subTest(command=" ".join([command, *verbs])):
                text = self.help_text(command, *verbs)
                for fragment in expected:
                    self.assertIn(fragment, " ".join(text.split()))
                for fragment in NOISE:
                    self.assertNotIn(fragment, text)


if __name__ == "__main__":
    unittest.main()
