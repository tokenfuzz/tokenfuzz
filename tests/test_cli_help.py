#!/usr/bin/env python3
"""Behavior tests: operator commands state their defaults and requirements."""

from __future__ import annotations

import ast
import re
import subprocess
import sys
import unittest
from concurrent.futures import ThreadPoolExecutor
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
    ("rank-work",): ("(default: 80)", "(default: primary)"),
    ("validate-finding",): ("(required unless a batch manifest is supplied)", "(default: 300)"),
}

# Defaults that carry no information and must never reach an operator.
NOISE = ("(default: None)", "(default: )", "(default: False)")

# A command an error message, prompt, agent instruction, or handbook page tells
# someone to run, quoted in backticks.
HINT_SPAN = re.compile(r"`(bin/[a-z][a-z0-9_-]*[^`]*)`")
HINT_FLAG = re.compile(r"--[a-z][a-z0-9-]*")


def command_hints():
    """Yield (location, command text) for every backticked `bin/` command."""
    python_sources = sorted((ROOT / "lib").rglob("*.py")) + [
        path for path in sorted((ROOT / "bin").iterdir())
        if path.is_file() and path.read_bytes().startswith(b"#!/usr/bin/env python")
    ]
    for path in python_sources:
        # Parsed rather than grepped: a message split across f-string lines is
        # one literal here.
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                text = node.value
            elif isinstance(node, ast.JoinedStr):
                text = "".join(
                    part.value if isinstance(part, ast.Constant) else "{}"
                    for part in node.values
                )
            else:
                continue
            for match in HINT_SPAN.finditer(text):
                yield f"{path.relative_to(ROOT)}:{node.lineno}", match.group(1)
    prose = [
        ROOT / "AGENTS.md", ROOT / "README.md",
        *sorted((ROOT / ".agents").rglob("*.md")),
        *sorted((ROOT / "lib" / "prompts").glob("*.j2")),
        *sorted((ROOT / "docs").rglob("*.md")),
    ]
    for path in prose:
        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            for match in HINT_SPAN.finditer(line):
                yield f"{path.relative_to(ROOT)}:{lineno}", match.group(1)


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

    def test_command_hints_name_accepted_flags(self) -> None:
        # A hint naming a flag its command never accepted fails exactly when
        # someone follows it, usually while recovering from another failure.
        hints = []
        for location, span in command_hints():
            words = span.split()
            flags = [
                word.split("=")[0] for word in words[1:]
                if HINT_FLAG.fullmatch(word.split("=")[0])
            ]
            if flags and (ROOT / words[0]).is_file():
                hints.append((location, words, flags))

        def usage(argv: tuple[str, ...]) -> str:
            process = subprocess.run(
                [sys.executable, str(ROOT / argv[0]), *argv[1:], "--help"],
                cwd=ROOT, text=True, capture_output=True, timeout=120, check=False,
            )
            return process.stdout + process.stderr

        with ThreadPoolExecutor(max_workers=8) as pool:
            commands = sorted({(words[0],) for _, words, _ in hints})
            helps = dict(zip(commands, pool.map(usage, commands)))
            # A subcommand is the first word argparse lists as one, so global
            # options may precede it (`bin/state --results-dir DIR resume`).
            listed = {
                command: {
                    name for group in re.findall(r"\{([a-z0-9_,-]+)\}", text)
                    for name in group.split(",")
                }
                for (command,), text in helps.items()
            }
            hints = [
                (location, words, flags,
                 next((word for word in words[1:] if word in listed[words[0]]), None))
                for location, words, flags in hints
            ]
            verbs = sorted({(words[0], verb) for _, words, _, verb in hints if verb})
            helps.update(zip(verbs, pool.map(usage, verbs)))

        self.assertGreater(len(hints), 50, "the scan still finds command hints")
        unaccepted = [
            f"{location}: `{' '.join(words)}` names {flag}"
            for location, words, flags, verb in hints
            for flag in flags
            if not re.search(
                re.escape(flag) + r"(?![A-Za-z0-9-])",
                helps[(words[0],)] + (helps[(words[0], verb)] if verb else ""),
            )
        ]
        self.assertEqual([], unaccepted)

if __name__ == "__main__":
    unittest.main()
