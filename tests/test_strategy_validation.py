#!/usr/bin/env python3
"""Strategy registry, classifier, documentation, and runtime wiring checks."""

from __future__ import annotations

import re
import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
REFERENCES = ROOT / ".agents" / "references"
STRATEGIES = REFERENCES / "strategies"
sys.path.insert(0, str(ROOT / "lib"))

import prompt
import workqueue


class StrategyValidationTests(unittest.TestCase):
    def text(self, relative):
        return (STRATEGIES / relative).read_text(encoding="utf-8")

    def test_registry_is_complete_and_every_reference_is_substantive(self) -> None:
        self.assertEqual(
            list(prompt._STRATEGIES),
            ["S1", "S2", "S3", "S4", "S5", "S6", "S7", "S8", "REF"],
        )
        for strategy, (filename, _summary) in prompt._STRATEGIES.items():
            with self.subTest(strategy=strategy, filename=filename):
                path = STRATEGIES / filename
                self.assertTrue(path.is_file())
                self.assertGreater(path.stat().st_size, 100)
        self.assertTrue((STRATEGIES / "README.md").is_file())
        self.assertTrue((REFERENCES / "session-rules.md").is_file())

    def test_agents_and_session_rules_retain_runtime_contract(self) -> None:
        agents = (ROOT / "AGENTS.md").read_text(encoding="utf-8")
        for expected in ("ROLES", "CRITICAL RULES", "STRATEGY", "REPRODUCTION", "CRASH", "FIND", "STATE"):
            self.assertIn(expected, agents)
        rules = (REFERENCES / "session-rules.md").read_text(encoding="utf-8")
        for expected in ("coverage", "testcase", "ASan", "guard"):
            self.assertIn(expected, rules)
        self.assertFalse((REFERENCES / "directory-lookup.md").exists())

    def test_retired_strategy_files_and_references_do_not_return(self) -> None:
        retired = (
            "S6-state-machine.md", "S7-cross-browser.md",
            "S6-cross-browser.md", "S8-fuzz-improvement.md",
        )
        for filename in retired:
            self.assertFalse((STRATEGIES / filename).exists())
        scanned = list(STRATEGIES.glob("*.md")) + list(REFERENCES.glob("*.md")) + [ROOT / "AGENTS.md"]
        pattern = re.compile(r"S6-state-machine|S6-cross-browser|S7-cross-browser|S8-fuzz")
        for path in scanned:
            with self.subTest(path=path.name):
                self.assertIsNone(pattern.search(path.read_text(encoding="utf-8")))

    def test_s5_s7_and_s8_playbooks_cover_their_declared_methods(self) -> None:
        s5 = self.text("S5-reentrancy.md")
        for pattern in (
            r"Class 1.*Re-entrancy", r"Class 2.*Error-Path",
            r"Class 3.*Thread Race", r"Class 4.*State Machine", r"mState",
        ):
            self.assertRegex(s5, pattern)
        s7 = self.text("S7-fuzz-improvement.md")
        for pattern in (
            r"Strategy S7", r"Part A.*Adversarial", r"Part B.*Seed", r"Truncation",
            r"Size issue", r"Encoding.*charset", r"Format confusion", r"bin/probe",
            r"Do NOT run the fuzzer yourself",
        ):
            self.assertRegex(s7, pattern)
        s8 = self.text("S8-property-based.md")
        for pattern in (
            r"Strategy S8", r"Category 1.*Inverse", r"Category 2.*Idempotence",
            r"Category 3.*Injectivity", r"Category 4.*Numerical", r"Category 5.*Format",
            r"generator step", r"Hypothesis", r"proptest|QuickCheck", r"shrink",
            r"PROPERTY:", r"bin/probe",
        ):
            self.assertRegex(s8, pattern)

    def test_readme_agents_and_headings_match_eight_strategy_model(self) -> None:
        readme = self.text("README.md")
        agents = (ROOT / "AGENTS.md").read_text(encoding="utf-8")
        self.assertIn("8 strategies", readme)
        self.assertNotIn("7 strategies ", readme)
        self.assertRegex(readme, r"S7.*Adversarial")
        self.assertRegex(readme, r"S8.*Property-based")
        self.assertNotIn("State machine sequences", readme)
        self.assertIn("8 strategies", agents)
        self.assertIn("S8: Property-based", agents)
        self.assertIn("Strategy S6", self.text("S6-cross-project.md"))
        self.assertIn("Strategy S7", self.text("S7-fuzz-improvement.md"))
        self.assertEqual(prompt._STRATEGIES["S8"][0], "S8-property-based.md")

    def test_s6_playbook_time_query_and_mapping_guidance_are_current(self) -> None:
        s6 = self.text("S6-cross-project.md")
        for pattern in (
            r"3 years", r'since="3 years ago"', r'-d "-1095"', r"\.fixed // empty",
            r"next_page_token", r"page_token", r"(?m)^CUTOFF=", r"select\(\(\.modified",
            r"--name-only", r"Severity fallback", r"database_specific",
            r"peer .* fix .*target", r"cross-listed",
        ):
            with self.subTest(pattern=pattern):
                self.assertRegex(s6, pattern)
        for stale in (
            "6.12 months", "12 months ago", '-d "-365"',
            ".events[]?.fixed][0]", "--stat   # files only",
        ):
            self.assertNotIn(stale, s6)

    @staticmethod
    def split_top_level_alternatives(pattern):
        parts = []
        buffer = []
        parentheses = brackets = 0
        index = 0
        while index < len(pattern):
            character = pattern[index]
            if character == "\\" and index + 1 < len(pattern):
                buffer.append(pattern[index:index + 2])
                index += 2
                continue
            if character == "[": brackets += 1
            elif character == "]": brackets -= 1
            elif character == "(" and brackets == 0: parentheses += 1
            elif character == ")" and brackets == 0: parentheses -= 1
            if character == "|" and parentheses == 0 and brackets == 0:
                parts.append("".join(buffer).strip())
                buffer = []
            else:
                buffer.append(character)
            index += 1
        parts.append("".join(buffer).strip())
        return [part for part in parts if part]

    def test_s6_classifier_matches_generic_evidence_without_false_positives_or_duplicates(self) -> None:
        matcher, weight = workqueue.STRATEGY_KEYWORDS["S6"]
        for text in (
            "found analogue in the X.509 parser", "peer-fix from last year",
            "cross-project mining of the codec", "upstream advisory CVE-2024-12345",
            "same class in another parser", "oss-fuzz issue 12345 references this",
            "peer impl shares the same gap",
        ):
            self.assertIsNotNone(matcher.search(text), text)
        for text in (
            "ordinary memcpy issue in this file", "MOZ_ASSERT failed at runtime",
            "lifetime issue in destructor", "spec compliance question",
            "firefox issue here", "the libressl patch",
        ):
            self.assertIsNone(matcher.search(text), text)
        match = re.match(r"^\\b\(\?:(.*)\)$", matcher.pattern, re.DOTALL)
        self.assertIsNotNone(match)
        alternatives = self.split_top_level_alternatives(match.group(1))
        self.assertEqual(len(alternatives), len(set(alternatives)))
        self.assertEqual(weight, 1)

    def test_s8_classifier_covers_property_categories_without_cross_strategy_noise(self) -> None:
        matcher, weight = workqueue.STRATEGY_KEYWORDS["S8"]
        positive = (
            "round-trip serialization", "decode then encode again",
            "function is idempotent on canonical input", "injective hash over the domain",
            "numerical domain invariant violated", "URL format compliance check",
            "wrote a Hypothesis strategy", "used proptest with a custom shrinker",
            "ran a QuickCheck property", "fixed point not reached",
        )
        for text in positive:
            self.assertIsNotNone(matcher.search(text), text)
        for text in (
            "memcpy bounds issue in this parser", "MOZ_ASSERT failed in release",
            "thread race on the dispatch table", "spec says MUST reject",
            "JIT differential check via ion-eager",
        ):
            self.assertIsNone(matcher.search(text), text)
        self.assertGreaterEqual(weight, 2)

    def test_audit_help_and_prompt_brief_expose_s8(self) -> None:
        proc = subprocess.run(
            [str(ROOT / "bin" / "audit"), "--help"], capture_output=True, text=True
        )
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("S1,S2,S3,S4,S5,S6,S7,S8", proc.stdout + proc.stderr)
        self.assertIn("Property oracle", prompt.strategy_brief("S8", REFERENCES))


if __name__ == "__main__":
    unittest.main(verbosity=2)
