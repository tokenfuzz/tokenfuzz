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
import audit_runner


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
            "S4-differential.md", "S7-fuzz-improvement.md",
        )
        for filename in retired:
            self.assertFalse((STRATEGIES / filename).exists())
        scanned = list(STRATEGIES.glob("*.md")) + list(REFERENCES.glob("*.md")) + [ROOT / "AGENTS.md"]
        pattern = re.compile(
            r"S6-state-machine|S6-cross-browser|S7-cross-browser|S8-fuzz"
            r"|S7-fuzz-improvement")
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
        s7 = self.text("S7-adversarial-input.md")
        for pattern in (
            r"Strategy S7", r"Adversarial", r"Truncation",
            r"Size issue", r"Encoding.*charset", r"Format confusion", r"bin/probe",
            r"one documented parse or\s+decode operation",
            r"runner fixed to another subcommand",
            r"Startup or teardown code",
            r"update-card --card-id <id> --status\s+blocked",
        ):
            self.assertRegex(s7, pattern)
        # Fuzzing moved to S4 wholesale. If any of it comes back here, two
        # strategies own the same method and the rotation stops meaning
        # anything.
        for stale in ("Part B", "fuzz-seeds", "Smart seed generation",
                      "Do NOT run the fuzzer yourself", "artifact_prefix"):
            self.assertNotIn(stale, s7)
        self.assertIn("S4-directed-fuzzing.md", s7)
        self.assertIn("Existing parser fixture mutation", s7)
        self.assertIn("state/lifetime experiments owned by S5", s7)
        self.assertIn("quantified memory or CPU amplification", s7)
        self.assertIn("target's own size ceiling", s7)
        self.assertIn("configured availability boundary", s7)
        self.assertNotIn("Not OOM (which is noise)", s7)

        s3 = self.text("S3-spec-vs-impl.md")
        self.assertIn("path-taking language APIs", s3)
        self.assertIn("filesystem-only or a multiprotocol stream API", s3)
        self.assertIn("command channels", s3)
        self.assertNotIn("Remove waits/syncs", s7)
        self.assertNotIn("Double operations", s7)
        s8 = self.text("S8-property-based.md")
        for pattern in (
            r"Strategy S8", r"Category 1.*Inverse", r"Category 2.*Idempotence",
            r"Category 3.*Injectivity", r"Category 4.*Numerical", r"Category 5.*Format",
            r"generator step", r"Hypothesis", r"proptest|QuickCheck", r"shrink",
            r"PROPERTY:", r"bin/probe",
        ):
            self.assertRegex(s8, pattern)

    def test_readme_agents_and_headings_match_active_strategy_model(self) -> None:
        readme = self.text("README.md")
        agents = (ROOT / "AGENTS.md").read_text(encoding="utf-8")
        self.assertIn("8 active strategies", readme)
        self.assertRegex(readme, r"S4.*Boundary-directed fuzzing")
        self.assertRegex(readme, r"S7.*Adversarial")
        self.assertRegex(readme, r"S8.*Property-based")
        self.assertNotIn("State machine sequences", readme)
        self.assertNotIn("S4: Reserved", readme)
        self.assertIn("8 active strategies", agents)
        self.assertNotIn("S4: Reserved", agents)
        self.assertIn("S4: Boundary-directed fuzzing", agents)
        self.assertIn("S8: Property-based", agents)
        self.assertIn("Strategy S6", self.text("S6-cross-project.md"))
        self.assertIn("Strategy S7", self.text("S7-adversarial-input.md"))
        self.assertIn("Strategy S4", self.text("S4-directed-fuzzing.md"))
        self.assertEqual(prompt._STRATEGIES["S8"][0], "S8-property-based.md")

    def test_s4_grounding_receipt_and_variation_are_bounded_and_non_gating(self) -> None:
        # Matched against one normalised line so a paragraph reflow cannot
        # fail a test that is about the guidance, not the line breaks.
        s4 = " ".join(self.text("S4-directed-fuzzing.md").split())
        for pattern in (
            r"at most two.*local caller",
            r"SOURCE-USAGE", r"CONSTRUCTOR", r"ARG-RELATIONS",
            r"RESOURCE-FLOW", r"TEARDOWN", r"UNRESOLVED",
            r"at most three.*hop",
            r"does not prove.*reachab",
            r"guided harness that saturated",
            r"at most one derivative",
            # The derivative must not become a second campaign inside the
            # iteration the review gate closes.
            r"not a second campaign in this one",
            r"bin/probe --confirm",
        ):
            with self.subTest(pattern=pattern):
                self.assertRegex(s4, pattern)

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
        ):
            self.assertIsNone(matcher.search(text), text)
        self.assertGreaterEqual(weight, 2)

    def test_audit_accepts_s4_and_prompt_brief_exposes_it(self) -> None:
        proc = subprocess.run(
            [str(ROOT / "bin" / "audit"), "--help"], capture_output=True, text=True
        )
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("S1,S2,S3,S4,S5,S6,S7,S8", proc.stdout + proc.stderr)
        self.assertIn("Boundary-directed fuzzing", prompt.strategy_brief("S4", REFERENCES))
        self.assertIn("Property oracle", prompt.strategy_brief("S8", REFERENCES))
        self.assertIn("S4", audit_runner.STRATEGIES)

    def test_s4_is_assignable_from_one_campaign_card_not_per_file(self) -> None:
        """S4 must be assignable without competing for per-file cards.

        A strategy owning no card is never handed to an agent — that is what
        kept S4 dormant. But a card per ranked file would let several agents
        each start the same global campaign over one shared corpus, so its
        supply is exactly one target-level card.
        """
        for reasons, primary in (
            (["input-consumption entrypoint"], "S7"),
            (["remote-peer endpoint"], "S7"),
            (["exported API surface"], "S3"),
        ):
            with self.subTest(reasons=reasons):
                self.assertEqual(workqueue.strategy_for(reasons), primary)
                self.assertNotIn(
                    "S4", workqueue.complementary_strategies(reasons, primary))

    def test_every_strategy_naming_site_agrees_with_the_registry(self) -> None:
        """One registry, or activating a strategy silently misses a validator.

        S4 was assignable, promptable, and documented while both cluster
        extractors still returned "" for it, so it scored zero in every ROI
        table. These are the places that enumerate strategies for a human or
        for the agent; they must not drift from lib/strategies.ACTIVE.
        """
        import strategies
        self.assertEqual(list(audit_runner.STRATEGIES), list(strategies.ACTIVE))
        self.assertEqual(
            [s for s in prompt._STRATEGIES if s != "REF"], list(strategies.ACTIVE))
        for name in (
            REFERENCES / "session-rules.digest.md",
            ROOT / "docs" / "guides" / "triage-results.md",
        ):
            with self.subTest(path=name.name):
                text = name.read_text(encoding="utf-8")
                self.assertIn("|".join(strategies.ACTIVE) + "|REF", text)
        for value in ("S4", "s4", "S4 (boundary-directed fuzzing)"):
            self.assertEqual(strategies.normalize(value), "S4")
        self.assertEqual(strategies.normalize("—"), "")

    def test_s4_classifier_recognises_campaign_evidence_only(self) -> None:
        matcher, weight = workqueue.STRATEGY_KEYWORDS["S4"]
        for text in (
            "wrote a fuzz harness for the parser entry point",
            "libFuzzer campaign reached 4000 new edges",
            "the corpus merge cut it from 900 to 120",
            "harness quarantined as blocked-on-crash",
            "cargo-fuzz target already covers this",
            "coverage-guided run at 90000 exec/s",
        ):
            self.assertIsNotNone(matcher.search(text), text)
        for text in (
            "memcpy bounds issue in this parser", "MOZ_ASSERT failed in release",
            "spec says MUST reject", "truncated the header by one byte",
        ):
            self.assertIsNone(matcher.search(text), text)
        self.assertGreaterEqual(weight, 2)
        # The fuzzing spellings must not also complete an S7 rotation, or a
        # campaign note would retire a strategy the agent never worked.
        s7_matcher, _ = workqueue.STRATEGY_KEYWORDS["S7"]
        for text in ("fuzz seed", "corpus gap", "libFuzzer harness"):
            self.assertIsNone(s7_matcher.search(text), text)


if __name__ == "__main__":
    unittest.main(verbosity=2)
