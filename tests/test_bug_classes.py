#!/usr/bin/env python3
"""The canonical bug-class vocabulary and everything that must agree with it."""

from __future__ import annotations

import importlib.machinery
import importlib.util
import re
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "lib"))

import bug_classes  # noqa: E402
import triage  # noqa: E402
from prompt_render import render_template  # noqa: E402


def load_severity():
    loader = importlib.machinery.SourceFileLoader(
        "tokenfuzz_severity_for_classes", str(ROOT / "bin" / "severity")
    )
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    loader.exec_module(module)
    return module


# The bug classes Anthropic Red's disclosure dashboard files findings under
# (https://red.anthropic.com/2026/cvd/data/payload.json, `by_bug_class`, as of
# 2026-08-26). The harness vocabulary is aligned to it by name, so a class
# breakdown here reads on the same axis as the public ledger.
DASHBOARD_BUG_CLASSES = frozenset({
    "arbitrary-file-write", "arbitrary-write", "auth-bypass",
    "broken-access-control", "buffer-overflow", "code-injection",
    "command-injection", "confused-deputy", "cors-misconfig", "crypto-failure",
    "denial-of-service", "deserialization", "double-free",
    "global-buffer-overflow", "heap-buffer-overflow", "idor",
    "improper-cert-validation", "info-disclosure", "integer-overflow",
    "integer-underflow", "logic-error", "null-deref", "off-by-one", "oob-read",
    "oob-write", "open-redirect", "other", "path-traversal",
    "privilege-escalation", "rce", "segv", "session-fixation",
    "signature-bypass", "sql-injection", "ssrf", "stack-buffer-overflow",
    "stack-overflow", "symlink-following", "toctou", "type-confusion",
    "uncaught-exception", "use-after-free", "xss",
})


class VocabularyTests(unittest.TestCase):
    def test_dashboard_vocabulary_is_carried_whole(self) -> None:
        self.assertEqual(set(bug_classes.DASHBOARD_CLASSES), DASHBOARD_BUG_CLASSES)
        self.assertFalse(set(bug_classes.HARNESS_CLASSES) & DASHBOARD_BUG_CLASSES)

    def test_every_class_has_a_family_and_every_alias_resolves(self) -> None:
        for name, family in bug_classes.BUG_CLASSES.items():
            with self.subTest(name=name):
                self.assertIn(family, bug_classes.FAMILIES)
                self.assertEqual(name, bug_classes._token(name), "tokens are kebab-case")
        for alias, target in bug_classes.ALIASES.items():
            with self.subTest(alias=alias):
                self.assertNotIn(alias, bug_classes.BUG_CLASSES, "alias shadows a class")
                self.assertTrue(
                    target in bug_classes.BUG_CLASSES or target in bug_classes.FAMILIES,
                    f"{alias!r} -> {target!r} is neither a class nor a family",
                )
        for label, target in bug_classes._LEGACY_LABELS.items():
            self.assertIn(target, bug_classes.BUG_CLASSES, label)

    def test_canonical_class_resolution(self) -> None:
        for raw, expected in (
            ("heap-buffer-overflow", "heap-buffer-overflow"),
            ("Heap Buffer Overflow", "heap-buffer-overflow"),
            ("`use-after-free`", "use-after-free"),
            ("heap-use-after-free", "use-after-free"),
            ("UAF", "use-after-free"),
            ("SQLI", "sql-injection"),
            ("privesc", "privilege-escalation"),
            ("race-condition", "toctou"),
            ("redos", "denial-of-service"),
            ("memory_leak", "denial-of-service"),
            ("stack-exhaustion", "stack-overflow"),
            ("arbitrary-file-read", "path-traversal"),
            # the legacy prompt's escape hatch: the sub-label decides
            ("other:ssrf", "ssrf"),
            ("other:privilege-escalation", "privilege-escalation"),
            # neutral hypothesis categories
            ("bounds", "buffer-overflow"),
            ("Lifetime", "use-after-free"),
            ("uninit", "uninitialized-read"),
            ("state", "memory-safety"),
            # legacy top:sub labels: the sub-label names the class ...
            ("memory-safety:lifetime", "use-after-free"),
            ("memory-safety:bounds", "buffer-overflow"),
            ("injection:sql", "sql-injection"),
            ("injection:command", "command-injection"),
            ("info-disclosure:xxe", "xxe"),
            ("side-channel:timing", "info-disclosure"),
            ("dos:regex-complexity", "denial-of-service"),
            ("logic:business-rule", "logic-error"),
            # ... unless it names another family: the reviewer's top wins
            ("memory-safety:stack-overflow", "memory-safety"),
            ("dos:null-deref", "denial-of-service"),
            ("info-disclosure:uninit", "info-disclosure"),
            ("crypto:timing", "crypto"),
            # ... or only the top pins a family
            ("auth:bypass", "auth"),
            ("boundary:csp-bypass", "boundary"),
            ("config:permissive-default", "config"),
            ("injection:terminal-escape", "injection"),
            # a traversal whose top says it writes keeps the write
            ("file-write:path-traversal", "arbitrary-file-write"),
            ("integrity:path-traversal", "arbitrary-file-write"),
            ("boundary:context-confusion", "logic-error"),
            # unknown *overflow* is a bounds violation of unspecified region
            ("container-overflow:xyz", "heap-buffer-overflow"),
            ("wibble-overflow", "buffer-overflow"),
            # unknown → other
            ("protocol:request-smuggling", "other"),
            ("supply-chain:dependency-confusion", "other"),
            ("other:weird-thing", "other"),
            ("", "other"),
            (None, "other"),
            ("null", "other"),
        ):
            with self.subTest(raw=raw):
                self.assertEqual(bug_classes.canonical_class(raw), expected)

    def test_family_resolution(self) -> None:
        for raw, expected in (
            ("heap-buffer-overflow", "memory-safety"),
            ("integer-overflow", "memory-safety"),
            ("oob-write", "memory-safety"),
            ("stack-overflow", "dos"),
            ("uncaught-exception", "dos"),
            ("xss", "injection"),
            ("xxe", "injection"),
            ("csrf", "auth"),
            ("privilege-escalation", "auth"),
            ("signature-bypass", "crypto"),
            ("toctou", "race"),
            ("data-race", "race"),
            ("ssrf", "boundary"),
            ("sandbox-escape", "boundary"),
            ("prototype-pollution", "deserialization"),
            ("auth:bypass", "auth"),
            ("state", "memory-safety"),
            ("other", "other"),
            ("", "other"),
        ):
            with self.subTest(raw=raw):
                self.assertEqual(bug_classes.family_of(raw), expected)

    def test_prompt_menu_lists_every_class_once(self) -> None:
        menu = bug_classes.prompt_menu()
        self.assertTrue(menu.endswith("; other"))
        groups = menu[: -len("; other")].split("; ")
        listed: list[str] = ["other"]
        for group in groups:
            family, _, members = group.partition(": ")
            self.assertIn(family, bug_classes.FAMILIES)
            for member in members.split(", "):
                self.assertEqual(bug_classes.BUG_CLASSES[member], family)
                listed.append(member)
        self.assertEqual(sorted(listed), sorted(bug_classes.BUG_CLASSES))


class ConsumerAgreementTests(unittest.TestCase):
    """Every consumer of the vocabulary covers all of it."""

    def test_severity_scores_or_explicitly_reviews_every_class(self) -> None:
        severity = load_severity()
        for name in bug_classes.BUG_CLASSES:
            with self.subTest(name=name):
                self.assertIn(name, severity._CLASS_PRIMITIVES)
                primitive = severity._CLASS_PRIMITIVES[name]
                if primitive:
                    self.assertIn(primitive, severity.CVSS4_CLASS)
        self.assertFalse(
            set(severity._CLASS_PRIMITIVES) - set(bug_classes.BUG_CLASSES),
            "severity maps a class the vocabulary does not define",
        )
        for family, primitive in severity._FAMILY_PRIMITIVES.items():
            self.assertIn(family, bug_classes.FAMILIES)
            self.assertIn(primitive, severity.CVSS4_CLASS)

    def test_reference_page_documents_every_class(self) -> None:
        page = (ROOT / "docs" / "reference" / "bug-classes.md").read_text()
        documented = set(re.findall(r"^\| `([a-z0-9-]+)` \|", page, re.MULTILINE))
        self.assertEqual(documented, set(bug_classes.BUG_CLASSES))
        for name, (_family, why) in bug_classes.HARNESS_CLASSES.items():
            self.assertIn(f"| `{name}` |", page)
        self.assertGreater(len(why), 0)

    def test_prompts_render_the_menu_where_they_ask_for_a_class(self) -> None:
        menu = bug_classes.prompt_menu()
        templates = ROOT / "lib" / "prompts"
        asking = sorted(
            path.name for path in templates.glob("*.md.j2")
            if "bug_class_menu" in path.read_text()
        )
        self.assertEqual(asking, [
            "benchmark_model_direct.md.j2", "find_first_directive.md.j2",
            "triage_find_quality.md.j2",
        ])
        for name in asking:
            rendered = render_template(name, {"bug_class_menu": menu})
            self.assertIn("heap-buffer-overflow", rendered, name)
            self.assertIn("auth-bypass", rendered, name)
        # Every caller that renders one of these passes the menu; a template
        # asking for it and a caller omitting it renders an empty list.
        callers = "".join(
            (ROOT / "lib" / name).read_text()
            for name in ("triage.py", "prompt.py", "benchmark_model_direct_render.py")
        )
        self.assertEqual(callers.count("bug_classes.prompt_menu()"), 4)

    def test_review_queue_lanes_are_canonical_classes(self) -> None:
        # Three spellings of one class share a lane; otherwise one class
        # could occupy three of the rotating slots a partial drain reaches.
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            spellings = {
                "FIND-A": "memory-safety:lifetime",
                "FIND-B": "use-after-free",
                "FIND-C": "heap-use-after-free",
                "FIND-D": "ssrf",
            }
            for name, label in spellings.items():
                directory = root / name
                directory.mkdir()
                (directory / "report.md").write_text(
                    f"| Class | {label} |\nLocation: a.c:f:1\n", encoding="utf-8",
                )
            lanes = {
                triage._finding_review_rank(root / name)[0] for name in spellings
            }
            self.assertEqual(lanes, {"use-after-free", "ssrf"})
            ordered = triage._finding_review_order(
                [root / name for name in sorted(spellings)]
            )
            # Two lanes, so the single ssrf finding is reached in the first
            # rotation rather than after every use-after-free spelling.
            self.assertIn("FIND-D", {path.name for path in ordered[:2]})


if __name__ == "__main__":
    unittest.main(verbosity=2)
