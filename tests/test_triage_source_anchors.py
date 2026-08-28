#!/usr/bin/env python3
"""Deterministic verification of LLM source citations."""

from __future__ import annotations

import hashlib
import tempfile
import unittest
from pathlib import Path

import sys

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "lib"))

import triage_validate  # noqa: E402


class SourceAnchorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="source-anchors-")
        self.root = Path(self.temporary.name)
        self.excerpt = "if (length > capacity) return ERROR;"
        source = self.root / "src" / "sample.c"
        source.parent.mkdir()
        source.write_text(
            "int app_parse(void) {\n"
            f"  {self.excerpt}\n"
            "}\n",
            encoding="utf-8",
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def anchor(self, **changes) -> dict:
        value = {
            "path": "src/sample.c",
            "line": 2,
            "symbol": "app_parse",
            "kind": "source",
            "excerpt": self.excerpt,
            "excerpt_sha256": hashlib.sha256(self.excerpt.encode()).hexdigest(),
        }
        value.update(changes)
        return value

    def test_exact_source_anchor_verifies(self) -> None:
        self.assertEqual(
            triage_validate.verify_source_anchors([self.anchor()], self.root),
            [self.anchor()],
        )

    def test_wrong_line_hash_and_path_escape_fail_closed(self) -> None:
        for anchor in (
            self.anchor(line=1),
            self.anchor(excerpt="different source line"),
            self.anchor(path="../outside.c"),
            self.anchor(kind="unknown"),
            self.anchor(symbol="missing_symbol"),
        ):
            with self.subTest(anchor=anchor):
                self.assertEqual(
                    triage_validate.verify_source_anchors([anchor], self.root),
                    [],
                )

    def test_harness_computes_the_excerpt_digest(self) -> None:
        anchor = self.anchor(excerpt_sha256="not supplied by reviewer")
        verified = triage_validate.verify_source_anchors([anchor], self.root)
        self.assertEqual(
            verified[0]["excerpt_sha256"],
            hashlib.sha256(self.excerpt.encode()).hexdigest(),
        )

    def test_qualified_symbol_accepts_its_source_spelled_leaf(self) -> None:
        anchor = self.anchor(symbol="sample::Parser.app_parse")
        self.assertEqual(
            triage_validate.verify_source_anchors([anchor], self.root),
            [anchor],
        )

    def test_review_facts_accept_only_generic_enumerated_values(self) -> None:
        self.assertEqual(
            triage_validate.source_review_facts({
                "vulnerable_boundary_surface": " File-Format ",
                "reproducer_carrier": "CLI",
                "rejection_kind": "Consequence-Disproved",
                "target_specific_detail": "ignored",
            }),
            {
                "vulnerable_boundary_surface": "file-format",
                "reproducer_carrier": "cli",
                "rejection_kind": "consequence-disproved",
            },
        )
        self.assertEqual(
            triage_validate.source_review_facts({
                "vulnerable_boundary_surface": "custom-parser",
                "reproducer_carrier": "special-wrapper",
            }),
            {},
        )


if __name__ == "__main__":
    unittest.main()
