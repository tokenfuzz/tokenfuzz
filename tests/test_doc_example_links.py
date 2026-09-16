#!/usr/bin/env python3
"""The handbook's shipped example pages link only to files the copy serves.

GitHub Pages serves the copy case-sensitively while the pages are generated
and checked on case-insensitive disks, where a link spelled `report.html`
still opens an on-disk `REPORT.html`. Every relative link that reaches a file
must therefore match the file's spelling exactly, and nothing may point at an
absolute or external location that the handbook does not carry.
"""

from __future__ import annotations

import os
import re
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = ROOT / "docs" / "assets" / "examples"
LINK_RE = re.compile(r'(?:href|src)="([^"#?]+)')


def _spelling_of(base: Path, relative: Path) -> str | None:
    """How the disk spells *relative* under *base*, ignoring case: the exact
    relative path when every component exists, None when none matches."""
    current = base
    found: list[str] = []
    for part in relative.parts:
        try:
            names = os.listdir(current)
        except OSError:
            return None
        match = next((n for n in names if n.casefold() == part.casefold()), None)
        if match is None:
            return None
        found.append(match)
        current = current / match
    return "/".join(found)


def link_problems(examples: Path) -> list[str]:
    problems: list[str] = []
    for page in sorted(examples.rglob("*.html")):
        text = page.read_text(encoding="utf-8", errors="replace")
        for match in LINK_RE.finditer(text):
            ref = match.group(1)
            if ref.startswith(("/", "http:", "https:", "file:", "//")):
                problems.append(f"{page.relative_to(examples)}: absolute link {ref}")
                continue
            target = os.path.normpath(page.parent / ref)
            try:
                relative = Path(target).relative_to(examples)
            except ValueError:
                problems.append(f"{page.relative_to(examples)}: {ref} leaves the copy")
                continue
            spelled = _spelling_of(examples, relative)
            if spelled is None:
                continue  # a target the copy deliberately omits
            if spelled != relative.as_posix():
                problems.append(f"{page.relative_to(examples)}: {ref} is spelled {spelled} on disk")
    return problems


class DocExampleLinkTests(unittest.TestCase):
    def test_a_link_in_the_wrong_case_is_a_problem_on_any_disk(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "CRASH-1").mkdir()
            (root / "CRASH-1" / "REPORT.html").write_text("<p>x</p>", encoding="utf-8")
            (root / "index.html").write_text(
                '<a href="CRASH-1/report.html">a</a> <a href="CRASH-1/REPORT.html">b</a> '
                '<a href="missing.html">c</a>', encoding="utf-8")
            self.assertEqual(
                link_problems(root),
                ["index.html: CRASH-1/report.html is spelled CRASH-1/REPORT.html on disk"])

    def test_every_shipped_link_matches_the_target_spelling(self) -> None:
        self.assertTrue(list(EXAMPLES.rglob("*.html")), f"no example pages under {EXAMPLES}")
        problems = link_problems(EXAMPLES)
        self.assertEqual(problems, [], "\n".join(problems[:20]))


if __name__ == "__main__":
    unittest.main(verbosity=2)
