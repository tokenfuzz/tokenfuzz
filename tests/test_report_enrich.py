#!/usr/bin/env python3
"""Report enrichment and enriched Markdown rendering regressions."""

from __future__ import annotations

import hashlib
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
ENRICH = ROOT / "bin" / "enrich-report"
RENDER = ROOT / "bin" / "render-md"
sys.path.insert(0, str(ROOT / "lib"))

import report_enrich


class ReportEnrichTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="report-enrich-")
        self.root = Path(self.temporary.name)
        self.source = self.root / "src"
        source = self.source / "lib" / "parser.c"
        source.parent.mkdir(parents=True)
        source.write_text(
            '#include "parser.h"\n\n'
            "int parse_header(const char *buf, size_t len) {\n"
            "    if (len < 4) {\n        return -1;\n    }\n"
            "    /* input-shaped read */\n"
            "    size_t off = buf[len - 1];\n    return (int) off;\n}\n\n"
            "void emit(int v) {\n    printf(\"%d\\n\", v);\n}\n",
            encoding="utf-8",
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def enrich(self, *reports: Path, source: Path | None = None, upstream: str = "", revision: str = ""):
        command = [sys.executable, str(ENRICH), "--quiet"]
        if source is not None:
            command += ["--source-root", str(source)]
        if upstream:
            command += ["--upstream-url", upstream]
        if revision:
            command += ["--pinned-rev", revision]
        command += [str(report) for report in reports]
        return subprocess.run(command, capture_output=True, text=True, check=False)

    @staticmethod
    def patch(directory: Path) -> None:
        (directory / "patch.diff").write_text(
            "diff --git a/lib/parser.c b/lib/parser.c\n"
            "--- a/lib/parser.c\n+++ b/lib/parser.c\n@@ -1,5 +1,5 @@\n"
            " int parse_header(const char *buf, size_t len) {\n"
            "-    if (len < 4) {\n+    if (len == 0 || len < 4) {\n"
            "         return -1;\n     }\n",
            encoding="utf-8",
        )

    def test_full_enrichment_rendering_and_idempotency(self) -> None:
        crash = self.root / "crashes" / "CRASH-001"
        crash.mkdir(parents=True)
        report = crash / "report.md"
        report.write_text(
            """# CRASH-001: parse_header reads past buffer

## Summary
parse_header reads buf[len-1] without enforcing len > 0.

## Classification
- **Severity**: High (CVSS-BTE 4.0: 8.1 High; CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:H/VI:N/VA:L/SC:N/SI:N/SA:N/E:P/CR:M/IR:M/AR:M; primitive=heap READ; surface=library)
- **Type**: Bounds Issue
- **Location**: lib/parser.c:9
- **Confidence**: High

## Trigger Surface
Surface: library
Boundary: caller-supplied byte buffer to parse_header
Caller controls: buf pointer and len
Trusted caller actions: call parse_header(buf, len) with len matching buf size
Caller contract: obeyed
Trigger source: bytes

## Reproduction
- Reproducer: testcase.c
- Command: ./reproduce.sh
- Result: ASan reports heap-buffer-overflow on read of 1 byte

## Expected sanitizer output
```
==12345==ERROR: AddressSanitizer: heap-buffer-overflow on address 0xdeadbeef
READ of size 1 at 0xdeadbeef thread T0
    #0 0x100000000 in parse_header lib/parser.c:9
    #1 0x100000100 in emit lib/parser.c:14
```

## Data Flow Trace
- entry: `caller` (lib/parser.c:3) — passes buf and len
- step: `parse_header` (lib/parser.c:4) — checks len < 4 only
- affected: `parse_header` (lib/parser.c:9) — reads buf[len-1]

## Patch
Agent-inlined narrative that must be replaced by the sibling diff.
""",
            encoding="utf-8",
        )
        self.patch(crash)
        (crash / "sanitizer.txt").write_text(
            "==12345==ERROR: AddressSanitizer: heap-buffer-overflow\n"
            "    #0 0x1 in parse_header lib/parser.c:9\n"
            "    #1 0x2 in emit lib/parser.c:14\n",
            encoding="utf-8",
        )
        process = self.enrich(
            report, source=self.source, upstream="https://github.com/acme/widgets",
            revision="abcdef1234567890",
        )
        self.assertEqual(process.returncode, 0, process.stderr)
        text = report.read_text(encoding="utf-8")
        for required in (
            "enrich:patch-diff", "len == 0 || len < 4", "**Captured patch**",
            "enrich:data-flow-snippets", "buf[len - 1]", "▶",
            "enrich:asan-snippets", "parse_header", "enrich:severity-badge",
            "Severity: High", "enrich:tldr", "Reviewer TL;DR", "abcdef123456",
            "blob/abcdef1234567890/lib/parser.c",
        ):
            self.assertIn(required, text)
        self.assertNotIn("Agent-inlined narrative", text)
        self.assertEqual(len(re.findall(r"^## Patch\b", text, re.MULTILINE)), 1)
        before = hashlib.sha1(report.read_bytes()).digest()
        process = self.enrich(
            report, source=self.source, upstream="https://github.com/acme/widgets",
            revision="abcdef1234567890",
        )
        self.assertEqual(process.returncode, 0, process.stderr)
        self.assertEqual(hashlib.sha1(report.read_bytes()).digest(), before)
        self.assertEqual(report.read_text().count("enrich:patch-diff"), 2)

        html = crash / "report.html"
        rendered = subprocess.run(
            [sys.executable, str(RENDER), str(report), "--html", str(html),
             "--title", "CRASH-001", "--no-pad"],
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(rendered.returncode, 0, rendered.stderr)
        html_text = html.read_text(encoding="utf-8")
        self.assertNotIn("enrich:tldr", html_text)
        self.assertNotIn("Reviewer TL;DR", html_text)
        self.assertIn('class="triage-card sev-High"', html_text)
        self.assertIn('class="sev sev-High">High', html_text)

    def test_heading_styles_placeholder_links_and_audit_patch(self) -> None:
        colon = self.root / "colon" / "report.md"
        colon.parent.mkdir()
        colon.write_text(
            "# Colon labels\n\nSummary:\nA parser issue.\n\nClassification:\n"
            "- **Severity**: High\n\nData Flow:\n"
            "- step: parse_header (lib/parser.c:9) — reads buf[len-1]\n"
        )
        self.assertEqual(self.enrich(colon, source=self.source).returncode, 0)
        colon_text = colon.read_text()
        self.assertIn("enrich:data-flow-snippets", colon_text)
        self.assertIn("buf[len - 1]", colon_text)

        placeholder = self.root / "placeholder" / "report.md"
        placeholder.parent.mkdir()
        placeholder.write_text(
            "# Placeholder upstream\n\nData Flow:\n"
            "- step: parse_header (lib/parser.c:9) — reads buf[len-1]\n"
        )
        process = self.enrich(
            placeholder, source=self.source, upstream="FILL_ME", revision="norev"
        )
        self.assertEqual(process.returncode, 0, process.stderr)
        placeholder_text = placeholder.read_text()
        self.assertIn("buf[len - 1]", placeholder_text)
        self.assertNotIn("View at", placeholder_text)
        self.assertNotIn("blob/norev", placeholder_text)

        exported = self.root / "exported"
        (exported / ".audit").mkdir(parents=True)
        exported_report = exported / "REPORT.md"
        exported_report.write_text("# Exported\n\n## Summary\nA crash.\n")
        (exported / ".audit" / "patch.diff").write_text(
            "diff --git a/x.c b/x.c\n--- a/x.c\n+++ b/x.c\n@@ -1 +1 @@\n-old\n+new\n"
        )
        self.assertEqual(self.enrich(exported_report).returncode, 0)
        exported_text = exported_report.read_text()
        self.assertIn("enrich:patch-diff", exported_text)
        self.assertRegex(exported_text, r"(?m)^\+new$")
        self.assertRegex(exported_text, r"(?m)^## Patch$")

    def test_patch_placement_fix_reordering_and_sparse_reports(self) -> None:
        cases = {
            "direction": (
                "# Direction\n\n## Summary\nA bug.\n\n## Root Cause\nX.\n\n"
                "## Fix Direction\nValidate input.\n\n## Reproduce\nRun it.\n\n"
                "## Severity rationale\nLocal impact.\n",
                ("## Reproduce", "## Patch", "## Severity rationale"),
            ),
            "fix": (
                "# Fix\n\n## Summary\nA bug.\n\n## Fix\nAdd a check.\n\n"
                "## Reproduce\nRun it.\n\n## Severity rationale\nLocal impact.\n",
                ("## Reproduce", "## Fix", "## Patch", "## Severity rationale"),
            ),
            "sparse": (
                "# Sparse\n\n## Classification\n- **Severity**: Medium\n\n"
                "## Severity rationale\nLocal impact.\n",
                ("## Classification", "## Patch", "## Severity rationale"),
            ),
        }
        for name, (body, order) in cases.items():
            with self.subTest(name=name):
                directory = self.root / name
                directory.mkdir()
                report = directory / "report.md"
                report.write_text(body)
                self.patch(directory)
                self.assertEqual(self.enrich(report).returncode, 0)
                text = report.read_text()
                positions = [text.index(heading) for heading in order]
                self.assertEqual(positions, sorted(positions))
                self.assertEqual(text.count("## Patch\n"), 1)
                if name == "fix":
                    self.assertEqual(len(re.findall(r"(?m)^## Fix$", text)), 1)
                    before = report.read_bytes()
                    self.assertEqual(self.enrich(report).returncode, 0)
                    self.assertEqual(report.read_bytes(), before)

    def test_missing_source_batch_and_empty_structured_fields(self) -> None:
        missing = self.root / "missing" / "report.md"
        missing.parent.mkdir()
        missing.write_text(
            "# Missing source\n\n## Classification\n- **Severity**: Low\n\n"
            "## Data Flow Trace\n- step: `none` (no/such/file.c:42) — unresolved\n"
        )
        process = self.enrich(missing, source=self.root / "does-not-exist")
        self.assertEqual(process.returncode, 0, process.stderr)
        missing_text = missing.read_text()
        self.assertNotIn("enrich:data-flow-snippets", missing_text)
        self.assertIn("Severity: Low", missing_text)

        reports = []
        for name in ("a", "b"):
            directory = self.root / f"multi-{name}"
            directory.mkdir()
            report = directory / "report.md"
            report.write_text(f"# {name.upper()}\n\n## Patch\n\n`patch.diff`\n")
            (directory / "patch.diff").write_text(f"diff --git a/{name} b/{name}\n+line\n")
            reports.append(report)
        self.assertEqual(self.enrich(*reports).returncode, 0)
        for report in reports:
            self.assertIn("+line", report.read_text())

        empty = self.root / "empty" / "report.md"
        empty.parent.mkdir()
        empty.write_text(
            "# Empty fields\n\nBoundary:\nCaller controls:\nTrusted caller actions:\n"
            "Caller contract:\nTrigger source:\n\n## Summary\nConcrete report.\n"
        )
        self.assertEqual(self.enrich(empty).returncode, 0)
        lines = empty.read_text().splitlines()
        for label in (
            "Boundary:", "Caller controls:", "Trusted caller actions:",
            "Caller contract:", "Trigger source:",
        ):
            self.assertIn(label, lines)

    def test_fence_aware_insertion_badges_links_and_anchor_truncation(self) -> None:
        no_h1 = (
            "## Fields\n\n| a | b |\n\n## Reproducer\n\n```\nclang sample.c\n"
            "# -> output\n```\n\n## Impact\n\ntext\n"
        )
        output = report_enrich._insert_after_h1(
            no_h1, report_enrich._wrap_block("tldr", "**TLDR**")
        )
        self.assertLess(output.index("enrich:tldr"), output.index("```"))
        self.assertTrue(output.lstrip().startswith("<!-- enrich:tldr -->"))
        self.assertIsNone(report_enrich._first_h1_outside_fence(no_h1))
        real = "# Real Title\n\nintro\n\n## Repro\n\n```\n# not a heading\n```\n"
        output = report_enrich._insert_after_h1(
            real, report_enrich._wrap_block("tldr", "**TLDR**")
        )
        self.assertLess(output.index("# Real Title"), output.index("enrich:tldr"))
        self.assertLess(output.index("enrich:tldr"), output.index("## Repro"))
        self.assertEqual(
            report_enrich._build_severity_badge(
                "- **Severity**: None (CVSS-BTE 4.0: 0.0 None; primitive=x)"
            ),
            "⚪ **Severity: None**",
        )

        def context(url: str, revision: str) -> report_enrich.EnrichContext:
            return report_enrich.EnrichContext(
                report_path=Path("r.md"), report_dir=Path("."),
                upstream_url=url, pinned_rev=revision,
            )

        self.assertEqual(
            report_enrich._source_url(
                context("https://github.com/acme/widgets", "abcdef1234567890"),
                "lib/parser.c", 9,
            ),
            "https://github.com/acme/widgets/blob/abcdef1234567890/lib/parser.c#L9",
        )
        self.assertIn("/blob/HEAD/", report_enrich._source_url(
            context("https://github.com/acme/widgets", "HEAD"), "lib/parser.c", 9
        ))
        for url, revision in (
            ("FILL_ME", "abcdef12"), ("https://x/y", "norev"),
            ("FILL_ME", "norev"), ("", "abcdef12"), ("https://x/y", ""),
        ):
            self.assertIsNone(report_enrich._source_url(context(url, revision), "x.c", 1))
        short = "guard: f (a.c:1) — small note"
        self.assertEqual(report_enrich._truncate_anchor(short), short)
        long_anchor = "guard: f (a.c:1) — rejects values against `sizeof" + "x" * 100
        truncated = report_enrich._truncate_anchor(long_anchor)
        self.assertTrue(truncated.endswith("…"))
        self.assertEqual(truncated.count("`") % 2, 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
