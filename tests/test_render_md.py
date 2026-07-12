#!/usr/bin/env python3
"""Markdown table normalization and HTML rendering regressions."""

from __future__ import annotations

import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
COMMAND = ROOT / "bin" / "render-md"


class RenderMarkdownTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="render-md-")
        self.root = Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def markdown(self, name: str, body: str) -> Path:
        path = self.root / f"{name}.md"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body, encoding="utf-8")
        return path

    def render(self, *paths: Path, arguments: tuple[str, ...] = ()) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, str(COMMAND), *(str(path) for path in paths), *arguments],
            capture_output=True, text=True, check=False,
        )

    def html(self, path: Path) -> str:
        process = self.render(path, arguments=("--html-sibling",))
        self.assertEqual(process.returncode, 0, process.stderr)
        return path.with_suffix(".html").read_text(encoding="utf-8")

    def test_table_padding_check_mode_and_idempotency(self) -> None:
        document = self.markdown(
            "sample",
            """# Sample

_Auto-generated_

| ID | Score | Note |
|:---|------:|:-----|
| [thing](other.md) | 7 | a short one |
| [really-long-id-here](deep/nested/path/REPORT.md) | 12345 | longer note here |
""",
        )
        self.assertEqual(self.render(document).returncode, 0)
        text = document.read_text()
        self.assertRegex(text, r"(?m)^\| ID +\| ")
        self.assertRegex(text, r"\| +7 \|")
        self.assertIn("# Sample", text)
        self.assertIn("_Auto-generated_", text)
        self.assertIn("[really-long-id-here](deep/nested/path/REPORT.md)", text)
        before = document.read_bytes()
        self.assertEqual(self.render(document).returncode, 0)
        self.assertEqual(document.read_bytes(), before)
        self.assertEqual(self.render(document, arguments=("--check",)).returncode, 0)

        ragged = self.markdown(
            "ragged", "| A | B |\n|:--|:--|\n| really long cell | x |\n"
        )
        before = ragged.read_bytes()
        self.assertNotEqual(self.render(ragged, arguments=("--check",)).returncode, 0)
        self.assertEqual(ragged.read_bytes(), before)

    def test_tables_pills_chips_links_and_content_based_wrapping(self) -> None:
        severity = self.markdown(
            "severity",
            """# Sample

| Severity | Cluster | Surface | Note |
|:---------|:--------|:--------|:-----|
| Critical (CVSS-BTE 4.0: 9.3) | `CL-abc12345` | library-api — sample_parse | [link](other.md) |
| High | `CL-def67890` | cli | x |
| Medium (CVSS-BTE 4.0: 6.5) | `CL-feedface` | maint-tool | y |
| Low | `CL-cafebabe` | unknown | z |
| None (CVSS-BTE 4.0: 0.0) | `CL-0a1b2c3d` | maint-tool | w |

## Some Heading

paragraph
""",
        )
        html = self.html(severity)
        for required in (
            "<!DOCTYPE html>", "<table", 'class="table-wrap"',
            'class="sev sev-Critical">Critical', 'class="sev-score">9.3',
            'class="sev sev-High">High', 'class="sev sev-Medium">Medium',
            'class="sev sev-Low">Low', 'class="sev sev-None">None',
            'class="chip chip-library">library-api', 'class="chip chip-cli">cli',
            'class="chip chip-maint">maint-tool', 'href="other.html"',
            "position: sticky", "white-space: nowrap;", 'id="some-heading"',
            'class="anchor"',
        ):
            self.assertIn(required, html)
        self.assertIn("(other.md)", severity.read_text())

        cluster = self.markdown(
            "cluster",
            """# Crash Clusters

| Severity | Cluster | Root signature |
|:---------|:--------|:---------------|
| Medium (CVSS-BTE 4.0: 6.4) | `CL-f2422e11` | `node_free node.c:100 -> node_free node.c:120 -> node_free node.c:140` |
""",
        )
        cluster_html = self.html(cluster)
        self.assertIn("<code>CL-f2422e11</code>", cluster_html)
        self.assertIn(
            '<code class="wrap">node_free node.c:100 -&gt; node_free node.c:120',
            cluster_html,
        )
        for css in (
            "td code, th code", "td code.wrap, th code.wrap",
            "overflow-wrap: anywhere;", "min-width: 100%;",
        ):
            self.assertIn(css, cluster_html)
        self.assertNotIn("min-width: max-content;", cluster_html)
        self.assertNotIn("th.col-primitive, td.col-primitive", cluster_html)

        signatures = self.markdown(
            "signatures",
            """# Finding Clusters

| Cluster | Signature |
|:--------|:----------|
| `FCL-9a914177` | `frame-length-truncation-overflow` |
| `FCL-1111aaaa` | `src/sampledb.cpp:proj::Store::set_blob` |
| `FCL-2222bbbb` | `abcdef1234567890abcdef1234567890` |
""",
        )
        signature_html = self.html(signatures)
        self.assertIn('<code class="wrap">frame-length-truncation-overflow</code>', signature_html)
        self.assertIn('<code class="wrap">src/sampledb.cpp:proj::Store::set_blob</code>', signature_html)
        self.assertIn("<code>FCL-9a914177</code>", signature_html)
        self.assertIn("<code>abcdef1234567890abcdef1234567890</code>", signature_html)

    def test_lists_and_structured_label_suppression(self) -> None:
        lists = self.markdown(
            "lists",
            """# Lists

Affected files:
- `github.com/foo/bar` :: `src/x.c`
- `github.com/baz/qux` :: `src/y.c`

Steps:
1. apply delta
2. decode bytes
3. dispatch
""",
        )
        html = self.html(lists)
        self.assertIn("<ul><li><code>github.com/foo/bar", html)
        self.assertIn("<ol><li>apply delta", html)
        self.assertNotRegex(html, r"<p>[^<]*- <code>github\.com")

        bare = self.markdown(
            "bare",
            """# Sample

| Field | Value |
|:------|:------|
| Surface | library-api |
| Severity | Medium (CVSS-BTE 4.0: 6.5) |

Surface: library-api
Trigger source: bytes
Caller contract: obeyed
Boundary: serialized sample bytes
Caller controls: bytes
Parameter control: direct
- **Severity**: Medium (CVSS-BTE 4.0: 6.5 Medium; primitive=heap READ)

## Summary

Real prose lives here.
""",
        )
        bare_html = self.html(bare)
        source = bare.read_text()
        self.assertIn("Surface: library-api", source)
        self.assertIn("- **Severity**: Medium", source)
        for duplicate in (
            "Trigger source: bytes", "Parameter control: direct",
            "CVSS-BTE 4.0: 6.5 Medium",
        ):
            self.assertNotIn(duplicate, bare_html)
        self.assertIn("Real prose lives here", bare_html)

        mixed = self.markdown(
            "mixed",
            """# Sample

| Field | Value |
|:------|:------|
| Caller controls | DNS query name |
| Parameter control | mapped |

Caller controls:
DNS query name bytes shape the request.
Parameter control: mapped
""",
        )
        mixed_html = self.html(mixed)
        self.assertIn("DNS query name bytes shape the request", mixed_html)
        self.assertNotIn("Parameter control: mapped", mixed_html)

    def test_triage_hero_enrichment_collapsibles_and_label_sections(self) -> None:
        hero = self.markdown(
            "hero",
            """# CRASH-001

## Fields

| Field | Value |
|:------|:------|
| Primitive | heap-buffer-overflow |
| Severity | High (CVSS-BTE 4.0: 8.1) |
| Surface | library-api — public entry |
| Cluster | CL-deadbeef (3 reports) |
| Reproduction rate | 5/5 |

## Summary
A bug in the sample subsystem causes an out-of-range read.

## Expected sanitizer output
```
==<pid>==ERROR: AddressSanitizer: heap-buffer-overflow
    #0 <addr> in strlen+0x400 (libclang_rt.asan.dylib+0x3ec80)
    #1 <addr> in sample_parse sample.c:42
    #2 <addr> in sample_dispatch dispatch.c:84
    #3 <addr> in sample_entry entry.c:126
    #4 <addr> in main main.c:9
SUMMARY: AddressSanitizer: heap-buffer-overflow sample.c:42 in sample_parse
```

## Severity rationale
Math goes here.
""",
        )
        html = self.html(hero)
        for required in (
            'class="triage-card sev-High"',
            'class="primitive cat-bounds">heap-buffer-overflow',
            'class="frame-func"><code>sample_parse', "sample.c:42",
            "<code>sample_dispatch</code>", "<code>sample_entry</code>",
            "<strong>Repro</strong> 5/5", "CL-deadbeef",
            'class="triage-summary">A bug in the sample subsystem',
            '<details class="collapsible" id="severity-rationale">',
        ):
            self.assertIn(required, html)
        self.assertNotIn('frame-func"><code>strlen', html)
        self.assertNotRegex(html, r'<details[^>]*id="expected-sanitizer-output"')

        enriched = self.markdown(
            "hero-enriched",
            """# CRASH-002

## Fields
| Field | Value |
|:------|:------|
| Primitive | heap-buffer-overflow |
| Severity | High (CVSS-BTE 4.0: 8.1) |

## Summary
<!-- enrich:cluster-siblings -->
**Cluster siblings** (CL-abc123): 2 other reports

- [CRASH-0009](../CRASH-0009/report.html)
<!-- /enrich:cluster-siblings -->

The real headline: an upgrade frees the parser twice.

## Expected sanitizer output
```
==1==ERROR: AddressSanitizer: heap-buffer-overflow
#1 in sample_parse sample.c:42
```
""",
        )
        enriched_html = self.html(enriched)
        self.assertIn('class="triage-summary">The real headline', enriched_html)
        self.assertNotRegex(enriched_html, r"&lt;!--.*enrich")

        labels = self.markdown(
            "labels",
            """# CRASH-LABELS

## Fields
| Field | Value |
|:------|:------|
| Primitive | heap-use-after-free |
| Severity | — |

- **Severity**: Medium (CVSS-BTE 4.0: 6.5 Medium; primitive=use-after-free READ)

Summary:
Duplicating a channel reaches a lifetime diagnostic.

Classification:
Category: lifetime
ASan: heap-use-after-free
Crash site: src/lib/event.c:wake:65

Root Cause:
The duplicate keeps callback data.
""",
        )
        labels_html = self.html(labels)
        for required in (
            'class="triage-card sev-Medium"', '<h2 id="summary">Summary',
            '<h2 id="classification">Classification', '<dl class="report-definition">',
        ):
            self.assertIn(required, labels_html)
        self.assertNotIn("<p>Classification: Category:", labels_html)

        placeholder = self.markdown(
            "placeholder", "# Sample\n\n| Field | Value |\n|:------|:------|\n| Cluster | (set by bin/cluster-crashes) |\n"
        )
        placeholder_html = self.html(placeholder)
        self.assertNotIn("set by bin/cluster-crashes", placeholder_html)
        self.assertRegex(placeholder_html, r'color: var\(--muted\);?">—')

    def test_safe_links_notes_blockquotes_diff_and_thematic_breaks(self) -> None:
        note = self.markdown("note", "# Sample\n\n_Probed at: 2026-05-04T00:00:00Z_\n")
        note_html = self.html(note)
        self.assertIn('<em class="note">Probed at', note_html)
        self.assertNotIn('class=\\"note\\"', note_html)

        schemes = self.markdown(
            "schemes",
            "# Sample\n\nA [bad](javascript:danger), [data](data:text/html;base64,abcd), "
            "[safe](https://example.com/page), [relative](report.md), and [anchor](#summary).\n",
        )
        scheme_html = self.html(schemes)
        self.assertNotRegex(scheme_html.lower(), r'href="(?:javascript|data):')
        self.assertIn("bad", scheme_html)
        self.assertIn('href="https://example.com/page"', scheme_html)
        self.assertIn('href="report.html"', scheme_html)
        self.assertIn('href="#summary"', scheme_html)

        quote = self.markdown("quote", "# Quote\n\n> A footnote about the table above.\n")
        quote_html = self.html(quote)
        self.assertIn("<blockquote>A footnote about the table", quote_html)
        self.assertNotIn("<p>&gt;", quote_html)
        self.assertIn("Material 3 Expressive", quote_html)
        self.assertIn("--m3-primary", quote_html)

        diff = self.markdown(
            "diff",
            """# Patch

```diff
--- a/main.c
+++ b/main.c
@@ -1,3 +1,3 @@
 ctx
-old
+new
```
""",
        )
        diff_html = self.html(diff)
        for required in (
            '<code class="language-diff">', '<span class="da">+new</span>',
            '<span class="dr">-old</span>', '<span class="dx">@@ -1,3 +1,3 @@</span>',
            '<span class="dh">--- a/main.c</span>', "code.language-diff .da",
        ):
            self.assertIn(required, diff_html)

        thematic = self.markdown("thematic", "First paragraph\n\n---\n\nSecond paragraph\n")
        thematic_html = self.html(thematic)
        self.assertIn("<hr>", thematic_html)
        self.assertNotIn("<p>---</p>", thematic_html)
        self.assertNotIn("<hr>", diff_html)

    def test_no_h1_empty_heading_and_multi_file_batch(self) -> None:
        no_h1 = self.markdown(
            "no-h1",
            """## Classification
- **Severity**: Medium (CVSS-BTE 4.0: 6.5 Medium; primitive=use-after-free READ)

## Fields
| Field | Value |
|:------|:------|
| Severity | Medium (CVSS-BTE 4.0: 6.5) |
| Primitive | heap_write |
| Surface | library-api — sampletool |

## Summary
A lifetime issue occurs in sample_resolve_entry.
""",
        )
        html = self.html(no_h1)
        self.assertIn('class="triage-card sev-Medium"', html)
        self.assertIn('class="primitive', html)
        self.assertLess(html.index("triage-card"), html.index('id="classification"'))

        empty = self.markdown(
            "empty-heading",
            """## Classification

## Fields
| Field | Value |
|:------|:------|
| Severity | Medium (CVSS-BTE 4.0: 6.5) |
| Primitive | heap_write |

- **Severity**: Medium (CVSS-BTE 4.0: 6.5 Medium; primitive=use-after-free READ)
Boundary: sample public API

# Summary
A lifetime issue.

# Classification
Memory Safety
""",
        )
        empty_html = self.html(empty)
        self.assertNotIn('id="classification"', empty_html)
        self.assertIn('id="fields"', empty_html)
        self.assertEqual(len(re.findall(r"<h[123][^>]*>Classification", empty_html)), 1)
        self.assertIn("<h1>Summary</h1>", empty_html)

        plain = self.markdown("plain", "## Index\nSome links and prose, no severity or primitive.\n")
        self.assertNotIn('<div class="triage-card', self.html(plain))

        first = self.markdown("FIND-001/report", "# Alpha\n\ntext\n")
        second = self.markdown("FIND-002/report", "# Beta\n\ntext\n")
        process = self.render(first, second, arguments=("--html-sibling", "--title-from", "parent"))
        self.assertEqual(process.returncode, 0, process.stderr)
        self.assertIn("<title>FIND-001</title>", first.with_suffix(".html").read_text())
        self.assertIn("<title>FIND-002</title>", second.with_suffix(".html").read_text())
        self.assertNotEqual(self.render(first, second, arguments=("--title", "X")).returncode, 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
