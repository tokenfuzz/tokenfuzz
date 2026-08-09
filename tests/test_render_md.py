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

    def test_fields_grid_glosses_harness_vocabulary(self) -> None:
        fields = self.markdown(
            "fields",
            """# CRASH-1

| Field | Value |
|:------|:------|
| Primitive | heap-buffer-overflow |
| Caller contract | unspecified |
| Reviewer note | see thread |
""",
        )
        html = self.html(fields)
        # Known key: definition rides along as a hover gloss, so no report
        # has to spend prose explaining the harness's own vocabulary.
        self.assertIn('<abbr title="The concrete security effect', html)
        self.assertIn("Caller contract</abbr>", html)
        self.assertIn("cursor: help", html)
        # Unknown key renders exactly as before.
        self.assertIn('<td class="left">Reviewer note</td>', html)
        # Value cells are never glossed — only the label column.
        self.assertNotIn('<abbr title="Bug class', html)

    def test_fields_missing_from_the_table_fold_into_it(self) -> None:
        # A bare label the Fields table lacks used to render where it sat —
        # an orphan key/value list at the foot of the page, answering the
        # same questions as the grid at the top. 18% of pooled reports hit
        # this, mostly `Strategy`.
        folded = self.markdown(
            "folded",
            """# CRASH-1

| Field | Value |
|:------|:------|
| Primitive | double-free |

## Summary

prose

Trusted caller actions: reuses the handle after close
Strategy: S5
""",
        )
        html = self.html(folded)
        grid = html.split('class="fields-table"')[1].split("</table>")[0]
        for field in ("Trusted caller actions", "reuses the handle after close",
                      "Strategy", "S5"):
            self.assertIn(field, grid)
        page = html.split("<body>")[1]                # not the stylesheet
        self.assertNotIn("report-definition", page)   # no orphan list
        self.assertEqual(page.count("reuses the handle after close"), 1)

        # A placeholder is an existing-but-empty row, not a populated one.
        # Replace its value rather than displaying two contradictory rows.
        placeholder = self.markdown(
            "placeholder",
            """# CRASH-2

| Field | Value |
|:------|:------|
| Boundary | — |

## Summary

prose

Boundary: caller-supplied sample bytes
""",
        )
        placeholder_grid = self.html(placeholder).split(
            'class="fields-table"'
        )[1].split("</table>")[0]
        self.assertEqual(placeholder_grid.count("Boundary</abbr>"), 1)
        self.assertEqual(placeholder_grid.count("caller-supplied sample bytes"), 1)
        self.assertNotIn(">—<", placeholder_grid)

        # A report the scorer never gave a Fields table gets one built from
        # its own bare labels, rather than a loose key/value list.
        loose = self.markdown(
            "loose",
            "# CRASH-2\n\n## Summary\n\nprose\n\n"
            "Primitive: double-free\n"
            "Trusted caller actions: reuses the handle\nStrategy: S5\n",
        )
        loose_page = self.html(loose).split("<body>")[1]
        loose_grid = loose_page.split('class="fields-table"')[1].split("</table>")[0]
        self.assertIn("reuses the handle", loose_grid)
        self.assertNotIn("report-definition", loose_page)

    def test_every_report_field_lands_in_the_grid_not_beside_it(self) -> None:
        # Field-ness is decided by the run a label sits in, not by a list of
        # label names kept here. A private list went stale against the
        # writers, and report authors add labels of their own, so both kinds
        # rendered beside the grid as an orphan key/value list.
        report = self.markdown(
            "fields",
            """# CRASH-1

Strategy: S3
CARD-ID: WORK-abc123
Entry: `app_parse()` on a caller-supplied buffer

## Fields

| Field | Value |
|:------|:------|
| Primitive | heap-use-after-free |
| Class | memory-safety |

## Summary

prose

## Data Flow

step 1: app_parse (app.c:12) - takes the buffer
step 2: app_free (app.c:44) - releases it

Class: memory-safety
Reproducer carrier: cli
Disclosed content: cross-principal
""",
        )
        page = self.html(report).split("<body>")[1]
        grid, rest = page.split('class="fields-table"')[1].split("</table>", 1)

        # Contract fields the grid lacks, and an author's own label from the
        # same metadata run, are folded into the grid and not left beside it.
        for field, value in (
            ("Entry", "caller-supplied buffer"), ("Reproducer carrier", "cli"),
            ("Disclosed content", "cross-principal"), ("Strategy", "S3"),
        ):
            self.assertIn(field, grid, field)
            self.assertIn(value, grid, field)
            self.assertNotIn(value, rest, field)
        # A bare label the grid already answers is dropped, not repeated.
        self.assertNotIn("memory-safety", rest)
        # A harness-internal id means nothing outside the run that made it —
        # it leaves the page rather than landing in a maintainer's grid.
        for internal in ("CARD-ID", "WORK-abc123"):
            self.assertNotIn(internal, page, internal)

        # Canonical order: the verdict leads, then location, then who can
        # reach it, then verification, then the author's own labels.
        self.assertLess(grid.index("Class"), grid.index("Primitive"))
        self.assertLess(grid.index("Primitive"), grid.index("Entry"))
        self.assertLess(grid.index("Disclosed content"), grid.index("Reproducer carrier"))
        self.assertLess(grid.index("Reproducer carrier"), grid.index("Strategy"))

        # A run of label lines carrying no known field is prose, and stays
        # where the author put it — a Data Flow step list is not metadata.
        self.assertNotIn("step 1", grid)
        self.assertIn("app_parse (app.c:12)", rest)

    def test_a_field_is_hidden_only_where_something_else_shows_it(self) -> None:
        # Suppressing a bare label before its replacement renders is how a
        # field leaves the report entirely. Each case below is a page the
        # grid or hero does NOT cover, so the value has to survive.
        bare = self.markdown(     # no grid to fold into, no hero to carry it
            "bare", "# FIND-1\n\nBoundary: network request\nStrategy: S3\n",
        )
        bare_page = self.html(bare).split("<body>")[1]
        for value in ("network request", "S3"):
            self.assertIn(value, bare_page, value)

        # Cluster is dropped only when a hero card actually renders it. With
        # no hero, the grid keeps the row rather than losing the value.
        heroless = self.markdown(
            "heroless",
            "# FIND-2\n\n| Field | Value |\n|:--|:--|\n| Boundary | file bytes |\n\n"
            "Cluster: CL-abc (2 reports: FIND-3)\n",
        )
        heroless_page = self.html(heroless).split("<body>")[1]
        self.assertNotIn("triage-card", heroless_page)
        self.assertIn("CL-abc", heroless_page)

        # With a hero card carrying it, the same row leaves the grid — the
        # hero shows it with click-through links to the siblings.
        with_hero = self.markdown(
            "with_hero",
            "# CRASH-7\n\n| Field | Value |\n|:--|:--|\n"
            "| Severity | High (CVSS-BT 4.0: 7.8) |\n"
            "| Primitive | heap-use-after-free |\n"
            "| Cluster | CL-q (2 reports: CRASH-3) |\n\n## Summary\n\nprose\n",
        )
        hero_page = self.html(with_hero).split("<body>")[1]
        hero_card = hero_page.split("</div>")[0]
        self.assertIn("triage-card", hero_card)
        self.assertIn("CL-q", hero_page)
        grid = hero_page.split('class="fields-table"')[1].split("</table>")[0]
        self.assertNotIn("CL-q", grid)

        # Cluster is the ONLY hero-owned label. The dedup signature keeps its
        # row even when the hero shows sanitizer frames: those frames usually
        # describe the same chain but are not the same string, and an exact
        # dedup signature is identity evidence in its own right.
        dedup = self.markdown(
            "dedup",
            "# CRASH-6\n\n| Field | Value |\n|:--|:--|\n"
            "| Severity | High (CVSS-BT 4.0: 7.8) |\n"
            "| Dedup frames | app_parse app.c:91 -> app_free app.c:44 |\n\n"
            "## Expected sanitizer output\n\n```\n"
            "    #0 0x1 in app_parse app.c:91\n    #1 0x2 in app_free app.c:44\n```\n",
        )
        dedup_page = self.html(dedup).split("<body>")[1]
        dedup_grid = dedup_page.split('class="fields-table"')[1].split("</table>")[0]
        self.assertIn("triage-card", dedup_page)     # a hero did render
        self.assertIn("app.c:91", dedup_grid)        # ...and the row stayed

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
            "CVSS-BTE 4.0: 6.5 Medium",
        ):
            self.assertNotIn(duplicate, bare_html)
        # A field the table lacks must stay visible. It is folded into the
        # Fields grid rather than rendered where it sits, so the reader has
        # one place to look; the requirement is that the value survives.
        grid = bare_html.split('class="fields-table"')[1].split("</table>")[0]
        for field, value in (("Trigger source", "bytes"),
                             ("Parameter control", "direct"),
                             ("Boundary", "serialized sample bytes")):
            self.assertIn(field, grid)
            self.assertIn(value, grid)
        self.assertIn("Real prose lives here", bare_html)

        unrelated_table = self.markdown(
            "unrelated-table",
            """# Sample

| Field | Value |
|:------|:------|
| Boundary | unspecified |

| Fact | Value |
|:-----|:------|
| Boundary | internal component |

Boundary: caller-supplied document
""",
        )
        unrelated_html = self.html(unrelated_table)
        self.assertIn("caller-supplied document", unrelated_html)

        # Audit-only metadata is never the "sole copy" a reader needs: the
        # hero card carries the cluster and the dedup key is harness state.
        # Findings carry them as bare labels only, so exposing a bare label
        # that no table row backs must not drag them into the HTML.
        audit_only = self.markdown(
            "audit-only",
            """# Sample

| Field | Value |
|:------|:------|
| Surface | library-api |

Surface: library-api
Cluster: FCL-ab12cd (3 reports: FIND-0001, FIND-0007, FIND-0011)
Dedup key: app_parse:120:heap-buffer-overflow
Reproduction rate: 5/5

## Summary

Real prose lives here.
""",
        )
        audit_only_html = self.html(audit_only)
        for hidden in ("<dt>Cluster</dt>", "<dt>Dedup key</dt>",
                       "<dt>Reproduction rate</dt>"):
            self.assertNotIn(hidden, audit_only_html)
        self.assertIn("Real prose lives here", audit_only_html)

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

        # No hero card renders this report's cluster, so the grid keeps the
        # row — and mutes the placeholder, which reads as broken to a triager.
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
