#!/usr/bin/env python3
"""The evidence pages: cluster index, rejected index, and the report shell."""

from __future__ import annotations

import json
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "lib"))

import evidence_pages  # noqa: E402


def _report(directory: Path, name: str, text: str) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / name
    path.write_text(text, encoding="utf-8")
    return path


_FINDING = """# Session token reaches the log line

<!-- enrich:tldr -->
**📋 Reviewer TL;DR**

- **Bug** — The session handler logs the raw token.
- **Trigger** — request header bytes · caller controls the header
- **Fix** — Redact the token before the log call.
<!-- /enrich:tldr -->

Location: app/session.c:app_session_log:91

## Fields

| Field | Value |
| :--- | :--- |
| Class | info-disclosure |
| Severity | High (CVSS-BT 4.0: 7.1) |
| Surface | library-api — public entry point |
| Boundary | request header bytes |
| Caller controls | the header value |
| Strategy | S3 |
| Cluster | FCL-aaaa1111 (2 reports: FIND-0002) |

## Summary

The handler writes the raw token to the log.

## Fix Direction

Redact the token before the log call.
"""

_CRASH = """# CRASH-0001

Location: app/parse.c:app_parse:12

## Fields

| Field | Value |
| :--- | :--- |
| Primitive | heap-buffer-overflow |
| Severity | Medium (CVSS-BTE 4.0: 5.5) |
| Reproduction rate | 3/3 |
| Strategy | S5 |
| Dedup frames | app_parse app/parse.c:12 -> app_read app/read.c:40 -> main harness.c:5 |

## Summary

The parser reads one byte past the record.
"""


class EvidencePagesTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="evidence-pages-")
        self.root = Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def make_run(self) -> Path:
        """A benchmark pool with two conditions on their own clocks."""
        run = self.root / "run"
        for cell, cond, start in (("harness-r1", "harness", "2026-09-05T10:00:00Z"),
                                  ("model-direct-r1", "model-direct", "2026-09-05T04:00:00Z")):
            (run / "cells" / cell).mkdir(parents=True)
            (run / "cells" / cell / "cell.json").write_text(json.dumps({
                "condition": cond, "started_at": start, "wall_seconds": 7200,
            }))
        (run / "target.toml").write_text('target = "sampleproj"\n')
        (run / "pool-members.json").write_text(json.dumps({
            "findings": {"FIND-0001": "harness", "FIND-0002": "model-direct", "FIND-0003": "harness"},
            "findings-rejected": {"FIND-REJECTED-0001": "model-direct"},
        }))
        findings = run / "pool" / "findings"
        one = _report(findings / "FIND-0001", "report.md", _FINDING)
        two = _report(findings / "FIND-0002", "report.md",
                      _FINDING.replace("FIND-0002", "FIND-0001").replace("S3", "S5"))
        three = _report(findings / "FIND-0003", "report.md",
                        _FINDING.replace("app/session.c", "lib/net/dial.c")
                        .replace("High (CVSS-BT 4.0: 7.1)", "Low (CVSS-BT 4.0: 2.0)")
                        .replace("FCL-aaaa1111 (2 reports: FIND-0002)", "FCL-bbbb2222 (singleton)"))
        (one.parent / "severity.json").write_text(json.dumps({
            "level": "High", "score": 7.1,
            "vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N/E:P",
            "scored_at": "2026-09-05T12:30:00+00:00",
        }))
        (one.parent / "validation.json").write_text(json.dumps({
            "state": "reportable", "detail": "source review placed the trigger within bytes",
            "validated_at": 1788698400, "evidence": {"source_attestations": [{}, {}]},
        }))
        rejected = _report(run / "pool" / "findings-rejected" / "FIND-REJECTED-0001", "report.md", _FINDING)
        (rejected.parent / "REJECTION.md").write_text(
            "# Rejected artifact\n\nReason: trigger-provenance: triggering state not attacker-reachable\n")
        return run

    def cluster(self, results: Path) -> Path:
        process = subprocess.run(
            [sys.executable, str(ROOT / "bin" / "cluster-findings"), str(results)],
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(process.returncode, 0, process.stderr)
        return results / "findings" / "FINDING-CLUSTERS.html"

    def test_cluster_page_places_each_condition_on_its_own_clock(self) -> None:
        import benchmark
        run = self.make_run()
        # index maintenance writes the rejected index before it clusters
        benchmark.write_rejected_findings_index(run / "pool" / "findings-rejected")
        page = self.cluster(run / "pool").read_text(encoding="utf-8")
        payload = json.loads(re.search(r'id="page-data">(.*?)</script>', page, re.S).group(1))
        timeline = payload["timeline"]
        self.assertTrue(timeline["per_condition"])
        by_id = {p["id"]: p for p in timeline["points"]}
        self.assertEqual(len(by_id), 2, "two distinct problems: the shared site merges")
        shared = next(p for p in by_id.values() if p["size"] == 2)
        self.assertEqual(sorted(shared["who"]), ["harness", "model-direct"])
        # a merged problem is placed at its earliest report, on that report's own clock;
        # the model-direct cell started six hours earlier, so its clock is the later one
        self.assertIsNotNone(shared["t"])
        self.assertIn("hours into each condition", page.replace("&#x27;", "'"))
        # the who column and filter appear only when the page has more than one side
        self.assertIn('data-filter="who" data-value="harness"', page)
        self.assertIn('class="who who-model-direct"', page)
        self.assertIn('href="FIND-0001/report.html"', page)
        self.assertIn("Session token reaches the log line", page)
        self.assertIn('href="../findings-rejected/REJECTED-FINDINGS.html"', page)
        self.assertNotIn("Reviewer TL;DR", page)
        # lane by class heat table and the subsystem bars come from the same problems
        self.assertIn('class="lane lane-S3"', page)
        self.assertIn("lib/net", page)

    def test_single_side_page_omits_the_who_column(self) -> None:
        results = self.root / "output" / "sampleproj" / "codex" / "results"
        _report(results / "findings" / "FIND-0001", "report.md", _FINDING)
        (results / ".session-env").write_text("SESSION_STARTED=2026-09-05T10:00:00Z\n")
        page = self.cluster(results).read_text(encoding="utf-8")
        self.assertNotIn('data-filter="who"', page)
        self.assertIn("t = 0 is the run start", page)

    def test_rejected_page_groups_by_reason_family(self) -> None:
        import benchmark
        run = self.make_run()
        self.cluster(run / "pool")
        rejected = run / "pool" / "findings-rejected"
        benchmark.write_rejected_findings_index(rejected)
        page = (rejected / "REJECTED-FINDINGS.html").read_text(encoding="utf-8")
        self.assertIn("did not hold up", page)
        # one family draws no filter chip; the family still labels the row
        self.assertNotIn('data-filter="why"', page)
        self.assertIn('class="fam fam-S7">trigger-provenance</span>', page)
        self.assertIn("triggering state not attacker-reachable", page)
        self.assertIn('href="FIND-REJECTED-0001/report.html"', page)
        self.assertIn('href="../findings/FINDING-CLUSTERS.html"', page)
        empty = self.root / "empty-rejected"
        empty.mkdir()
        benchmark.write_rejected_findings_index(empty)
        self.assertIn("Nothing was rejected", (empty / "REJECTED-FINDINGS.html").read_text())

    def test_reason_families(self) -> None:
        self.assertEqual(
            evidence_pages._reason_family(
                "trigger-provenance (2 independent rejects): triggering state not attacker-reachable"),
            ("trigger-provenance", "triggering state not attacker-reachable"))
        self.assertEqual(
            evidence_pages._reason_family("Route names are not authentication; no bypass is shown."),
            ("reviewer verdict", "Route names are not authentication; no bypass is shown."))
        self.assertEqual(evidence_pages._reason_family("—"), ("unrecorded", ""))

    def test_report_shell_carries_action_card_and_rail(self) -> None:
        run = self.make_run()
        self.cluster(run / "pool")
        report = run / "pool" / "findings" / "FIND-0001" / "report.md"
        (report.parent / "patch.diff").write_text("--- a\n+++ b\n")
        process = subprocess.run(
            [sys.executable, str(ROOT / "bin" / "render-md"), str(report), "--html-sibling",
             "--title-from", "parent"],
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(process.returncode, 0, process.stderr)
        page = report.with_suffix(".html").read_text(encoding="utf-8")
        self.assertIn('class="page report"', page)
        self.assertIn("Act on it", page)
        self.assertIn('href="patch.diff"', page)
        self.assertIn("Redact the token before the log call.", page)
        self.assertIn("app/session.c:app_session_log:91", page)
        self.assertIn('title="Attack vector: network"', page)
        self.assertIn("2 source attestations", page)
        self.assertIn('href="../FIND-0002/report.md"', page.replace("report.html", "report.md"))
        self.assertIn('class="who who-harness"', page)
        self.assertIn("&larr; all findings", page.replace("← all findings", "&larr; all findings"))
        # the body's own triage card and the shell never repeat the TL;DR block
        self.assertIn('class="triage-card sev-High"', page)
        self.assertNotIn("Reviewer TL;DR", page)

    def test_rejected_report_shell_leads_with_the_rejection(self) -> None:
        import benchmark
        run = self.make_run()
        benchmark.write_rejected_findings_index(run / "pool" / "findings-rejected")
        report = run / "pool" / "findings-rejected" / "FIND-REJECTED-0001" / "report.md"
        facts = evidence_pages.report_context(report.parent)
        self.assertEqual(facts["status"], "rejected")
        self.assertEqual(facts["who"], "model-direct")
        page = evidence_pages.report_document("FIND-REJECTED-0001", "<h1>x</h1>", facts)
        self.assertIn("Rejected by triage.", page)
        self.assertIn("triggering state not attacker-reachable", page)
        self.assertIn("all rejected findings", page)

    def test_plain_documents_get_the_plain_shell(self) -> None:
        self.assertIsNone(evidence_pages.report_context(self.root))
        page = evidence_pages.report_document("INDEX", "<h1>Index</h1>", None)
        self.assertIn('class="page report plain"', page)
        self.assertNotIn("Act on it", page)

    def test_crash_facts_read_the_site_from_the_dedup_frames(self) -> None:
        crash = self.root / "CRASH-0001"
        _report(crash, "REPORT.md", _CRASH)
        (crash / "reproduce.sh").write_text("#!/bin/sh\n")
        (crash / "input.bin").write_bytes(b"\x00\x01")
        facts = evidence_pages.artifact_facts(crash, "crash")
        self.assertEqual(facts["site_text"], "app/parse.c:app_parse:12")
        self.assertEqual(facts["primitive"], "heap-buffer-overflow")
        self.assertEqual(facts["severity"]["level"], "Medium")
        self.assertEqual(facts["lanes"], ["S5"])
        self.assertEqual(facts["title"], "The parser reads one byte past the record.")
        card = evidence_pages.action_card(facts)
        self.assertIn("./reproduce.sh", card)
        self.assertIn("input.bin", card)
        self.assertIn("reproduced 3/3 times", card)


if __name__ == "__main__":
    unittest.main()
