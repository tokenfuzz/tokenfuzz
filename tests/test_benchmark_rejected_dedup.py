#!/usr/bin/env python3
"""Deduplicated rejection counts.

Accepted results are clustered before they are counted; rejections used to be a
raw directory tally. Counting one side deduplicated and the other raw compares
two different things, so the same clustering now feeds both.
"""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "lib"))

import benchmark  # noqa: E402


class RejectedDedupTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="rejected-dedup-")
        self.bench = Path(self.temporary.name)
        self.addCleanup(self.temporary.cleanup)
        self._write("run.json", {
            "runid": "20260101-000000", "target": "sample",
            "backend": "codex", "model": "gpt-test",
        })
        cell = self.bench / "cells" / "harness-r1"
        cell.mkdir(parents=True)
        self._write("cells/harness-r1/cell.json", {
            "cell": "harness-r1", "condition": "harness", "replicate": 1,
            "status": "done", "wall_seconds": 60,
        })
        self._write("cells/harness-r1/metrics.json", {
            "confirmed_crashes": 2, "crashes_rejected": 3,
            "confirmed_findings": 1, "findings_rejected": 4,
        })

    def _write(self, rel: str, payload: dict) -> None:
        path = self.bench / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload), encoding="utf-8")

    def _condition(self) -> dict:
        report = benchmark.aggregate(self.bench)
        return next(c for c in report["conditions"] if c["condition"] == "harness")

    def test_rejections_are_counted_after_clustering(self) -> None:
        # four rejected findings, but two share a root cause -> three clusters;
        # three rejected crashes collapsing to a single stack -> one cluster.
        self._write("pool-members.json", {
            "crashes": {"CRASH-0001": "harness", "CRASH-0002": "harness"},
            "findings": {"FIND-0001": "harness"},
            "crashes-rejected": {
                "CRASH-REJECTED-0001": "harness",
                "CRASH-REJECTED-0002": "harness",
                "CRASH-REJECTED-0003": "harness",
            },
            "findings-rejected": {
                "FIND-REJECTED-0001": "harness",
                "FIND-REJECTED-0002": "harness",
                "FIND-REJECTED-0003": "harness",
                "FIND-REJECTED-0004": "harness",
            },
        })
        self._write("clusters-crashes.json", {"clusters": [
            {"id": "CL-a", "members": ["CRASH-0001", "CRASH-0002"]},
        ]})
        self._write("clusters-findings.json", {"clusters": [
            {"id": "FCL-a", "members": ["FIND-0001"]},
        ]})
        self._write("clusters-crashes-rejected.json", {"clusters": [
            {"id": "CL-r", "members": [
                "CRASH-REJECTED-0001", "CRASH-REJECTED-0002", "CRASH-REJECTED-0003",
            ]},
        ]})
        self._write("clusters-findings-rejected.json", {"clusters": [
            {"id": "FCL-r1", "members": ["FIND-REJECTED-0001", "FIND-REJECTED-0002"]},
            {"id": "FCL-r2", "members": ["FIND-REJECTED-0003"]},
            {"id": "FCL-r3", "members": ["FIND-REJECTED-0004"]},
        ]})
        cond = self._condition()
        self.assertEqual(cond["unique_rejected_finding_clusters"], 3)
        self.assertEqual(cond["unique_rejected_crash_clusters"], 1)
        self.assertFalse(cond["rejected_finding_clusters_upper_bound"])
        self.assertFalse(cond["rejected_crash_clusters_upper_bound"])
        # the raw tallies stay available for accounting; they are just no longer
        # what the table shows
        self.assertEqual(cond["rejected_finding_total"], 4)
        self.assertEqual(cond["rejected_crash_total"], 3)

    def test_rejections_are_never_silently_dropped(self) -> None:
        # No pooled clustering yet, so nothing can be merged. Degrade to the raw
        # upper bound rather than to zero: "0 rejected" reads as a clean run.
        cond = self._condition()
        self.assertEqual(cond["unique_rejected_crash_clusters"], 3)

    def test_row_only_ledger_rejections_reach_the_unique_total(self) -> None:
        # count_crashes_rejected has two legitimate sources: CRASH-* dirs and
        # row-only ledger signatures that never got a dir. Only dirs can be
        # clustered, so the row-only remainder must still be counted or real
        # rejections vanish from the table.
        self._write("pool-members.json", {
            "crashes-rejected": {"CRASH-REJECTED-0001": "harness"},
        })
        self._write("clusters-crashes-rejected.json", {"clusters": [
            {"id": "CL-r", "members": ["CRASH-REJECTED-0001"]},
        ]})
        # metrics book 3 rejects; only 1 has a directory -> 2 are row-only
        cond = self._condition()
        self.assertEqual(cond["rejected_crash_total"], 3)
        self.assertEqual(cond["unique_rejected_crash_clusters"], 3)  # 1 cluster + 2 rows
        self.assertTrue(cond["rejected_crash_clusters_upper_bound"])


class ClusterFailureTests(unittest.TestCase):
    """A tool failure must never render as a clean bill."""

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="cluster-fail-")
        self.bench = Path(self.temporary.name)
        self.addCleanup(self.temporary.cleanup)
        (self.bench / "run.json").write_text(json.dumps({
            "runid": "r", "target": "t", "backend": "codex", "model": "m"}))
        cell = self.bench / "cells" / "harness-r1"
        cell.mkdir(parents=True)
        (cell / "cell.json").write_text(json.dumps({
            "cell": "harness-r1", "condition": "harness", "replicate": 1,
            "status": "done", "wall_seconds": 60}))
        (cell / "metrics.json").write_text(json.dumps({
            "crashes_rejected": 3, "findings_rejected": 4,
            "confirmed_crashes": 1, "confirmed_findings": 1}))
        (self.bench / "pool-members.json").write_text(json.dumps({
            "crashes-rejected": {f"CRASH-REJECTED-000{i}": "harness" for i in (1, 2, 3)},
            "findings-rejected": {f"FIND-REJECTED-000{i}": "harness" for i in (1, 2, 3, 4)}}))

    def _harness(self) -> dict:
        return next(c for c in benchmark.aggregate(self.bench)["conditions"]
                    if c["condition"] == "harness")

    def test_clusterer_failure_falls_back_to_the_raw_upper_bound(self) -> None:
        # the runner turns a clusterer failure into empty cluster JSON; pooled
        # dirs with zero clusters is impossible, so it means "did not cluster",
        # not "nothing was rejected"
        (self.bench / "clusters-crashes-rejected.json").write_text('{"clusters":[]}')
        (self.bench / "clusters-findings-rejected.json").write_text('{"clusters":[]}')
        cond = self._harness()
        self.assertEqual(cond["unique_rejected_crash_clusters"], 3)
        self.assertEqual(cond["unique_rejected_finding_clusters"], 4)
        self.assertTrue(cond["rejected_crash_clusters_upper_bound"])
        self.assertTrue(cond["rejected_finding_clusters_upper_bound"])

    def test_successful_clustering_still_merges(self) -> None:
        (self.bench / "clusters-crashes-rejected.json").write_text(json.dumps({"clusters": [
            {"id": "a", "members": ["CRASH-REJECTED-0001", "CRASH-REJECTED-0002"]},
            {"id": "b", "members": ["CRASH-REJECTED-0003"]}]}))
        (self.bench / "clusters-findings-rejected.json").write_text(json.dumps({"clusters": [
            {"id": "f", "members": [f"FIND-REJECTED-000{i}" for i in (1, 2, 3, 4)]}]}))
        cond = self._harness()
        self.assertEqual(cond["unique_rejected_crash_clusters"], 2)
        self.assertEqual(cond["unique_rejected_finding_clusters"], 1)
        self.assertFalse(cond["rejected_crash_clusters_upper_bound"])
        self.assertFalse(cond["rejected_finding_clusters_upper_bound"])


class ProductiveWallTests(unittest.TestCase):
    """Wall must measure finding work, not the triage that measures it."""

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="wall-")
        self.cell = Path(self.temporary.name)
        self.addCleanup(self.temporary.cleanup)

    def test_declared_productive_wall_wins_over_recorded_elapsed(self) -> None:
        # cell.json ran long because triage followed the audit; the audit's own
        # log is authoritative for what it spent finding things
        (self.cell / "audit.log").write_text(
            "[01:00:00] Iteration 1 starting\n"
            "[04:00:00] Reached productive wall budget: 10800s productive, 0s provider pause excluded\n",
            encoding="utf-8",
        )
        self.assertEqual(benchmark._declared_productive_wall(self.cell), 10800)

    def test_no_audit_log_falls_back_to_recorded_wall(self) -> None:
        self.assertIsNone(benchmark._declared_productive_wall(self.cell))
        self.assertEqual(benchmark._effective_wall({"wall_seconds": 900}), 900)

    def test_log_without_the_budget_line_does_not_invent_a_wall(self) -> None:
        (self.cell / "audit.log").write_text("[01:00:00] Iteration 1 starting\n", encoding="utf-8")
        self.assertIsNone(benchmark._declared_productive_wall(self.cell))


if __name__ == "__main__":
    unittest.main()
