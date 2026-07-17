#!/usr/bin/env python3
"""Per-finding discovery stamps in state/events.jsonl.

The in-run accepted counter is an inventory: it falls when a finding is demoted
and finalization re-adjudicates it either way, so it cannot answer "when was
this found". These cover the immutable first-seen row that can.
"""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "lib"))

import triage  # noqa: E402
import workqueue  # noqa: E402

REPORT = """# Finding

| Field | Value |
| --- | --- |
| Class | memory-safety |
| Site | buf.c:529 |

Out-of-bounds read in `xmlBufAdd` at buf.c:529.
"""


class FindingDiscoveryEventTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="find-discovery-")
        self.results = Path(self.temporary.name)
        self.addCleanup(self.temporary.cleanup)

    def _finding(self, name: str, parent: str = "findings") -> Path:
        directory = self.results / parent / name
        directory.mkdir(parents=True)
        (directory / "report.md").write_text(REPORT, encoding="utf-8")
        return directory

    def _events(self) -> list[dict]:
        return [
            row for row in workqueue.read_jsonl(self.results / "state" / "events.jsonl")
            if row.get("type") == "finding_created"
        ]

    def test_records_each_finding_once_with_a_signature(self) -> None:
        self._finding("FIND-001-oob-read")
        self.assertEqual(triage.record_finding_discovery(self.results), 1)
        rows = self._events()
        self.assertEqual([r["id"] for r in rows], ["FIND-001-oob-read"])
        # the signature is the cluster key, so the stamp survives pooling's rename
        self.assertEqual(rows[0]["signature"], ["memory-safety", "buf.c", "529"])
        self.assertTrue(rows[0]["first_seen"])
        self.assertTrue(rows[0]["mtime"])

    def test_stamp_is_immutable_across_repeated_housekeeping(self) -> None:
        self._finding("FIND-001-oob-read")
        triage.record_finding_discovery(self.results)
        first = self._events()[0]["first_seen"]
        # a later pass must not re-stamp: discovery time is when it was found
        self.assertEqual(triage.record_finding_discovery(self.results), 0)
        rows = self._events()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["first_seen"], first)

    def test_rejected_findings_keep_their_discovery_stamp(self) -> None:
        # rejection moves the directory out of findings/; it was still found
        self._finding("FIND-002-cut", parent="findings-rejected")
        self.assertEqual(triage.record_finding_discovery(self.results), 1)
        self.assertEqual([r["id"] for r in self._events()], ["FIND-002-cut"])

    def test_validate_find_gate_stamps_before_any_vote_work(self) -> None:
        # an expired deadline skips the LLM votes entirely; the discovery row
        # must still land, which is exactly the slow-backend case
        self._finding("FIND-003-late")
        triage.validate_find_gate(self.results, deadline=0.0, workers=1)
        self.assertEqual([r["id"] for r in self._events()], ["FIND-003-late"])

    def test_discovery_order_is_recoverable_and_monotonic(self) -> None:
        for name in ("FIND-001-a", "FIND-002-b"):
            self._finding(name)
            triage.record_finding_discovery(self.results)
        rows = self._events()
        stamps = [r["first_seen"] for r in rows]
        self.assertEqual([r["id"] for r in rows], ["FIND-001-a", "FIND-002-b"])
        self.assertEqual(stamps, sorted(stamps))


class BatchedWriteTests(unittest.TestCase):
    """Telemetry pays for durability once, not once per finding."""

    def test_a_pass_costs_one_fsync(self) -> None:
        import os
        from unittest import mock
        temporary = tempfile.TemporaryDirectory(prefix="fsync-")
        self.addCleanup(temporary.cleanup)
        results = Path(temporary.name)
        for i in range(25):
            directory = results / "findings" / f"FIND-{i:03d}"
            directory.mkdir(parents=True)
            (directory / "report.md").write_text(REPORT, encoding="utf-8")
        calls = []
        real = os.fsync
        with mock.patch("os.fsync", side_effect=lambda fd: (calls.append(1), real(fd))[1]):
            self.assertEqual(triage.record_finding_discovery(results), 25)
        self.assertEqual(len(calls), 1, "one batch, one durability round-trip")


if __name__ == "__main__":
    unittest.main()
