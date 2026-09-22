#!/usr/bin/env python3
"""One defect, one verdict: findings at a crash's exact line ride with the crash.

Also covers the two clocks that made the defect read twice: crash numbers
that skipped rejected bundles, and admission stamps dated by the scan that
noticed them rather than by the receipt.
"""

from __future__ import annotations

import json
import sys
import tempfile
import time
import unittest
from unittest import mock
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "lib"))

import crash_bundle  # noqa: E402
import triage  # noqa: E402
import validation_receipt  # noqa: E402
import workqueue  # noqa: E402

SANITIZER = (
    "==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x60200000001\n"
    "READ of size 1 at 0x60200000001 thread T0\n"
    "    #0 0x1000 in app_push_cdata parse.c:8190:5\n"
    "    #1 0x2000 in main harness.c:12:3\n"
)


def _finding_report(
    file: str, function: str, line: int, klass: str = "oob-read",
) -> str:
    return (
        "# Progressive data reads beyond its length\n\n"
        f"Location: {file}:{function}:{line}\n\n"
        "## Fields\n\n"
        "| Field | Value |\n|:--|:--|\n"
        f"| Class | {klass} |\n"
        f"| File | `{file}` |\n"
        f"| Function | `{function}` |\n"
        f"| Line | {line} |\n\n"
        "## Summary\n\nThe scan ignores the supplied length.\n"
    )


class CompanionAbsorptionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="companion-")
        self.addCleanup(self.temporary.cleanup)
        self.results = Path(self.temporary.name)
        (self.results / "findings").mkdir()

    def _crash(
        self, name: str, lane: str = "crashes", file: str = "parse.c",
    ) -> Path:
        directory = self.results / lane / name
        directory.mkdir(parents=True)
        sanitizer = SANITIZER.replace("parse.c:8190", f"{file}:8190")
        (directory / "sanitizer.txt").write_text(sanitizer, encoding="utf-8")
        (directory / "report.md").write_text("# crash\n", encoding="utf-8")
        return directory

    def _finding(
        self, name: str, file="parse.c", function="app_push_cdata", line=8190,
        klass="oob-read",
    ) -> Path:
        directory = self.results / "findings" / name
        directory.mkdir()
        (directory / "report.md").write_text(
            _finding_report(file, function, line, klass), encoding="utf-8",
        )
        return directory

    def test_finding_at_the_crash_line_moves_under_the_crash(self) -> None:
        crash = self._crash("CRASH-001-3")
        same = self._finding("FIND-004-length-read")
        other_line = self._finding("FIND-005-other", line=8210)
        other_file = self._finding("FIND-006-other-file", file="save.c")
        other_function = self._finding("FIND-007-other-fn", function="app_other")
        kept = triage.absorb_crash_companions(
            self.results, [same, other_line, other_file, other_function],
        )
        self.assertEqual(kept, [other_line, other_file, other_function])
        self.assertFalse(same.exists())
        moved = crash / ".companion" / "FIND-004-length-read"
        self.assertTrue((moved / "report.md").is_file())

    def test_rejected_crash_still_owns_its_companion(self) -> None:
        crash = self._crash("CRASH-001-1", lane="crashes-rejected")
        finding = self._finding("FIND-004-length-read")
        kept = triage.absorb_crash_companions(self.results, [finding])
        self.assertEqual(kept, [])
        self.assertTrue((crash / ".companion" / "FIND-004-length-read" / "report.md").is_file())

    def test_pinned_findings_and_unparsed_crashes_are_left_alone(self) -> None:
        self._crash("CRASH-001-3")
        pinned = self._finding("FIND-004-pinned")
        (pinned / ".keep").touch()
        blind = self.results / "crashes" / "CRASH-002-3"
        blind.mkdir()
        (blind / "sanitizer.txt").write_text(
            "==1==ERROR: AddressSanitizer: heap-buffer-overflow\n", encoding="utf-8",
        )
        far = self._finding("FIND-008-far", line=42)
        kept = triage.absorb_crash_companions(self.results, [pinned, far])
        self.assertEqual(kept, [pinned, far])

    def test_same_basename_or_different_class_does_not_fold(self) -> None:
        self._crash("CRASH-001-3", file="src/one/parse.c")
        other_path = self._finding(
            "FIND-004-other-path", file="src/two/parse.c",
        )
        other_class = self._finding(
            "FIND-005-other-class", file="src/one/parse.c", klass="auth-bypass",
        )
        other_case = self._finding(
            "FIND-006-other-case", file="src/one/Parse.c",
        )
        kept = triage.absorb_crash_companions(
            self.results, [other_path, other_class, other_case],
        )
        self.assertEqual(kept, [other_path, other_class, other_case])

    def test_absolute_crash_path_matches_target_relative_finding(self) -> None:
        target = self.results / "target"
        (target / "src").mkdir(parents=True)
        (self.results / ".session-env").write_text(
            f"TARGET_ROOT={target}\n", encoding="utf-8",
        )
        crash = self._crash(
            "CRASH-001-3", file=str(target / "src" / "parse.c"),
        )
        finding = self._finding("FIND-004-relative", file="src/parse.c")
        kept = triage.absorb_crash_companions(self.results, [finding])
        self.assertEqual(kept, [])
        self.assertTrue((crash / ".companion" / finding.name).is_dir())

    def test_find_gate_folds_an_already_rejected_companion(self) -> None:
        crash = self._crash("CRASH-001-3")
        rejected = self.results / "findings-rejected" / "FIND-004-length-read"
        rejected.mkdir(parents=True)
        (rejected / "report.md").write_text(
            _finding_report("parse.c", "app_push_cdata", 8190), encoding="utf-8",
        )
        (rejected / "rejection.md").write_text(
            "# Rejected artifact\n\nReason: threat-model: outside\n", encoding="utf-8",
        )
        with mock.patch.dict("os.environ", {"LLM_DECIDE_DISABLE": "1"}):
            triage.validate_find_gate(self.results, workers=1)
        self.assertFalse(rejected.exists())
        self.assertTrue((crash / ".companion" / "FIND-004-length-read" / "rejection.md").is_file())

    def test_find_gate_absorbs_before_spending_a_vote(self) -> None:
        crash = self._crash("CRASH-001-3")
        self._finding("FIND-004-length-read")
        with mock.patch.dict("os.environ", {"LLM_DECIDE_DISABLE": "1"}):
            counts = triage.validate_find_gate(self.results, workers=1)
        self.assertEqual(counts, {"accepted": 0, "rejected": 0, "pending": 0})
        self.assertTrue((crash / ".companion" / "FIND-004-length-read").is_dir())
        self.assertEqual(list((self.results / "findings").glob("FIND-*")), [])


class CrashNumberTests(unittest.TestCase):
    def test_next_number_counts_rejected_bundles(self) -> None:
        with tempfile.TemporaryDirectory(prefix="crash-number-") as temporary:
            root = Path(temporary)
            (root / "crashes-rejected" / "CRASH-001-1").mkdir(parents=True)
            (root / "crashes-rejected" / "CRASH-002-1.20260922T020533Z.1").mkdir()
            (root / "crashes" / "CRASH-004-2").mkdir(parents=True)
            testcase = root / "input.bin"
            sanitizer = root / "trace.txt"
            testcase.write_bytes(b"A")
            sanitizer.write_text(SANITIZER, encoding="utf-8")
            status, crash_id = crash_bundle.materialize(
                root, "1", testcase, sanitizer, "asan", "generic",
            )
            self.assertEqual(status, "FILED")
            # Past both rejected numbers for agent 1; agent 2's bundle is not counted.
            self.assertEqual(crash_id, "CRASH-003-1")


class AdmissionStampTests(unittest.TestCase):
    def test_admission_is_dated_by_the_receipt_not_the_scan(self) -> None:
        with tempfile.TemporaryDirectory(prefix="stamp-") as temporary:
            results = Path(temporary)
            crash = results / "crashes" / "CRASH-001-3"
            crash.mkdir(parents=True)
            (crash / "sanitizer.txt").write_text(SANITIZER, encoding="utf-8")
            (crash / "report.md").write_text("# crash\n", encoding="utf-8")
            validation_receipt.write(
                crash, kind="crash", state="reportable", detail="in-model",
            )
            receipt = crash / "validation.json"
            payload = json.loads(receipt.read_text(encoding="utf-8"))
            validated_at = time.time() - 1800
            payload["validated_at"] = validated_at
            receipt.write_text(json.dumps(payload), encoding="utf-8")
            (results / "state").mkdir()
            self.assertGreater(triage.record_artifact_events(results), 0)
            admitted = [
                row for row in workqueue.read_jsonl(results / "state" / "events.jsonl")
                if row.get("type") == "artifact_admitted"
            ]
            self.assertEqual([row["id"] for row in admitted], ["CRASH-001-3"])
            self.assertEqual(
                admitted[0]["first_seen"],
                datetime.fromtimestamp(validated_at, timezone.utc).isoformat(),
            )


if __name__ == "__main__":
    unittest.main()
