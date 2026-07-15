#!/usr/bin/env python3
"""Behavior tests for read-only technical/scope disposition."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "lib"))

import report_identity  # noqa: E402
import result_disposition  # noqa: E402
import triage_validate  # noqa: E402


ASAN = "==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602\n"


class ResultDispositionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="result-disposition-")
        self.root = Path(self.temporary.name)
        self.results = self.root / "results"
        self.results.mkdir()
        (self.root / "target.toml").write_text(
            'slug = "sampleproj"\npinned_rev = "actual-rev"\n'
            '[threat_model]\nattacker_controls = ["bytes"]\n',
            encoding="utf-8",
        )
        (self.root / "run.json").write_text(json.dumps({
            "target": "sampleproj", "target_sha": "actual-rev",
        }))

    def tearDown(self) -> None:
        self.temporary.cleanup()

    @staticmethod
    def _write_json(path: Path, payload: dict) -> None:
        path.write_text(json.dumps(payload), encoding="utf-8")

    def _artifact(self, kind: str, name: str, trigger: str, *, finding: bool = False) -> Path:
        directory = self.results / kind / name
        directory.mkdir(parents=True)
        report = directory / "report.md"
        report.write_text(
            f"# Neutral issue\n\nTrigger source: {trigger}\n"
            "Boundary: public input boundary\n",
            encoding="utf-8",
        )
        if finding:
            self._write_json(directory / ".llm-find-quality.json", {
                "decision_version": report_identity.FIND_QUALITY_DECISION_VERSION,
                "accept": True,
                "report_sha1": report_identity.content_sha1(report),
            })
        else:
            (directory / "sanitizer.txt").write_text(ASAN, encoding="utf-8")
        return directory

    def _trigger_vote(self, directory: Path, name: str, vote: str, *, current: bool = True) -> None:
        report = report_identity.find_report(directory)
        self.assertIsNotNone(report)
        payload = {
            "decision_version": (
                triage_validate.TRIGGER_GATE_DECISION_VERSION
                if current else "trigger-v2-caller-buffer"
            ),
            "content_sha1": report_identity.content_sha1(report),
            "vote": vote,
        }
        if current:
            payload["attacker_controls"] = ["bytes"]
        self._write_json(directory / name, payload)

    def test_source_promote_and_declared_scope_must_agree(self) -> None:
        contested = self._artifact("crashes", "CRASH-001", "both")
        self._trigger_vote(contested, ".trigger-gate.json", "Promote")
        record = result_disposition.inspect_artifact(
            self.results, contested, "crashes",
        )
        self.assertEqual((record["technical"], record["scope"]), ("confirmed", "unknown"))
        self.assertEqual(record["disposition"], "needs-review")
        self.assertEqual(record["missing_controls"], ["call-sequence"])

        agreed = self._artifact("findings", "FIND-001", "bytes", finding=True)
        self._trigger_vote(agreed, ".trigger-gate.json", "Promote")
        record = result_disposition.inspect_artifact(
            self.results, agreed, "findings",
        )
        self.assertEqual((record["technical"], record["scope"]), ("confirmed", "in"))
        self.assertEqual(record["disposition"], "security")

    def test_only_two_bound_negative_votes_prove_out_of_scope(self) -> None:
        one = self._artifact("crashes", "CRASH-ONE", "call-sequence")
        self._trigger_vote(one, ".trigger-gate.json", "Reject")
        self.assertEqual(
            result_disposition.inspect_artifact(self.results, one, "crashes")["scope"],
            "unknown",
        )

        two = self._artifact("crashes", "CRASH-TWO", "call-sequence")
        self._trigger_vote(two, ".trigger-gate.json", "Reject")
        self._trigger_vote(two, ".trigger-gate-2.json", "Reject")
        record = result_disposition.inspect_artifact(self.results, two, "crashes")
        self.assertEqual((record["scope"], record["disposition"]), ("out", "robustness"))

    def test_legacy_unbound_vote_is_advisory_and_revision_mismatch_is_visible(self) -> None:
        (self.root / "target.toml").write_text(
            'slug = "sampleproj"\npinned_rev = "config-rev"\n'
            '[threat_model]\nattacker_controls = ["bytes"]\n',
            encoding="utf-8",
        )
        finding = self._artifact("findings", "FIND-LEGACY", "bytes", finding=True)
        self._trigger_vote(finding, ".trigger-gate.json", "Promote", current=False)
        report = result_disposition.inspect_results(self.results)
        record = report["artifacts"][0]
        self.assertEqual(record["scope"], "unknown")
        self.assertEqual(record["trigger_votes"], [{
            "vote": "Promote", "attacker_controls_bound": False,
            "report_content_bound": True,
        }])
        self.assertEqual(report["target"]["revision_status"], "mismatch")
        self.assertEqual(report["issue_summary"], {"needs-review": 1})

    def test_revision_mismatch_prevents_a_conclusive_disposition(self) -> None:
        (self.root / "target.toml").write_text(
            'slug = "sampleproj"\npinned_rev = "different-rev"\n'
            '[threat_model]\nattacker_controls = ["bytes"]\n',
            encoding="utf-8",
        )
        finding = self._artifact("findings", "FIND-REV", "bytes", finding=True)
        self._trigger_vote(finding, ".trigger-gate.json", "Promote")
        record = result_disposition.inspect_artifact(
            self.results, finding, "findings",
        )
        self.assertEqual((record["technical"], record["scope"]), ("confirmed", "in"))
        self.assertEqual(record["disposition"], "needs-review")

    def test_exported_crash_reads_vote_from_audit_provenance(self) -> None:
        crash = self._artifact("crashes", "CRASH-EXPORTED", "bytes")
        audit = crash / ".audit"
        audit.mkdir()
        audit_report = audit / "report.md"
        audit_report.write_text((crash / "report.md").read_text())
        (crash / "report.md").write_text(
            (crash / "report.md").read_text() + "Substantive export rewrite.\n",
        )
        self._write_json(audit / ".trigger-gate.json", {
            "decision_version": "trigger-v2-caller-buffer",
            "content_sha1": report_identity.content_sha1(audit_report),
            "vote": "Promote",
        })
        record = result_disposition.inspect_artifact(
            self.results, crash, "crashes",
        )
        self.assertEqual(record["trigger_votes"], [{
            "vote": "Promote", "attacker_controls_bound": False,
            "report_content_bound": True,
        }])
        self.assertEqual(record["scope"], "unknown")

    def test_explicit_recon_identity_deduplicates_across_evidence_kinds(self) -> None:
        crash = self._artifact("crashes", "CRASH-RECON", "bytes")
        finding = self._artifact("findings", "FIND-RECON", "bytes", finding=True)
        for directory in (crash, finding):
            report = report_identity.find_report(directory)
            self.assertIsNotNone(report)
            report.write_text(report.read_text() + "Recon ID: RECON-neutral\n")
            self._trigger_vote(directory, ".trigger-gate.json", "Promote")
        result = result_disposition.inspect_results(self.results)
        self.assertEqual(len(result["artifacts"]), 2)
        self.assertEqual(len(result["issues"]), 1)
        self.assertEqual(result["issue_summary"], {"security": 1})

    def test_cli_discovers_condition_pools_without_writing_artifacts(self) -> None:
        benchmark = self.root / "benchmark"
        condition = benchmark / "pool" / "harness"
        crash = condition / "crashes" / "CRASH-001"
        crash.mkdir(parents=True)
        (crash / "report.md").write_text("Trigger source: bytes\n")
        (crash / "sanitizer.txt").write_text(ASAN)
        before = sorted(str(path.relative_to(benchmark)) for path in benchmark.rglob("*"))
        completed = subprocess.run(
            [str(ROOT / "bin" / "disposition"), str(benchmark)],
            text=True, capture_output=True, check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(json.loads(completed.stdout)["mode"], "shadow")
        after = sorted(str(path.relative_to(benchmark)) for path in benchmark.rglob("*"))
        self.assertEqual(before, after)


if __name__ == "__main__":
    unittest.main(verbosity=2)
