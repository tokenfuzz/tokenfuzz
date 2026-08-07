#!/usr/bin/env python3
"""Receipt-lifecycle regression tests.

A pooled artifact publishes unrated when the review that cleared it no longer
covers its report. Two things kept that invisible: reach-field convergence
stopped after one pass and let a later pass rewrite an already-reviewed
report, and the pool's own guard skipped exactly the artifacts whose
validation had gone stale.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "lib"))

import benchmark_runner
import triage
import validation_receipt


REPORT = (
    "# Parsed length reaches a copy without a bound\n\n"
    "| Field | Value |\n| :---- | :---- |\n"
    "| Caller controls | — |\n| Boundary | — |\n\n"
    "Trigger source: bytes\n\n"
    "A parsed field sizes a copy into a fixed destination.\n"
)

# Two decisions: the first answers part of what is missing, the second the
# rest. One pass per artifact stops after the first and leaves the report
# short — which is what a later pass then rewrites.
FIRST_PASS = {
    "surface": "file-format",
    "primitive": "heap_write",
    "class": "memory-safety",
    "caller_controls": "bytes",
    "boundary": "parsed input bytes",
}
SECOND_PASS = {
    "caller_contract": "obeyed",
    "parameter_control": "application-supplied",
    "trusted_caller_actions": "normal public call",
    "advisory": "no",
}


def _artifact(root: Path, kind: str, name: str) -> Path:
    directory = root / kind / name
    directory.mkdir(parents=True)
    (directory / "report.md").write_text(REPORT, encoding="utf-8")
    return directory


def _attempts(directory: Path) -> int:
    return json.loads(
        (directory / ".llm_fields.json").read_text(encoding="utf-8")
    ).get("_fill_attempts", 0)


def _batches(*passes: dict | None):
    """Stand in for the batch decider, serving one answer per pass.

    `None` models the omitted/unparsable answer the batch protocol allows:
    the pass still spends an attempt and materializes nothing.
    """
    seen: list[list[str]] = []

    def fake(*args, **kwargs):
        items = args[3]
        seen.append([item["id"] for item in items])
        answer = passes[min(len(seen) - 1, len(passes) - 1)]
        return {} if answer is None else {item["id"]: answer for item in items}

    fake.seen = seen
    return fake


class ConvergeReachFields(unittest.TestCase):
    def test_runs_to_a_fixed_point_then_leaves_a_later_pass_inert(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            directory = _artifact(root, "findings", "FIND-0001")
            batch = _batches(FIRST_PASS, SECOND_PASS)
            with mock.patch.object(triage, "_batch_decisions", batch):
                triage.converge_reach_fields([directory])
            text = (directory / "report.md").read_text(encoding="utf-8")
            for field in ("Caller contract:", "Parameter control:", "Advisory:"):
                self.assertIn(field, text)
            # The pool rebuild runs this same pass over the pooled copy. On a
            # converged report it must neither decide nor write, or it would
            # invalidate the receipt bound to that report.
            attempted, _, prefilled = triage._batch_reach_field_decisions(
                [directory], None,
            )
            self.assertEqual((attempted, prefilled), (set(), set()))

    def test_answerless_first_pass_still_spends_the_retry_here(self) -> None:
        """The decisive case: an omitted answer materializes nothing.

        Keying the loop on "did the report change" stops after that pass and
        leaves the retry for the pool — the original defect, reintroduced.
        """
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            directory = _artifact(root, "findings", "FIND-0001")
            batch = _batches(None, {**FIRST_PASS, **SECOND_PASS})
            with mock.patch.object(triage, "_batch_decisions", batch):
                triage.converge_reach_fields([directory])
            self.assertEqual(len(batch.seen), 2)
            self.assertEqual(
                triage._missing_reach_fields(
                    (directory / "report.md").read_text(encoding="utf-8")
                ),
                {},
            )
            # And the later pool pass now has nothing to do.
            with mock.patch.object(triage.llm_decide, "llm_decide") as later:
                self.assertFalse(triage.fill_reach_fields(directory))
            self.assertEqual(later.call_count, 0)

    def test_converged_report_spends_no_decision(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            directory = _artifact(root, "findings", "FIND-0001")
            with mock.patch.object(
                triage, "_batch_decisions", _batches(FIRST_PASS, SECOND_PASS),
            ):
                triage.converge_reach_fields([directory])
            batch = _batches(SECOND_PASS)
            with mock.patch.object(triage, "_batch_decisions", batch):
                triage.converge_reach_fields([directory])
            self.assertEqual(batch.seen, [])

    def test_stops_at_the_attempt_ceiling_when_answers_never_arrive(self) -> None:
        # An answer that never resolves the fields must not spin: the loop is
        # bounded by the same ceiling one pass enforces.
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            directory = _artifact(root, "findings", "FIND-0001")
            batch = _batches(None)
            with mock.patch.object(triage, "_batch_decisions", batch):
                triage.converge_reach_fields([directory])
            self.assertEqual(len(batch.seen), 2)
            self.assertEqual(_attempts(directory), 2)

    def test_retries_the_whole_group_in_one_batched_pass(self) -> None:
        # Convergence must not trade the batched pass for one call per
        # artifact: that multiplies provider calls at finalization time.
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            group = [
                _artifact(root, "findings", f"FIND-{n:04d}") for n in range(1, 7)
            ]
            batch = _batches(None)
            with mock.patch.object(triage, "_batch_decisions", batch):
                triage.converge_reach_fields(group, workers=4)
            # Two passes, each handed all six artifacts at once — not twelve
            # single-report decisions.
            self.assertEqual(len(batch.seen), 2)
            self.assertTrue(all(len(seen) == 6 for seen in batch.seen))
            for directory in group:
                self.assertEqual(_attempts(directory), 2)

    def test_deadline_stops_the_loop(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            directory = _artifact(root, "findings", "FIND-0001")
            batch = _batches(FIRST_PASS)
            with mock.patch.object(triage, "_batch_decisions", batch):
                triage.converge_reach_fields([directory], deadline=0.0)
            self.assertEqual(batch.seen, [])


def _write_receipt(directory: Path, state: str) -> None:
    (directory / "validation.json").write_text(
        json.dumps({"schema_version": 1, "kind": "finding", "state": state,
                    "evidence": {}}),
        encoding="utf-8",
    )


class PoolReceiptProblems(unittest.TestCase):
    def test_stale_validation_is_reported_not_skipped(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            pool = Path(tmp)
            directory = _artifact(pool, "findings", "FIND-0001")
            # Claims a concluded security review, but nothing on disk backs
            # it any more. This is the case the old guard skipped outright.
            _write_receipt(directory, "reportable")
            with mock.patch.object(
                validation_receipt, "read_current", return_value=None,
            ):
                unvalidated, unscored = benchmark_runner._pool_receipt_problems(
                    pool,
                )
            self.assertEqual(unvalidated, ["findings/FIND-0001"])
            self.assertEqual(unscored, [])

    def test_never_reviewed_artifact_is_in_neither_list(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            pool = Path(tmp)
            directory = _artifact(pool, "findings", "FIND-0001")
            _write_receipt(directory, "pending")
            with mock.patch.object(
                validation_receipt, "read_current", return_value=None,
            ):
                unvalidated, unscored = benchmark_runner._pool_receipt_problems(
                    pool,
                )
            self.assertEqual((unvalidated, unscored), ([], []))

    def test_condition_subtrees_are_in_scope(self) -> None:
        # split_pool copies each condition into its own subtree and maintains
        # indexes there afterwards, so a receipt can go stale in a place the
        # combined-tree walk never looked.
        with tempfile.TemporaryDirectory() as tmp:
            pool = Path(tmp)
            _artifact(pool, "findings", "FIND-0001")
            (pool / "logs").mkdir()
            condition = pool / "model-direct"
            _artifact(condition, "findings", "FIND-0009")
            with mock.patch.object(
                validation_receipt, "read_current",
                return_value={"state": "reportable", "kind": "finding"},
            ), mock.patch.object(
                benchmark_runner.severity_receipt, "read_current",
                return_value=None,
            ):
                _, unscored = benchmark_runner._pool_receipt_problems(pool)
            self.assertEqual(
                unscored,
                ["findings/FIND-0001", "model-direct/findings/FIND-0009"],
            )

    def test_stale_severity_still_reported_separately(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            pool = Path(tmp)
            _artifact(pool, "findings", "FIND-0001")
            with mock.patch.object(
                validation_receipt, "read_current",
                return_value={"state": "reportable", "kind": "finding"},
            ), mock.patch.object(
                benchmark_runner.severity_receipt, "read_current",
                return_value=None,
            ):
                unvalidated, unscored = benchmark_runner._pool_receipt_problems(
                    pool,
                )
            self.assertEqual(unvalidated, [])
            self.assertEqual(unscored, ["findings/FIND-0001"])


class CachedFinalizationConverges(unittest.TestCase):
    """The cached shortcut writes a receipt too, so it owes the same convergence.

    An artifact whose required fields and cached votes are already complete
    skips the disposition groups entirely. Left un-converged, its optional
    score-bearing fields are still open when its receipt is written, and the
    pool's pass then rewrites the report the receipt covers.
    """

    def test_cached_crash_converges_before_its_receipt_is_written(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            results = Path(tmp)
            directory = _artifact(results, "crashes", "CRASH-0001")
            (directory / "sanitizer.txt").write_text(
                "==1==ERROR: AddressSanitizer: heap-buffer-overflow\n"
                "    #0 0x0 in app_parse sampleproj.c:91\n",
                encoding="utf-8",
            )
            order: list[str] = []
            with mock.patch.dict(os.environ, {"CRASH_TRIGGER_GATE": "0"}), \
                mock.patch.object(
                    triage, "converge_reach_fields",
                    lambda dirs, *a, **k: order.append(
                        f"converge:{sorted(d.name for d in dirs)}"
                    ),
                ), \
                mock.patch.object(
                    triage, "triage_one_crash",
                    lambda directory, *a, **k: (
                        order.append(f"finalize:{directory.name}") or "promoted"
                    ),
                ):
                triage.triage_crash_dirs(results, results, "slug", ["bytes"])
        # Convergence must come first, and must carry the cached artifact.
        self.assertEqual(
            order, ["converge:['CRASH-0001']", "finalize:CRASH-0001"],
        )

    def test_settled_cached_crash_finalizes_without_convergence(self) -> None:
        # The cached path exists to finish already-reviewed work before
        # anything asks a provider. An artifact with nothing left to resolve
        # must not be routed through the batch decider on the way.
        with tempfile.TemporaryDirectory() as tmp:
            results = Path(tmp)
            directory = _artifact(results, "crashes", "CRASH-0001")
            (directory / "report.md").write_text(
                REPORT
                + "Surface: file-format\nPrimitive: heap_write\n"
                  "Class: memory-safety\nCaller contract: obeyed\n"
                  "Parameter control: direct\nCaller controls: bytes\n"
                  "Boundary: public parser\n"
                  "Trusted caller actions: normal public call\nAdvisory: no\n",
                encoding="utf-8",
            )
            self.assertFalse(triage.reach_fields_open(directory))
            order: list[str] = []
            with mock.patch.dict(os.environ, {"CRASH_TRIGGER_GATE": "0"}), \
                mock.patch.object(
                    triage, "converge_reach_fields",
                    lambda dirs, *a, **k: order.append("converge"),
                ), \
                mock.patch.object(
                    triage, "triage_one_crash",
                    lambda directory, *a, **k: (
                        order.append("finalize") or "promoted"
                    ),
                ):
                triage.triage_crash_dirs(results, results, "slug", ["bytes"])
        self.assertEqual(order, ["finalize"])


class PooledReportsAreImmutableOnceReviewed(unittest.TestCase):
    """The pool pass must not reopen fields a review already concluded on.

    Convergence upstream is what keeps fields from being left open, but it can
    be cut short — an expired deadline, an unavailable provider, a spent
    attempt budget. This is the backstop that makes the cause irrelevant.
    """

    def test_open_fields_under_a_final_receipt_are_left_alone(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            pool = Path(tmp)
            directory = _artifact(pool, "findings", "FIND-0001")
            validation_receipt.write(
                directory, kind="finding", state="reportable",
                attacker_controls=["bytes"],
            )
            self.assertTrue(triage.reach_fields_open(directory))
            before = (directory / "report.md").read_text(encoding="utf-8")

            batch = _batches(SECOND_PASS)
            with mock.patch.object(triage, "_batch_decisions", batch):
                self.assertEqual(triage.fill_reach_fields_tree(pool), 0)

            self.assertEqual(batch.seen, [], "asked a provider about a reviewed report")
            self.assertEqual(
                (directory / "report.md").read_text(encoding="utf-8"), before,
            )
            self.assertIsNotNone(validation_receipt.read_current(directory))

    def test_unreviewed_artifacts_are_still_filled(self) -> None:
        # The pass still exists for the legacy backlog it was written for.
        with tempfile.TemporaryDirectory() as tmp:
            pool = Path(tmp)
            directory = _artifact(pool, "findings", "FIND-0001")
            batch = _batches({**FIRST_PASS, **SECOND_PASS})
            with mock.patch.object(triage, "_batch_decisions", batch):
                self.assertEqual(triage.fill_reach_fields_tree(pool), 1)
            self.assertEqual(len(batch.seen), 1)
            self.assertIn(
                "Parameter control:",
                (directory / "report.md").read_text(encoding="utf-8"),
            )


class PoolAuditBlocks(unittest.TestCase):
    def test_stale_validation_blocks_publication(self) -> None:
        # The published aggregate sums per-cell totals captured while the
        # receipts were fresh, so a warning would let a run credit findings no
        # current review covers.
        with tempfile.TemporaryDirectory() as tmp:
            pool = Path(tmp)
            directory = _artifact(pool, "findings", "FIND-0001")
            _write_receipt(directory, "reportable")
            with mock.patch.object(
                validation_receipt, "read_current", return_value=None,
            ):
                with self.assertRaisesRegex(RuntimeError, "revalidate them"):
                    benchmark_runner._audit_pool_receipts(pool, "test")

    def test_clean_pool_publishes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            pool = Path(tmp)
            directory = _artifact(pool, "findings", "FIND-0001")
            _write_receipt(directory, "pending")
            with mock.patch.object(
                validation_receipt, "read_current", return_value=None,
            ):
                benchmark_runner._audit_pool_receipts(pool, "test")


class SeverityUnratedLabel(unittest.TestCase):
    """A concluded review whose report moved must not read as unfinished work."""

    def _severity(self, directory: Path) -> dict:
        result = subprocess.run(
            [str(ROOT / "bin" / "severity"), "--report", str(directory), "--json"],
            capture_output=True, text=True, check=False,
        )
        return json.loads(result.stdout)["severity"]

    def test_stale_receipt_reads_as_stale_and_pending_reads_as_pending(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            pool = Path(tmp)
            stale = _artifact(pool, "findings", "FIND-0001")
            _write_receipt(stale, "reportable")
            pending = _artifact(pool, "findings", "FIND-0002")
            _write_receipt(pending, "pending")

            stale_severity = self._severity(stale)
            pending_severity = self._severity(pending)
            stale_report = (stale / "report.md").read_text(encoding="utf-8")
            pending_report = (pending / "report.md").read_text(encoding="utf-8")

        self.assertEqual(stale_severity["level"], "Unknown")
        self.assertIn("no longer matches", stale_severity["reason"])
        self.assertIn("validation stale", stale_report)
        self.assertEqual(pending_severity["level"], "Unknown")
        self.assertIn("no current final", pending_severity["reason"])
        self.assertIn("validation pending", pending_report)


if __name__ == "__main__":
    unittest.main()
