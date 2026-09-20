#!/usr/bin/env python3
"""Filing-time and expansion-time dedup of bundles that share one crash state."""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "lib"))

import audit_runner  # noqa: E402
import crash_bundle  # noqa: E402
import triage  # noqa: E402
import validation_receipt  # noqa: E402
import workqueue  # noqa: E402


def trace(
    kind: str = "heap-buffer-overflow", line: int = 20, access: str = "",
) -> str:
    access_line = f"{access} of size 4 at 0x1 thread T0\n" if access else ""
    return (
        f"==1==ERROR: AddressSanitizer: {kind} on address 0x1\n"
        f"{access_line}"
        f"    #0 0x1 in app_parse /src/parser.c:{line}\n"
        "    #1 0x2 in main /src/cli.c:9\n"
        f"SUMMARY: AddressSanitizer: {kind} /src/parser.c:{line} in app_parse\n"
    )


def uaf_trace(free_line: int) -> str:
    return (
        "==1==ERROR: AddressSanitizer: heap-use-after-free on address 0x1\n"
        "READ of size 4 at 0x1 thread T0\n"
        "    #0 0x1 in app_use /src/parser.c:40\n"
        "    #1 0x2 in main /src/cli.c:9\n"
        "0x1 is located 0 bytes inside of 8-byte region\n"
        "freed by thread T0 here:\n"
        "    #0 0x3 in free /lib/asan.c:1\n"
        f"    #1 0x4 in app_release /src/parser.c:{free_line}\n"
        "    #2 0x5 in main /src/cli.c:9\n"
        "previously allocated by thread T0 here:\n"
        "    #0 0x6 in malloc /lib/asan.c:2\n"
        "    #1 0x7 in app_alloc /src/parser.c:5\n"
        "SUMMARY: AddressSanitizer: heap-use-after-free /src/parser.c:40 in app_use\n"
    )


class CrashStateDedupTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="crash-state-dedup-")
        self.root = Path(self.temporary.name)
        self.results = self.root / "results"
        (self.results / "state").mkdir(parents=True)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def file(self, agent: str, name: str, text: str, **kwargs) -> tuple[str, str]:
        testcase = self.root / f"{name}.bin"
        testcase.write_bytes(name.encode())
        sanitizer = self.root / f"{name}.txt"
        sanitizer.write_text(text, encoding="utf-8")
        mode = kwargs.pop("mode", "generic")
        return crash_bundle.materialize(
            self.results, agent, testcase, sanitizer, "asan", mode, **kwargs,
        )

    def promote(self, crash_id: str) -> None:
        receipt = validation_receipt.write(
            self.results / "crashes" / crash_id, kind="crash", state="reportable",
            target_revision="rev", target_config_sha256="cfg", attacker_controls=["bytes"],
        )
        self.assertIsNotNone(receipt)

    def test_same_state_files_until_the_first_bundle_is_promoted(self) -> None:
        status, first = self.file("1", "a", trace())
        self.assertEqual(status, "FILED")
        # Pending review: the second agent's evidence may still be needed.
        status, second = self.file("2", "b", trace())
        self.assertEqual(status, "FILED")
        self.assertNotEqual(first, second)
        self.promote(first)
        status, duplicate = self.file("3", "c", trace())
        self.assertEqual((status, duplicate), ("DUP-STATE", first))
        self.assertEqual(
            sorted(p.name for p in (self.results / "crashes").glob("CRASH-*")),
            [first, second],
        )

    def test_a_different_primitive_or_frame_is_a_new_state(self) -> None:
        _, first = self.file("1", "a", trace())
        self.promote(first)
        self.assertEqual(self.file("2", "b", trace(kind="heap-use-after-free"))[0], "FILED")
        self.assertEqual(self.file("2", "c", trace(line=25))[0], "FILED")

    def test_a_different_access_direction_is_a_new_metric_state(self) -> None:
        _, first = self.file("1", "a", trace(access="READ"))
        self.promote(first)
        self.assertEqual(
            self.file("2", "b", trace(access="READ")),
            ("DUP-STATE", first),
        )
        self.assertEqual(self.file("2", "c", trace(access="WRITE"))[0], "FILED")

    def test_a_different_probe_route_keeps_its_own_evidence(self) -> None:
        _, first = self.file("1", "a", trace())
        self.promote(first)
        self.assertEqual(self.file("2", "b", trace()), ("DUP-STATE", first))
        self.assertEqual(self.file("2", "c", trace(), mode="browser")[0], "FILED")
        self.assertEqual(self.file("2", "d", trace(), args=("--strict",))[0], "FILED")

    def test_a_lifetime_crash_is_keyed_on_its_free_site_too(self) -> None:
        _, first = self.file("1", "a", uaf_trace(free_line=60))
        self.promote(first)
        self.assertEqual(self.file("2", "b", uaf_trace(free_line=60)), ("DUP-STATE", first))
        # Same use site, different free: a distinct defect and cluster row.
        self.assertEqual(self.file("2", "c", uaf_trace(free_line=75))[0], "FILED")
        state = crash_bundle.bundle_crash_state(self.results / "crashes" / first)
        self.assertEqual(state[1], "heap-use-after-free-READ")
        self.assertTrue(state[3] and state[3][0].startswith("app_release"))

    def test_an_edited_report_suspends_the_promoted_receipt(self) -> None:
        _, first = self.file("1", "a", trace())
        self.promote(first)
        self.assertEqual(self.file("2", "b", trace())[0], "DUP-STATE")
        report = self.results / "crashes" / first / "report.md"
        report.write_text(report.read_text() + "\nRevised after review.\n")
        self.assertEqual(self.file("2", "c", trace())[0], "FILED")

    def test_rejected_or_retained_bundles_never_absorb_a_new_reproducer(self) -> None:
        _, first = self.file("1", "a", trace())
        (self.results / "crashes" / first / "validation.json").write_text(
            json.dumps({"kind": "crash", "state": "not-reportable"}), encoding="utf-8",
        )
        self.assertEqual(self.file("2", "b", trace())[0], "FILED")

    def test_resume_lists_distinct_states_with_the_promoted_member(self) -> None:
        target = self.root / "target"
        (target / ".git").mkdir(parents=True)
        ctx = workqueue.Context(ROOT, target, "sample", self.results, "git")
        workqueue.init_state(ctx)
        _, first = self.file("1", "a", trace())
        _, second = self.file("2", "b", trace())
        _, other = self.file("2", "c", trace(line=25))
        self.promote(second)
        resume = workqueue.state_resume(ctx, "3", "generic", claim=False)
        self.assertIn("## Crash States Already Filed", resume)
        self.assertIn(f"- `{second}` (promoted): asan heap-buffer-overflow at app_parse", resume)
        self.assertNotIn(f"`{first}`", resume)
        self.assertNotIn(f"`{other}`", resume)

    def test_resume_does_not_treat_pending_evidence_as_taken(self) -> None:
        target = self.root / "target"
        (target / ".git").mkdir(parents=True)
        ctx = workqueue.Context(ROOT, target, "sample", self.results, "git")
        workqueue.init_state(ctx)
        _, pending = self.file("1", "a", trace())
        resume = workqueue.state_resume(ctx, "2", "generic", claim=False)
        self.assertNotIn("## Crash States Already Filed", resume)
        self.assertNotIn(f"`{pending}`", resume)

    def test_resume_flags_an_active_hypothesis_at_a_filed_site(self) -> None:
        target = self.root / "target"
        (target / ".git").mkdir(parents=True)
        ctx = workqueue.Context(ROOT, target, "sample", self.results, "git")
        workqueue.init_state(ctx)
        _, filed = self.file("1", "a", trace())
        self.promote(filed)
        def add(hid: str, site: str) -> None:
            workqueue.add_hypothesis(ctx, argparse.Namespace(
                agent="2", id=hid, card_id="", hypothesis="size math", file=site,
                input_shape="bytes", guard_gap="none", diagnostic="bounds",
                strategy="S7", status="PENDING",
            ))

        add("H-other", "src/parser.c:app_other:22")
        resume = workqueue.state_resume(ctx, "2", "generic", claim=False)
        self.assertIn("- ID: `H-other`", resume)
        self.assertNotIn("Already filed at this site", resume)
        workqueue.update_hypothesis(ctx, "H-other", "DISCARDED", agent="2")
        add("H-other-path", "vendor/parser.c:app_parse:22")
        resume = workqueue.state_resume(ctx, "2", "generic", claim=False)
        self.assertIn("- ID: `H-other-path`", resume)
        self.assertNotIn("Already filed at this site", resume)
        workqueue.update_hypothesis(ctx, "H-other-path", "DISCARDED", agent="2")
        add("H-same", "src/parser.c:app_parse:22")
        resume = workqueue.state_resume(ctx, "2", "generic", claim=False)
        self.assertIn("- ID: `H-same`", resume)
        self.assertIn(f"- Already filed at this site: `{filed}` (promoted): asan heap-buffer-overflow at app_parse", resume)
        self.assertIn("Continue if this hypothesis predicts a different crash state", resume)

    def test_resume_omits_the_section_without_crashes(self) -> None:
        target = self.root / "target"
        (target / ".git").mkdir(parents=True)
        ctx = workqueue.Context(ROOT, target, "sample", self.results, "git")
        workqueue.init_state(ctx)
        self.assertNotIn("Crash States Already Filed", workqueue.state_resume(ctx, "1", "generic", claim=False))

    def test_expansion_skips_a_seed_whose_state_was_already_expanded(self) -> None:
        _, first = self.file("1", "a", trace())
        _, repeat = self.file("2", "b", trace())
        _, other = self.file("2", "c", trace(line=25))
        (self.results / "crashes" / first / ".cluster_expanded").write_text("expanded\n")
        (self.results / "state" / ".cluster-expand-backlog-done").write_text("done\n")
        runtime = SimpleNamespace(
            results=self.results, target_root=self.root / "target", num_agents=2,
            root=ROOT, target_slug="sample", repo_type="git", index=self.root / "index.log",
            config=SimpleNamespace(attacker_controls=["bytes"]),
        )
        with mock.patch.object(
            triage, "cluster_expansion_decisions",
            side_effect=lambda dirs, _t, **_k: {d: [] for d in dirs},
        ) as decision:
            counts = audit_runner.expand_new_crash_clusters(runtime)
        considered = [d.name for call in decision.call_args_list for d in call.args[0]]
        self.assertEqual(considered, [other])
        self.assertEqual(counts["expanded"], 1)
        self.assertTrue((self.results / "crashes" / repeat / ".cluster_expanded").is_file())

    def test_same_tick_duplicates_share_one_seed_and_stay_retryable(self) -> None:
        _, first = self.file("1", "a", trace())
        _, repeat = self.file("2", "b", trace())
        (self.results / "state" / ".cluster-expand-backlog-done").write_text("done\n")
        runtime = SimpleNamespace(
            results=self.results, target_root=self.root / "target", num_agents=2,
            root=ROOT, target_slug="sample", repo_type="git", index=self.root / "index.log",
            config=SimpleNamespace(attacker_controls=["bytes"]),
        )
        crashes = self.results / "crashes"
        with mock.patch.object(
            triage, "cluster_expansion_decisions",
            side_effect=lambda dirs, _t, **_k: {d: None for d in dirs},
        ) as unavailable:
            audit_runner.expand_new_crash_clusters(runtime)
        self.assertEqual([d.name for d in unavailable.call_args[0][0]], [first])
        # The representative's decision never came back: neither bundle is
        # marked, so the state is still expanded on a later pass.
        self.assertFalse((crashes / first / ".cluster_expanded").exists())
        self.assertFalse((crashes / repeat / ".cluster_expanded").exists())
        runtime.cluster_expansion_attempted = set()
        with mock.patch.object(
            triage, "cluster_expansion_decisions",
            side_effect=lambda dirs, _t, **_k: {d: [] for d in dirs},
        ) as decided:
            counts = audit_runner.expand_new_crash_clusters(runtime)
        self.assertEqual([d.name for d in decided.call_args[0][0]], [first])
        self.assertEqual(counts["expanded"], 1)
        self.assertTrue((crashes / first / ".cluster_expanded").is_file())
        self.assertTrue((crashes / repeat / ".cluster_expanded").is_file())


if __name__ == "__main__":
    unittest.main()
