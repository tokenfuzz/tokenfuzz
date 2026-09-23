#!/usr/bin/env python3
"""Filing-time and expansion-time dedup of bundles that share one crash state."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
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
import telemetry  # noqa: E402
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

    def file_unchecked(self, agent: str, name: str, text: str, **kwargs) -> tuple[str, str]:
        """File past the state check: a bundle that landed before the rule, or a race."""
        with mock.patch.object(crash_bundle, "filed_duplicate", return_value=None):
            return self.file(agent, name, text, **kwargs)

    def promote(self, crash_id: str) -> None:
        directory = self.results / "crashes" / crash_id
        # Triage settles the class before any receipt; a receipt written over
        # a classless skeleton would lapse the moment the gate stamps it.
        triage._materialize_crash_class(directory)
        receipt = validation_receipt.write(
            directory, kind="crash", state="reportable",
            target_revision="rev", target_config_sha256="cfg", attacker_controls=["bytes"],
        )
        self.assertIsNotNone(receipt)

    def test_same_state_through_the_same_route_is_refused_once_filed(self) -> None:
        status, first = self.file("1", "a", trace())
        self.assertEqual(status, "FILED")
        # Still under review: the second agent's reproducer would earn the
        # same verdict through the same route, so it is refused at once.
        self.assertEqual(self.file("2", "b", trace()), ("DUP-STATE", first))
        self.assertEqual(crash_bundle.bundle_review_label(
            self.results / "crashes" / first), "under review")
        self.promote(first)
        self.assertEqual(self.file("3", "c", trace()), ("DUP-STATE", first))
        self.assertEqual(crash_bundle.bundle_review_label(
            self.results / "crashes" / first), "promoted")
        # An edited report suspends the receipt, not the filing refusal.
        report = self.results / "crashes" / first / "report.md"
        report.write_text(report.read_text() + "\nRevised after review.\n")
        self.assertEqual(self.file("3", "d", trace()), ("DUP-STATE", first))
        self.assertEqual(
            sorted(p.name for p in (self.results / "crashes").glob("CRASH-*")),
            [first],
        )

    def test_truncated_first_report_uses_the_later_complete_fault(self) -> None:
        partial = (
            "==1==ERROR: AddressSanitizer: heap-buffer-overflow\n"
            "READ of size 1 at 0x1 thread T0\n"
        )
        complete = (
            "==2==ERROR: AddressSanitizer: heap-buffer-overflow\n"
            "WRITE of size 1 at 0x2 thread T0\n"
            "#0 0x1 in app_store src/app.c:102\n"
            "#1 0x2 in dispatch src/main.c:12\n"
            "SUMMARY: AddressSanitizer: heap-buffer-overflow\n"
        )
        self.assertEqual(crash_bundle.crash_state(partial + complete),
                         crash_bundle.crash_state(complete))

    def test_an_exploration_probe_finds_the_owner_filing_would_refuse_for(self) -> None:
        harness = self.root / "harness.c"
        harness.write_text("int main(void) { return 0; }\n", encoding="utf-8")
        status, first = self.file("1", "a", trace(), harness=harness, args=("-x",))
        self.assertEqual(status, "FILED")
        repeat = self.root / "repeat.txt"
        repeat.write_text(trace(), encoding="utf-8")
        same = crash_bundle.probe_route("asan", "generic", harness, ("-x",))
        self.assertEqual(crash_bundle.filed_duplicate(self.results, repeat, same), first)
        # A single run through another argv contract is not that bundle's.
        other = crash_bundle.probe_route("asan", "generic", harness, ())
        self.assertIsNone(crash_bundle.filed_duplicate(self.results, repeat, other))

    def test_a_promoted_owner_is_preferred_over_a_pending_one(self) -> None:
        state = crash_bundle.crash_state(trace())
        route = ("asan", "generic", "", (), "", "")
        filed = [
            crash_bundle.FiledCrashState("CRASH-001-1", state, promoted=False),
            crash_bundle.FiledCrashState(
                "CRASH-002-2", state, promoted=True, receipt_state="reportable",
            ),
        ]
        with mock.patch.object(crash_bundle, "bundle_crash_route", return_value=route):
            self.assertEqual(
                crash_bundle.state_owner(self.results, state, route, filed=filed),
                "CRASH-002-2",
            )
            self.assertEqual(
                crash_bundle.state_owner(
                    self.results, state, route, filed=filed[:1], promoted_only=True,
                ),
                None,
            )
            self.assertEqual(
                crash_bundle.state_owner(self.results, state, route, filed=filed[:1]),
                "CRASH-001-1",
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

    def test_a_retained_bundle_absorbs_and_a_rejected_one_does_not(self) -> None:
        _, first = self.file("1", "a", trace())
        (self.results / "crashes" / first / "validation.json").write_text(
            json.dumps({"kind": "crash", "state": "not-reportable"}), encoding="utf-8",
        )
        self.assertEqual(self.file("2", "b", trace()), ("DUP-STATE", first))
        rejected = self.results / "crashes-rejected"
        rejected.mkdir()
        (self.results / "crashes" / first).rename(rejected / first)
        self.assertEqual(self.file("2", "c", trace())[0], "FILED")

    def test_resume_lists_distinct_states_with_the_promoted_member(self) -> None:
        target = self.root / "target"
        (target / ".git").mkdir(parents=True)
        ctx = workqueue.Context(ROOT, target, "sample", self.results, "git")
        workqueue.init_state(ctx)
        _, first = self.file("1", "a", trace())
        _, second = self.file("2", "b", trace(), mode="browser")
        _, other = self.file("2", "c", trace(line=25))
        self.promote(second)
        resume = workqueue.state_resume(ctx, "3", "generic", claim=False)
        self.assertIn("## Crash States Already Filed", resume)
        self.assertIn(f"- `{second}` (promoted): asan heap-buffer-overflow at app_parse", resume)
        self.assertIn(f"- `{other}` (under review): asan heap-buffer-overflow at app_parse", resume)
        self.assertNotIn(f"`{first}`", resume)
        self.assertIn("whether or not its review has finished", resume)

    def test_resume_lists_pending_evidence_as_under_review(self) -> None:
        target = self.root / "target"
        (target / ".git").mkdir(parents=True)
        ctx = workqueue.Context(ROOT, target, "sample", self.results, "git")
        workqueue.init_state(ctx)
        _, pending = self.file("1", "a", trace())
        resume = workqueue.state_resume(ctx, "2", "generic", claim=False)
        self.assertIn("## Crash States Already Filed", resume)
        self.assertIn(f"- `{pending}` (under review):", resume)

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

    def test_add_hyp_names_what_already_holds_its_site(self) -> None:
        target = self.root / "target"
        (target / ".git").mkdir(parents=True)
        ctx = workqueue.Context(ROOT, target, "sample", self.results, "git")
        workqueue.init_state(ctx)

        def add(agent: str, hid: str, site: str) -> dict:
            return workqueue.add_hypothesis(ctx, argparse.Namespace(
                agent=agent, id=hid, card_id="", hypothesis=f"size math {hid}", file=site,
                input_shape="bytes", guard_gap="none", diagnostic="bounds",
                strategy="S7", status="PENDING",
            ))

        def advise(row: dict) -> list[str]:
            return workqueue.site_overlap_advisory(ctx, row)

        add("1", "H-found", "src/parser.c:app_check:198")
        workqueue.update_hypothesis(ctx, "H-found", "FIND-001", agent="1")
        add("1", "H-dropped", "src/parser.c:app_check:190")
        workqueue.update_hypothesis(ctx, "H-dropped", "DISCARDED", agent="1")
        self.assertEqual(advise(add("2", "H-elsewhere", "src/parser.c:app_other:5")), [])
        # Distinct files that share a suffix are distinct sites.
        self.assertEqual(advise(add("2", "H-vendor", "vendor/src/parser.c:app_check:198")), [])
        self.assertEqual(advise(add("2", "H-sibling", "vendor/parser.c:app_check:198")), [])
        # The same file spelled absolute or repo-prefixed is the same site.
        (target / "src").mkdir()
        (target / "src" / "parser.c").write_text("int app_check;\n")
        for hid, spelling in (
            ("H-absolute", f"{target}/src/parser.c:app_check:197"),
            ("H-prefixed", "target/src/parser.c:app_check:199"),
        ):
            advisory = advise(add("2", hid, spelling))
            self.assertTrue(any("`H-found` (agent 1, FIND-001)" in line for line in advisory), (hid, advisory))
            self.assertFalse(any("H-dropped" in line for line in advisory), advisory)
            self.assertIn(f"--id {hid} --status <that CRASH/FIND id>", advisory[-1])
            self.assertIn("Compare mechanisms first", advisory[-1])

        # Two agents opening one site at once: only the newer row yields.
        first = add("3", "H-live", "src/parser.c:app_live:4")
        second = add("2", "H-late", "src/parser.c:app_live:6")
        self.assertEqual(advise(first), [])
        advisory = advise(second)
        self.assertTrue(any("`H-live` (agent 3, PENDING)" in line for line in advisory), advisory)
        self.assertIn("--id H-late --status DISCARDED", advisory[-1])

        # A package named like its target keeps its own directory.
        (target / "target").mkdir()
        (target / "target" / "api.py").write_text("x = 1\n")
        add("1", "H-pkg", "target/api.py:get:3")
        self.assertEqual(advise(add("2", "H-toplevel", "api.py:get:3")), [])
        self.assertTrue(advise(add("2", "H-pkg2", f"{target}/target/api.py:get:9")))

        # A lineless C++ method is its own site, not `Parser:` shared by all.
        add("3", "H-read", "src/codec.cc:Parser::read")
        self.assertEqual(advise(add("2", "H-write", "src/codec.cc:Parser::write")), [])
        self.assertTrue(advise(add("2", "H-read2", "src/codec.cc:Parser::read:40")))
        # A file at the target root is unambiguous once paths are anchored.
        add("1", "H-root", "valid.c:check_one:10")
        self.assertTrue(advise(add("2", "H-root2", "valid.c:check_one:12")))

        _, filed = self.file("1", "a", trace())
        advisory = advise(add("3", "H-crash", "src/parser.c:app_parse:20"))
        self.assertTrue(any(f"Already filed at this site: `{filed}`" in line for line in advisory), advisory)

    def test_resume_omits_the_section_without_crashes(self) -> None:
        target = self.root / "target"
        (target / ".git").mkdir(parents=True)
        ctx = workqueue.Context(ROOT, target, "sample", self.results, "git")
        workqueue.init_state(ctx)
        self.assertNotIn("Crash States Already Filed", workqueue.state_resume(ctx, "1", "generic", claim=False))

    def test_expansion_skips_a_seed_whose_state_was_already_expanded(self) -> None:
        _, first = self.file("1", "a", trace())
        _, repeat = self.file_unchecked("2", "b", trace())
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
        _, repeat = self.file_unchecked("2", "b", trace())
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

    def context(self) -> workqueue.Context:
        target = self.root / "target"
        (target / ".git").mkdir(parents=True, exist_ok=True)
        ctx = workqueue.Context(ROOT, target, "sample", self.results, "git")
        workqueue.init_state(ctx)
        return ctx

    def add(self, ctx: workqueue.Context, agent: str, hid: str, site: str, status: str = "PENDING") -> None:
        workqueue.add_hypothesis(ctx, argparse.Namespace(
            agent=agent, id=hid, card_id="", hypothesis="size math", file=site,
            input_shape="bytes", guard_gap="none", diagnostic="bounds",
            strategy="S7", status=status,
        ))

    def gate(self, adjudicate=None) -> tuple[dict, list[list[str]]]:
        with mock.patch.object(
            triage, "_adjudicate_crash_dirs",
            side_effect=adjudicate or (lambda directories, **_kw: None),
        ) as reviewed:
            counts = triage.triage_crash_dirs(
                self.results, self.root / "target", "sample", ["bytes"], workers=1,
            )
        groups = [
            sorted(d.name for d in call.args[0])
            for call in reviewed.call_args_list if call.args[0]
        ]
        return counts, groups

    def duplicates(self) -> list[str]:
        root = self.results / "crashes" / triage.DUPLICATE_CRASHES_DIR
        return sorted(p.name for p in root.glob("CRASH-*")) if root.is_dir() else []

    def test_triage_folds_a_pending_duplicate_of_a_promoted_state(self) -> None:
        ctx = self.context()
        _, first = self.file("1", "a", trace())
        _, duplicate = self.file_unchecked("2", "b", trace())
        self.add(ctx, "2", "H-dup", "src/parser.c:app_parse:20", status=duplicate)
        self.promote(first)
        counts, groups = self.gate()
        self.assertEqual(counts["duplicate"], 1)
        self.assertEqual(self.duplicates(), [duplicate])
        self.assertFalse((self.results / "crashes" / duplicate).exists())
        self.assertNotIn(duplicate, [name for group in groups for name in group])
        note = (
            self.results / "crashes" / triage.DUPLICATE_CRASHES_DIR / duplicate / "duplicate-of.txt"
        ).read_text().splitlines()
        self.assertEqual(note[0], first)
        rows = {r["id"]: r for r in workqueue.read_jsonl(self.results / "state" / "hypotheses.jsonl")}
        self.assertEqual(rows["H-dup"]["status"], first)
        self.assertIn(f"Triage folded {duplicate} into {first}", rows["H-dup"]["note"])

    def test_same_pass_siblings_wait_for_the_representative_s_verdict(self) -> None:
        _, first = self.file("1", "a", trace())
        _, second = self.file_unchecked("2", "b", trace())
        _, other = self.file("2", "c", trace(line=25))

        def promote_first(directories, **_kw):
            for directory in directories:
                if directory.name == first:
                    self.promote(first)

        counts, groups = self.gate(promote_first)
        # One review settles the state; the sibling folds without a second.
        self.assertEqual(groups, [sorted([first, other])])
        self.assertEqual(counts["duplicate"], 1)
        self.assertEqual(self.duplicates(), [second])

    def test_an_unpromoted_representative_leaves_its_sibling_judged(self) -> None:
        _, first = self.file("1", "a", trace())
        _, second = self.file_unchecked("2", "b", trace())
        counts, groups = self.gate()
        self.assertEqual(groups, [[first], [second]])
        self.assertEqual(counts["duplicate"], 0)
        self.assertEqual(self.duplicates(), [])

    def test_a_different_route_is_reviewed_on_its_own(self) -> None:
        _, first = self.file("1", "a", trace())
        _, browser = self.file("2", "b", trace(), mode="browser")
        self.promote(first)
        counts, groups = self.gate()
        self.assertEqual(counts["duplicate"], 0)
        self.assertEqual(groups, [sorted([first, browser])])

    def test_two_promoted_bundles_are_never_folded_into_each_other(self) -> None:
        _, first = self.file("1", "a", trace())
        _, second = self.file_unchecked("2", "b", trace())
        self.promote(first)
        self.promote(second)
        counts, groups = self.gate()
        self.assertEqual(counts["duplicate"], 0)
        self.assertEqual(self.duplicates(), [])
        self.assertEqual(groups, [sorted([first, second])])

    def test_a_hand_filed_duplicate_without_a_probe_receipt_is_reviewed(self) -> None:
        _, first = self.file("1", "a", trace())
        self.promote(first)
        manual = self.results / "crashes" / "CRASH-001-manual"
        manual.mkdir()
        (manual / "sanitizer.txt").write_text(trace(), encoding="utf-8")
        (manual / "input.bin").write_bytes(b"manual")
        (manual / "report.md").write_text(
            "# Manual\n\nLocation: src/parser.c:app_parse:20\n\nTrigger source: bytes\n"
            "Caller contract: obeyed\n", encoding="utf-8",
        )
        counts, groups = self.gate()
        self.assertEqual(counts["duplicate"], 0)
        self.assertEqual(self.duplicates(), [])
        self.assertEqual(groups, [sorted([first, "CRASH-001-manual"])])

    def test_a_failed_state_update_rolls_the_bundle_back(self) -> None:
        ctx = self.context()
        _, duplicate = self.file_unchecked("2", "b", trace())
        self.add(ctx, "2", "H-dup", "src/parser.c:app_parse:20", status=duplicate)
        directory = self.results / "crashes" / duplicate
        with mock.patch.object(
            workqueue, "record_artifact_duplicate", side_effect=OSError("state unavailable"),
        ):
            with self.assertRaisesRegex(OSError, "state unavailable"):
                triage._fold_duplicate_crash(directory, self.results, "CRASH-001-1")
        self.assertTrue(directory.is_dir())
        self.assertEqual(self.duplicates(), [])

    def test_a_fold_closes_the_open_hypothesis_named_in_the_evidence_header(self) -> None:
        ctx = self.context()
        _, first = self.file("1", "a", trace())
        self.add(ctx, "2", "H-open", "src/parser.c:app_parse:20", status="INVESTIGATING")
        testcase = self.root / "b.bin"
        # Opaque inputs carry the hypothesis in structured probe provenance,
        # not by prepending a text header to the testcase bytes.
        testcase.write_bytes(b"opaque")
        sanitizer = self.root / "b.txt"
        sanitizer.write_text(trace(), encoding="utf-8")
        with mock.patch.object(crash_bundle, "filed_duplicate", return_value=None):
            status, duplicate = crash_bundle.materialize(
                self.results, "2", testcase, sanitizer, "asan", "generic", hypothesis="H-open",
            )
        self.assertEqual(status, "FILED")
        self.promote(first)
        counts, _groups = self.gate()
        self.assertEqual(counts["duplicate"], 1)
        rows = {r["id"]: r for r in workqueue.read_jsonl(self.results / "state" / "hypotheses.jsonl")}
        self.assertEqual(rows["H-open"]["status"], first)
        self.assertIn(f"Triage folded {duplicate} into {first}", rows["H-open"]["note"])

    def test_expansion_prompt_names_filed_lines_without_filtering(self) -> None:
        ctx = self.context()
        _, first = self.file("1", "a", trace())
        self.add(ctx, "2", "H-find", "src/other.c:app_other:7", status="FIND-001")
        prompts: list[str] = []

        def decide(_kind, _key, prompt, _timeout, **_kw):
            prompts.append(prompt)
            return {"items": [{"id": first, "rows": []}]}

        with mock.patch.object(triage.llm_decide, "llm_decide", side_effect=decide):
            triage.cluster_expansion_decisions(
                [self.results / "crashes" / first], self.root / "target",
            )
        self.assertEqual(len(prompts), 1)
        self.assertNotIn("Promoted crash signature frames", prompts[0])
        self.assertNotIn("src/other.c:app_other:7", prompts[0])
        self.promote(first)
        prompts.clear()
        with mock.patch.object(triage.llm_decide, "llm_decide", side_effect=decide):
            triage.cluster_expansion_decisions(
                [self.results / "crashes" / first], self.root / "target",
            )
        self.assertIn(f"- app_parse /src/parser.c:20 - {first}", prompts[0])
        self.assertNotIn("src/other.c:app_other:7", prompts[0])
        self.assertIn("A different primitive, object, or materially different route", prompts[0])

    def test_expansion_keeps_distinct_leads_at_a_filed_line(self) -> None:
        ctx = self.context()
        _, first = self.file("1", "a", trace())
        self.add(ctx, "2", "H-find", "src/other.c:app_other:7", status="FIND-001")
        rows = [
            {"file": "src/parser.c", "function": "app_parse", "line": 20,
             "hypothesis": "a different primitive at the crash line", "category": "type"},
            {"file": "src/other.c", "function": "ns::app_other", "line": 7,
             "hypothesis": "a distinct route to the finding line", "category": "state"},
            {"file": "src/parser.c", "function": "app_parse", "line": 31,
             "hypothesis": "a different line of the same function", "category": "bounds"},
        ]
        result = workqueue.add_cluster_hypotheses(ctx, first, rows, num_agents=2)
        self.assertEqual((result["added"], result["skipped"]), (3, 0))
        added = [
            r for r in workqueue.read_jsonl(self.results / "state" / "hypotheses.jsonl")
            if r.get("card_id") == "" and r["status"] == "PENDING"
        ]
        self.assertEqual(
            [r["file"] for r in added],
            [
                "src/parser.c:app_parse:20",
                "src/other.c:ns::app_other:7",
                "src/parser.c:app_parse:31",
            ],
        )


class ExplorationProbeTests(unittest.TestCase):
    def test_a_single_run_names_the_bundle_a_confirm_would_repeat(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target"
            results = root / "output/sample/codex/results"
            scratch = results / "scratch-1"
            logs = root / "logs"
            source = target / "src/app.c"
            scratch.mkdir(parents=True)
            logs.mkdir()
            source.parent.mkdir(parents=True)
            source.write_text("int app_parse(void) { return 0; }\n")
            tool = target / "build-asan/tool"
            tool.parent.mkdir()
            tool.write_text(
                "#!/bin/sh\n"
                "echo TESTCASE_EXECUTED\n"
                "echo 'ERROR: AddressSanitizer: heap-buffer-overflow on address 0x1' >&2\n"
                f"echo '    #0 0x1 in app_parse {source}:1' >&2\n"
                f"echo 'SUMMARY: AddressSanitizer: heap-buffer-overflow {source}:1 in app_parse' >&2\n"
                "exit 1\n",
                encoding="utf-8",
            )
            tool.chmod(0o755)
            (root / "output/sample/target.toml").write_text(
                'target="sample"\nbuild_system="cmake"\nbuild_widening=false\n'
                'asan_bin="build-asan/tool"\n',
                encoding="utf-8",
            )
            (results / ".session-env").write_text(
                f"RESULTS_DIR={results}\nTARGET_ROOT={target}\nTARGET_SLUG=sample\n"
                f"TARGET_REV=test\nLOGDIR={logs}\n"
            )
            environment = os.environ.copy()
            environment.update(PROBE_AUTO_ROUTE="0", LLM_DECIDE_DISABLE="1")
            environment.pop("AUDIT_BUILD_SUFFIX", None)

            def probe(name: str, *flags: str) -> str:
                testcase = scratch / f"{name}.txt"
                testcase.write_text(
                    f"// TARGET: src/app.c:app_parse:1\n// HYPOTHESIS-ID: H-{name}\n"
                    f"// CATEGORY: bounds\n// MODE: generic\n{name}\n"
                )
                completed = subprocess.run(
                    [str(ROOT / "bin/probe"), *flags, str(testcase)],
                    env=environment, capture_output=True, text=True, check=False,
                )
                return completed.stdout + completed.stderr

            first = probe("first", "--confirm")
            crashes = sorted((results / "crashes").glob("CRASH-*"))
            self.assertEqual(len(crashes), 1, first)
            output = probe("second")
            self.assertIn("verdict=CRASH", output)
            self.assertIn(f"CRASH STATE ALREADY FILED: this crash state and probe route are {crashes[0]}", output)
            self.assertEqual(len(list((results / "crashes").glob("CRASH-*"))), 1)
            # The owner is structured run state, not only a prose note.
            rows = [
                json.loads(line)
                for line in (results / "state" / "runs.jsonl").read_text().splitlines()
            ]
            self.assertEqual(
                [(row["hypothesis_id"], row.get("duplicate_of")) for row in rows],
                [("H-first", ""), ("H-second", crashes[0].name)],
            )
            execution = telemetry.execution_verdicts(results)
            self.assertEqual(
                (execution["filed_state_repeats"], execution["filed_state_checked"]), (1, 2),
            )
            (results / "state" / "runs.jsonl").write_text(
                json.dumps({"verdict": "CRASH"}) + "\n", encoding="utf-8",
            )
            self.assertIsNone(telemetry.execution_verdicts(results)["filed_state_repeats"])


if __name__ == "__main__":
    unittest.main()
