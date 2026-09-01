#!/usr/bin/env python3
"""Precision, recall, attribution, manifest, and rendering coverage."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
COMMAND = ROOT / "lib" / "benchmark.py"
MANIFEST = ROOT / "output" / "canary" / ".ground-truth.json"
sys.path.insert(0, str(ROOT / "lib"))

import benchmark
import validation_receipt


class BenchmarkScoringTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="benchmark-score-")
        self.root = Path(self.temporary.name)
        self.pool = self.root / "pool"
        self.members = self.root / "pool-members.json"
        crashes = (
            ("CRASH-0001", "render_cell", "heap-buffer-overflow", "harness"),
            ("CRASH-0002", "format_line", "stack-buffer-overflow", "harness"),
            ("CRASH-0003", "recycle_entry", "heap-use-after-free", "model-direct"),
            ("CRASH-0004", "pack_field", "ABRT", "model-direct"),
            ("CRASH-0005", "app_helper", "heap-buffer-overflow", "harness"),
        )
        member_rows = {}
        for crash_id, symbol, diagnostic, condition in crashes:
            self.make_crash(self.pool, crash_id, symbol, diagnostic)
            member_rows[crash_id] = condition
        missing = self.pool / "crashes" / "CRASH-0006"
        missing.mkdir()
        (missing / "report.md").write_text("# prose-only report\n")
        member_rows["CRASH-0006"] = "harness"
        self.members.write_text(json.dumps({"crashes": member_rows}) + "\n")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def make_crash(
        self, run, crash_id, symbol, diagnostic, extra="", access="WRITE",
    ):
        crash = run / "crashes" / crash_id
        crash.mkdir(parents=True)
        (crash / "sanitizer.txt").write_text(
            f"==42==ERROR: AddressSanitizer: {diagnostic} on address 0x602000000010\n"
            f"{access} of size 64 at 0x602000000010 thread T0\n"
            "    #0 0x0000 in __asan_memcpy\n"
            f"    #1 0x0000 in {symbol} sample.c:42\n{extra}",
            encoding="utf-8",
        )
        return crash

    def score(self, run, manifest=MANIFEST, members=None, conditions=None):
        output = self.root / (run.name + "-score-" + str(len(list(self.root.glob("*-score-*")))) + ".json")
        args = [sys.executable, str(COMMAND), "score", str(run),
                "--ground-truth", str(manifest), "--out", str(output)]
        if members is not None:
            args.extend(("--members", str(members)))
        if conditions is not None:
            args.extend(("--conditions", conditions))
        proc = subprocess.run(args, capture_output=True, text=True)
        return proc, json.loads(output.read_text()) if output.is_file() else None

    def test_overall_and_condition_scoring(self) -> None:
        self.assertTrue(MANIFEST.is_file())
        proc, score = self.score(self.pool, members=self.members)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        overall = score["overall"]
        self.assertEqual(overall["recall"], 1.0)
        self.assertEqual(overall["precision"], 0.6)
        self.assertEqual(overall["confirmed_crashes"], 5)
        self.assertEqual(overall["true_positive_crashes"], 3)
        self.assertEqual(overall["false_positive_crashes"], 2)
        self.assertEqual(overall["false_positive_traps_fired"], ["debug-only-assert"])
        self.assertEqual(overall["unexpected_crashes"], ["CRASH-0005"])
        self.assertEqual(overall["missed"], [])
        harness = score["by_condition"]["harness"]
        self.assertEqual(harness["recall"], 0.6667)
        self.assertEqual(harness["precision"], 0.6667)
        self.assertEqual(harness["false_positive_crashes"], 1)
        direct = score["by_condition"]["model-direct"]
        self.assertEqual(direct["recall"], 0.3333)
        self.assertEqual(direct["precision"], 0.5)
        self.assertEqual(direct["false_positive_traps_fired"], ["debug-only-assert"])
        _, explicit = self.score(
            self.pool, members=self.members, conditions="harness,model-direct,ablation"
        )
        zero = explicit["by_condition"]["ablation"]
        self.assertEqual(zero["recall"], 0.0)
        self.assertEqual(zero["confirmed_crashes"], 0)
        self.assertEqual(zero["missed"], ["heap-oob-write", "stack-oob-write", "use-after-free"])

    def make_finding(self, run, finding_id, function, condition=None):
        finding = run / "findings" / finding_id
        finding.mkdir(parents=True)
        (finding / "REPORT.md").write_text(
            f"# {finding_id}\n\n| Field | Value |\n| --- | --- |\n"
            f"| File | src/sample.c |\n| Function | {function} |\n| Line | 42 |\n\n"
            "## Summary\n\nA report.\n",
            encoding="utf-8",
        )
        validation_receipt.write(
            finding, kind="finding", state="reportable", detail="fixture",
            target_revision="rev", target_config_sha256="cfg",
        )
        return finding

    def test_findings_only_bugs_are_scored_from_confirmed_findings(self) -> None:
        manifest = {
            "target": "sampleproj",
            "planted_bugs": [
                {"id": "crash-bug", "kind": "real", "primitive": "heap-buffer-overflow",
                 "signature_symbol": "render_cell", "access": "WRITE"},
                {"id": "secret-leak", "kind": "real", "findings_only": True,
                 "primitive": "info-disclosure", "signature_symbol": "render_template"},
                {"id": "path-escape", "kind": "real", "findings_only": True,
                 "primitive": "path-traversal", "signature_symbol": "open_entry"},
            ],
            "false_positive_traps": [
                {"id": "json-config", "kind": "fp", "expected_outcome": "clean",
                 "signature_symbol": "parse_config"},
            ],
        }
        path = self.root / "gt.json"
        path.write_text(json.dumps(manifest))
        run = self.root / "findrun"
        self.make_finding(run, "FIND-0001-leak", "render_template")
        self.make_finding(run, "FIND-0002-trap", "parse_config")
        self.make_finding(run, "FIND-0003-novel", "app_other_func")
        unconfirmed = run / "findings" / "FIND-0004-pending"
        unconfirmed.mkdir()
        (unconfirmed / "REPORT.md").write_text("| Function | open_entry |\n")
        members = self.root / "find-members.json"
        members.write_text(json.dumps({"findings": {
            "FIND-0001-leak": "harness", "FIND-0002-trap": "model-direct",
            "FIND-0003-novel": "harness",
        }}))
        (run / "crashes").mkdir()
        proc, score = self.score(run, manifest=path, members=members,
                                 conditions="harness,model-direct")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        findings = score["findings"]["overall"]
        # The pending FIND is not confirmed, so open_entry stays missed.
        self.assertEqual(findings["detected"], ["secret-leak"])
        self.assertEqual(findings["missed"], ["path-escape"])
        self.assertEqual(findings["recall"], 0.5)
        self.assertEqual(findings["false_positive_traps_fired"], ["json-config"])
        self.assertEqual(findings["open_world_findings"], ["FIND-0003-novel"])
        # Precision counts traps against, and keeps open-world neutral.
        self.assertEqual(findings["precision"], 0.5)
        self.assertEqual(findings["confirmed_findings"], 3)
        harness = score["findings"]["by_condition"]["harness"]
        self.assertEqual((harness["recall"], harness["precision"]), (0.5, 1.0))
        direct = score["findings"]["by_condition"]["model-direct"]
        self.assertEqual((direct["recall"], direct["false_positive_findings"]), (0.0, 1))
        # The crash oracle is untouched by findings-only bugs.
        self.assertEqual(score["overall"]["real_total"], 1)
        rendered = "\n".join(benchmark._render_ground_truth(score))
        self.assertIn("Ground truth — findings", rendered)
        self.assertIn("| **overall** | 50% | 1/2 | path-escape | 50% | 3 | json-config | 1 |", rendered)
        rendered_only = "\n".join(benchmark._render_ground_truth(
            {"not_scored": "findings-only", "findings": score["findings"]}))
        self.assertIn("crashes not scored", rendered_only)
        self.assertIn("Ground truth — findings", rendered_only)

    def test_a_manifest_level_findings_only_flag_scores_every_bug(self) -> None:
        # Findings-only targets flag the manifest, not each bug; a trap in the
        # same function as a real bug is named as one the oracle cannot fire.
        manifest = {
            "target": "sampleproj", "findings_only": True,
            "planted_bugs": [
                {"id": "shell-escape", "kind": "real", "primitive": "command-injection",
                 "signature_symbol": "run_export"},
                {"id": "amplification", "kind": "real", "primitive": "resource-exhaustion",
                 "signature_symbol": "load_state"},
            ],
            "false_positive_traps": [
                {"id": "inert-reconstruction", "kind": "fp", "expected_outcome": "clean",
                 "signature_symbol": "load_state"},
                {"id": "json-config", "kind": "fp", "expected_outcome": "clean",
                 "signature_symbol": "parse_config"},
                # Refutes an abort crash's promotion, not a finding that the
                # release build lacks the check.
                {"id": "debug-assert", "kind": "fp", "expected_outcome": "abort",
                 "signature_symbol": "check_field"},
            ],
        }
        path = self.root / "gt-top.json"
        path.write_text(json.dumps(manifest))
        run = self.root / "toprun"
        self.make_finding(run, "FIND-0001-shell", "run_export")
        self.make_finding(run, "FIND-0002-state", "load_state")
        self.make_finding(run, "FIND-0003-check", "check_field")
        (run / "crashes").mkdir()
        proc, score = self.score(run, manifest=path)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        findings = score["findings"]["overall"]
        self.assertEqual(findings["real_total"], 2)
        self.assertEqual(findings["detected"], ["amplification", "shell-escape"])
        self.assertEqual(findings["false_positive_traps_fired"], [])
        self.assertEqual(findings["open_world_findings"], ["FIND-0003-check"])
        self.assertEqual(findings["traps_sharing_a_real_symbol"], ["inert-reconstruction"])
        rendered = "\n".join(benchmark._render_ground_truth(
            {"not_scored": "findings-only", "findings": score["findings"]}))
        self.assertIn("`inert-reconstruction`", rendered)

    def test_prose_caller_and_allocation_frames_cannot_spoof_attribution(self) -> None:
        spoof = self.root / "spoof"
        crash = self.make_crash(spoof, "SPOOF-0001", "app_other_func", "heap-buffer-overflow")
        (crash / "report.md").write_text("Root cause looks identical to render_cell.\n")
        _, score = self.score(spoof)
        self.assertEqual(score["overall"]["detected"], [])
        self.assertEqual(score["overall"]["recall"], 0.0)
        self.assertEqual(score["overall"]["unexpected_crashes"], ["SPOOF-0001"])
        caller = self.root / "caller"
        self.make_crash(
            caller, "CS-0001", "app_helper", "heap-buffer-overflow",
            "    #2 0x0000 in render_cell sample.c:40\n",
        )
        _, score = self.score(caller)
        self.assertEqual(score["overall"]["detected"], [])
        self.assertEqual(score["overall"]["unexpected_crashes"], ["CS-0001"])
        allocation = self.root / "allocation"
        self.make_crash(
            allocation, "AF-0001", "app_other_func", "heap-buffer-overflow",
            "0x1 is located after a region allocated by thread T0:\n"
            "    #0 0x0 in malloc\n    #1 0x0 in render_cell sample.c:40\n",
        )
        _, score = self.score(allocation)
        self.assertEqual(score["overall"]["detected"], [])
        self.assertEqual(score["overall"]["unexpected_crashes"], ["AF-0001"])

    def test_report_only_and_non_diagnostic_artifacts_do_not_inflate_recall(self) -> None:
        report_only = self.root / "report-only"
        crash = report_only / "crashes" / "RO-0001"
        crash.mkdir(parents=True)
        (crash / "report.md").write_text(
            "Observed under AddressSanitizer:\n"
            "==3==ERROR: AddressSanitizer: heap-buffer-overflow\n"
            "    #1 0x0 in render_cell sample.c:40\n"
        )
        _, score = self.score(report_only)
        overall = score["overall"]
        self.assertEqual(overall["detected"], [])
        self.assertEqual(overall["recall"], 0.0)
        self.assertEqual(overall["unattributed_crashes"], ["RO-0001"])
        self.assertEqual(overall["confirmed_crashes"], 1)
        self.assertEqual(overall["precision"], 0.0)
        empty_san = self.root / "empty-san"
        crash = empty_san / "crashes" / "ES-0001"
        crash.mkdir(parents=True)
        (crash / "sanitizer.txt").write_text("build log: no errors, exit 0\n")
        _, score = self.score(empty_san)
        self.assertEqual(score["overall"]["confirmed_crashes"], 0)

    def test_rust_mangled_frame_attributes_to_plain_symbol(self) -> None:
        # A Rust ASan frame carries a v0-mangled symbol with an unstable crate
        # hash; the scorer must still credit the plain signature_symbol.
        run = self.root / "rust"
        crash = run / "crashes" / "R-0001"
        crash.mkdir(parents=True)
        (crash / "sanitizer.txt").write_text(
            "==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x60\n"
            "READ of size 1 at 0x60 thread T0\n"
            "    #0 0x0 in __asan_memcpy\n"
            "    #1 0x0 in _RNvNtCs9a5x3Hu2sLi_11sample_rust9reportkit10sum_window+0x1b0\n",
            encoding="utf-8",
        )
        manifest = self.root / "rust-gt.json"
        manifest.write_text(json.dumps({"language": "rust", "planted_bugs": [
            {"id": "oob", "primitive": "heap-buffer-overflow", "signature_symbol": "sum_window"}
        ]}), encoding="utf-8")
        _, score = self.score(run, manifest=manifest)
        self.assertEqual(score["overall"]["detected"], ["oob"])
        self.assertEqual(score["overall"]["recall"], 1.0)

    def test_cpp_frame_is_not_reduced_to_a_colliding_leaf_symbol(self) -> None:
        # A C++ crash at ns::Class::parse (or its Itanium mangling) must NOT be
        # credited to a ground-truth signature_symbol "parse" — Rust demangling
        # is scoped to Rust targets so it cannot manufacture a false positive.
        manifest = self.root / "cpp-gt.json"
        manifest.write_text(json.dumps({"language": "cpp", "planted_bugs": [
            {"id": "other", "primitive": "heap-buffer-overflow", "signature_symbol": "parse"}
        ]}), encoding="utf-8")
        for i, frame in enumerate(("ns::Class::parse", "_ZN2ns5Class5parseEv")):
            run = self.root / f"cpp-{i}"
            self.make_crash(run, f"C-{i}", frame, "heap-buffer-overflow")
            _, score = self.score(run, manifest=manifest)
            self.assertEqual(score["overall"]["detected"], [], frame)
            self.assertEqual(score["overall"]["unexpected_crashes"], [f"C-{i}"], frame)

    def test_rust_symbol_tail_reduces_rust_and_leaves_cpp_and_plain_frames(self) -> None:
        cases = {
            "_RNvNtCs9a5x3Hu2sLi_11sample_rust9reportkit10sum_window+0x1b0": "sum_window",
            "_RNvNtCs9a5x3Hu2sLi_11sample_rust9reportkit10pack_table": "pack_table",
            "sample_rust::reportkit::sum_window": "sum_window",
            "_ZN11sample_rust9reportkit10sum_window17h0123456789abcdefE": "sum_window",  # legacy Rust
            "rbundle::decode::h0123456789abcdef": "decode",
            "_ZN2ns5Class5parseEv": "",  # plain C++ Itanium (no Rust hash) — untouched
            "handle_array": "",          # plain C frame — left untouched
            "main.mergeTallies.func1": "",  # Go frame — left untouched
        }
        for frame, expected in cases.items():
            with self.subTest(frame=frame):
                self.assertEqual(benchmark._rust_symbol_tail(frame), expected)

    def test_go_data_race_attributes_via_race_primitive(self) -> None:
        # Go's race detector prints "WARNING: DATA RACE" (no ThreadSanitizer
        # primitive line); the scorer maps it to the data-race primitive and
        # keys on the goroutine-closure frame.
        run = self.root / "go"
        crash = run / "crashes" / "G-0001"
        crash.mkdir(parents=True)
        (crash / "sanitizer.txt").write_text(
            "==================\n"
            "WARNING: DATA RACE\n"
            "Write at 0x00c0 by goroutine 7:\n"
            "  main.mergeTallies.func1()\n"
            "      sample-go/reportkit.go:154 +0x90\n",
            encoding="utf-8",
        )
        manifest = self.root / "go-gt.json"
        manifest.write_text(json.dumps({"planted_bugs": [
            {"id": "race", "primitive": "data-race", "signature_symbol": "main.mergeTallies.func1"}
        ]}), encoding="utf-8")
        _, score = self.score(run, manifest=manifest)
        self.assertEqual(score["overall"]["detected"], ["race"])
        self.assertEqual(score["overall"]["recall"], 1.0)

    def test_findings_only_bug_excluded_from_crash_recall(self) -> None:
        # A hybrid target plants a sanitizer bug plus a findings-only bug that
        # never crashes; the latter must not sit permanently "missed" in the
        # crash-recall denominator.
        run = self.root / "hybrid"
        self.make_crash(run, "H-0001", "pack_cells", "heap-buffer-overflow")
        manifest = self.root / "hybrid-gt.json"
        manifest.write_text(json.dumps({"planted_bugs": [
            {"id": "native", "primitive": "heap-buffer-overflow", "signature_symbol": "pack_cells"},
            {"id": "traversal", "findings_only": True, "primitive": "path-traversal",
             "signature_symbol": "read_asset"},
        ]}), encoding="utf-8")
        _, score = self.score(run, manifest=manifest)
        self.assertEqual(score["overall"]["detected"], ["native"])
        self.assertEqual(score["overall"]["recall"], 1.0)
        self.assertEqual(score["overall"]["missed"], [])

    def test_alternate_runtime_signature_credits_the_same_source_bug(self) -> None:
        run = self.root / "alternate"
        crash = self.make_crash(run, "ALT-0001", "cleanup", "double-free")
        sanitizer = crash / "sanitizer.txt"
        sanitizer.write_text(sanitizer.read_text().replace(
            "AddressSanitizer: double-free",
            "AddressSanitizer: attempting double-free",
        ))
        manifest = self.root / "alternate-gt.json"
        manifest.write_text(json.dumps({"planted_bugs": [{
            "id": "lifetime",
            "primitive": "heap-use-after-free",
            "signature_symbol": "consume",
            "alternate_signatures": [{
                "primitive": "double-free", "signature_symbol": "cleanup",
            }],
        }]}) + "\n")
        _, score = self.score(run, manifest=manifest)
        self.assertEqual(score["overall"]["detected"], ["lifetime"])
        self.assertEqual(score["overall"]["recall"], 1.0)
        self.assertEqual(score["overall"]["precision"], 1.0)

    def test_multi_report_attribution_does_not_splice_faults(self) -> None:
        run = self.root / "multi-report"
        crash = self.make_crash(
            run, "MULTI-0001", "consume", "heap-use-after-free", access="READ",
        )
        with (crash / "sanitizer.txt").open("a", encoding="utf-8") as output:
            output.write(
                "SUMMARY: AddressSanitizer: heap-use-after-free sample.c:42 in consume\n"
                "\n==43==ERROR: AddressSanitizer: double-free on address 0x602000000020\n"
                "WRITE of size 8 at 0x602000000020 thread T0\n"
                "    #0 0x0000 in cleanup sample.c:77\n"
                "SUMMARY: AddressSanitizer: double-free sample.c:77 in cleanup\n"
            )
        manifest = self.root / "multi-report-gt.json"
        manifest.write_text(json.dumps({"planted_bugs": [
            {
                "id": "first-fault", "primitive": "heap-use-after-free",
                "signature_symbol": "consume",
            },
            {
                "id": "spliced-non-fault", "primitive": "double-free",
                "signature_symbol": "consume",
            },
        ]}) + "\n", encoding="utf-8")

        _, score = self.score(run, manifest=manifest)

        self.assertEqual(score["overall"]["detected"], ["first-fault"])

    def test_access_qualified_alternates_disambiguate_inlined_crashes(self) -> None:
        run = self.root / "inlined"
        self.make_crash(
            run, "INLINE-READ", "run", "heap-buffer-overflow", access="READ",
        )
        self.make_crash(
            run, "INLINE-WRITE", "run", "heap-buffer-overflow", access="WRITE",
        )
        manifest = self.root / "inlined-gt.json"
        manifest.write_text(json.dumps({"planted_bugs": [
            {
                "id": "read-bug", "primitive": "out-of-bounds-read",
                "signature_symbol": "sumWindow", "alternate_signatures": [{
                    "primitive": "heap-buffer-overflow",
                    "signature_symbol": "run", "access": "READ",
                }],
            },
            {
                "id": "write-bug", "primitive": "out-of-bounds-write",
                "signature_symbol": "packTable", "alternate_signatures": [{
                    "primitive": "heap-buffer-overflow",
                    "signature_symbol": "run", "access": "WRITE",
                }],
            },
        ]}) + "\n")
        _, score = self.score(run, manifest=manifest)
        self.assertEqual(score["overall"]["detected"], ["read-bug", "write-bug"])
        self.assertEqual(score["overall"]["recall"], 1.0)
        self.assertEqual(score["overall"]["precision"], 1.0)

    def test_trap_requires_the_expected_non_memory_diagnostic(self) -> None:
        trap = self.root / "trap"
        self.make_crash(trap, "TF-0001", "pack_field", "heap-buffer-overflow")
        _, score = self.score(trap)
        self.assertEqual(score["overall"]["unexpected_crashes"], ["TF-0001"])
        self.assertEqual(score["overall"]["false_positive_traps_fired"], [])

    def test_manifest_validation_rejects_missing_duplicate_and_invalid_keys(self) -> None:
        manifests = (
            {"planted_bugs": [{"id": "x", "primitive": "heap-buffer-overflow"}]},
            {"planted_bugs": [{"id": "x", "kind": "reel", "primitive": "heap-buffer-overflow",
                                "signature_symbol": "render_cell"}]},
            {"planted_bugs": [
                {"id": "a", "primitive": "heap-buffer-overflow", "signature_symbol": "render_cell"},
                {"id": "b", "primitive": "heap-buffer-overflow", "signature_symbol": "render_cell"},
            ]},
            {"planted_bugs": [
                {"id": "x", "primitive": "heap-buffer-overflow", "signature_symbol": "render_cell",
                 "findings_only": "false"},
            ]},
            {"planted_bugs": [
                {"id": "x", "primitive": "heap-buffer-overflow", "signature_symbol": "render_cell",
                 "alternate_signatures": "not-a-list"},
            ]},
            {"planted_bugs": [
                {"id": "x", "primitive": "heap-buffer-overflow", "signature_symbol": "render_cell",
                 "alternate_signatures": [{"primitive": "double-free"}]},
            ]},
            {"planted_bugs": [
                {"id": "a", "primitive": "one", "signature_symbol": "a",
                 "alternate_signatures": [{"primitive": "heap-buffer-overflow",
                                            "signature_symbol": "run"}]},
                {"id": "b", "primitive": "two", "signature_symbol": "b",
                 "alternate_signatures": [{"primitive": "heap-buffer-overflow",
                                            "signature_symbol": "run", "access": "READ"}]},
            ]},
            {"planted_bugs": [
                {"id": "x", "primitive": "heap-buffer-overflow", "signature_symbol": "render_cell",
                 "alternate_signatures": [{"primitive": "double-free",
                                            "signature_symbol": "cleanup", "access": "EXEC"}]},
            ]},
        )
        for number, payload in enumerate(manifests):
            with self.subTest(number=number):
                manifest = self.root / f"bad-{number}.json"
                manifest.write_text(json.dumps(payload) + "\n")
                proc, score = self.score(self.pool, manifest=manifest)
                self.assertEqual(proc.returncode, 1)
                self.assertIsNone(score)

    def test_committed_sample_manifests_validate(self) -> None:
        manifests = sorted((ROOT / "output" / "samples").glob(
            "sample-*/.ground-truth.json"
        ))
        self.assertEqual(len(manifests), 17)
        for manifest in manifests:
            with self.subTest(manifest=manifest.parent.name):
                payload = json.loads(manifest.read_text())
                self.assertEqual(benchmark.manifest_errors(payload), [])

    def test_every_sample_can_actually_run_the_sanitizer_it_declares(self) -> None:
        """A declared sanitizer with nothing to run is an inert fixture.

        `[sanitizer] enabled` and the binary that serves it are set in
        different places, and a per-sanitizer binary written at the top level
        of target.toml parses fine and loads as the empty string — the target
        then measures nothing while still counting as a planted-bug fixture.
        Ask the loader, not the file, so the check follows the same path the
        harness takes. A sanitizer driven through `[runner]` has no binary of
        its own and answers with the runner instead.
        """
        sys.path.insert(0, str(ROOT / "lib"))
        import target_config  # noqa: PLC0415 - lives beside the harness, not the test

        manifests = sorted((ROOT / "output" / "samples").glob(
            "sample-*/.ground-truth.json"
        ))
        self.assertTrue(manifests)
        for manifest in manifests:
            config_path = manifest.parent / "target.toml"
            with self.subTest(sample=manifest.parent.name):
                self.assertTrue(config_path.is_file())
                config = target_config.Config()
                target_config.load_toml_into(config, config_path)
                for sanitizer in config.sanitizers_enabled:
                    self.assertTrue(
                        config.sanitizer_bin(sanitizer) or config.runner_bin,
                        f"{manifest.parent.name} enables {sanitizer} but the "
                        "loader finds neither a binary for it nor a runner",
                    )

    def test_aggregate_and_rendering_handle_not_scored_states_explicitly(self) -> None:
        no_pool = self.root / "no-pool"
        no_pool.mkdir()
        (no_pool / "run.json").write_text(
            json.dumps({"target": "canary", "backend": "demo", "runid": "np"}) + "\n"
        )
        report = no_pool / "report.json"
        proc = subprocess.run(
            [sys.executable, str(COMMAND), "aggregate", str(no_pool), "--out", str(report)],
            capture_output=True, text=True,
        )
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertNotIn("ground_truth_scoring", json.loads(report.read_text()))
        self.assertIn("not scored", "\n".join(benchmark._render_ground_truth(None, ["oops"])))
        rendered = "\n".join(benchmark._render_ground_truth({"not_scored": "findings-only"}))
        self.assertIn("not scored", rendered.casefold())
        self.assertNotIn("precision / recall", rendered.casefold())

    def test_canonical_artifacts_and_empty_run_metrics(self) -> None:
        canonical = self.root / "canonical"
        self.make_crash(canonical, "DISC-0001", "render_cell", "heap-buffer-overflow")
        self.make_crash(canonical, "DISC-0002", "format_line", "stack-buffer-overflow")
        _, score = self.score(canonical)
        self.assertEqual(score["overall"]["detected"], ["heap-oob-write", "stack-oob-write"])
        empty = self.root / "empty"
        (empty / "crashes").mkdir(parents=True)
        _, score = self.score(empty)
        self.assertEqual(score["overall"]["recall"], 0.0)
        self.assertIsNone(score["overall"]["precision"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
