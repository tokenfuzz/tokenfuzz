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

    def make_crash(self, run, crash_id, symbol, diagnostic, extra=""):
        crash = run / "crashes" / crash_id
        crash.mkdir(parents=True)
        (crash / "sanitizer.txt").write_text(
            f"==42==ERROR: AddressSanitizer: {diagnostic} on address 0x602000000010\n"
            "WRITE of size 64 at 0x602000000010 thread T0\n"
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
        )
        for number, payload in enumerate(manifests):
            with self.subTest(number=number):
                manifest = self.root / f"bad-{number}.json"
                manifest.write_text(json.dumps(payload) + "\n")
                proc, score = self.score(self.pool, manifest=manifest)
                self.assertEqual(proc.returncode, 1)
                self.assertIsNone(score)

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
