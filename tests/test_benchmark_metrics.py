#!/usr/bin/env python3
"""Harvest, aggregate, pooling, ledger, and cost-accounting regressions."""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "lib"))

import benchmark
import llm_usage


ASAN = "==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602\n"


class BenchmarkMetricsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="benchmark-metrics-")
        self.root = Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    @staticmethod
    def write_json(path: Path, value: object) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value) + "\n", encoding="utf-8")

    def make_cell(
        self,
        bench: Path,
        name: str,
        condition: str,
        replicate: int,
        crashes: int,
        *,
        status: str = "done",
        findings: int = 0,
        rejected_findings: int = 0,
        refusals: int = 0,
    ) -> Path:
        cell = bench / "cells" / name
        self.write_json(cell / "cell.json", {
            "condition": condition,
            "replicate": replicate,
            "status": status,
            "wall_seconds": 42,
        })
        self.write_json(cell / "metrics.json", {
            "confirmed_crashes": crashes,
            "crash_clusters": crashes,
            "crash_dirs": [f"CRASH-{i}" for i in range(crashes)],
            "findings": findings,
            "confirmed_findings": findings,
            "findings_rejected": rejected_findings,
            "model_refusals": refusals,
            "tokens": {"output_tokens": 111, "token_source": "measured"},
        })
        return cell

    def test_harvest_counts_only_proved_and_adjudicated_artifacts(self) -> None:
        results = self.root / "results"
        proved = results / "crashes" / "CRASH-001"
        claimed = results / "crashes" / "CRASH-002"
        proved.mkdir(parents=True)
        claimed.mkdir()
        (proved / "sanitizer.txt").write_text(ASAN)
        (claimed / "report.md").write_text("claim only\n")
        rejected = results / "crashes-rejected"
        (rejected / "CRASH-009").mkdir(parents=True)
        (rejected / "REJECTED-CRASHES.md").write_text(
            "# Rejected crashes\n\n## Rejected crash directories\n\n"
            "| ID | Site | Reason | Report |\n|:--|:--|:--|:--|\n"
            "| `CRASH-009` | app_parse app.c:91 | rejected | "
            "[Link](CRASH-009/REPORT.md) |\n"
        )

        findings = results / "findings"
        for name in ("FIND-ACCEPTED", "FIND-PENDING", "FIND-KEEP", "FIND-REVIEWED"):
            (findings / name).mkdir(parents=True)
        self.write_json(findings / "FIND-ACCEPTED" / ".llm-find-quality.json", {"accept": True})
        (findings / "FIND-KEEP" / ".keep").touch()
        (findings / "FIND-REVIEWED" / ".reviewed").touch()
        (results / "findings-rejected" / "FIND-REJECTED").mkdir(parents=True)
        (results / "recon-hypotheses.jsonl").write_text(
            '{"id":"RECON-a"}\n{"id":"REC-b"}\ninvalid\n{"id":"WORK-c"}\n'
        )
        (results / "state").mkdir()
        (results / "state" / "hypotheses.jsonl").write_text(
            '{"id":"H1","status":"DISCARDED"}\n{"id":"H2","status":"PENDING"}\n'
        )
        logs = results / "logs"
        logs.mkdir()
        (logs / "index.jsonl").write_text(
            '{"backend":"codex","tokens":{"input":1000,"cached_input":800,"output":50},"probe":{"asan_invocations":2}}\n'
            '{"backend":"codex","tokens":{"input":500,"cached_input":400,"output":30},"probe":{"asan_invocations":1}}\n'
        )
        (logs / "provider.refusals.log").write_text("WARN MODEL_REFUSAL one\nnoise\n")

        metrics = benchmark.harvest(results)
        self.assertEqual(metrics["confirmed_crashes"], 1)
        self.assertEqual(metrics["crash_dirs"], ["CRASH-001"])
        self.assertEqual(metrics["crashes_rejected"], 1)
        self.assertEqual(metrics["findings"], 4)
        self.assertEqual(metrics["confirmed_findings"], 3)
        self.assertEqual(metrics["confirmed_finding_dirs"], ["FIND-ACCEPTED", "FIND-KEEP", "FIND-REVIEWED"])
        self.assertEqual(metrics["findings_unadjudicated"], 1)
        self.assertEqual(metrics["findings_rejected"], 1)
        self.assertEqual(metrics["recon_candidates"], 2)
        self.assertEqual(metrics["discarded_hypotheses"], 1)
        self.assertEqual(metrics["model_refusals"], 1)
        self.assertEqual(metrics["tokens"]["input_tokens"], 300)
        self.assertEqual(metrics["tokens"]["cached_input_tokens"], 1200)
        self.assertEqual(metrics["tokens"]["output_tokens"], 80)
        self.assertEqual(metrics["tokens"]["asan_invocations"], 3)

        legacy = self.root / "legacy-row-rejected"
        (legacy / "crashes-rejected").mkdir(parents=True)
        (legacy / "crashes-rejected" / "REJECTED-CRASHES.md").write_text(
            "| ID | Crash site | Rejected at |\n|:--|:--|:--|\n"
            "| CR-a | app_parse.c:10 | t1 |\n"
            "| CR-b | app_parse.c:20 | t2 |\n"
        )
        self.assertEqual(benchmark.harvest(legacy)["crashes_rejected"], 2)

    def test_sibling_logs_and_sanitizer_effort_floor(self) -> None:
        backend = self.root / "experiment" / "codex"
        results = backend / "results"
        logs = backend / "logs"
        results.mkdir(parents=True)
        logs.mkdir()
        (logs / "index.jsonl").write_text(
            '{"backend":"codex","tokens":{"input":4000,"cached_input":3800,"output":120},"probe":{"asan_invocations":5}}\n'
        )
        metrics = benchmark.harvest(results)
        self.assertEqual(metrics["tokens"]["input_tokens"], 200)
        self.assertEqual(metrics["tokens"]["asan_invocations"], 5)

        direct = self.root / "direct"
        crash = direct / "crashes" / "CRASH-1"
        crash.mkdir(parents=True)
        (crash / "sanitizer.txt").write_text(ASAN)
        self.assertEqual(benchmark.harvest(direct)["tokens"]["asan_invocations"], 1)

    def test_token_normalization_sources_and_pricing(self) -> None:
        index = self.root / "index.jsonl"
        rows = [
            {"backend": "codex", "tokens": {"input": 1000, "cached_input": 800, "output": 50}},
            {"backend": "claude", "tokens": {"input": 30, "cached_input": 4000, "cache_creation": 120, "output": 700}},
            {"backend": "gemini", "tokens": {"input": 58000, "cached_input": 55000, "output": 80}},
        ]
        index.write_text("".join(json.dumps(row) + "\n" for row in rows))
        totals = benchmark.harvest_tokens(index)
        self.assertEqual(totals["input_tokens"], 3350)
        self.assertEqual(totals["cached_input_tokens"], 59800)
        self.assertEqual(totals["cache_creation_tokens"], 120)
        self.assertEqual(totals["output_tokens"], 830)
        self.assertEqual(totals["token_source"], "measured")

        cases = (
            ("claude", "claude-opus-4-8", {"input": 1000, "cached_input": 2000, "cache_creation": 400, "output": 3000}, "0.083500"),
            ("grok", "grok-build-0.1", {"input": 3000, "cached_input": 2000, "output": 3000}, "0.007400"),
            ("codex", "gpt-5.5", {"input": 5000000, "cached_input": 4800000, "output": 1000, "prompt_estimate_build": 16000}, "3.430000"),
        )
        for backend, model, tokens, expected in cases:
            with self.subTest(backend=backend, model=model):
                index.write_text(json.dumps({"backend": backend, "model": model, "tokens": tokens}) + "\n")
                self.assertEqual(benchmark.harvest_tokens(index)["cost_usd"], expected)

        index.write_text(json.dumps({
            "backend": "claude", "model": "claude-opus-4-8",
            "cost_usd": 0.123456, "cost_source": "backend-reported",
            "tokens": {"input": 1, "output": 1},
        }) + "\n")
        native = benchmark.harvest_tokens(index)
        self.assertEqual(native["cost_usd"], "0.123456")
        self.assertEqual(native["cost_source"], "backend-reported")

    def test_usage_extraction_for_supported_backend_shapes(self) -> None:
        cases = (
            ("codex", [
                {"type": "item.completed", "usage": {"input_tokens": 2000, "cached_input_tokens": 1800, "output_tokens": 90}},
            ], (2000, 1800, 0, 90)),
            ("oss", [
                {"type": "step_finish", "part": {"type": "step-finish", "tokens": {"input": 1200, "output": 34, "cache": {"read": 900, "write": 25}}}},
            ], (1200, 900, 25, 34)),
            ("claude", [
                {"type": "assistant", "message": {"usage": {"input_tokens": 5, "output_tokens": 7}}},
                {"type": "result", "usage": {"input_tokens": 50, "cache_read_input_tokens": 40, "cache_creation_input_tokens": 15, "output_tokens": 12}},
            ], (50, 40, 15, 12)),
            ("gemini", [
                {"type": "result", "stats": {"input_tokens": 58000000, "output_tokens": 80, "cached": 55000000}},
            ], (58000000, 55000000, 0, 80)),
        )
        for backend, rows, expected in cases:
            with self.subTest(backend=backend):
                path = self.root / f"{backend}.log"
                path.write_text("".join(json.dumps(row) + "\n" for row in rows))
                usage = llm_usage.extract_usage(str(path), backend=backend)
                tokens = usage["tokens"]
                self.assertEqual(
                    (tokens["input"], tokens["cached_input"], tokens["cache_creation"], tokens["output"]),
                    expected,
                )
        self.assertEqual(
            llm_usage.extract_usage(str(self.root / "missing.log"), backend="codex")["tokens"]["input"],
            0,
        )

    def test_aggregate_excludes_incomplete_cells_and_keeps_observed_counts(self) -> None:
        bench = self.root / "bench"
        self.write_json(bench / "run.json", {
            "runid": "run1", "target": "sample", "backend": "codex",
            "replicates": 2, "budget_wall": 60,
            "conditions": ["model-direct", "harness"],
            "target_sha": "abc", "harness_sha": "def",
        })
        self.make_cell(bench, "model-direct-r1", "model-direct", 1, 0, rejected_findings=2, refusals=1)
        self.make_cell(bench, "model-direct-r2", "model-direct", 2, 0)
        self.make_cell(bench, "harness-r1", "harness", 1, 3, findings=2, refusals=2)
        self.make_cell(bench, "harness-r2", "harness", 2, 1, findings=1)
        aggregate = benchmark.aggregate(bench)
        by_condition = {row["condition"]: row for row in aggregate["conditions"]}
        harness = by_condition["harness"]
        self.assertEqual(harness["crashes"], [3, 1])
        self.assertEqual(harness["crash_total"], 4)
        self.assertEqual(harness["crash_median"], 2)
        self.assertEqual(harness["confirmed_finding_total"], 3)
        self.assertEqual(harness["model_refusal_total"], 2)
        self.assertEqual(by_condition["model-direct"]["rejected_finding_total"], 2)

        failed = self.make_cell(bench, "harness-r3", "harness", 3, 0, status="failed")
        (failed / "metrics.json").unlink()
        self.make_cell(bench, "harness-r4", "harness", 4, 6, status="incomplete", findings=5)
        updated = {row["condition"]: row for row in benchmark.aggregate(bench)["conditions"]}["harness"]
        self.assertEqual(updated["replicates_total"], 4)
        self.assertEqual(updated["replicates_done"], 2)
        self.assertEqual(updated["crash_total"], 4)
        self.assertEqual(updated["incomplete_observed"][0]["crashes"], 6)
        self.assertEqual(updated["incomplete_observed"][0]["findings"], 5)

    def test_ledger_replaces_same_run_and_reset_archives(self) -> None:
        bench = self.root / "bench-ledger"
        self.write_json(bench / "run.json", {
            "runid": "run1", "target": "sample", "backend": "codex",
            "conditions": ["harness"], "replicates": 1,
        })
        self.make_cell(bench, "harness-r1", "harness", 1, 1)
        ledger = self.root / "ledger.md"
        section = benchmark.render_section(benchmark.aggregate(bench))
        benchmark.append_to_ledger(ledger, section)
        benchmark.append_to_ledger(ledger, section)
        text = ledger.read_text()
        self.assertEqual(text.count("# Benchmark results"), 1)
        self.assertEqual(text.count("Benchmark run `run1`"), 1)

        archived = benchmark.reset_ledger(ledger)
        self.assertFalse(ledger.exists())
        self.assertIsNotNone(archived)
        self.assertTrue(Path(archived).is_file())
        ledger.write_text("temporary\n")
        self.assertIsNone(benchmark.reset_ledger(ledger, hard=True))
        self.assertFalse(ledger.exists())

    def test_pool_and_split_preserve_condition_membership_and_rejections(self) -> None:
        bench = self.root / "pool-bench"
        self.write_json(bench / "run.json", {
            "runid": "pool", "target": "sample", "backend": "codex",
            "conditions": ["model-direct", "harness"], "replicates": 1,
        })
        for condition in ("model-direct", "harness"):
            results = self.root / f"results-{condition}"
            crash = results / "crashes" / "CRASH-001"
            finding = results / "findings" / "FIND-001"
            rejected = results / "findings-rejected" / "FIND-REJECTED"
            rejected_crash = results / "crashes-rejected" / "CRASH-OLD"
            crash.mkdir(parents=True)
            finding.mkdir(parents=True)
            rejected.mkdir(parents=True)
            rejected_crash.mkdir(parents=True)
            (crash / "sanitizer.txt").write_text(ASAN)
            (crash / "report.md").write_text(f"# {condition} crash\n")
            (finding / "report.md").write_text(f"# {condition} finding\n")
            (finding / ".keep").touch()
            (rejected / "report.md").write_text("# rejected\n")
            (rejected_crash / "REPORT.md").write_text("# Rejected crash\n")
            (results / "crashes-rejected" / "REJECTED-CRASHES.md").write_text(
                "# Rejected crashes\n\n## Rejected crash directories\n\n"
                "| ID | Site | Reason | Report |\n|:--|:--|:--|:--|\n"
                "| `CRASH-OLD` | app_parse app.c:91 | rejected | "
                "[Link](CRASH-OLD/REPORT.md) |\n"
            )
            cell = self.make_cell(bench, f"{condition}-r1", condition, 1, 1, findings=1, rejected_findings=1)
            data = json.loads((cell / "cell.json").read_text())
            data["results_dir"] = str(results)
            self.write_json(cell / "cell.json", data)
            metrics = benchmark.harvest(results)
            self.write_json(cell / "metrics.json", metrics)

        pooled = benchmark.build_pool(bench)
        self.assertEqual(len(pooled["crashes"]), 2)
        self.assertEqual(len(pooled["findings"]), 2)
        self.assertFalse(any(
            (bench / "pool" / "crashes-rejected").glob("CELL-REJECTIONS-*.md")
        ))
        members = json.loads((bench / "pool-members.json").read_text())
        self.assertEqual(set(members["crashes"].values()), {"model-direct", "harness"})
        split = benchmark.split_pool(bench)
        self.assertEqual(split["model-direct"], 4)
        self.assertEqual(split["harness"], 4)
        for condition in ("model-direct", "harness"):
            condition_pool = bench / "pool" / condition
            self.assertEqual(len(list((condition_pool / "crashes").glob("CRASH-*"))), 1)
            self.assertEqual(len(list((condition_pool / "findings").glob("FIND-*"))), 1)
            self.assertTrue((condition_pool / "findings-rejected" / "REJECTED-FINDINGS.md").is_file())

    def test_crosstab_explains_finalized_populations_without_pending_columns(self) -> None:
        run = self.root / "crosstab" / "codex" / "20260101-000000"
        report = {
            "run": {
                "runid": "20260101-000000", "target": "sample",
                "backend": "codex", "model": "gpt-test",
            },
            "bench_dir": str(run),
            "conditions": [{
                "condition": "harness", "replicates_done": 1,
                "replicates_total": 1, "wall_median": 60,
                "rejected_finding_total": 2, "confirmed_finding_total": 3,
                "unique_finding_clusters": 2, "medium_plus_findings": 1,
                "rejected_crash_total": 4, "crash_total": 5,
                "unique_crash_clusters": 3, "medium_plus_bugs": 2,
                "top_severity_level": "High", "tokens": {},
            }],
        }
        self.write_json(run / "report.json", report)
        text = benchmark.crosstab(self.root / "crosstab")
        for expected in (
            "total candidate reports = Rejected findings + Confirmed findings",
            "Unique findings deduplicates Confirmed findings only",
            "Unique crashes deduplicates Confirmed crashes only",
            "Rejected findings | Confirmed findings | Unique findings",
            "Rejected crashes | Confirmed crashes | Unique crashes",
        ):
            with self.subTest(expected=expected):
                self.assertIn(expected, text)
        self.assertNotIn("Pending findings", text)
        self.assertNotIn("Pending crashes", text)
        ledger = benchmark.render_section(report)
        self.assertNotIn("Pending findings", ledger)
        self.assertNotIn("Pending crashes", ledger)


if __name__ == "__main__":
    unittest.main()
