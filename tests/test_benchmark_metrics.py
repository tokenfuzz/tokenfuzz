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
import llm_invoke
import llm_usage
import report_identity


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
        # No work-cards.jsonl: nothing is a recon lead, so counting falls back
        # to gate acceptance and confirmed is unchanged.
        self.assertEqual(metrics["finding_leads"], 0)
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

    def test_uninvestigated_recon_findings_count_as_leads(self) -> None:
        # A gate-accepted recon FIND is confirmed only if an agent investigated
        # it: ANY of its (fanned-out) work cards ever reached find/crash — read
        # from the authoritative claims ledger, with the work-card status as a
        # fallback — OR agent output in the dir, OR a human pin. Un-investigated
        # recon guesses become leads. Production-shaped: recon fans one finding
        # out to several cards, so a productive card among unclaimed siblings
        # must still confirm.
        results = self.root / "results"
        findings = results / "findings"
        cases = [
            "FIND-0001-agent",              # agent-filed, no recon card -> confirmed
            "FIND-RECON-fanout-productive",  # 3 cards, one 'find' -> confirmed
            "FIND-RECON-fanout-lead",        # cards all unclaimed, bare -> lead
            "FIND-RECON-claims-only",        # wc stale unclaimed, ledger 'find' -> confirmed
            "FIND-RECON-artifact",           # unclaimed + non-empty agent file -> confirmed
            "FIND-RECON-emptyfile",          # unclaimed + empty file -> lead (P4)
            "FIND-RECON-pinned",             # unclaimed + .keep -> confirmed
            "FIND-RECON-ungated",            # gate never verdicted -> unadjudicated
        ]
        for name in cases:
            (findings / name).mkdir(parents=True)
        for name in cases:
            if name != "FIND-RECON-ungated":
                self.write_json(findings / name / ".llm-find-quality.json", {"accept": True})
        (findings / "FIND-RECON-artifact" / "validation_report.md").write_text("evidence\n")
        (findings / "FIND-RECON-emptyfile" / "scratch.txt").write_text("")  # empty: no rescue
        (findings / "FIND-RECON-pinned" / ".keep").touch()
        # Fan-out: one find_id -> several cards. Card status is a fallback; the
        # ledger is authoritative and can carry a productive status the stale
        # work-card row misses (claims-only).
        (results / "work-cards.jsonl").write_text(
            "\n".join(json.dumps(c) for c in [
                {"id": "fp1", "find_id": "FIND-RECON-fanout-productive", "status": "unclaimed"},
                {"id": "fp2", "find_id": "FIND-RECON-fanout-productive", "status": "unclaimed"},
                {"id": "fp3", "find_id": "FIND-RECON-fanout-productive", "status": "find"},
                {"id": "fl1", "find_id": "FIND-RECON-fanout-lead", "status": "unclaimed"},
                {"id": "fl2", "find_id": "FIND-RECON-fanout-lead", "status": "unclaimed"},
                {"id": "co1", "find_id": "FIND-RECON-claims-only", "status": "unclaimed"},
                {"id": "ar1", "find_id": "FIND-RECON-artifact", "status": "unclaimed"},
                {"id": "ef1", "find_id": "FIND-RECON-emptyfile", "status": "unclaimed"},
                {"id": "pn1", "find_id": "FIND-RECON-pinned", "status": "unclaimed"},
                {"id": "un1", "find_id": "FIND-RECON-ungated", "status": "unclaimed"},
            ]) + "\n",
            encoding="utf-8",
        )
        (results / "state").mkdir()
        (results / "state" / "claims.jsonl").write_text(
            "\n".join(json.dumps(c) for c in [
                {"card_id": "co1", "status": "claimed"},
                {"card_id": "co1", "status": "find"},   # ledger productive; wc row stale
                {"card_id": "fl1", "status": "released"},
            ]) + "\n",
            encoding="utf-8",
        )
        metrics = benchmark.harvest(results)
        self.assertEqual(metrics["findings"], 8)
        self.assertEqual(
            metrics["confirmed_finding_dirs"],
            ["FIND-0001-agent", "FIND-RECON-artifact", "FIND-RECON-claims-only",
             "FIND-RECON-fanout-productive", "FIND-RECON-pinned"],
        )
        self.assertEqual(metrics["confirmed_findings"], 5)
        self.assertEqual(
            metrics["lead_finding_dirs"],
            ["FIND-RECON-emptyfile", "FIND-RECON-fanout-lead"],
        )
        self.assertEqual(metrics["finding_leads"], 2)
        # gate never verdicted ungated -> unadjudicated, not a lead
        self.assertEqual(metrics["findings_unadjudicated"], 1)

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
            ("codex", "gpt-5.6-sol", {"input": 5000000, "cached_input": 4800000, "output": 1000, "prompt_estimate_build": 16000}, "3.430000"),
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

    def test_current_model_families_use_their_exact_price_tiers(self) -> None:
        cases = (
            ("codex", "gpt-5.6", "5", "0.50", "30"),
            ("codex", "gpt-5.6-sol", "5", "0.50", "30"),
            ("codex", "gpt-5.6-terra", "2.50", "0.25", "15"),
            ("codex", "gpt-5.6-luna", "1", "0.10", "6"),
            ("codex", "gpt-5.5-2026-04-23", "5", "0.50", "30"),
            ("codex", "gpt-5.5-pro", "30", "0", "180"),
            ("codex", "gpt-5.4", "2.50", "0.25", "15"),
            ("codex", "gpt-5.4-mini", "0.75", "0.075", "4.50"),
            ("codex", "gpt-5.4-nano", "0.20", "0.02", "1.25"),
            ("codex", "gpt-5.4-pro", "30", "0", "180"),
            ("codex", "gpt-5.2", "1.75", "0.175", "14"),
            ("codex", "gpt-5.2-pro", "21", "0", "168"),
            ("codex", "gpt-5.1", "1.25", "0.125", "10"),
            ("codex", "gpt-5", "1.25", "0.125", "10"),
            ("codex", "gpt-5-mini", "0.25", "0.025", "2"),
            ("codex", "gpt-5-nano", "0.05", "0.005", "0.40"),
            ("codex", "gpt-4.1", "2", "0.50", "8"),
            ("codex", "gpt-4.1-mini", "0.40", "0.10", "1.60"),
            ("codex", "gpt-4o", "2.50", "1.25", "10"),
            ("codex", "gpt-4o-2024-05-13", "5", "0", "15"),
            ("codex", "gpt-4o-mini", "0.15", "0.075", "0.60"),
            ("codex", "o1", "15", "7.50", "60"),
            ("codex", "o1-pro", "150", "0", "600"),
            ("codex", "o3", "2", "0.50", "8"),
            ("codex", "o3-pro", "20", "0", "80"),
            ("codex", "o4-mini", "1.10", "0.275", "4.40"),
            ("codex", "gpt-4-turbo-2024-04-09", "10", "0", "30"),
            ("codex", "gpt-3.5-turbo", "0.50", "0", "1.50"),
            ("claude", "claude-fable-5", "10", "1", "50"),
            ("claude", "claude-mythos-5", "10", "1", "50"),
            ("claude", "claude-opus-4-8", "5", "0.50", "25"),
            ("claude", "claude-opus-4-5", "5", "0.50", "25"),
            ("claude", "claude-opus-4-1", "15", "1.50", "75"),
            ("claude", "claude-3-opus-20240229", "15", "1.50", "75"),
            ("claude", "claude-sonnet-5", "2", "0.20", "10"),
            ("claude", "claude-sonnet-4-6", "3", "0.30", "15"),
            ("claude", "claude-sonnet-4-5", "3", "0.30", "15"),
            ("claude", "claude-3-7-sonnet-20250219", "3", "0.30", "15"),
            ("claude", "claude-3-5-sonnet-20241022", "3", "0.30", "15"),
            ("claude", "claude-haiku-4-5-20251001", "1", "0.10", "5"),
            ("claude", "claude-3-5-haiku-20241022", "0.80", "0.08", "4"),
            ("claude", "claude-3-haiku-20240307", "0.25", "0.03", "1.25"),
            ("gemini", "gemini-3.5-flash", "1.50", "0.15", "9"),
            ("gemini", "gemini-3.1-pro-preview", "2", "0.20", "12"),
            ("gemini", "gemini-3.1-flash-lite", "0.25", "0.025", "1.50"),
            ("gemini", "gemini-3-flash-preview", "0.50", "0.05", "3"),
            ("gemini", "gemini-2.5-pro", "1.25", "0.125", "10"),
            ("gemini", "gemini-2.5-flash", "0.30", "0.03", "2.50"),
            ("gemini", "gemini-2.5-flash-lite", "0.10", "0.01", "0.40"),
            ("gemini", "gemini-2.0-flash", "0.10", "0.025", "0.40"),
            ("gemini", "gemini-2.0-flash-lite", "0.075", "0", "0.30"),
            ("grok", "grok-build-0.1", "1", "0.20", "2"),
            ("grok", "grok-4.5", "2", "0.50", "6"),
            ("grok", "grok-4.3", "1.25", "0.20", "2.50"),
            ("grok", "grok-4.20-0309-reasoning", "1.25", "0.20", "2.50"),
        )
        for backend, model, input_rate, cache_rate, output_rate in cases:
            with self.subTest(backend=backend, model=model):
                rates = benchmark._pricing_rates(
                    backend, model, priced_at="2026-07-12",
                )
                self.assertIsNotNone(rates)
                if rates.get("tiered"):
                    self.assertEqual(str(rates["input_low"]), input_rate)
                    self.assertEqual(str(rates["cache_read_low"]), cache_rate)
                    self.assertEqual(str(rates["output_low"]), output_rate)
                else:
                    self.assertEqual(str(rates["input"]), input_rate)
                    self.assertEqual(str(rates.get("cache_read", 0)), cache_rate)
                    self.assertEqual(str(rates["output"]), output_rate)

        # The old "mini" suffix is not a GPT-5.6 model tier, and arbitrary
        # future-looking names must not inherit Sol pricing by substring.
        self.assertIsNone(benchmark._pricing_rates("codex", "gpt-5.6-mini"))
        self.assertIsNone(benchmark._pricing_rates("codex", "gpt-5.60"))
        self.assertIsNone(benchmark._pricing_rates("codex", "gpt-5-6"))
        self.assertIsNone(benchmark._pricing_rates("claude", "claude-opus-5"))
        self.assertIsNone(benchmark._pricing_rates("claude", "claude-haiku-5"))
        sonnet_standard = benchmark._pricing_rates(
            "claude", "claude-sonnet-5", priced_at="2026-09-01",
        )
        self.assertEqual(str(sonnet_standard["input"]), "3")
        self.assertEqual(str(sonnet_standard["cache_write"]), "3.75")
        self.assertEqual(str(sonnet_standard["cache_write_1h"]), "6")
        self.assertEqual(str(sonnet_standard["cache_read"]), "0.30")
        self.assertEqual(str(sonnet_standard["output"]), "15")

        long_context = (
            ("gpt-5.6-sol", "10", "1", "12.50", "45"),
            ("gpt-5.6-terra", "5", "0.50", "6.25", "22.50"),
            ("gpt-5.6-luna", "2", "0.20", "2.50", "9"),
            ("gpt-5.5", "10", "1", None, "45"),
            ("gpt-5.5-pro", "60", "0", None, "270"),
        )
        for model, input_high, cache_high, write_high, output_high in long_context:
            with self.subTest(model=model, tier="long-context"):
                rates = benchmark._pricing_rates("codex", model)
                self.assertEqual(str(rates["input_high"]), input_high)
                self.assertEqual(str(rates["cache_read_high"]), cache_high)
                self.assertEqual(str(rates["output_high"]), output_high)
                if write_high is None:
                    self.assertNotIn("cache_write_high", rates)
                else:
                    self.assertEqual(str(rates["cache_write_high"]), write_high)

        claude_cache = (
            ("claude-fable-5", "12.50", "20"),
            ("claude-opus-4-8", "6.25", "10"),
            ("claude-sonnet-5", "2.50", "4"),
            ("claude-sonnet-4-6", "3.75", "6"),
            ("claude-haiku-4-5", "1.25", "2"),
            ("claude-3-5-haiku", "1", "1.60"),
            ("claude-3-haiku", "0.30", "0.50"),
        )
        for model, write_5m, write_1h in claude_cache:
            with self.subTest(model=model, tier="cache-write"):
                rates = benchmark._pricing_rates(
                    "claude", model, priced_at="2026-07-12",
                )
                self.assertEqual(str(rates["cache_write"]), write_5m)
                self.assertEqual(str(rates["cache_write_1h"]), write_1h)

    def test_tiered_cache_writes_estimates_and_corrupt_rows_price_safely(self) -> None:
        # GPT-5.6 cache writes cost 1.25x uncached input. The normalized input
        # bucket contains writes, so pricing must split them back out.
        cost, source = benchmark._cost_decimal(
            "codex", "gpt-5.6-terra",
            input_tokens=1_000_000,
            cached_input_tokens=1_000_000,
            cache_creation_tokens=400_000,
            output_tokens=1_000_000,
            prompt_tokens_for_tier=200_000,
        )
        self.assertEqual(benchmark._decimal_text(cost), "18.000000")
        self.assertEqual(source, "openai-api-gpt-5.6-terra-standard")

        claude_long, _ = benchmark._cost_decimal(
            "claude", "claude-sonnet-4-5",
            input_tokens=1_000_000,
            cached_input_tokens=1_000_000,
            cache_creation_tokens=400_000,
            cache_creation_1h_tokens=200_000,
            output_tokens=1_000_000,
            prompt_tokens_for_tier=1_400_000,
        )
        self.assertEqual(benchmark._decimal_text(claude_long), "30.600000")

        gemini_long, _ = benchmark._cost_decimal(
            "gemini", "gemini-2.5-pro",
            input_tokens=1_000_000, cached_input_tokens=1_000_000,
            output_tokens=1_000_000, prompt_tokens_for_tier=200_001,
        )
        self.assertEqual(benchmark._decimal_text(gemini_long), "17.750000")

        grok_standard, _ = benchmark._cost_decimal(
            "grok", "grok-4.5",
            input_tokens=1_000_000, cached_input_tokens=1_000_000,
            output_tokens=1_000_000,
        )
        self.assertEqual(benchmark._decimal_text(grok_standard), "8.500000")

        # Vendor thresholds are per request. Harness rows retain the rendered
        # prompt size, so cumulative session input must not force the high tier.
        index = self.root / "tier-boundary.jsonl"
        index.write_text(json.dumps({
            "backend": "gemini", "model": "gemini-2.5-pro",
            "prompt_chars": 800_000,
            "tokens": {"input": 1_000_000, "output": 1_000_000},
        }) + "\n")
        at_boundary = benchmark.harvest_tokens(index)
        self.assertEqual(at_boundary["cost_usd"], "11.250000")
        self.assertTrue(at_boundary["cost_estimated"])
        index.write_text(json.dumps({
            "backend": "gemini", "model": "gemini-2.5-pro",
            "prompt_chars": 800_001,
            "tokens": {"input": 1_000_000, "output": 1_000_000},
        }) + "\n")
        over_boundary = benchmark.harvest_tokens(index)
        self.assertEqual(over_boundary["cost_usd"], "17.500000")
        self.assertTrue(over_boundary["cost_estimated"])

        index.write_text(json.dumps({
            "backend": "gemini", "model": "gemini-2.5-pro",
            "prompt_chars": 800_001, "cost_usd": 9.25,
            "cost_source": "backend-reported",
            "tokens": {"input": 1_000_000, "output": 1_000_000},
        }) + "\n")
        reported = benchmark.harvest_tokens(index)
        self.assertEqual(reported["cost_usd"], "9.250000")
        self.assertFalse(reported["cost_estimated"])

        index = self.root / "estimated.jsonl"
        index.write_text(json.dumps({
            "backend": "grok", "model": "grok-build-0.1", "estimated": True,
            "tokens": {"input": 0, "prompt_estimate": 1000, "output": 1000},
        }) + "\n")
        estimated = benchmark.harvest_tokens(index)
        self.assertEqual(estimated["cost_usd"], "0.003000")
        self.assertTrue(estimated["estimated"])

        # JSONL is durable shared state: syntactically valid but malformed
        # values must not crash a live report or create negative/NaN totals.
        index.write_text(
            "[]\n"
            + json.dumps({"backend": "grok", "model": "grok-build-0.1", "tokens": []}) + "\n"
            + json.dumps({
                "backend": "grok", "model": "grok-build-0.1",
                "cost_usd": "NaN", "tokens": {"input": -3, "output": 1e999},
            }) + "\n"
        )
        corrupt = benchmark.harvest_tokens(index)
        self.assertEqual(corrupt["input_tokens"], 0)
        self.assertEqual(corrupt["output_tokens"], 0)
        self.assertEqual(corrupt["cost_usd"], "0.000000")
        self.assertEqual(benchmark._fmt_usd("NaN"), "—")
        self.assertEqual(benchmark._fmt_usd("Infinity"), "—")
        self.assertEqual(
            benchmark._sum_cost_usd([
                {"cost_usd": "NaN"}, {"cost_usd": "Infinity"},
                {"cost_usd": "1.25"},
            ]),
            "1.250000",
        )

        cell = {
            "condition": "harness", "status": "done",
            "wall_seconds": "not-a-number",
            "metrics": {"tokens": {
                "input_tokens": -1, "output_tokens": float("inf"),
                "iterations": "broken",
            }},
        }
        token_row = benchmark._tokens_for_cell(cell)
        self.assertEqual(token_row["input_tokens"], 0)
        self.assertEqual(token_row["output_tokens"], 0)
        self.assertEqual(token_row["wall_seconds"], 0)

    def test_configured_default_models_have_pricing(self) -> None:
        # Every backend default in config/models.toml must key a pricing row.
        # Backends without a backend-reported cost (codex/gemini/grok) render a
        # blank dollar column when the table lacks their model, so a model bump
        # that skips the table degrades silently — this pins the two together.
        for backend in ("claude", "codex", "gemini", "grok"):
            model = llm_invoke.default_model(backend)
            self.assertTrue(model, f"{backend} has no configured default model")
            self.assertIsNotNone(
                benchmark._pricing_rates(backend, model),
                f"no pricing row for {backend} default model {model!r}",
            )

    def test_usage_extraction_for_supported_backend_shapes(self) -> None:
        cases = (
            ("codex", [
                {"type": "item.completed", "usage": {"input_tokens": 2000, "cached_input_tokens": 1800, "cache_write_tokens": 100, "output_tokens": 90}},
            ], (2000, 1800, 100, 90)),
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
            ("grok", [
                {"type": "response.completed", "usage": {
                    "input_tokens": 5000, "output_tokens": 60,
                    "input_tokens_details": {
                        "cached_tokens": 4000, "cache_write_tokens": 250,
                    },
                }},
            ], (5000, 4000, 250, 60)),
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

    def test_pool_rejected_finding_keeps_reason_after_report_link_rewrite(self) -> None:
        bench = self.root / "rejection-reason-bench"
        self.write_json(bench / "run.json", {
            "runid": "rejection-reason", "target": "sample",
            "backend": "codex", "conditions": ["harness"], "replicates": 1,
        })
        results = self.root / "rejection-reason-results"
        rejected = results / "findings-rejected" / "FIND-REJECTED"
        recon = results / "recon" / "RECON-deadbeef"
        rejected.mkdir(parents=True)
        recon.mkdir(parents=True)
        report = rejected / "report.md"
        report.write_text(
            "# Rejected finding\n\nRecon ID: RECON-deadbeef\n",
            encoding="utf-8",
        )
        (recon / "REPORT.md").write_text("# Recon evidence\n", encoding="utf-8")
        reason = "caller control does not reach the reported operation"
        self.write_json(rejected / ".llm-find-quality.json", {
            "accept": False,
            "reason": reason,
            "report_sha1": report_identity.content_sha1(report),
        })
        (rejected / "REJECTION.md").write_text(
            f"# Rejected artifact\n\nReason: {reason}\n\n"
            "The original evidence is retained for audit.\n",
            encoding="utf-8",
        )
        cell = self.make_cell(
            bench, "harness-r1", "harness", 1, 0, rejected_findings=1,
        )
        data = json.loads((cell / "cell.json").read_text(encoding="utf-8"))
        data["results_dir"] = str(results)
        self.write_json(cell / "cell.json", data)
        self.write_json(cell / "metrics.json", benchmark.harvest(results))

        benchmark.build_pool(bench)

        pooled = bench / "pool" / "findings-rejected" / "FIND-REJECTED-0001"
        self.assertIn("[RECON-deadbeef]", (pooled / "report.md").read_text())
        self.assertFalse(report_identity.quality_cache_matches_report(
            pooled, json.loads((pooled / ".llm-find-quality.json").read_text()),
        ))
        index = (pooled.parent / "REJECTED-FINDINGS.md").read_text()
        self.assertIn(reason, index)

    def test_rejection_artifact_is_the_final_disposition(self) -> None:
        rejected_root = self.root / "final-disposition"
        finding = rejected_root / "FIND-TRIGGER-REJECTED"
        finding.mkdir(parents=True)
        report = finding / "report.md"
        report.write_text("# Finding\n", encoding="utf-8")
        self.write_json(finding / ".llm-find-quality.json", {
            "accept": True,
            "reason": "quality gate accepted the report",
            "report_sha1": report_identity.content_sha1(report),
        })
        final_reason = "triggering state is not attacker-reachable"
        (finding / "REJECTION.md").write_text(
            f"# Rejected artifact\n\nReason: {final_reason}\n",
            encoding="utf-8",
        )

        rows = benchmark._rejected_finding_rows(rejected_root)

        self.assertEqual(rows[0]["reason"], final_reason)

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
            "Rejected findings, Confirmed findings, and leads are distinct populations",
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
