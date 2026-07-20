#!/usr/bin/env python3
"""Benchmark prompt, cell metadata, pool, and report-link regressions."""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "lib"))

import benchmark
import benchmark_model_direct_render
import benchmark_runner
import llm_invoke
import prompt_render
import target_config


class BenchmarkReportTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="benchmark-report-")
        self.root = Path(self.temporary.name)
        self.repo_targets: list[Path] = []

    def tearDown(self) -> None:
        for target in self.repo_targets:
            shutil.rmtree(target, ignore_errors=True)
        self.temporary.cleanup()

    @staticmethod
    def write_json(path: Path, value: object) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value) + "\n", encoding="utf-8")

    def test_model_direct_prompt_for_managed_and_sanitized_targets(self) -> None:
        managed = self.root / "managed"
        managed.mkdir()
        (managed / "target.toml").write_text(
            'target = "sample"\n[sanitizer]\nenabled = []\n', encoding="utf-8"
        )
        body = benchmark_model_direct_render.render(str(managed), "/abs/out", str(ROOT))
        for required in (
            "CRASH-<n>", "FIND-<n>", "sanitizer-instrumented", "Writing scope",
            "absolute paths only", "Do not delegate work to subagents", "Primary objective",
            "Use the configured\nrunner", "save that evidence with the FINDING",
        ):
            self.assertIn(required, body)
        for forbidden in (
            "unsupported claim", "falsification attempt", "symlink facade",
            "writable facade of", "deserialization", "info-leak",
            "protocol-state", "denial-of-service",
            "Mode switch after ~5 FINDs", "roughly five plausible candidates",
        ):
            self.assertNotIn(forbidden, body)
        self.assertLess(body.index("For every FINDING:"), body.index("For every CRASH:"))
        self.assertRegex(body, r"find as many|file generously|breadth and depth")
        self.assertNotRegex(body, r"\{\{\s*(target_path|output_dir)\s*\}\}")

        literal = prompt_render.render_template(
            ROOT / "lib" / "prompts" / "benchmark_model_direct.md.j2",
            {
                "target_path": "/abs/target", "output_dir": "/abs/out",
                "crash_objective": "", "asan_invocation_hint": "",
                "harness_build_recipe": "",
            },
        )
        self.assertIn("/abs/target", literal)
        self.assertIn("/abs/out", literal)

        native = self.root / "native"
        binary = native / "build-asan" / "src" / "sample-cli"
        library = native / "build-asan" / "lib" / "libsample.a"
        binary.parent.mkdir(parents=True)
        library.parent.mkdir(parents=True)
        (native / "include").mkdir()
        (native / "lib").mkdir()
        (native / "CMakeLists.txt").write_text("project(sample C)\n")
        (native / "target.toml").write_text(
            'target = "sample"\n'
            'build_system = "cmake"\n'
            'asan_bin = "build-asan/src/sample-cli"\n'
            'asan_lib = "build-asan/lib/libsample.a"\n'
            'includes = ["include", "lib"]\n'
            'link_libs = ["-lm", "-lpthread"]\n'
            '[sanitizer]\nenabled = ["asan"]\n',
            encoding="utf-8",
        )
        binary.write_text(f"#!{sys.executable}\n", encoding="utf-8")
        binary.chmod(0o755)
        library.touch()
        unstamped_body = benchmark_model_direct_render.render(
            str(native), "/abs/out", str(ROOT)
        )
        self.assertIn("Driving the asan binary directly", unstamped_body)
        self.assertNotIn("No native sanitizer-instrumented build", unstamped_body)
        target_config.build_write_stamp(native, "asan")
        native_body = benchmark_model_direct_render.render(str(native), "/abs/out", str(ROOT))
        for required in (
            "build-asan/src/sample-cli", "Driving the asan binary directly",
            "Building a one-off harness driver", "build-asan/lib/libsample.a",
            "fsanitize=address", "When source review identifies a\nplausible sanitizer-class",
            "file a CRASH only when a real\nsanitizer trace reproduces",
        ):
            self.assertIn(required, native_body)
        self.assertNotIn("merely to fill the crashes directory", body)
        self.assertIn("merely to fill the crashes directory", native_body)

        # A sanitizer-runner build system (swift) is advertised as
        # crash-capable. Detection keys on build_system, the same structured
        # signal target_config uses for the findings-only default — not on
        # sniffing the runner args for a sanitizer token.
        runner_native = self.root / "runner-native"
        runner_native.mkdir()
        runner_toml = (
            'target = "sample"\n'
            'build_system = "swift"\n'
            '[sanitizer]\nenabled = ["asan"]\n'
            '[runner]\nbin = "swift"\n'
            'args = ["run", "-sanitize={SWIFT_SANITIZER}", "{TESTCASE}"]\n'
        )
        (runner_native / "target.toml").write_text(runner_toml, encoding="utf-8")
        runner_body = benchmark_model_direct_render.render(
            str(runner_native), "/abs/out", str(ROOT)
        )
        self.assertIn("asan sanitizer runner is configured", runner_body)
        self.assertIn("Driving the asan runner directly", runner_body)
        self.assertIn("-sanitize=address", runner_body)
        self.assertNotIn("No native sanitizer-instrumented build", runner_body)

        # Same runner+token, but a build_system the classification does not
        # recognize falls through to findings-only framing — the token alone
        # must not trigger crash-capability framing.
        unknown_runner = self.root / "unknown-runner"
        unknown_runner.mkdir()
        (unknown_runner / "target.toml").write_text(
            runner_toml.replace('build_system = "swift"', 'build_system = "make"'),
            encoding="utf-8",
        )
        unknown_body = benchmark_model_direct_render.render(
            str(unknown_runner), "/abs/out", str(ROOT)
        )
        self.assertIn("No native sanitizer-instrumented build", unknown_body)
        self.assertNotIn("sanitizer runner is configured", unknown_body)

        race = self.root / "race"
        race.mkdir()
        (race / "target.toml").write_text(
            'target = "sample"\n'
            '[sanitizer]\nenabled = ["race"]\n'
            '[runner]\nbin = "go"\nargs = ["run", "-race", "{TESTCASE}"]\n',
            encoding="utf-8",
        )
        race_body = benchmark_model_direct_render.render(
            str(race), "/abs/out", str(ROOT)
        )
        self.assertIn("race-detector runner is configured", race_body)
        self.assertIn("Driving the race runner directly", race_body)
        self.assertIn("WARNING: DATA RACE", race_body)
        self.assertNotIn("No native sanitizer-instrumented build", race_body)

    def test_sanitizer_runner_build_systems_match_language_runners(self) -> None:
        # SANITIZER_RUNNER_BUILD_SYSTEMS is the single source of truth for
        # "this ecosystem's default runner drives a sanitizer." Guard it
        # against drift from lib/languages.py: every listed build system must
        # map to a language whose canonical runner selects a sanitizer via a
        # {SANITIZER}/{SWIFT_SANITIZER} token. Otherwise the model-direct
        # prompt would advertise crash capability the runner cannot deliver.
        import languages

        tokens = ("{SANITIZER}", "{SWIFT_SANITIZER}")
        for build_system in target_config.SANITIZER_RUNNER_BUILD_SYSTEMS:
            matches = [
                lang for lang in languages.LANGUAGES
                if build_system in lang.build_systems
            ]
            self.assertTrue(
                matches,
                f"{build_system!r} has no language in lib/languages.py",
            )
            for lang in matches:
                blob = " ".join((*lang.runner_args, *lang.runner_env))
                self.assertTrue(
                    any(tok in blob for tok in tokens),
                    f"{lang.name} runner drives no sanitizer token",
                )

    def test_default_model_and_end_to_end_cell_metadata(self) -> None:
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("GEMINI_MODEL_DEFAULT", None)
            self.assertEqual(llm_invoke.default_model("gemini"), "gemini-3.1-pro-preview")
        with mock.patch.dict(os.environ, {"GEMINI_MODEL_DEFAULT": "custom-model"}):
            self.assertEqual(llm_invoke.default_model("gemini"), "custom-model")

        slug = f"early-cell-{uuid.uuid4().hex}"
        target = ROOT / "targets" / slug
        self.repo_targets.append(target)
        target.mkdir()
        (target / "file.c").write_text("int main(void) { return 0; }\n", encoding="utf-8")
        (target / "target.toml").write_text(
            'target = "sample"\n[sanitizer]\nenabled = []\n'
            '[runner]\nbin = "/bin/true"\nargs = []\n',
            encoding="utf-8",
        )
        fake = self.root / "fake-codex"
        fake.write_text(
            f"#!{sys.executable}\n"
            "import json, sys\n"
            "args = sys.argv[1:]\n"
            "cd = args[args.index('--cd') + 1]\n"
            "adds = [args[i + 1] for i, value in enumerate(args[:-1]) if value == '--add-dir']\n"
            "print('FAKE_ARGS=' + json.dumps(args), file=sys.stderr)\n"
            "print('FAKE_CD=' + cd, file=sys.stderr)\n"
            "print('FAKE_ADDS=' + '|'.join(adds), file=sys.stderr)\n"
            "print(json.dumps({'type': 'item.completed', 'usage': {"
            "'input_tokens': 1, 'cached_input_tokens': 0, 'output_tokens': 1}}))\n",
            encoding="utf-8",
        )
        fake.chmod(0o755)
        bench_root = self.root / "bench"
        environment = os.environ | {"CODEX_BIN": str(fake)}
        process = subprocess.run(
            [
                sys.executable, str(ROOT / "bin" / "benchmark"),
                "--target", slug, "--backend", "codex", "--replicates", "1",
                "--conditions", "model-direct", "--budget-wall", "5",
                "--bench-root", str(bench_root), "--no-validate-findings",
            ],
            env=environment, text=True, capture_output=True, timeout=90, check=False,
        )
        self.assertEqual(process.returncode, 0, process.stdout + process.stderr)
        output = process.stdout + process.stderr
        self.assertIn("Cell model-direct-r1 validation: DISABLED", output)
        self.assertIn(
            "findings: rejected=0 confirmed=0 pending=0 roots=0; "
            "crashes: rejected=0 confirmed=0 unique=0",
            output,
        )
        cells = list(bench_root.glob("codex/*/cells/model-direct-r1"))
        self.assertEqual(len(cells), 1)
        cell = cells[0]
        metadata = json.loads((cell / "cell.json").read_text(encoding="utf-8"))
        self.assertEqual(metadata["status"], "done")
        self.assertEqual(Path(metadata["results_dir"]), cell)
        self.assertTrue((cell / "findings").is_dir())
        self.assertTrue((cell / "crashes").is_dir())
        self.assertFalse((cell / "workspace").exists())
        self.assertFalse((target / "findings").exists())
        self.assertTrue((target / "file.c").is_file())
        usage = json.loads((cell / "logs" / "index.jsonl").read_text(encoding="utf-8"))
        self.assertEqual(usage["tokens"]["input"], 1)
        self.assertEqual(usage["backend"], "codex")
        prompt = (cell / "prompt.txt").read_text(encoding="utf-8")
        self.assertIn(str(cell), prompt)
        self.assertIn(str(target.resolve()), prompt)
        self.assertNotRegex(prompt, r"\{\{\s*(target_path|output_dir)\s*\}\}")
        raw = (cell / "backend.raw.log").read_text(encoding="utf-8")
        args_line = next(
            line for line in raw.splitlines() if line.startswith("FAKE_ARGS=")
        )
        invoked = json.loads(args_line.removeprefix("FAKE_ARGS="))
        self.assertIn("features.plugins=false", invoked)
        self.assertIn(f"FAKE_CD={cell}", raw)
        self.assertIn(str(target.resolve()), raw.split("FAKE_ADDS=", 1)[1])

    def test_find_gate_uses_benchmark_context(self) -> None:
        results = self.root / "gate-results"
        results.mkdir()
        config = target_config.Config(
            target_root=str(self.root / "target"), attacker_controls=["bytes"]
        )
        observed: dict[str, str] = {}

        def validate(path, **kwargs):
            observed.update({
                key: os.environ.get(key, "")
                for key in ("ACTIVE_BACKEND", "MODEL", "TARGET_ROOT", "TARGET_SLUG")
            })
            return {"accepted": 1, "rejected": 2, "pending": 0}

        with mock.patch.object(benchmark_runner, "benchmark_target_config", return_value=config), \
                mock.patch.object(benchmark_runner.triage, "validate_find_gate", side_effect=validate):
            counts = benchmark_runner.drain_find_gate(
                results, "codex", "sample-model", self.root / "target", "sample-slug"
            )
        self.assertEqual(counts, {"accepted": 1, "rejected": 2, "pending": 0})
        self.assertEqual(observed["ACTIVE_BACKEND"], "codex")
        self.assertEqual(observed["MODEL"], "sample-model")
        self.assertEqual(observed["TARGET_ROOT"], str(self.root / "target"))
        self.assertEqual(observed["TARGET_SLUG"], "sample-slug")

    def test_discarded_hypotheses_are_harvested_and_pooled(self) -> None:
        results = self.root / "discarded-results"
        state = results / "state"
        state.mkdir(parents=True)
        rows = [
            {"id": "H-1", "agent": "1", "file": "a/x.c:parse:10",
             "hypothesis": "bounds in parse", "note": "three clean variants", "status": "DISCARDED"},
            {"id": "H-2", "agent": "2", "file": "a/y.c:free:20",
             "hypothesis": "lifetime in free", "note": "guard saturated", "status": "DISCARDED"},
            {"id": "H-3", "agent": "1", "file": "a/z.c:pack:30",
             "hypothesis": "size in pack", "note": "open", "status": "PENDING"},
        ]
        (state / "hypotheses.jsonl").write_text(
            "".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8"
        )
        metrics = benchmark.harvest(results)
        self.assertEqual(metrics["discarded_hypotheses"], 2)

        bench = self.root / "discarded-bench"
        cell = bench / "cells" / "d-r1"
        cell.mkdir(parents=True)
        (cell / "results").symlink_to(results, target_is_directory=True)
        self.write_json(cell / "cell.json", {
            "condition": "harness", "replicate": 1, "status": "done",
            "wall_seconds": 60, "results_dir": str(results),
        })
        self.write_json(cell / "metrics.json", metrics)
        benchmark.build_pool(bench)
        roster = bench / "pool" / "crashes-rejected" / "DISCARDED-harness-d-r1.md"
        self.assertTrue(roster.is_file())
        roster_text = roster.read_text(encoding="utf-8")
        for text in ("| 1 |", "| 2 |", "three clean variants", "bounds in parse"):
            self.assertIn(text, roster_text)
        index = (bench / "pool" / "crashes-rejected" / "REJECTED-CRASHES.md").read_text()
        self.assertIn("## Discarded hypotheses", index)
        self.assertIn(roster.name, index)

    def make_config_cell(self, bench: Path, name: str, config: str) -> Path:
        results = bench / "output" / name / "backend" / "results"
        results.mkdir(parents=True)
        (results.parents[1] / "target.toml").write_text(config, encoding="utf-8")
        cell = bench / "cells" / name
        cell.mkdir(parents=True)
        self.write_json(cell / "cell.json", {
            "condition": "harness", "replicate": 1, "status": "done",
            "wall_seconds": 1, "results_dir": str(results),
        })
        self.write_json(cell / "metrics.json", {"crash_dirs": []})
        return results

    def test_pool_target_config_resolution_and_normalization(self) -> None:
        for name, controls in (
            ("matching", (["bytes", "call-sequence"], ["bytes", "call-sequence"])),
            ("aliases", (["call-order", "bytes"], ["bytes", "call-sequence"])),
        ):
            with self.subTest(name=name):
                bench = self.root / name
                for index, values in enumerate(controls, 1):
                    self.make_config_cell(
                        bench, f"sample-{index}",
                        f'includes = ["/tmp/generated-{index}"]\n[threat_model]\n'
                        f"attacker_controls = {json.dumps(values)}\n",
                    )
                benchmark.build_pool(bench)
                text = (bench / "pool" / "target.toml").read_text(encoding="utf-8")
                self.assertIn('attacker_controls = ["bytes", "call-sequence"]', text)

        base = self.root / "live"
        pool = base / "pool"
        pool.mkdir(parents=True)
        stale = base / "stale.toml"
        live = base / "live.toml"
        stale.write_text('[threat_model]\nattacker_controls = ["bytes", "call-sequence"]\n')
        live.write_text('[threat_model]\nattacker_controls = ["bytes"]\n')
        benchmark._copy_pool_target_toml(pool, [stale], live_target_toml=live)
        self.assertIn('attacker_controls = ["bytes"]', (pool / "target.toml").read_text())
        (pool / "target.toml").unlink()
        benchmark._copy_pool_target_toml(pool, [stale], live_target_toml=None)
        self.assertIn("call-sequence", (pool / "target.toml").read_text())

        nested = self.root / "nested" / "output" / "samples" / "demo"
        results = nested / "backend" / "results"
        results.mkdir(parents=True)
        (nested / "target.toml").write_text('[threat_model]\nattacker_controls = ["bytes"]\n')
        self.assertEqual(
            benchmark._find_output_target_toml(results), (nested / "target.toml").resolve()
        )

    def test_rejected_indexes_and_cluster_links(self) -> None:
        rejected = self.root / "rejected"
        report = rejected / "CRASH-REJECTED-0001" / "REPORT.md"
        report.parent.mkdir(parents=True)
        report.write_text("# Rejected crash\nTrigger source: bytes\n", encoding="utf-8")
        benchmark.write_rejected_crashes_index(rejected)
        index = rejected / "REJECTED-CRASHES.md"
        text = index.read_text(encoding="utf-8")
        self.assertIn("[Link](CRASH-REJECTED-0001/REPORT.md)", text)
        self.assertIn("| ID | Site | Reason | Report |", text)
        self.assertNotIn("[CRASH-REJECTED-0001/](CRASH-REJECTED-0001/)", text)
        rendered = subprocess.run(
            [sys.executable, str(ROOT / "bin" / "render-md"), str(index), "--html-sibling"],
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(rendered.returncode, 0, rendered.stderr)
        self.assertIn(
            'href="CRASH-REJECTED-0001/REPORT.html"',
            (rejected / "REJECTED-CRASHES.html").read_text(encoding="utf-8"),
        )

        layouts = [self.root / "regular", self.root / "pool" / "harness"]
        for layout in layouts:
            for directory in ("crashes", "crashes-rejected", "findings", "findings-rejected"):
                (layout / directory).mkdir(parents=True)
            (layout / "crashes-rejected" / "REJECTED-CRASHES.md").write_text("# Rejected\n")
            (layout / "findings-rejected" / "REJECTED-FINDINGS.md").write_text("# Rejected\n")
            for command in ("cluster-crashes", "cluster-findings"):
                process = subprocess.run(
                    [sys.executable, str(ROOT / "bin" / command), str(layout)],
                    capture_output=True, text=True, check=False,
                )
                self.assertEqual(process.returncode, 0, process.stderr)
            self.assertIn(
                'href="../crashes-rejected/REJECTED-CRASHES.html"',
                (layout / "crashes" / "CRASH-CLUSTERS.html").read_text(),
            )
            self.assertIn(
                'href="../findings-rejected/REJECTED-FINDINGS.html"',
                (layout / "findings" / "FINDING-CLUSTERS.html").read_text(),
            )

    def write_cell(self, path: Path, results: Path, requested: str) -> dict:
        args = argparse.Namespace(
            path=str(path), condition="harness", replicate="1", experiment="sample",
            results_dir=str(results), wall_seconds="100", status="done",
            requested_agents=requested, paused_seconds="0",
        )
        self.assertEqual(benchmark._cmd_write_cell(args), 0)
        return json.loads(path.read_text(encoding="utf-8"))

    def test_cell_metadata_records_requested_and_actual_agents(self) -> None:
        results = self.root / "agents" / "results"
        config = results / "state" / "run-config.json"
        self.write_json(config, {"num_agents": 3, "backend": "claude"})
        path = self.root / "agents" / "cell.json"
        matching = self.write_cell(path, results, "3")
        self.assertEqual(matching["requested_agents"], 3)
        self.assertEqual(matching["actual_agents"], 3)
        self.assertNotIn("agent_count_mismatch", matching)
        mismatch = self.write_cell(path, results, "1")
        self.assertEqual(mismatch["requested_agents"], 1)
        self.assertEqual(mismatch["actual_agents"], 3)
        self.assertTrue(mismatch["agent_count_mismatch"])
        config.unlink()
        absent = self.write_cell(path, results, "1")
        self.assertEqual(absent["requested_agents"], 1)
        self.assertNotIn("actual_agents", absent)
        self.write_json(config, {"num_agents": 2, "backend": "claude"})
        unspecified = self.write_cell(path, results, "")
        self.assertEqual(unspecified["actual_agents"], 2)
        self.assertNotIn("requested_agents", unspecified)


if __name__ == "__main__":
    unittest.main(verbosity=2)
