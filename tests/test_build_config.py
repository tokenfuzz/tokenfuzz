#!/usr/bin/env python3
"""Primary-preserving build configuration behavior."""

from __future__ import annotations

import json
import importlib.machinery
import importlib.util
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

import audit_runner
import build_config
import build_preflight
import crash_bundle
import target_config

_BUILD_CONFIGS_LOADER = importlib.machinery.SourceFileLoader(
    "build_configs_command", str(ROOT / "bin" / "build-configs")
)
_BUILD_CONFIGS_SPEC = importlib.util.spec_from_loader(
    _BUILD_CONFIGS_LOADER.name, _BUILD_CONFIGS_LOADER
)
build_configs = importlib.util.module_from_spec(_BUILD_CONFIGS_SPEC)
_BUILD_CONFIGS_LOADER.exec_module(build_configs)


class BuildConfigTests(unittest.TestCase):
    def test_identity_preserves_argument_order_and_isolates_primary(self) -> None:
        first = build_config.BuildConfig("wide", "wide", ("-DA=1", "-DB=2"))
        reordered = build_config.BuildConfig("wide", "wide", ("-DB=2", "-DA=1"))
        self.assertNotEqual(first.config_id, reordered.config_id)
        self.assertEqual(build_config.suffix(first, "-image"), f"-image+cfg-{first.config_id}")
        self.assertEqual(build_config.build_dir("/tmp/src", first).name, f"build-asan+cfg-{first.config_id}")
        self.assertEqual(Path("/tmp/src/build-asan").name, "build-asan")
        recipe = Path("/tmp/widened.sh")
        self.assertNotEqual(
            build_configs.unavailable_path(recipe, "", backend="claude"),
            build_configs.unavailable_path(recipe, "", backend="codex"),
        )
        command = build_configs.recipe_command(
            Path("/tmp/src"), first, Path("/tmp/widened.sh")
        )
        self.assertNotIn("--llm-timeout-secs", command)
        widened = build_config.BuildConfig("widened", "widened", widen=True)
        command = build_configs.recipe_command(
            Path("/tmp/src"), widened, Path("/tmp/widened.sh")
        )
        attempts_index = command.index("--max-iters")
        self.assertEqual(command[attempts_index + 1], "2")
        timeout_index = command.index("--llm-timeout-secs")
        self.assertEqual(command[timeout_index + 1], "600")
        self.assertEqual(build_configs.recipe_timeout_seconds(widened, 900), 3060)

    def test_loader_adds_visible_widened_sibling_and_honors_opt_out(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "target.toml"
            path.write_text('target="sample"\nbuild_system="cmake"\n', encoding="utf-8")
            config = target_config.Config(target_root=directory)
            target_config.load_toml_into(config, path)
            self.assertEqual([item.name for item in config.build_configs], ["widened"])
            path.write_text(
                'target="sample"\nbuild_system="cmake"\nbuild_widening=false\n'
                '[[build_config]]\nname="compact"\nflags=["-DA=1", "-DB=2"]\nfeatures=["small tables"]\n',
                encoding="utf-8",
            )
            target_config.load_toml_into(config, path)
            self.assertFalse(config.build_widening)
            self.assertEqual(config.build_configs[0].flags, ("-DA=1", "-DB=2"))

            path.write_text(
                'target="sample"\nbuild_system="cmake"\nbuild_widening=true\n'
                '[sanitizer]\nenabled=[]\n'
                '[[build_config]]\nname="compact"\nflags=["-DA=1"]\n',
                encoding="utf-8",
            )
            target_config.load_toml_into(config, path)
            self.assertFalse(config.build_widening)
            self.assertEqual(config.build_configs, [])

    def test_fallback_toml_parser_reads_array_tables(self) -> None:
        parsed = target_config._parse_simple_toml(
            'target="sample"\n[[build_config]]\nname="one"\nflags=["-DA=1"]\n'
            '[[build_config]]\nname="two"\nwiden=true\n'
        )
        self.assertEqual([row["name"] for row in parsed["build_config"]], ["one", "two"])

    def test_placeholder_refresh_preserves_build_policy(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "sample"
            root.mkdir()
            (root / "CMakeLists.txt").write_text("project(sample C)\n")
            path = Path(directory) / "target.toml"
            path.write_text(
                'target="sample"\nbuild_system="cmake"\nbuild_widening=false\n'
                '[[build_config]]\nname="compact"\nflags=["-DSMALL=ON"]\n'
                'features=["small tables"]\n',
                encoding="utf-8",
            )
            target_config.seed_toml(root, path, preserve_curated=True)
            parsed = target_config.parse_toml(path)
            self.assertFalse(parsed["build_widening"])
            self.assertEqual(parsed["build_config"][0]["flags"], ["-DSMALL=ON"])

    def test_probe_runs_the_selected_alternate(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target"
            results = root / "output" / "sample" / "codex" / "results"
            scratch = results / "scratch-1"
            logs = root / "logs"
            scratch.mkdir(parents=True)
            logs.mkdir()
            primary = target / "build-asan" / "tool"
            primary.parent.mkdir(parents=True)
            primary.write_text("#!/bin/sh\nexit 9\n")
            primary.chmod(0o755)
            config_path = root / "output" / "sample" / "target.toml"
            config_path.write_text(
                'target="sample"\nbuild_system="cmake"\nbuild_widening=false\n'
                'asan_bin="build-asan/tool"\n'
                '[[build_config]]\nname="compact"\nflags=["-DSMALL=ON"]\n',
                encoding="utf-8",
            )
            config = target_config.Config(target_root=str(target))
            target_config.load_toml_into(config, config_path)
            item = config.build_configs[0]
            alternate = build_config.build_dir(target, item) / "tool"
            alternate.parent.mkdir(parents=True)
            marker = root / "alternate-ran"
            alternate.write_text(
                f'#!/bin/sh\ntouch "{marker}"\necho TESTCASE_EXECUTED\n',
                encoding="utf-8",
            )
            alternate.chmod(0o755)
            recipe = build_config.recipe_path(target, item)
            recipe.parent.mkdir(parents=True)
            recipe.write_text("#!/bin/sh\n")
            build_config.write_recipe_stamp(alternate.parent, recipe)
            build_config.mark_ready(alternate.parent, recipe)
            (results / ".session-env").write_text(
                f"RESULTS_DIR={results}\nTARGET_ROOT={target}\nTARGET_SLUG=sample\n"
                f"TARGET_REV=test\nLOGDIR={logs}\n"
            )
            testcase = scratch / "testcase.txt"
            testcase.write_text(
                "// TARGET: sample.c:parse:1\n// HYPOTHESIS-ID: H1\n"
                "// CATEGORY: bounds\n// MODE: generic\ninput\n"
            )
            environment = os.environ.copy()
            environment.update(
                PROBE_BUILD_CONFIG="compact", PROBE_AUTO_ROUTE="0",
                LLM_DECIDE_DISABLE="1",
            )
            environment.pop("AUDIT_BUILD_SUFFIX", None)
            completed = subprocess.run(
                [str(ROOT / "bin" / "probe"), str(testcase)],
                env=environment, capture_output=True, text=True, check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
            self.assertTrue(marker.is_file(), completed.stdout + completed.stderr)
            self.assertIn("build_config=compact", completed.stdout)

    def test_confirmed_alternate_crash_runs_primary_differential(self) -> None:
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
            primary = target / "build-asan/tool"
            primary.parent.mkdir()
            primary.write_text("#!/bin/sh\necho TESTCASE_EXECUTED\n")
            primary.chmod(0o755)
            config_path = root / "output/sample/target.toml"
            config_path.write_text(
                'target="sample"\nbuild_system="cmake"\nbuild_widening=false\n'
                'asan_bin="build-asan/tool"\n'
                '[[build_config]]\nname="compact"\nflags=["-DSMALL=ON"]\n',
                encoding="utf-8",
            )
            config = target_config.Config(target_root=str(target))
            target_config.load_toml_into(config, config_path)
            item = config.build_configs[0]
            alternate = build_config.build_dir(target, item) / "tool"
            alternate.parent.mkdir(parents=True)
            alternate.write_text(
                "#!/bin/sh\n"
                "echo TESTCASE_EXECUTED\n"
                "echo 'ERROR: AddressSanitizer: heap-buffer-overflow' >&2\n"
                f"echo '    #0 0x1 in app_parse {source}:1' >&2\n"
                f"echo 'SUMMARY: AddressSanitizer: heap-buffer-overflow {source}:1 in app_parse' >&2\n"
                "exit 1\n",
                encoding="utf-8",
            )
            alternate.chmod(0o755)
            recipe = build_config.recipe_path(target, item)
            recipe.parent.mkdir(parents=True)
            recipe.write_text("#!/bin/sh\n")
            build_config.write_recipe_stamp(alternate.parent, recipe)
            build_config.mark_ready(alternate.parent, recipe)
            (results / ".session-env").write_text(
                f"RESULTS_DIR={results}\nTARGET_ROOT={target}\nTARGET_SLUG=sample\n"
                f"TARGET_REV=test\nLOGDIR={logs}\n"
            )
            testcase = scratch / "testcase.txt"
            testcase.write_text(
                "// TARGET: src/app.c:app_parse:1\n// HYPOTHESIS-ID: H1\n"
                "// CATEGORY: bounds\n// MODE: generic\ninput\n"
            )
            environment = os.environ.copy()
            environment.update(
                PROBE_BUILD_CONFIG="compact", PROBE_AUTO_ROUTE="0",
                LLM_DECIDE_DISABLE="1",
            )
            environment.pop("AUDIT_BUILD_SUFFIX", None)
            completed = subprocess.run(
                [str(ROOT / "bin/probe"), "--confirm", str(testcase)],
                env=environment, capture_output=True, text=True, check=False,
            )
            crashes = list((results / "crashes").glob("CRASH-*"))
            self.assertEqual(len(crashes), 1, completed.stdout + completed.stderr)
            evidence = crash_bundle.verified_primary_differential(crashes[0])
            self.assertIsNotNone(evidence, completed.stdout + completed.stderr)
            self.assertEqual(evidence["status"], "not-reproduced")
            self.assertIn("PRIMARY BUILD DIFFERENTIAL: not-reproduced", completed.stdout)

    def test_materializer_builds_only_the_named_sibling(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "source"
            root.mkdir()
            (root / "CMakeLists.txt").write_text("project(sample C)\n", encoding="utf-8")
            primary = root / "build-asan"
            primary.mkdir()
            primary_control = primary / "control"
            primary_control.write_text("regular\n")
            target_config.build_write_stamp(root, "asan")
            config_path = Path(directory) / "target.toml"
            config_path.write_text(
                'target="sample"\nbuild_system="cmake"\nbuild_widening=false\n'
                '[[build_config]]\nname="compact"\nflags=["-DSMALL=ON"]\n',
                encoding="utf-8",
            )
            config = target_config.Config(target_root=str(root))
            target_config.load_toml_into(config, config_path)
            item = config.build_configs[0]
            recipe = build_config.recipe_path(root, item)
            recipe.parent.mkdir(parents=True)
            recipe.write_text(
                "#!/usr/bin/env bash\nset -eu\nbuild=\"$2\"\nmkdir -p \"$build\"\n"
                "dd if=/dev/zero of=\"$build/sample\" bs=5000 count=1 2>/dev/null\nchmod +x \"$build/sample\"\n",
                encoding="utf-8",
            )
            recipe.chmod(0o755)
            completed = subprocess.run(
                [
                    str(ROOT / "bin" / "build-configs"),
                    "--target-path", str(root), "--target-toml", str(config_path),
                    "--config", "compact", "--timeout-seconds", "30",
                ],
                capture_output=True, text=True, check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
            tree = build_config.build_dir(root, item)
            self.assertTrue((tree / "sample").is_file())
            self.assertTrue(build_config.is_ready(tree, recipe))
            self.assertEqual(primary_control.read_text(), "regular\n")

    def test_failed_alternate_is_cached_until_forced(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "source"
            root.mkdir()
            (root / "CMakeLists.txt").write_text("project(sample C)\n", encoding="utf-8")
            primary = root / "build-asan"
            primary.mkdir()
            target_config.build_write_stamp(root, "asan")
            primary_recipe = root / ".audit" / "build.sh"
            primary_recipe.parent.mkdir(parents=True)
            primary_recipe.write_text("#!/bin/sh\n# primary one\n")
            config_path = Path(directory) / "target.toml"
            config_path.write_text(
                'target="sample"\nbuild_system="cmake"\nbuild_widening=false\n'
                '[[build_config]]\nname="broken"\nflags=["-DBROKEN=ON"]\n',
                encoding="utf-8",
            )
            config = target_config.Config(target_root=str(root))
            target_config.load_toml_into(config, config_path)
            recipe = build_config.recipe_path(root, config.build_configs[0])
            recipe.parent.mkdir(parents=True)
            recipe.write_text(
                '#!/usr/bin/env bash\necho attempt >> "$1/.audit/attempts"\nexit 1\n',
                encoding="utf-8",
            )
            recipe.chmod(0o755)
            command = [
                str(ROOT / "bin" / "build-configs"), "--target-path", str(root),
                "--target-toml", str(config_path), "--config", "broken",
                "--timeout-seconds", "30",
            ]
            first = subprocess.run(command, capture_output=True, text=True, check=False)
            second = subprocess.run(command, capture_output=True, text=True, check=False)
            self.assertEqual((first.returncode, second.returncode), (1, 1))
            self.assertIn("unavailable for this source/primary recipe", second.stderr)
            primary_recipe.write_text("#!/bin/sh\n# primary two\n")
            changed = subprocess.run(command, capture_output=True, text=True, check=False)
            self.assertEqual(changed.returncode, 1)
            self.assertEqual((root / ".audit/attempts").read_text().splitlines(), ["attempt", "attempt"])

    def test_widening_without_backend_fails_before_caching(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "source"
            root.mkdir()
            (root / "CMakeLists.txt").write_text("project(sample C)\n")
            primary = root / "build-asan"
            primary.mkdir()
            target_config.build_write_stamp(root, "asan")
            config_path = Path(directory) / "target.toml"
            config_path.write_text(
                'target="sample"\nbuild_system="cmake"\nbuild_widening=true\n',
                encoding="utf-8",
            )
            environment = os.environ.copy()
            for key in ("ACTIVE_BACKEND", "BACKEND"):
                environment.pop(key, None)
            completed = subprocess.run(
                [str(ROOT / "bin/build-configs"), "--target-path", str(root),
                 "--target-toml", str(config_path), "--all"],
                env=environment, capture_output=True, text=True, check=False,
            )
            self.assertEqual(completed.returncode, 2)
            self.assertIn("automatic widening requires --backend", completed.stderr)
            self.assertEqual(list((root / ".audit/configs").glob("*.unavailable")), [])

            help_output = subprocess.run(
                [str(ROOT / "bin/build-configs"), "--help"],
                capture_output=True, text=True, check=False,
            )

    def test_widening_without_surface_options_is_cached_as_not_applicable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "source"
            root.mkdir()
            (root / "CMakeLists.txt").write_text("project(sample C)\n")
            primary = root / "build-asan"
            primary.mkdir()
            target_config.build_write_stamp(root, "asan")
            primary_recipe = root / ".audit/build.sh"
            primary_recipe.parent.mkdir(parents=True)
            primary_recipe.write_text(
                "#!/usr/bin/env bash\nset -eu\nsrc=\"$1\"; build=\"$2\"\n"
                ": -fsanitize=address -O2 -g1 -DNDEBUG -fno-omit-frame-pointer\n"
            )
            primary_recipe.chmod(0o755)
            config_path = Path(directory) / "target.toml"
            config_path.write_text(
                'target="sample"\nbuild_system="cmake"\nbuild_widening=true\n',
                encoding="utf-8",
            )
            command = [
                str(ROOT / "bin/build-configs"), "--target-path", str(root),
                "--target-toml", str(config_path), "--all", "--backend", "codex",
            ]
            first = subprocess.run(command, capture_output=True, text=True, check=False)
            second = subprocess.run(command, capture_output=True, text=True, check=False)
            self.assertEqual((first.returncode, second.returncode), (0, 0))
            self.assertIn("not applicable", first.stderr)
            self.assertIn("not applicable", second.stderr)
            self.assertEqual(len(list((root / ".audit/configs").glob("*.not-applicable"))), 1)
            self.assertEqual(list((root / ".audit/configs").glob("*.unavailable")), [])

    def test_crash_bundle_keeps_exact_alternate_recipe(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            testcase = root / "input.bin"
            sanitizer = root / "trace.txt"
            recipe = root / "config.sh"
            binary = root / "binary"
            testcase.write_bytes(b"A")
            sanitizer.write_text("AddressSanitizer: heap-buffer-overflow\n")
            recipe.write_text("#!/bin/sh\necho CONFIG_RECIPE\n")
            binary.write_bytes(b"binary")
            binary.chmod(0o755)
            item = build_config.BuildConfig("wide", "wide", widen=True)
            status, crash_id = crash_bundle.materialize(
                root, "1", testcase, sanitizer, "asan", "generic",
                binary=binary, build_config=item, build_recipe=recipe,
            )
            self.assertEqual(status, "FILED")
            crash = root / "crashes" / crash_id
            metadata = json.loads((crash / ".build-config.json").read_text())
            self.assertEqual(metadata["id"], item.config_id)
            self.assertEqual((crash / ".build-config-recipe.sh").read_text(), recipe.read_text())
            recipe.write_text("#!/bin/sh\necho CHANGED_CONFIG_RECIPE\n")
            changed_status, changed_id = crash_bundle.materialize(
                root, "1", testcase, sanitizer, "asan", "generic",
                binary=binary, build_config=item, build_recipe=recipe,
            )
            self.assertEqual(changed_status, "FILED")
            self.assertNotEqual(changed_id, crash_id)
            primary_status, primary_id = crash_bundle.materialize(
                root, "1", testcase, sanitizer, "asan", "generic", binary=binary,
            )
            self.assertEqual(primary_status, "FILED")
            self.assertNotEqual(primary_id, crash_id)

    def test_primary_differential_is_bound_to_both_builds_and_testcase(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            testcase = root / "input.bin"
            alternate_sanitizer = root / "alternate.txt"
            primary_sanitizer = root / "primary.txt"
            recipe = root / "config.sh"
            alternate_binary = root / "build-asan+cfg-wide" / "tool"
            primary_binary = root / "build-asan" / "tool"
            alternate_binary.parent.mkdir()
            primary_binary.parent.mkdir()
            testcase.write_bytes(b"A")
            recipe.write_text("#!/bin/sh\n")
            for binary in (alternate_binary, primary_binary):
                binary.write_bytes(b"binary")
                binary.chmod(0o755)
            alternate_sanitizer.write_text(
                "ERROR: AddressSanitizer: heap-buffer-overflow\n"
                "    #0 0x1 in app_parse src/app.c:9\n"
                "CRASH_RATE: 5/5\n"
                "[run-sanitizer-multi] EXECUTION_RATE: 5/5\n"
            )
            primary_sanitizer.write_text(
                "CRASH_RATE: 0/5\n"
                "[run-sanitizer-multi] EXECUTION_RATE: 5/5\n"
            )
            item = build_config.BuildConfig(
                "wide", "wide", features=("legacy APIs",), widen=True
            )
            _, crash_id = crash_bundle.materialize(
                root, "1", testcase, alternate_sanitizer, "asan", "generic",
                binary=alternate_binary, build_config=item, build_recipe=recipe,
            )
            crash = root / "crashes" / crash_id
            # The bundle records the configuration identity and advertised
            # features so bin/severity can surface them without target.toml.
            self.assertEqual(
                json.loads((crash / ".build-config.json").read_text())["features"],
                ["legacy APIs"],
            )
            result = crash_bundle.record_primary_differential(
                crash,
                primary_sanitizer,
                {
                    "version": 1,
                    "testcase_sha1": crash_bundle._sha1(testcase),
                    "build_config": "primary",
                    "verdict": "CLEAN",
                    "binary": crash_bundle.binary_identity(primary_binary),
                },
            )
            self.assertIsNotNone(result)
            self.assertEqual(result["status"], "not-reproduced")
            self.assertEqual(
                crash_bundle.verified_primary_differential(crash)["status"],
                "not-reproduced",
            )
            primary_binary.write_bytes(b"changed")
            self.assertIsNone(crash_bundle.verified_primary_differential(crash))

    def test_rotation_keeps_one_reproducer_on_primary(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            results = root / "results"
            results.mkdir()
            item = build_config.BuildConfig("wide", "wide", widen=True)
            recipe = build_config.recipe_path(root, item)
            tree = build_config.build_dir(root, item)
            recipe.parent.mkdir(parents=True)
            recipe.write_text("#!/bin/sh\n")
            tree.mkdir()
            artifact = tree / "tool"
            artifact.write_bytes(b"x" * 5000)
            artifact.chmod(0o755)
            build_config.write_recipe_stamp(tree, recipe)
            build_config.mark_ready(tree, recipe)
            runtime = SimpleNamespace(
                results=results, target_root=root,
                config=SimpleNamespace(build_configs=[item]), num_agents=3,
            )
            context = SimpleNamespace(role=lambda agent: "analysis" if agent == 3 else "reproduce")
            with mock.patch.object(audit_runner, "index_log"), mock.patch.object(
                audit_runner.structured_state, "agent_counts", return_value={"active": 0}
            ):
                audit_runner.assign_build_configs(runtime, context, 1)
            self.assertFalse((results / "state/build-config-1").exists())
            self.assertEqual(
                (results / "state/build-config-2").read_text().strip(), item.config_id
            )
            self.assertFalse((results / "state/build-config-3").exists())

    def test_single_agent_does_not_switch_an_active_hypothesis(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            results = root / "results"
            state = results / "state"
            state.mkdir(parents=True)
            item = build_config.BuildConfig("wide", "wide", widen=True)
            recipe = build_config.recipe_path(root, item)
            tree = build_config.build_dir(root, item)
            recipe.parent.mkdir(parents=True)
            recipe.write_text("#!/bin/sh\n")
            tree.mkdir()
            build_config.write_recipe_stamp(tree, recipe)
            build_config.mark_ready(tree, recipe)
            assignment = state / "build-config-1"
            assignment.write_text(item.config_id + "\n")
            runtime = SimpleNamespace(
                results=results, target_root=root,
                config=SimpleNamespace(build_configs=[item]), num_agents=1,
            )
            context = SimpleNamespace(role=lambda _agent: "reproduce")
            with mock.patch.object(audit_runner, "index_log"), mock.patch.object(
                audit_runner.structured_state, "agent_counts", return_value={"active": 1}
            ):
                audit_runner.assign_build_configs(runtime, context, 3)
            self.assertEqual(assignment.read_text().strip(), item.config_id)

    def test_single_agent_keeps_three_of_four_closed_iterations_primary(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            results = root / "results"
            results.mkdir()
            item = build_config.BuildConfig("wide", "wide", widen=True)
            recipe = build_config.recipe_path(root, item)
            tree = build_config.build_dir(root, item)
            recipe.parent.mkdir(parents=True)
            recipe.write_text("#!/bin/sh\n")
            tree.mkdir()
            build_config.write_recipe_stamp(tree, recipe)
            build_config.mark_ready(tree, recipe)
            runtime = SimpleNamespace(
                results=results, target_root=root,
                config=SimpleNamespace(build_configs=[item]), num_agents=1,
            )
            context = SimpleNamespace(role=lambda _agent: "reproduce")
            assignments = []
            with mock.patch.object(audit_runner, "index_log"), mock.patch.object(
                audit_runner.structured_state, "agent_counts", return_value={"active": 0}
            ):
                for iteration in range(1, 5):
                    audit_runner.assign_build_configs(runtime, context, iteration)
                    path = results / "state/build-config-1"
                    assignments.append(path.read_text().strip() if path.is_file() else "primary")
            self.assertEqual(assignments, ["primary", "primary", "primary", item.config_id])

    def test_benchmark_policy_clears_alternate_assignments(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            results = Path(directory) / "results"
            state = results / "state"
            state.mkdir(parents=True)
            assignment = state / "build-config-1"
            assignment.write_text("wide-id\n")
            runtime = SimpleNamespace(
                results=results, target_root=Path(directory),
                config=SimpleNamespace(build_configs=[]), num_agents=1,
            )
            context = SimpleNamespace(role=lambda _agent: "reproduce")
            with mock.patch.dict(
                os.environ, {"_TOKENFUZZ_BENCHMARK_PRIMARY_BUILD": "1"}, clear=False
            ):
                audit_runner.assign_build_configs(runtime, context, 1)
            self.assertFalse(assignment.exists())

    def test_preflight_materializes_alternates_without_replacing_primary(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "targets/sample"
            logs = root / "logs"
            toml = root / "output/sample/target.toml"
            target.mkdir(parents=True)
            logs.mkdir()
            toml.parent.mkdir(parents=True)
            toml.write_text('target="sample"\n')
            item = build_config.BuildConfig("wide", "wide", widen=True)
            messages: list[str] = []
            with mock.patch.object(
                build_preflight, "run_timeout",
                return_value=SimpleNamespace(returncode=1),
            ) as launched:
                build_preflight._refresh_alternates(
                    root, target, "sample", SimpleNamespace(build_configs=[item]),
                    {}, logs / "setup-build.log", messages.append,
                )
            command = launched.call_args.args[0]
            self.assertEqual(command[-1], "--all")
            self.assertIn(str(root / "bin/build-configs"), command)
            self.assertEqual(
                launched.call_args.args[1],
                build_preflight._ALTERNATE_PREFLIGHT_TIMEOUT_SECONDS,
            )
            self.assertTrue(any("regular sanitizer build remains active" in line for line in messages))


if __name__ == "__main__":
    unittest.main(verbosity=2)
