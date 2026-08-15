#!/usr/bin/env python3
"""tests/test_build_pin.py — one pinned build generation per benchmark run.

A benchmark converges one build, holds it, and compares every cell against it.
These cover the pieces that make that true: a cell verifies and never builds, the
isolated-tree key is a function of build inputs alone, a cell that read different
source leaves the comparison for good, and garbage collection only ever removes
alternate-configuration trees the harness itself owns.
"""

from __future__ import annotations

import fcntl
import importlib.machinery
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "lib"))
import audit_runner  # noqa: E402
import benchmark_runner  # noqa: E402
import build_config  # noqa: E402
import build_lease  # noqa: E402
import build_preflight  # noqa: E402
import target_config  # noqa: E402

def _load_script(name: str, path: Path):
    """Import an extensionless bin/ entry point as a module."""
    loader = importlib.machinery.SourceFileLoader(name, str(path))
    module = importlib.util.module_from_spec(
        importlib.util.spec_from_loader(loader.name, loader)
    )
    loader.exec_module(module)
    return module


build_configs = _load_script("build_configs_mod", ROOT / "bin" / "build-configs")


def _native_target(root: Path) -> None:
    root.mkdir(parents=True, exist_ok=True)
    (root / "CMakeLists.txt").write_text("cmake_minimum_required(VERSION 3.16)\n")
    (root / "main.c").write_text("int main(void){return 0;}\n")
    (root / ".audit").mkdir(exist_ok=True)
    (root / ".audit" / "build.sh").write_text("#!/bin/sh\n")


def _git_commit_all(root: Path) -> None:
    """Make the target a checkout with tracked source, as a real one is."""
    for args in (("init", "-q"), ("add", "-A"), ("commit", "-qm", "init")):
        subprocess.run(
            ["git", "-c", "user.email=t@example.invalid", "-c", "user.name=t",
             "-c", "init.defaultBranch=main", "-C", str(root), *args],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )


class VerifyOnlyCellTests(unittest.TestCase):
    """A benchmark cell must verify the pinned build and never replace it."""

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="pin-"))
        self.target = self.tmp / "target"
        _native_target(self.target)
        self.config = SimpleNamespace(
            is_browser="0", sanitizers_explicitly_disabled=False,
            sanitizers_enabled=["asan"],
            sanitizer_bin=lambda name: "build-asan/app" if name == "asan" else "",
            sanitizer_lib=lambda name: "",
            resolve_path=lambda raw: str(self.target / raw),
        )

    def tearDown(self) -> None:
        subprocess.run(["rm", "-rf", str(self.tmp)], check=False)

    def _build(self) -> None:
        (self.target / "build-asan").mkdir(exist_ok=True)
        (self.target / "build-asan" / "app").write_text("#!/bin/sh\n")
        (self.target / "build-asan" / "app").chmod(0o755)
        target_config.build_write_stamp(self.target, "asan")

    def _benchmark_environment(self) -> dict[str, str]:
        identity = build_preflight.build_identity(self.target, self.config)
        return {
            "_TOKENFUZZ_BENCHMARK_PRIMARY_BUILD": "1",
            build_preflight.BENCHMARK_BUILD_PIN_ENV:
                build_preflight.encode_benchmark_build_pin(identity),
        }

    def test_no_problems_when_the_pinned_build_is_present(self) -> None:
        self._build()
        self.assertEqual([], build_preflight.build_problems(self.target, self.config))

    def test_missing_tree_is_a_problem(self) -> None:
        problems = build_preflight.build_problems(self.target, self.config)
        self.assertTrue(any("missing" in item for item in problems), problems)

    def test_browser_native_build_is_not_exempt_from_verification(self) -> None:
        self.config.is_browser = "1"
        problems = build_preflight.build_problems(self.target, self.config)
        self.assertTrue(any("missing" in item for item in problems), problems)

    def test_stale_source_is_a_problem(self) -> None:
        self._build()
        (self.target / "main.c").write_text("int main(void){return 1;}\n")
        problems = build_preflight.build_problems(self.target, self.config)
        self.assertTrue(any("stale" in item for item in problems), problems)

    def test_a_stale_build_names_the_paths_that_staled_it(self) -> None:
        """The operator has to choose between rebuilding and removing a
        by-product, and cannot without knowing which path is responsible."""
        _git_commit_all(self.target)
        self._build()
        (self.target / "testcase.db").write_bytes(b"")
        self.assertEqual(
            ["build-asan is stale (changed: testcase.db)"],
            build_preflight.build_problems(self.target, self.config),
        )

    def test_a_changed_recipe_is_named(self) -> None:
        self._build()
        (self.target / ".audit" / "build.sh").write_text(
            "#!/bin/sh\n# changed\n", encoding="utf-8",
        )
        self.assertEqual(
            ["build-asan is stale (changed: .audit/build.sh)"],
            build_preflight.build_problems(self.target, self.config),
        )

    def test_missing_configured_binary_is_a_problem(self) -> None:
        self._build()
        (self.target / "build-asan" / "app").unlink()
        problems = build_preflight.build_problems(self.target, self.config)
        self.assertTrue(any("asan_bin" in item for item in problems), problems)

    def test_findings_only_target_has_nothing_to_verify(self) -> None:
        self.config.sanitizers_explicitly_disabled = True
        self.assertEqual([], build_preflight.build_problems(self.target, self.config))

    def test_findings_only_target_does_not_pin_leftover_native_builds(self) -> None:
        self._build()
        self.config.sanitizers_explicitly_disabled = True
        self.assertEqual(
            {}, build_preflight.build_identity(self.target, self.config),
        )

    def test_disabled_sanitizer_stamp_is_not_part_of_the_pin(self) -> None:
        self._build()
        (self.target / "build-ubsan").mkdir()
        target_config.build_write_stamp(self.target, "ubsan")
        identity = build_preflight.build_identity(self.target, self.config)
        self.assertEqual(set(identity["stamps"]), {"asan"})

    def test_cell_preflight_fails_loudly_and_never_builds(self) -> None:
        self._build()
        environment = self._benchmark_environment()
        (self.target / "build-asan" / "app").write_text("#!/bin/sh\nchanged\n")
        runtime = SimpleNamespace(
            target_root=self.target, config=self.config, root=ROOT,
            target_slug="sampleproj", logs=self.tmp, backend="codex", model="m",
        )
        with mock.patch.dict(
            os.environ, environment, clear=False
        ), mock.patch.object(build_preflight, "refresh") as refresh:
            with self.assertRaises(RuntimeError) as caught:
                audit_runner.preflight_build(runtime)
            self.assertIn("pinned benchmark build", str(caught.exception))
            refresh.assert_not_called()

    def test_cell_preflight_passes_on_a_good_build_without_building(self) -> None:
        self._build()
        environment = self._benchmark_environment()
        runtime = SimpleNamespace(
            target_root=self.target, config=self.config, root=ROOT,
            target_slug="sampleproj", logs=self.tmp, backend="codex", model="m",
        )
        with mock.patch.dict(
            os.environ, environment, clear=False
        ), mock.patch.object(build_preflight, "refresh") as refresh:
            audit_runner.preflight_build(runtime)
            refresh.assert_not_called()

    def test_cell_preflight_requires_the_parent_pin(self) -> None:
        self._build()
        runtime = SimpleNamespace(
            target_root=self.target, config=self.config, root=ROOT,
            target_slug="sampleproj", logs=self.tmp, backend="codex", model="m",
        )
        with mock.patch.dict(
            os.environ, {"_TOKENFUZZ_BENCHMARK_PRIMARY_BUILD": "1"}, clear=True
        ), self.assertRaises(RuntimeError) as caught:
            audit_runner.preflight_build(runtime)
        self.assertIn("pin is missing or unreadable", str(caught.exception))

    def test_the_pin_names_what_changed(self) -> None:
        self._build()
        identity = build_preflight.build_identity(self.target, self.config)
        (self.target / "build-asan" / "app").write_text("#!/bin/sh\nchanged\n")
        self.assertEqual(
            ["asan_bin changed since this run pinned it (build-asan/app)"],
            build_preflight.pinned_build_problems(self.target, identity),
        )
        (self.target / "build-asan" / "app").unlink()
        self.assertEqual(
            ["asan_bin is missing (build-asan/app)"],
            build_preflight.pinned_build_problems(self.target, identity),
        )
        (self.target / "build-asan" / ".audit-build-stamp").unlink()
        self.assertIn(
            "asan_bin is missing (build-asan/app)",
            build_preflight.pinned_build_problems(self.target, identity),
        )

    def test_the_pin_checks_bytes_without_a_target_config(self) -> None:
        """Legacy callers can still verify the exact recorded paths."""
        self._build()
        identity = build_preflight.build_identity(self.target, self.config)
        self.assertEqual(
            [], build_preflight.pinned_build_problems(self.target, identity)
        )

    def test_the_pin_rejects_a_changed_execution_route(self) -> None:
        self._build()
        identity = build_preflight.build_identity(self.target, self.config)
        self.config.sanitizer_bin = lambda name: ""
        self.config.sanitizer_lib = lambda name: "build-asan/libnew.a"
        problems = build_preflight.pinned_build_problems(
            self.target, identity, self.config,
        )
        self.assertTrue(any("no longer selected" in item for item in problems))
        self.assertTrue(any("not part of this run" in item for item in problems))

    def test_a_version_one_pin_keeps_its_recorded_route(self) -> None:
        self._build()
        identity = build_preflight.build_identity(self.target, self.config)
        identity["version"] = 1
        self.config.sanitizer_bin = lambda name: ""
        problems = build_preflight.pinned_build_problems(
            self.target, identity, self.config,
        )
        self.assertIn(
            "asan_bin is no longer selected by target.toml", problems,
        )

    def test_an_empty_pin_has_nothing_to_verify(self) -> None:
        """A target that declares no sanitizer artifacts pins none of them."""
        self.assertEqual([], build_preflight.pinned_build_problems(self.target, {}))

    def test_cell_uses_the_pin_not_checkout_artifacts(self) -> None:
        """A direct cell's generated input cannot reinterpret a pinned build."""
        self._build()
        environment = self._benchmark_environment()
        (self.target / "testcase.db").write_bytes(b"")
        self.assertIn(
            "build-asan is stale",
            build_preflight.build_problems(self.target, self.config),
        )
        runtime = SimpleNamespace(
            target_root=self.target, config=self.config, root=ROOT,
            target_slug="sampleproj", logs=self.tmp, backend="codex", model="m",
        )
        with mock.patch.dict(
            os.environ, environment, clear=False
        ), mock.patch.object(build_preflight, "refresh") as refresh:
            audit_runner.preflight_build(runtime)
            refresh.assert_not_called()


class BuildInputKeyTests(unittest.TestCase):
    """An isolated tree is named by its inputs, so identical inputs share it."""

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="key-"))
        self.target = self.tmp / "target"
        _native_target(self.target)

    def tearDown(self) -> None:
        subprocess.run(["rm", "-rf", str(self.tmp)], check=False)

    def test_same_inputs_produce_the_same_key(self) -> None:
        first = target_config.build_input_key(self.target)
        self.assertEqual(first, target_config.build_input_key(self.target))

    def test_changed_source_produces_a_different_key(self) -> None:
        first = target_config.build_input_key(self.target)
        (self.target / "main.c").write_text("int main(void){return 1;}\n")
        self.assertNotEqual(first, target_config.build_input_key(self.target))

    def test_changed_recipe_produces_a_different_key(self) -> None:
        first = target_config.build_input_key(self.target)
        (self.target / ".audit" / "build.sh").write_text("#!/bin/sh\n# widened\n")
        self.assertNotEqual(first, target_config.build_input_key(self.target))


class DriftAccountingTests(unittest.TestCase):
    """A drifted cell keeps its artifacts and leaves the headline comparison."""

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="drift-"))
        self.cell = self.tmp / "model-direct-r1"
        self.cell.mkdir(parents=True)

    def tearDown(self) -> None:
        subprocess.run(["rm", "-rf", str(self.tmp)], check=False)

    def _write(self, status: str) -> dict:
        benchmark_runner.write_cell(
            self.cell / "cell.json", "model-direct", 1, "bench-x",
            self.cell, 10, status, 1,
        )
        return json.loads((self.cell / "cell.json").read_text(encoding="utf-8"))

    def test_source_drift_quality_survives_into_the_cell_record(self) -> None:
        (self.cell / ".run-quality").write_text("source_drift\n")
        benchmark_runner._write_json(
            self.cell / "source-drift.json",
            {"observed_at": "2026-07-26T00:00:00+00:00", "paths": ["parser.c"]},
        )
        cell = self._write("incomplete")
        self.assertEqual("source_drift", cell["run_quality"])
        self.assertEqual(["parser.c"], cell["source_drift"]["paths"])

    def test_harness_drift_is_recorded_beside_target_drift(self) -> None:
        # The harness tree had no pin at all, so a run whose own code changed
        # mid-flight published its cells as a clean comparison. It is not one:
        # the long-lived process keeps the modules it imported at startup while
        # its subprocesses read the edited files, so one cell can be audited by
        # one revision and finalized by another.
        (self.cell / ".run-quality").write_text("source_drift\n")
        benchmark_runner._write_json(
            self.cell / "harness-drift.json",
            {
                "observed_at": "2026-08-14T17:09:00+00:00",
                "pinned": "0" * 64,
                "observed": "1" * 64,
            },
        )
        cell = self._write("done")
        self.assertEqual("source_drift", cell["run_quality"])
        self.assertEqual("0" * 64, cell["harness_drift"]["pinned"])
        self.assertNotIn("source_drift", cell)

    def test_unknown_quality_markers_are_still_ignored(self) -> None:
        (self.cell / ".run-quality").write_text("banana\n")
        self.assertEqual("clean", self._write("done")["run_quality"])

    def test_a_rebuilt_tree_stops_the_next_cell(self) -> None:
        target = self.tmp / "target"
        _native_target(target)
        (target / "build-asan").mkdir()
        binary = target / "build-asan" / "app"
        binary.write_text("#!/bin/sh\n")
        binary.chmod(0o755)
        target_config.build_write_stamp(target, "asan")
        config = SimpleNamespace(
            is_browser="0", sanitizers_explicitly_disabled=False,
            sanitizers_enabled=["asan"], runner_bin="",
            sanitizer_bin=lambda name: "build-asan/app" if name == "asan" else "",
            sanitizer_lib=lambda name: "",
            resolve_path=lambda raw: str(target / raw),
        )
        pinned = build_preflight.build_identity(target, config)
        self.assertEqual([], build_preflight.pinned_build_problems(target, {}))
        self.assertEqual([], build_preflight.pinned_build_problems(target, pinned))
        (target / "main.c").write_text("int main(void){return 1;}\n")
        target_config.build_write_stamp(target, "asan")
        self.assertEqual(
            ["build-asan was rebuilt since this run pinned it"],
            build_preflight.pinned_build_problems(target, pinned),
        )

    def test_same_input_rebuilds_get_distinct_generations(self) -> None:
        target = self.tmp / "same-input"
        _native_target(target)
        (target / "build-asan").mkdir()
        target_config.build_write_stamp(target, "asan")
        first = (
            target / "build-asan" / ".audit-build-stamp"
        ).read_bytes()
        target_config.build_write_stamp(target, "asan")
        second = (
            target / "build-asan" / ".audit-build-stamp"
        ).read_bytes()
        self.assertNotEqual(first, second)
        self.assertEqual(target_config.build_freshness(target, "asan"), "fresh")


class ResumeAndSuffixTests(unittest.TestCase):
    """A resumed run must land on the generation it pinned, or refuse."""

    def test_recorded_source_mismatch_refuses(self) -> None:
        self.assertIn(
            "source differs",
            benchmark_runner._source_pin_mismatch(
                {"source_signature": "s0"}, "s1",
            ),
        )

    def test_matching_pin_is_not_a_mismatch(self) -> None:
        previous = {"source_signature": "s0"}
        self.assertEqual(
            "", benchmark_runner._source_pin_mismatch(previous, "s0"),
        )

    def test_harness_revision_tracks_only_harness_bytes(self) -> None:
        # `output/` and `targets/` carry tracked fixture config that a second
        # backend's run legitimately rewrites. Untracked caches under lib are
        # run by-products too. Neither may invalidate this run, while every
        # edit to an already-dirty tracked harness file still must.
        with tempfile.TemporaryDirectory(prefix="harness-revision-") as temp:
            root = Path(temp)
            (root / "lib").mkdir()
            (root / "targets" / "sample").mkdir(parents=True)
            (root / "lib" / "runner.py").write_text("revision = 1\n")
            fixture = root / "targets" / "sample" / "target.toml"
            fixture.write_text('target = "sample"\n')
            _git_commit_all(root)

            baseline = benchmark_runner._harness_revision(root)
            self.assertTrue(baseline)
            fixture.write_text('target = "changed-by-peer"\n')
            (root / "lib" / "cache.pyc").write_bytes(b"untracked")
            self.assertEqual(baseline, benchmark_runner._harness_revision(root))

            source = root / "lib" / "runner.py"
            source.write_text("revision = 2\n")
            first_edit = benchmark_runner._harness_revision(root)
            source.write_text("revision = 3\n")
            self.assertNotEqual(first_edit, benchmark_runner._harness_revision(root))

    def test_recorded_harness_source_mismatch_refuses(self) -> None:
        self.assertIn(
            "harness source differs",
            benchmark_runner._source_pin_mismatch(
                {"harness_revision": "h0"}, "h1",
                field="harness_revision", subject="harness source",
            ),
        )

    def test_a_run_recorded_before_pinning_has_nothing_to_contradict(self) -> None:
        """Runs from before this existed carry no pin. They must stay resumable
        rather than becoming permanently refused."""
        self.assertEqual(
            "", benchmark_runner._source_pin_mismatch({}, "s0"),
        )
        self.assertEqual(
            "", benchmark_runner._source_pin_mismatch(
                {"source_signature": ""}, "s1",
            ),
        )

    def test_recorded_suffix_wins_over_recomputing(self) -> None:
        args = SimpleNamespace(regenerate=False, isolate_build=True, target="t")
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("AUDIT_BUILD_SUFFIX", None)
            self.assertEqual(
                "+bench-deadbeef01",
                benchmark_runner._resolve_build_suffix(
                    args, {"build_suffix": "+bench-deadbeef01"}
                ),
            )

    def test_isolation_composes_with_a_container_suffix(self) -> None:
        args = SimpleNamespace(regenerate=False, isolate_build=True, target="t")
        with mock.patch.dict(os.environ, {"AUDIT_BUILD_SUFFIX": "-img42"}), \
             mock.patch.object(
                 benchmark_runner.target_config, "build_input_key",
                 return_value="0123456789",
             ):
            self.assertEqual(
                "-img42+bench-0123456789",
                benchmark_runner._resolve_build_suffix(args, {}),
            )

    def test_without_isolation_the_ambient_suffix_is_kept(self) -> None:
        args = SimpleNamespace(regenerate=False, isolate_build=False, target="t")
        with mock.patch.dict(os.environ, {"AUDIT_BUILD_SUFFIX": "-img42"}):
            self.assertEqual("-img42", benchmark_runner._resolve_build_suffix(args, {}))

    def test_suffix_scope_is_restored(self) -> None:
        """--regenerate walks many runs in one process; a leaked suffix would
        resolve the next run's builds to a tree that was never its own."""
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("AUDIT_BUILD_SUFFIX", None)
            with benchmark_runner._build_suffix("+bench-aaaaaaaaaa"):
                self.assertEqual("+bench-aaaaaaaaaa", os.environ["AUDIT_BUILD_SUFFIX"])
            self.assertNotIn("AUDIT_BUILD_SUFFIX", os.environ)
        with mock.patch.dict(os.environ, {"AUDIT_BUILD_SUFFIX": "-img42"}):
            with benchmark_runner._build_suffix("+bench-bbbbbbbbbb"):
                pass
            self.assertEqual("-img42", os.environ["AUDIT_BUILD_SUFFIX"])


class BoundarySourceDriftTests(unittest.TestCase):
    """Boundary source checks must never invent drift."""

    def test_an_unavailable_boundary_check_is_not_drift(self) -> None:
        """A transient VCS failure must not discard a finished cell."""
        with mock.patch.object(
            benchmark_runner.target_config, "vcs_source_signature", return_value=""
        ):
            self.assertEqual(
                {}, benchmark_runner._source_drift(
                    Path("/nonexistent"), "sig-base",
                ),
            )

    def test_a_changed_boundary_is_drift(self) -> None:
        with mock.patch.object(
            benchmark_runner.target_config, "vcs_source_signature",
            return_value="sig-other",
        ), mock.patch.object(
            benchmark_runner.target_config, "source_changed_paths",
            return_value=["parser.c"],
        ):
            drift = benchmark_runner._source_drift(
                Path("/nonexistent"), "sig-base",
            )
        self.assertEqual(["parser.c"], drift["paths"])

    def test_an_unchanged_boundary_is_not_drift(self) -> None:
        with mock.patch.object(
            benchmark_runner.target_config, "vcs_source_signature",
            return_value="sig-base",
        ):
            self.assertEqual(
                {}, benchmark_runner._source_drift(
                    Path("/nonexistent"), "sig-base",
                ),
            )

    def test_a_generated_artifact_is_not_drift(self) -> None:
        """A cell's own testcases land in the checkout it is auditing.

        A model-direct cell writes crafted inputs beside the target it drives.
        None of that is code any cell read, so counting it as drift discarded
        finished cells over their own by-products. A tracked edit in the same
        tree still ends the cell.
        """
        tmp = Path(tempfile.mkdtemp(prefix="drift-"))
        self.addCleanup(subprocess.run, ["rm", "-rf", str(tmp)], check=False)
        _native_target(tmp)
        _git_commit_all(tmp)
        baseline = target_config.vcs_source_signature(
            tmp, include_untracked=False,
        )
        self.assertTrue(baseline)
        (tmp / "inj.mkv").write_bytes(b"\x1a\x45\xdf\xa3crafted")
        self.assertEqual({}, benchmark_runner._source_drift(tmp, baseline))
        (tmp / "main.c").write_text("int main(void){return 1;}\n")
        self.assertEqual(
            ["main.c"], benchmark_runner._source_drift(tmp, baseline)["paths"],
        )

    def test_an_empty_baseline_does_no_work(self) -> None:
        with mock.patch.object(
            benchmark_runner.target_config, "vcs_source_signature"
        ) as signature:
            self.assertEqual(
                {}, benchmark_runner._source_drift(
                    Path("/nonexistent"), "",
                ),
            )
            signature.assert_not_called()


class PrimaryOnlyBuildTests(unittest.TestCase):
    """A caller that asked for the primary build must not get alternates too."""

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="alt-"))
        self.target = self.tmp / "targets" / "sampleproj"
        _native_target(self.target)
        self.config = SimpleNamespace(
            is_browser="0", sanitizers_explicitly_disabled=False,
            sanitizers_enabled=["asan"], build_configs=[],
            sanitizer_bin=lambda name: "", sanitizer_lib=lambda name: "",
            resolve_path=lambda raw: str(self.target / raw),
        )

    def tearDown(self) -> None:
        subprocess.run(["rm", "-rf", str(self.tmp)], check=False)

    def _setup_target_argv(self, include_alternates: bool) -> list[str]:
        states = iter(["missing", "fresh"])
        with mock.patch.object(
            build_preflight.target_config, "build_freshness",
            side_effect=lambda root, san="asan": next(states, "fresh"),
        ), mock.patch.object(
            build_preflight.subprocess, "run",
            return_value=SimpleNamespace(returncode=0),
        ) as run, mock.patch.object(build_preflight, "_refresh_alternates"):
            build_preflight.refresh(
                self.tmp, self.target, "sampleproj", self.config, self.tmp,
                "codex", "model", lambda message: None,
                include_alternates=include_alternates,
            )
        return list(run.call_args[0][0])

    def test_primary_only_suppresses_alternate_configurations(self) -> None:
        self.assertIn("--no-alternates", self._setup_target_argv(False))

    def test_an_ordinary_audit_still_gets_alternates(self) -> None:
        self.assertNotIn("--no-alternates", self._setup_target_argv(True))


class GenericRunnerLeaseTests(unittest.TestCase):
    def test_a_target_owned_runner_is_leased(self) -> None:
        with tempfile.TemporaryDirectory(prefix="runner-lease-") as directory:
            target = Path(directory)
            runner = target / "app"
            runner.write_text("#!/bin/sh\n", encoding="utf-8")
            runner.chmod(0o755)
            config = target_config.Config(target_root=str(target))
            config.sanitizers_enabled = []
            config.sanitizers_explicitly_disabled = True
            config.runner_bin = "app"
            with mock.patch.object(
                build_preflight.build_lease, "hold_shared", return_value=True,
            ) as hold:
                self.assertEqual(
                    [], build_preflight.hold_builds(
                        target, config, lambda message: None,
                    ),
                )
            hold.assert_called_once_with(
                target, build_preflight.build_lease.RUNNER_LEASE_NAME,
                logger=mock.ANY,
            )

    def test_a_system_runner_is_pinned_but_not_target_leased(self) -> None:
        with tempfile.TemporaryDirectory(prefix="system-runner-pin-") as directory:
            target = Path(directory)
            config = target_config.Config(target_root=str(target))
            config.sanitizers_enabled = []
            config.sanitizers_explicitly_disabled = True
            config.runner_bin = sys.executable
            identity = build_preflight.build_identity(target, config)
            self.assertIn("runner-bin", identity["artifacts"])
            with mock.patch.object(
                build_preflight.build_lease, "hold_shared", return_value=True,
            ) as hold:
                self.assertEqual(
                    [], build_preflight.hold_builds(
                        target, config, lambda message: None,
                    ),
                )
            hold.assert_not_called()

    def test_a_bootstrap_refuses_a_busy_runner_without_waiting(self) -> None:
        """A consumer holds the runner for a whole run.

        Blocking out the lease timeout only delays the same refusal, so the
        operator waits fifteen minutes to be told to try later.
        """
        setup_target = _load_script("setup_target_mod", ROOT / "bin" / "setup-target")
        with tempfile.TemporaryDirectory(prefix="runner-busy-") as directory:
            target = Path(directory)
            (target / "go.mod").write_text("module example.com/x\n", encoding="utf-8")
            runner = target / "app"
            runner.write_text("#!/bin/sh\n", encoding="utf-8")
            runner.chmod(0o755)
            config = target_config.Config(target_root=str(target))
            config.build_system = "go"
            config.runner_bin = "app"
            setup = setup_target.Setup(SimpleNamespace(
                target="busy", source="", build=True,
            ))
            setup.target_root = target
            lock = build_lease.lease_path(target, build_lease.RUNNER_LEASE_NAME)
            lock.parent.mkdir(parents=True, exist_ok=True)
            # A separate open file description, so this reads as a foreign
            # holder exactly as another run's lease would.
            held = os.open(lock, os.O_RDWR | os.O_CREAT, 0o600)
            try:
                fcntl.flock(held, fcntl.LOCK_SH)
                started = time.monotonic()
                with self.assertRaises(RuntimeError) as caught:
                    setup.language_build(config)
                waited = time.monotonic() - started
            finally:
                os.close(held)
            self.assertIn("is in use by another audit", str(caught.exception))
            self.assertLess(waited, 1, "the bootstrap waited on a busy runner")

    def test_an_unusable_runner_is_reported_as_the_artifact_it_is(self) -> None:
        """Losing the file is not a configuration change.

        Reporting one as the other sends the operator to restore a snapshot
        that never moved instead of the runner that did.
        """
        with tempfile.TemporaryDirectory(prefix="runner-artifact-") as directory:
            target = Path(directory)
            runner = target / "app"
            runner.write_text("#!/bin/sh\n", encoding="utf-8")
            runner.chmod(0o755)
            config = target_config.Config(target_root=str(target))
            config.sanitizers_enabled = []
            config.sanitizers_explicitly_disabled = True
            config.runner_bin = "app"
            identity = build_preflight.build_identity(target, config)
            runner.chmod(0o644)
            self.assertEqual(
                [f"runner_bin is not executable ({runner})"],
                build_preflight.pinned_build_problems(target, identity, config),
            )
            runner.unlink()
            self.assertEqual(
                [f"runner_bin is missing ({runner})"],
                build_preflight.pinned_build_problems(target, identity, config),
            )


class ResumeNeverConvergesTests(unittest.TestCase):
    """A resumed run verifies its recorded build; it must never rebuild it.

    Converging first and checking after would destroy the generation the
    finished cells were measured on, and `--regenerate` needs, before any check
    could refuse the run.
    """

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="resume-"))
        self.args = SimpleNamespace(
            dry_run=False, regenerate=False, target="sampleproj", backend="codex",
        )

    def tearDown(self) -> None:
        subprocess.run(["rm", "-rf", str(self.tmp)], check=False)

    def _preflight(self, pinned: bool):
        identity = {"version": 1} if pinned else None
        with mock.patch.object(benchmark_runner, "_benchmark_config") as config, \
             mock.patch.object(benchmark_runner, "runner_preflight"), \
             mock.patch.object(benchmark_runner.build_preflight, "refresh",
                               return_value=[]) as refresh, \
             mock.patch.object(benchmark_runner.build_preflight, "hold_builds",
                               return_value=[]) as hold, \
             mock.patch.object(benchmark_runner.build_preflight, "build_problems",
                               return_value=[]) as freshness, \
             mock.patch.object(benchmark_runner.build_preflight,
                               "pinned_build_problems",
                               return_value=[]) as exact_pin, \
             mock.patch.object(benchmark_runner.build_preflight,
                               "enabled_sanitizers", return_value=["asan"]):
            config.return_value = SimpleNamespace()
            benchmark_runner.preflight_build(
                self.args, self.tmp, "m", identity,
            )
        return refresh, hold, freshness, exact_pin

    def test_a_pinned_resume_holds_without_converging(self) -> None:
        refresh, hold, freshness, exact_pin = self._preflight(pinned=True)
        refresh.assert_not_called()
        self.assertEqual(1, hold.call_count)
        freshness.assert_not_called()
        exact_pin.assert_called_once()

    def test_a_first_run_converges_normally(self) -> None:
        refresh, hold, freshness, exact_pin = self._preflight(pinned=False)
        self.assertEqual(1, refresh.call_count)
        hold.assert_not_called()
        freshness.assert_called_once()
        exact_pin.assert_not_called()


class ImmutableRunSettingsTests(unittest.TestCase):
    """Resuming under different experiment settings would put two experiments
    in one median."""

    def _args(self, **changes) -> SimpleNamespace:
        base = dict(
            backend="codex", budget_wall=10800, agents=3,
            target="sampleproj", agent_security="sandboxed",
        )
        base.update(changes)
        return SimpleNamespace(**base)

    def _previous(self, **changes) -> dict:
        base = {
            "model": "gpt-5.6-sol", "resolved_effort": "high",
            "agent_security": "sandboxed",
            "budget_wall": 10800, "harness_agents": 3, "target_sha": "abc123",
        }
        base.update(changes)
        return base

    def _mismatch(self, previous, args, model="gpt-5.6-sol"):
        with mock.patch.object(
            benchmark_runner.llm_invoke, "default_effort", return_value="high"
        ), mock.patch.object(
            benchmark_runner.target_config, "detect_rev", return_value="abc123"
        ), mock.patch.object(
            benchmark_runner, "_git_rev", return_value="harness123"
        ):
            return benchmark_runner._settings_mismatch(previous, args, model)

    def test_identical_settings_resume_cleanly(self) -> None:
        self.assertEqual("", self._mismatch(self._previous(), self._args()))

    def test_a_changed_budget_refuses(self) -> None:
        self.assertIn(
            "budget_wall", self._mismatch(self._previous(), self._args(budget_wall=5400))
        )

    def test_a_changed_model_refuses(self) -> None:
        self.assertIn(
            "model", self._mismatch(self._previous(), self._args(), model="other-model")
        )

    def test_a_changed_agent_count_refuses(self) -> None:
        self.assertIn(
            "harness_agents", self._mismatch(self._previous(), self._args(agents=5))
        )

    def test_a_changed_agent_security_profile_refuses(self) -> None:
        self.assertIn(
            "agent_security",
            self._mismatch(
                self._previous(), self._args(agent_security="external-bypass"),
            ),
        )

    def test_a_moved_target_revision_refuses(self) -> None:
        self.assertIn(
            "target_sha",
            self._mismatch(self._previous(target_sha="deadbee"), self._args()),
        )

    def test_a_legacy_run_on_another_harness_revision_refuses(self) -> None:
        self.assertIn(
            "tokenfuzz_sha",
            self._mismatch(
                self._previous(tokenfuzz_sha="older-harness"), self._args(),
            ),
        )

    def test_replicates_and_conditions_stay_changeable(self) -> None:
        """Raising replicates and resuming a subset of conditions are the
        documented ways to continue a run."""
        previous = self._previous()
        previous.update({"replicates": 3, "conditions": ["model-direct", "harness"]})
        self.assertEqual("", self._mismatch(previous, self._args()))

    def test_a_fresh_run_has_nothing_to_compare(self) -> None:
        self.assertEqual("", self._mismatch({}, self._args(budget_wall=1)))


class IsolatedBuildCollectionTests(unittest.TestCase):
    """Isolated trees outlive their run for replay, so only unreferenced ones go."""

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="gc-bench-"))
        self.target = self.tmp / "target"
        self.target.mkdir(parents=True)
        self.bench_root = self.tmp / "benchmark"
        (self.bench_root / "codex" / "20260101-000000").mkdir(parents=True)
        benchmark_runner._write_json(
            self.bench_root / "codex" / "20260101-000000" / "run.json",
            {"build_suffix": "+bench-1111111111"},
        )
        self.names = (
            "build-asan",
            "build-asan-repro",
            "build-asan-img42",
            "build-asan+cfg-widened-abc0000000",
            "build-asan+bench-1111111111",
            "build-asan+bench-1111111111+cfg-widened-abc0000000",
            "build-asan+bench-2222222222",
            "build-ubsan+bench-2222222222",
        )
        for name in self.names:
            (self.target / name).mkdir()

    def tearDown(self) -> None:
        subprocess.run(["rm", "-rf", str(self.tmp)], check=False)

    def test_collects_only_unreferenced_bench_trees(self) -> None:
        removed = benchmark_runner._collect_isolated_builds(
            self.target, self.bench_root, ""
        )
        self.assertEqual(2, removed)
        self.assertFalse((self.target / "build-asan+bench-2222222222").exists())
        self.assertFalse((self.target / "build-ubsan+bench-2222222222").exists())

    def test_keeps_referenced_trees_and_their_alternates(self) -> None:
        benchmark_runner._collect_isolated_builds(self.target, self.bench_root, "")
        self.assertTrue((self.target / "build-asan+bench-1111111111").is_dir())
        self.assertTrue(
            (self.target / "build-asan+bench-1111111111+cfg-widened-abc0000000").is_dir()
        )

    def test_never_touches_canonical_repro_container_or_cfg_trees(self) -> None:
        benchmark_runner._collect_isolated_builds(self.target, self.bench_root, "")
        for name in (
            "build-asan", "build-asan-repro", "build-asan-img42",
            "build-asan+cfg-widened-abc0000000",
        ):
            self.assertTrue((self.target / name).is_dir(), name)

    def test_keeps_the_current_runs_tree_even_before_it_is_recorded(self) -> None:
        removed = benchmark_runner._collect_isolated_builds(
            self.target, self.bench_root, "+bench-2222222222"
        )
        self.assertEqual(0, removed)
        self.assertTrue((self.target / "build-asan+bench-2222222222").is_dir())

    def test_a_reference_from_another_bench_root_protects_a_tree(self) -> None:
        """Ownership cannot be inferred by scanning one benchmark root: a run
        under a different --bench-root still needs its build for replay."""
        other = self.tmp / "other-root" / "codex" / "20260102-000000"
        other.mkdir(parents=True)
        benchmark_runner._record_isolated_reference(
            self.target, "+bench-2222222222", other
        )
        removed = benchmark_runner._collect_isolated_builds(
            self.target, self.bench_root, ""
        )
        self.assertEqual(0, removed)
        self.assertTrue((self.target / "build-asan+bench-2222222222").is_dir())

    def test_a_reference_whose_run_is_gone_is_itself_collected(self) -> None:
        vanished = self.tmp / "deleted-root" / "codex" / "20260103-000000"
        benchmark_runner._record_isolated_reference(
            self.target, "+bench-2222222222", vanished
        )
        removed = benchmark_runner._collect_isolated_builds(
            self.target, self.bench_root, ""
        )
        self.assertEqual(2, removed)
        self.assertFalse(
            list((self.target / ".audit" / "bench-refs").glob("*/*.ref")),
            "a marker pointing at a deleted run is garbage too",
        )

    def test_an_unreadable_run_record_collects_nothing(self) -> None:
        (self.bench_root / "codex" / "20260101-000000" / "run.json").write_text("{ bad")
        removed = benchmark_runner._collect_isolated_builds(
            self.target, self.bench_root, ""
        )
        self.assertEqual(0, removed)
        for name in self.names:
            self.assertTrue((self.target / name).is_dir(), name)


class PruneOrphanTreeTests(unittest.TestCase):
    """Collection is limited to alternate-configuration trees the harness owns."""

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="gc-"))
        self.target = self.tmp / "target"
        _native_target(self.target)
        self.declared = build_config.BuildConfig(
            name="widened", label="widened", flags=("-O1",), widen=True
        )
        self.kept = build_config.build_dir(self.target, self.declared)
        self.orphan = self.target / "build-asan+cfg-widened-0000000000"
        for tree in (self.kept, self.orphan):
            tree.mkdir(parents=True)
        for name in ("build-asan", "build-asan-repro", "build-asan-img42"):
            (self.target / name).mkdir(exist_ok=True)

    def tearDown(self) -> None:
        subprocess.run(["rm", "-rf", str(self.tmp)], check=False)

    def test_removes_only_the_undeclared_alternate(self) -> None:
        removed = build_configs.prune_orphan_trees(
            self.target, [self.declared], ""
        )
        self.assertEqual(1, removed)
        self.assertFalse(self.orphan.exists())
        self.assertTrue(self.kept.is_dir())

    def test_never_touches_canonical_repro_or_container_trees(self) -> None:
        build_configs.prune_orphan_trees(self.target, [self.declared], "")
        for name in ("build-asan", "build-asan-repro", "build-asan-img42"):
            self.assertTrue(
                (self.target / name).is_dir(), f"{name} must not be collected"
            )

    def test_leaves_a_tree_another_run_is_holding(self) -> None:
        with mock.patch.object(
            build_lease, "consumers_active", return_value=True
        ):
            removed = build_configs.prune_orphan_trees(
                self.target, [self.declared], ""
            )
        self.assertEqual(0, removed)
        self.assertTrue(self.orphan.is_dir())


if __name__ == "__main__":
    unittest.main(verbosity=2)
