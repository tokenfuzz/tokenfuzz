#!/usr/bin/env python3
"""tests/test_coverage_build.py — the coverage sibling is built, verified, held.

The property, constructed rather than sampled: a target's canonical recipe,
rerun with CC/CXX pointed at the coverage shim, yields `build-asan+fuzz` with
trace-pc-guard instrumentation and its own freshness stamp, while the shared
`build-asan` tree and the source signature it is measured against stay
untouched. A recipe that ignores CC yields a tree without guards, which is
reported unavailable and remembered rather than rebuilt on every start.

Builds with the harness's own clang discovery and skips loudly when no capable
toolchain is present; the preflight and lease behaviour is exercised without
a compiler.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "lib"))
import build_lease  # noqa: E402
import build_preflight  # noqa: E402
import coverage_build  # noqa: E402
import sanitizer  # noqa: E402
import target_config  # noqa: E402

APP_C = """\
#include <stdio.h>
int app_parse(const char *s, int n) {
    int acc = 0;
    for (int i = 0; i < n; i++) { if (s[i] == 'x') acc++; else acc--; }
    return acc;
}
int main(int argc, char **argv) {
    if (argc < 2) return 2;
    FILE *f = fopen(argv[1], "rb");
    if (!f) return 3;
    char buf[256];
    int n = (int)fread(buf, 1, sizeof buf, f);
    fclose(f);
    return app_parse(buf, n) > 0 ? 0 : 1;
}
"""

# The recipe contract: argv <src> <build>, honours CC. `-fsanitize=address`
# is what the primary carries; the shim adds coverage on top.
RECIPE_HONOURING_CC = """\
#!/bin/sh
set -eu
src="$1"; build="$2"
mkdir -p "$build"
"${CC:-clang}" -g -O0 -fsanitize=address -o "$build/app" "$src/src.c"
"""

RECIPE_IGNORING_CC = """\
#!/bin/sh
set -eu
src="$1"; build="$2"
mkdir -p "$build"
%s -g -O0 -fsanitize=address -o "$build/app" "$src/src.c"
"""

TARGET_TOML = """\
target = "sampleproj"
upstream_url = "https://example.invalid/sampleproj"
build_system = "cmake"
asan_bin = "build-asan/app"
is_browser = "0"
[threat_model]
attacker_controls = ["bytes"]
[sanitizer]
enabled = ["asan"]
"""


def _tool(name: str) -> str:
    found = sanitizer.llvm_tool(name)
    return found if (os.access(found, os.X_OK) or shutil.which(found)) else ""


class CoverageSiblingBuildTests(unittest.TestCase):
    def setUp(self) -> None:
        self.clang = _tool("clang")
        if not self.clang:
            self.skipTest("no clang for trace-pc-guard instrumentation")
        self._tmp = tempfile.TemporaryDirectory(prefix="coverage-build-")
        root = Path(self._tmp.name)
        self.target = root / "target"
        (self.target / ".audit").mkdir(parents=True)
        (self.target / "CMakeLists.txt").write_text("cmake_minimum_required(VERSION 3.16)\n")
        (self.target / "src.c").write_text(APP_C)
        self.recipe = self.target / ".audit" / "build.sh"
        self._write_recipe(RECIPE_HONOURING_CC)
        toml = root / "output" / "sampleproj" / "target.toml"
        toml.parent.mkdir(parents=True)
        toml.write_text(TARGET_TOML)
        self.config = target_config.Config(target_root=str(self.target))
        target_config.load_toml_into(self.config, toml)
        # The primary the sibling twins: built by the recipe with the plain
        # compiler, stamped fresh, exactly as setup-target leaves it.
        primary = self.target / "build-asan"
        built = subprocess.run(
            [str(self.recipe), str(self.target), str(primary)],
            env={**os.environ, "CC": self.clang}, capture_output=True, text=True,
            check=False,
        )
        if built.returncode:
            self.skipTest(f"cannot build the primary fixture: {built.stderr[-200:]}")
        target_config.build_write_stamp(self.target, "asan")
        os.environ.pop("AUDIT_BUILD_SUFFIX", None)
        self.sibling = self.target / "build-asan+fuzz"

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _write_recipe(self, text: str) -> None:
        self.recipe.write_text(text)
        self.recipe.chmod(0o755)

    def test_sibling_is_built_instrumented_stamped_and_the_primary_untouched(self) -> None:
        before_sig = target_config.source_signature(self.target)
        primary_stamp = (self.target / "build-asan" / ".audit-build-stamp").read_bytes()

        result = coverage_build.materialize(self.target, self.config)
        self.assertEqual(result.status, "built", result)
        binary = self.sibling / "app"
        self.assertTrue(os.access(binary, os.X_OK))
        present, why = coverage_build.sancov_section_present(binary)
        if not present:
            self.skipTest(f"this clang did not emit trace-pc-guard: {why}")
        # Its own stamp, its own freshness; the primary's stamp is byte-identical.
        self.assertEqual(coverage_build.freshness(self.target, self.config), "fresh")
        self.assertEqual(
            (self.target / "build-asan" / ".audit-build-stamp").read_bytes(), primary_stamp,
        )
        self.assertEqual(target_config.source_signature(self.target), before_sig)
        self.assertEqual(target_config.build_freshness(self.target, "asan"), "fresh")
        # The shim is what the recipe compiled with, and it carries the flags.
        shim = (self.target / ".audit" / "coverage-toolchain" / "cc").read_text()
        self.assertIn("-fsanitize-coverage=trace-pc-guard", shim)
        self.assertTrue(shim.rstrip().endswith('"$@" -Wno-error'))

        # A second pass finds it fresh and does not rebuild.
        stamp = (self.sibling / ".audit-build-stamp").read_bytes()
        again = coverage_build.materialize(self.target, self.config)
        self.assertEqual(again.status, "fresh", again)
        self.assertEqual((self.sibling / ".audit-build-stamp").read_bytes(), stamp)

        # bin/hits selects it for the configured CLI route.
        self.assertEqual(
            coverage_build.sibling_path(self.config, "build-asan/app", "asan", "+fuzz"),
            binary,
        )

    def test_a_recipe_that_ignores_cc_is_unavailable_and_remembered(self) -> None:
        self._write_recipe(RECIPE_IGNORING_CC % self.clang)
        target_config.build_write_stamp(self.target, "asan")
        result = coverage_build.materialize(self.target, self.config)
        self.assertEqual(result.status, "failed", result)
        self.assertFalse((self.sibling / ".audit-build-stamp").exists())
        log = (self.target / ".audit" / "build-materialize-asan+fuzz.log").read_text()
        self.assertIn("__sancov_guards", log)
        self.assertIn("honour CC/CXX", log)
        # The primary's own log is not where a sibling failure lands.
        self.assertFalse((self.target / ".audit" / "build-materialize-asan.log").exists())

        # The same inputs are not built again; a changed recipe is.
        with mock.patch.object(
            coverage_build.build_materialize, "materialize",
        ) as untouched:
            remembered = coverage_build.materialize(self.target, self.config)
        self.assertEqual(remembered.status, "failed")
        self.assertIn("retry with", remembered.reason)
        untouched.assert_not_called()
        self._write_recipe(RECIPE_HONOURING_CC)
        target_config.build_write_stamp(self.target, "asan")
        repaired = coverage_build.materialize(self.target, self.config)
        self.assertEqual(repaired.status, "built", repaired)

    def test_nothing_to_instrument_is_skipped_not_built(self) -> None:
        browser = SimpleNamespace(
            is_browser="1", sanitizers_explicitly_disabled=False,
            sanitizer_bin=lambda san: "build-asan/app", sanitizer_lib=lambda san: "",
            resolve_path=self.config.resolve_path,
        )
        self.assertIn("browser", coverage_build.applicable(browser))
        external = SimpleNamespace(
            is_browser="0", sanitizers_explicitly_disabled=False,
            sanitizer_bin=lambda san: "/usr/bin/true", sanitizer_lib=lambda san: "",
            resolve_path=lambda raw: raw,
        )
        self.assertIn("names no asan_bin", coverage_build.applicable(external))
        result = coverage_build.materialize(self.target, external)
        self.assertEqual(result.status, "skip")
        self.assertFalse(self.sibling.exists())

    def test_a_missing_coverage_toolchain_is_a_reason_not_a_crash(self) -> None:
        with mock.patch.object(
            coverage_build.fuzz_harness, "fuzzing_compiler",
            return_value=str(self.target / "no-such-clang"),
        ):
            result = coverage_build.materialize(self.target, self.config)
        self.assertEqual(result.status, "skip", result)
        self.assertIn("no coverage toolchain", result.reason)
        self.assertFalse(self.sibling.exists())

    def test_a_held_sibling_is_left_in_place(self) -> None:
        first = coverage_build.materialize(self.target, self.config)
        self.assertEqual(first.status, "built", first)
        holder = subprocess.Popen(
            [sys.executable, "-c", (
                "import sys, time; sys.path.insert(0, %r); import build_lease\n"
                "with build_lease.shared(%r, 'build-asan+fuzz') as held:\n"
                "    assert held\n"
                "    print('held', flush=True)\n"
                "    time.sleep(30)\n"
            ) % (str(ROOT / "lib"), str(self.target))],
            stdout=subprocess.PIPE, text=True,
        )
        try:
            self.assertEqual(holder.stdout.readline().strip(), "held")
            result = coverage_build.materialize(self.target, self.config, force=True)
            self.assertEqual(result.status, "held", result)
        finally:
            holder.kill()
            holder.wait()


class CoveragePreflightTests(unittest.TestCase):
    """The audit builds the sibling beside fresh primaries and holds it."""

    def test_refresh_builds_the_sibling_once_primaries_are_fresh(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "targets" / "sample"
            target.mkdir(parents=True)
            (root / "logs").mkdir()
            config = SimpleNamespace(
                sanitizers_explicitly_disabled=False, sanitizers_enabled=["asan"],
                build_configs=[], build_system="cmake",
                sanitizer_bin=lambda san: "build-asan/app", sanitizer_lib=lambda san: "",
                runner_bin="", is_browser="0",
            )
            messages: list[str] = []
            result = SimpleNamespace(status="built", log_path=None, reason="")
            with mock.patch.object(
                build_preflight, "_build_freshness", return_value="fresh",
            ), mock.patch.object(
                build_preflight, "_stamped_but_unlaunchable", return_value=False,
            ), mock.patch.object(
                build_preflight.coverage_build, "materialize", return_value=result,
            ) as built, mock.patch.object(
                build_preflight, "hold_builds", return_value=[],
            ):
                build_preflight.refresh(
                    root, target, "sample", config, root / "logs", "codex", "",
                    messages.append, include_alternates=False,
                )
            built.assert_called_once()
            self.assertEqual(built.call_args.args[:2], (target, config))
            self.assertTrue(any("coverage sibling built" in line for line in messages))

            # A tree outside targets/ is the operator's to build.
            external = root / "elsewhere" / "sample"
            external.mkdir(parents=True)
            with mock.patch.object(
                build_preflight, "_build_freshness", return_value="fresh",
            ), mock.patch.object(
                build_preflight, "_stamped_but_unlaunchable", return_value=False,
            ), mock.patch.object(
                build_preflight.coverage_build, "materialize",
            ) as untouched, mock.patch.object(
                build_preflight, "hold_builds", return_value=[],
            ):
                build_preflight.refresh(
                    root, external, "sample", config, root / "logs", "codex", "",
                    messages.append, include_alternates=False,
                )
            untouched.assert_not_called()

    def test_hold_builds_holds_the_sibling_that_exists(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            (target / "build-asan").mkdir()
            (target / "build-asan+fuzz").mkdir()
            config = SimpleNamespace(
                sanitizers_explicitly_disabled=False, sanitizers_enabled=["asan"],
                sanitizer_bin=lambda san: "", sanitizer_lib=lambda san: "",
                runner_bin="",
            )
            held: list[str] = []
            with mock.patch.object(
                build_lease, "hold_shared",
                side_effect=lambda root, name, logger=None: held.append(name) or True,
            ):
                unleased = build_preflight.hold_builds(target, config, print)
            self.assertEqual(unleased, [])
            self.assertEqual(held, ["build-asan", "build-asan+fuzz"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
