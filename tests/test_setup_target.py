#!/usr/bin/env python3
"""Target setup, configuration preservation, and build bootstrap regressions."""

from __future__ import annotations

import importlib.machinery
import importlib.util
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


ROOT = Path(__file__).resolve().parent.parent
COMMAND = ROOT / "bin" / "setup-target"
sys.path.insert(0, str(ROOT / "lib"))
import build_materialize
import target_config


def _load_setup_target():
    loader = importlib.machinery.SourceFileLoader(
        "setup_target_test_module", str(COMMAND),
    )
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module

# Holds a shared build lease on a tree, the way a live audit does, until the
# stop file appears.
_HOLDER = """
import sys, time
from pathlib import Path
sys.path.insert(0, {lib!r})
import build_lease
root, name, ready, stop = sys.argv[1:5]
with build_lease.shared(root, name) as held:
    assert held, "holder could not take the shared lease"
    Path(ready).write_text("up\\n")
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline and not Path(stop).exists():
        time.sleep(0.02)
"""


class SetupTargetTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="setup-target-")
        self.temp = Path(self.temporary.name)
        self.harness = self.temp / "harness"
        (self.harness / "bin").mkdir(parents=True)
        (self.harness / "lib").symlink_to(ROOT / "lib", target_is_directory=True)
        (self.harness / ".agents").symlink_to(ROOT / ".agents", target_is_directory=True)
        self.remote = self.temp / "remote"
        self.git("init", str(self.remote))
        (self.remote / "CMakeLists.txt").write_text(
            "cmake_minimum_required(VERSION 3.16)\nproject(sample C)\n",
            encoding="utf-8",
        )
        self.commit(self.remote, "initial", "CMakeLists.txt")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    @staticmethod
    def git(*arguments: str, cwd: Path | None = None) -> subprocess.CompletedProcess:
        process = subprocess.run(
            ["git", *(("-C", str(cwd)) if cwd else ()), *arguments],
            capture_output=True, text=True, check=False,
        )
        if process.returncode:
            raise AssertionError(process.stdout + process.stderr)
        return process

    @staticmethod
    def hg(*arguments: str) -> subprocess.CompletedProcess:
        process = subprocess.run(
            ["hg", "--config", "ui.username=test <test@example.invalid>", *arguments],
            capture_output=True, text=True, check=False,
        )
        if process.returncode:
            raise AssertionError(process.stdout + process.stderr)
        return process

    def commit(self, repository: Path, message: str, *files: str) -> None:
        self.git("add", *files, cwd=repository)
        self.git(
            "-c", "user.name=test", "-c", "user.email=test@example.invalid",
            "commit", "-m", message, cwd=repository,
        )

    def setup(
        self, slug: str, *arguments: str, environment: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess:
        env = os.environ | {"AUDIT_ROOT": str(self.harness)}
        if environment:
            env.update(environment)
        return subprocess.run(
            [sys.executable, str(COMMAND), slug, *arguments],
            env=env, capture_output=True, text=True, check=False,
        )

    def config(self, slug: str) -> Path:
        return self.harness / "output" / slug / "target.toml"

    def test_a_detected_harness_input_mismatch_does_not_retarget_the_library(self) -> None:
        setup_target = _load_setup_target()
        target = self.temp / "mismatch-target"
        target.mkdir()
        config = self.temp / "mismatch-target.toml"
        config.write_text(
            'target = "demo"\nasan_lib = "build-asan/curated/libdemo.a"\n'
            'includes = ["curated/include"]\n\n'
            '[sanitizer]\nenabled = ["asan"]\n',
            encoding="utf-8",
        )
        setup = setup_target.Setup.__new__(setup_target.Setup)
        setup.target_root = target
        setup.toml = config
        before = config.read_bytes()
        with (
            mock.patch.object(
                setup, "declared_exports", side_effect=[(3, 0), (3, 0)],
            ),
            mock.patch.object(
                setup_target.target_config, "detected_harness_inputs",
                return_value=("build-asan/libother.a", ["include"]),
            ),
        ):
            setup.report_harness_input_mismatch()
        self.assertEqual(before, config.read_bytes())

    def test_a_header_only_repair_preserves_curated_harness_inputs(self) -> None:
        setup_target = _load_setup_target()
        target = self.temp / "header-mismatch-target"
        target.mkdir()
        config = self.temp / "header-mismatch-target.toml"
        config.write_text(
            'target = "demo"\nasan_lib = "build-asan/libproduct.a"\n'
            'includes = [\n  "stale/include", # old\n  "generated/[old]",\n]\n\n'
            '[sanitizer]\nenabled = ["asan"]\n',
            encoding="utf-8",
        )
        setup = setup_target.Setup.__new__(setup_target.Setup)
        setup.target_root = target
        setup.toml = config
        with (
            mock.patch.object(
                setup, "declared_exports", side_effect=[(3, 0), (3, 2)],
            ),
            mock.patch.object(
                setup_target.target_config, "detected_harness_inputs",
                return_value=("build-asan/libhelper.a", ["include"]),
            ),
        ):
            setup.report_harness_input_mismatch()
        text = config.read_text(encoding="utf-8")
        self.assertIn('asan_lib = "build-asan/libproduct.a"', text)
        self.assertIn(
            'includes      = ["stale/include", "generated/[old]", "include"]',
            text,
        )
        self.assertNotIn("libhelper.a", text)
        setup_target.target_config.parse_toml(config)

    def test_browser_setup_does_not_invent_a_c_harness_contract(self) -> None:
        setup_target = _load_setup_target()
        target = self.temp / "browser-target"
        target.mkdir()
        config = self.temp / "browser-target.toml"
        config.write_text(
            'target = "browser"\nis_browser = "1"\n'
            'asan_lib = "build-asan/libinternal.a"\n\n'
            '[sanitizer]\nenabled = ["asan"]\n',
            encoding="utf-8",
        )
        setup = setup_target.Setup.__new__(setup_target.Setup)
        setup.target_root = target
        setup.toml = config
        self.assertEqual([], setup.harness_input_sanitizers())

    def test_clone_preservation_refresh_force_and_updates(self) -> None:
        process = self.setup("demo", str(self.remote))
        self.assertEqual(process.returncode, 0, process.stdout + process.stderr)
        self.assertTrue((self.harness / "targets" / "demo" / ".git").is_dir())
        config = self.config("demo")
        self.assertIn('build_system  = "cmake"', config.read_text())

        config.write_text('target = "demo"\nbuild_system = "cmake"\n# operator edit\n')
        process = self.setup("demo")
        self.assertEqual(process.returncode, 0, process.stdout + process.stderr)
        text = config.read_text()
        self.assertIn("# operator edit", text)
        self.assertNotIn("asan_bin", text)
        self.assertIn("Keeping reviewed output/demo/target.toml", process.stdout)

        config.write_text('target = "demo"\ninvalid = [\n')
        process = self.setup("demo")
        self.assertEqual(process.returncode, 0, process.stdout + process.stderr)
        self.assertIn('target        = "demo"', config.read_text())
        self.assertIn("because it no longer parses", process.stdout)

        config.write_text('target        = "demo"\nasan_bin = "build-asan/FILL_ME"\n')
        process = self.setup("demo")
        self.assertEqual(process.returncode, 0, process.stdout + process.stderr)
        self.assertIn("to fill placeholders", process.stdout)

        config.write_text(
            'target = "demo"\nbuild_system = "cmake"\nasan_lib = "build-asan/FILL_ME.a"\n\n'
            '[threat_model]\nattacker_controls = ["bytes", "call-sequence", "protocol-state"]\n\n'
            '[s6_peers]\ndomain = "JSON"\npeers = ["rapidjson", "simdjson", "json-c"]\n'
        )
        process = self.setup("demo", environment={"LLM_DECIDE_DISABLE": "1"})
        self.assertEqual(process.returncode, 0, process.stdout + process.stderr)
        text = config.read_text()
        self.assertIn('attacker_controls = ["bytes", "call-sequence", "protocol-state"]', text)
        self.assertIn("[s6_peers]", text)
        self.assertIn('peers = ["rapidjson", "simdjson", "json-c"]', text)
        self.assertIn("preserving curated", process.stdout)
        self.assertNotRegex(text, r"(?m)^asan_lib.*FILL_ME")

        config.write_text("# local edit\n")
        process = self.setup("demo", str(self.remote), "--no-update", "--force")
        self.assertEqual(process.returncode, 0, process.stdout + process.stderr)
        self.assertIn('target        = "demo"', config.read_text())
        self.assertNotIn("# local edit", config.read_text())

        (self.remote / "skipped.c").write_text("int skipped(void) { return 0; }\n")
        self.commit(self.remote, "add skipped", "skipped.c")
        self.assertEqual(self.setup("demo").returncode, 0)
        self.assertFalse((self.harness / "targets" / "demo" / "skipped.c").exists())
        # --pull updates the checkout without re-passing the repo URL, and is
        # incompatible with the flag that suppresses updates.
        pulled = self.setup("demo", "--pull")
        self.assertEqual(pulled.returncode, 0, pulled.stdout + pulled.stderr)
        self.assertTrue((self.harness / "targets" / "demo" / "skipped.c").is_file())
        self.assertEqual(self.setup("demo", "--pull", "--no-update").returncode, 2)
        (self.remote / "demo.c").write_text("int main(void) { return 0; }\n")
        self.commit(self.remote, "add demo", "demo.c")
        process = self.setup("demo", str(self.remote))
        self.assertEqual(process.returncode, 0, process.stdout + process.stderr)
        self.assertTrue((self.harness / "targets" / "demo" / "demo.c").is_file())

    def test_pull_ignores_untracked_build_artifacts(self) -> None:
        self.assertEqual(self.setup("demo", str(self.remote)).returncode, 0)
        checkout = self.harness / "targets" / "demo"
        (checkout / "build-asan").mkdir()
        (checkout / "build-asan" / "libdemo.a").write_text("junk\n")
        (checkout / ".audit").mkdir()
        (checkout / "asan.err").write_text("leftover\n")
        (self.remote / "fresh.c").write_text("int fresh(void) { return 0; }\n")
        self.commit(self.remote, "add fresh", "fresh.c")

        pulled = self.setup("demo", "--pull")
        self.assertEqual(pulled.returncode, 0, pulled.stdout + pulled.stderr)
        self.assertTrue((checkout / "fresh.c").is_file())
        self.assertNotIn("leaving source checkout untouched", pulled.stdout)
        self.assertTrue((checkout / "build-asan" / "libdemo.a").is_file())

        # Tracked edits still block the update; they are what a pull clobbers.
        (checkout / "CMakeLists.txt").write_text("# operator edit\n")
        (self.remote / "later.c").write_text("int later(void) { return 0; }\n")
        self.commit(self.remote, "add later", "later.c")
        blocked = self.setup("demo", "--pull")
        self.assertEqual(blocked.returncode, 0, blocked.stdout + blocked.stderr)
        self.assertIn("tracked local changes", blocked.stdout)
        self.assertFalse((checkout / "later.c").exists())

    @unittest.skipUnless(shutil.which("hg"), "Mercurial is not installed")
    def test_hg_pull_ignores_untracked_build_artifacts(self) -> None:
        remote = self.temp / "hg-remote"
        remote.mkdir()
        self.hg("init", str(remote))
        (remote / "CMakeLists.txt").write_text(
            "cmake_minimum_required(VERSION 3.16)\nproject(sample C)\n", encoding="utf-8",
        )
        self.hg("--cwd", str(remote), "add", "CMakeLists.txt")
        self.hg("--cwd", str(remote), "commit", "-m", "initial")
        self.assertEqual(self.setup("hgdemo", str(remote)).returncode, 0)
        checkout = self.harness / "targets" / "hgdemo"
        self.assertTrue((checkout / ".hg").is_dir())
        (checkout / "build-asan").mkdir()
        (checkout / "build-asan" / "libdemo.a").write_text("junk\n")
        (remote / "fresh.c").write_text("int fresh(void) { return 0; }\n")
        self.hg("--cwd", str(remote), "add", "fresh.c")
        self.hg("--cwd", str(remote), "commit", "-m", "add fresh")

        pulled = self.setup("hgdemo", "--pull")
        self.assertEqual(pulled.returncode, 0, pulled.stdout + pulled.stderr)
        self.assertTrue((checkout / "fresh.c").is_file())
        self.assertNotIn("leaving source checkout untouched", pulled.stdout)

        (checkout / "CMakeLists.txt").write_text("# operator edit\n", encoding="utf-8")
        (remote / "later.c").write_text("int later(void) { return 0; }\n")
        self.hg("--cwd", str(remote), "add", "later.c")
        self.hg("--cwd", str(remote), "commit", "-m", "add later")
        blocked = self.setup("hgdemo", "--pull")
        self.assertEqual(blocked.returncode, 0, blocked.stdout + blocked.stderr)
        self.assertIn("tracked local changes", blocked.stdout)
        self.assertFalse((checkout / "later.c").exists())

    def test_s6_peer_bootstrap_and_force_replacement(self) -> None:
        self.assertEqual(self.setup("demo", str(self.remote)).returncode, 0)
        for name in ("suggest-threat-model", "suggest-peers"):
            (self.harness / "bin" / name).symlink_to(ROOT / "bin" / name)
        fake = self.temp / "fake-codex"
        fake.write_text(
            f"#!{sys.executable}\n"
            "import json, sys\nprompt = sys.stdin.read()\n"
            "if 'attacker_controls' in prompt:\n"
            "    print(json.dumps({'attacker_controls': ['bytes'], 'reasoning': 'byte input'}))\n"
            "else:\n"
            "    print(json.dumps({'domain': 'JSON', 'peers': ['rapidjson', 'simdjson', 'json-c'], 'reasoning': 'data parsers'}))\n",
            encoding="utf-8",
        )
        fake.chmod(0o755)
        env = {
            "LLM_DECIDE_DISABLE": "0", "LLM_DECIDE_MAX_CALLS": "0",
            "CLAUDE_BIN": str(self.temp / "no-claude"), "CODEX_BIN": str(fake),
            "GEMINI_BIN": str(self.temp / "no-gemini"),
        }
        process = self.setup("demo", str(self.remote), "--no-update", "--force", environment=env)
        self.assertEqual(process.returncode, 0, process.stdout + process.stderr)
        text = self.config("demo").read_text()
        self.assertIn("[s6_peers]", text)
        self.assertIn("rapidjson", text)
        self.assertRegex(process.stdout, r"suggest-peers returned rc=\d+ on backend=claude")
        self.assertIn("suggest-peers succeeded on backend=codex", process.stdout)
        self.assertNotIn("LLM call failed or unavailable", process.stdout)

        self.config("demo").write_text(text.replace("rapidjson", "oldjson"))
        process = self.setup("demo", str(self.remote), "--no-update", "--force", environment=env)
        self.assertEqual(process.returncode, 0, process.stdout + process.stderr)
        text = self.config("demo").read_text()
        self.assertIn("rapidjson", text)
        self.assertNotIn("oldjson", text)

    def test_force_beside_build_calibrates_a_reviewed_runner_without_reselecting(self) -> None:
        # --force --build rematerializes build output. A reviewed [runner] that
        # only lacks its exit calibration is calibrated in place; handing the
        # helper --force made it re-select the argv the operator had reviewed.
        setup_target = _load_setup_target()
        target = self.temp / "force-build-target"
        binary = target / "build-asan" / "demo"
        binary.parent.mkdir(parents=True)
        binary.write_text(f"#!{sys.executable}\n", encoding="utf-8")
        binary.chmod(0o755)
        toml = self.temp / "force-build.toml"
        reviewed = (
            'target = "demo"\nbuild_system = "cmake"\n'
            'asan_bin = "build-asan/demo"\n'
            '[sanitizer]\nenabled = ["asan"]\n'
            '[runner]\nargs = ["--input", "{TESTCASE}"]\n'
        )
        toml.write_text(reviewed, encoding="utf-8")
        setup = setup_target.Setup.__new__(setup_target.Setup)
        setup.name = "demo"
        setup.target_root = target
        setup.toml = toml
        setup.run_config_helper = mock.Mock()
        clean = {"AUDIT_NEW_TARGET_BOOTSTRAP": "1", "LLM_DECIDE_DISABLE": "0"}
        for force, build, expected in (
            (True, True, ["demo", "--apply"]),
            (False, False, ["demo", "--apply"]),
            (True, False, ["demo", "--apply", "--force"]),
        ):
            with self.subTest(force=force, build=build):
                setup.args = SimpleNamespace(
                    no_llm_config=False, force=force, build=build,
                )
                setup.run_config_helper.reset_mock()
                with mock.patch.dict(os.environ, clean):
                    setup.runner_bootstrap()
                setup.run_config_helper.assert_called_once_with(
                    "suggest-runner", expected,
                )
        toml.write_text(reviewed + "success_codes = [0, 1]\n", encoding="utf-8")
        setup.args = SimpleNamespace(no_llm_config=False, force=True, build=True)
        setup.run_config_helper.reset_mock()
        with mock.patch.dict(os.environ, clean):
            setup.runner_bootstrap()
        setup.run_config_helper.assert_not_called()

    def test_native_cli_invocation_bootstraps_after_binary_detection(self) -> None:
        self.assertEqual(self.setup("demo", str(self.remote)).returncode, 0)
        target = self.harness / "targets" / "demo"
        binary = target / "build-ubsan" / "demo"
        binary.parent.mkdir(parents=True)
        binary.write_text(f"#!{sys.executable}\n", encoding="utf-8")
        binary.chmod(0o755)
        self.config("demo").write_text(
            'target = "demo"\nbuild_system = "cmake"\n'
            '[sanitizer]\nenabled = ["ubsan"]\n'
            'ubsan_bin = "build-ubsan/demo"\n',
            encoding="utf-8",
        )
        helper = self.harness / "bin" / "suggest-runner"
        helper.write_text(
            f"#!{sys.executable}\n"
            "import os, pathlib\n"
            "root = pathlib.Path(os.environ['SCRIPT_ROOT'])\n"
            "path = root / 'output' / 'demo' / 'target.toml'\n"
            "text = path.read_text()\n"
            "addition = ('success_codes = [0]\\n' if '[runner]' in text else "
            "'\\n[runner]\\nargs = [\"--input\", \"{TESTCASE}\"]\\n')\n"
            "path.write_text(text + addition)\n",
            encoding="utf-8",
        )
        helper.chmod(0o755)
        process = self.setup(
            "demo", "--no-update",
            environment={"ACTIVE_BACKEND": "codex", "LLM_DECIDE_DISABLE": "0"},
        )
        self.assertEqual(process.returncode, 0, process.stdout + process.stderr)
        self.assertIn("suggest-runner succeeded", process.stdout)
        config = target_config.Config(target_root=str(target))
        target_config.load_toml_into(config, self.config("demo"))
        self.assertEqual(config.runner_args, ["--input", "{TESTCASE}"])

        calibrated = self.setup(
            "demo", "--no-update",
            environment={"ACTIVE_BACKEND": "codex", "LLM_DECIDE_DISABLE": "0"},
        )
        self.assertEqual(
            calibrated.returncode, 0, calibrated.stdout + calibrated.stderr,
        )
        self.assertIn("suggest-runner succeeded", calibrated.stdout)
        self.assertIn("success_codes = [0]", self.config("demo").read_text())

    def test_plain_local_sources_nested_slugs_and_reserved_components(self) -> None:
        self.git("init", str(self.harness))
        plain = self.harness / "targets" / "plain-cpp"
        plain.mkdir(parents=True)
        (plain / "CMakeLists.txt").write_text(
            "cmake_minimum_required(VERSION 3.16)\nproject(plain CXX)\nadd_executable(plain main.cpp)\n"
        )
        (plain / "main.cpp").write_text("int main() { return 0; }\n")
        # CMake is a target dependency, not a test-suite prerequisite. Exercise
        # plain-tree materialization through the suite's hermetic recipe.
        self.build_recipe(plain)
        process = self.setup("plain-cpp", "--build", environment={"LLM_DECIDE_DISABLE": "1"})
        self.assertEqual(process.returncode, 0, process.stdout + process.stderr)
        self.assertNotIn("pinned_rev", self.config("plain-cpp").read_text())
        self.assertIn("Using existing targets/plain-cpp as a plain source tree", process.stdout)
        process = self.setup(
            "plain-cpp", str(self.remote), "--ref", "main",
            environment={"LLM_DECIDE_DISABLE": "1"},
        )
        self.assertEqual(process.returncode, 0, process.stdout + process.stderr)
        self.assertFalse((plain / ".git").exists())
        self.assertIn("repo URL/ref/--pull ignored", process.stdout)

        external = self.temp / "external-plain"
        external.mkdir()
        (external / "CMakeLists.txt").write_text(
            "cmake_minimum_required(VERSION 3.16)\nproject(external C)\n"
        )
        process = self.setup("extlink", str(external), environment={"LLM_DECIDE_DISABLE": "1"})
        self.assertEqual(process.returncode, 0, process.stdout + process.stderr)
        link = self.harness / "targets" / "extlink"
        self.assertTrue(link.is_symlink())
        self.assertTrue((link / "CMakeLists.txt").is_file())
        text = self.config("extlink").read_text()
        self.assertIn('upstream_url  = "FILL_ME"', text)
        self.assertNotIn("pinned_rev", text)
        self.assertNotIn(str(external), text)
        self.assertIn("non-VCS source", process.stdout)

        nested_source = self.temp / "nested"
        nested_source.mkdir()
        (nested_source / "app.py").write_text('print("hello")\n')
        process = self.setup(
            "samples/extlink", str(nested_source), environment={"LLM_DECIDE_DISABLE": "1"}
        )
        self.assertEqual(process.returncode, 0, process.stdout + process.stderr)
        self.assertTrue((self.harness / "targets" / "samples" / "extlink").is_symlink())
        self.assertTrue(self.config("samples/extlink").is_file())

        for slug in ("output", "benchmark", "samples/output/demo", "samples/benchmark/demo"):
            with self.subTest(slug=slug):
                process = self.setup(slug, environment={"LLM_DECIDE_DISABLE": "1"})
                self.assertNotEqual(process.returncode, 0)
                self.assertIn("reserved directory name", process.stdout + process.stderr)
                self.assertFalse((self.harness / "targets" / slug).exists())
                self.assertFalse((self.harness / "output" / slug).exists())

        checkout = self.temp / "external-git"
        self.git("clone", str(self.remote), str(checkout))
        process = self.setup("gitclone", str(checkout), environment={"LLM_DECIDE_DISABLE": "1"})
        self.assertEqual(process.returncode, 0, process.stdout + process.stderr)
        cloned = self.harness / "targets" / "gitclone"
        self.assertFalse(cloned.is_symlink())
        self.assertTrue((cloned / ".git").is_dir())

        with self.config("extlink").open("a", encoding="utf-8") as stream:
            stream.write('\n# OPERATOR_EDIT_MARKER\nlink_libs = ["-lm", "-lcustom"]\n')
        process = self.setup("extlink", str(external), environment={"LLM_DECIDE_DISABLE": "1"})
        self.assertEqual(process.returncode, 0, process.stdout + process.stderr)
        self.assertIn("OPERATOR_EDIT_MARKER", self.config("extlink").read_text())
        self.assertIn("-lcustom", self.config("extlink").read_text())
        self.assertIn("Keeping reviewed", process.stdout)
        process = self.setup("rejecttype", str(external), "--repo-type", "git")
        self.assertNotEqual(process.returncode, 0)
        self.assertIn("plain source tree, not a git repo", process.stdout + process.stderr)
        self.assertFalse((self.harness / "targets" / "rejecttype").exists())

    def test_chromium_profile_fetches_a_gclient_workspace(self) -> None:
        tools = self.temp / "depot-tools"
        tools.mkdir()
        fetch_log = self.temp / "fetch.log"
        fetch = tools / "fetch"
        fetch.write_text(
            f"#!{sys.executable}\n"
            "import os, pathlib, subprocess, sys\n"
            "root = pathlib.Path.cwd()\n"
            "pathlib.Path(os.environ['FETCH_LOG']).write_text("
            "' '.join(sys.argv[1:]) + '\\n')\n"
            "(root / '.gclient').write_text('solutions = []\\n')\n"
            "subprocess.run(['git', 'clone', os.environ['FETCH_REMOTE'], "
            "str(root / 'src')], check=True)\n"
            "(root / 'src' / '.gn').write_text("
            "'buildconfig = \"//build/config/BUILDCONFIG.gn\"\\n')\n",
            encoding="utf-8",
        )
        fetch.chmod(0o755)
        gclient = tools / "gclient"
        gclient_log = self.temp / "gclient.log"
        gclient.write_text(
            "#!/bin/sh\nprintf '%s\\n' \"$*\" > \"$GCLIENT_LOG\"\n",
            encoding="utf-8",
        )
        gclient.chmod(0o755)
        environment = {
            "PATH": f"{tools}{os.pathsep}{os.environ['PATH']}",
            "FETCH_LOG": str(fetch_log),
            "FETCH_REMOTE": str(self.remote),
            "GCLIENT_LOG": str(gclient_log),
        }
        process = self.setup(
            "chromium", "--no-llm-config",
            environment=environment,
        )
        self.assertEqual(process.returncode, 0, process.stdout + process.stderr)
        workspace = self.harness / "targets" / "chromium"
        self.assertTrue((workspace / ".gclient").is_file())
        self.assertTrue((workspace / "src" / ".git").is_dir())
        config = self.config("chromium/src")
        self.assertTrue(config.is_file())
        self.assertIn('target        = "chromium/src"', config.read_text())
        self.assertIn('is_browser    = "1"', config.read_text())
        self.assertIn('"--enable-logging=stderr"', config.read_text())
        self.assertIn('"--no-sandbox"', config.read_text())
        if sys.platform == "darwin":
            self.assertIn('"--use-mock-keychain"', config.read_text())
        if sys.platform == "linux":
            self.assertIn('"NSS_DISABLE_UNLOAD=1"', config.read_text())
        recipe = workspace / "src" / ".audit" / "build.sh"
        self.assertIn(
            'autoninja -C "$build" chrome',
            recipe.read_text(),
        )
        product_relative = (
            "Chromium.app/Contents/MacOS/Chromium"
            if sys.platform == "darwin" else "chrome"
        )
        product = workspace / "src" / "build-asan" / product_relative
        product.parent.mkdir(parents=True)
        product.write_text(
            f"#!{sys.executable}\n", encoding="utf-8"
        )
        product.chmod(0o755)
        refreshed = self.setup(
            "chromium", "--no-llm-config", environment=environment,
        )
        self.assertEqual(
            refreshed.returncode, 0, refreshed.stdout + refreshed.stderr
        )
        self.assertIn(
            f'asan_bin      = "build-asan/{product_relative}"',
            config.read_text(),
        )
        self.assertEqual("chromium\n", fetch_log.read_text())
        self.assertIn(
            "bin/audit --target chromium --backend", process.stdout
        )
        updated = self.setup(
            "chromium", "--pull", "--no-llm-config",
            environment=environment,
        )
        self.assertEqual(updated.returncode, 0, updated.stdout + updated.stderr)
        self.assertEqual("sync\n", gclient_log.read_text())
        self.assertIn("Fast-forwarding git checkout", updated.stdout)
        recipe.write_text("#!/bin/sh\nexit 99\n", encoding="utf-8")
        forced = self.setup(
            "chromium/src", "--force", "--no-llm-config",
            environment=environment,
        )
        self.assertEqual(forced.returncode, 0, forced.stdout + forced.stderr)
        self.assertIn(
            'autoninja -C "$build" chrome',
            recipe.read_text(),
        )

    def test_registered_ordinary_chromium_target_keeps_its_identity(self) -> None:
        ordinary = self.harness / "targets" / "chromium"
        self.git("clone", str(self.remote), str(ordinary))
        config = self.config("chromium")
        config.parent.mkdir(parents=True)
        config.write_text(
            'target = "chromium"\nbuild_system = "cmake"\n',
            encoding="utf-8",
        )

        process = self.setup("chromium", "--no-llm-config")

        self.assertEqual(process.returncode, 0, process.stdout + process.stderr)
        self.assertIn(
            "Using existing targets/chromium without updating", process.stdout
        )
        self.assertFalse(self.config("chromium/src").exists())

    def test_chrome_profile_resumes_an_interrupted_gclient_fetch(self) -> None:
        tools = self.temp / "resume-depot-tools"
        tools.mkdir()
        gclient = tools / "gclient"
        gclient.write_text(
            f"#!{sys.executable}\n"
            "import os, pathlib, subprocess, sys\n"
            "root = pathlib.Path.cwd()\n"
            "subprocess.run(['git', 'clone', os.environ['FETCH_REMOTE'], "
            "str(root / 'src')], check=True)\n"
            "(root / 'src' / '.gn').write_text("
            "'buildconfig = \"//build/config/BUILDCONFIG.gn\"\\n')\n"
            "pathlib.Path(os.environ['GCLIENT_LOG']).write_text("
            "' '.join(sys.argv[1:]) + '\\n')\n",
            encoding="utf-8",
        )
        gclient.chmod(0o755)
        workspace = self.harness / "targets" / "chrome"
        workspace.mkdir(parents=True)
        (workspace / ".gclient").write_text(
            "solutions = []\n", encoding="utf-8"
        )
        gclient_log = self.temp / "resume-gclient.log"
        process = self.setup(
            "chrome", "--no-llm-config",
            environment={
                "PATH": f"{tools}{os.pathsep}{os.environ['PATH']}",
                "FETCH_REMOTE": str(self.remote),
                "GCLIENT_LOG": str(gclient_log),
            },
        )
        self.assertEqual(process.returncode, 0, process.stdout + process.stderr)
        self.assertTrue((workspace / "src" / ".git").is_dir())
        self.assertTrue(self.config("chrome/src").is_file())
        self.assertEqual("sync\n", gclient_log.read_text())
        self.assertIn("Resuming incomplete gclient workspace", process.stdout)

    def test_native_target_ignores_unrelated_python_abi_artifacts(self) -> None:
        process = self.setup("nativeabi", str(self.remote), "--no-llm-config")
        self.assertEqual(process.returncode, 0, process.stdout + process.stderr)
        target = self.harness / "targets" / "nativeabi"
        (target / "helper.cpython-9999-darwin.so").write_bytes(b"")
        refreshed = self.setup("nativeabi", "--no-llm-config")
        self.assertEqual(
            refreshed.returncode, 0, refreshed.stdout + refreshed.stderr
        )
        self.assertNotIn("ABI mismatch", refreshed.stdout)

    def build_recipe(
        self, target: Path, sanitizer: str = "asan", executable: bool = True,
        body: str = "exit 0",
    ) -> Path:
        """A recipe that emits one stub program. `body` is its shell body, so a
        test can build a program that reacts to its argument rather than the
        default one that ignores it."""
        suffix = "" if sanitizer == "asan" else f"-{sanitizer}"
        recipe = target / ".audit" / f"build{suffix}.sh"
        recipe.parent.mkdir(parents=True, exist_ok=True)
        recipe.write_text(
            f"#!{sys.executable}\n"
            "import pathlib, sys\n"
            "build = pathlib.Path(sys.argv[2])\nbuild.mkdir(parents=True, exist_ok=True)\n"
            f"binary = build / {target.name!r}\n"
            f"binary.write_text('#!/bin/sh\\n' + {body!r} + '\\n')\nbinary.chmod(0o755)\n"
            f"(build / 'lib{target.name}.a').write_bytes(b'archive')\n",
            encoding="utf-8",
        )
        recipe.chmod(0o755 if executable else 0o644)
        return recipe

    def make_build_target(self, slug: str) -> Path:
        target = self.harness / "targets" / slug
        target.mkdir(parents=True)
        (target / "CMakeLists.txt").write_text(
            f"cmake_minimum_required(VERSION 3.16)\nproject({slug} C)\nadd_executable({slug} main.c)\n"
        )
        (target / "main.c").write_text("int main(void) { return 0; }\n")
        return target

    def test_build_materializes_all_required_sanitizers_and_repairs_recipe_mode(self) -> None:
        (self.harness / "bin" / "auto-build-script").symlink_to(ROOT / "bin" / "auto-build-script")
        multi = self.make_build_target("multisan")
        self.build_recipe(multi, "asan")
        self.build_recipe(multi, "ubsan")
        config = self.config("multisan")
        config.parent.mkdir(parents=True)
        config.write_text(
            'target = "multisan"\nbuild_system = "cmake"\n'
            'asan_bin = "build-asan/multisan"\n[sanitizer]\nenabled = ["ubsan"]\n'
        )
        process = self.setup("multisan", "--build", environment={"LLM_DECIDE_DISABLE": "1"})
        self.assertEqual(process.returncode, 0, process.stdout + process.stderr)
        self.assertTrue((multi / "build-asan").is_dir())
        self.assertTrue((multi / "build-ubsan").is_dir())
        self.assertRegex(process.stdout, r"keeping existing .*\.audit/build\.sh")
        self.assertRegex(process.stdout, r"keeping existing .*\.audit/build-ubsan\.sh")
        self.assertIn("materializing ubsan build", process.stdout)
        self.assertIn("ubsan build complete", process.stdout)

        asan = self.make_build_target("asanonly")
        self.build_recipe(asan)
        config = self.config("asanonly")
        config.parent.mkdir(parents=True)
        config.write_text('target = "asanonly"\nbuild_system = "cmake"\nasan_bin = "build-asan/asanonly"\n')
        process = self.setup("asanonly", "--build", environment={"LLM_DECIDE_DISABLE": "1"})
        self.assertEqual(process.returncode, 0, process.stdout + process.stderr)
        self.assertTrue((asan / "build-asan").is_dir())
        self.assertFalse((asan / "build-ubsan").exists())
        self.assertNotIn("materializing ubsan", process.stdout)

        noexec = self.make_build_target("noexecrecipe")
        recipe = self.build_recipe(noexec, executable=False)
        config = self.config("noexecrecipe")
        config.parent.mkdir(parents=True)
        config.write_text(
            'target = "noexecrecipe"\nbuild_system = "cmake"\n'
            'asan_bin = "build-asan/noexecrecipe"\n'
        )
        process = self.setup("noexecrecipe", "--build", environment={"LLM_DECIDE_DISABLE": "1"})
        self.assertEqual(process.returncode, 0, process.stdout + process.stderr)
        self.assertTrue((noexec / "build-asan" / "noexecrecipe").is_file())
        self.assertTrue(recipe.stat().st_mode & 0o111)
        self.assertNotIn("permission denied", process.stdout.lower())

    def test_build_materializes_language_target_with_committed_recipe(self) -> None:
        # A language target (non-native build system) opts into a sanitizer build
        # by shipping a committed .audit/build.sh; setup-target --build must
        # materialize it even though cargo/go/pip are not native build systems.
        target = self.harness / "targets" / "langbuild"
        target.mkdir(parents=True)
        (target / "main.rs").write_text("fn main() {}\n", encoding="utf-8")
        self.build_recipe(target)
        config = self.config("langbuild")
        config.parent.mkdir(parents=True)
        config.write_text(
            'target = "langbuild"\nbuild_system = "cargo"\n'
            'asan_bin = "build-asan/langbuild"\n[sanitizer]\nenabled = ["asan"]\n'
        )
        process = self.setup("langbuild", "--build", environment={"LLM_DECIDE_DISABLE": "1"})
        self.assertEqual(process.returncode, 0, process.stdout + process.stderr)
        self.assertTrue((target / "build-asan" / "langbuild").is_file())
        self.assertIn("materializing asan build", process.stdout)
        # The coverage sibling follows the primary through the same recipe and
        # is verified, never assumed: a stub program carries no guards, so it
        # reports unavailable with its own log, and setup still succeeds.
        self.assertIn("coverage sibling build-asan+fuzz unavailable", process.stdout)
        self.assertTrue((target / ".audit" / "build-materialize-asan+fuzz.log").is_file())
        self.assertFalse((target / "build-asan+fuzz" / ".audit-build-stamp").exists())
        self.assertTrue((target / "build-asan" / ".audit-build-stamp").is_file())

        sentinel = target / "build-asan" / "keep-existing-tree"
        sentinel.write_text("preserved\n")
        repeated = self.setup(
            "langbuild", "--build", environment={"LLM_DECIDE_DISABLE": "1"}
        )
        self.assertEqual(repeated.returncode, 0, repeated.stdout + repeated.stderr)
        self.assertNotIn("materializing asan build", repeated.stdout)
        self.assertTrue(sentinel.is_file())

    def test_an_invariant_runner_is_reported_and_never_rewritten(self) -> None:
        """The diagnostic runs on the final config and only ever reports.

        Placed inside the build verifier it could not reach an externally
        configured binary, could not see a runner this same pass had just
        selected, and its escalation branch was unreachable because
        materialization only runs under --build. It also must not rewrite:
        the probe sees exit status and output, so a parser that reads quietly
        looks the same as one that never opened the file.
        """
        target = self.make_build_target("blindrunner")
        self.build_recipe(target)
        blind = target / "build-asan" / "blindrunner"
        blind.parent.mkdir(parents=True, exist_ok=True)
        blind.write_text("#!/bin/sh\necho fixed banner\n", encoding="utf-8")
        blind.chmod(0o755)
        config = self.config("blindrunner")
        config.parent.mkdir(parents=True)
        original = (
            'target = "blindrunner"\nbuild_system = "cmake"\n'
            'asan_bin = "build-asan/blindrunner"\n# REVIEWED_CONFIG\n'
        )
        config.write_text(original, encoding="utf-8")

        process = self.setup(
            "blindrunner", "--build", environment={"LLM_DECIDE_DISABLE": "1"},
        )

        self.assertEqual(process.returncode, 0, process.stdout + process.stderr)
        output = process.stdout + process.stderr
        self.assertIn("same exit status and output", output)
        self.assertIn(
            "bin/suggest-runner blindrunner --apply --force", output,
            "the remediation named must be one that actually reselects",
        )
        self.assertNotIn(
            "so crashes cannot be confirmed", output,
            "an observation may not be restated as a categorical claim",
        )
        self.assertEqual(
            original, config.read_text(encoding="utf-8"),
            "the diagnostic must never rewrite configuration",
        )

    def test_a_runner_that_varies_with_its_input_is_not_reported(self) -> None:
        target = self.make_build_target("readingrunner")
        # The recipe emits the program, so the behaviour under test belongs
        # there: one that opens its argument and reports whether it could
        # varies with the testcase, which is what must not be reported.
        self.build_recipe(
            target, body='cat "$1" 2>&1 || echo "cannot open $1"',
        )
        config = self.config("readingrunner")
        config.parent.mkdir(parents=True)
        config.write_text(
            'target = "readingrunner"\nbuild_system = "cmake"\n'
            'asan_bin = "build-asan/readingrunner"\n',
            encoding="utf-8",
        )

        process = self.setup(
            "readingrunner", "--build", environment={"LLM_DECIDE_DISABLE": "1"},
        )

        self.assertEqual(process.returncode, 0, process.stdout + process.stderr)
        self.assertNotIn(
            "same exit status and output", process.stdout + process.stderr,
        )

    def test_a_forced_reseed_keeps_what_it_cannot_rederive(self) -> None:
        """Destroying unconditionally while restoring conditionally loses data.

        A full re-seed dropped the curated threat model and peer set and left
        replacing them to the LLM helpers, so every reason those do not run —
        this flag, a disabled bootstrap, or simply every backend failing —
        deleted an operator's work with nothing to recover it from. The
        helpers overwrite these sections when they do run, so carrying them
        across costs nothing and is the only behaviour safe when they do not.
        """
        self.make_build_target("curated")
        config = self.config("curated")
        config.parent.mkdir(parents=True)
        config.write_text(
            'target = "curated"\nbuild_system = "cmake"\n'
            'asan_bin = "build-asan/curated"\n'
            '[threat_model]\n'
            'attacker_controls = ["bytes", "protocol-state"]\n'
            '[s6_peers]\ndomain = "example stacks"\n'
            'peers  = ["alpha", "beta"]\n',
            encoding="utf-8",
        )

        process = self.setup(
            "curated", "--force", "--no-llm-config",
            environment={"LLM_DECIDE_DISABLE": "1"},
        )

        self.assertEqual(process.returncode, 0, process.stdout + process.stderr)
        rewritten = config.read_text(encoding="utf-8")
        self.assertIn('attacker_controls = ["bytes", "protocol-state"]', rewritten)
        self.assertIn("[s6_peers]", rewritten)
        self.assertIn('"alpha"', rewritten)
        self.assertIn('"beta"', rewritten)

    def test_force_build_preserves_reviewed_config_and_recipe(self) -> None:
        target = self.make_build_target("reviewedbuild")
        recipe = self.build_recipe(target)
        original_recipe = recipe.read_text(encoding="utf-8")
        config = self.config("reviewedbuild")
        config.parent.mkdir(parents=True)
        config.write_text(
            'target = "reviewedbuild"\nbuild_system = "cmake"\n'
            'asan_bin = "build-asan/reviewedbuild"\n'
            '# REVIEWED_CONFIG\n'
            '[runner]\nbin = "python3"\nargs = ["driver.py", "{TESTCASE}"]\n',
            encoding="utf-8",
        )
        called = self.temp / "auto-builder-called"
        auto_builder = self.harness / "bin" / "auto-build-script"
        auto_builder.write_text(
            f"#!{sys.executable}\n"
            "import pathlib, sys\n"
            f"pathlib.Path({str(called)!r}).write_text('called\\n')\n"
            "raise SystemExit(9)\n",
            encoding="utf-8",
        )
        auto_builder.chmod(0o755)
        runner_called = self.temp / "runner-called"
        runner = self.harness / "bin" / "suggest-runner"
        runner.write_text(
            f"#!{sys.executable}\n"
            "import pathlib\n"
            f"pathlib.Path({str(runner_called)!r}).write_text('called\\n')\n",
            encoding="utf-8",
        )
        runner.chmod(0o755)

        process = self.setup(
            "reviewedbuild", "--build", "--force",
            environment={"LLM_DECIDE_DISABLE": "0"},
        )

        self.assertEqual(process.returncode, 0, process.stdout + process.stderr)
        self.assertIn("REVIEWED_CONFIG", config.read_text(encoding="utf-8"))
        self.assertIn('args = ["driver.py", "{TESTCASE}"]', config.read_text())
        self.assertEqual(original_recipe, recipe.read_text(encoding="utf-8"))
        self.assertFalse(called.exists())
        self.assertFalse(runner_called.exists())
        self.assertIn("--force rebuilds its output", process.stdout)

    def test_header_only_cmake_build_converges_without_fake_artifact(self) -> None:
        target = self.harness / "targets" / "headeronly"
        target.mkdir(parents=True)
        (target / "CMakeLists.txt").write_text(
            "cmake_minimum_required(VERSION 3.16)\n"
            "project(headeronly CXX)\n"
            "add_library(headeronly INTERFACE)\n",
            encoding="utf-8",
        )
        (target / "include").mkdir()
        (target / "include" / "headeronly.hpp").write_text(
            "inline int sample_value() { return 1; }\n", encoding="utf-8"
        )
        recipe = target / ".audit" / "build.sh"
        recipe.parent.mkdir()
        recipe.write_text(
            f"#!{sys.executable}\n"
            "import pathlib, sys\n"
            "build = pathlib.Path(sys.argv[2])\n"
            "build.mkdir(parents=True, exist_ok=True)\n"
            "(build / 'sampleTargets.cmake').write_text("
            "'add_library(sample::sample INTERFACE IMPORTED)\\n')\n",
            encoding="utf-8",
        )
        recipe.chmod(0o755)
        config = self.config("headeronly")
        config.parent.mkdir(parents=True)
        config.write_text(
            'target = "headeronly"\nbuild_system = "cmake"\n'
            '# asan_lib = "build-asan/FILL_ME.a"\n'
            'includes = ["include"]\n[sanitizer]\nenabled = ["asan"]\n',
            encoding="utf-8",
        )

        first = self.setup(
            "headeronly", "--build", environment={"LLM_DECIDE_DISABLE": "1"}
        )
        repeated = self.setup(
            "headeronly", "--build", environment={"LLM_DECIDE_DISABLE": "1"}
        )
        forced = self.setup(
            "headeronly", "--build", "--force",
            environment={"LLM_DECIDE_DISABLE": "1"},
        )

        for process in (first, repeated, forced):
            self.assertEqual(
                process.returncode, 0, process.stdout + process.stderr
            )
        self.assertTrue((target / "build-asan" / "sampleTargets.cmake").is_file())
        self.assertNotRegex(config.read_text(), r"(?m)^asan_(?:bin|lib)\s*=")
        self.assertEqual(
            "fresh",
            target_config.build_freshness(
                target, "asan", recipe_path=recipe
            ),
        )

    def test_mach_browser_uses_deterministic_native_build_route(self) -> None:
        (self.harness / "bin" / "auto-build-script").symlink_to(
            ROOT / "bin" / "auto-build-script"
        )
        target = self.harness / "targets" / "machbrowser"
        target.mkdir(parents=True)
        mach = target / "mach"
        mach.write_text(
            f"#!{sys.executable}\n"
            "import os, pathlib, re\n"
            "text = pathlib.Path(os.environ['MOZCONFIG']).read_text()\n"
            "match = re.search(r'MOZ_OBJDIR=\"([^\"]+)\"', text)\n"
            "if match is None:\n    raise SystemExit(2)\n"
            "build = pathlib.Path(match.group(1))\n"
            "binary = build / 'dist' / 'bin' / 'machbrowser'\n"
            "binary.parent.mkdir(parents=True, exist_ok=True)\n"
            "binary.write_bytes(b'\\0' * 5000)\n"
            "binary.chmod(0o755)\n",
            encoding="utf-8",
        )
        mach.chmod(0o755)
        config = self.config("machbrowser")
        config.parent.mkdir(parents=True)
        config.write_text(
            'target = "machbrowser"\nbuild_system = "mach"\nis_browser = "1"\n'
            'asan_bin = "build-asan/dist/bin/machbrowser"\n'
            '[sanitizer]\nenabled = ["asan"]\n',
            encoding="utf-8",
        )

        process = self.setup(
            "machbrowser", "--build",
            environment={"LLM_DECIDE_DISABLE": "1"},
        )

        self.assertEqual(process.returncode, 0, process.stdout + process.stderr)
        binary = target / "build-asan" / "dist" / "bin" / "machbrowser"
        self.assertTrue(binary.is_file())
        recipe = target / ".audit" / "build.sh"
        self.assertIn("--enable-address-sanitizer", recipe.read_text())
        self.assertIn("generated deterministic asan recipe", process.stdout)
        self.assertEqual(
            target_config.build_freshness(
                target, "asan", recipe_path=recipe
            ),
            "fresh",
        )

    def test_gn_browser_is_detected_built_and_configured_without_slug_rules(self) -> None:
        (self.harness / "bin" / "auto-build-script").symlink_to(
            ROOT / "bin" / "auto-build-script"
        )
        target = self.harness / "targets" / "renamed-browser"
        target.mkdir(parents=True)
        (target / ".gn").write_text(
            'buildconfig = "//build/config/BUILDCONFIG.gn"\n',
            encoding="utf-8",
        )
        tools = self.temp / "gn-tools"
        tools.mkdir()
        gn = tools / "gn"
        gn.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        gn.chmod(0o755)
        autoninja = tools / "autoninja"
        autoninja.write_text(
            f"#!{sys.executable}\n"
            "import pathlib, plistlib, subprocess, sys\n"
            "build = pathlib.Path(sys.argv[sys.argv.index('-C') + 1])\n"
            "source = build / 'browser.c'\n"
            "source.write_text('int main(void) { return 0; }\\n')\n"
            "binary = build / 'Sample.app' / 'Contents' / 'MacOS' / 'Sample'\n"
            "binary.parent.mkdir(parents=True, exist_ok=True)\n"
            "with (binary.parents[1] / 'Info.plist').open('wb') as stream:\n"
            "    plistlib.dump({'CFBundleExecutable': 'Sample'}, stream)\n"
            "subprocess.run(['cc', '-fsanitize=address', str(source), '-o', str(binary)], check=True)\n",
            encoding="utf-8",
        )
        autoninja.chmod(0o755)

        process = self.setup(
            "renamed-browser", "--browser", "--build", "--no-llm-config",
            environment={"PATH": f"{tools}{os.pathsep}{os.environ['PATH']}"},
        )

        self.assertEqual(process.returncode, 0, process.stdout + process.stderr)
        text = self.config("renamed-browser").read_text()
        self.assertIn('build_system  = "gn"', text)
        self.assertIn('is_browser    = "1"', text)
        self.assertIn("--user-data-dir={PROFILE}", text)
        self.assertIn(
            'asan_bin      = "build-asan/Sample.app/Contents/MacOS/Sample"',
            text,
        )
        recipe = target / ".audit" / "build.sh"
        self.assertIn("is_asan=true", recipe.read_text())
        self.assertNotIn("chrome", recipe.read_text())
        self.assertEqual(
            target_config.build_freshness(
                target, "asan", recipe_path=recipe
            ),
            "fresh",
        )

    def test_explicit_browser_mode_updates_an_existing_config_in_place(self) -> None:
        target = self.harness / "targets" / "existing-gn"
        target.mkdir(parents=True)
        (target / ".gn").write_text(
            'buildconfig = "//build/config/BUILDCONFIG.gn"\n',
            encoding="utf-8",
        )
        config = self.config("existing-gn")
        config.parent.mkdir(parents=True)
        config.write_text(
            'target = "existing-gn"\nbuild_system = "gn"\n'
            'is_browser = "0"\n# OPERATOR_EDIT_MARKER\n',
            encoding="utf-8",
        )

        enabled = self.setup(
            "existing-gn", "--browser", "--no-llm-config",
            environment={"LLM_DECIDE_DISABLE": "1"},
        )
        self.assertEqual(enabled.returncode, 0, enabled.stdout + enabled.stderr)
        self.assertIn('is_browser    = "1"', config.read_text())
        self.assertIn("OPERATOR_EDIT_MARKER", config.read_text())

        disabled = self.setup(
            "existing-gn", "--no-browser", "--no-llm-config",
            environment={"LLM_DECIDE_DISABLE": "1"},
        )
        self.assertEqual(disabled.returncode, 0, disabled.stdout + disabled.stderr)
        self.assertIn('is_browser    = "0"', config.read_text())
        self.assertIn("OPERATOR_EDIT_MARKER", config.read_text())

        config.write_text(
            'target = "existing-gn"\n'
            '[threat_model]\nattacker_controls = ["bytes"]\n',
            encoding="utf-8",
        )
        legacy = self.setup(
            "existing-gn", "--browser", "--no-llm-config",
            environment={"LLM_DECIDE_DISABLE": "1"},
        )
        self.assertEqual(legacy.returncode, 0, legacy.stdout + legacy.stderr)
        parsed = target_config.parse_toml(config)
        self.assertEqual(parsed.get("is_browser"), "1")
        self.assertNotIn("is_browser", parsed["threat_model"])

        config.write_text(
            'target = "existing-gn"\nbuild_system = "gn"\n'
            'is_browser = "0"\nasan_bin = "build-asan/FILL_ME"\n'
            '[sanitizer]\nenabled = []\n# OPERATOR_EDIT_MARKER\n',
            encoding="utf-8",
        )
        placeholder_build = self.setup(
            "existing-gn", "--browser", "--build", "--no-llm-config",
            environment={"LLM_DECIDE_DISABLE": "1"},
        )
        self.assertEqual(
            placeholder_build.returncode, 0,
            placeholder_build.stdout + placeholder_build.stderr,
        )
        self.assertIn('is_browser    = "1"', config.read_text())
        self.assertIn("OPERATOR_EDIT_MARKER", config.read_text())

    def test_partial_build_failure_persists_successful_artifacts(self) -> None:
        target = self.make_build_target("partialbuild")
        self.build_recipe(target, "asan")
        failed = self.build_recipe(target, "ubsan")
        failed.write_text(
            f"#!{sys.executable}\nraise SystemExit(7)\n",
            encoding="utf-8",
        )
        config = self.config("partialbuild")
        config.parent.mkdir(parents=True)
        config.write_text(
            'target = "partialbuild"\nbuild_system = "cmake"\n'
            '# asan_lib = "build-asan/FILL_ME.a"\n'
            '[sanitizer]\nenabled = ["asan", "ubsan"]\n',
            encoding="utf-8",
        )

        process = self.setup(
            "partialbuild", "--build", "--no-llm-config",
            environment={"LLM_DECIDE_DISABLE": "1"},
        )

        self.assertNotEqual(process.returncode, 0)
        self.assertIn(
            'asan_lib      = "build-asan/libpartialbuild.a"',
            config.read_text(),
        )
        self.assertTrue((target / "build-asan" / "libpartialbuild.a").is_file())

    def test_held_build_tree_is_not_reported_as_a_build_failure(self) -> None:
        """A tree a live run is reading is deliberately left alone. Reporting
        that as a --build failure would make the exit code depend on which
        peer audits happen to be running."""
        target = self.make_build_target("heldbuild")
        self.build_recipe(target)
        (target / "build-asan").mkdir()
        witness = target / "build-asan" / "witness"
        witness.write_text("original\n", encoding="utf-8")
        config = self.config("heldbuild")
        config.parent.mkdir(parents=True)
        config.write_text(
            'target = "heldbuild"\nbuild_system = "cmake"\n'
            'asan_bin = "build-asan/heldbuild"\n',
            encoding="utf-8",
        )
        ready = self.temp / "holder-ready"
        stop = self.temp / "holder-stop"
        holder = subprocess.Popen(
            [sys.executable, "-c", _HOLDER.format(lib=str(ROOT / "lib")),
             str(target), "build-asan", str(ready), str(stop)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        try:
            deadline = time.monotonic() + 30
            while time.monotonic() < deadline and not ready.exists():
                if holder.poll() is not None:
                    self.fail(holder.communicate()[1].decode())
                time.sleep(0.02)
            self.assertTrue(ready.exists(), "holder never took the shared lease")
            process = self.setup(
                "heldbuild", "--build", environment={"LLM_DECIDE_DISABLE": "1"},
            )
        finally:
            stop.write_text("stop\n", encoding="utf-8")
            holder.wait(timeout=30)
            for stream in (holder.stdout, holder.stderr):
                if stream is not None:
                    stream.close()

        self.assertEqual(process.returncode, 0, process.stdout + process.stderr)
        self.assertIn("asan build not replaced", process.stdout)
        self.assertEqual("original\n", witness.read_text(encoding="utf-8"))

    def test_stale_build_is_cleanly_rebuilt_and_restored_on_failure(self) -> None:
        target = self.make_build_target("cleanbuild")
        recipe = self.build_recipe(target)
        config = self.config("cleanbuild")
        config.parent.mkdir(parents=True)
        config.write_text(
            'target = "cleanbuild"\nbuild_system = "cmake"\n'
            'asan_bin = "build-asan/cleanbuild"\n'
        )
        environment = {"LLM_DECIDE_DISABLE": "1"}
        first = self.setup("cleanbuild", "--build", environment=environment)
        self.assertEqual(first.returncode, 0, first.stdout + first.stderr)

        build = target / "build-asan"
        stale_only = build / "stale-cache-entry"
        stale_only.write_text("must not survive a clean refresh\n")
        (target / "main.c").write_text("int main(void) { return 1; }\n")
        rebuilt = self.setup("cleanbuild", "--build", environment=environment)
        self.assertEqual(rebuilt.returncode, 0, rebuilt.stdout + rebuilt.stderr)
        self.assertFalse(stale_only.exists(), rebuilt.stdout + rebuilt.stderr)
        self.assertTrue((build / "cleanbuild").is_file())

        preserved = build / "preserve-on-failure"
        preserved.write_text("old usable tree\n")
        recipe.write_text(
            f"#!{sys.executable}\nimport sys\nprint('intentional failure')\nsys.exit(9)\n",
            encoding="utf-8",
        )
        recipe.chmod(0o755)
        failed = self.setup("cleanbuild", "--build", environment=environment)
        self.assertNotEqual(failed.returncode, 0, failed.stdout + failed.stderr)
        self.assertIn("clean build failed", failed.stdout)
        self.assertIn("build failed", failed.stderr)
        self.assertTrue(preserved.is_file())
        self.assertTrue((build / "cleanbuild").is_file())
        self.assertEqual(
            list((target / ".audit" / "build-backups").glob("*")), []
        )

    def test_candidate_promotion_failure_restores_recipe_and_build(self) -> None:
        target = self.make_build_target("promotionfail")
        canonical = self.build_recipe(target)
        old_recipe = canonical.read_text(encoding="utf-8")
        build = target / "build-asan"
        build.mkdir()
        (build / "promotionfail").write_bytes(b"old binary")
        marker = build / "old-tree-marker"
        marker.write_text("preserved\n")
        self.assertTrue(target_config.build_write_stamp(
            target, "asan", recipe_path=canonical
        ))

        candidate = target / ".audit" / "build-candidates" / "build.sh.new"
        candidate.parent.mkdir(parents=True)
        candidate.write_text(
            old_recipe + "# validated candidate\n",
            encoding="utf-8",
        )
        candidate.chmod(0o755)
        real_replace = os.replace

        def fail_promotion(source, destination):
            if Path(source) == candidate and Path(destination) == canonical:
                raise OSError("simulated promotion failure")
            return real_replace(source, destination)

        with mock.patch.object(
            build_materialize.os, "replace", side_effect=fail_promotion
        ):
            result = build_materialize.materialize(
                target, "asan", candidate, canonical,
                lambda tree: (tree / "promotionfail").is_file(), force=True,
            )

        self.assertEqual(result.status, "failed")
        self.assertIn("validated recipe could not be installed", result.reason)
        self.assertEqual(canonical.read_text(encoding="utf-8"), old_recipe)
        self.assertTrue(candidate.is_file())
        self.assertTrue(marker.is_file())
        self.assertEqual(
            target_config.build_freshness(
                target, "asan", recipe_path=canonical
            ),
            "fresh",
        )

    def test_existing_recipe_clean_failure_triggers_validated_repair(self) -> None:
        target = self.make_build_target("repairbuild")
        recipe = self.build_recipe(target)
        config = self.config("repairbuild")
        config.parent.mkdir(parents=True)
        config.write_text(
            'target = "repairbuild"\nbuild_system = "cmake"\n'
            'asan_bin = "build-asan/repairbuild"\n'
        )
        first = self.setup(
            "repairbuild", "--build", environment={"LLM_DECIDE_DISABLE": "1"}
        )
        self.assertEqual(first.returncode, 0, first.stdout + first.stderr)

        recipe.write_text(
            f"#!{sys.executable}\nimport sys\nsys.exit(7)\n", encoding="utf-8"
        )
        recipe.chmod(0o755)
        capture = self.temp / "repair-args"
        auto_builder = self.harness / "bin" / "auto-build-script"
        repaired_body = (
            f"#!{sys.executable}\nimport pathlib, sys\n"
            "build = pathlib.Path(sys.argv[2])\nbuild.mkdir(parents=True, exist_ok=True)\n"
            "binary = build / 'repairbuild'\n"
            "binary.write_text('#!/bin/sh\\nexit 0\\n')\nbinary.chmod(0o755)\n"
            "# REPAIRED_RECIPE\n"
        )
        auto_builder.write_text(
            f"#!{sys.executable}\nimport os, pathlib, sys\n"
            f"with pathlib.Path({str(capture)!r}).open('a') as stream:\n"
            "    stream.write(os.environ['ACTIVE_BACKEND'] + '\\n')\n"
            "if os.environ['ACTIVE_BACKEND'] == 'claude':\n"
            "    raise SystemExit(9)\n"
            "out = pathlib.Path(sys.argv[sys.argv.index('--out') + 1])\n"
            f"out.write_text({repaired_body!r})\nout.chmod(0o755)\n",
            encoding="utf-8",
        )
        auto_builder.chmod(0o755)
        repaired = self.setup(
            "repairbuild", "--build",
            environment={"LLM_DECIDE_DISABLE": "0"},
        )
        self.assertEqual(repaired.returncode, 0, repaired.stdout + repaired.stderr)
        self.assertIn(
            "repaired asan recipe", repaired.stdout, repaired.stdout + repaired.stderr
        )
        self.assertEqual(capture.read_text().splitlines()[:2], ["claude", "codex"])
        self.assertIn("REPAIRED_RECIPE", recipe.read_text())
        self.assertTrue((target / "build-asan" / "repairbuild").is_file())
        self.assertEqual(
            target_config.build_freshness(
                target, "asan", recipe_path=recipe
            ),
            "fresh",
        )

    def test_stamped_build_that_stops_starting_is_rebuilt(self) -> None:
        target = self.make_build_target("hostdrift")
        self.build_recipe(target)
        config = self.config("hostdrift")
        config.parent.mkdir(parents=True)
        config.write_text(
            'target = "hostdrift"\nbuild_system = "cmake"\n'
            'asan_bin = "build-asan/hostdrift"\n'
            'asan_lib = "build-asan/libhostdrift.a"\n',
            encoding="utf-8",
        )
        environment = {"LLM_DECIDE_DISABLE": "1"}
        first = self.setup("hostdrift", "--build", environment=environment)
        self.assertEqual(first.returncode, 0, first.stdout + first.stderr)

        binary = target / "build-asan" / "hostdrift"
        binary.write_text(
            "#!/bin/sh\n"
            "echo \"$0: error while loading shared libraries: libsample.so.1: "
            'cannot open shared object file" >&2\n'
            "exit 127\n",
            encoding="utf-8",
        )
        binary.chmod(0o755)
        self.assertEqual(
            "fresh",
            target_config.build_freshness(
                target, "asan", recipe_path=target / ".audit" / "build.sh"
            ),
        )

        rebuilt = self.setup("hostdrift", "--build", environment=environment)

        self.assertEqual(rebuilt.returncode, 0, rebuilt.stdout + rebuilt.stderr)
        self.assertIn("asan build complete", rebuilt.stdout)
        self.assertEqual("#!/bin/sh\nexit 0\n", binary.read_text(encoding="utf-8"))

        # A surviving library does not make a configured CLI route usable.
        # The exact binary bin/probe selects must be restored.
        binary.unlink()
        restored = self.setup("hostdrift", "--build", environment=environment)

        self.assertEqual(restored.returncode, 0, restored.stdout + restored.stderr)
        self.assertIn("asan build complete", restored.stdout)
        self.assertEqual("#!/bin/sh\nexit 0\n", binary.read_text(encoding="utf-8"))

    def test_pre_main_loader_failure_reaches_build_recipe_repair(self) -> None:
        target = self.make_build_target("loaderbuild")
        recipe = self.build_recipe(target)
        recipe.write_text(
            f"#!{sys.executable}\n"
            "import pathlib, sys\n"
            "build = pathlib.Path(sys.argv[2])\nbuild.mkdir(parents=True, exist_ok=True)\n"
            "binary = build / 'loaderbuild'\n"
            "binary.write_text("
            "\"#!/bin/sh\\necho 'dyld[123]: Library not loaded: "
            "/opt/lib/libsample.1.dylib' >&2\\nexit 134\\n\")\n"
            "binary.chmod(0o755)\n",
            encoding="utf-8",
        )
        recipe.chmod(0o755)
        config = self.config("loaderbuild")
        config.parent.mkdir(parents=True)
        config.write_text(
            'target = "loaderbuild"\nbuild_system = "cmake"\n'
            'asan_bin = "build-asan/loaderbuild"\n',
            encoding="utf-8",
        )

        captured_log = self.temp / "loader-repair-log"
        repaired_body = (
            f"#!{sys.executable}\nimport pathlib, sys\n"
            "build = pathlib.Path(sys.argv[2])\nbuild.mkdir(parents=True, exist_ok=True)\n"
            "binary = build / 'loaderbuild'\n"
            "binary.write_text('#!/bin/sh\\nexit 0\\n')\nbinary.chmod(0o755)\n"
            "# LOADER_REPAIRED_RECIPE\n"
        )
        auto_builder = self.harness / "bin" / "auto-build-script"
        auto_builder.write_text(
            f"#!{sys.executable}\nimport pathlib, sys\n"
            "failure = pathlib.Path(sys.argv[sys.argv.index('--failure-log') + 1])\n"
            f"pathlib.Path({str(captured_log)!r}).write_text(failure.read_text())\n"
            "out = pathlib.Path(sys.argv[sys.argv.index('--out') + 1])\n"
            f"out.write_text({repaired_body!r})\nout.chmod(0o755)\n",
            encoding="utf-8",
        )
        auto_builder.chmod(0o755)

        repaired = self.setup(
            "loaderbuild", "--build",
            environment={"LLM_DECIDE_DISABLE": "0"},
        )

        self.assertEqual(repaired.returncode, 0, repaired.stdout + repaired.stderr)
        self.assertIn("repaired asan recipe", repaired.stdout)
        self.assertIn("Library not loaded", captured_log.read_text())
        self.assertIn("LOADER_REPAIRED_RECIPE", recipe.read_text())

    def test_build_supplies_backend_when_materializing_widened_config(self) -> None:
        target = self.make_build_target("widebuild")
        self.build_recipe(target)
        config = self.config("widebuild")
        config.parent.mkdir(parents=True)
        config.write_text(
            'target = "widebuild"\nbuild_system = "cmake"\n'
            'asan_bin = "build-asan/widebuild"\nbuild_widening = true\n'
        )
        capture = self.temp / "build-config-backend"
        helper = self.harness / "bin" / "build-configs"
        helper.write_text(
            f"#!{sys.executable}\n"
            "import os, pathlib, sys\n"
            f"pathlib.Path({str(capture)!r}).write_text("
            "os.environ.get('ACTIVE_BACKEND', '') + '\\n' + ' '.join(sys.argv[1:]))\n",
            encoding="utf-8",
        )
        helper.chmod(0o755)
        process = self.setup(
            "widebuild", "--build",
            environment={"LLM_DECIDE_DISABLE": "1", "ACTIVE_BACKEND": "codex"},
        )
        self.assertEqual(process.returncode, 0, process.stdout + process.stderr)
        invocation = capture.read_text(encoding="utf-8")
        self.assertTrue(invocation.startswith("codex\n"), invocation)
        self.assertIn("--backend codex", invocation)

    def test_build_does_not_reseed_placeholder_configuration(self) -> None:
        (self.harness / "bin" / "auto-build-script").symlink_to(ROOT / "bin" / "auto-build-script")
        target = self.make_build_target("phtarget")
        self.build_recipe(target)
        config = self.config("phtarget")
        config.parent.mkdir(parents=True)
        config.write_text(
            'target = "phtarget"\nbuild_system = "cmake"\nasan_bin = "build-asan/FILL_ME"\n\n'
            '[threat_model]\nattacker_controls = ["hand-curated-token"]\n'
        )
        process = self.setup("phtarget", "--build", environment={"LLM_DECIDE_DISABLE": "1"})
        self.assertEqual(process.returncode, 0, process.stdout + process.stderr)
        self.assertIn('attacker_controls = ["hand-curated-token"]', config.read_text())
        self.assertIn("--build does not re-seed", process.stdout)
        self.assertNotIn("because generated placeholders remain", process.stdout)


if __name__ == "__main__":
    unittest.main(verbosity=2)
