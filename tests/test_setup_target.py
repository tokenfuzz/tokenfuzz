#!/usr/bin/env python3
"""Target setup, configuration preservation, and build bootstrap regressions."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parent.parent
COMMAND = ROOT / "bin" / "setup-target"
sys.path.insert(0, str(ROOT / "lib"))
import build_materialize
import target_config


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
        (self.remote / "demo.c").write_text("int main(void) { return 0; }\n")
        self.commit(self.remote, "add demo", "demo.c")
        process = self.setup("demo", str(self.remote))
        self.assertEqual(process.returncode, 0, process.stdout + process.stderr)
        self.assertTrue((self.harness / "targets" / "demo" / "demo.c").is_file())

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
            "path.write_text(path.read_text() + "
            "'\\n[runner]\\nargs = [\"--input\", \"{TESTCASE}\"]\\n')\n",
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

    def test_plain_local_sources_nested_slugs_and_reserved_components(self) -> None:
        self.git("init", str(self.harness))
        plain = self.harness / "targets" / "plain-cpp"
        plain.mkdir(parents=True)
        (plain / "CMakeLists.txt").write_text(
            "cmake_minimum_required(VERSION 3.16)\nproject(plain CXX)\nadd_executable(plain main.cpp)\n"
        )
        (plain / "main.cpp").write_text("int main() { return 0; }\n")
        process = self.setup("plain-cpp", "--build", environment={"LLM_DECIDE_DISABLE": "1"})
        self.assertEqual(process.returncode, 0, process.stdout + process.stderr)
        self.assertIn('pinned_rev    = "norev"', self.config("plain-cpp").read_text())
        self.assertIn("Using existing targets/plain-cpp as a plain source tree", process.stdout)
        process = self.setup(
            "plain-cpp", str(self.remote), "--ref", "main",
            environment={"LLM_DECIDE_DISABLE": "1"},
        )
        self.assertEqual(process.returncode, 0, process.stdout + process.stderr)
        self.assertFalse((plain / ".git").exists())
        self.assertIn("repo URL/ref ignored", process.stdout)

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
        self.assertIn('pinned_rev    = "norev"', text)
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

    def build_recipe(self, target: Path, sanitizer: str = "asan", executable: bool = True) -> Path:
        suffix = "" if sanitizer == "asan" else f"-{sanitizer}"
        recipe = target / ".audit" / f"build{suffix}.sh"
        recipe.parent.mkdir(parents=True, exist_ok=True)
        recipe.write_text(
            f"#!{sys.executable}\n"
            "import pathlib, sys\n"
            "build = pathlib.Path(sys.argv[2])\nbuild.mkdir(parents=True, exist_ok=True)\n"
            f"binary = build / {target.name!r}\n"
            "binary.write_bytes(b'\\0' * 5000)\nbinary.chmod(0o755)\n"
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

        sentinel = target / "build-asan" / "keep-existing-tree"
        sentinel.write_text("preserved\n")
        repeated = self.setup(
            "langbuild", "--build", environment={"LLM_DECIDE_DISABLE": "1"}
        )
        self.assertEqual(repeated.returncode, 0, repeated.stdout + repeated.stderr)
        self.assertNotIn("materializing asan build", repeated.stdout)
        self.assertTrue(sentinel.is_file())

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
        self.assertEqual(failed.returncode, 0, failed.stdout + failed.stderr)
        self.assertIn("clean build failed", failed.stdout)
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
            "binary.write_bytes(b'\\0' * 5000)\nbinary.chmod(0o755)\n"
            "# REPAIRED_RECIPE\n"
        )
        auto_builder.write_text(
            f"#!{sys.executable}\nimport pathlib, sys\n"
            f"pathlib.Path({str(capture)!r}).write_text(' '.join(sys.argv[1:]))\n"
            "out = pathlib.Path(sys.argv[sys.argv.index('--out') + 1])\n"
            f"out.write_text({repaired_body!r})\nout.chmod(0o755)\n",
            encoding="utf-8",
        )
        auto_builder.chmod(0o755)
        repaired = self.setup(
            "repairbuild", "--build",
            environment={"LLM_DECIDE_DISABLE": "0", "ACTIVE_BACKEND": "codex"},
        )
        self.assertEqual(repaired.returncode, 0, repaired.stdout + repaired.stderr)
        self.assertIn(
            "repaired asan recipe", repaired.stdout, repaired.stdout + repaired.stderr
        )
        self.assertIn("--repair-from", capture.read_text())
        self.assertIn("--max-iters 3", capture.read_text())
        self.assertIn("REPAIRED_RECIPE", recipe.read_text())
        self.assertTrue((target / "build-asan" / "repairbuild").is_file())
        self.assertEqual(
            target_config.build_freshness(
                target, "asan", recipe_path=recipe
            ),
            "fresh",
        )

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
