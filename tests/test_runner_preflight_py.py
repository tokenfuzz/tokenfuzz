#!/usr/bin/env python3
"""Behavior tests for audit and benchmark configured-runner preflight."""

from __future__ import annotations

import contextlib
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "lib"))

import audit_runner
import benchmark_runner
import build_preflight
import runner_preflight
import target_config


def executable(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR)


class RunnerPreflightTests(unittest.TestCase):
    def config(self, root: Path, runner: str, *, findings_only: bool = True):
        return target_config.Config(
            target_root=str(root), runner_bin=runner,
            sanitizers_explicitly_disabled=findings_only,
        )

    def test_missing_failed_and_target_relative_runners(self):
        with tempfile.TemporaryDirectory(prefix="runner-preflight-") as temporary:
            root = Path(temporary)
            # A runner is optional: a findings-only target with no [runner].bin
            # audits in code-review mode rather than failing at startup.
            messages = []
            self.assertIsNone(
                runner_preflight.validate(self.config(root, ""), messages.append)
            )
            self.assertTrue(any("code-review findings only" in m for m in messages))
            with mock.patch.object(runner_preflight.shutil, "which", return_value=None):
                with self.assertRaisesRegex(RuntimeError, "was not found"):
                    runner_preflight.validate(self.config(root, "missing-runner"))

            custom = root / "tools" / "sample-driver"
            executable(custom)
            with mock.patch.object(runner_preflight.shutil, "which", return_value=None), \
                 mock.patch.object(runner_preflight, "run_timeout") as launched:
                resolved = runner_preflight.validate(
                    self.config(root, "tools/sample-driver")
                )
            self.assertEqual(custom, resolved)
            launched.assert_not_called()

            java = root / "java"
            executable(java)
            failed = SimpleNamespace(returncode=1, stdout=b"runtime unavailable\n")
            with mock.patch.object(runner_preflight.shutil, "which", return_value=str(java)), \
                 mock.patch.object(runner_preflight, "run_timeout", return_value=failed):
                with self.assertRaisesRegex(RuntimeError, "runtime unavailable"):
                    runner_preflight.validate(self.config(root, "java"))

    def test_startup_probe_reports_only_pre_main_failures(self):
        for diagnostic in (
            "dyld[123]: Symbol not found: _sample_symbol",
            "dyld[123]: symbol not found in flat namespace '_sample_symbol'",
            "./sample: error while loading shared libraries: libsample.so.1: "
            "cannot open shared object file: No such file or directory",
            "./sample: symbol lookup error: ./sample: undefined symbol: sample_symbol",
            'ld-elf.so.1: Shared object "libsample.so.1" not found, required by "sample"',
            "Error loading shared library libsample.so.1: No such file or directory",
            "Error relocating /tmp/sample: sample_symbol: symbol not found",
            "ld.so.1: sample: fatal: libsample.so.1: open failed: No such file or directory",
        ):
            with self.subTest(diagnostic=diagnostic):
                self.assertEqual(
                    diagnostic,
                    runner_preflight.startup_failure_reason(127, diagnostic),
                )

        # A program describing itself is not a loader diagnostic. The words
        # overlap, so only the loader's own spelling and placement may match:
        # misreading help text here rejects a working build.
        for help_text in (
            "usage: sampleproj\n  exec: run a command in the sandbox\n",
            "  Library not loaded: reported when a plugin is unavailable\n",
            "Options:\n  --error-relocating   emit a relocation report\n",
            # The loader always owns its whole line; these phrases are ordinary
            # English mid-sentence, and many CLIs exit nonzero on --help.
            "sampleproj reports an error while loading shared libraries: retry\n",
            "On a symbol lookup error: rebuild the plugin against this ABI.\n",
            'A Shared object "plugin" not found, required by the renderer.\n',
        ):
            with self.subTest(help_text=help_text):
                self.assertEqual(
                    "", runner_preflight.startup_failure_reason(2, help_text)
                )

        # A program that finished has plainly reached main(), whatever it
        # printed; a loader warning is survivable by definition.
        self.assertEqual(
            "",
            runner_preflight.startup_failure_reason(
                0, "dyld[123]: Library not loaded: /opt/lib/libsample.1.dylib"
            ),
        )
        self.assertEqual(
            "",
            runner_preflight.startup_failure_reason(
                1, "dyld[123]: warning: duplicate LC_RPATH '@loader_path'"
            ),
        )

        with tempfile.TemporaryDirectory(prefix="runner-startup-") as temporary:
            root = Path(temporary)
            loader_failure = root / "loader-failure"
            loader_failure.write_text(
                "#!/bin/sh\n"
                "echo \"$0: error while loading shared libraries: "
                'libsample.so.1: cannot open shared object file" >&2\n'
                "exit 127\n",
                encoding="utf-8",
            )
            loader_failure.chmod(0o755)
            self.assertIn(
                "error while loading shared libraries",
                runner_preflight.probe_startup(loader_failure),
            )

            # A target may supply its own library path in [runner].env; the
            # sanitizer runner applies it, so the probe must too or a working
            # build is reported unlaunchable.
            needs_env = root / "needs-env"
            needs_env.write_text(
                "#!/bin/sh\n"
                'if [ -z "${EXPECTED_LIB_PATH:-}" ] || '
                '[ "${SAMPLE_LIB_PATH:-}" != "$EXPECTED_LIB_PATH" ]; then\n'
                "  echo \"$0: error while loading shared libraries: "
                'libsample.so.1: cannot open shared object file" >&2\n'
                "  exit 127\n"
                "fi\n"
                "exit 0\n",
                encoding="utf-8",
            )
            needs_env.chmod(0o755)
            self.assertIn(
                "error while loading shared libraries",
                runner_preflight.probe_startup(needs_env),
            )
            configured = target_config.Config(
                target_root=str(root),
                runner_env=[
                    "SAMPLE_LIB_PATH={TARGET_ROOT}/build-{SANITIZER}",
                    f"EXPECTED_LIB_PATH={root}/build-asan",
                ],
            )
            self.assertEqual(
                "", runner_preflight.probe_startup(
                    needs_env, configured, "asan"
                )
            )

            # A build-time probe has no testcase or session directory. A
            # loader failure under guessed values is ambiguous: the real probe
            # supplies both, so rejecting the build here would be a false
            # failure with a much larger consequence than deferring the check.
            run_scoped = root / "run-scoped"
            run_scoped.write_text(
                "#!/bin/sh\n"
                'if [ -z "${SAMPLE_CASE:-}" ] || '
                '[ "$SAMPLE_RESULTS" != "/session/results/lib" ]; then\n'
                "  echo \"$0: error while loading shared libraries: "
                'libsample.so.1: cannot open shared object file" >&2\n'
                "  exit 127\n"
                "fi\n"
                "exit 0\n",
                encoding="utf-8",
            )
            run_scoped.chmod(0o755)
            dynamic = target_config.Config(
                target_root=str(root),
                runner_env=[
                    "SAMPLE_CASE={TESTCASE}",
                    "SAMPLE_RESULTS={RESULTS_DIR}/lib",
                ],
            )
            self.assertEqual(
                "", runner_preflight.probe_startup(
                    run_scoped, dynamic, "asan"
                )
            )

            # An executable bit on bytes the kernel cannot load never reaches
            # main() either; the wrapper reports it as a refused exec.
            unloadable = root / "unloadable"
            unloadable.write_bytes(b"\0" * 5000)
            unloadable.chmod(0o755)
            self.assertIn("Errno", runner_preflight.probe_startup(unloadable))

            ordinary_failure = root / "ordinary-failure"
            ordinary_failure.write_text(
                "#!/bin/sh\n"
                "echo 'unknown option: --help' >&2\n"
                "exit 2\n",
                encoding="utf-8",
            )
            ordinary_failure.chmod(0o755)
            self.assertEqual("", runner_preflight.probe_startup(ordinary_failure))

            # target.toml paths are target-relative. The probe runs in a
            # scratch directory, so it must resolve one before launching it
            # rather than reporting every such program as a refused exec.
            previous = os.getcwd()
            os.chdir(root)
            try:
                relative = runner_preflight.probe_startup(
                    Path(ordinary_failure.name)
                )
            finally:
                os.chdir(previous)
            self.assertEqual("", relative)

            # A program that answers with volume, not usage. Both what the
            # probe reads back and the evidence it returns stay bounded, so a
            # firehose cannot be buffered whole or pasted into a repair prompt.
            noisy = root / "noisy"
            noisy.write_text(
                "#!/bin/sh\n"
                'echo "$0: error while loading shared libraries: libsample.so.1" >&2\n'
                "yes 'sampleproj output line' | head -c 400000\n"
                "exit 127\n",
                encoding="utf-8",
            )
            noisy.chmod(0o755)
            reason = runner_preflight.probe_startup(noisy)
            self.assertIn("error while loading shared libraries", reason)
            self.assertLessEqual(len(reason), 4000)

    def test_a_stamped_build_that_stopped_starting_is_not_fresh(self):
        """The build stamp is content-based, so a host change that breaks the
        loader leaves it saying fresh. Preflight would then skip the rebuild and
        every run of the audit or benchmark cell would record NO_EXEC."""
        with tempfile.TemporaryDirectory(prefix="preflight-fresh-") as temporary:
            root = Path(temporary)
            build = root / "build-asan"
            build.mkdir(parents=True)
            binary = build / "sample"
            binary.write_text(
                "#!/bin/sh\n"
                "echo \"$0: error while loading shared libraries: libsample.so.1: "
                'cannot open shared object file" >&2\n'
                "exit 127\n",
                encoding="utf-8",
            )
            binary.chmod(0o755)
            config = target_config.Config(
                target_root=str(root), asan_bin="build-asan/sample",
            )
            messages = []
            self.assertTrue(
                build_preflight._stamped_but_unlaunchable(config, "asan", messages.append)
            )
            self.assertTrue(any("no longer starts" in m for m in messages))

            # A build that still starts stays fresh: this must not rebuild
            # every healthy target on every audit and benchmark start.
            binary.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            binary.chmod(0o755)
            self.assertFalse(
                build_preflight._stamped_but_unlaunchable(config, "asan", messages.append)
            )

            binary.chmod(0o644)
            self.assertTrue(
                build_preflight._stamped_but_unlaunchable(
                    config, "asan", messages.append
                )
            )
            binary.unlink()
            self.assertTrue(
                build_preflight._stamped_but_unlaunchable(
                    config, "asan", messages.append
                )
            )

            # Nothing configured, nothing to launch — an unset or placeholder
            # field is not a broken build.
            for raw in ("", "build-asan/FILL_ME"):
                self.assertFalse(
                    build_preflight._stamped_but_unlaunchable(
                        target_config.Config(target_root=str(root), asan_bin=raw),
                        "asan", messages.append,
                    )
                )

    def test_every_sample_target_runner_contract(self):
        configs = sorted((ROOT / "output" / "samples").glob("*/target.toml"))
        self.assertGreaterEqual(len(configs), 14)
        with tempfile.TemporaryDirectory(prefix="sample-runner-matrix-") as temporary:
            temp = Path(temporary)
            path_dir = temp / "bin"
            loaded = []
            for config_path in configs:
                target = temp / "targets" / config_path.parent.name
                target.mkdir(parents=True)
                config = target_config.Config(target_root=str(target))
                target_config.load_toml_into(config, config_path)
                loaded.append(config)
                raw = config.runner_bin
                if not raw:
                    continue
                destination = target / raw if "/" in raw else path_dir / raw
                executable(destination)

            completed = SimpleNamespace(returncode=0, stdout=b"fixture version\n")
            with mock.patch.dict(os.environ, {"PATH": str(path_dir)}), \
                 mock.patch.object(runner_preflight, "run_timeout", return_value=completed) as launched:
                for config in loaded:
                    runner_preflight.validate(config)

            checked = {Path(call.args[0][0]).name for call in launched.call_args_list}
            self.assertEqual(
                {"Rscript", "java", "kotlinc", "node", "perl", "php",
                 "python3", "ruby", "swift", "ts-node"},
                checked,
            )

    def test_audit_and_benchmark_call_shared_preflight_before_work(self):
        events = []
        runtime = SimpleNamespace(config=self.config(Path("/target"), "python3"))
        args = SimpleNamespace(allow_concurrent=False, max_iterations=1)
        state = SimpleNamespace(iteration=0)
        with mock.patch.object(
            audit_runner, "instance_lock", return_value=contextlib.nullcontext()
        ), mock.patch.object(
            audit_runner.runner_preflight, "validate",
            side_effect=lambda *_a, **_k: events.append("runner"),
        ), mock.patch.object(
            audit_runner, "validate_model", side_effect=lambda *_a: events.append("model")
        ), mock.patch.object(
            audit_runner, "preflight_build", side_effect=lambda *_a: events.append("build")
        ), mock.patch.object(
            audit_runner, "initialize_backend", return_value=state
        ), mock.patch.object(
            audit_runner, "run_iteration", return_value=("stalled", [])
        ):
            audit_runner.run_backend(runtime, args, "")
        self.assertEqual(["runner", "model", "build"], events)

        bench_args = SimpleNamespace(
            dry_run=False, regenerate=False, target="sample-python", backend="codex",
        )
        with mock.patch.object(benchmark_runner.target_config, "load_toml_into"), \
             mock.patch.object(benchmark_runner.runner_preflight, "validate") as checked, \
             mock.patch.object(benchmark_runner.build_preflight, "refresh"):
            benchmark_runner.preflight_build(bench_args, Path("/bench"), "fixture-model")
        checked.assert_called_once()


class TestcaseDependenceTests(unittest.TestCase):
    """Does the configured program actually read the input it is handed?

    A binary that never opens its testcase makes every CLI replay report
    CLEAN, so a crash that reproduces by hand is recorded as gone. The check
    must only ever speak from a positive signal: it warns operators, and one
    that cries wolf on a correct runner is worse than silence.
    """

    def script(self, body: str) -> Path:
        # A distinct file per call: two programs sharing one path means the
        # second body silently answers for the first.
        self.written = getattr(self, "written", 0) + 1
        path = Path(self.tmp) / f"prog{self.written}"
        path.write_text(f"#!/bin/sh\n{body}\n", encoding="utf-8")
        path.chmod(0o755)
        return path

    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp(prefix="dependence-")

    def test_a_program_ignoring_its_argument_is_named(self) -> None:
        blind = self.script('echo "fixed banner"')
        self.assertEqual(
            runner_preflight.OBSERVABLY_INVARIANT,
            runner_preflight.testcase_verdict(blind, ["{TESTCASE}"]),
        )

    def test_a_program_reading_its_argument_is_left_alone(self) -> None:
        reader = self.script('cat "$1" 2>&1 || echo "cannot open $1"')
        self.assertEqual(
            runner_preflight.OBSERVABLY_DEPENDS,
            runner_preflight.testcase_verdict(reader, ["{TESTCASE}"]),
        )

    def test_a_program_that_never_ran_is_undetermined(self) -> None:
        """The failure mode that made this condemn every target at once.

        The probe runs in a scratch directory, so a relative program never
        execs — and two launches that both died in the loader agree perfectly,
        which reads as "ignored its input" for a runner that was never asked.
        """
        reader = self.script('cat "$1" 2>&1 || echo "cannot open $1"')
        self.assertEqual(
            runner_preflight.TESTCASE_UNKNOWN,
            runner_preflight.testcase_verdict(Path("prog"), ["{TESTCASE}"]),
            "a relative program that cannot exec proves nothing",
        )
        self.assertEqual(
            runner_preflight.TESTCASE_UNKNOWN,
            runner_preflight.testcase_verdict(
                Path(self.tmp) / "absent", ["{TESTCASE}"],
            ),
            "a program that is not there proves nothing",
        )
        self.assertEqual(
            runner_preflight.OBSERVABLY_INVARIANT,
            runner_preflight.testcase_verdict(reader.resolve(), ["ignored"]),
            "the same program is judged once it is actually run",
        )

    def test_a_program_that_disagrees_with_itself_is_undetermined(self) -> None:
        """The failure that would have selected a benchmark as the runner.

        A benchmark prints different timings every run, so it differs from the
        missing-input launch for reasons that have nothing to do with reading
        it. Without establishing repeatability first, that difference reads as
        proof the input was consumed — and a selector acting on it points the
        audit at a program that never parses anything.
        """
        noisy = self.script('date +%s%N; echo "$RANDOM"')
        self.assertEqual(
            runner_preflight.TESTCASE_UNKNOWN,
            runner_preflight.testcase_verdict(noisy, ["{TESTCASE}"]),
        )
        self.assertNotEqual(
            runner_preflight.OBSERVABLY_INVARIANT,
            runner_preflight.testcase_verdict(noisy, ["{TESTCASE}"]),
            "an unrepeatable program is never accused of ignoring its input",
        )

    def test_the_verdict_separates_proof_from_ignorance(self) -> None:
        """Both callers need a positive answer, and opposite ones.

        A warning may only fire on proof the input was ignored; a runner may
        only be selected on proof it was read. Anything else must be neither.
        """
        reader = self.script('cat "$1" 2>&1 || echo "cannot open $1"')
        blind = self.script('echo "fixed banner"')
        self.assertEqual(
            runner_preflight.OBSERVABLY_DEPENDS,
            runner_preflight.testcase_verdict(reader, ["{TESTCASE}"]),
        )
        self.assertEqual(
            runner_preflight.OBSERVABLY_INVARIANT,
            runner_preflight.testcase_verdict(blind, ["{TESTCASE}"]),
        )
        self.assertEqual(
            runner_preflight.TESTCASE_UNKNOWN,
            runner_preflight.testcase_verdict(
                Path(self.tmp) / "absent", ["{TESTCASE}"],
            ),
        )

    def test_a_program_writing_to_the_testcase_path_is_undetermined(self) -> None:
        # It was handed a path and created it. Whatever it is doing with the
        # argument, it is not consuming it as input, and a rate measured
        # through it would describe the harness's own file.
        writer = self.script('echo produced > "$1"')
        self.assertEqual(
            runner_preflight.TESTCASE_UNKNOWN,
            runner_preflight.testcase_verdict(writer, ["{TESTCASE}"]),
        )

    def test_the_probe_does_not_claim_the_file_was_read(self) -> None:
        """Both answers are about observable behaviour, not consumption.

        Exit status and output are all a portable probe sees. A program that
        only stat()s the path varies with it while never opening it, and one
        that reads the file whole while printing nothing does not vary at all.
        Naming these `reads`/`ignores` invited a caller to rewrite a config
        from them; they are evidence, and the names now say so.
        """
        stat_only = self.script(
            'if [ -e "$1" ]; then echo present; else echo absent; fi'
        )
        silent_reader = self.script('cat "$1" >/dev/null 2>&1; exit 0')
        self.assertEqual(
            runner_preflight.OBSERVABLY_DEPENDS,
            runner_preflight.testcase_verdict(stat_only, ["{TESTCASE}"]),
            "existence sensitivity is not proof the file was opened",
        )
        self.assertEqual(
            runner_preflight.OBSERVABLY_INVARIANT,
            runner_preflight.testcase_verdict(silent_reader, ["{TESTCASE}"]),
            "a silent reader is invariant, so this may not condemn a runner",
        )

    def test_configured_arguments_decide_the_verdict(self) -> None:
        """A bare positional is not every target's invocation.

        Judging `<bin> <testcase>` when the config says `-e pattern
        {TESTCASE}` condemns a correctly configured runner for being asked the
        wrong question.
        """
        picky = self.script(
            'if [ "$1" != "--read" ]; then echo "usage"; exit 2; fi\n'
            'cat "$2" 2>&1 || echo "cannot open $2"'
        )
        self.assertEqual(
            runner_preflight.OBSERVABLY_INVARIANT,
            runner_preflight.testcase_verdict(picky, ["{TESTCASE}"]),
        )
        self.assertEqual(
            runner_preflight.OBSERVABLY_DEPENDS,
            runner_preflight.testcase_verdict(
                picky, ["--read", "{TESTCASE}"],
            ),
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
