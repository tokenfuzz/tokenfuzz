#!/usr/bin/env python3
"""tests/test_auto_build_script_py.py — exercise the toolchain-missing
short-circuit in bin/auto-build-script.

The script's LLM revision loop is the wrong tool for a missing
toolchain: the safety rails in ``validate_proposed_script`` block sudo /
apt-get / curl|sh, and a recipe that installed packages would be
unshippable in reproduce.sh anyway. So we expect iter 1 to detect
``command not found`` in the build log and exit 3 with an actionable
diagnostic, without ever calling the LLM.

Output matches helpers.sh (✓/✗) so tests/run-tests.sh's pass/fail
counter still works.
"""

from __future__ import annotations

import importlib.machinery
import importlib.util
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ABS = ROOT / "bin" / "auto-build-script"

_PASSED = 0
_FAILED = 0
_GREEN = "\033[0;32m"
_RED = "\033[0;31m"
_NC = "\033[0m"


def passed(name: str) -> None:
    global _PASSED
    _PASSED += 1
    print(f"  {_GREEN}✓{_NC} {name}")


def failed(name: str, detail: str = "") -> None:
    global _FAILED
    _FAILED += 1
    suffix = f" — {detail}" if detail else ""
    print(f"  {_RED}✗{_NC} {name}{suffix}")


def ok(cond: bool, name: str, detail: str = "") -> None:
    if cond:
        passed(name)
    else:
        failed(name, detail)


# ─── Load bin/auto-build-script as a module ─────────────────────────

sys.path.insert(0, str(ROOT / "lib"))
loader = importlib.machinery.SourceFileLoader("abs_mod", str(ABS))
spec = importlib.util.spec_from_loader("abs_mod", loader)
abs_mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(abs_mod)


# ─── debug-info flag (symbolization) ────────────────────────────────
# Audit sanitizer builds use -g1 (line tables only): function + file:line for
# symbolized crash stacks without full -g's DWARF, which also keeps
# symbolization fast (slow symbolization is what truncated macOS reports under
# the run timeout). -g1 is the portable spelling (clang and gcc both accept it;
# -gline-tables-only is clang-only). Pin the flag so a future edit does not
# silently drop debug info or regress to heavyweight -g.
for _name in ("_INITIAL_CMAKE", "_INITIAL_AUTOTOOLS", "_INITIAL_MESON"):
    _tmpl = getattr(abs_mod, _name)
    ok("-g1" in _tmpl, f"{_name}: builds with -g1 (line tables only)")
    ok(" -g " not in _tmpl and ' -g"' not in _tmpl,
       f"{_name}: no bare -g (full DWARF) in build flags")

# Mach is a regular deterministic build-system route, not a target-specific
# skill. Its recipe must select the caller's clean output tree and retain both
# the product browser and JS shell surfaces used by bin/probe.
with tempfile.TemporaryDirectory() as _mach_tmp:
    _mach_root = Path(_mach_tmp)
    _mach = _mach_root / "mach"
    _mach.write_text("#!/bin/sh\n", encoding="utf-8")
    _mach.chmod(0o755)
    ok(abs_mod.detect_build_system(_mach_root) == "mach",
       "detect: executable mach driver selects the mach build system")
_mach_script = abs_mod.initial_script("mach", "asan")
ok("--enable-address-sanitizer" in _mach_script,
   "mach: ASan uses the build system's sanitizer option")
ok("MOZ_OBJDIR" in _mach_script and '"$src/mach" build' in _mach_script,
   "mach: recipe binds output to argv-2 and invokes the source driver")
ok("--enable-js-shell" in _mach_script and "--enable-fuzzing" in _mach_script,
   "mach: recipe builds browser audit execution surfaces")
ok("--enable-debug-symbols" in _mach_script,
   "mach: recipe asks the driver for line-table debug symbols")
ok("export CFLAGS" not in _mach_script and "export LDFLAGS" not in _mach_script,
   "mach: sanitizer flags do not leak into unsanitized host build tools")
with tempfile.TemporaryDirectory() as _mach_exec_tmp:
    _mach_exec_root = Path(_mach_exec_tmp)
    _mach_exec_src = _mach_exec_root / "src"
    _mach_exec_build = _mach_exec_root / "build"
    _mach_exec_src.mkdir()
    _mach_exec = _mach_exec_src / "mach"
    _mach_exec.write_text(
        "#!/bin/sh\n"
        "grep -F 'ac_add_options --enable-foo' \"$MOZCONFIG\" >/dev/null\n",
        encoding="utf-8",
    )
    _mach_exec.chmod(0o755)
    _mach_recipe = _mach_exec_root / "build.sh"
    _mach_recipe.write_text(
        abs_mod.initial_script("mach", "asan", ["--enable-foo"]),
        encoding="utf-8",
    )
    _mach_run = subprocess.run(
        ["bash", str(_mach_recipe), str(_mach_exec_src), str(_mach_exec_build)]
    )
    ok(_mach_run.returncode == 0,
       "mach: extra configuration flags remain valid shell arguments")

# GN is selected from its root marker and uses the driver graph's default
# target. The shared recipe carries only GN/Chromium sanitizer conventions;
# it does not branch on a checkout slug or product name.
with tempfile.TemporaryDirectory() as _gn_tmp:
    _gn_root = Path(_gn_tmp)
    (_gn_root / ".gn").write_text("buildconfig = \"//build/config/BUILDCONFIG.gn\"\n")
    ok(abs_mod.detect_build_system(_gn_root) == "gn",
       "detect: .gn marker selects the GN build system")
_gn_script = abs_mod.initial_script("gn", "asan")
ok("is_asan=true" in _gn_script and "is_debug=false" in _gn_script,
   "gn: recipe selects release ASan configuration")
ok('autoninja -C "$build"' in _gn_script and " chrome" not in _gn_script,
   "gn: recipe builds the graph default without a hardcoded product target")
ok('--root="$src"' in _gn_script,
   "gn: recipe binds source discovery to argv-1 instead of caller cwd")
for _san, _arg in (
    ("ubsan", "is_ubsan=true"),
    ("msan", "is_msan=true"),
    ("tsan", "is_tsan=true"),
):
    _script = abs_mod.initial_script("gn", _san)
    ok(_arg in _script and "is_asan=true" not in _script,
       f"gn: {_san} build selects its own sanitizer argument")
ok(abs_mod.validate_proposed_script(_mach_script)[0],
   "validation accepts build-driver sanitizer configuration")
ok(abs_mod.validate_proposed_script(_gn_script)[0],
   "validation accepts GN sanitizer configuration")

with tempfile.TemporaryDirectory() as _gn_exec_tmp:
    _gn_exec_root = Path(_gn_exec_tmp)
    _gn_exec_src = _gn_exec_root / "src"
    _gn_exec_build = _gn_exec_root / "build"
    _gn_exec_tools = _gn_exec_root / "tools"
    (_gn_exec_src / "buildtools" / "host").mkdir(parents=True)
    _gn_exec_tools.mkdir()
    _local_gn = _gn_exec_src / "buildtools" / "host" / "gn"
    _local_gn.write_text(
        "#!/bin/sh\nmkdir -p \"$2\"\ntouch \"$2/source-local-gn\"\n",
        encoding="utf-8",
    )
    _local_gn.chmod(0o755)
    _path_gn = _gn_exec_tools / "gn"
    _path_gn.write_text("#!/bin/sh\nexit 91\n", encoding="utf-8")
    _path_gn.chmod(0o755)
    _autoninja = _gn_exec_tools / "autoninja"
    _autoninja.write_text(
        "#!/bin/sh\nbuild=\"$2\"\ntest -f \"$build/source-local-gn\"\n",
        encoding="utf-8",
    )
    _autoninja.chmod(0o755)
    _gn_recipe = _gn_exec_root / "build.sh"
    _gn_recipe.write_text(_gn_script, encoding="utf-8")
    _gn_env = os.environ.copy()
    _gn_env["PATH"] = f"{_gn_exec_tools}{os.pathsep}{_gn_env['PATH']}"
    _gn_run = subprocess.run(
        ["bash", str(_gn_recipe), str(_gn_exec_src), str(_gn_exec_build)],
        env=_gn_env,
    )
    ok(_gn_run.returncode == 0,
       "gn: source-local driver wins over a PATH wrapper")


# ─── detect_missing_commands ────────────────────────────────────────

ok(abs_mod.detect_missing_commands("") == [],
   "detect: empty log returns empty list")

ok(abs_mod.detect_missing_commands(
    "/tmp/auto-build-script-xyz/build.candidate.sh: line 7: cmake: command not found\n"
) == ["cmake"],
   "detect: bash 'line N: <cmd>: command not found' captured")

ok(abs_mod.detect_missing_commands(
    "cmake: command not found\n"
) == ["cmake"],
   "detect: bare '<cmd>: command not found' captured")

ok(abs_mod.detect_missing_commands(
    "sh: 1: ninja: not found\n"
) == ["ninja"],
   "detect: dash-style '<cmd>: not found' captured")

ok(abs_mod.detect_missing_commands(
    "line 3: cmake: command not found\n"
    "line 7: ninja: command not found\n"
    "line 9: cmake: command not found\n"
) == ["cmake", "ninja"],
   "detect: distinct commands deduped, order preserved")

# Path-shaped 'not found' lines must NOT be interpreted as missing
# commands. configure logs often contain "/usr/lib/foo.so: not found"
# meaning a library file, not a binary.
ok(abs_mod.detect_missing_commands(
    "/usr/local/lib/libfoo.so: not found\n"
) == [],
   "detect: path-shaped 'not found' ignored (not a command)")

# A real build log mixes both. The command name still gets surfaced.
ok(abs_mod.detect_missing_commands(
    "checking for /usr/bin/ld... /usr/bin/ld: not found\n"
    "/tmp/build.sh: line 4: meson: command not found\n"
) == ["meson"],
   "detect: command name extracted, path 'not found' lines ignored")


# ─── prompt assembly ───────────────────────────────────────────────

captured_prompts: list[str] = []
original_llm_decide = abs_mod.llm_decide


def capture_prompt(_decision: str, _keys: str, prompt: str, **_kwargs):
    captured_prompts.append(prompt)
    return {"script": "#!/bin/bash\nset -eu\necho ok\n"}


abs_mod.llm_decide = capture_prompt
try:
    abs_mod.ask_llm_for_revision(
        slug="sampleproj", build_system="cmake", sanitizer="asan",
        current_script="#!/bin/bash\nset -eu\n", build_log="failed",
        readme_excerpt="Use the bundled configure preset.", timeout_secs=10,
    )
    abs_mod.ask_llm_for_revision(
        slug="sampleproj", build_system="cmake", sanitizer="asan",
        current_script="#!/bin/bash\nset -eu\n", build_log="failed",
        readme_excerpt="", timeout_secs=10,
    )
finally:
    abs_mod.llm_decide = original_llm_decide

ok("Use the bundled configure preset." in captured_prompts[0],
   "prompt: caller includes a non-empty README excerpt")
ok("Upstream README build-instructions excerpt" not in captured_prompts[1],
   "prompt: caller omits the README section when no excerpt exists")
ok(all("{%" not in prompt and "%}" not in prompt for prompt in captured_prompts),
   "prompt: unsupported template control tags never reach the model")


# ─── Existing-recipe repair budget ────────────────────────────────────

with tempfile.TemporaryDirectory() as _repair_tmp:
    _repair_root = Path(_repair_tmp)
    _repair_src = _repair_root / "sampleproj"
    _repair_src.mkdir()
    (_repair_src / "CMakeLists.txt").write_text("project(sampleproj C)\n")
    _repair_recipe = _repair_root / "build.sh"
    _repair_recipe.write_text(
        '#!/usr/bin/env bash\nset -eu\nsrc="$1"; build="$2"\n'
        ': -fsanitize=address\nfalse\n'
    )
    _repair_failure = _repair_root / "failed.log"
    _repair_failure.write_text("stale dependency: removed.c: No such file\n")
    _repair_out = _repair_root / "repaired.sh"
    _repair_scratch = _repair_root / "scratch"
    _repair_calls: list[str] = []
    _repair_attempts: list[str] = []
    _original_ask = abs_mod.ask_llm_for_revision
    _original_run = abs_mod.run_script

    def _repair_ask(**kwargs):
        _repair_calls.append(kwargs["build_log"])
        number = len(_repair_calls)
        return (
            '#!/usr/bin/env bash\nset -eu\nsrc="$1"; build="$2"\n'
            f': -fsanitize=address\n# revision {number}\nfalse\n'
        )

    def _repair_run(candidate, _src, _build, _timeout):
        _repair_attempts.append(Path(candidate).read_text())
        return 1, f"revision attempt {len(_repair_attempts)} failed\n"

    abs_mod.ask_llm_for_revision = _repair_ask
    abs_mod.run_script = _repair_run
    try:
        try:
            abs_mod.main([
                "--src", str(_repair_src), "--sanitizer", "asan",
                "--out", str(_repair_out), "--scratch", str(_repair_scratch),
                "--repair-from", str(_repair_recipe),
                "--failure-log", str(_repair_failure), "--max-iters", "3",
            ])
            _repair_rc = 0
        except SystemExit as exc:
            _repair_rc = int(exc.code)
    finally:
        abs_mod.ask_llm_for_revision = _original_ask
        abs_mod.run_script = _original_run

    ok(_repair_rc == 3, "repair: exhausts the bounded budget without convergence")
    ok(len(_repair_attempts) == 3,
       "repair: --max-iters 3 performs exactly three revised build attempts")
    ok(len(_repair_calls) == 3,
       "repair: requests no unused revision after the third failed attempt")
    ok(_repair_calls[0].startswith("stale dependency"),
       "repair: the canonical clean-build failure seeds the first revision")
    ok(not _repair_out.exists(),
       "repair: does not overwrite the durable recipe when validation fails")


# ─── End-to-end: iter 1 detects missing toolchain, exits 3 ──────────
#
# We can't run a real cmake build inside the test harness portably, so
# instead we run auto-build-script against a fake source tree whose
# build.candidate.sh execution will fail with "command not found" by
# running the script under a PATH that excludes cmake. The script's
# initial cmake template is what we feed it; we don't need a real
# CMakeLists.txt because the cmake invocation fails before reading it.

with tempfile.TemporaryDirectory() as tmpd:
    src = Path(tmpd) / "src"
    src.mkdir()
    (src / "CMakeLists.txt").write_text(
        "cmake_minimum_required(VERSION 3.0)\nproject(fake C)\n",
        encoding="utf-8",
    )
    out_path = Path(tmpd) / "build.sh"

    # PATH that contains bash + coreutils but NOT cmake. /usr/bin is
    # enough for the script's own runtime; cmake will be unresolvable.
    minimal_path = "/usr/bin:/bin"
    env = os.environ.copy()
    env["PATH"] = minimal_path
    # Confirm cmake is genuinely absent from the test PATH. If a host
    # has cmake at /usr/bin/cmake, skip the e2e test (still meaningful
    # because the unit cases above already covered the detector).
    try:
        which = subprocess.run(
            ["bash", "-c", "command -v cmake"],
            env=env, capture_output=True, text=True, check=False,
        )
        cmake_present = which.returncode == 0
    except OSError:
        cmake_present = True  # be conservative: skip if anything weird

    if cmake_present:
        passed("e2e: cmake present on host PATH — skipping toolchain-missing e2e (detector unit tests still cover the logic)")
    else:
        proc = subprocess.run(
            [sys.executable, str(ABS),
             "--src", str(src),
             "--sanitizer", "asan",
             "--out", str(out_path),
             "--max-iters", "5",
             "--build-timeout-secs", "30"],
            env=env, capture_output=True, text=True, check=False,
        )
        ok(proc.returncode == 3,
           f"e2e: exits 3 on missing toolchain (got {proc.returncode})",
           detail=f"stderr tail: {proc.stderr[-400:]!r}")
        ok("toolchain missing" in proc.stderr,
           "e2e: stderr names the failure as 'toolchain missing'",
           detail=f"stderr tail: {proc.stderr[-400:]!r}")
        ok("cmake" in proc.stderr,
           "e2e: stderr names the missing command",
           detail=f"stderr tail: {proc.stderr[-400:]!r}")
        ok("apt-get install" in proc.stderr or "install-container-deps" in proc.stderr,
           "e2e: stderr points operator at an install path",
           detail=f"stderr tail: {proc.stderr[-400:]!r}")
        ok("asking LLM for revision" not in proc.stderr,
           "e2e: LLM revision loop is skipped",
           detail=f"stderr tail: {proc.stderr[-400:]!r}")


# ─── alternate configuration helpers ───────────────────────────────

_ordered = ["-DFIRST=1", "-DVALUE=two words", "-DTHIRD=$(literal)"]
_script = abs_mod.initial_script("cmake", "asan", _ordered)
ok(_script.index("-DFIRST=1") < _script.index("-DVALUE=two words") < _script.index("-DTHIRD=$(literal)"),
   "named config flags retain declared order")
ok("'-DVALUE=two words'" in _script and "'-DTHIRD=$(literal)'" in _script,
   "named config flags are shell-quoted as single literal argv entries")

_baseline = (
    "#!/usr/bin/env bash\nset -eu\nsrc=\"$1\"; build=\"$2\"\n"
    ": -fsanitize=address -O2 -g1 -DNDEBUG -fno-omit-frame-pointer\n"
)
ok(abs_mod.widened_preserves_baseline(_baseline, _baseline + ": -DWITH_X=ON\n")[0],
   "widen guard accepts added features while retaining the primary contract")
ok(not abs_mod.widened_preserves_baseline(
       _baseline, _baseline.replace("-fsanitize=address", ""))[0],
   "widen guard rejects a candidate that drops the sanitizer")
ok(abs_mod.widened_adds_advertised_option(
       _baseline, _baseline + ": -DWITH_PARSER=ON\n", "WITH_PARSER\nBUILD_TESTING", "cmake"),
   "widen guard requires an advertised feature option")
ok(not abs_mod.widened_adds_advertised_option(
       _baseline, _baseline + "# comment only\n", "WITH_PARSER", "cmake"),
   "widen guard rejects a recipe with no advertised option")
ok(abs_mod.widened_disables_advertised_option(
       _baseline, _baseline + ": -DWITH_ICONV=OFF\n", "WITH_ICONV\nWITH_READER", "cmake")
   == "WITH_ICONV", "widen guard detects a newly disabled primary-default feature")
ok(abs_mod.widened_disables_advertised_option(
       _baseline + ": -DWITH_ICONV=OFF\n",
       _baseline + ": -DWITH_ICONV=OFF -DWITH_READER=ON\n",
       "WITH_ICONV\nWITH_READER", "cmake") == "",
   "widen guard permits a disable already present in the primary recipe")

with tempfile.TemporaryDirectory() as _empty_options_tmp:
    _empty_options_root = Path(_empty_options_tmp)
    (_empty_options_root / "CMakeLists.txt").write_text(
        "project(no_options C)\n", encoding="utf-8"
    )
    _empty_options_scratch = _empty_options_root / "scratch"
    _empty_options_scratch.mkdir()
    ok(abs_mod.widen_features(
           slug="no-options", build_system="cmake", sanitizer="asan",
           baseline_script=_baseline, src=_empty_options_root,
           scratch=_empty_options_scratch, readme_excerpt="",
           build_timeout_secs=10, llm_timeout_secs=10,
       ) == "", "widening distinguishes a target with no shipped feature options")

with tempfile.TemporaryDirectory() as _nested_tmp:
    _nested_root = Path(_nested_tmp)
    (_nested_root / "CMakeLists.txt").write_text(
        "add_subdirectory(build/cmake)\n", encoding="utf-8"
    )
    _nested_options = _nested_root / "build/cmake/CMakeModules/Options.cmake"
    _nested_options.parent.mkdir(parents=True)
    _nested_options.write_text(
        'option(NESTED_SHIPPED_FEATURE "nested feature" OFF)\n', encoding="utf-8"
    )
    ok("NESTED_SHIPPED_FEATURE" in abs_mod.collect_feature_options(_nested_root, "cmake"),
       "feature collection follows bounded nested CMake source layouts")

ok(abs_mod.is_surface_option("LIB_WITH_LEGACY_DECODER"),
   "feature filtering keeps shipped decoder surfaces")
for _non_surface in (
    "BUILD_SHARED_LIBS", "LIB_BUILD_TESTS", "PROGRAMS_LINK_SHARED",
    "ENABLE_BENCHMARKS", "MULTITHREADED_COMPILATION",
):
    ok(not abs_mod.is_surface_option(_non_surface),
       f"feature filtering drops non-surface option {_non_surface}")

with tempfile.TemporaryDirectory() as _declared_options_tmp:
    _declared_root = Path(_declared_options_tmp)
    (_declared_root / "meson.options").write_text(
        "option('legacy_decoder', type: 'feature', value: 'auto')\n"
        "option('build-tests', type: 'boolean', value: false)\n"
        "option('default_library', type: 'combo', choices: ['shared', 'static'])\n",
        encoding="utf-8",
    )
    _meson_options = abs_mod.collect_feature_options(_declared_root, "meson")
    ok("legacy_decoder" in _meson_options and "build-tests" in _meson_options,
       "Meson feature collection preserves option semantics for model selection")
    ok(abs_mod.widened_adds_advertised_option(
           _baseline, _baseline + ": -Dlegacy_decoder=enabled\n",
           _meson_options, "meson"),
       "Meson widen guard accepts a filtered advertised feature")
    ok(not abs_mod.widened_adds_advertised_option(
           _baseline, _baseline + ": -Dbuild-tests=true\n",
           _meson_options, "meson"),
       "Meson widen guard does not count test controls as feature coverage")
    ok(abs_mod.widened_enables_non_surface_option(
           _baseline, _baseline + ": -Dbuild-tests=true\n", "meson")
       == "build-tests",
       "Meson widen guard rejects newly enabled test controls")

    _configure = _declared_root / "configure"
    _configure.write_text(
        "#!/bin/sh\n"
        "echo '  --enable-legacy-decoder  include compatibility decoder'\n"
        "echo '  --enable-tests           build test programs'\n"
        "echo '  --enable-shared          build shared library'\n"
        "echo '  --without-zlib           omit compression support'\n",
        encoding="utf-8",
    )
    _configure.chmod(0o755)
    _autotools_options = abs_mod.collect_feature_options(_declared_root, "autotools")
    ok("--enable-legacy-decoder" in _autotools_options
       and "include compatibility decoder" in _autotools_options,
       "Autotools feature collection preserves option descriptions")
    ok(not abs_mod.widened_adds_advertised_option(
           _baseline, _baseline + ": --enable-tests\n",
           _autotools_options, "autotools"),
       "Autotools widen guard does not count test controls as feature coverage")

with tempfile.TemporaryDirectory() as _feedback_tmp:
    _feedback_root = Path(_feedback_tmp)
    (_feedback_root / "CMakeLists.txt").write_text(
        'option(LEGACY_DECODER "compatibility decoder" OFF)\n', encoding="utf-8"
    )
    _feedback_scratch = _feedback_root / "scratch"
    _feedback_scratch.mkdir()
    _bad_widen = _baseline + ": -DLEGACY_DECODER=MAYBE\n"
    _good_widen = _baseline + ": -DLEGACY_DECODER=ON\n"
    _proposals = iter([_bad_widen, _good_widen])
    _build_results = iter([(1, "configure rejected MAYBE\n"), (0, "built\n")])
    _feedback_seen = []
    _saved_ask = abs_mod.ask_llm_for_widened
    _saved_run = abs_mod.run_script
    _saved_artifacts = abs_mod.build_produced_artifacts
    try:
        def _fake_widened(**kwargs):
            _feedback_seen.append(kwargs.get("build_log", ""))
            return next(_proposals)
        abs_mod.ask_llm_for_widened = _fake_widened
        abs_mod.run_script = lambda *args, **kwargs: next(_build_results)
        abs_mod.build_produced_artifacts = lambda _path: True
        _feedback_result = abs_mod.widen_features(
            slug="feedback", build_system="cmake", sanitizer="asan",
            baseline_script=_baseline, src=_feedback_root,
            scratch=_feedback_scratch, readme_excerpt="",
            build_timeout_secs=10, llm_timeout_secs=10,
        )
    finally:
        abs_mod.ask_llm_for_widened = _saved_ask
        abs_mod.run_script = _saved_run
        abs_mod.build_produced_artifacts = _saved_artifacts
    ok(_feedback_result == _good_widen,
       "widening revises and builds after deterministic validation feedback")
    ok(len(_feedback_seen) == 2 and "configure rejected MAYBE" in _feedback_seen[1],
       "widening sends the failed candidate build log to the model")

_saved_decide = abs_mod.llm_decide
_rendered_feedback = []
try:
    def _capture_decide(_decision, _keys, prompt, **_kwargs):
        _rendered_feedback.append(prompt)
        return {"script": _good_widen}
    abs_mod.llm_decide = _capture_decide
    abs_mod.ask_llm_for_widened(
        slug="feedback", build_system="cmake", sanitizer="asan",
        baseline_script=_baseline, feature_options="LEGACY_DECODER",
        readme_excerpt="", timeout_secs=10,
        current_script=_baseline, build_log="synthetic configure failure",
    )
finally:
    abs_mod.llm_decide = _saved_decide
ok(len(_rendered_feedback) == 1
   and "synthetic configure failure" in _rendered_feedback[0]
   and "{%" not in _rendered_feedback[0],
   "widening feedback renders through the control-tag-free prompt path")


# ─── summary ────────────────────────────────────────────────────────

if _FAILED:
    print(f"  {_RED}{_PASSED + _FAILED} tests, {_FAILED} failed{_NC}")
    sys.exit(1)
print(f"  {_GREEN}{_PASSED}/{_PASSED} passed{_NC}")
