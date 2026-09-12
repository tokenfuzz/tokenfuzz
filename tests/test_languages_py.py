#!/usr/bin/env python3
"""tests/test_languages_py.py — exercise the lib/languages.py registry.

Coverage:
  1. All required languages are registered with non-empty extensions.
  2. Source / harness extension unions match the per-language tuples.
  3. Build_system lookups return the expected language.
  4. probe_dispatch shape is correct for every harness extension
     (compiled vs interpreted, .kts script-mode override, etc.).
  5. The runner_table matches every entry in target_config.LANGUAGE_RUNNERS
     — guards against the silos drifting.
  6. workqueue.SOURCE_EXTS is the same frozenset as languages.all_source_exts()
     — guards against the silo that triggered this refactor.
  7. crash_artifacts._HARNESS_SOURCE_SUFFIXES still spells the C/C++ set.
  8. mode_for_ext returns "js" for .js/.mjs and "auto" otherwise.
  9. bootstrap_for_target gates correctly on manifest presence.
 10. CLI subcommands emit the expected shapes.

Output matches helpers.sh (✓/✗) so tests/run-tests.sh's pass/fail counter
still works.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "lib"))
import languages
import verdict
import workqueue
import target_config
import crash_artifacts

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
    print(f"  {_RED}✗{_NC} {name}")
    if detail:
        print(f"    {detail}")


def assert_eq(expected, actual, name: str) -> None:
    if expected == actual:
        passed(name)
    else:
        failed(name, f"expected={expected!r} actual={actual!r}")


def assert_true(cond, name: str, detail: str = "") -> None:
    if cond:
        passed(name)
    else:
        failed(name, detail or "condition was false")


def assert_in(needle, haystack, name: str) -> None:
    if needle in haystack:
        passed(name)
    else:
        failed(name, f"{needle!r} not in {haystack!r}")


def assert_not_in(needle, haystack, name: str) -> None:
    if needle not in haystack:
        passed(name)
    else:
        failed(name, f"{needle!r} unexpectedly in {haystack!r}")


# SwiftPM metadata discovery runs inside the audit sandbox, so both SwiftPM
# itself and Clang must use target-local writable state.
with tempfile.TemporaryDirectory() as td:
    root = Path(td)
    (root / "Package.swift").write_text("// swift-tools-version: 6.0\n")
    described = subprocess.CompletedProcess(
        [], 0, stdout='{"name": "Sample", "products": [], "targets": []}', stderr="",
    )
    with mock.patch.object(languages.subprocess, "run", return_value=described) as run_swift:
        languages.swift_package_info(root)
    command = run_swift.call_args.args[0]
    environment = run_swift.call_args.kwargs["env"]
    assert_in("--disable-sandbox", command,
              "SwiftPM metadata disables its nested sandbox")
    assert_true(environment["SWIFTPM_MODULECACHE_OVERRIDE"].startswith(str(root)),
                "SwiftPM metadata uses target-local module cache")
    assert_true(environment["CLANG_MODULE_CACHE_PATH"].startswith(str(root)),
                "SwiftPM metadata gives Clang the target-local module cache")

with tempfile.TemporaryDirectory() as td:
    root = Path(td)
    (root / "Package.swift").write_text("// swift-tools-version: 6.0\n")
    with mock.patch.object(
        languages.subprocess, "run", side_effect=FileNotFoundError("swift"),
    ):
        try:
            languages.swift_package_info(root)
        except ValueError as exc:
            assert_in("SwiftPM could not describe", str(exc),
                      "missing SwiftPM is reported as package metadata failure")
        else:
            failed("missing SwiftPM is reported as package metadata failure")
        try:
            target_config.seed_toml(root, root / "target.toml", "")
        except ValueError as exc:
            assert_in("SwiftPM could not describe", str(exc),
                      "missing SwiftPM does not hide a real package manifest")
        else:
            failed("missing SwiftPM does not hide a real package manifest")

with tempfile.TemporaryDirectory() as td:
    root = Path(td)
    (root / "Package.swift").touch()
    config = root / "target.toml"
    with mock.patch.object(
        languages.subprocess, "run", side_effect=FileNotFoundError("swift"),
    ):
        target_config.seed_toml(root, config, "")
    seeded = target_config.parse_toml(config)
    assert_eq("swift", seeded["runner"]["bin"],
              "an empty Swift placeholder seeds a runner without the toolchain")
    assert_eq(["{TESTCASE}"], seeded["runner"]["args"],
              "an empty Swift placeholder keeps the safe source fallback")


# ─── 1. Required languages are present ─────────────────────────────

REQUIRED_LANGUAGES = (
    "c", "cpp", "rust", "python", "php", "javascript", "typescript",
    "java", "kotlin", "go", "swift",
)

names = {lang.name for lang in languages.LANGUAGES}
for required in REQUIRED_LANGUAGES:
    assert_in(required, names, f"registry: {required} is registered")

# Every registered language has at least source_exts or harness_exts.
for lang in languages.LANGUAGES:
    assert_true(
        bool(lang.source_exts) or bool(lang.harness_exts),
        f"registry: {lang.name} has at least one extension",
    )


# ─── 2. Extension unions ───────────────────────────────────────────

all_src = languages.all_source_exts()
for ext in (".c", ".cpp", ".rs", ".py", ".pyx", ".php", ".js", ".mjs",
            ".ts", ".tsx", ".java", ".kt", ".kts", ".go", ".swift"):
    assert_in(ext, all_src, f"all_source_exts contains {ext}")

# .pyc / .so / .o must NOT be in source_exts — they're build outputs.
for ext in (".pyc", ".so", ".o", ".jar", ".class"):
    assert_not_in(ext, all_src, f"all_source_exts excludes build output {ext}")

# Harness compiled vs interpreted buckets are disjoint.
hc = languages.all_harness_exts(compiled=True)
hi = languages.all_harness_exts(compiled=False)
assert_eq(set(), hc & hi, "harness compiled / interpreted are disjoint")
assert_eq(hc | hi, languages.all_harness_exts(), "harness union covers both buckets")

# Kotlin: .kt is compiled, .kts is interpreted (script-mode override).
assert_in(".kt", hc, "harness-compiled contains .kt")
assert_in(".kts", hi, "harness-interpreted contains .kts (script override)")
assert_not_in(".kt", hi, "harness-interpreted excludes .kt")
assert_not_in(".kts", hc, "harness-compiled excludes .kts")


# ─── 3. build_system lookups ───────────────────────────────────────

assert_eq("python", languages.for_build_system("python").name,
          "for_build_system: python -> python")
assert_eq("rust", languages.for_build_system("cargo").name,
          "for_build_system: cargo -> rust")
assert_eq("go", languages.for_build_system("go").name,
          "for_build_system: go -> go")
assert_eq("swift", languages.for_build_system("swift").name,
          "for_build_system: swift -> swift")
assert_eq("javascript", languages.for_build_system("npm").name,
          "for_build_system: npm -> javascript")
assert_eq("php", languages.for_build_system("composer").name,
          "for_build_system: composer -> php")
assert_eq("ruby", languages.for_build_system("bundler").name,
          "for_build_system: bundler -> ruby")
assert_in("RUBYLIB={TARGET_ROOT}/lib",
          languages.for_build_system("bundler").runner_env,
          "Ruby runner imports the audited checkout")
assert_in("RUBYOPT=-rbundler/setup",
          languages.for_build_system("bundler").runner_env,
          "Ruby runner activates the target's vendored bundle")
with tempfile.TemporaryDirectory() as td:
    ruby_error = Path(td) / "runner.txt"
    ruby_error.write_text(
        "/tmp/sample.rb:9:in 'Sample#parse': invalid value (Sample::ParseError)\n",
        encoding="utf-8",
    )
    assert_true(verdict.file_has_crash(
        ruby_error, languages.for_build_system("bundler").crash_patterns,
    ), "Ruby runner recognizes the standard uncaught-exception header")
assert_eq("java", languages.for_build_system("maven").name,
          "for_build_system: maven -> java")
assert_eq("java", languages.for_build_system("gradle").name,
          "for_build_system: gradle -> java")
assert_eq("kotlin", languages.for_build_system("kotlin").name,
          "for_build_system: kotlin -> kotlin")
_perl_path = languages.for_build_system("perl").runner_env[0]
assert_in("{TARGET_ROOT}/blib/arch", _perl_path,
          "Perl runner loads the checkout's compiled XS modules")
assert_in("{TARGET_ROOT}/.audit/perl5/lib/perl5", _perl_path,
          "Perl runner loads target-local dependencies")
assert_eq(("R_LIBS_USER={TARGET_ROOT}/.audit/r-library",),
          languages.for_build_system("rlang").runner_env,
          "R runner imports the target-local package install")
# Every language whose runner executes a testcase as source can prove it
# reaches the target. Swift's canary is completed with a real exported module
# after SwiftPM describes the package.
_CANARY_EXEMPT = set()
for _lang in languages.LANGUAGES:
    if not _lang.runner_bin or _lang.name in _CANARY_EXEMPT:
        continue
    assert_true(bool(_lang.canary_source),
                f"{_lang.name} runner carries a reachability canary")
    assert_in("TOKENFUZZ-CANARY", _lang.canary_source,
              f"{_lang.name} canary prints the marker the harness reads")
assert_in("TOKENFUZZ-CANARY", languages.for_build_system("swift").canary_source,
          "swift carries the marker used by its package-aware canary")

# Native C/C++ build systems -> c (which carries the union)
assert_eq("c", languages.for_build_system("cmake").name,
          "for_build_system: cmake -> c")
assert_eq("c", languages.for_build_system("meson").name,
          "for_build_system: meson -> c")
assert_eq("c", languages.for_build_system("autotools").name,
          "for_build_system: autotools -> c")
assert_eq(None, languages.for_build_system("nosuch"),
          "for_build_system: unknown slug -> None")


# ─── 4. probe_dispatch shapes ──────────────────────────────────────

def assert_dispatch_compiled(ext, expected_build_kind, expected_compiler, expected_env):
    info = languages.probe_dispatch(ext)
    assert_eq(expected_build_kind, info["build_kind"],
              f"probe_dispatch {ext}: build_kind")
    assert_eq(expected_compiler, info["compiler_default"],
              f"probe_dispatch {ext}: compiler_default")
    assert_eq(expected_env, info["compiler_env"],
              f"probe_dispatch {ext}: compiler_env")


def assert_dispatch_interpret(ext, expected_interpreter, expected_env, expected_preargs=None):
    info = languages.probe_dispatch(ext)
    assert_eq("interpret", info["build_kind"],
              f"probe_dispatch {ext}: build_kind=interpret")
    assert_eq(expected_interpreter, info["interpreter_default"],
              f"probe_dispatch {ext}: interpreter_default")
    assert_eq(expected_env, info["interpreter_env"],
              f"probe_dispatch {ext}: interpreter_env")
    if expected_preargs is not None:
        assert_eq(expected_preargs, info["interpreter_preargs"],
                  f"probe_dispatch {ext}: interpreter_preargs")


assert_dispatch_compiled(".c", "cc", "clang", "CC")
assert_dispatch_compiled(".cpp", "cc", "clang++", "CXX")
assert_dispatch_compiled(".cc", "cc", "clang++", "CXX")
assert_dispatch_compiled(".rs", "rust", "rustc", "RUSTC")
assert_dispatch_compiled(".go", "go", "go", "GO")
assert_dispatch_compiled(".swift", "swift", "swiftc", "SWIFTC")
assert_dispatch_compiled(".kt", "kotlin", "kotlinc", "KOTLINC")

assert_dispatch_interpret(".py", "python3", "PYTHON3", [])
assert_dispatch_interpret(".rb", "ruby", "RUBY", [])
assert_dispatch_interpret(".js", "node", "NODE", [])
assert_dispatch_interpret(".mjs", "node", "NODE", [])
assert_dispatch_interpret(".ts", "ts-node", "TSNODE", [])
assert_dispatch_interpret(".tsx", "ts-node", "TSNODE", [])
assert_dispatch_interpret(".php", "php", "PHP", [])
assert_dispatch_interpret(".pl", "perl", "PERL", [])
assert_dispatch_interpret(".java", "java", "JAVA", [])
assert_dispatch_interpret(".kts", "kotlinc", "KOTLINC", ["-script"])
assert_dispatch_interpret(".r", "Rscript", "RSCRIPT", [])
assert_dispatch_interpret(".sh", "bash", "BASH", [])

# Bogus extension yields None.
assert_eq(None, languages.probe_dispatch(".xyz"),
          "probe_dispatch unknown ext returns None")

# Extension without a leading dot is accepted.
info_py = languages.probe_dispatch("py")
assert_true(info_py and info_py["build_kind"] == "interpret",
            "probe_dispatch accepts 'py' (no leading dot)")


# ─── 5. runner_table matches target_config.LANGUAGE_RUNNERS ────────

runner_table = languages.runner_table()
assert_eq(set(runner_table.keys()), set(target_config.LANGUAGE_RUNNERS.keys()),
          "runner_table keys == target_config.LANGUAGE_RUNNERS keys")
for bs, block in runner_table.items():
    tc_block = target_config.LANGUAGE_RUNNERS[bs]
    assert_eq(block["bin"], tc_block["bin"], f"runner_table[{bs}].bin matches")
    assert_eq(list(block["args"]), list(tc_block["args"]),
              f"runner_table[{bs}].args matches")
    assert_eq(list(block["env"]), list(tc_block["env"]),
              f"runner_table[{bs}].env matches")
    assert_eq(list(block["crash_patterns"]), list(tc_block["crash_patterns"]),
              f"runner_table[{bs}].crash_patterns matches")


# ─── 6. workqueue.SOURCE_EXTS is the registry union ────────────────

assert_eq(workqueue.SOURCE_EXTS, languages.all_source_exts(),
          "workqueue.SOURCE_EXTS == languages.all_source_exts()")
# Pre-bug-fix sanity: Python and other interpreted languages MUST be present.
for ext in (".py", ".rb", ".go", ".java", ".kt", ".php", ".ts"):
    assert_in(ext, workqueue.SOURCE_EXTS,
              f"workqueue.SOURCE_EXTS contains {ext} (regression guard for pyyaml bug)")


# ─── 7. crash_artifacts._HARNESS_SOURCE_SUFFIXES is C/C++ only ────

expected_chc = (".c", ".cc", ".cpp", ".cxx")
actual_chc = crash_artifacts._HARNESS_SOURCE_SUFFIXES
assert_eq(set(expected_chc), set(actual_chc),
          "crash_artifacts._HARNESS_SOURCE_SUFFIXES is C/C++ set")
# Rust / Go / Swift / Kotlin .so harnesses must NOT be in this set —
# the heuristic only fires on free-standing main() bodies.
for non_c in (".rs", ".go", ".swift", ".kt", ".py", ".js"):
    assert_not_in(non_c, set(actual_chc),
                  f"crash_artifacts excludes non-C/C++ harness ext {non_c}")


# ─── 8. mode_for_ext ───────────────────────────────────────────────

assert_eq("js", languages.mode_for_ext(".js"), "mode_for_ext .js -> js")
assert_eq("js", languages.mode_for_ext(".mjs"), "mode_for_ext .mjs -> js")
assert_eq("js", languages.mode_for_ext(".cjs"), "mode_for_ext .cjs -> js")
assert_eq("auto", languages.mode_for_ext(".c"), "mode_for_ext .c -> auto")
assert_eq("auto", languages.mode_for_ext(".py"), "mode_for_ext .py -> auto")
assert_eq("auto", languages.mode_for_ext(".ts"),
          "mode_for_ext .ts -> auto (TypeScript not in js mode)")
assert_eq("auto", languages.mode_for_ext(".unknown"),
          "mode_for_ext unknown ext -> auto")


# ─── 9. bootstrap_for_target ───────────────────────────────────────

with tempfile.TemporaryDirectory() as td:
    tmp_root = Path(td)
    # Empty target: no manifest -> no bootstrap.
    assert_eq([], languages.bootstrap_for_target(tmp_root, "python"),
              "bootstrap: empty python target -> no commands")
    assert_eq([], languages.bootstrap_for_target(tmp_root, "cargo"),
              "bootstrap: empty rust target -> no commands")

    # setup.py present -> python bootstrap fires (three-step recipe:
    # create .audit/venv, upgrade pip, then `pip install -e .` which
    # uses PEP 517 build isolation to provision setuptools/Cython
    # from [build-system].requires and writes C extensions in-place).
    # The venv path sidesteps PEP 668 on Homebrew/Debian
    # externally-managed pythons.
    (tmp_root / "setup.py").write_text("# placeholder\n")
    cmds = languages.bootstrap_for_target(tmp_root, "python")
    assert_eq(3, len(cmds), "bootstrap: python with setup.py -> 3 commands")
    assert_in("venv", cmds[0],
              "bootstrap: python step 1 creates a venv (PEP 668 safe)")
    assert_in(".audit/venv", cmds[0],
              "bootstrap: python venv lives under .audit/")
    assert_in(".audit/venv/bin/python", cmds[1],
              "bootstrap: python step 2 uses the venv's interpreter to upgrade pip")
    assert_in("-e", cmds[2],
              "bootstrap: python step 3 uses editable install (writes .so in-place)")
    assert_in(".audit/venv/bin/python", cmds[2],
              "bootstrap: python step 3 builds via venv python "
              "(same ABI tag as system python3 — runner can still use python3)")
    (tmp_root / "setup.py").unlink()

    # Cargo.toml present -> rust bootstrap fires (release mode with
    # --locked primary, and a fallback that drops --locked for
    # lockfile-drift recovery).
    (tmp_root / "Cargo.toml").write_text("[package]\n")
    cmds = languages.bootstrap_for_target(tmp_root, "cargo")
    assert_eq(2, len(cmds), "bootstrap: rust fetches then builds")
    assert_in("cargo", cmds[0], "bootstrap: rust command starts with cargo")
    assert_in("fetch", cmds[0],
              "bootstrap: rust prefetches testcase dev-dependencies")
    assert_in("--release", cmds[1],
              "bootstrap: rust uses release mode (no debug-assertions noise)")
    assert_in("--locked", cmds[1],
              "bootstrap: rust primary uses --locked for reproducibility")
    rust_plan = languages.bootstrap_plan_for_target(tmp_root, "cargo")
    assert_eq(1, len(rust_plan["alternatives"]),
              "bootstrap: rust has 1 fallback (drops --locked)")
    assert_true("--locked" not in rust_plan["alternatives"][0],
                "bootstrap: rust fallback drops --locked (drift recovery)")
    assert_in(["CARGO_HOME", ".audit/cargo-home"], rust_plan["env"],
              "bootstrap: rust populates a target-owned Cargo cache")
    (tmp_root / "Cargo.toml").unlink()

    (tmp_root / "DESCRIPTION").write_text("Package: sample\n")
    r_plan = languages.bootstrap_plan_for_target(tmp_root, "rlang")
    assert_eq(3, len(r_plan["cmds"]),
              "bootstrap: R installs dependencies before the package")
    assert_eq("Rscript", r_plan["cmds"][0][0],
              "bootstrap: R creates its local library portably")
    assert_in("remotes::install_deps", r_plan["cmds"][1][-1],
              "bootstrap: R resolves hard dependencies from DESCRIPTION")
    assert_in("dependencies=NA", r_plan["cmds"][1][-1],
              "bootstrap: R excludes development-only dependencies")
    assert_eq(["R", "CMD", "INSTALL"], r_plan["cmds"][2][:3],
              "bootstrap: R installs the package after its dependencies")
    assert_in(["R_LIBS_USER", ".audit/r-library"], r_plan["env"],
              "bootstrap: R install stays target-local")
    (tmp_root / "DESCRIPTION").unlink()

    (tmp_root / "build.gradle").write_text("plugins { id 'java' }\n")
    gradle_cmd = languages.bootstrap_for_target(tmp_root, "gradle")[0]
    assert_in("-Dorg.gradle.configuration-cache=false", gradle_cmd,
              "bootstrap: injected Gradle task disables incompatible configuration cache")
    (tmp_root / "build.gradle").unlink()

    # go.mod -> go primes the default cache, so no probe compiles std inside
    # its run deadline, then builds with -race (Go's maintained sanitizer).
    (tmp_root / "go.mod").write_text("module x\n")
    cmds = languages.bootstrap_for_target(tmp_root, "go")
    assert_eq(2, len(cmds), "bootstrap: go with go.mod -> 2 commands")
    assert_in("std", cmds[0],
              "bootstrap: go primes the default standard-library cache")
    assert_in("-race", cmds[1],
              "bootstrap: go enables -race data-race detector")
    go_plan = languages.bootstrap_plan_for_target(tmp_root, "go")
    assert_eq(3, len(go_plan["alternatives"]),
              "bootstrap: go keeps race and plain root-package fallbacks")
    assert_eq(["go", "build", "-race", "-trimpath", "."],
              go_plan["alternatives"][0],
              "bootstrap: optional subpackages cannot block the audited root package")
    assert_not_in("-race", go_plan["alternatives"][1],
                  "bootstrap: the remaining go fallbacks drop the cgo-only detector")
    assert_in(["GOCACHE", "{TARGET_ROOT}/.audit/go-build"], go_plan["env"],
              "bootstrap: go build cache stays under the target")
    assert_in(["GOMODCACHE", "{TARGET_ROOT}/.audit/go-mod"], go_plan["env"],
              "bootstrap: go module cache stays under the target")
    (tmp_root / "go.mod").unlink()

    # package.json -> npm bootstrap, primary is `npm ci`.
    (tmp_root / "package.json").write_text("{}\n")
    cmds = languages.bootstrap_for_target(tmp_root, "npm")
    assert_eq(1, len(cmds), "bootstrap: javascript with package.json -> 1 command")
    assert_in("npm", cmds[0], "bootstrap: javascript command is npm")
    assert_in("ci", cmds[0],
              "bootstrap: javascript primary is `npm ci` (deterministic from lockfile)")
    # The new plan API also exposes alternatives and sanitizer env.
    plan = languages.bootstrap_plan_for_target(tmp_root, "npm")
    assert_true(len(plan["alternatives"]) >= 3,
                "bootstrap-plan: npm has install + --legacy-peer-deps + pnpm alternatives")
    assert_true(any("--legacy-peer-deps" in alt for alt in plan["alternatives"]),
                "bootstrap-plan: npm alternatives include --legacy-peer-deps fallback")
    assert_true(any("pnpm" in alt for alt in plan["alternatives"]),
                "bootstrap-plan: npm alternatives include pnpm (workspace: protocol)")

# Unknown build_system silently returns no commands.
assert_eq([], languages.bootstrap_for_target(Path("/tmp"), "nosuch"),
          "bootstrap: unknown build_system -> no commands")


# ─── 9b. JS package-manager detection ──────────────────────────────
# The npm-first chain is only the default. A checkout that signals
# pnpm/yarn (lockfile, Corepack packageManager field, or the
# `workspace:` protocol npm cannot resolve) must run that manager
# first so a monorepo does not burn doomed npm invocations.

def js_primary(root: Path) -> list:
    return languages.bootstrap_plan_for_target(root, "npm")["cmds"][0]

with tempfile.TemporaryDirectory() as td:
    root = Path(td)
    (root / "package.json").write_text("{}\n")

    # No signal at all -> npm default (`npm ci`).
    assert_in("npm", js_primary(root), "js-pm: bare package.json -> npm")
    assert_in("ci", js_primary(root), "js-pm: bare package.json primary is npm ci")

    with mock.patch.object(
        languages.shutil, "which",
        side_effect=lambda name: "/usr/bin/python3" if name == "python3" else None,
    ):
        shim_plan = languages.bootstrap_plan_for_target(root, "npm")
    shim = root / ".audit" / "tool-bin" / "python"
    assert_true(os.access(shim, os.X_OK),
                "js bootstrap: missing legacy python name gets target-local shim")
    assert_in(["PYTHON", "/usr/bin/python3"], shim_plan["env"],
              "js bootstrap: node-gyp receives the discovered Python 3")
    assert_true(dict(shim_plan["env"])["PATH"].startswith(
                    "{TARGET_ROOT}/.audit/tool-bin" + os.pathsep),
                "js bootstrap: shim directory is bootstrap-local PATH prefix")

    # pnpm-lock.yaml -> pnpm runs first.
    (root / "pnpm-lock.yaml").write_text("lockfileVersion: 9\n")
    assert_in("pnpm", js_primary(root), "js-pm: pnpm-lock.yaml -> pnpm primary")
    assert_true("npm" not in js_primary(root) or "pnpm" in js_primary(root),
                "js-pm: pnpm lockfile does not select bare npm")
    # npm/yarn remain available as fallbacks for resilience.
    pnpm_plan = languages.bootstrap_plan_for_target(root, "npm")
    assert_true(any("npm" in alt and "ci" in alt for alt in pnpm_plan["alternatives"]),
                "js-pm: pnpm primary still keeps npm fallbacks")
    (root / "pnpm-lock.yaml").unlink()

    # yarn.lock -> yarn runs first.
    (root / "yarn.lock").write_text("# yarn lockfile v1\n")
    assert_in("yarn", js_primary(root), "js-pm: yarn.lock -> yarn primary")
    (root / "yarn.lock").unlink()

    # Corepack packageManager field, no lockfile.
    (root / "package.json").write_text('{"packageManager":"pnpm@9.1.0"}\n')
    assert_in("pnpm", js_primary(root), "js-pm: packageManager=pnpm -> pnpm primary")
    (root / "package.json").write_text('{"packageManager":"yarn@4.2.2"}\n')
    assert_in("yarn", js_primary(root), "js-pm: packageManager=yarn -> yarn primary")

    # `workspace:` dependency protocol -> pnpm (npm cannot resolve it).
    (root / "package.json").write_text(
        '{"dependencies":{"@scope/pkg":"workspace:*"}}\n')
    assert_in("pnpm", js_primary(root),
              "js-pm: workspace: protocol -> pnpm primary (npm has no resolver)")

    # Lockfile beats a conflicting packageManager field (lockfile is the
    # ground truth of what was actually installed).
    (root / "package.json").write_text('{"packageManager":"yarn@4.2.2"}\n')
    (root / "pnpm-lock.yaml").write_text("lockfileVersion: 9\n")
    assert_in("pnpm", js_primary(root),
              "js-pm: lockfile outranks packageManager field")
    (root / "package-lock.json").write_text("{}\n")
    with mock.patch.object(
        languages.subprocess, "run",
        return_value=subprocess.CompletedProcess(
            args=[], returncode=0, stdout="package-lock.json\n", stderr="",
        ),
    ):
        assert_in("npm", js_primary(root),
                  "js-pm: tracked lock outranks a foreign generated lock")


# ─── 10. CLI subcommands ───────────────────────────────────────────

CLI = [sys.executable, str(ROOT / "lib" / "languages.py")]


def run(cmd, expect_rc=0):
    p = subprocess.run(cmd, capture_output=True, text=True)
    if p.returncode != expect_rc:
        return None, p.stdout, p.stderr
    return p.stdout, p.stdout, p.stderr


out, _, _ = run(CLI + ["exts", "--kind", "source"])
out_lines = (out or "").splitlines()
assert_in("py", out_lines, "CLI exts --kind source includes py")
assert_in("c", out_lines, "CLI exts --kind source includes c")
assert_in("ts", out_lines, "CLI exts --kind source includes ts")

out, _, _ = run(CLI + ["probe-dispatch", "py"])
info = json.loads(out)
assert_eq("interpret", info["build_kind"], "CLI probe-dispatch py emits build kind")
assert_eq("python3", info["interpreter_default"],
          "CLI probe-dispatch py emits interpreter")

out, _, _ = run(CLI + ["probe-dispatch", "rs"])
info = json.loads(out)
assert_eq("rust", info["build_kind"], "CLI probe-dispatch rs emits build kind")
assert_eq("rustc", info["compiler_default"], "CLI probe-dispatch rs emits compiler")

out, _, _ = run(CLI + ["probe-dispatch", "kts"])
info = json.loads(out)
assert_eq("interpret", info["build_kind"], "CLI probe-dispatch kts emits build kind")
assert_eq(["-script"], info["interpreter_preargs"],
          "CLI probe-dispatch kts emits -script preargs")

# Unknown ext exits 2.
out, _, err = run(CLI + ["probe-dispatch", "xyz"], expect_rc=2)
assert_true("unsupported harness extension" in err,
            "CLI probe-dispatch unknown ext: stderr message")

# supports-build-system exits 0 with name, or 1 with empty stdout.
out, _, _ = run(CLI + ["supports-build-system", "python"])
assert_eq("python\n", out, "CLI supports-build-system python -> python (exit 0)")
out, _, _ = run(CLI + ["supports-build-system", "bogus"], expect_rc=1)
assert_eq("\n", out, "CLI supports-build-system bogus -> empty (exit 1)")

# runner-block emits json with the expected shape.
out, _, _ = run(CLI + ["runner-block", "python"])
block = json.loads(out)
assert_eq("python3", block["bin"], "CLI runner-block python -> bin=python3")
assert_in("PYTHONDEVMODE=1", block["env"][0],
          "CLI runner-block python -> env carries PYTHONDEVMODE")

# bootstrap-cmds emits shell-quoted lines (now multi-step for python).
with tempfile.TemporaryDirectory() as td:
    (Path(td) / "setup.py").write_text("# x\n")
    out, _, _ = run(CLI + ["bootstrap-cmds", "python", td])
    assert_in(".audit/venv/bin/python -m pip install -e .", out.strip(),
              "CLI bootstrap-cmds python emits venv-python editable install line")
    assert_in("python3 -m venv .audit/venv", out.strip(),
              "CLI bootstrap-cmds python emits venv creation line")

# bootstrap-plan JSON includes env (release flags), alternatives, and
# fuzz_backends in a single payload.
with tempfile.TemporaryDirectory() as td:
    (Path(td) / "package.json").write_text("{}\n")
    out, _, _ = run(CLI + ["bootstrap-plan", "npm", td])
    plan = json.loads(out)
    assert_eq("javascript", plan["language"],
              "bootstrap-plan npm: language=javascript")
    assert_in("jsfuzz", plan["fuzz_backends"],
              "bootstrap-plan npm: lists jsfuzz as fuzz backend")
    assert_true(len(plan["alternatives"]) >= 1,
                "bootstrap-plan npm: at least one alternative present")

with tempfile.TemporaryDirectory() as td:
    (Path(td) / "package.json").write_text(json.dumps({
        "packageManager": "pnpm@10.0.0",
        "scripts": {"build": "tsc"},
    }))
    plan = languages.bootstrap_plan_for_target(Path(td), "npm")
    assert_eq([["npx", "--yes", "pnpm", "run", "build"]], plan["post_cmds"],
              "bootstrap-plan npm: declared build runs after dependency install")

with tempfile.TemporaryDirectory() as td:
    root = Path(td)
    member = root / "core"
    member.mkdir()
    raw = {
        "workspace_members": ["core-id"],
        "packages": [{
            "id": "core-id", "name": "sample-core",
            "manifest_path": str(member / "Cargo.toml"),
            "targets": [
                {"name": "sample_core", "kind": ["lib"]},
                {"name": "helper", "kind": ["bin"]},
            ],
        }],
    }
    info = languages._cargo_workspace_info(raw, root)
    assert_eq((languages.CargoLibraryProduct("sample-core", "sample_core", "core"),),
              info.libraries,
              "Cargo metadata: workspace member library is retained")
    assert_eq("core", info.executables[0].manifest_dir,
              "Cargo metadata: executable retains its member manifest")

with tempfile.TemporaryDirectory() as td:
    root = Path(td)
    for member in ("app", "tool"):
        (root / member).mkdir()
    raw = {
        "workspace_members": ["app-id", "tool-id"],
        "workspace_default_members": ["app-id"],
        "packages": [
            {
                "id": "app-id", "name": "sample-app",
                "manifest_path": str(root / "app" / "Cargo.toml"),
                "targets": [{"name": "sample_app", "kind": ["lib"]}],
            },
            {
                "id": "tool-id", "name": "helper-tool",
                "manifest_path": str(root / "tool" / "Cargo.toml"),
                "targets": [{"name": "helper", "kind": ["bin"]}],
            },
        ],
    }
    info = languages._cargo_workspace_info(raw, root)
    assert_eq("sample_app", languages.preferred_cargo_libraries(info)[0].crate,
              "Cargo metadata: direct harnesses prefer a default member library")
    assert_eq(False, info.executables[0].default_member,
              "Cargo metadata: non-default workspace tools remain distinguishable")
    with mock.patch.object(languages, "cargo_workspace_info", return_value=info):
        assert_eq(("{TESTCASE}",), languages.cargo_runner_args(root, "helper-tool"),
                  "Cargo metadata: a default library beats a non-default helper binary")

    binaries = languages.CargoWorkspaceInfo((), (
        languages.CargoExecutableProduct("sample-app", "sample-app", "app"),
        languages.CargoExecutableProduct("sample-app", "helper", "app"),
    ))
    with mock.patch.object(languages, "cargo_workspace_info", return_value=binaries):
        args = languages.cargo_runner_args(root, "sample-app")
    assert_in("sample-app", args,
              "Cargo metadata: an exact binary beats other bins in the matching package")

with tempfile.TemporaryDirectory() as td:
    (Path(td) / "composer.json").write_text(json.dumps({
        "require": {"ext-json": "*"},
        "require-dev": {"ext-sample": "*", "sample/tests": "^1"},
    }))
    plan = languages.bootstrap_plan_for_target(Path(td), "composer")
    assert_eq([["composer", "install", "--no-interaction"]], plan["cmds"],
              "bootstrap-plan composer: full install remains primary")
    fallback = plan["alternatives"][0]
    assert_in("--no-dev", fallback,
              "bootstrap-plan composer: production-only fallback skips dev packages")
    assert_in("--ignore-platform-req=ext-sample", fallback,
              "bootstrap-plan composer: ignores a root development-only extension")
    assert_true("--ignore-platform-req=ext-json" not in fallback,
                "bootstrap-plan composer: production extension remains enforced")

with tempfile.TemporaryDirectory() as td:
    root = Path(td)
    old_bin = root / "path-bin"
    brew_bin = root / "brew-bin"
    keg_bin = root / "new-ruby" / "bin"
    for directory in (old_bin, brew_bin, keg_bin):
        directory.mkdir(parents=True)
    for path, version in ((old_bin / "ruby", "2.6.10"),
                          (keg_bin / "ruby", "3.4.2")):
        path.write_text(f"#!/bin/sh\nprintf '%s' '{version}'\n")
        path.chmod(0o755)
        bundle = path.with_name("bundle")
        bundle.write_text("#!/bin/sh\nexit 0\n")
        bundle.chmod(0o755)
    brew = brew_bin / "brew"
    brew.write_text(f"#!/bin/sh\nprintf '%s\\n' '{keg_bin.parent}'\n")
    brew.chmod(0o755)
    ruby, bundle = languages.preferred_ruby_toolchain({
        "PATH": f"{old_bin}:{brew_bin}",
    })
    assert_eq(str(keg_bin / "ruby"), ruby,
              "Ruby discovery prefers a newer installed package-manager toolchain")
    assert_eq(str(keg_bin / "bundle"), bundle,
              "Ruby discovery keeps Bundler on the selected Ruby toolchain")

with tempfile.TemporaryDirectory() as td:
    root = Path(td)
    (root / "sample.gemspec").write_text("Gem::Specification.new {}\n")
    entrypoint = root / "lib" / "sample.rb"
    entrypoint.parent.mkdir()
    entrypoint.write_text("module Sample; end\n")
    metadata = subprocess.CompletedProcess(
        [], 0,
        stdout=json.dumps({
            "name": "sample", "require_paths": ["lib"],
            "extensions": ["ext/sample/extconf.rb"],
        }),
        stderr="",
    )
    with mock.patch.object(
        languages, "preferred_ruby_toolchain", return_value=("ruby", "bundle"),
    ), mock.patch.object(languages.subprocess, "run", return_value=metadata):
        info = languages.ruby_package_info(root)
    assert_eq("sample", info.entrypoint,
              "Ruby metadata selects the declared gem entrypoint")
    assert_eq(str(entrypoint.resolve()), info.entrypoint_path,
              "Ruby metadata retains the checkout entrypoint path")
    assert_eq(("ext/sample/extconf.rb",), info.extensions,
              "Ruby metadata retains declared native extensions")
    with mock.patch.object(
        languages, "preferred_ruby_toolchain", return_value=("ruby", "bundle"),
    ), mock.patch.object(
        languages, "ruby_package_info", return_value=info,
    ), mock.patch.dict(os.environ, {"CONFIGURE_ARGS": "--with-sample-dir=/opt/sample"}):
        plan = languages.bootstrap_plan_for_target(root, "bundler")
    assert_eq([["bundle", "exec", "rake", "compile"]], plan["post_cmds"],
              "Ruby bootstrap compiles a root gem's declared extensions")
    assert_in(["CONFIGURE_ARGS", "--with-sample-dir=/opt/sample"], plan["env"],
              "Ruby bootstrap records standard native configure arguments")

with tempfile.TemporaryDirectory() as td:
    root = Path(td)
    old_bin = root / "old" / "bin"
    new_bin = root / "new" / "bin"
    old_bin.mkdir(parents=True)
    new_bin.mkdir(parents=True)
    for path, version in ((old_bin / "perl", "v5.34.1"),
                          (new_bin / "perl", "v5.40.5")):
        path.write_text(f"#!/bin/sh\nprintf '%s' '{version}'\n")
        path.chmod(0o755)
    cpanm = old_bin / "cpanm"
    cpanm.write_text("#!/bin/sh\nexit 0\n")
    cpanm.chmod(0o755)
    perl, cpanm_bin = languages.preferred_perl_toolchain({
        "PATH": f"{old_bin}:{new_bin}",
    })
    assert_eq(str(new_bin / "perl"), perl,
              "Perl discovery prefers the newest installed PATH toolchain")
    assert_eq(str(cpanm), cpanm_bin,
              "Perl discovery returns an available cpanm script")
    assert_in("v5.40.5", languages.perl_local_lib_root(perl, {
        "PATH": f"{old_bin}:{new_bin}",
    }), "Perl dependency root is isolated by interpreter version")

with tempfile.TemporaryDirectory() as td:
    root = Path(td)
    (root / "Makefile.PL").write_text("# sample\n")
    (root / "lib" / "Sample").mkdir(parents=True)
    (root / "lib" / "Sample.pm").write_text("package Sample; 1;\n")
    (root / "lib" / "Sample" / "Nested.pm").write_text(
        "package Sample::Nested; 1;\n"
    )
    plan = languages.bootstrap_plan_for_target(root, "perl")
    assert_eq(4, len(plan["cmds"]),
              "bootstrap-plan Perl: installs dependencies, builds, and installs")
    assert_in("--installdeps", plan["cmds"][0],
              "bootstrap-plan Perl: resolves declared CPAN dependencies")
    assert_in("--verbose", plan["cmds"][0],
              "bootstrap-plan Perl: exposes configure prerequisite diagnostics")
    assert_in("--mirror-only", plan["cmds"][0],
              "bootstrap-plan Perl: avoids the optional per-module metadata service")
    assert_in(["PERL_CPANM_HOME", "{TARGET_ROOT}/.audit/cpanm"], plan["env"],
              "bootstrap-plan Perl: keeps installer state inside the target")
    assert_in("NO_COLOR", plan["unset_env"],
              "bootstrap-plan Perl: isolates dependency tests from display policy")
    assert_in("{TARGET_ROOT}", plan["env"][0][1],
              "bootstrap-plan Perl: requests an absolute local-library path")
    assert_true(any(value.startswith(".audit/perl5/") for value in plan["cmds"][0]),
                "bootstrap-plan Perl: isolates native dependencies by ABI")
    assert_eq("Sample.pm", languages.perl_canary_module(root),
              "Perl canary selects the distribution's shallow root module")
    (root / "Makefile").write_text("# generated\n")
    rebuilt = languages.bootstrap_plan_for_target(root, "perl")
    assert_eq(["make", "realclean"], rebuilt["cmds"][0],
              "bootstrap-plan Perl: cleans generated native artifacts before rebuild")

# A Module::Build distribution has no Makefile.PL; its Build.PL drives the build.
with tempfile.TemporaryDirectory() as td:
    root = Path(td)
    (root / "Build.PL").write_text("# sample\n")
    (root / "lib").mkdir()
    (root / "lib" / "Sample.pm").write_text("package Sample; 1;\n")
    plan = languages.bootstrap_plan_for_target(root, "perl")
    assert_eq(4, len(plan["cmds"]),
              "bootstrap-plan Perl Build.PL: installs dependencies, builds, and installs")
    assert_in("--installdeps", plan["cmds"][0],
              "bootstrap-plan Perl Build.PL: resolves declared CPAN dependencies")
    assert_in("Build.PL", plan["cmds"][1],
              "bootstrap-plan Perl Build.PL: configures through Build.PL")
    assert_eq(["./Build"], plan["cmds"][2], "bootstrap-plan Perl Build.PL: runs ./Build")
    assert_eq(["./Build", "install"], plan["cmds"][3],
              "bootstrap-plan Perl Build.PL: installs into the local library")

with tempfile.TemporaryDirectory() as td:
    root = Path(td)
    (root / "dist.ini").write_text("name = Sample\nversion = 1\n")
    with mock.patch.object(
        languages, "preferred_perl_toolchain", return_value=("perl", "cpanm"),
    ), mock.patch.object(
        languages, "perl_local_lib_root", return_value=".audit/perl5",
    ):
        plan = languages.bootstrap_plan_for_target(root, "perl")
    assert_eq("Dist::Zilla", plan["cmds"][0][-1],
              "bootstrap-plan Perl: author checkout installs its declared build tool")
    assert_in("authordeps", plan["module_queries"][0]["cmd"],
              "bootstrap-plan Perl: asks Dist::Zilla for author dependencies")
    assert_in("--cpanm-versions", plan["module_queries"][0]["cmd"],
              "bootstrap-plan Perl: requests cpanm's structured requirement format")
    assert_eq(".audit/perl-dist", plan["post_cmds"][0][-1],
              "bootstrap-plan Perl: materializes a release tree before installation")

with tempfile.TemporaryDirectory() as td:
    (Path(td) / "setup.py").write_text("# x\n")
    out, _, _ = run(CLI + ["bootstrap-plan", "python", td])
    plan = json.loads(out)
    env_keys = [pair[0] for pair in plan["env"]]
    assert_in("CFLAGS", env_keys,
              "bootstrap-plan python: env includes CFLAGS")
    cflags = dict(plan["env"]).get("CFLAGS", "")
    assert_in("DNDEBUG", cflags,
              "bootstrap-plan python: CFLAGS carries -DNDEBUG (release mode)")
    assert_in("O2", cflags,
              "bootstrap-plan python: CFLAGS carries -O2 (release optimisation)")

# The setup-target executor runs argv directly, falls back only on the final
# command, persists the successful recipe, and records complete output.
with tempfile.TemporaryDirectory() as td:
    target_root = Path(td)
    log_path = target_root / ".audit" / "bootstrap.log"
    recipe_path = target_root / ".audit" / "bootstrap.sh"
    log_path.parent.mkdir()
    log_path.write_text("stale-error-from-prior-setup\n")
    plan = {
        "cmds": [
            [sys.executable, "-c", "print('first-ok')"],
            [sys.executable, "-c", "print('primary-failed'); raise SystemExit(7)"],
        ],
        "alternatives": [
            [sys.executable, "-c", "import os; print(os.environ['SETUP_SENTINEL'])"],
        ],
        "post_cmds": [
            [sys.executable, "-c",
             "import os; assert 'REMOVE_SENTINEL' not in os.environ; print('post-ok')"],
        ],
        "env": [["SETUP_SENTINEL", "fallback ok"],
                ["ROOT_SENTINEL", "{TARGET_ROOT}/deps"]],
        "unset_env": ["REMOVE_SENTINEL"],
    }
    with mock.patch.dict(os.environ, {"REMOVE_SENTINEL": "host-value"}):
        rc = languages.execute_bootstrap_plan(
            target_root, plan, log_path, recipe_path,
        )
    assert_eq(0, rc, "bootstrap executor: successful final alternative returns zero")
    log_text = log_path.read_text()
    assert_in("first-ok", log_text, "bootstrap executor: logs successful command output")
    assert_in("primary-failed", log_text, "bootstrap executor: logs failed command output")
    assert_in("fallback ok", log_text, "bootstrap executor: applies plan environment")
    assert_in("post-ok", log_text,
              "bootstrap executor: runs post-install commands after fallback")
    assert_true("stale-error-from-prior-setup" not in log_text,
                "bootstrap executor: log describes only the current setup")
    assert_in(str(target_root / "deps"), recipe_path.read_text(),
              "bootstrap executor: materializes target-root placeholders")
    recipe_text = recipe_path.read_text()
    assert_in("export SETUP_SENTINEL='fallback ok'", recipe_text,
              "bootstrap executor: quotes environment in recipe")
    assert_in("first-ok", recipe_text,
              "bootstrap executor: recipe retains successful preceding command")
    assert_in("SETUP_SENTINEL", recipe_text,
              "bootstrap executor: recipe records successful alternative")
    assert_in("post-ok", recipe_text,
              "bootstrap executor: recipe records successful post-install command")
    assert_in("unset REMOVE_SENTINEL", recipe_text,
              "bootstrap executor: recipe records removed host policy")
    assert_eq(True, bool(recipe_path.stat().st_mode & 0o111),
              "bootstrap executor: recipe is executable")
    failed_plan = {
        "cmds": [[sys.executable, "-c",
                  "print('current-failure'); raise SystemExit(9)"]],
        "alternatives": [], "post_cmds": [], "env": [],
    }
    rc = languages.execute_bootstrap_plan(
        target_root, failed_plan, log_path, recipe_path,
    )
    assert_eq(9, rc, "bootstrap executor: reports a failed new attempt")
    assert_true(not recipe_path.exists(),
                "bootstrap executor: failed attempt removes stale recipe")
    assert_in("current-failure", log_path.read_text(),
              "bootstrap executor: failed attempt keeps its diagnostic")
    assert_true("first-ok" not in log_path.read_text(),
                "bootstrap executor: failed attempt replaces the prior log")

# Failed JS package-manager attempts must not poison the next manager with a
# partial node_modules tree or a lockfile the failed attempt generated.
with tempfile.TemporaryDirectory() as td:
    target_root = Path(td)
    audit = target_root / ".audit"
    audit.mkdir()
    package_lock = target_root / "package-lock.json"
    package_lock.write_text("tracked\n")
    failed = (
        "from pathlib import Path; "
        "Path('node_modules/partial').mkdir(parents=True); "
        "Path('pnpm-lock.yaml').write_text('generated'); "
        "Path('package-lock.json').write_text('changed'); "
        "raise SystemExit(7)"
    )
    fallback = (
        "from pathlib import Path; "
        "assert not Path('node_modules').exists(); "
        "assert not Path('pnpm-lock.yaml').exists(); "
        "assert Path('package-lock.json').read_text() == 'tracked\\n'"
    )
    plan = {
        "language": "javascript",
        "cmds": [[sys.executable, "-c", failed]],
        "alternatives": [[sys.executable, "-c", fallback]],
        "post_cmds": [], "env": [],
    }
    rc = languages.execute_bootstrap_plan(
        target_root, plan, audit / "bootstrap.log", audit / "bootstrap.sh",
    )
    assert_eq(0, rc, "js bootstrap: clean fallback succeeds after failed manager")
    assert_true(not (target_root / "node_modules").exists(),
                "js bootstrap: failed manager's partial install is removed")
    assert_true(not (target_root / "pnpm-lock.yaml").exists(),
                "js bootstrap: failed manager's generated lock is removed")
    assert_eq("tracked\n", package_lock.read_text(),
              "js bootstrap: failed manager's tracked lock change is restored")

# A node_modules that existed before the attempt is not the failed manager's
# to delete: a vendored tree or an earlier good install must survive.
with tempfile.TemporaryDirectory() as td:
    target_root = Path(td)
    audit = target_root / ".audit"
    audit.mkdir()
    vendored = target_root / "node_modules" / "leftpad"
    vendored.mkdir(parents=True)
    (vendored / "index.js").write_text("module.exports = 1;\n")
    plan = {
        "language": "javascript",
        "cmds": [[sys.executable, "-c", "raise SystemExit(7)"]],
        "alternatives": [[sys.executable, "-c", "pass"]],
        "post_cmds": [], "env": [],
    }
    rc = languages.execute_bootstrap_plan(
        target_root, plan, audit / "bootstrap.log", audit / "bootstrap.sh",
    )
    assert_eq(0, rc, "js bootstrap: fallback succeeds after failed manager")
    assert_true((vendored / "index.js").is_file(),
                "js bootstrap: a pre-existing node_modules survives a failed manager")

# A CPAN repository checkout can need configure prerequisites before cpanm can
# execute Makefile.PL and discover the rest.  The executor uses cpanm's own
# diagnostic to install exactly those modules, then retries the unchanged
# dependency command and records a reproducible recipe.
with tempfile.TemporaryDirectory() as td:
    target_root = Path(td)
    fake_bin = target_root / "bin"
    fake_bin.mkdir()
    fake_cpanm = fake_bin / "cpanm"
    fake_cpanm.write_text(
        "#!/bin/sh\n"
        "case \" $* \" in\n"
        "  *' Sample::Configure '*) touch .configured; exit 0 ;;\n"
        "esac\n"
        "if [ ! -f .configured ]; then\n"
        "  echo 'Configuring sample ... Warning: prerequisite Sample::Configure 1.0 not found.'\n"
        "  echo \"Can't locate Sample/Bootstrap.pm in @INC at Makefile.PL line 4.\"\n"
        "  exit 1\n"
        "fi\n"
        "echo dependencies-ready\n"
    )
    fake_cpanm.chmod(0o755)
    log_path = target_root / ".audit" / "bootstrap.log"
    recipe_path = target_root / ".audit" / "bootstrap.sh"
    plan = {
        "cmds": [[str(fake_cpanm), "--local-lib-contained", ".audit/perl5",
                  "--installdeps", "."]],
        "alternatives": [], "post_cmds": [], "env": [],
    }
    rc = languages.execute_bootstrap_plan(target_root, plan, log_path, recipe_path)
    assert_eq(0, rc, "bootstrap executor: repairs CPAN configure dependency cycle")
    assert_in("dependencies-ready", log_path.read_text(),
              "bootstrap executor: retries dependency discovery after repair")
    assert_in("Sample::Configure", recipe_path.read_text(),
              "bootstrap executor: records the cpanm prerequisite repair")
    assert_in("Sample::Bootstrap", recipe_path.read_text(),
              "bootstrap executor: repairs Makefile.PL import prerequisites")

# cpanm identifies repository transfer failures explicitly. The executor gives
# the unchanged command one clean retry so a partial dependency graph can
# resume from the target-local cache.
with tempfile.TemporaryDirectory() as td:
    target_root = Path(td)
    fake_cpanm = target_root / "cpanm"
    fake_cpanm.write_text(
        "#!/bin/sh\n"
        "if [ ! -f .downloaded ]; then\n"
        "  touch .downloaded\n"
        "  echo '! Download https://cpan.example/Sample.tar.gz failed'\n"
        "  exit 1\n"
        "fi\n"
        "echo download-ready\n"
    )
    fake_cpanm.chmod(0o755)
    audit = target_root / ".audit"
    plan = {
        "cmds": [[str(fake_cpanm), "Sample"]],
        "alternatives": [], "post_cmds": [], "env": [],
    }
    rc = languages.execute_bootstrap_plan(
        target_root, plan, audit / "bootstrap.log", audit / "bootstrap.sh",
    )
    assert_eq(0, rc, "bootstrap executor: retries a reported CPAN transfer failure")
    assert_in("download-ready", (audit / "bootstrap.log").read_text(),
              "bootstrap executor: resumed cpanm after the transfer retry")

# Structured dependency queries let author-oriented build tools report their
# own missing modules without parsing a target-specific manifest.
with tempfile.TemporaryDirectory() as td:
    target_root = Path(td)
    audit = target_root / ".audit"
    audit.mkdir()
    generated = audit / "generated-release"
    generated.mkdir()
    (generated / "stale").write_text("old")
    installed = audit / "installed"
    installer = (
        "from pathlib import Path; import sys; "
        f"Path({str(installed)!r}).write_text(' '.join(sys.argv[1:]))"
    )
    plan = {
        "cmds": [], "alternatives": [], "post_cmds": [], "env": [],
        "unset_env": [],
        "module_queries": [{
            "cmd": [sys.executable, "-c", "print('Sample::Plugin~>= 1.2, < 2')"],
            "install_prefix": [sys.executable, "-c", installer],
        }],
        "clean_dirs": [".audit/generated-release"],
    }
    rc = languages.execute_bootstrap_plan(
        target_root, plan, audit / "bootstrap.log", audit / "bootstrap.sh",
    )
    assert_eq(0, rc, "bootstrap executor: installs build-tool-reported modules")
    assert_eq("Sample::Plugin~>= 1.2, < 2", installed.read_text(),
              "bootstrap executor: preserves the build tool's version requirement")
    assert_in("Sample::Plugin~>= 1.2, < 2", (audit / "bootstrap.sh").read_text(),
              "bootstrap executor: records resolved build dependencies")
    assert_true(not generated.exists(),
                "bootstrap executor: removes a stale generated release tree")

# fuzz-backends CLI returns the maintained toolchains per build_system.
out, _, _ = run(CLI + ["fuzz-backends", "python"])
assert_in("atheris", out, "fuzz-backends python -> atheris")
out, _, _ = run(CLI + ["fuzz-backends", "cmake"])
assert_in("asan", out, "fuzz-backends cmake -> asan")
out, _, _ = run(CLI + ["fuzz-backends", "maven"])
assert_in("jazzer", out, "fuzz-backends maven -> jazzer")
out, _, _ = run(CLI + ["fuzz-backends", "composer"])
assert_eq("\n", out,
          "fuzz-backends composer -> empty (no maintained toolchain)")

# list command runs and prints all required languages.
out, _, _ = run(CLI + ["list"])
for required in REQUIRED_LANGUAGES:
    assert_in(required, out, f"CLI list contains {required}")


# ─── 11. Cross-silo invariant: no consumer hardcodes a divergent list ─

# The whole point of this refactor: every consumer must derive its
# extension set from the registry. We re-import the consumers, ask
# them for their list, and compare against the registry's helper.
# A failure here means a future contributor silently re-introduced a
# silo. Update the registry, not the consumer.
assert_eq(set(languages.all_source_exts()), set(workqueue.SOURCE_EXTS),
          "invariant: workqueue.SOURCE_EXTS == registry.all_source_exts()")

# crash_artifacts derives from C+C++ harness exts (lowercased + deduped).
expected_chc_set = set()
for n in ("c", "cpp"):
    lang = languages.for_name(n)
    if lang:
        for e in lang.harness_exts:
            expected_chc_set.add(e.lower())
assert_eq(expected_chc_set, set(crash_artifacts._HARNESS_SOURCE_SUFFIXES),
          "invariant: crash_artifacts harness suffixes derive from C+C++ registry entries")


# ─── 12. stale_python_extensions: ABI mismatch detection ──────────

# Detection is keyed on sys.implementation.cache_tag of the running
# interpreter. We synthesize a fake target tree with .so files that
# either match (=current tag) or mismatch (a deliberately-wrong tag),
# and verify the helper picks the right ones — independent of which
# Python version actually runs this test.
def _fake_cp_so(tmp: Path, rel: str, tag: str) -> Path:
    p = tmp / f"{rel}.{tag}-darwin.so"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(b"")
    return p


active = sys.implementation.cache_tag  # e.g. "cpython-314"
# Pick a wrong tag that's structurally valid but cannot equal the active
# tag (active is "cpython-NN"; "cpython-9999" is safe across versions).
wrong = "cpython-9999"
assert_true(active != wrong, "test sentinel differs from the running interpreter tag")

with tempfile.TemporaryDirectory() as td:
    root = Path(td)
    # Case A: a target that ONLY ships the wrong-ABI .so → flagged.
    _fake_cp_so(root, "pkg_a/_extA", wrong)
    # Case B: a target with both ABIs side-by-side (pillow shape) → clean.
    _fake_cp_so(root, "pkg_b/_extB", wrong)
    _fake_cp_so(root, "pkg_b/_extB", active)
    # Case C: untagged .so (libfoo.so) → ignored.
    (root / "libfoo.so").write_bytes(b"")
    # Case D: stale artifact under build/ → ignored (transient build output).
    _fake_cp_so(root / "build", "stale/_extD", wrong)

    stale = languages.stale_python_extensions(root)

    names = sorted(p.name for p in stale)
    assert_eq([f"_extA.{wrong}-darwin.so"], names,
              "stale_python_extensions: flags wrong-ABI .so when no active sibling")
    paths = {str(p) for p in stale}
    siblings = [p for p in paths if "pkg_b" in p]
    assert_eq([], siblings,
              "stale_python_extensions: ignores wrong-ABI .so when active sibling exists")
    libfoos = [p for p in paths if p.endswith("libfoo.so")]
    assert_eq([], libfoos,
              "stale_python_extensions: ignores untagged libfoo.so")
    build_artifacts = [p for p in paths if "/build/" in p]
    assert_eq([], build_artifacts,
              "stale_python_extensions: ignores transient build/ output")

# Empty / missing target_root must not raise.
assert_eq([], languages.stale_python_extensions(Path("/nonexistent/xyz")),
          "stale_python_extensions: missing target_root returns empty list")

# CLI surface emits one path per line.
with tempfile.TemporaryDirectory() as td:
    root = Path(td)
    _fake_cp_so(root, "x/_only", wrong)
    cli = subprocess.run(
        [sys.executable, str(ROOT / "lib/languages.py"),
         "stale-python-extensions", str(root)],
        capture_output=True, text=True, check=True,
    )
    cli_lines = [l for l in cli.stdout.splitlines() if l.strip()]
    assert_eq(1, len(cli_lines), "CLI stale-python-extensions: one line per stale file")
    assert_eq(True, cli_lines[0].endswith(f"_only.{wrong}-darwin.so"),
              "CLI stale-python-extensions: emits absolute path")


# all_crash_patterns unions every Language's crash_patterns (deduped) so
# consumers stay generic across every sanitizer/runtime the registry knows.
_crash_pats = languages.all_crash_patterns()
assert_eq(True, len(_crash_pats) > 0, "all_crash_patterns: non-empty")
assert_eq(len(_crash_pats), len(set(_crash_pats)), "all_crash_patterns: deduped")
assert_eq(True, any("AddressSanitizer" in p for p in _crash_pats),
          "all_crash_patterns: includes the ASan banner")
assert_eq(True, any("ThreadSanitizer" in p for p in _crash_pats),
          "all_crash_patterns: includes the TSan banner")


# ─── sanitizer_env debug-info flag ─────────────────────────────────
# Any debug flag a language injects for its (C/C++) sanitizer build must be
# -g1 (line tables only), never full -g: line tables suffice for symbolized
# crash stacks (function + file:line) and keep symbolization cheap, which is
# what the macOS report-truncation fix relies on. -g1 is portable across clang
# and gcc.
for _lang in languages.LANGUAGES:
    for _key, _val in _lang.sanitizer_env:
        if _key not in ("CFLAGS", "CXXFLAGS"):
            continue
        _toks = _val.split()
        assert_eq(False, "-g" in _toks,
                  f"{_lang.name} {_key}: no bare -g (full DWARF)")
        if any(t.startswith("-g") for t in _toks):
            assert_in("-g1", _val,
                      f"{_lang.name} {_key}: debug info is -g1 (line tables only)")


# ─── Bootstrap snapshot staleness ──────────────────────────────────
# An R package library is a copy of the source; the stamp says which source.
import tempfile as _tempfile
with _tempfile.TemporaryDirectory(prefix="bootstrap-stamp-") as _name:
    _root = Path(_name)
    (_root / "DESCRIPTION").write_text("Package: sampleproj\n")
    (_root / "R").mkdir()
    (_root / "R" / "parse.R").write_text("parse <- function(x) x\n")
    assert_eq(True, languages.bootstrap_snapshot_stale(_root), "no stamp: stale")
    languages.write_bootstrap_stamp(_root)
    assert_eq(False, languages.bootstrap_snapshot_stale(_root), "stamped: fresh")
    (_root / "R" / "parse.R").write_text("parse <- function(x) x + 1\n")
    assert_eq(True, languages.bootstrap_snapshot_stale(_root), "source moved: stale")
    assert_eq(True, next(l for l in languages.LANGUAGES if l.name == "r").bootstrap_snapshot,
              "R bootstrap is a snapshot")


# ─── Summary ───────────────────────────────────────────────────────

print()
print(f"  {_PASSED} passed, {_FAILED} failed")
sys.exit(0 if _FAILED == 0 else 1)
