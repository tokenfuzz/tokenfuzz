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

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "lib"))
import languages
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
assert_eq("java", languages.for_build_system("maven").name,
          "for_build_system: maven -> java")
assert_eq("java", languages.for_build_system("gradle").name,
          "for_build_system: gradle -> java")
assert_eq("kotlin", languages.for_build_system("kotlin").name,
          "for_build_system: kotlin -> kotlin")
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
    assert_eq(1, len(cmds), "bootstrap: rust with Cargo.toml -> 1 command")
    assert_in("cargo", cmds[0], "bootstrap: rust command starts with cargo")
    assert_in("--release", cmds[0],
              "bootstrap: rust uses release mode (no debug-assertions noise)")
    assert_in("--locked", cmds[0],
              "bootstrap: rust primary uses --locked for reproducibility")
    rust_plan = languages.bootstrap_plan_for_target(tmp_root, "cargo")
    assert_eq(1, len(rust_plan["alternatives"]),
              "bootstrap: rust has 1 fallback (drops --locked)")
    assert_true("--locked" not in rust_plan["alternatives"][0],
                "bootstrap: rust fallback drops --locked (drift recovery)")
    (tmp_root / "Cargo.toml").unlink()

    # go.mod -> go bootstrap with -race (Go's maintained sanitizer).
    (tmp_root / "go.mod").write_text("module x\n")
    cmds = languages.bootstrap_for_target(tmp_root, "go")
    assert_eq(1, len(cmds), "bootstrap: go with go.mod -> 1 command")
    assert_in("-race", cmds[0],
              "bootstrap: go enables -race data-race detector")
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
    plan = {
        "cmds": [
            [sys.executable, "-c", "print('first-ok')"],
            [sys.executable, "-c", "print('primary-failed'); raise SystemExit(7)"],
        ],
        "alternatives": [
            [sys.executable, "-c", "import os; print(os.environ['SETUP_SENTINEL'])"],
        ],
        "env": [["SETUP_SENTINEL", "fallback ok"]],
    }
    rc = languages.execute_bootstrap_plan(target_root, plan, log_path, recipe_path)
    assert_eq(0, rc, "bootstrap executor: successful final alternative returns zero")
    log_text = log_path.read_text()
    assert_in("first-ok", log_text, "bootstrap executor: logs successful command output")
    assert_in("primary-failed", log_text, "bootstrap executor: logs failed command output")
    assert_in("fallback ok", log_text, "bootstrap executor: applies plan environment")
    recipe_text = recipe_path.read_text()
    assert_in("export SETUP_SENTINEL='fallback ok'", recipe_text,
              "bootstrap executor: quotes environment in recipe")
    assert_in("first-ok", recipe_text,
              "bootstrap executor: recipe retains successful preceding command")
    assert_in("SETUP_SENTINEL", recipe_text,
              "bootstrap executor: recipe records successful alternative")
    assert_eq(True, bool(recipe_path.stat().st_mode & 0o111),
              "bootstrap executor: recipe is executable")

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


# ─── Summary ───────────────────────────────────────────────────────

print()
print(f"  {_PASSED} passed, {_FAILED} failed")
sys.exit(0 if _FAILED == 0 else 1)
