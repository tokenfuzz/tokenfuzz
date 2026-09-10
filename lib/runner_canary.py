"""Prove a seeded language configuration can reach the audited tree.

`bin/setup-target` writes `[runner]` from the registry in lib/languages.py, and
until this check nothing executed what it wrote. `runner_preflight.validate()`
runs the interpreter's `--version`, which proves a runtime starts, not that a
testcase reaches the target: a Perl probe resolved the system copy of a module
instead of the checkout and reported CLEAN against code that was never audited,
and the only signal was a real audit spending its wall to find out.

The canary is one testcase in the target's own language, run through `bin/probe`
so it takes the route an agent's testcase takes. It asserts exactly what it
prints, so a language claims only what it can show:

* nothing at all -- the route still executed, which is what a Cargo library
  target needs, since its canary only links if the audited crate resolved;
* ``cwd=`` -- the configured runner executed from TARGET_ROOT, the contract a
  module resolver that reads the current directory depends on;
* ``path=`` -- the runtime searches somewhere inside TARGET_ROOT, so an import
  reaches the checkout rather than an installed copy of the same name.

Whatever it prints, the harness must also have *counted* the run: a canary whose
marker reached the transcript while EXECUTION_RATE stayed 0 is a probe that will
report NO_EXEC for every real testcase too.

It runs in a throwaway tree so a live audit's results directory is untouched,
and it stays quiet -- returning no reason -- whenever it cannot make one of
those claims: the target has taken the invocation over, or the language's own
canary cannot bind to the audited tree. Passing on evidence it never had would
be worse than not looking.
"""

from __future__ import annotations

import os
import json
import re
import shutil
import tempfile
from pathlib import Path

import languages
from timeout import run_timeout
import target_config

ROOT = Path(__file__).resolve().parent.parent
MARKER = "TOKENFUZZ-CANARY"


def canary_suffix(language) -> str:
    """The extension the language's own runner executes as source."""
    if language.script_exts:
        return language.script_exts[0]
    return language.source_exts[0] if language.source_exts else ""


def runner_sanitizer(config) -> str:
    """An enabled route that still executes through [runner], or ""."""
    if config.sanitizers_explicitly_disabled:
        return "runner"
    for name in config.sanitizers_enabled:
        if not config.sanitizer_bin(name):
            return name
    return ""


def skip_reason(config) -> str:
    """Why this target cannot be canary-checked, or "" when it can be."""
    language = languages.for_build_system(getattr(config, "build_system", ""))
    if language is None or not language.canary_source:
        return "the language registry has no canary for this build system"
    if not config.runner_bin:
        return "no [runner].bin is configured"
    if Path(str(config.runner_bin)).name != language.runner_bin:
        return f"[runner].bin is not the registry's {language.runner_bin}"
    expected_args = list(language.runner_args)
    if language.name == "java":
        expected_args = list(languages.java_runner_args(
            config.target_root, config.build_system,
        ))
    if language.name == "rust":
        try:
            expected_args = list(languages.cargo_runner_args(
                config.target_root, config.slug,
            ))
        except ValueError as exc:
            return str(exc)
    if language.name == "swift":
        try:
            info = languages.swift_package_info(config.target_root)
            expected_args = list(
                languages.swift_runner_args(config.target_root, config.slug)
            )
        except ValueError as exc:
            return str(exc)
        if "--skip-build" in expected_args:
            return "the Swift executable owns its input and cannot print the source canary"
        if not info.library_products:
            return "the Swift package exposes no library product for a source canary"
    if list(config.runner_args) != expected_args:
        return "[runner].args no longer match the registry's own invocation"
    if language.name == "rust" and not target_config.cargo_workspace_has_library(
        config.target_root,
    ):
        return "the Cargo workspace exposes no library to depend on"
    # Stand aside only when every enabled route has its own binary. In a mixed
    # configuration, the runner still needs proving on the sanitizer it owns.
    if not runner_sanitizer(config):
        return "configured sanitizer binaries own every enabled route"
    return ""


def _stage(config, language, tree: Path) -> Path:
    """Lay out the throwaway session `bin/probe` discovers its config from."""
    slug = config.slug or "canary"
    results = tree / "output" / slug / "canary" / "results"
    scratch = results / "scratch-1"
    scratch.mkdir(parents=True)
    (tree / "logs").mkdir()
    source = Path(getattr(config, "source_path", ""))
    if not source.is_file() and config.results_dir:
        source = Path(config.results_dir).resolve().parent.parent / "target.toml"
    if source.is_file():
        shutil.copy2(source, tree / "output" / slug / "target.toml")
    # Every tool below bin/probe rediscovers the session from this file, so a
    # canary run without one is not the route an agent's testcase takes.
    target_config.write_session_env(
        str(results), str(results), str(Path(
            config.checkout_root or config.target_root
        ).resolve()),
        slug, getattr(config, "target_rev", "") or "", str(tree / "logs"),
    )
    canary = scratch / f"canary{canary_suffix(language)}"
    source = language.canary_source
    if language.name == "rust":
        info = languages.cargo_workspace_info(config.target_root)
        library = languages.preferred_cargo_libraries(info)[0]
        source = f"use {library.crate} as _;\n{source}"
    if language.name == "swift":
        info = languages.swift_package_info(config.target_root)
        module = info.library_products[0][1][0]
        source = f"import {module}\n{source}"
    if language.name == "java":
        classes = languages.java_canary_classes(
            config.target_root, config.build_system,
        )
        quoted = ", ".join(json.dumps(name) for name in classes)
        source = f"""public class Canary {{
    public static void main(String[] args) {{
        String[] names = new String[] {{{quoted}}};
        for (String name : names) {{
            try {{
                Class<?> type = Class.forName(name, false, Canary.class.getClassLoader());
                java.security.CodeSource origin = type.getProtectionDomain().getCodeSource();
                if (origin != null) {{
                    String path = new java.io.File(origin.getLocation().toURI()).getCanonicalPath();
                    System.out.println("{MARKER} path=" + path);
                    return;
                }}
            }} catch (Throwable ignored) {{}}
        }}
    }}
}}
"""
    if language.name == "ruby":
        gemspecs = list(Path(config.target_root).glob("*.gemspec"))
        package = (
            languages.ruby_package_info(config.target_root)
            if len(gemspecs) == 1 else None
        )
        if package and package.entrypoint:
            entrypoint = json.dumps(package.entrypoint)
            expected = json.dumps(package.entrypoint_path)
            source = f'''require {entrypoint}
expected = File.realpath({expected})
loaded = $LOADED_FEATURES.find {{ |path|
  File.file?(path) && File.realpath(path) == expected
}}
abort "audited gem entrypoint was not loaded" unless loaded
print "{MARKER} path=#{{loaded}}"
'''
    if language.name == "perl":
        module = languages.perl_canary_module(config.target_root)
        if module:
            quoted = json.dumps(module)
            source = f'''use strict;
use warnings;
use Cwd ();
my $module = {quoted};
require $module;
my $package = $module;
$package =~ s{{/}}{{::}}g;
$package =~ s{{\\.pm$}}{{}};
$package->import() if $package->can("import");
print "{MARKER} path=" . Cwd::abs_path($INC{{$module}});
'''
    canary.write_text(source, encoding="utf-8")
    return canary


def _reasons(config, output: str) -> list[str]:
    """Every claim the canary's own output failed to back up."""
    target_root = Path(config.target_root).resolve()
    lines = [
        line[len(MARKER) + 1:]
        for line in output.splitlines()
        if line.startswith(MARKER + " ")
    ]
    if not lines:
        return [f"the canary never printed {MARKER}; the route does not execute"]
    failures = []
    # The canary printing is not the same as the harness seeing it run: a
    # status marker that lands mid-line is not counted, and every downstream
    # verdict reads the rate rather than the output.
    rate = re.search(r"EXECUTION_RATE: (\d+)/(\d+)", output)
    if rate is None:
        failures.append("the harness did not report an EXECUTION_RATE")
    elif rate.group(1) == "0":
        failures.append(
            f"the canary printed {MARKER} but the harness recorded "
            f"EXECUTION_RATE {rate.group(0).split(': ')[1]}, so a run that "
            "reached the target reads as never executed"
        )
    for claim in ("cwd", "path"):
        values = [v[len(claim) + 1:] for v in lines if v.startswith(claim + "=")]
        if not values:
            continue
        inside = [v for v in values if _under(target_root, v)]
        if claim == "cwd" and not inside:
            failures.append(
                f"the runner executed in {values[0]}, not the target root "
                f"{target_root}; a resolver that reads the working directory "
                "cannot find the audited package"
            )
        if claim == "path" and not inside:
            # Name what the runtime did search: the fix is an import path in
            # [runner].env, and the operator needs to see the shape it takes.
            sample = ", ".join(values[:3]) + (" ..." if len(values) > 3 else "")
            failures.append(
                f"none of the {len(values)} runtime search paths is inside "
                f"{target_root}, so an import resolves an installed copy "
                f"instead of the audited checkout (searched: {sample})"
            )
    return failures


def _under(root: Path, candidate: str) -> bool:
    # A reported import directory or the concrete module file it supplied is
    # proof only when that object exists. A missing path can be skipped by the
    # runtime before it resolves an installed copy.
    path = Path(candidate)
    if not path.exists():
        return False
    try:
        path.resolve().relative_to(root)
    except (OSError, ValueError):
        return False
    return True


def check(config, timeout: int = 300) -> str:
    """Return "" when a testcase reaches the target, else why it does not."""
    reason = skip_reason(config)
    if reason:
        return ""
    language = languages.for_build_system(config.build_system)
    with tempfile.TemporaryDirectory(prefix="runner-canary-") as name:
        tree = Path(name)
        canary = _stage(config, language, tree)
        environment = os.environ.copy()
        environment.update({
            "RESULTS_DIR": str(canary.parent.parent),
            "TARGET_ROOT": str(Path(config.target_root).resolve()),
            "TARGET_SLUG": config.slug or "canary",
            "LOGDIR": str(tree / "logs"),
            "PROBE_SANITIZER": runner_sanitizer(config),
        })
        # Through the process-tree wrapper: a plain deadline killed bin/probe
        # alone and left the harness build it started running in a directory
        # that is deleted on exit.
        try:
            completed = run_timeout(
                [str(ROOT / "bin" / "probe"), str(canary)], timeout,
                kill=True, capture_output=True, text=True, env=environment,
            )
        except OSError as exc:
            return f"the canary testcase could not be run: {exc}"
        if completed.returncode == 124:
            return f"the canary testcase did not finish within {timeout}s"
        report = canary.with_suffix(".asan.txt")
        output = report.read_text(errors="replace") if report.is_file() else ""
        combined = output + completed.stdout + completed.stderr
        failures = _reasons(config, combined)
        if completed.returncode:
            failures.append(f"bin/probe exited {completed.returncode}")
            noise = (
                "[run-", "[probe]", "===", "CRASH_RATE:",
                "SANITIZER_RUN_HEADER:",
            )
            detail = [
                line.strip() for line in combined.splitlines()
                if line.strip() and not line.lstrip().startswith(noise)
            ]
            if detail:
                failures.append(
                    "last output: "
                    + " | ".join(line[:300] for line in detail[-3:])
                )
    if not failures:
        return ""
    return "; ".join(failures)
