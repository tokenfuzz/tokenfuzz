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
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

import languages
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
    if list(config.runner_args) != list(language.runner_args):
        return "[runner].args no longer match the registry's own invocation"
    if language.name == "rust" and not target_config.cargo_root_has_library(
        config.target_root,
    ):
        return "the root Cargo package exposes no library to depend on"
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
        str(results), str(results), str(Path(config.target_root).resolve()),
        slug, getattr(config, "target_rev", "") or "", str(tree / "logs"),
    )
    canary = scratch / f"canary{canary_suffix(language)}"
    canary.write_text(language.canary_source, encoding="utf-8")
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
    # A search path that does not exist proves nothing: the runtime skips it
    # and resolves the installed copy, which is the failure this checks for.
    path = Path(candidate)
    if not path.is_dir():
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
        try:
            completed = subprocess.run(
                [str(ROOT / "bin" / "probe"), str(canary)],
                capture_output=True, text=True, check=False,
                timeout=timeout, env=environment,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            return f"the canary testcase could not be run: {exc}"
        report = canary.with_suffix(".asan.txt")
        output = report.read_text(errors="replace") if report.is_file() else ""
        failures = _reasons(config, output + completed.stdout + completed.stderr)
        if completed.returncode:
            failures.append(f"bin/probe exited {completed.returncode}")
    if not failures:
        return ""
    return "; ".join(failures)
