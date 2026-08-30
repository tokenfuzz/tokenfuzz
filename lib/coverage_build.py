#!/usr/bin/env python3
"""The SanitizerCoverage sibling of a sanitizer build: build it, find it, prove it.

`build-<san>` is what every recorded probe was measured against, so it is never
rebuilt with different flags. Execution coverage needs the same recipe compiled
with SanitizerCoverage, and that lives in a sibling tree, `build-<san>+fuzz`:
a name target_config already prunes from build freshness, a name the build
lease keys on its own, the tree `bin/fuzz` links campaigns against and the one
`bin/hits` replays native testcases in. One sibling serves both.

The sibling is produced by the target's own canonical recipe, run with CC and
CXX pointed at a shim that adds the coverage flags and hands off to the LLVM
toolchain that ships libFuzzer. Recipes honour CC/CXX by contract (the
generated ones spell `${CC:-clang}`); one that does not yields a tree without
guards, which verification reports and `bin/hits` then declines to select, so
coverage reads unavailable rather than measuring the wrong binary.
"""

from __future__ import annotations

import hashlib
import os
import shlex
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Callable

import build_config
import build_materialize
import fuzz_harness
import runner_preflight
import target_config

COVERAGE_SUFFIX = fuzz_harness.COVERAGE_TREE_SUFFIX
# `+cov` is the accepted name for a sibling an operator built by hand.
ACCEPTED_SUFFIXES = (COVERAGE_SUFFIX, "+cov")
_SHIM_DIR = Path(".audit") / "coverage-toolchain"
_FLAGS_CACHE: dict[str, list[str]] = {}


def tree_name(san: str = "asan", *, suffix: "str | None" = None) -> str:
    """Directory name of the coverage sibling, honouring AUDIT_BUILD_SUFFIX."""
    return target_config.build_dir_name(san, suffix=suffix) + COVERAGE_SUFFIX


def sibling_path(config, raw: str, san: str, sibling_suffix: str) -> "Path | None":
    """The configured artifact's twin inside ``build-<san>…<sibling_suffix>``.

    None when nothing is configured or the artifact does not live under the
    sanitizer build — an external executable has no sibling to instrument.
    """
    if not raw or "FILL_ME" in raw:
        return None
    plain = str(Path(config.resolve_path(raw)))
    marker = f"/{target_config.build_dir_name(san)}/"
    if marker not in plain:
        return None
    return Path(plain.replace(marker, marker[:-1] + sibling_suffix + "/", 1))


def sancov_section_present(binary: Path) -> "tuple[bool, str]":
    """Whether a binary carries the trace-pc-guard ``__sancov_guards`` section.

    Returns (present, diagnostic). A tool failure is (False, why) so callers
    can either raise (verify) or simply not select the sibling (resolution).
    """
    if sys.platform == "darwin":
        command = ["otool", "-l", str(binary)]
        needle = "sectname __sancov_guards"
    else:
        tool = (shutil.which("readelf") or shutil.which("llvm-readelf")
                or shutil.which("objdump"))
        if not tool:
            return False, (
                f"cannot inspect ELF sections ({binary}): install binutils or "
                "LLVM tools"
            )
        name = Path(tool).name
        flag = "-WS" if name == "readelf" else "-S" if name == "llvm-readelf" else "-h"
        command = [tool, flag, str(binary)]
        needle = "__sancov_guards"
    completed = subprocess.run(command, capture_output=True, text=True, check=False)
    output = completed.stdout + completed.stderr
    if completed.returncode:
        return False, (
            f"{Path(command[0]).name} failed on {binary}: {output or '<no output>'}"
        )
    if needle not in output:
        return False, (
            f"__sancov_guards section not present in {binary} - rebuild the "
            f"coverage sibling with -fsanitize-coverage=trace-pc-guard"
        )
    return True, ""


def coverage_flags(compiler: str) -> "list[str]":
    """The instrumentation one sibling needs for both of its consumers.

    ``trace-pc-guard`` is what ASan's ``coverage=1`` dump reads. ``fuzzer-no-
    link`` adds the counters libFuzzer guides on and is included only when this
    compiler accepts it: a platform clang without libFuzzer rejects the flag,
    and a sibling that still serves `bin/hits` beats no sibling at all.
    """
    cached = _FLAGS_CACHE.get(compiler)
    if cached is not None:
        return list(cached)
    flags = ["-fsanitize-coverage=trace-pc-guard"]
    with tempfile.TemporaryDirectory(prefix="coverage-flags-") as directory:
        source = Path(directory) / "probe.c"
        source.write_text("int main(void) { return 0; }\n", encoding="utf-8")
        probe = subprocess.run(
            [compiler, "-fsanitize=fuzzer-no-link", *flags, "-c",
             str(source), "-o", str(Path(directory) / "probe.o")],
            capture_output=True, check=False,
        )
    if probe.returncode == 0:
        flags.insert(0, "-fsanitize=fuzzer-no-link")
    _FLAGS_CACHE[compiler] = list(flags)
    return flags


def toolchain_shims(root: Path) -> "tuple[Path, Path]":
    """Write `.audit/coverage-toolchain/{cc,cxx}` and return their paths.

    Each execs the LLVM compiler `bin/fuzz` links harnesses with, plus the
    coverage flags. Rewritten on every build so a toolchain upgrade is picked
    up; written atomically because parallel setups share the directory.

    ``-Wno-error`` trails the recipe's own flags: this compiler is deliberately
    not the one the primary was built with, and a newer clang's new warnings
    under a project's ``-Werror`` are the predictable way an instrumentation
    build of code that already compiles would fail. Warnings never change
    what the sibling executes.
    """
    directory = Path(root) / _SHIM_DIR
    directory.mkdir(parents=True, exist_ok=True)
    shims = []
    for name, real in (
        ("cc", fuzz_harness.fuzzing_compiler()),
        ("cxx", fuzz_harness.fuzzing_compiler(cxx=True)),
    ):
        path = directory / name
        text = (
            "#!/bin/sh\nexec " + shlex.join([real, *coverage_flags(real)])
            + ' "$@" -Wno-error\n'
        )
        temporary = path.with_name(f".{name}.{os.getpid()}.tmp")
        temporary.write_text(text, encoding="utf-8")
        temporary.chmod(0o755)
        os.replace(temporary, path)
        shims.append(path)
    return shims[0], shims[1]


def verify_tree(config, san: str, tree: Path) -> bool:
    """True when the sibling can serve coverage; raises with the reason otherwise.

    The configured executable must carry guards and start, because that is the
    file `bin/hits` replays; the configured library must carry guards because
    harness twins and `bin/fuzz` link it. A tree with neither has nothing a
    coverage consumer would select.
    """
    suffix = tree.name[len(target_config.build_dir_name(san)):]
    checked = False
    binary = sibling_path(config, config.sanitizer_bin(san), san, suffix)
    if binary is not None:
        if not binary.is_file() or not os.access(binary, os.X_OK):
            raise RuntimeError(f"coverage sibling produced no {binary.name}: {binary}")
        present, why = sancov_section_present(binary)
        if not present:
            raise RuntimeError(
                f"{why}; the build recipe must honour CC/CXX for the coverage "
                "sibling to be instrumented"
            )
        failure = runner_preflight.probe_startup(binary, config, san)
        if failure:
            raise RuntimeError(
                f"coverage sibling does not start: {failure.splitlines()[0][:200]}"
            )
        checked = True
    library = sibling_path(config, config.sanitizer_lib(san), san, suffix)
    if library is not None:
        if not library.is_file():
            raise RuntimeError(f"coverage sibling produced no {library.name}: {library}")
        if not fuzz_harness.is_coverage_instrumented(library):
            present, why = sancov_section_present(library)
            if not present:
                raise RuntimeError(
                    f"{why}; the build recipe must honour CC/CXX for the "
                    "coverage sibling to be instrumented"
                )
        checked = True
    if not checked:
        raise RuntimeError(
            f"target.toml names no {san}_bin or {san}_lib under "
            f"{target_config.build_dir_name(san)}/ to instrument"
        )
    return True


def applicable(config, san: str = "asan") -> str:
    """Why this target has no coverage sibling to build, or "" when it does."""
    if config.is_browser in ("1", "true", "True"):
        return "browser targets carry their own coverage build"
    if config.sanitizers_explicitly_disabled:
        return "sanitizers are disabled for this target"
    if not any(
        sibling_path(config, raw, san, COVERAGE_SUFFIX) is not None
        for raw in (config.sanitizer_bin(san), config.sanitizer_lib(san))
    ):
        return (
            f"target.toml names no {san}_bin or {san}_lib under "
            f"{target_config.build_dir_name(san)}/"
        )
    return ""


def freshness(root: Path, config, san: str = "asan") -> str:
    """The sibling's freshness, classified exactly like the primary's."""
    recipe = target_config.build_recipe_path(Path(root), san)
    with build_config.selected_suffix(
        os.environ.get("AUDIT_BUILD_SUFFIX", "") + COVERAGE_SUFFIX
    ):
        return target_config.build_freshness(root, san, recipe_path=recipe)


def _unavailable_marker(root: Path, san: str) -> Path:
    return Path(root) / ".audit" / f"coverage-{tree_name(san)}.unavailable"


def _identity(root: Path, recipe: Path, shims: "tuple[Path, Path]") -> str:
    """What a failed sibling build is bound to: source, recipe and toolchain."""
    digest = hashlib.sha256()
    digest.update(target_config.source_signature(root).encode())
    for path in (recipe, *shims):
        try:
            digest.update(path.read_bytes())
        except OSError:
            digest.update(b"<missing>")
        digest.update(b"\0")
    return digest.hexdigest()


def materialize(
    root: Path, config, san: str = "asan", *, force: bool = False,
) -> build_materialize.MaterializeResult:
    """Build or refresh ``build-<san>+fuzz`` from the canonical recipe.

    Statuses: ``skip`` (nothing to instrument, no recipe, or the primary is
    not fresh — the sibling is its twin and is built only beside a working
    original), ``fresh``, ``built``, ``held`` (a run is reading it), and
    ``failed`` with the log. A failure is remembered against the exact source,
    recipe and toolchain so an audit start does not pay for the same doomed
    build again; a change to any of them, or ``force``, retries.
    """
    root = Path(root)
    reason = applicable(config, san)
    if reason:
        return build_materialize.MaterializeResult("skip", None, reason)
    recipe = target_config.build_recipe_path(root, san)
    if not recipe.is_file():
        return build_materialize.MaterializeResult(
            "skip", None, f"no build recipe at {recipe}"
        )
    primary = target_config.build_freshness(root, san, recipe_path=recipe)
    if primary != "fresh":
        return build_materialize.MaterializeResult(
            "skip", None, f"{target_config.build_dir_name(san)} is {primary}"
        )
    try:
        shims = toolchain_shims(root)
    except OSError as exc:
        # No LLVM clang to instrument with: the sibling has nothing to build
        # from, and a primary that just built must not be failed for it.
        return build_materialize.MaterializeResult(
            "skip", None, f"no coverage toolchain available ({exc})"
        )
    marker = _unavailable_marker(root, san)
    identity = _identity(root, recipe, shims)
    if force:
        marker.unlink(missing_ok=True)
    else:
        try:
            remembered = marker.read_text(encoding="utf-8").strip() == identity
        except OSError:
            remembered = False
        if remembered:
            return build_materialize.MaterializeResult(
                "failed",
                root / ".audit" / f"build-materialize-{san}{COVERAGE_SUFFIX}.log",
                "unavailable for this source, recipe and toolchain; retry with "
                "bin/setup-target --build --force",
            )
    with build_config.selected_suffix(
        os.environ.get("AUDIT_BUILD_SUFFIX", "") + COVERAGE_SUFFIX
    ):
        # Captured inside the suffix, so the recipe sees the tree it builds.
        environment = dict(os.environ, CC=str(shims[0]), CXX=str(shims[1]))
        result = build_materialize.materialize(
            root, san, recipe, recipe,
            lambda tree: verify_tree(config, san, tree),
            force=force, env=environment, log_label=f"{san}{COVERAGE_SUFFIX}",
        )
    if result.status == "failed":
        marker.parent.mkdir(parents=True, exist_ok=True)
        marker.write_text(identity + "\n", encoding="utf-8")
    elif result.status in ("built", "fresh"):
        marker.unlink(missing_ok=True)
    return result


def report(result: build_materialize.MaterializeResult, san: str,
           logger: Callable[[str], None]) -> None:
    """One line per outcome, in the caller's log voice."""
    name = tree_name(san)
    if result.status == "built":
        logger(f"coverage sibling built: {name} (native coverage feedback is on)")
    elif result.status == "fresh":
        logger(f"coverage sibling fresh: {name}")
    elif result.status == "held":
        logger(f"coverage sibling {name} not replaced ({result.reason})")
    elif result.status == "failed":
        logger(
            f"WARN: coverage sibling {name} unavailable; native coverage stays "
            f"unavailable for this target ({result.reason}) | log={result.log_path}"
        )
    else:
        logger(f"coverage sibling not applicable: {result.reason}")
