#!/usr/bin/env python3
"""The SanitizerCoverage siblings of a sanitizer build: build, find, prove them.

`build-<san>` is what every recorded probe was measured against, so it is never
rebuilt with different flags. Coverage-instrumented twins live beside it, one
per consumer: `build-<san>+cov` carries trace-pc-guard, the only hook ASan's
`coverage=1` `.sancov` dump reads, and is what `bin/hits` replays native
testcases in; `build-<san>+fuzz` carries the inline counters libFuzzer guides
on, and is what `bin/fuzz` links harnesses against. They cannot be one tree:
libFuzzer exits at startup when any object it loads carries trace-pc-guard.

Each sibling is produced by the target's own canonical recipe, run with CC and
CXX pointed at a shim that adds its flags and hands off to the LLVM toolchain
that ships libFuzzer. Recipes honour CC/CXX by contract (the generated ones
spell `${CC:-clang}`); one that does not yields a tree without instrumentation,
which verification reports and the consumers then decline to select, so
coverage reads unavailable rather than measuring the wrong binary.
"""

from __future__ import annotations

import hashlib
import os
import shlex
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

import build_config
import build_materialize
import fuzz_harness
import native_symbols
import runner_preflight
import target_config

COVERAGE_SUFFIX = "+cov"
FUZZ_SUFFIX = fuzz_harness.COVERAGE_TREE_SUFFIX


@dataclass(frozen=True)
class Sibling:
    label: str
    flags: tuple[str, ...]
    shim_dir: str
    feedback: str


_SIBLINGS = {
    COVERAGE_SUFFIX: Sibling(
        "coverage sibling", ("-fsanitize-coverage=trace-pc-guard",),
        "coverage-toolchain", "native replay coverage is on",
    ),
    FUZZ_SUFFIX: Sibling(
        "fuzz sibling", ("-fsanitize=fuzzer-no-link",),
        "fuzz-toolchain", "libFuzzer feedback is on",
    ),
}
SIBLING_SUFFIXES = tuple(_SIBLINGS)
#: Compiler names a build may invoke instead of honouring ``CC``/``CXX``.
#: A hand-written configure is free to ignore the environment and pick its own
#: default — ffmpeg's records `CC=gcc` even when `CC=clang` is exported — and
#: an uninstrumented sibling is indistinguishable from a working one until
#: `verify_tree` refuses it. Answering to the names as well as the variables
#: costs nothing on a build that does honour them, because they resolve to the
#: same shim. The shim `exec`s an absolute compiler path, so nothing recurses.
_MASQUERADE_NAMES = (
    ("cc", "gcc", "clang"),
    ("c++", "g++", "clang++"),
)


def tree_name(san: str = "asan", sibling: str = COVERAGE_SUFFIX, *,
              suffix: "str | None" = None) -> str:
    """Directory name of a sibling, honouring AUDIT_BUILD_SUFFIX."""
    return target_config.build_dir_name(san, suffix=suffix) + sibling


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


def toolchain_shims(root: Path, sibling: str = COVERAGE_SUFFIX) -> "tuple[Path, Path]":
    """Write `.audit/<sibling shim dir>/{cc,cxx}` and return their paths.

    Each execs the LLVM compiler `bin/fuzz` links harnesses with, plus the
    sibling's flags. Rewritten on every build so a toolchain upgrade is picked
    up; written atomically because parallel setups share the directory. A
    compiler that is not there is an OSError, so the caller can skip rather
    than record a doomed build as this target's failure.

    ``-Wno-error`` trails the recipe's own flags: this compiler is deliberately
    not the one the primary was built with, and a newer clang's new warnings
    under a project's ``-Werror`` are the predictable way an instrumentation
    build of code that already compiles would fail. Warnings never change
    what the sibling executes.
    """
    spec = _SIBLINGS[sibling]
    directory = Path(root) / ".audit" / spec.shim_dir
    directory.mkdir(parents=True, exist_ok=True)
    shims = []
    for name, real in (
        ("cc", fuzz_harness.fuzzing_compiler()),
        ("cxx", fuzz_harness.fuzzing_compiler(cxx=True)),
    ):
        if not shutil.which(real):
            raise OSError(f"compiler not found: {real}")
        path = directory / name
        text = (
            "#!/bin/sh\nexec " + shlex.join([real, *spec.flags])
            + ' "$@" -Wno-error\n'
        )
        temporary = path.with_name(f".{name}.{os.getpid()}.tmp")
        temporary.write_text(text, encoding="utf-8")
        temporary.chmod(0o755)
        os.replace(temporary, path)
        shims.append(path)
    # Same content under every name a build might reach for, so a recipe that
    # ignores CC/CXX still compiles through the instrumentation when this
    # directory leads PATH.
    for shim, names in zip(shims, _MASQUERADE_NAMES):
        body = shim.read_text(encoding="utf-8")
        for name in names:
            alias = directory / name
            temporary = alias.with_name(f".{name}.{os.getpid()}.tmp")
            temporary.write_text(body, encoding="utf-8")
            temporary.chmod(0o755)
            os.replace(temporary, alias)
    return shims[0], shims[1]


def verify_tree(config, san: str, tree: Path) -> bool:
    """True when the sibling can serve its consumer; raises with the reason otherwise.

    In the coverage sibling the configured executable must carry guards and
    start, because that is the file `bin/hits` replays, and the configured
    library must carry guards because harness twins link it. In the fuzz
    sibling the library must carry the counters libFuzzer guides on and none
    of the guards it refuses. A tree with nothing to check has nothing a
    consumer would select.
    """
    # Inside the sibling's selected build suffix the computed suffix is empty,
    # so the consumer is read off the directory name.
    suffix = tree.name[len(target_config.build_dir_name(san)):]
    if tree.name.endswith(FUZZ_SUFFIX):
        return _verify_fuzz_tree(config, san, suffix)
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


def _verify_fuzz_tree(config, san: str, suffix: str) -> bool:
    library = sibling_path(config, config.sanitizer_lib(san), san, suffix)
    if library is None:
        raise RuntimeError(f"target.toml names no {san}_lib to instrument for fuzzing")
    if not library.is_file():
        raise RuntimeError(f"fuzz sibling produced no {library.name}: {library}")
    undefined = native_symbols.undefined_symbols(library)
    if not any("sanitizer_cov_8bit_counters_init" in name for name in undefined):
        raise RuntimeError(
            f"inline 8-bit counters not present in {library}; the build recipe "
            "must honour CC/CXX for the fuzz sibling to be instrumented"
        )
    if any("sanitizer_cov_trace_pc_guard" in name for name in undefined):
        raise RuntimeError(
            f"{library} also carries trace-pc-guard, which current libFuzzer "
            "rejects at startup"
        )
    return True


def applicable(config, san: str = "asan", sibling: str = COVERAGE_SUFFIX) -> str:
    """Why this target has no such sibling to build, or "" when it does."""
    if config.is_browser in ("1", "true", "True"):
        return "browser targets carry their own coverage build"
    if config.sanitizers_explicitly_disabled:
        return "sanitizers are disabled for this target"
    # Only a library is ever linked into a libFuzzer harness; the coverage
    # sibling also serves the configured CLI.
    raws, fields = [config.sanitizer_lib(san)], f"{san}_lib"
    if sibling != FUZZ_SUFFIX:
        raws.insert(0, config.sanitizer_bin(san))
        fields = f"{san}_bin or {san}_lib"
    if not any(sibling_path(config, raw, san, sibling) is not None for raw in raws):
        return (
            f"target.toml names no {fields} under "
            f"{target_config.build_dir_name(san)}/"
        )
    return ""


def freshness(root: Path, config, san: str = "asan",
              sibling: str = COVERAGE_SUFFIX) -> str:
    """The sibling's freshness, classified exactly like the primary's."""
    recipe = target_config.build_recipe_path(Path(root), san)
    with build_config.selected_suffix(
        os.environ.get("AUDIT_BUILD_SUFFIX", "") + sibling
    ):
        return target_config.build_freshness(root, san, recipe_path=recipe)


def _unavailable_marker(root: Path, san: str, sibling: str) -> Path:
    name = target_config.build_dir_name(san) + sibling
    return Path(root) / ".audit" / f"coverage-{name}.unavailable"


def _identity(root: Path, recipe: Path, shims: "tuple[Path, Path]") -> str:
    """What a failed sibling build is bound to: source, recipe and toolchain.

    The toolchain is the compiler binary itself, not only the path the shim
    names: an upgrade installed over the same path must retry the build.
    """
    digest = hashlib.sha256()
    digest.update(target_config.source_signature(root).encode())
    for path in (recipe, *shims):
        try:
            digest.update(path.read_bytes())
        except OSError:
            digest.update(b"<missing>")
        digest.update(b"\0")
    for real in (fuzz_harness.fuzzing_compiler(), fuzz_harness.fuzzing_compiler(cxx=True)):
        try:
            stat = os.stat(shutil.which(real) or real)
            digest.update(f"{stat.st_mtime_ns}:{stat.st_size}".encode())
        except OSError:
            digest.update(b"<missing>")
        digest.update(b"\0")
    return digest.hexdigest()


def stale_reason(root: Path, san: str, suffix: str) -> str:
    """Why the sibling cannot stand in for ``build-<san>``, or "".

    A sibling left behind when its rebuild failed still carries guards, but
    replaying today's testcases against yesterday's code answers MISSED for
    every symbol the source added since. Both stamps record the source
    signature they were built from; a sibling without a stamp is hand-built
    and taken as offered.
    """
    primary = target_config.build_stamp_fields(root, san)
    with build_config.selected_suffix(os.environ.get("AUDIT_BUILD_SUFFIX", "") + suffix):
        sibling = target_config.build_stamp_fields(root, san)
    if primary is None or sibling is None or not (primary[1] and sibling[1]):
        return ""
    if sibling[1] != primary[1]:
        return (
            f"sibling build-{san}{suffix} was built from different source than "
            f"build-{san}; `bin/setup-target <slug> --build` rebuilds it"
        )
    return ""


def materialize(
    root: Path, config, san: str = "asan", *, force: bool = False,
    sibling: str = COVERAGE_SUFFIX,
) -> build_materialize.MaterializeResult:
    """Build or refresh ``build-<san><sibling>`` from the canonical recipe.

    Statuses: ``skip`` (nothing to instrument, no recipe, or the primary is
    not fresh — the sibling is its twin and is built only beside a working
    original), ``fresh``, ``built``, ``held`` (a run is reading it), and
    ``failed`` with the log. A failure is remembered against the exact source,
    recipe and toolchain so an audit start does not pay for the same doomed
    build again; a change to any of them, or ``force``, retries.
    """
    root = Path(root)
    reason = applicable(config, san, sibling)
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
        shims = toolchain_shims(root, sibling)
    except OSError as exc:
        # No LLVM clang to instrument with: the sibling has nothing to build
        # from, and a primary that just built must not be failed for it.
        return build_materialize.MaterializeResult(
            "skip", None, f"no coverage toolchain available ({exc})"
        )
    marker = _unavailable_marker(root, san, sibling)
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
                root / ".audit" / f"build-materialize-{san}{sibling}.log",
                "unavailable for this source, recipe and toolchain; retry with "
                "bin/setup-target --build --force",
            )
    with build_config.selected_suffix(
        os.environ.get("AUDIT_BUILD_SUFFIX", "") + sibling
    ):
        # Captured inside the suffix, so the recipe sees the tree it builds.
        # PATH leads with the shim directory as well as naming it in CC/CXX:
        # the variables are the polite route, the directory is the one a build
        # that ignores them still has to take. Scoped to this subprocess, so
        # the primary build and everything else keep the real toolchain.
        environment = dict(
            os.environ,
            CC=str(shims[0]),
            CXX=str(shims[1]),
            PATH=os.pathsep.join(
                [str(shims[0].parent), os.environ.get("PATH", "")]
            ).rstrip(os.pathsep),
        )
        result = build_materialize.materialize(
            root, san, recipe, recipe,
            lambda tree: verify_tree(config, san, tree),
            force=force, env=environment, log_label=f"{san}{sibling}",
        )
    if result.status == "failed":
        marker.parent.mkdir(parents=True, exist_ok=True)
        marker.write_text(identity + "\n", encoding="utf-8")
    elif result.status in ("built", "fresh"):
        marker.unlink(missing_ok=True)
    return result


def report(result: build_materialize.MaterializeResult, san: str,
           logger: Callable[[str], None], sibling: str = COVERAGE_SUFFIX) -> None:
    """One line per outcome, in the caller's log voice."""
    name = tree_name(san, sibling)
    label = _SIBLINGS[sibling].label
    if result.status == "built":
        logger(f"{label} built: {name} ({_SIBLINGS[sibling].feedback})")
    elif result.status == "fresh":
        logger(f"{label} fresh: {name}")
    elif result.status == "held":
        logger(f"{label} {name} not replaced ({result.reason})")
    elif result.status == "failed":
        logger(
            f"WARN: {label} {name} unavailable; its feedback stays "
            f"unavailable for this target ({result.reason}) | log={result.log_path}"
        )
    else:
        logger(f"{label} not applicable: {result.reason}")
