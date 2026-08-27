"""Validate configured target runners before an audit spends model budget."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Callable

import languages
import sanitizer_run
from timeout import capture_timeout, run_timeout


# Version switches for the standard language runners emitted by lib/languages.py.
# Target-owned executables are only required to resolve and be executable: there
# is no portable, side-effect-free argument that every application must accept.
_VERSION_ARGS = {
    "Rscript": ("--version",),
    "cargo": ("--version",),
    "go": ("version",),
    "java": ("-version",),
    "kotlinc": ("-version",),
    "node": ("--version",),
    "perl": ("--version",),
    "php": ("--version",),
    "python": ("--version",),
    "python3": ("--version",),
    "ruby": ("--version",),
    "swift": ("--version",),
    "ts-node": ("--version",),
}

# Fatal diagnostics the process loader emits before the configured program
# reaches main(), one alternative per libc/loader family — the inclusion
# criterion is "the loader wrote it and the program never ran". Every family
# prefixes its own line ("<loader-or-program>: <phrase>"), so each alternative
# is anchored to that whole-line shape: the phrases themselves are ordinary
# English a program may print in its own help or diagnostics. Loader warnings
# are excluded because the program survives them.
_STARTUP_FAILURE_RE = re.compile(
    r"^dyld(?:\[[0-9]+\])?: (?!warning)"                        # macOS
    r"|^.*: error while loading shared libraries: "             # glibc
    r"|^.*: symbol lookup error: "                              # glibc
    r"|^.*: Shared object \".+\" not found, required by "       # BSD
    r"|^Error (?:loading shared library|relocating) "           # musl
    r"|^ld\.so\.[0-9]+: .*: fatal: "                            # Solaris
    r"|^exec: \[Errno [0-9]+\]",                                # lib/timeout.py execvp
    re.MULTILINE,
)
_STARTUP_PROBE_SECONDS = 3
_STARTUP_PROBE_BYTES = 16384
_TARGET_CONTEXT_SECONDS = 600
_RUN_SCOPED_ENV_TOKENS = ("{TESTCASE}", "{RESULTS_DIR}", "{PROFILE}")


def capture_probe(
    command: list[str], seconds: int, cwd: str | os.PathLike[str],
    max_bytes: int, env: dict[str, str] | None = None,
) -> tuple[subprocess.CompletedProcess, bytes]:
    """Run a target program with closed stdin and bounded captured output.

    A program probed for its own behavior may do work instead: it must not
    consume the caller's input, and it must not stream unbounded output into
    the caller's memory. Callers supply a scratch ``cwd`` so anything it writes
    lands outside their tree, and ``env`` so it sees the same environment the
    harness would give it.
    """
    with capture_timeout(command, seconds, cwd=cwd, input=b"", env=env) as (
        completed, output_path,
    ):
        with output_path.open("rb") as output:
            return completed, output.read(max_bytes)


def probe_signature(
    result: subprocess.CompletedProcess, output: bytes, path: Path,
) -> tuple[int, str]:
    """One launch's observable behaviour, with the testcase path folded out.

    Two launches that differ only in which path they were handed produce equal
    signatures when nothing the program does observably depends on it — which
    is weaker than never looking: a program that reads the file and prints
    nothing compares equal too. Folding both the full path and the bare name
    keeps a program that merely echoes its argument from looking like one that
    used it.
    """
    rendered = output.decode("utf-8", errors="replace")
    normalized = rendered.replace(str(path), "{TESTCASE}")
    return result.returncode, normalized.replace(path.name, "{TESTCASE}")


# What a black-box launch comparison can and cannot establish. Neither answer
# proves the program read the file: one that only stat()s the path varies with
# its existence, and one that reads it whole and prints nothing does not. These
# name the observation, so no caller can mistake it for proof of consumption.
OBSERVABLY_DEPENDS = "depends"
OBSERVABLY_INVARIANT = "invariant"
TESTCASE_UNKNOWN = "unknown"


def testcase_verdict(
    binary: Path, args: list[str], env: dict[str, str] | None = None,
    *, seconds: int = 10,
) -> str:
    """Whether this launch's observable behaviour varies with its testcase.

    A binary that never opens its input makes every CLI replay report CLEAN,
    so a crash that reproduces by hand is recorded as gone. This is the cheap
    portable check for that, and its limits are the reason it only ever
    reports: exit status and output are all it sees, so a program that merely
    stat()s the path counts as depending on it, and one that reads the file
    whole while printing nothing counts as invariant. `OBSERVABLY_INVARIANT`
    is therefore evidence worth acting on, never proof of an input-blind
    runner, and no caller may rewrite configuration from it alone.

    Three launches: the same input twice, then a path that is not there. The
    repeat is what makes the third comparison mean anything — a benchmark
    prints different timings every run, so it differs from the missing-input
    launch for reasons that have nothing to do with reading it, and without
    the repeat that reads as dependence on the input.
    """
    # The probe runs in a scratch cwd, so a relative program never execs and
    # every launch fails identically — which reads as perfect agreement and
    # would condemn every correct runner. Resolve before comparing anything.
    binary = Path(binary).resolve()
    if not binary.is_file() or not os.access(binary, os.X_OK):
        return TESTCASE_UNKNOWN
    with tempfile.TemporaryDirectory(prefix="testcase-dependence-") as directory:
        present = Path(directory) / "input.bin"
        absent = Path(directory) / "missing-input.bin"
        present.write_bytes(b"tokenfuzz invocation probe\n")

        def expand(path: Path) -> list[str]:
            return [
                value.replace("{TESTCASE}", str(path)).replace(
                    "{NULL_DEVICE}", os.devnull
                )
                for value in args
            ]

        signatures = []
        for path in (present, present, absent):
            try:
                completed, output = capture_probe(
                    [str(binary), *expand(path)], seconds, directory,
                    65536, env,
                )
            except (OSError, subprocess.SubprocessError):
                return TESTCASE_UNKNOWN
            # 124 timed out; 126/127 never reached the program. A launch that
            # did not run says nothing about what the program reads, and two
            # of them agree trivially — the shape that made an early version
            # of this check condemn every target at once.
            if completed.returncode in (124, 126, 127):
                return TESTCASE_UNKNOWN
            if startup_failure_reason(completed.returncode, output):
                return TESTCASE_UNKNOWN
            signatures.append(probe_signature(completed, output, path))
        if signatures[0] != signatures[1]:
            return TESTCASE_UNKNOWN
        if any(path.exists() for path in (absent,)):
            # The program wrote to the path it was told to read. Whatever it
            # is doing with its argument, it is not consuming it as input.
            return TESTCASE_UNKNOWN
        return (
            OBSERVABLY_INVARIANT if signatures[0] == signatures[2]
            else OBSERVABLY_DEPENDS
        )


def startup_failure_reason(
    returncode: int, output: bytes | str | None,
) -> str:
    """Return bounded pre-main loader/exec evidence from a probe, else empty.

    A program that exited successfully reached main() whatever its output says,
    so the exit status carries the general half of the judgement and the
    loader-family list only has to name the failure once the program is
    already known to have died.
    """
    if returncode == 0:
        return ""
    if isinstance(output, bytes):
        output = output.decode("utf-8", errors="replace")
    text = str(output or "")
    if not _STARTUP_FAILURE_RE.search(text):
        return ""
    return text.strip()[:4000]


def probe_startup(
    binary: Path, config=None, sanitizer_name: str = "",
) -> str:
    """Launch one native CLI help probe and return only pre-main failures.

    A nonzero exit, timeout, or application diagnostic is not a build failure:
    CLIs differ on whether ``--help`` is accepted. The narrow failure class
    here is executable loading itself, which no later argv inference can fix.

    Pass the target's config and sanitizer name so the program sees the same
    expanded ``[runner].env`` the sanitizer runner applies: a target may
    legitimately supply its own sanitizer-specific library path there, and
    probing without it would call a working build unlaunchable. The path is
    made absolute first — the scratch working directory is not the one a
    target-relative configured path resolves against.

    A run-scoped environment cannot be reproduced during build setup. Defer
    that check to the real probe instead of rejecting a build under guessed
    testcase, results, or browser-profile values.
    """
    if config is not None and not sanitizer_name:
        raise ValueError("sanitizer name is required with target configuration")
    if config is not None and any(
        token in entry
        for entry in config.runner_env
        for token in _RUN_SCOPED_ENV_TOKENS
    ):
        return ""
    with tempfile.TemporaryDirectory(prefix="runner-startup-") as directory:
        completed, output = capture_probe(
            [str(Path(binary).absolute()), "--help"], _STARTUP_PROBE_SECONDS,
            directory, _STARTUP_PROBE_BYTES,
            (
                runner_environment(config, sanitizer_name)
                if config is not None else None
            ),
        )
    return startup_failure_reason(completed.returncode, output)


def runner_path(config) -> Path:
    """The file ``[runner].bin`` selects, usable or not.

    Selection and usability are separate questions: a caller checking whether a
    pinned runner still has its recorded bytes must be able to say "missing" or
    "not executable" about the file the config points at, rather than losing the
    path and reporting a configuration change that did not happen.
    """
    raw = str(config.runner_bin or "").strip()
    found = shutil.which(raw) if raw else None
    return Path(found or config.resolve_path(raw))


def resolve(config) -> Path:
    """Resolve the exact executable selected by ``[runner].bin``."""
    raw = str(config.runner_bin or "").strip()
    candidate = runner_path(config)
    if not candidate.is_file():
        raise RuntimeError(
            f"configured [runner].bin '{raw}' was not found on PATH or at {candidate}"
        )
    if not os.access(candidate, os.X_OK):
        raise RuntimeError(f"configured [runner].bin is not executable: {candidate}")
    return candidate


def runner_environment(config, sanitizer_name: str) -> dict[str, str]:
    """The environment ``[runner].env`` selects, as the sanitizer runner builds it.

    lib/sanitizer_run.py applies these entries to every sanitizer execution, so
    any probe that judges a configured program must apply them too.
    """
    environment = os.environ.copy()
    for entry in config.runner_env:
        expanded = sanitizer_run.expand_runner_value(
            entry, config, sanitizer_name
        )
        key, value = expanded.split("=", 1)
        environment[key] = value
    return environment


def _output_summary(output: bytes | str | None) -> str:
    if isinstance(output, bytes):
        output = output.decode("utf-8", errors="replace")
    for line in str(output or "").splitlines():
        if line.strip():
            return line.strip()[:300]
    return "no diagnostic output"


def validate(config, logger: Callable[[str], object] | None = None) -> Path | None:
    """Validate a configured ``[runner].bin``, raising on an unusable runner.

    A runner is optional: native targets execute through the sanitizer binary,
    and a findings-only target can file code-review findings without ever
    running a testcase. When one is configured we hard-fail on a launcher stub
    or missing interpreter so it cannot silently burn model budget; when none
    is, there is nothing to validate.
    """
    raw = str(config.runner_bin or "").strip()
    if not raw:
        if config.sanitizers_explicitly_disabled and logger is not None:
            logger(
                "Runner preflight: no [runner].bin configured; testcase "
                "execution disabled (code-review findings only)"
            )
        return None

    binary = resolve(config)
    sanitizer_names = (
        ["runner"]
        if config.sanitizers_explicitly_disabled
        else list(dict.fromkeys(config.sanitizers_enabled or ["asan"]))
    )
    sanitizer_name = sanitizer_names[0]
    version_args = _VERSION_ARGS.get(Path(raw).name)
    language = languages.for_build_system(getattr(config, "build_system", ""))
    preflight_args = (
        languages.runner_preflight_args(language, config.runner_args)
        if language is not None and Path(raw).name == language.runner_bin
        else ()
    )
    # Only runners with a check expand their environment: a custom executable
    # carrying a run-scoped token cannot be expanded outside a real run.
    environments: dict[str, dict[str, str]] = {}

    def environment_for(name: str) -> dict[str, str]:
        if name not in environments:
            environments[name] = runner_environment(config, name)
        return environments[name]

    if version_args:
        completed = run_timeout(
            [str(binary), *version_args], 10,
            env=environment_for(sanitizer_name),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        if completed.returncode != 0:
            command = " ".join((str(binary), *version_args))
            reason = (
                "timed out after 10s" if completed.returncode == 124
                else f"exited {completed.returncode}: {_output_summary(completed.stdout)}"
            )
            raise RuntimeError(f"configured [runner].bin failed startup check `{command}`: {reason}")

    # Prepare exactly what this config will run for every runner-owned route.
    for selected in sanitizer_names if preflight_args else ():
        if selected not in {"runner", "race"} and config.sanitizer_bin(selected):
            continue
        prepare = [str(binary), *(
            sanitizer_run.expand_runner_value(
                arg, config, selected,
            )
            for arg in preflight_args
        )]
        completed = run_timeout(
            prepare, _TARGET_CONTEXT_SECONDS, cwd=config.target_root,
            env=environment_for(selected),
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        )
        if completed.returncode != 0:
            reason = (
                f"timed out after {_TARGET_CONTEXT_SECONDS}s"
                if completed.returncode == 124
                else f"exited {completed.returncode}: {_output_summary(completed.stdout)}"
            )
            raise RuntimeError(
                f"configured [runner].bin cannot prepare the {selected} target "
                f"context `{' '.join(prepare)}`: {reason}"
            )

    # Starting is not reaching: a runtime that runs but resolves an installed
    # copy of the audited package audits code the operator never chose.
    import runner_canary

    unreachable = runner_canary.check(config)
    if unreachable:
        raise RuntimeError(
            f"configured [runner] starts but cannot reach the audited tree: "
            f"{unreachable}. Re-run `bin/setup-target --target "
            f"{config.slug or '<slug>'} --build`, or correct [runner] in the "
            f"target's target.toml."
        )
    if logger is not None:
        logger(f"Runner preflight OK: {raw} -> {binary}")
    return binary
