"""Validate configured target runners before an audit spends model budget."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path
from typing import Callable

from timeout import run_timeout


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


def _resolve(config) -> Path:
    raw = str(config.runner_bin or "").strip()
    found = shutil.which(raw) if raw else None
    candidate = Path(found or config.resolve_path(raw))
    if not candidate.is_file():
        raise RuntimeError(
            f"configured [runner].bin '{raw}' was not found on PATH or at {candidate}"
        )
    if not os.access(candidate, os.X_OK):
        raise RuntimeError(f"configured [runner].bin is not executable: {candidate}")
    return candidate


def _environment(config) -> dict[str, str]:
    environment = os.environ.copy()
    replacements = {
        "{TARGET_ROOT}": str(config.target_root or ""),
        "{RESULTS_DIR}": str(config.results_dir or ""),
        "{TARGET_SLUG}": str(config.slug or ""),
    }
    for entry in config.runner_env:
        key, value = entry.split("=", 1)
        for token, replacement in replacements.items():
            value = value.replace(token, replacement)
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

    binary = _resolve(config)
    version_args = _VERSION_ARGS.get(Path(raw).name)
    if version_args:
        completed = run_timeout(
            [str(binary), *version_args], 10,
            env=_environment(config), stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        if completed.returncode != 0:
            command = " ".join((str(binary), *version_args))
            reason = (
                "timed out after 10s" if completed.returncode == 124
                else f"exited {completed.returncode}: {_output_summary(completed.stdout)}"
            )
            raise RuntimeError(f"configured [runner].bin failed startup check `{command}`: {reason}")

    if logger is not None:
        logger(f"Runner preflight OK: {raw} -> {binary}")
    return binary
