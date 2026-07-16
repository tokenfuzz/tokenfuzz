"""Refresh native sanitizer builds before audit or benchmark work starts."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import target_config
from timeout import run_timeout

_NATIVE_SANITIZERS = {"ubsan", "msan", "tsan"}
_ALTERNATE_PREFLIGHT_TIMEOUT_SECONDS = 600


def _refresh_alternates(
    root: Path, target_root: Path, target_slug: str, config, environment: dict,
    build_log: Path, logger,
) -> None:
    if not getattr(config, "build_configs", None):
        return
    target_toml = root / "output" / target_slug / "target.toml"
    if not target_toml.is_file():
        return
    try:
        with build_log.open("ab") as output:
            completed = run_timeout(
                [
                    str(root / "bin" / "build-configs"),
                    "--target-path", str(target_root),
                    "--target-toml", str(target_toml), "--all",
                ],
                _ALTERNATE_PREFLIGHT_TIMEOUT_SECONDS,
                env=environment, stdout=output, stderr=subprocess.STDOUT,
            )
    except OSError as exc:
        logger(f"WARN: alternate build configuration preflight could not run; continuing: {exc}")
        return
    if completed.returncode:
        reason = "timed out" if completed.returncode == 124 else "were unavailable"
        logger(
            f"WARN: alternate build configurations {reason}; "
            f"the regular sanitizer build remains active | log={build_log}"
        )


def refresh(
    root: Path,
    target_root: Path,
    target_slug: str,
    config,
    log_dir: Path,
    backend: str,
    model: str,
    logger,
    *,
    include_alternates: bool = True,
) -> None:
    """Rebuild enabled native sanitizer trees that are missing or stale.

    Build failure is visible but never aborts the caller. Targets outside the
    harness's ``targets/`` tree are not passed to setup-target because its slug
    lookup would resolve a different path.
    """
    if str(config.is_browser).lower() in {"1", "true"} or config.sanitizers_explicitly_disabled:
        return
    enabled = config.sanitizers_enabled if isinstance(config.sanitizers_enabled, list) else []
    sanitizers = [
        "asan", *(name for name in enabled if name in _NATIVE_SANITIZERS)
    ]
    try:
        before = {
            name: target_config.build_freshness(target_root, name)
            for name in sanitizers
        }
    except OSError as exc:
        logger(f"WARN: sanitizer build freshness probe failed; continuing: {exc}")
        return
    pending = [name for name, state in before.items() if state not in ("fresh", "skip")]
    build_log = log_dir / "setup-build.log"
    environment = os.environ.copy()
    environment.update(
        AUDIT_ROOT=str(root), SCRIPT_ROOT=str(root),
        ACTIVE_BACKEND=backend, BACKEND=backend, MODEL=model,
    )
    if not pending:
        if not include_alternates:
            return
        _refresh_alternates(
            root, target_root, target_slug, config, environment, build_log, logger
        )
        return
    try:
        target_root.relative_to(root / "targets")
    except ValueError:
        logger(
            "WARN: sanitizer build is stale/missing for an external --target-path; "
            "run its build recipe manually before continuing"
        )
        return

    logger(
        f"Sanitizer build stale/missing ({','.join(pending)}); "
        "running bin/setup-target --build (fail-open)"
    )
    try:
        with build_log.open("ab") as output:
            subprocess.run(
                [str(root / "bin" / "setup-target"), target_slug, "--build"],
                env=environment, stdout=output, stderr=subprocess.STDOUT,
                check=False,
            )
    except OSError as exc:
        logger(f"WARN: sanitizer build preflight could not run; continuing: {exc}")
        return

    try:
        after = {
            name: target_config.build_freshness(target_root, name)
            for name in sanitizers
        }
    except OSError as exc:
        logger(f"WARN: post-build freshness probe failed; continuing: {exc}")
        return
    remaining = [name for name, state in after.items() if state not in ("fresh", "skip")]
    if not remaining:
        logger(f"Sanitizer builds refreshed | log={build_log}")
        if include_alternates:
            _refresh_alternates(
                root, target_root, target_slug, config, environment, build_log, logger
            )
        return
    states = ",".join(f"{name}={after[name]}" for name in remaining)
    logger(
        f"WARN: sanitizer builds still stale/missing ({states}); "
        f"sanitizer-dependent work may be unavailable | log={build_log}"
    )
