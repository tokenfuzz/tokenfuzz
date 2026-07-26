"""Refresh native sanitizer builds before audit or benchmark work starts."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import build_lease
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


def enabled_sanitizers(config) -> list[str]:
    """asan plus every enabled native sanitizer — the trees a run reads."""
    enabled = config.sanitizers_enabled if isinstance(config.sanitizers_enabled, list) else []
    return ["asan", *(name for name in enabled if name in _NATIVE_SANITIZERS)]


def build_problems(target_root: Path, config) -> list[str]:
    """Why the present sanitizer builds are not usable as they stand, if not.

    The check a verify-only consumer makes. A build it may not replace must
    still be the one it was promised: present, matching the source it is about
    to read, and carrying the artifacts the target declares. Returns an empty
    list when there is nothing to build or nothing wrong.
    """
    if (str(config.is_browser).lower() in {"1", "true"}
            or config.sanitizers_explicitly_disabled):
        return []
    problems: list[str] = []
    for name in enabled_sanitizers(config):
        state = target_config.build_freshness(target_root, name)
        if state == "skip":
            continue
        if state != "fresh":
            problems.append(f"{target_config.build_dir_name(name)} is {state}")
            continue
        for kind, raw in (
            ("bin", config.sanitizer_bin(name)), ("lib", config.sanitizer_lib(name)),
        ):
            if raw and not Path(config.resolve_path(raw)).is_file():
                problems.append(f"{name}_{kind} is missing ({raw})")
    return problems


def hold_builds(target_root: Path, sanitizers: list[str], logger) -> list[str]:
    """Keep the builds this run will read from being replaced underneath it.

    Held for the life of the process, because that is the span the guarantee
    covers: evidence a run records must stay replayable against the binary it
    was measured on, across every session, replay and finalization step. A peer
    run that wants the same inputs takes its own shared lease and shares the
    build; one that wants different inputs is told rather than silently
    rebuilding over this one.
    """
    unleased: list[str] = []
    for name in sanitizers:
        directory = target_config.build_dir_name(name)
        # Only a tree that exists can be held, and a tree that does not exist
        # has nothing to protect. Asking about existence rather than freshness
        # also keeps this off the freshness path, which shells out to the VCS.
        if not (target_root / directory).is_dir():
            continue
        if not build_lease.hold_shared(target_root, directory, logger=logger):
            unleased.append(directory)
    return unleased


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
) -> list[str]:
    """Rebuild enabled native sanitizer trees that are missing or stale, then
    hold them for the rest of this run.

    Build failure is visible but never aborts the caller. Targets outside the
    harness's ``targets/`` tree are not passed to setup-target because its slug
    lookup would resolve a different path.

    Returns the build directories it could not lease — empty when every existing
    tree is held. An audit continues regardless (the warning is on the record);
    a benchmark, whose whole result depends on the build not moving, refuses.
    """
    if str(config.is_browser).lower() in {"1", "true"} or config.sanitizers_explicitly_disabled:
        return []
    sanitizers = enabled_sanitizers(config)
    try:
        _converge(
            root, target_root, target_slug, config, log_dir, backend, model,
            logger, sanitizers, include_alternates,
        )
    finally:
        unleased = hold_builds(target_root, sanitizers, logger)
    return unleased


def _converge(
    root: Path,
    target_root: Path,
    target_slug: str,
    config,
    log_dir: Path,
    backend: str,
    model: str,
    logger,
    sanitizers: list[str],
    include_alternates: bool,
) -> None:
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
    command = [str(root / "bin" / "setup-target"), target_slug, "--build"]
    if not include_alternates:
        # setup-target materializes every declared alternate configuration of
        # its own accord. Left on, a caller that asked for the primary build
        # only — a benchmark — would get a full set of alternate trees too, and
        # under an isolated suffix a whole second set of them.
        command.append("--no-alternates")
    try:
        with build_log.open("ab") as output:
            subprocess.run(
                command, env=environment, stdout=output,
                stderr=subprocess.STDOUT, check=False,
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
