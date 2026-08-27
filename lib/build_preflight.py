"""Refresh native sanitizer builds before audit or benchmark work starts."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
from pathlib import Path

import build_lease
import runner_preflight
import target_config
from timeout import run_timeout

_NATIVE_SANITIZERS = {"ubsan", "msan", "tsan"}
_ALTERNATE_PREFLIGHT_TIMEOUT_SECONDS = 600
BENCHMARK_BUILD_PIN_ENV = "_TOKENFUZZ_BENCHMARK_BUILD_PIN"


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


def _build_freshness(target_root: Path, config, sanitizer: str) -> str:
    """Freshness under the build system selected by the pinned config."""
    build_system = str(getattr(config, "build_system", "") or "")
    if build_system not in ("", "unknown") and \
            build_system not in target_config.NATIVE_BUILD_SYSTEMS:
        recipe = target_config.build_recipe_path(target_root, sanitizer)
        # A tree this harness built carries its stamp, and stays answerable
        # even once its recipe is gone -- a deleted recipe reads as stale, not
        # as nothing to check. A tree with no stamp is the operator's own
        # prebuilt artifact: nothing here can rebuild or date it, so existence
        # below is the whole contract.
        stamp = target_root / target_config.build_dir_name(sanitizer) / \
            ".audit-build-stamp"
        if not recipe.is_file() and not stamp.is_file():
            return "skip"
        return target_config.build_freshness(
            target_root, sanitizer, recipe_path=recipe,
        )
    return target_config.build_freshness(target_root, sanitizer)


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _build_stamp_path(target_root: Path, sanitizer: str) -> Path:
    directory = target_config.build_dir_name(sanitizer)
    return Path(target_root) / directory / ".audit-build-stamp"


def _target_owned(path: Path, target_root: Path) -> bool:
    try:
        path.absolute().relative_to(target_root.absolute())
    except ValueError:
        return False
    return True


def _artifact_routes(target_root: Path, config) -> dict[str, tuple[str, Path]]:
    """Exact configured files this benchmark can execute or link."""
    routes: dict[str, tuple[str, Path]] = {}
    if not config.sanitizers_explicitly_disabled:
        for sanitizer in enabled_sanitizers(config):
            for kind, raw in (
                ("bin", config.sanitizer_bin(sanitizer)),
                ("lib", config.sanitizer_lib(sanitizer)),
            ):
                if not raw:
                    continue
                try:
                    routes[f"{sanitizer}-{kind}"] = (
                        raw, Path(config.resolve_path(raw)),
                    )
                except ValueError:
                    continue
    if getattr(config, "runner_bin", ""):
        # The path it selects, not whether it currently runs: a deleted or
        # unexecutable runner is a changed artifact, and dropping the route here
        # would report it as a target.toml change instead.
        try:
            runner = runner_preflight.runner_path(config)
        except (OSError, ValueError):
            runner = None
        if runner is not None:
            routes["runner-bin"] = (str(runner), runner)
    return routes


def build_identity(target_root: Path, config) -> dict:
    """Content identity of the files this config may execute or link."""
    artifacts: dict[str, dict[str, object]] = {}
    for name, (raw, path) in _artifact_routes(target_root, config).items():
        try:
            if not path.is_file():
                continue
            artifacts[name] = {
                "path": raw,
                "size": path.stat().st_size,
                "sha256": _file_sha256(path),
            }
        except (OSError, ValueError):
            continue
    stamps: dict[str, str] = {}
    for sanitizer in sorted({
        name.partition("-")[0]
        for name in artifacts
        if name.partition("-")[0] in target_config.SANITIZERS_VALID
    }):
        path = _build_stamp_path(target_root, sanitizer)
        try:
            stamps[sanitizer] = hashlib.sha256(path.read_bytes()).hexdigest()
        except OSError:
            continue
    if not stamps and not artifacts:
        return {}
    return {"version": 2, "stamps": stamps, "artifacts": artifacts}


def encode_benchmark_build_pin(identity: dict) -> str:
    """Serialize the parent-owned pin for a benchmark cell's environment."""
    return json.dumps(identity, sort_keys=True, separators=(",", ":"))


def benchmark_build_pin(environment: dict[str, str] | None = None) -> dict | None:
    """Read a benchmark cell's exact build pin, or None when it is unusable."""
    source = os.environ if environment is None else environment
    raw = source.get(BENCHMARK_BUILD_PIN_ENV, "")
    try:
        identity = json.loads(raw)
    except (TypeError, ValueError):
        return None
    return identity if isinstance(identity, dict) else None


def _pinned_artifact_problem(resolver, key: str, recorded: object) -> str:
    """Why one pinned artifact is no longer the file that was pinned, if it is not."""
    sanitizer, _, kind = key.partition("-")
    label = f"{sanitizer}_{kind}"
    if not isinstance(recorded, dict):
        return f"{label} pin is unreadable"
    raw = str(recorded.get("path", ""))
    try:
        path = Path(resolver.resolve_path(raw))
        if not path.is_file():
            return f"{label} is missing ({raw})"
        if kind == "bin" and not os.access(path, os.X_OK):
            return f"{label} is not executable ({raw})"
        if path.stat().st_size != recorded.get("size") or \
                _file_sha256(path) != recorded.get("sha256"):
            return f"{label} changed since this run pinned it ({raw})"
    except (OSError, ValueError):
        return f"{label} could not be read ({raw})"
    return ""


def _pinned_route_problems(
    target_root: Path,
    config,
    artifacts: dict,
    artifact_keys: set[str] | None = None,
    *,
    exact: bool,
) -> list[str]:
    routes = _artifact_routes(target_root, config)
    if artifact_keys is not None:
        routes = {key: value for key, value in routes.items()
                  if key in artifact_keys}
        artifacts = {key: value for key, value in artifacts.items()
                     if key in artifact_keys}
    resolver = target_config.Config(target_root=str(target_root))
    problems: list[str] = []
    keys = set(routes) | set(artifacts) if exact else set(routes)
    for key in sorted(keys):
        label = key.replace("-", "_")
        if key not in routes:
            problems.append(f"{label} is no longer selected by target.toml")
            continue
        if key not in artifacts:
            problems.append(f"{label} was not part of this run's build pin")
            continue
        recorded = artifacts[key]
        if not isinstance(recorded, dict):
            continue
        try:
            pinned_path = Path(
                resolver.resolve_path(str(recorded.get("path", "")))
            ).absolute()
            current_path = routes[key][1].absolute()
        except ValueError:
            problems.append(f"{label} route is unreadable")
            continue
        if pinned_path != current_path:
            problems.append(
                f"{label} now selects {routes[key][0]} instead of "
                f"{recorded.get('path', '')}"
            )
    return problems


def pinned_build_problems(
    target_root: Path,
    pinned: dict | None,
    config=None,
    artifact_keys: set[str] | None = None,
) -> list[str]:
    """Why the live build is not the exact generation the benchmark pinned.

    Checks the pin against itself — the paths it recorded and their bytes — so
    what gets verified comes from the parent, not from a freshness probe the
    cell re-derives. The effective target config must still select those same
    files, so unchanged pinned bytes cannot hide a route change. Version-1 pins
    scope that comparison to the artifact routes they recorded.

    The parent converged this generation against the source, pinned the tracked
    source separately, and holds the build lease; what is left to ask is whether
    these are still those bytes. A tree or artifact nobody pinned is not part of
    the experiment, and an empty pin has nothing to verify at all — the parent's
    own freshness check is what gates both.
    """
    if artifact_keys is not None and not artifact_keys:
        return []
    if pinned is None:
        return ["benchmark build pin is missing or unreadable"]
    stamps = pinned.get("stamps", {})
    artifacts = pinned.get("artifacts", {})
    if not isinstance(stamps, dict) or not isinstance(artifacts, dict):
        return ["benchmark build pin is unreadable"]
    problems: list[str] = []
    selected_keys = artifact_keys
    legacy_pin = pinned.get("version") != 2
    if config is not None:
        if selected_keys is None and legacy_pin:
            # Version-1 pins predate config snapshots, but their artifact list
            # contains only the routes that run selected. Verify those routes;
            # deriving the set from today's config would let deleting a route
            # delete its own check.
            selected_keys = set(artifacts)
        problems.extend(_pinned_route_problems(
            target_root, config, artifacts, selected_keys,
            exact=True,
        ))
    elif artifact_keys is not None:
        for key in sorted(artifact_keys - set(artifacts)):
            problems.append(
                f"{key.replace('-', '_')} was not part of this run's build pin"
            )
    resolver = target_config.Config(target_root=str(target_root))
    artifact_failures: set[str] = set()
    for key, recorded in sorted(artifacts.items()):
        if selected_keys is not None and key not in selected_keys:
            continue
        problem = _pinned_artifact_problem(resolver, key, recorded)
        if problem:
            problems.append(problem)
            artifact_failures.add(key.partition("-")[0])
    for sanitizer, digest in sorted(stamps.items()):
        if selected_keys is not None and not any(
            key.startswith(f"{sanitizer}-") for key in selected_keys
        ):
            continue
        if sanitizer in artifact_failures:
            continue
        directory = target_config.build_dir_name(sanitizer)
        try:
            current = hashlib.sha256(
                _build_stamp_path(target_root, sanitizer).read_bytes()
            ).hexdigest()
        except OSError:
            problems.append(f"{directory} is missing")
            continue
        if current != digest:
            problems.append(f"{directory} was rebuilt since this run pinned it")
    return problems


def build_problems(target_root: Path, config) -> list[str]:
    """Why the present sanitizer builds are not usable as they stand, if not.

    The check a verify-only consumer makes. A build it may not replace must
    still be the one it was promised: present, matching the source it is about
    to read, and carrying the artifacts the target declares. Returns an empty
    list when there is nothing to build or nothing wrong.
    """
    if config.sanitizers_explicitly_disabled:
        return []
    problems: list[str] = []
    # Name what made a build stale. This refusal is where an operator chooses
    # between rebuilding and removing something, and "stale" alone does not say
    # which — a by-product a run left in the checkout reads exactly like a
    # source edit here. Read at most once: every tree shares this one source.
    changed: list[str] | None = None
    for name in enabled_sanitizers(config):
        state = _build_freshness(target_root, config, name)
        if state not in ("fresh", "skip"):
            problem = f"{target_config.build_dir_name(name)} is {state}"
            if state == "stale":
                if changed is None:
                    changed = target_config.source_changed_paths(target_root, 5)
                causes = list(changed)
                recipe = target_config.changed_build_recipe(target_root, name)
                if recipe and recipe not in causes:
                    causes.append(recipe)
                if causes:
                    problem += f" (changed: {', '.join(causes[:5])})"
            problems.append(problem)
            continue
        # A configured artifact is an execution route even when no harness-
        # owned native build exists. Never let a language build-system label
        # suppress the cheaper and definitive existence/executable check.
        for kind, raw in (
            ("bin", config.sanitizer_bin(name)), ("lib", config.sanitizer_lib(name)),
        ):
            if not raw:
                continue
            path = Path(config.resolve_path(raw))
            if not path.is_file():
                problems.append(f"{name}_{kind} is missing ({raw})")
            elif kind == "bin" and not os.access(path, os.X_OK):
                problems.append(f"{name}_{kind} is not executable ({raw})")
    return problems


def hold_builds(target_root: Path, config, logger) -> list[str]:
    """Keep the target-owned execution routes from changing under this run.

    Held for the life of the process, because that is the span the guarantee
    covers: evidence a run records must stay replayable against the binary it
    was measured on, across every session, replay and finalization step. A peer
    run that wants the same inputs takes its own shared lease and shares the
    build; one that wants different inputs is told rather than silently
    rebuilding over this one.
    """
    directories = [
        target_config.build_dir_name(name)
        for name in enabled_sanitizers(config)
    ]
    routes = _artifact_routes(target_root, config)
    if "runner-bin" in routes and \
            _target_owned(routes["runner-bin"][1], target_root):
        directories.append(build_lease.RUNNER_LEASE_NAME)
    unleased: list[str] = []
    for directory in directories:
        # Only a tree that exists can be held, and a tree that does not exist
        # has nothing to protect. Asking about existence rather than freshness
        # also keeps this off the freshness path, which shells out to the VCS.
        if directory != build_lease.RUNNER_LEASE_NAME and \
                not (target_root / directory).is_dir():
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
    if config.sanitizers_explicitly_disabled:
        return hold_builds(target_root, config, logger)
    sanitizers = enabled_sanitizers(config)
    try:
        _converge(
            root, target_root, target_slug, config, log_dir, backend, model,
            logger, sanitizers, include_alternates,
        )
    finally:
        unleased = hold_builds(target_root, config, logger)
    return unleased


def _stamped_but_unlaunchable(config, sanitizer: str, logger) -> bool:
    """True when a stamped-fresh sanitizer binary no longer reaches main().

    The freshness stamp is content-based, so it cannot see the host: an
    external shared dependency removed or version-bumped after the build
    leaves the tree stamped fresh and the program unable to start. Every run
    it serves would then record NO_EXEC, and a benchmark cell would pin it and
    measure nothing. Report it as not-fresh instead, so the ordinary build path
    re-runs and its recipe repair can engage.
    """
    if config.is_browser in ("1", "true", "True"):
        return False
    raw = config.sanitizer_bin(sanitizer)
    if not raw or "FILL_ME" in raw:
        return False
    try:
        binary = Path(config.resolve_path(raw))
    except (OSError, ValueError):
        return False
    if not binary.is_file():
        logger(
            f"WARN: stamped {sanitizer} executable is missing, rebuilding: "
            f"{binary}"
        )
        return True
    if not os.access(binary, os.X_OK):
        logger(
            f"WARN: stamped {sanitizer} executable is not executable, "
            f"rebuilding: {binary}"
        )
        return True
    failure = runner_preflight.probe_startup(binary, config, sanitizer)
    if failure:
        logger(
            f"WARN: stamped {sanitizer} build no longer starts, rebuilding: "
            f"{failure.splitlines()[0][:200]}"
        )
    return bool(failure)


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
            name: _build_freshness(target_root, config, name)
            for name in sanitizers
        }
    except OSError as exc:
        logger(f"WARN: sanitizer build freshness probe failed; continuing: {exc}")
        return
    pending = []
    for name, state in before.items():
        if state not in ("fresh", "skip"):
            pending.append(name)
        elif state == "fresh" and _stamped_but_unlaunchable(config, name, logger):
            pending.append(name)
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
            name: _build_freshness(target_root, config, name)
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
