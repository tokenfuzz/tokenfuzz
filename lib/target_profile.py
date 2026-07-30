#!/usr/bin/env python3
"""Load small, opt-in target overlays."""

from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import sys

import target_config


@dataclass(frozen=True)
class Profile:
    source_subdir: str
    checkout: str
    browser: bool
    fetch_args: tuple[str, ...]
    build_recipe: str
    browser_bin: str


def load(script_root: Path, target: str) -> Profile | None:
    """Load an exact-name overlay; nested targets remain ordinary targets."""
    if "/" in target:
        return None
    directory = script_root / "lib" / "target-overlays"
    filename = f"{target}.toml"
    try:
        if filename not in os.listdir(directory):
            return None
    except OSError:
        return None
    path = directory / filename
    if not path.is_file():
        return None
    data = target_config.parse_toml(path)
    alias = data.get("alias")
    if alias is not None:
        if set(data) != {"alias"} or not isinstance(alias, str) or not alias:
            raise ValueError(f"{path}: alias must be the overlay's only field")
        canonical = path.with_name(f"{alias}.toml")
        if canonical == path or not canonical.is_file():
            raise ValueError(f"{path}: alias target does not exist")
        data = target_config.parse_toml(canonical)
    source_subdir = data.get("source_subdir")
    if not isinstance(source_subdir, str) or not source_subdir:
        raise ValueError(f"{path}: source_subdir must be a non-empty string")
    parts = Path(source_subdir).parts
    if Path(source_subdir).is_absolute() or any(
        part in ("", ".", "..") for part in parts
    ):
        raise ValueError(f"{path}: source_subdir must stay below the target workspace")
    checkout = data.get("checkout", "")
    if checkout not in ("", "gclient"):
        raise ValueError(f"{path}: unsupported checkout driver {checkout!r}")
    fetch_args = data.get("fetch_args", [])
    if not isinstance(fetch_args, list) or not all(
        isinstance(value, str) and value for value in fetch_args
    ):
        raise ValueError(f"{path}: fetch_args must contain only strings")
    build_recipe = data.get("build_recipe", "")
    if not isinstance(build_recipe, str) or Path(build_recipe).name != build_recipe:
        raise ValueError(f"{path}: build_recipe must be a file name")
    browser_bins = {
        key: value
        for key, value in data.items()
        if key.startswith("browser_bin_")
    }
    for value in browser_bins.values():
        if not isinstance(value, str) or not value or (
            Path(value).is_absolute()
            or any(part in ("", ".", "..") for part in Path(value).parts)
        ):
            raise ValueError(
                f"{path}: browser binary must stay below the build directory"
            )
    browser = data.get("browser", False)
    if not isinstance(browser, bool):
        raise ValueError(f"{path}: browser must be true or false")
    return Profile(
        source_subdir=source_subdir,
        checkout=checkout,
        browser=browser,
        fetch_args=tuple(fetch_args),
        build_recipe=build_recipe,
        browser_bin=browser_bins.get(f"browser_bin_{sys.platform}", ""),
    )


def effective_slug(
    script_root: Path,
    target: str,
    *,
    output_root: Path | None = None,
) -> str:
    """Redirect a workspace name to its nested source, unless the bare name is
    already a target of its own.

    ``output/<slug>/target.toml`` is the identity every entry point resolves a
    target through, so an ordinary target set up under an overlay's name keeps
    resolving to itself instead of to a path it never had. A name that is not a
    target yet resolves the way setup will create it.
    """
    profile = load(script_root, target)
    if profile is None:
        return target
    nested = f"{target}/{profile.source_subdir}"
    configs = output_root or Path(script_root) / "output"
    if (configs / target / "target.toml").is_file():
        return target
    if (configs / nested / "target.toml").is_file():
        return nested
    return nested


def resolve(script_root: Path, target: str) -> tuple[str, Profile | None]:
    """Return the workspace name/profile for an alias or its effective slug."""
    profile = load(script_root, target)
    if profile is not None:
        if effective_slug(script_root, target) == target:
            return target, None
        return target, profile
    workspace, separator, remainder = target.partition("/")
    if not separator:
        return target, None
    profile = load(script_root, workspace)
    if profile is None or remainder != profile.source_subdir:
        return target, None
    return workspace, profile
