#!/usr/bin/env python3
"""Named, isolated sanitizer build configurations.

The canonical ``build-asan`` tree remains the control configuration.  Extra
configurations are content-addressed from their ordered build arguments and
live in sibling trees selected through ``AUDIT_BUILD_SUFFIX``.  This module is
pure configuration/path policy; materialization lives in ``bin/build-configs``.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


NAME_RE = re.compile(r"^[a-z][a-z0-9_-]{0,31}$")
MAX_FLAG_LENGTH = 1024


@dataclass(frozen=True)
class BuildConfig:
    name: str
    label: str
    flags: tuple[str, ...] = ()
    features: tuple[str, ...] = ()
    widen: bool = False

    @property
    def config_id(self) -> str:
        # Argument order and duplicates can change configure/compiler behavior;
        # preserve both in the identity rather than treating flags as a set.
        payload = json.dumps(
            {"name": self.name, "flags": self.flags, "widen": self.widen},
            ensure_ascii=True,
            separators=(",", ":"),
        )
        digest = hashlib.sha256(payload.encode()).hexdigest()[:10]
        return f"{self.name}-{digest}"


def validate_name(name: str) -> None:
    if not NAME_RE.fullmatch(name):
        raise ValueError(
            "build_config name must start with a lowercase letter and contain "
            "only lowercase letters, digits, '_' or '-' (maximum 32 characters)"
        )


def validate_flags(flags: object) -> tuple[str, ...]:
    if not isinstance(flags, list):
        raise ValueError("build_config flags must be an array of strings")
    result: list[str] = []
    for flag in flags:
        if not isinstance(flag, str) or not flag or "\x00" in flag or "\n" in flag or "\r" in flag:
            raise ValueError("build_config flags must be non-empty, single-line strings")
        if len(flag) > MAX_FLAG_LENGTH:
            raise ValueError(f"build_config flag exceeds {MAX_FLAG_LENGTH} characters")
        result.append(flag)
    return tuple(result)


def from_parsed(entries: object, *, include_widened: bool = False) -> list[BuildConfig]:
    """Validate ``[[build_config]]`` rows and return them in declared order."""
    rows = entries if isinstance(entries, list) else []
    configs: list[BuildConfig] = []
    seen: set[str] = set()
    for raw in rows:
        if not isinstance(raw, dict):
            raise ValueError("each [[build_config]] entry must be a table")
        name = str(raw.get("name", ""))
        validate_name(name)
        if name in seen:
            raise ValueError(f"duplicate build_config name: {name}")
        seen.add(name)
        flags = validate_flags(raw.get("flags", []))
        widen = raw.get("widen", False)
        if not isinstance(widen, bool):
            raise ValueError(f"build_config {name}: widen must be true or false")
        if widen and flags:
            raise ValueError(f"build_config {name}: use either widen=true or flags, not both")
        if not widen and not flags:
            raise ValueError(f"build_config {name}: set widen=true or provide flags")
        features_raw = raw.get("features", [])
        if not isinstance(features_raw, list) or any(not isinstance(v, str) for v in features_raw):
            raise ValueError(f"build_config {name}: features must be an array of strings")
        configs.append(BuildConfig(
            name=name,
            label=str(raw.get("label") or name),
            flags=flags,
            features=tuple(v for v in features_raw if v),
            widen=widen,
        ))
    if include_widened and "widened" not in seen:
        configs.insert(0, BuildConfig(
            name="widened",
            label="widened in-tree features",
            features=("optional in-tree features",),
            widen=True,
        ))
    return configs


def find(configs: Iterable[BuildConfig], selector: str) -> BuildConfig | None:
    for config in configs:
        if selector in (config.name, config.config_id):
            return config
    return None


def suffix(config: BuildConfig, base: str = "") -> str:
    return f"{base}+cfg-{config.config_id}"


def build_dir(
    target_root: str | os.PathLike[str], config: BuildConfig,
    *, sanitizer: str = "asan", base_suffix: str = "",
) -> Path:
    return Path(target_root) / f"build-{sanitizer}{suffix(config, base_suffix)}"


def recipe_path(
    target_root: str | os.PathLike[str], config: BuildConfig,
    *, sanitizer: str = "asan",
) -> Path:
    return Path(target_root) / ".audit" / "configs" / f"{config.config_id}.{sanitizer}.sh"


def recipe_digest(path: str | os.PathLike[str]) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def recipe_stamp_path(tree: str | os.PathLike[str]) -> Path:
    return Path(tree) / ".audit-config-recipe.sha256"


def ready_path(tree: str | os.PathLike[str]) -> Path:
    return Path(tree) / ".audit-config-ready"


def write_recipe_stamp(tree: str | os.PathLike[str], recipe: str | os.PathLike[str]) -> None:
    recipe_stamp_path(tree).write_text(recipe_digest(recipe) + "\n", encoding="utf-8")


def mark_ready(tree: str | os.PathLike[str], recipe: str | os.PathLike[str]) -> None:
    """Record the artifact proof once, bound to the exact converged recipe."""
    ready_path(tree).write_text(recipe_digest(recipe) + "\n", encoding="utf-8")


def is_ready(tree: str | os.PathLike[str], recipe: str | os.PathLike[str]) -> bool:
    try:
        digest = recipe_digest(recipe)
        return (
            recipe_stamp_path(tree).read_text(encoding="utf-8").strip() == digest
            and ready_path(tree).read_text(encoding="utf-8").strip() == digest
        )
    except OSError:
        return False


def produced_artifacts(tree: str | os.PathLike[str]) -> bool:
    root = Path(tree)
    if not root.is_dir():
        return False
    try:
        paths = root.rglob("*")
        for path in paths:
            if not path.is_file():
                continue
            if path.name.endswith((".a", ".so", ".dylib")):
                return True
            if (
                os.access(path, os.X_OK)
                and not path.name.endswith((".cmake", ".sh", ".py", ".txt"))
                and path.stat().st_size > 4096
            ):
                return True
    except OSError:
        return False
    return False


def config_for_binary(
    configs: Iterable[BuildConfig], target_root: str | os.PathLike[str], binary: str,
    *, sanitizer: str = "asan", base_suffix: str = "",
) -> BuildConfig | None:
    if not binary:
        return None
    try:
        resolved = Path(binary).resolve()
    except OSError:
        return None
    for config in configs:
        tree = build_dir(target_root, config, sanitizer=sanitizer, base_suffix=base_suffix)
        try:
            resolved.relative_to(tree.resolve())
        except (OSError, ValueError):
            continue
        return config
    return None
