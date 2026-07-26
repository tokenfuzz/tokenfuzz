#!/usr/bin/env python3
"""Safely refresh one canonical sanitizer build from an existing recipe."""

from __future__ import annotations

import os
import shutil
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

import build_lease
import target_config


@dataclass(frozen=True)
class MaterializeResult:
    status: str
    log_path: Path | None = None
    reason: str = ""


def _remove_path(path: Path) -> None:
    if path.is_symlink() or path.is_file():
        path.unlink(missing_ok=True)
    elif path.is_dir():
        shutil.rmtree(path)


def materialize(
    target_root: Path,
    sanitizer: str,
    source_recipe: Path,
    canonical_recipe: Path,
    verify: Callable[[Path], bool],
    *,
    force: bool = False,
) -> MaterializeResult:
    """Build in a clean canonical tree, preserving the old tree on failure.

    Many build systems persist dependencies on source paths that later vanish.
    Re-running a valid recipe inside that stale tree can therefore fail even
    though the same recipe succeeds from empty state.  Keep the final build
    path stable (some build systems embed it), but move the old audit-owned
    tree aside while rebuilding and restore it on every failure. Candidate
    recipes are installed only after their output passes verification, then
    the build is stamped against the installed canonical bytes.

    Because the tree is replaced in place, the window in which it is absent or
    half-written belongs to this function alone: it takes the exclusive build
    lease for the whole build, and reports "held" without touching anything
    when a live run is executing that tree instead.
    """
    target_root = Path(target_root)
    suffix = os.environ.get("AUDIT_BUILD_SUFFIX", "")
    build_dir = target_root / f"build-{sanitizer}{suffix}"
    audit_dir = target_root / ".audit"
    log_path = audit_dir / f"build-materialize-{sanitizer}.log"

    # A peer builder is worth waiting for — its result may be the build we
    # wanted. A live consumer is not: rebuilding underneath a run swaps the
    # binary its recorded evidence was measured against, so the caller decides
    # what to do instead (keep the existing tree, isolate, or refuse).
    if not build_lease.writer_pending(target_root, build_dir.name) and \
            build_lease.consumers_active(target_root, build_dir.name):
        return MaterializeResult(
            "held", None, f"another run is using {build_dir.name}"
        )
    with build_lease.exclusive(target_root, build_dir.name) as acquired:
        if not acquired:
            # A lease we could not take is a busy tree, not a broken recipe:
            # report it as held so callers keep the existing build instead of
            # entering recipe repair.
            return MaterializeResult(
                "held", None,
                f"timed out waiting for the build lease on {build_dir.name}",
            )
        if not force and target_config.build_freshness(
            target_root, sanitizer, recipe_path=canonical_recipe
        ) == "fresh":
            return MaterializeResult("fresh")

        token = f"{os.getpid()}-{time.time_ns()}"
        backup = audit_dir / "build-backups" / f"{build_dir.name}.{token}"
        failed = audit_dir / "build-failures" / f"{build_dir.name}.{token}"
        recipe_backup = (
            audit_dir / "build-backups" /
            f"{canonical_recipe.name}.{token}"
        )
        had_previous = build_dir.exists() or build_dir.is_symlink()
        if had_previous:
            backup.parent.mkdir(parents=True, exist_ok=True)
            os.replace(build_dir, backup)

        returncode = 1
        reason = "build command failed"
        recipe_promoted = False
        recipe_had_previous = False
        try:
            build_dir.mkdir(parents=True, exist_ok=False)
            log_path.parent.mkdir(parents=True, exist_ok=True)
            with log_path.open("a", encoding="utf-8") as output:
                output.write(
                    f"\n=== {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())} "
                    f"recipe={source_recipe} ===\n"
                )
                output.flush()
                completed = subprocess.run(
                    [str(source_recipe), str(target_root), str(build_dir)],
                    stdout=output,
                    stderr=subprocess.STDOUT,
                    check=False,
                )
            returncode = completed.returncode
            if returncode == 0 and verify(build_dir):
                if source_recipe != canonical_recipe:
                    canonical_recipe.parent.mkdir(parents=True, exist_ok=True)
                    recipe_had_previous = (
                        canonical_recipe.exists() or canonical_recipe.is_symlink()
                    )
                    if recipe_had_previous:
                        recipe_backup.parent.mkdir(parents=True, exist_ok=True)
                        os.replace(canonical_recipe, recipe_backup)
                    try:
                        os.replace(source_recipe, canonical_recipe)
                    except OSError as exc:
                        if recipe_had_previous and recipe_backup.exists():
                            try:
                                os.replace(recipe_backup, canonical_recipe)
                            except OSError as restore_exc:
                                raise RuntimeError(
                                    "validated recipe could not be installed; "
                                    f"previous recipe is preserved at "
                                    f"{recipe_backup}: {restore_exc}"
                                ) from exc
                        raise RuntimeError(
                            f"validated recipe could not be installed: {exc}"
                        ) from exc
                    recipe_promoted = True
                if not target_config.build_write_stamp(
                    target_root, sanitizer, recipe_path=canonical_recipe
                ):
                    raise RuntimeError(
                        "build completed but freshness stamp could not be written"
                    )
                _remove_path(recipe_backup)
                if had_previous:
                    _remove_path(backup)
                return MaterializeResult("built", log_path)
            elif returncode == 0:
                returncode = 1
                reason = "build completed without a configured sanitizer artifact"
        except Exception as exc:
            returncode = 127
            reason = str(exc)

        if recipe_promoted:
            try:
                source_recipe.parent.mkdir(parents=True, exist_ok=True)
                os.replace(canonical_recipe, source_recipe)
                if recipe_had_previous:
                    os.replace(recipe_backup, canonical_recipe)
            except OSError as exc:
                reason = (
                    f"{reason}; previous recipe is preserved at "
                    f"{recipe_backup}: {exc}"
                )

        # Move a partial tree out of the selectable canonical path before
        # cleanup. The log is the durable forensic record.
        try:
            if build_dir.exists() or build_dir.is_symlink():
                failed.parent.mkdir(parents=True, exist_ok=True)
                os.replace(build_dir, failed)
        except OSError:
            _remove_path(build_dir)
        if had_previous:
            try:
                os.replace(backup, build_dir)
            except OSError as exc:
                return MaterializeResult(
                    "failed", log_path,
                    f"{reason}; previous build is preserved at {backup}: {exc}",
                )
        _remove_path(failed)
        return MaterializeResult("failed", log_path, reason)
