"""Shared filesystem and argument helpers for cleanup commands."""

from __future__ import annotations

import argparse
import os
import re
import shutil
import stat
from pathlib import Path


class CleanupArgumentParser(argparse.ArgumentParser):
    """Argument parser with the cleanup CLIs' concise diagnostics."""

    def __init__(self, *args, tool: str, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.tool = tool

    def error(self, message: str) -> None:
        missing = re.fullmatch(r"argument (--[^:]+): expected one argument", message)
        if missing:
            self.exit(2, f"[{self.tool}] {missing.group(1)} needs a value\n")
        if message.startswith("unrecognized arguments: "):
            unknown = message.removeprefix("unrecognized arguments: ").split()[0]
            if unknown.startswith("-"):
                self.exit(2, f"[{self.tool}] unknown option: {unknown}\n")
        self.exit(2, f"[{self.tool}] {message}\n")


def args_before_double_dash(argv: list[str]) -> list[str]:
    """Honor the standard `--` option terminator."""
    return argv[: argv.index("--")] if "--" in argv else argv


def parse_csv(value: str) -> list[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


def valid_component(name: str) -> bool:
    return bool(name) and name not in {".", ".."} and not (
        name.startswith(".") or "/" in name or ".." in name
    )


def valid_slug(slug: str) -> bool:
    return bool(slug) and all(valid_component(part) for part in slug.split("/"))


def resolve_output_root(raw: str, repo_root: Path) -> Path | None:
    path = Path(raw) if raw else repo_root / "output"
    if not path.is_dir():
        return None
    try:
        return path.resolve(strict=True)
    except OSError:
        return None


def target_slugs(output_root: Path, explicit: list[str]) -> list[str]:
    if explicit:
        return explicit
    from target_config import iter_target_roots

    slugs: list[str] = []
    for target in iter_target_roots(output_root):
        try:
            slugs.append(target.relative_to(output_root).as_posix())
        except ValueError:
            slugs.append(str(target))
    return slugs


def path_is_under(root: Path, path: Path) -> bool:
    if path == root:
        return False
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def directory_entries(path: Path) -> list[os.DirEntry[str]]:
    with os.scandir(path) as iterator:
        return sorted(iterator, key=lambda entry: os.fsencode(entry.name))


def count_removable_logs(path: Path) -> tuple[int, bool]:
    """Return removable entry count and whether a .gitkeep protects this tree."""
    count = 0
    protected = False
    for entry in directory_entries(path):
        if entry.name == ".gitkeep":
            protected = True
            continue
        if entry.is_dir(follow_symlinks=False):
            child_count, child_protected = count_removable_logs(Path(entry.path))
            count += child_count
            if child_protected:
                protected = True
            else:
                count += 1
        else:
            count += 1
    return count, protected


def clear_log_tree(path: Path) -> tuple[int, bool, bool]:
    """Clear a log tree without following symlinks.

    Returns ``(removed_count, success, protected)``. Protected directories are
    retained because they contain a .gitkeep entry.
    """
    removed = 0
    success = True
    protected = False
    try:
        entries = directory_entries(path)
    except OSError:
        return 0, False, False

    for entry in entries:
        if entry.name == ".gitkeep":
            protected = True
            continue
        entry_path = Path(entry.path)
        try:
            is_directory = entry.is_dir(follow_symlinks=False)
        except OSError:
            success = False
            continue

        if is_directory:
            child_removed, child_ok, child_protected = clear_log_tree(entry_path)
            removed += child_removed
            success = success and child_ok
            if child_protected:
                protected = True
                continue
            if not child_ok:
                continue
            try:
                entry_path.rmdir()
                removed += 1
            except FileNotFoundError:
                continue
            except OSError:
                success = False
        else:
            try:
                entry_path.unlink()
                removed += 1
            except FileNotFoundError:
                continue
            except OSError:
                success = False
    return removed, success, protected


def remove_entry(path: Path) -> None:
    """Remove one entry without following a directory symlink."""
    try:
        mode = path.lstat().st_mode
    except FileNotFoundError:
        return
    if stat.S_ISDIR(mode):
        shutil.rmtree(path)
    else:
        path.unlink()
