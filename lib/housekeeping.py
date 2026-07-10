"""Metadata snapshots used by housekeeping dirty checks."""

from __future__ import annotations

import hashlib
import os
import re
import stat
import time
from pathlib import Path


def _mtime_ns(value: os.stat_result) -> int:
    return getattr(value, "st_mtime_ns", int(value.st_mtime * 1_000_000_000))


def metadata_lines(path: str) -> list[str]:
    output: list[str] = []
    try:
        info = os.lstat(path)
    except OSError as error:
        return [f"MISSING\t{path}\t{type(error).__name__}"]
    mode = info.st_mode
    modified = _mtime_ns(info)
    if stat.S_ISDIR(mode):
        output.append(f"D\t{path}\t{mode:o}\t{modified}")
        for directory, dirnames, filenames in os.walk(path, followlinks=False):
            dirnames.sort()
            filenames.sort()
            for name in dirnames:
                child = os.path.join(directory, name)
                try:
                    child_info = os.lstat(child)
                    output.append(f"D\t{child}\t{child_info.st_mode:o}\t{_mtime_ns(child_info)}")
                except OSError as error:
                    output.append(f"ERR\t{child}\t{type(error).__name__}")
            for name in filenames:
                output.extend(metadata_lines(os.path.join(directory, name)))
        return output
    if stat.S_ISLNK(mode):
        try:
            target = os.readlink(path)
        except OSError:
            target = "<unreadable>"
        output.append(f"L\t{path}\t{mode:o}\t{info.st_size}\t{modified}\t{target}")
    elif stat.S_ISREG(mode):
        output.append(f"F\t{path}\t{mode:o}\t{info.st_size}\t{modified}")
    else:
        output.append(f"O\t{path}\t{mode:o}\t{info.st_size}\t{modified}")
    return output


def cache_dir() -> Path | None:
    value = os.environ.get("HOUSEKEEPING_CACHE_DIR")
    if not value:
        results = os.environ.get("RESULTS_DIR", "")
        value = str(Path(results) / ".housekeeping-cache") if results else ""
    if not value:
        return None
    path = Path(value)
    try:
        path.mkdir(parents=True, exist_ok=True)
    except OSError:
        return None
    return path


def safe_label(label: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "-", label)


def stamp_path(label: str) -> Path | None:
    directory = cache_dir()
    return None if directory is None else directory / f"{safe_label(label)}.sig"


def signature(label: str, paths: list[str], target_source_signature: str = "") -> str:
    lines = [
        "schema=3",
        f"label={label}",
        f"target_slug={os.environ.get('TARGET_SLUG', '')}",
        f"is_browser={os.environ.get('IS_BROWSER_TARGET', '')}",
        f"attacker_controls={os.environ.get('TARGET_ATTACKER_CONTROLS_CSV', '')}",
        f"llm_decide_disable={os.environ.get('LLM_DECIDE_DISABLE', '')}",
    ]
    if target_source_signature and label in ("patch-review", "work-cards-refresh"):
        lines.extend(("target_source_signature_begin", target_source_signature.rstrip("\n"), "target_source_signature_end"))
    for path in paths:
        lines.extend(metadata_lines(path))
    return hashlib.sha1(("\n".join(lines) + "\n").encode()).hexdigest()


def should_run(label: str, current_signature: str, ttl: str | int | None = None) -> bool:
    if os.environ.get("HOUSEKEEPING_DIRTY_CHECKS", "1") == "0" or not current_signature:
        return True
    stamp = stamp_path(label)
    if stamp is None or not stamp.is_file() or stamp.stat().st_size == 0:
        return True
    try:
        old_signature, old_timestamp, *_ = stamp.read_text().splitlines() + [""]
    except OSError:
        return True
    if old_signature != current_signature:
        return True
    value = str(ttl if ttl is not None else os.environ.get("HOUSEKEEPING_UNCHANGED_RERUN_SECS", "3600"))
    seconds = int(value) if value.isdigit() else 3600
    if seconds <= 0:
        return False
    if not old_timestamp.isdigit():
        return True
    return int(time.time()) - int(old_timestamp) >= seconds


def mark_clean(label: str, current_signature: str) -> None:
    if not current_signature:
        return
    stamp = stamp_path(label)
    if stamp is None:
        return
    temporary = stamp.with_name(f".{stamp.name}.{os.getpid()}.tmp")
    try:
        temporary.write_text(f"{current_signature}\n{int(time.time())}\n")
        os.replace(temporary, stamp)
    except OSError:
        pass
    finally:
        temporary.unlink(missing_ok=True)
