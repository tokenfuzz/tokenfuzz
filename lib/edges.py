#!/usr/bin/env python3
"""Coverage-edge extraction, novelty tracking, and atomic journals."""

from __future__ import annotations

import argparse
import fcntl
import os
import re
import tempfile
from collections import Counter
from pathlib import Path


DEFAULT_NOISE_RE = r"__asan|__sanitizer|__interceptor|libc\+\+abi|libsystem_|libobjc|libdyld|^_dyld_|libsancov|asan_interceptors|^_dispatch_|^_pthread_|^start\+|^_main$|^XPCOMGlueLoad|^NS_LogInit|^NSApplicationMain"


def results_root(slug: str = "") -> Path | None:
    explicit = os.environ.get("EDGES_RESULTS_DIR") or os.environ.get("RESULTS_DIR")
    if explicit:
        return Path(explicit)
    script_root = os.environ.get("SCRIPT_ROOT")
    if not slug or not script_root:
        return None
    output_slug = os.environ.get("TARGET_OUTPUT_SLUG", slug)
    experiment = os.environ.get("AUDIT_EXPERIMENT_NAME", "")
    suffix = os.environ.get("AUDIT_EXPERIMENT_SUFFIX", "")
    if experiment:
        output_slug = f"{output_slug}-{experiment}{suffix}"
    root = Path(script_root) / "output" / output_slug
    return root / "results" if (root / "results").is_dir() else root


def root(slug: str = "") -> Path | None:
    base = results_root(slug)
    if base is None:
        return None
    destination = base / "coverage"
    destination.mkdir(parents=True, exist_ok=True)
    return destination


def journal_path(slug: str, agent: str = "1") -> Path | None:
    directory = root(slug)
    return None if directory is None else directory / f"edges-agent-{agent}.journal"


def extract(path: str | Path, noise_pattern: str | None = None) -> list[str]:
    source = Path(path)
    if not source.is_file() or source.stat().st_size == 0:
        return []
    configured_noise = (os.environ.get("EDGES_NOISE_RE") or DEFAULT_NOISE_RE) if noise_pattern is None else noise_pattern
    noise = re.compile(configured_noise) if configured_noise else None
    output: set[str] = set()
    function = ""
    for raw in source.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if not line:
            function = ""
        elif not function:
            function = line
        else:
            location = re.sub(r":[0-9]+$", "", line)
            if function not in ("", "??") and location not in ("", "??", "??:0"):
                edge = f"{function}|{location}"
                if noise is None or not noise.search(edge):
                    output.add(edge)
            function = ""
    return sorted(output)


def master_union(slug: str = "") -> list[str]:
    directory = root(slug)
    if directory is None:
        return []
    output: set[str] = set()
    for journal in sorted(directory.glob("edges-agent-*.journal")):
        if journal.is_file():
            output.update(line for line in journal.read_text(errors="replace").splitlines() if line)
    return sorted(output)


def file_edges(path: str | Path) -> set[str]:
    source = Path(path)
    return set(source.read_text(errors="replace").splitlines()) if source.is_file() and source.stat().st_size else set()


def diff_new(slug: str, run_file: str | Path) -> list[str]:
    return sorted(file_edges(run_file) - set(master_union(slug)))


def record_run(slug: str, agent: str, run_file: str | Path) -> None:
    incoming = file_edges(run_file)
    if not incoming:
        return
    journal = journal_path(slug, agent)
    if journal is None:
        return
    lock_path = journal.with_suffix(journal.suffix + ".lock")
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with lock_path.open("a+") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        existing = file_edges(journal)
        merged = sorted(existing | (incoming - set(master_union(slug))))
        if merged == sorted(existing):
            return
        fd, temporary = tempfile.mkstemp(prefix=f".{journal.name}.", dir=journal.parent)
        try:
            with os.fdopen(fd, "w") as stream:
                stream.write("\n".join(merged) + "\n")
            os.replace(temporary, journal)
        finally:
            Path(temporary).unlink(missing_ok=True)


def subsystem_counts(slug: str = "", depth: int = 2) -> list[tuple[str, int]]:
    counts: Counter[str] = Counter()
    for edge in master_union(slug):
        _, separator, location = edge.partition("|")
        if not separator:
            continue
        path = re.sub(r":[0-9]+$", "", location)
        parts = path.split("/")
        counts["/".join(parts[: min(len(parts), depth)])] += 1
    return sorted(counts.items(), key=lambda item: (-item[1], item[0]))


def log_line_has_new_edges(line: str) -> bool:
    match = re.search(r"(?:^|\s)new=([0-9]+)(?:\s|$)", line)
    return bool(match and int(match.group(1)) > 0)


def main() -> int:
    parser = argparse.ArgumentParser(prog="edges")
    parser.add_argument("command", choices=("root", "journal", "extract", "union", "diff", "count-new", "record", "summary", "log-has-new"))
    parser.add_argument("values", nargs="*")
    args = parser.parse_args()
    values = args.values
    if args.command == "root":
        value = root(values[0] if values else "")
        if value is None:
            return 1
        print(value, end="")
    elif args.command == "journal":
        value = journal_path(values[0] if values else "", values[1] if len(values) > 1 else "1")
        if value is None:
            return 1
        print(value, end="")
    elif args.command == "extract":
        print("\n".join(extract(values[0] if values else "")))
    elif args.command == "union":
        print("\n".join(master_union(values[0] if values else "")))
    elif args.command in ("diff", "count-new"):
        result = diff_new(values[0], values[1]) if len(values) >= 2 else []
        print(len(result) if args.command == "count-new" else "\n".join(result), end="" if args.command == "count-new" else "\n")
    elif args.command == "record":
        record_run(values[0], values[1], values[2])
    elif args.command == "summary":
        slug = values[0] if values else ""
        depth = int(values[1]) if len(values) > 1 and values[1].isdigit() else 2
        print("\n".join(f"{name}\t{count}" for name, count in subsystem_counts(slug, depth)))
    else:
        return 0 if values and log_line_has_new_edges(values[0]) else 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
