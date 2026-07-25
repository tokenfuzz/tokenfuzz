#!/usr/bin/env python3
"""Read-only structured JSONL state queries for audit orchestration."""

from __future__ import annotations

import argparse
import json
import os
import re
import stat as stat_module
import threading
from pathlib import Path

from subsystem_paths import load_subsystems, subsystem_from_path


ACTIVE = {"PENDING", "INVESTIGATING", "NEEDS_TESTCASE"}
COUNTED_STATUS = re.compile(
    r"^(PENDING|INVESTIGATING|NEEDS_TESTCASE|DISCARDED|CRASH|CRASH-|FIND|FIND-|ENV-BLOCKED)$"
)

# One iteration funnels many queries (progress, cold-check, prompt builds)
# through rows(); each re-parsed the whole growing hypotheses.jsonl. Cache the
# parsed snapshot keyed on a full stat signature so an unchanged file is parsed
# once: an append changes size, an atomic replace changes st_ino, and any other
# write bumps st_mtime_ns/st_ctime_ns — so every edit invalidates transparently
# (ctime cannot be forged back, so even an mtime-preserving restore is caught).
# Callers get byte-identical rows; returned lists are read-only by contract.
_ROWS_CACHE: dict[str, tuple[tuple[int, int, int, int], list[dict]]] = {}
_ROWS_CACHE_LOCK = threading.Lock()


def hypotheses_path(results_dir: str | os.PathLike | None = None) -> Path:
    root = Path(results_dir if results_dir is not None else os.environ.get("RESULTS_DIR", ""))
    return root / "state" / "hypotheses.jsonl"


def rows(results_dir: str | os.PathLike | None = None) -> list[dict]:
    path = hypotheses_path(results_dir)
    try:
        info = path.stat()
    except OSError:
        return []
    if not stat_module.S_ISREG(info.st_mode) or info.st_size == 0:
        return []
    key = str(path)
    signature = (info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
    with _ROWS_CACHE_LOCK:
        cached = _ROWS_CACHE.get(key)
        if cached is not None and cached[0] == signature:
            return cached[1]
    output = []
    with path.open(encoding="utf-8", errors="replace") as stream:
        for line in stream:
            try:
                value = json.loads(line)
            except (TypeError, ValueError):
                continue
            if isinstance(value, dict):
                output.append(value)
    with _ROWS_CACHE_LOCK:
        _ROWS_CACHE[key] = (signature, output)
    return output


def agent_rows(agent: str, results_dir: str | os.PathLike | None = None) -> list[dict]:
    return [row for row in rows(results_dir) if row.get("agent", "") == agent]


def count_agent(agent: str, pattern: str, results_dir: str | os.PathLike | None = None) -> int | None:
    selected = agent_rows(agent, results_dir)
    if not selected:
        return None
    regex = re.compile(pattern)
    return sum(bool(regex.search(str(row.get("status", "")))) for row in selected)


def count_all(pattern: str, results_dir: str | os.PathLike | None = None) -> int | None:
    selected = rows(results_dir)
    if not selected:
        return None
    regex = re.compile(pattern)
    return sum(bool(regex.search(str(row.get("status", "")))) for row in selected)


def agent_counts(agent: str, results_dir: str | os.PathLike | None = None) -> dict[str, int] | None:
    selected = agent_rows(agent, results_dir)
    if not selected:
        return None
    statuses = [str(row.get("status", "")) for row in selected]
    pending = statuses.count("PENDING")
    investigating = statuses.count("INVESTIGATING")
    needs = statuses.count("NEEDS_TESTCASE")
    return {
        "rows": len(selected),
        "pending": pending,
        "investigating": investigating,
        "needs_testcase": needs,
        "active": pending + investigating + needs,
        "discards": statuses.count("DISCARDED"),
        "env_blocked": statuses.count("ENV-BLOCKED"),
        "result": sum(status.startswith(("CRASH", "FIND")) for status in statuses),
        "total": sum(bool(COUNTED_STATUS.match(status)) for status in statuses),
    }


def agents(results_dir: str | os.PathLike | None = None) -> list[str]:
    return sorted({str(row["agent"]) for row in rows(results_dir) if row.get("agent") not in (None, "")})


def known_subsystems() -> list[str]:
    if os.environ.get("IS_BROWSER_TARGET", "0") != "1":
        return []
    slug = os.environ.get("TARGET_SLUG", "firefox")
    path = Path(__file__).parent / "subsystems" / f"{slug}.txt"
    if not path.is_file():
        return []
    return load_subsystems(path)


def file_subsystem(path: str) -> str:
    return subsystem_from_path(path, subsystems=known_subsystems())


def agent_subsystem(agent: str) -> str | None:
    selected = agent_rows(agent)
    if not selected:
        return None
    active_pattern = re.compile(r"^(PENDING|INVESTIGATING|NEEDS_TESTCASE|ENV-BLOCKED|CRASH|CRASH-|FIND|FIND-)")
    active = [row for row in selected if active_pattern.search(str(row.get("status", "")))]
    path = str((active[-1] if active else selected[-1]).get("file", ""))
    return file_subsystem(path) if path else None


def latest_strategy(agent: str) -> str | None:
    values = [
        str(row.get("strategy", ""))
        for row in agent_rows(agent)
        if row.get("status") != "DISCARDED" and row.get("strategy")
    ]
    return values[-1] if values else None


def main() -> int:
    parser = argparse.ArgumentParser(prog="structured_state")
    parser.add_argument("command", choices=("path", "has-rows", "count-agent", "count-all", "counts", "agents", "subsystem", "agent-subsystem", "latest-strategy"))
    parser.add_argument("values", nargs="*")
    args = parser.parse_args()
    values = args.values
    if args.command == "path":
        print(hypotheses_path())
        return 0
    if args.command == "has-rows":
        return 0 if values and agent_rows(values[0]) else 1
    if args.command == "count-agent":
        value = count_agent(values[0], values[1]) if len(values) >= 2 else None
    elif args.command == "count-all":
        value = count_all(values[0]) if values else None
    elif args.command == "counts":
        result = agent_counts(values[0]) if values else None
        if result is None:
            return 1
        print("|".join(str(result[key]) for key in ("rows", "pending", "investigating", "needs_testcase", "discards", "env_blocked", "result", "total")))
        return 0
    elif args.command == "agents":
        print("\n".join(agents()))
        return 0
    elif args.command == "subsystem":
        value = file_subsystem(values[0]) if values else None
    elif args.command == "agent-subsystem":
        value = agent_subsystem(values[0]) if values else None
    else:
        value = latest_strategy(values[0]) if values else None
    if value is None:
        return 1
    print(value)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
