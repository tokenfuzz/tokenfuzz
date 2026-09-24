#!/usr/bin/env python3
"""Build the bounded, non-noise libFuzzer lead index."""

from __future__ import annotations

import heapq
import os
import stat
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

import fuzz_campaign
import fuzz_harness


TOOL = "triage"
# Where `bin/run-<san> fuzz` (FUZZER=<name>) writes. `bin/fuzz run` writes
# under `fuzz_harness.artifacts_root` instead; the index reads both.
LEGACY_DIRNAME = "fuzz-crashes"
DEFAULT_MAX_LEADS = 20
SHUTDOWN_SHA1 = "crash-da39a3ee5e6b4b0d3255bfef95601890afd80709"
CANDIDATE_PREFIXES = ("crash-", "oom-", "timeout-")


@dataclass(frozen=True)
class Candidate:
    path: Path
    mtime: int
    size: int
    # Whether a `bin/fuzz` campaign wrote it, which decides how it replays.
    campaign: bool = False


def _lead(path: Path, campaign: bool = False) -> "Candidate | None":
    if not path.name.startswith(CANDIDATE_PREFIXES) or path.name == SHUTDOWN_SHA1:
        return None
    try:
        info = path.lstat()
    except OSError:
        return None
    if not stat.S_ISREG(info.st_mode) or info.st_size == 0:
        return None
    return Candidate(path=path, mtime=int(info.st_mtime), size=info.st_size,
                     campaign=campaign)


def parse_limit(raw: str) -> int | None:
    if not raw.isascii() or not raw.isdigit():
        return None
    return int(raw)


def candidates(fuzz_root: Path):
    def ignore_walk_error(_error: OSError) -> None:
        return

    for current, directories, names in os.walk(
        fuzz_root, topdown=True, followlinks=False, onerror=ignore_walk_error
    ):
        directories[:] = [name for name in directories if name != "shutdown-noise"]
        current_path = Path(current)
        for name in names:
            lead = _lead(current_path / name)
            if lead is not None:
                yield lead


def campaign_candidates(results: Path):
    """`bin/fuzz` artifacts no campaign has replayed through `bin/probe` yet.

    A replayed artifact is already filed, duplicate, or clean; listing it
    would keep an idle slot launching on work that is done.
    """
    root = fuzz_harness.artifacts_root(results)
    try:
        harnesses = sorted(path.name for path in root.iterdir() if path.is_dir())
    except OSError:
        return
    states = fuzz_campaign.load_states(results)
    for name in harnesses:
        state = states.get(name) or fuzz_campaign.HarnessState(name=name, binary="")
        for path in fuzz_campaign.unreplayed_artifacts(results, state):
            lead = _lead(path, campaign=True)
            if lead is not None:
                yield lead


def newest_candidates(fuzz_root: Path, limit: int,
                      results: "Path | None" = None) -> list[Candidate]:
    found = list(candidates(fuzz_root))
    if results is not None:
        found.extend(campaign_candidates(results))
    return heapq.nlargest(
        limit,
        found,
        key=lambda item: (item.mtime, os.fsencode(str(item.path))),
    )


def render_no_leads(message: str) -> str:
    # Only a heading and italic lines, which `prompt.fuzz_leads_empty` reads
    # as no lead; guidance text here would keep idle slots launching.
    return "\n".join(["# Fuzz Crash Leads", "", f"_{message}_", ""])


def render_leads(
    leads: list[Candidate], max_leads: int, results: Path, results_display: str,
) -> str:
    if not leads:
        return render_no_leads("No non-noise fuzz crashes found.")
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    lines = [
        "# Fuzz Crash Leads",
        "",
        f"_Generated {generated} — newest first, max {max_leads}._",
        "",
        "Each lead is a libFuzzer artifact that survived infrastructure-noise",
        "filtering and no campaign has replayed. Replay it with the command",
        "on its entry; if the trace points at product code (not the libFuzzer",
        "runtime or a shutdown path), add a hypothesis row and write a minimal",
        "hand-authored testcase that reaches the same sink.",
        "",
        "---",
        "",
    ]
    for lead in leads:
        fuzzer = lead.path.parent.name
        display_path = f"{results_display}/{lead.path.relative_to(results)}"
        modified = datetime.fromtimestamp(lead.mtime, timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
        if lead.campaign:
            replay = (
                f"- **Replay:** `bin/fuzz run` replays harness `{fuzzer}`'s "
                "unreplayed artifacts through `bin/probe --confirm` before "
                "any new slice"
            )
        else:
            replay = (
                f"- **Reproduce:** `FUZZER={fuzzer} bin/run-asan fuzz-repro "
                f"{display_path}`"
            )
        lines.extend(
            [
                f"## {fuzzer} / {lead.path.name}",
                "",
                f"- **Path:** `{display_path}`",
                f"- **Size:** {lead.size} bytes",
                f"- **Modified:** {modified}",
                replay,
                "",
            ]
        )
    return "\n".join(lines) + "\n"


def atomic_write(path: Path, content: str) -> None:
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary_path = Path(temporary)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            output.write(content)
            output.flush()
        temporary_path.chmod(0o644)
        os.replace(temporary_path, path)
    finally:
        try:
            temporary_path.unlink()
        except FileNotFoundError:
            pass


def update_fuzz_leads(
    results_arg: str | os.PathLike[str], max_leads: int,
) -> tuple[int, str]:
    """Rewrite fuzz-leads.md and return ``(status, log_line)``.

    The empty log line for a missing fuzz root matches the CLI's deliberately
    quiet first-run marker. Errors are returned so Python callers retain the
    command's fail-open boundary without a child interpreter.
    """
    results_text = os.fspath(results_arg)
    results = Path(results_text)
    fuzz_root = results / LEGACY_DIRNAME
    output = results / "fuzz-leads.md"
    output_display = f"{results_text}/fuzz-leads.md"
    try:
        if not fuzz_root.is_dir() and not fuzz_harness.artifacts_root(results).is_dir():
            atomic_write(output, render_no_leads(
                "No fuzz artifacts yet — run a fuzz target first."))
            return 0, ""
        leads = newest_candidates(fuzz_root, max_leads, results)
        atomic_write(
            output, render_leads(leads, max_leads, results, results_text),
        )
    except OSError as error:
        return 1, f"[{TOOL}] failed to write {output_display}: {error}"

    return 0, f"[{TOOL}] wrote {output_display} ({len(leads)} leads)"
