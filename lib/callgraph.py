#!/usr/bin/env python3
"""Read the call-neighbourhood artifact and render it for a work card.

`bin/callgraph` produces the artifact under a separate interpreter; nothing
here imports trailmark, so the harness keeps running wherever it runs today.
Every path through this module falls open: no interpreter configured, no
artifact, a stale artifact, a file the parser never saw, or a graph too
incomplete to trust all render as "no block", which is the behaviour that
existed before this file.

The block is context, never a filter — the same contract
`prompt._ruled_out_routes` holds. A syntactic call graph is blind to indirect
dispatch, so "no path" is not evidence of unreachability and must never gate
a card, floor a severity, or feed a triage verdict.
"""

from __future__ import annotations

import hashlib
import itertools
import json
import os
import shutil
import sys
import tempfile
from pathlib import Path

import languages
import target_config
import timeout
import workqueue

ARTIFACT_NAME = "callgraph.json"

# Bump when the artifact's shape or the policy that fills it changes, so a
# stale artifact is rebuilt rather than read under new rules.
SCHEMA_VERSION = 3

# The unit pack is bounded in tokens, not units: it carries the definitions
# an agent would otherwise spend its first tool calls opening, and at 600
# tokens (the ~4 chars/token heuristic lib/llm_usage.py estimates with) it
# costs less than one such read. An excerpt is whole or absent — a definition
# cut mid-signature reads as a different function — and the per-line clip
# keeps one generated line from spending the whole pack.
PACK_TOKEN_CAP = 600
PACK_CHAR_CAP = PACK_TOKEN_CAP * 4
EXCERPT_LINES_BEFORE = 1
EXCERPT_LINES_AFTER = 4
EXCERPT_LINE_CHARS = 120

# A C definition whose return type is wrapped in an export macro above the
# name is not extracted, and those are disproportionately a library's public
# entry points. Measured against five native targets' own ASan builds, symbol
# coverage ran 29–100%, and the low end had lost its whole public boundary. A
# map missing that boundary misleads more than it helps, so suppress the block
# rather than show a partial neighbourhood as if it were the whole one.
MIN_COVERAGE = 0.75

# The largest target this analysis has ever produced a block for holds ~850
# auditable files and parses in ~12s at ~450 MB. A browser tree holds ~63k,
# costs ~6s of staging and ~940 MB of symlinks before the parser even starts,
# and has never yielded a block — so decline it on the cheap count rather than
# discover it minutes later. The ceilings then bound a parse that was worth
# starting: they are not performance knobs, and content-keying plus cached
# failures mean an ineligible tree pays once per revision, not per iteration.
MAX_TREE_FILES = 5000
BUILD_TIMEOUT_SECONDS = 300
BUILD_RSS_MB = 2048

# An interpreter probe is one import; anything slower is a broken environment,
# not a slow one.
PROBE_TIMEOUT_SECONDS = 30

# Resolved interpreter for this process: "" means none works, None means the
# candidates have not been tried yet. _TOOLCHAIN records what it reported.
_RESOLVED: str | None = None
_TOOLCHAIN = ""


def artifact_path(results_dir: Path) -> Path:
    return Path(results_dir) / "state" / ARTIFACT_NAME


def _sidecar() -> Path:
    return Path(__file__).resolve().parent.parent / "bin" / "callgraph"


def candidate_interpreters() -> list[str]:
    """Interpreters to try, best first.

    trailmark needs Python >= 3.12 plus packages the harness does not depend
    on, so it will not always be the interpreter running this code — but it
    often is, and `pip install trailmark` is then the whole setup. This
    process first, then PATH, covers both: run the harness from the
    environment holding trailmark, or install it into a `python3` that is
    already there. The versioned names exist because a platform `python3` is
    routinely older than trailmark's floor; the list runs from newest down to
    that floor and needs extending only when a newer Python ships.
    """
    return [
        sys.executable,
        "python3.15", "python3.14", "python3.13", "python3.12", "python3",
    ]


def _toolchain() -> str:
    """Interpreter and library versions the graph would be built with.

    Part of the cache fingerprint, and the reason the sidecar can keep reading
    trailmark's graph object directly: a parser upgrade that moved that
    structure invalidates every artifact built against the old one instead of
    silently changing what the block claims.
    """
    interpreter()
    return _TOOLCHAIN


def interpreter() -> str:
    """First candidate that can actually run the analysis, or "".

    Selection asks `bin/callgraph --probe`, which runs the same import and
    version checks the real build does, so nothing can pass here and fail
    there. There is no override: an interpreter this search cannot see is one
    the operator can put on PATH or run the harness from, and a knob for the
    remainder would be configuration nobody needs to vary.

    Memoised per process: a run resolves this once, and the callers that
    matter only ask when a rebuild is due.
    """
    global _RESOLVED, _TOOLCHAIN
    if _RESOLVED is None:
        _RESOLVED = ""
        for candidate in candidate_interpreters():
            # Resolve before spawning. Most of the versioned names are absent
            # on any given host, and skipping them here is what keeps the
            # "trailmark is not installed" answer — the common one — down to
            # the interpreters that actually exist.
            if not (os.path.isabs(candidate) and os.access(candidate, os.X_OK)) \
                    and shutil.which(candidate) is None:
                continue
            probe = timeout.run_timeout(
                [candidate, str(_sidecar()), "--probe"],
                PROBE_TIMEOUT_SECONDS, kill=True, capture_output=True, text=True,
            )
            if probe.returncode == 0:
                _RESOLVED = candidate
                # Version text is a fingerprint input, not a
                # requirement: a probe that reports nothing still
                # selected a working interpreter.
                # `callgraph: ready <versions>` — keep the versions.
                text = " ".join(str(getattr(probe, "stdout", "") or "").split())
                _TOOLCHAIN = text.split("ready", 1)[-1].strip()
                break
    return _RESOLVED


def status() -> str:
    """One line for the run log: whether this will contribute anything.

    An audit that silently ships work cards without the context an operator
    thinks they enabled is indistinguishable from one where the analysis ran
    and found nothing, so the run says which it is exactly once, at startup.
    """
    python = interpreter()
    if not python:
        return ("WARN: source call-graph context unavailable — trailmark is not "
                "importable from this interpreter or any python3 on PATH; work "
                "cards ship without caller/callee context "
                "(pip install trailmark to enable)")
    return (f"Source call-graph context: enabled via {python}"
            f" ({_TOOLCHAIN or 'versions unreported'})")


def load(results_dir: Path) -> dict | None:
    try:
        data = json.loads(artifact_path(results_dir).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) and data.get("version") == SCHEMA_VERSION else None


def cache_signature(target_root: Path, results_dir: Path,
                    artifacts: tuple[str, str] | None = None) -> str:
    """Identity of every input the graph depends on, or "" when unknowable.

    Source content alone is not enough. The boundary comes from the sanitizer
    route in target.toml and from the built artifact's symbol table, and the
    graph itself comes from a specific trailmark and tree-sitter — so pointing
    `asan_bin` at a different binary, or upgrading the parser, changes the
    answer without changing a line of source. Keying on source alone kept
    serving the old boundary.

    Empty is not a value to cache against: a target with no VCS would hold one
    signature forever and keep serving a map of source that has since changed,
    which is worse than the cost of re-deriving it. The size guard bounds what
    that costs.
    """
    if not interpreter():
        # Nothing to key: with no analysis available the outer gate should not
        # churn work cards, and refresh() reports the absence on its own.
        return ""
    source = target_config.vcs_source_signature(target_root, include_untracked=False)
    if not source:
        return ""
    parts = [f"schema={SCHEMA_VERSION}", f"source={source}", f"tools={_toolchain()}"]
    for artifact in (artifacts if artifacts is not None else _built_artifacts(target_root, results_dir)):
        try:
            stat = Path(artifact).stat() if artifact else None
        except OSError:
            stat = None
        parts.append(
            f"artifact={artifact}:{stat.st_size}:{stat.st_mtime_ns}" if stat
            else f"artifact={artifact}:-"
        )
    return hashlib.sha1("\n".join(parts).encode()).hexdigest()


def _built_artifacts(target_root: Path, results_dir: Path) -> tuple[str, str]:
    """(code universe, entry binary) as absolute paths, or empty strings.

    The library holds the audited code and answers "how much of it did the
    parser see"; the executable answers "which main() is this target's
    boundary" when the tree defines a dozen. Both come from the sanitizer
    route the target actually runs — a UBSan-only target has no `asan_bin`,
    and reading that field alone left it with no boundary at all. Either may
    be absent (a findings-only target has neither) and the analysis degrades
    to neighbours without paths rather than refusing to run.
    """
    toml_path = target_config.find_target_toml(results_dir)
    if toml_path is None:
        return "", ""
    config = target_config.Config()
    config.target_root = str(target_root)
    try:
        target_config.load_toml_into(config, toml_path)
    except (OSError, ValueError):
        return "", ""

    def existing(value: str) -> str:
        resolved = config.resolve_path(value) if value else ""
        return resolved if resolved and Path(resolved).is_file() else ""

    route = config.first_executable_sanitizer()
    name = route[0] if route else (config.sanitizers_enabled[:1] or ["asan"])[0]
    entry = route[1] if route else existing(config.sanitizer_bin(name))
    return existing(config.sanitizer_lib(name)) or entry, entry


def _auditable_sources(ctx: workqueue.Context) -> tuple[list[str], list[str]]:
    """Relative paths rank-work would consider, and their trailmark languages.

    Scoping to auditable paths keeps the language list off build scaffolding:
    a generated dependency stamp carries a `.ts` suffix and would otherwise
    enlist a whole extra grammar.
    """
    paths: list[str] = []
    names: set[str] = set()
    for path in workqueue.iter_source_files(ctx.target_root):
        rel = workqueue.relpath(path, ctx.target_root)
        if not workqueue.is_auditable_source_path(rel):
            continue
        paths.append(rel)
        language = languages.for_source_ext(Path(rel).suffix.lower())
        if language is not None:
            names.add(language.name)
    return paths, sorted(names)


def _link_sources(target_root: Path, sources: list[str], mirror: Path) -> None:
    """Symlink the auditable files into a tree the parser may read whole.

    This is the trust boundary. trailmark reads `.trailmark/links.toml` and
    `.trailmark/entrypoints.toml` from the root it is given, and a link entry
    may declare an arbitrary call edge at `confidence = "certain"` — so a file
    inside the audited tree can mint the exact evidence this block renders. A
    tree the target did not author cannot do that, and the same mirror answers
    the second problem for free: the parser now sees precisely the files
    rank-work considers auditable, so a test driver or example cannot become
    an entry root or a caller.
    """
    for rel in sources:
        link = mirror / rel
        link.parent.mkdir(parents=True, exist_ok=True)
        os.symlink(target_root / rel, link)


def _record(ctx: workqueue.Context, signature: str, reason: str) -> str:
    """Stamp a disposition against this fingerprint so it is not re-derived.

    Failures are cached too, not just refusals: a tree the parser cannot
    handle fails the same way every iteration, and the fingerprint already
    covers the interpreter and tool versions, so repairing the environment
    invalidates the record on its own.
    """
    path = artifact_path(ctx.results_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    body = json.dumps({
        "version": SCHEMA_VERSION, "signature": signature,
        "skipped": reason, "files": {},
    })
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        temporary.write_text(body, encoding="utf-8")
        os.replace(temporary, path)
    except OSError:
        temporary.unlink(missing_ok=True)
    return reason


def refresh(ctx: workqueue.Context) -> str:
    """Rebuild the artifact when any input to the graph changed. Never raises.

    Content-keyed like the work-card refresh in
    `audit_runner._work_card_signature`, so a run pays the parse once per
    revision rather than once per iteration. Under the benchmark wall rules
    this is steering and its cost is counted; keying is what keeps it small.
    """
    artifacts = _built_artifacts(ctx.target_root, ctx.results_dir)
    signature = cache_signature(ctx.target_root, ctx.results_dir, artifacts)
    existing = load(ctx.results_dir)
    if signature and existing is not None and existing.get("signature") == signature:
        return existing.get("skipped") or "fresh"
    # Past this point the artifact on disk cannot describe the current source,
    # and nothing downstream re-checks that: `block_for` is handed a results
    # directory, not a target. Dropping it here is what bounds a stale map's
    # life to one refresh — including when the analysis is switched off after
    # a run has already built one.
    if existing is not None:
        artifact_path(ctx.results_dir).unlink(missing_ok=True)

    python = interpreter()
    if not python:
        return "no trailmark interpreter"
    sources, names = _auditable_sources(ctx)
    if not sources:
        return "skipped: no auditable source"
    if len(sources) > MAX_TREE_FILES:
        return _record(ctx, signature, f"skipped: over {MAX_TREE_FILES} auditable files")
    api_artifact, entry_artifact = artifacts
    out = artifact_path(ctx.results_dir)
    out.parent.mkdir(parents=True, exist_ok=True)

    mirror = Path(tempfile.mkdtemp(prefix=".callgraph-tree-", dir=str(out.parent)))
    try:
        _link_sources(ctx.target_root, sources, mirror)
        command = [
            python, str(_sidecar()),
            "--root", str(mirror),
            "--out", str(out),
            "--language", ",".join(names) or "auto",
            "--signature", signature,
        ]
        if api_artifact:
            command += ["--api-artifact", api_artifact]
        if entry_artifact:
            command += ["--entry-artifact", entry_artifact]
        completed = timeout.run_timeout(
            command, BUILD_TIMEOUT_SECONDS, kill=True, rss_mb=BUILD_RSS_MB,
            capture_output=True, text=True,
        )
    except (OSError, ValueError) as exc:
        return _record(ctx, signature, f"unavailable: {exc}")
    finally:
        shutil.rmtree(mirror, ignore_errors=True)

    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout or "").strip().splitlines()
        return _record(
            ctx, signature,
            f"unavailable: {detail[-1] if detail else f'rc={completed.returncode}'}",
        )
    return "built"


def _coverage_note(data: dict) -> tuple[bool, str]:
    coverage = data.get("coverage") or {}
    ratio = coverage.get("ratio")
    if ratio is None:
        return True, "symbol coverage unmeasured (no built artifact to compare against)"
    if ratio < MIN_COVERAGE:
        return False, ""
    return True, f"{ratio:.0%} of the built target's symbols were parsed"


def _definition_window(path: Path, line: int) -> list[tuple[int, str]]:
    """Numbered lines around a definition, clipped; [] when unreadable.

    Reads only up to the last wanted line rather than the file: the sources
    this serves are the parsed tree's, and their large files are the ones
    whose definitions sit deepest.
    """
    first = max(1, line - EXCERPT_LINES_BEFORE)
    last = line + EXCERPT_LINES_AFTER
    try:
        with path.open("rb") as source:
            rows = list(itertools.islice(source, first - 1, last))
    except OSError:
        return []
    return [
        (first + index, raw.decode("utf-8", "replace").rstrip("\r\n")[:EXCERPT_LINE_CHARS])
        for index, raw in enumerate(rows)
    ]


def _unit_pack(entry: dict, target_root: Path) -> list[str]:
    """Definition excerpts for the file's key callers and callees, bounded.

    Whole excerpts are added in artifact order until the next would cross
    PACK_CHAR_CAP; a file that yields none renders no pack at all.
    """
    lines = [
        "- **Unit excerpts** (the definition lines of each routed function's "
        "key caller and callee, static and bounded):",
    ]
    used = sum(len(text) + 1 for text in lines)
    kept = 0
    for row in entry.get("excerpts") or []:
        rel = workqueue.normalized_relpath(row.get("file", ""))
        line = int(row.get("line") or 0)
        if not rel or line < 1 or ".." in rel.split("/"):
            continue
        window = _definition_window(Path(target_root) / rel, line)
        if not window:
            continue
        relation = (
            f"calls `{row.get('of', '')}`" if row.get("role") == "caller"
            else f"called by `{row.get('of', '')}`"
        )
        chunk = [f"  - `{row.get('function', '')}` (`{rel}:{line}`) {relation}:"]
        chunk += [f"        {number} | {text}" for number, text in window]
        size = sum(len(text) + 1 for text in chunk)
        if used + size > PACK_CHAR_CAP:
            break
        lines += chunk
        used += size
        kept += 1
    return lines if kept else []


def block_for(results_dir: Path, file: str, target_root: Path | None = None) -> list[str]:
    """Markdown lines describing who calls this file and how input reaches it.

    Returns [] whenever the answer would be partial or absent: the agent gets
    the map it had before rather than a map with holes it cannot see. With a
    `target_root`, the block also carries the unit pack — excerpts read from
    that tree at the definition sites the artifact recorded.
    """
    rel = workqueue.normalized_relpath(file)
    if not rel:
        return []
    data = load(results_dir)
    if data is None:
        return []
    entry = (data.get("files") or {}).get(rel)
    if not entry:
        return []
    def neighbours(key: str) -> str:
        # The number is distinct functions, not call sites — say which.
        rows = entry.get(key) or []
        return ", ".join(f"`{name}`({count} fn)" for name, count in rows) \
            or "no direct parsed edge observed"

    paths = [row for row in (entry.get("paths") or []) if row.get("function")]
    routed = [row for row in paths if len(row.get("path") or []) > 1]
    # A block with no neighbour and no route is an entry-boundary claim, two
    # "none in this tree" lines and a caveat: ~300 tokens that answer nothing.
    # Measured across seven non-native targets, that is what every card got,
    # because cross-file resolution is weak there and no built artifact exists
    # to anchor a boundary. Coverage cannot catch it — there is nothing to
    # measure against — so require the block to carry something instead.
    if not (entry.get("callers") or entry.get("callees") or routed):
        return []

    lines = [
        "",
        "### Call neighbourhood (static, `bin/callgraph`)",
        "",
    ]
    trustworthy, note = _coverage_note(data)
    if routed and trustworthy:
        # The boundary is only worth naming when it reached this file and the
        # parse saw enough of the built target to stand behind it. Coverage
        # gates this section alone: it measures how much of the symbol table
        # the parser matched, which bears on "main reaches here" and not at
        # all on whether one parsed file calls another.
        boundary = data.get("entry") or {}
        roots = ", ".join(f"`{name}`" for name in (boundary.get("roots") or [])[:3])
        extra = boundary.get("root_count", 0) - 3
        if extra > 0:
            roots += f" (+{extra} more)"
        artifact = boundary.get("artifact") or ""
        lines.append(
            f"- **Observed entry roots:** {roots or 'none detected'}"
            + (f" in `{artifact}`" if artifact else "")
            + f" — {note}."
        )
    lines += [
        f"- **Audited files calling `{rel}`:** {neighbours('callers')}",
        f"- **`{rel}` calls into:** {neighbours('callees')}",
    ]
    if routed and trustworthy:
        lines.append("- **Shortest path from that boundary:**")
        for row in paths:
            chain = row.get("path") or []
            if not chain:
                route = "no direct-call path found"
            elif len(chain) == 1:
                # The function is a root. Printing a one-element path would
                # read as a truncated route rather than as the boundary.
                route = "is itself on the entry boundary"
            else:
                route = " -> ".join(chain)
            lines.append(f"    - `{row['function']}`: {route}")
    if target_root is not None:
        lines += _unit_pack(entry, target_root)
    lines.append(
        "  Scope: syntactically resolved calls between files rank-work "
        "considers auditable — test, example, doc and fuzz trees are outside "
        "it, vendored product source is not. Indirect dispatch (callback "
        "tables, function pointers, macro-generated names) is invisible. An "
        "unobserved edge is not evidence of unreachability and is never "
        "grounds to discard the card or downgrade a finding."
    )
    return lines


def explain(results_dir: Path, file: str) -> str:
    """Why `block_for` produced nothing, for an operator checking the install.

    Each fall-open branch above is silent by design; this names which one
    fired so "it is not showing up" has an answer that is not a code read.
    """
    data = load(results_dir)
    if data is None:
        if not interpreter():
            return ("trailmark is not importable from any interpreter this "
                    "harness can see; `pip install trailmark`")
        return f"no artifact at {artifact_path(results_dir)}; run bin/rank-work first"
    if data.get("skipped"):
        return str(data["skipped"])
    rel = workqueue.normalized_relpath(file)
    entry = (data.get("files") or {}).get(rel)
    if entry is None:
        return f"{rel} is not in the parsed graph ({len(data.get('files') or {})} files)"
    if not block_for(results_dir, file):
        return (f"{rel} has no cross-file caller, callee, or entry path — "
                f"the block would say nothing")
    return ""


def main(argv: list[str]) -> int:
    """`python3 lib/callgraph.py --target <slug> <file>` — show one file's block."""
    import argparse

    parser = argparse.ArgumentParser(
        prog="callgraph",
        description="Show the call-neighbourhood block a work card would carry.",
    )
    workqueue.add_common_args(parser)
    parser.add_argument("file", help="target-relative source path")
    args = parser.parse_args(argv)
    ctx = workqueue.context_from_args(args)
    block = block_for(ctx.results_dir, args.file, ctx.target_root)
    if block:
        print("\n".join(block).strip())
        return 0
    print(f"callgraph: no block for {args.file}: "
          f"{explain(ctx.results_dir, args.file)}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
