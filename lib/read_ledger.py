#!/usr/bin/env python3
"""What file scope a session requested, read back from its transcript.

A receipt (`bin/state mark-examined`) is the agent's own claim about what it
read. This ledger is the other side: the file reads its backend transcript
shows was requested, recorded per session after it ends. It is evidence,
never a gate:
backends read files through different tools, shell idioms vary, and a read
the parser does not recognise is simply absent, so a file with no row here
was not proven unread. The coverage report shows the two side by side and
names this one "read requested". Command logs do not prove that an
untruncated response entered the model's context.

Recognised shapes:

- Claude: a `Read` tool call (`file_path`, optional `offset`/`limit`) and
  `Bash` commands.
- Gemini: `read_file` (`absolute_path`/`path`, `offset`/`limit`) and
  `run_shell_command`.
- OpenCode: a `read` tool part (`filePath`, `offset`/`limit`) and `bash`.
- Codex: `command_execution` items.

Shell commands are matched for the whole-file and range idioms the audit
shell wraps: `sed -n 'A,Bp' FILE`, `cat FILE`, `head`/`tail -n N FILE`,
`nl FILE`, and `bin/peek FILE[:A[-B]]`. A pattern search (`rg`, `grep`)
loads matches, not a range, and is not recorded.
"""

from __future__ import annotations

import json
import re
import shlex
from pathlib import Path

import workqueue


READS_NAME = "reads.jsonl"

_SED_RANGE_RE = re.compile(r"^(\d+)(?:,(\d+|\$))?p$")
_PEEK_RE = re.compile(r"^(?P<file>.+?)(?::(?P<start>\d+)(?:-(?P<end>\d+))?)?$")
_READ_TOOL_NAMES = {"read", "read_file", "readfile", "read_many_files"}
_SHELL_TOOL_NAMES = {"bash", "run_shell_command", "shell", "exec_command"}


def reads_path(results_dir: Path) -> Path:
    return workqueue.state_dir(Path(results_dir)) / READS_NAME


def _range(offset: object, limit: object) -> tuple[int, int | None] | None:
    """(start, end) from a tool's offset/limit; offsets are 1-based lines and
    an absent limit means to the end of the file. Malformed explicit values
    describe a failed request, not a whole-file read."""
    try:
        raw_start = int(offset) if offset not in (None, "") else 1
        count = int(limit) if limit not in (None, "") else None
    except (TypeError, ValueError):
        return None
    if raw_start < 0 or count is not None and count <= 0:
        return None
    start = max(1, raw_start)
    if count is None:
        return start, None
    return start, start + count - 1


def _split_commands(command: str) -> list[list[str]]:
    """Simple commands of a shell line, split on `|`, `;`, `&&`, `||`.

    Pipelines like `rg --files | head` then yield a `head` with no file
    argument, which records nothing. A wrapper prefix such as
    `/bin/zsh -lc '<script>'` is unwrapped one level, since that is how a
    backend CLI hands a command to the shell.
    """
    try:
        words = shlex.split(command)
    except ValueError:
        return []
    if len(words) >= 3 and words[1] in ("-lc", "-c") and words[0].endswith(("sh", "zsh", "bash")):
        return _split_commands(words[2])
    commands: list[list[str]] = []
    current: list[str] = []
    for word in words:
        if word in ("|", ";", "&&", "||"):
            if current:
                commands.append(current)
            current = []
        else:
            current.append(word)
    if current:
        commands.append(current)
    return commands


def reads_from_command(command: str) -> list[tuple[str, int, int | None]]:
    """(file, start, end) for each recognised read in one shell command."""
    out: list[tuple[str, int, int | None]] = []
    for words in _split_commands(command):
        if not words:
            continue
        tool = Path(words[0]).name
        args = words[1:]
        if tool == "sed":
            script = ""
            scripts = 0
            quiet = False
            files: list[str] = []
            skip = False
            for index, arg in enumerate(args):
                if skip:
                    skip = False
                    continue
                if arg in ("-e", "--expression"):
                    script = args[index + 1] if index + 1 < len(args) else ""
                    scripts += 1
                    skip = True
                elif arg in ("-n", "--quiet", "--silent"):
                    quiet = True
                elif arg.startswith("-"):
                    continue
                elif not script:
                    script = arg
                else:
                    files.append(arg)
            match = _SED_RANGE_RE.match(script.strip())
            if not quiet or scripts > 1 or not match or not files:
                # Several -e scripts print several windows; recording only
                # the last would under- or mis-count, so record none.
                continue
            start = int(match.group(1))
            end_text = match.group(2)
            end = None if end_text == "$" else (start if end_text is None else int(end_text))
            if end is not None and end < start:
                continue
            out.extend((file, start, end) for file in files)
        elif tool in ("cat", "nl"):
            out.extend((arg, 1, None) for arg in args if not arg.startswith("-"))
        elif tool in ("head", "tail"):
            count: int | None = 10
            from_line = 0
            files = []
            skip = byte_mode = False
            for index, arg in enumerate(args):
                if skip:
                    skip = False
                    continue
                if arg in ("-c", "--bytes") or (arg.startswith("-c") and arg != "-c"):
                    # A byte window says nothing about lines.
                    byte_mode = True
                    skip = arg in ("-c", "--bytes")
                elif arg in ("-n", "--lines") or arg.startswith("--lines=") or (arg.startswith("-n") and len(arg) > 2):
                    if arg in ("-n", "--lines"):
                        spec = args[index + 1] if index + 1 < len(args) else ""
                    elif arg.startswith("--lines="):
                        spec = arg.partition("=")[2]
                    else:
                        spec = arg[2:]
                    skip = arg in ("-n", "--lines")
                    if tool == "tail" and spec.startswith("+"):
                        # `tail -n +K` starts at line K, it is not a count.
                        from_line = int(spec[1:]) if spec[1:].isdigit() else 0
                        count = None
                    elif spec.isdigit():
                        count = int(spec)
                    elif tool == "tail" and re.fullmatch(r"-\d+", spec):
                        count = int(spec[1:])
                    else:
                        count = None
                elif re.fullmatch(r"-\d+", arg):
                    count = int(arg[1:])
                elif arg.startswith("-"):
                    continue
                else:
                    files.append(arg)
            if byte_mode:
                continue
            if count is None and not from_line:
                continue
            if count == 0:
                continue
            if tool == "head":
                out.extend((file, 1, count) for file in files)
            elif from_line:
                out.extend((file, from_line, None) for file in files)
            else:
                # tail's window is anchored at the end; without the file's
                # length here it records "somewhere in the file", which the
                # ledger resolves against the manifest's line count.
                out.extend((file, -(count or 10), None) for file in files)
        elif tool == "peek":
            for arg in args:
                if arg.startswith("-"):
                    continue
                match = _PEEK_RE.match(arg)
                if not match:
                    continue
                start = int(match.group("start")) if match.group("start") else 1
                end = int(match.group("end")) if match.group("end") else None
                out.append((match.group("file"), start, end))
                break
    return out


def reads_from_event(backend: str, event: dict) -> list[tuple[str, int, int | None]]:
    """Recognised file reads in one transcript event."""
    out: list[tuple[str, int, int | None]] = []

    def from_tool(name: str, params: dict) -> None:
        lowered = str(name or "").lower()
        if lowered in _READ_TOOL_NAMES:
            path = (
                params.get("file_path") or params.get("absolute_path")
                or params.get("filePath") or params.get("path") or ""
            )
            if isinstance(path, str) and path:
                bounds = _range(params.get("offset"), params.get("limit"))
                if bounds is not None:
                    out.append((path, *bounds))
        elif lowered in _SHELL_TOOL_NAMES:
            command = params.get("command") or params.get("cmd") or ""
            if isinstance(command, list):
                command = " ".join(str(part) for part in command)
            if isinstance(command, str) and command:
                out.extend(reads_from_command(command))

    if event.get("type") == "item.completed":
        item = event.get("item") or {}
        if isinstance(item, dict) and item.get("type") == "command_execution":
            command = item.get("command") or ""
            if isinstance(command, str):
                out.extend(reads_from_command(command))
        return out
    part = event.get("part")
    if event.get("type") == "tool_use" and isinstance(part, dict):
        state = part.get("state") if isinstance(part.get("state"), dict) else {}
        params = state.get("input") if isinstance(state.get("input"), dict) else {}
        from_tool(str(part.get("tool") or ""), params)
        return out
    if event.get("type") == "tool_use":
        params = event.get("parameters") or event.get("input") or {}
        from_tool(
            str(event.get("tool_name") or event.get("name") or ""),
            params if isinstance(params, dict) else {},
        )
        return out
    message = event.get("message")
    if isinstance(message, dict):
        for item in message.get("content") or []:
            if isinstance(item, dict) and item.get("type") == "tool_use":
                params = item.get("input") if isinstance(item.get("input"), dict) else {}
                from_tool(str(item.get("name") or ""), params)
    return out


def _resolve(path: str, target_root: Path, script_root: Path) -> str:
    """Target-relative path for a read, or "" when it is outside the target."""
    candidate = Path(path)
    if not candidate.is_absolute():
        candidate = script_root / candidate
    try:
        return workqueue.normalized_relpath(
            candidate.resolve().relative_to(target_root.resolve()).as_posix()
        )
    except (ValueError, OSError):
        return ""


def record_observed_reads(
    results_dir: Path, target_root: Path, script_root: Path,
    agent: str, backend: str, observed: list[tuple[str, int, int | None]],
    session: str,
) -> int:
    """Append one row per target file requested in a transcript.

    Rows are pinned to the current manifest identity: a file whose content
    changed after the manifest walk is skipped (stat first, hash on a
    mismatch), so a request is never pinned to content it did not read.
    """
    import coverage_ledger

    manifest = {
        str(row.get("file") or ""): row
        for row in coverage_ledger.read_manifest(results_dir)
    }
    by_file: dict[str, list[tuple[int, int | None]]] = {}
    for path, start, end in observed:
        rel = _resolve(path, Path(target_root), Path(script_root))
        row = manifest.get(rel)
        if not row or not coverage_ledger.content_matches_manifest(target_root, rel, row):
            continue
        by_file.setdefault(rel, []).append((start, end))
    rows = [
        {
            "file": rel, "ranges": [[start, end] for start, end in ranges],
            "sha1": manifest[rel].get("sha1", ""),
            "agent": str(agent), "backend": backend, "session": session,
            "source": "transcript", "at": workqueue.now_iso(),
        }
        for rel, ranges in sorted(by_file.items())
    ]
    if rows:
        workqueue.append_jsonl_many(reads_path(Path(results_dir)), rows)
    return len(rows)


def record_session_reads(
    results_dir: Path, target_root: Path, script_root: Path,
    agent: str, backend: str, raw_path: Path, session: str = "",
) -> int:
    """Standalone transcript scan used outside the audit runner."""
    observed: list[tuple[str, int, int | None]] = []
    try:
        with raw_path.open(encoding="utf-8", errors="replace") as stream:
            for line in stream:
                line = line.strip()
                if not line.startswith("{"):
                    continue
                try:
                    event = json.loads(line)
                except ValueError:
                    continue
                if not isinstance(event, dict):
                    continue
                observed.extend(reads_from_event(backend, event))
    except OSError:
        return 0
    return record_observed_reads(
        results_dir, target_root, script_root, agent, backend, observed,
        session or raw_path.name,
    )


def requested_ranges_by_file(results_dir: Path) -> dict[str, list[tuple[int, int]]]:
    """Merged requested ranges per current manifest file.

    Open ends resolve against the manifest line count and `tail` windows are
    anchored at its end. These are request scopes, not proof of untruncated
    tool output or model attention.
    """
    import coverage_ledger

    manifest = {
        str(row.get("file") or ""): row
        for row in coverage_ledger.read_manifest(results_dir)
    }
    collected: dict[str, list[tuple[int, int]]] = {}
    for row in workqueue.read_jsonl(reads_path(results_dir)):
        rel = str(row.get("file") or "")
        current = manifest.get(rel) or {}
        try:
            total = int(current.get("lines") or 0)
        except (TypeError, ValueError):
            continue
        if not rel or not total or row.get("sha1") != current.get("sha1"):
            continue
        for pair in row.get("ranges") or []:
            if not isinstance(pair, list) or len(pair) != 2:
                continue
            start, end = pair
            try:
                start = int(start)
                end = total if end is None else int(end)
            except (TypeError, ValueError):
                continue
            if start < 0:
                start = max(1, total + start + 1) if start else 1
            start = max(1, min(start, total))
            end = max(start, min(end, total))
            collected.setdefault(rel, []).append((start, end))
    return {rel: coverage_ledger.merge_ranges(ranges) for rel, ranges in collected.items()}
