#!/usr/bin/env python3
"""What a session loaded into context, read back from its transcript.

A receipt (`bin/state mark-examined`) is the agent's own claim about what it
read. This ledger is the other side: the file reads its backend transcript
shows, recorded per session after it ends. It is evidence, never a gate:
backends read files through different tools, shell idioms vary, and a read
the parser does not recognise is simply absent, so a file with no row here
was not proven unread. The coverage report shows the two side by side and
names this one "loaded".

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


def _range(offset: object, limit: object) -> tuple[int, int | None]:
    """(start, end) from a tool's offset/limit; offsets are 1-based lines and
    an absent limit means to the end of the file."""
    try:
        start = max(1, int(offset)) if offset not in (None, "") else 1
    except (TypeError, ValueError):
        start = 1
    try:
        count = int(limit) if limit not in (None, "") else None
    except (TypeError, ValueError):
        count = None
    if count is None or count <= 0:
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
            files: list[str] = []
            skip = False
            for index, arg in enumerate(args):
                if skip:
                    skip = False
                    continue
                if arg in ("-e", "--expression"):
                    script = args[index + 1] if index + 1 < len(args) else ""
                    skip = True
                elif arg.startswith("-"):
                    continue
                elif not script:
                    script = arg
                else:
                    files.append(arg)
            match = _SED_RANGE_RE.match(script.strip())
            if not match or not files:
                continue
            start = int(match.group(1))
            end_text = match.group(2)
            end = None if end_text in (None, "$") else int(end_text)
            if end is not None and end < start:
                continue
            out.extend((file, start, end) for file in files)
        elif tool in ("cat", "nl"):
            out.extend((arg, 1, None) for arg in args if not arg.startswith("-"))
        elif tool in ("head", "tail"):
            count = None
            files = []
            skip = False
            for index, arg in enumerate(args):
                if skip:
                    skip = False
                    continue
                if arg in ("-n", "--lines"):
                    try:
                        count = int(args[index + 1])
                    except (IndexError, ValueError):
                        count = None
                    skip = True
                elif arg.startswith("-n"):
                    try:
                        count = int(arg[2:])
                    except ValueError:
                        count = None
                elif re.fullmatch(r"-\d+", arg):
                    count = int(arg[1:])
                elif arg.startswith("-"):
                    continue
                else:
                    files.append(arg)
            if tool == "head":
                out.extend((file, 1, count) for file in files)
            else:
                # tail's window is anchored at the end; without the file's
                # length here it records "somewhere in the file", which the
                # ledger resolves against the manifest's line count.
                out.extend((file, -(count or 0), None) for file in files)
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
                start, end = _range(params.get("offset"), params.get("limit"))
                out.append((path, start, end))
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


def record_session_reads(
    ctx: workqueue.Context, agent: str, backend: str, raw_path: Path, session: str = "",
) -> int:
    """Append one row per file read in a finished session's transcript.

    Ranges are merged per file within the session. A read outside the target
    tree (a results directory, a scratch file) is not source and is skipped.
    """
    by_file: dict[str, list[tuple[int, int | None]]] = {}
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
                for path, start, end in reads_from_event(backend, event):
                    rel = _resolve(path, ctx.target_root, ctx.script_root)
                    if rel:
                        by_file.setdefault(rel, []).append((start, end))
    except OSError:
        return 0
    rows = [
        {
            "file": rel, "ranges": [[start, end] for start, end in ranges],
            "agent": str(agent), "backend": backend, "session": session or raw_path.name,
            "source": "transcript", "at": workqueue.now_iso(),
        }
        for rel, ranges in sorted(by_file.items())
    ]
    if rows:
        workqueue.append_jsonl_many(reads_path(ctx.results_dir), rows)
    return len(rows)


def loaded_ranges_by_file(results_dir: Path) -> dict[str, list[tuple[int, int]]]:
    """Merged loaded ranges per manifest file, open ends resolved against the
    manifest's line count and `tail` windows anchored at its end."""
    import coverage_ledger

    lengths = {
        str(row.get("file") or ""): int(row.get("lines") or 0)
        for row in coverage_ledger.read_manifest(results_dir)
    }
    collected: dict[str, list[tuple[int, int]]] = {}
    for row in workqueue.read_jsonl(reads_path(results_dir)):
        rel = str(row.get("file") or "")
        total = lengths.get(rel)
        if not rel or not total:
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
