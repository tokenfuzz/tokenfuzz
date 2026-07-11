#!/usr/bin/env python3
"""Helper subcommands extracted from bin/audit and bin/validate-finding.

The audit and validation runners import these helpers directly. The CLI
subcommands remain useful for operator inspection and focused tests.

Subcommands (run as `python3 lib/audit_helpers.py <name> ...`):

  relpath-list <root>
      Read newline-separated paths from stdin and print each one as a
      path relative to <root>, dropping "." entries.

  sanitize-target-slug <raw_path> <targets_root>
      Preserve a target's nested path relative to targets_root, or use an
      external target's basename, then normalize every slug component.

  write-run-config <path> <num> <browser> <shell> <backend> <model> <target> <overridden>
      Atomically write the structured run configuration consumed by
      bin/benchmark. Invalid integer fields are stored as zero.

  format-waste <telemetry>
      Render one waste-telemetry row for the human-readable session index.

  cluster-count <exclude_prefixes>
      Read cluster JSON from stdin and count clusters whose status does not
      start with a comma-separated excluded prefix. Invalid JSON exits 1.

  waste-telemetry <log_file>
      Stream a raw agent transcript (claude / codex stream-json) and emit
      a single-line `key=value` waste-telemetry summary. Gemini CLI
      stream-json logs are supported; the older Antigravity CLI emits
      plain text and naturally produces empty telemetry. Grok Build's
      stream currently exposes text and terminal events but no tool events,
      so it likewise produces empty tool telemetry.

  count-tools <log_file> <command_execution|all_tools>
      Count shell-command tool calls or all tool calls in a raw transcript.
      Supports Codex, Claude, and Gemini CLI stream-json shapes. Grok Build
      currently exposes no tool-call events to count.

  count-tools-all <log_file>
      Count both shell-command tool calls and all tool calls in one transcript
      pass. Prints key=value lines for automation callers.

  raw-status <log_file>
      Stream a raw transcript once and print status booleans used by the
      agent finish path: rate_limit, codex_completed, codex_failed,
      gemini_success. This replaces several independent grep passes over
      the same file while preserving broad provider-status checks.

  finish-fields <log_file> <backend> [--prompt <prompt_file>]
      Stream/read a raw transcript once and print every agent finish-path
      field needed by bin/audit: usage counters, tool counts, and backend
      status booleans. Existing focused subcommands remain for tests and
      one-off callers.

  codex-turn-delta <log_file> <offset>
      Count completed Codex command_execution items in complete JSONL lines
      appended at or after <offset>. Prints count=N and offset=N. The returned
      offset stops after the last complete line so a partially-written event is
      retried on the next poll.

  provider-reset-at <logfile> [--now-epoch N]
      Parse provider text for the next reset epoch.
      Prints the epoch on stdout and exits 0 if found, exits 1 otherwise.

  iteration-provider-status <raw_dir> <timestamp>
      Aggregate an iteration's session_<timestamp>_*.log.raw logs in one pass.
      Prints rate_limit=<0|1>, issue=<none|transient|capacity_limited>, and
      reset_at=<epoch|unknown|> (empty when no rejection).

  claims-activity-since <claims_file> <since_epoch>
      Summarize state/claims.jsonl events at or after <since_epoch>.
      Prints `total=N status:k ... claimed_ids=[id1,id2,...]` or exits 0
      silently if nothing matched.

  effective-work-cards <script_root> <target_root> <target_slug> <results_dir>
      Print every results/work-cards.jsonl row as one JSON object per line,
      overlaying the effective claim status from state/claims.jsonl (the same
      overlay bin/state uses) so already-claimed or terminal cards are not
      reported as unclaimed. Exits 0 with no output on any error so the bash
      caller can fall back to the raw file.

  extract-vote-json
      Read free-form LLM text from stdin and print the first
      brace-balanced JSON object containing a "vote" field set to one of
      {Promote, Reject, Uncertain}. Exits 1 if no such object exists.

  emit-event <events_file> <event_name> [key=value ...]
      Append one observability event to <events_file> (JSONL). Each
      argument after the event name is a `key=value` pair stored as a
      string. Use --int / --bool prefixes to coerce values:
        emit-event ev.jsonl agent-plan agent=1 --int streak=3 launch=cold
      Adds created_at (UTC RFC3339) and event keys automatically. Best-
      effort: if the parent directory does not exist or the write fails,
      returns 0 silently (matches the prior jq+>>file behavior).
"""

from __future__ import annotations

import argparse
import datetime as _dt
import fcntl
import json
import os
import re
import shlex
import sys
import tempfile
import time
from collections import Counter
from pathlib import Path


# ── relpath-list ────────────────────────────────────────────────────

def _cmd_relpath_list(args: argparse.Namespace) -> int:
    root = os.path.realpath(args.root)
    for raw in sys.stdin:
        path = raw.rstrip("\n")
        if not path:
            continue
        rel = os.path.relpath(os.path.realpath(path), root)
        if rel != ".":
            print(rel)
    return 0


# ── sanitize-target-slug ───────────────────────────────────────────

def sanitize_target_slug(raw: str, targets_root: str) -> str:
    targets_real = os.path.realpath(targets_root)
    raw_real = os.path.realpath(raw)
    if raw_real == targets_real or raw_real.startswith(targets_real + os.sep):
        relative = os.path.relpath(raw_real, targets_real)
    else:
        relative = os.path.basename(raw.rstrip("/")) or raw

    parts = []
    for component in relative.split(os.sep):
        normalized = re.sub(r"[^a-z0-9._-]+", "-", component.lower()).strip("-")
        if normalized:
            parts.append(normalized)
    slug = "/".join(parts)
    if not slug:
        raise ValueError(f"target path has no usable slug: {raw}")
    return slug


def _cmd_sanitize_target_slug(args: argparse.Namespace) -> int:
    print(sanitize_target_slug(args.raw_path, args.targets_root))
    return 0


# ── run metadata and display formatting ──────────────────────────────────

def _int_or_zero(value: str) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _fmt_count(value: object) -> str:
    number = _int_or_zero(str(value or 0))
    if number >= 1_000_000:
        text = f"{number / 1_000_000:.1f}".rstrip("0").rstrip(".")
        return f"{text}M"
    if number >= 1_000:
        return f"{number // 1_000}k"
    return str(number)


def _parse_waste(text: str) -> dict:
    parsed = dict(
        tool_bytes=0, max_output=0, over8k=0,
        native_tools={}, top_commands={}, largest="none",
    )
    try:
        parts = shlex.split(text or "")
    except ValueError:
        parts = []
    for part in parts:
        if "=" not in part:
            continue
        key, value = part.split("=", 1)
        if key in ("tool_bytes", "max_output", "over8k"):
            parsed[key] = _int_or_zero(value)
        elif key == "native_tools":
            parsed[key] = {
                name: _int_or_zero(count)
                for entry in value.split(",") if ":" in entry
                for name, count in (entry.rsplit(":", 1),)
            }
        elif key == "top_cmds":
            parsed["top_commands"] = {
                name: _int_or_zero(count)
                for entry in value.split(",") if ":" in entry and value != "none"
                for name, count in (entry.rsplit(":", 1),)
            }
        elif key == "largest":
            parsed[key] = value
    return parsed


def _cmd_write_run_config(args: argparse.Namespace) -> int:
    import llm_invoke

    path = Path(args.path)
    payload = {
        "num_agents": _int_or_zero(args.num_agents),
        "browser_agents": _int_or_zero(args.browser_agents),
        "shell_agents": _int_or_zero(args.shell_agents),
        "backend": args.backend,
        "model": args.model,
        "resolved_effort": llm_invoke.default_effort(args.backend),
        "target_slug": args.target_slug,
        "agent_count_overridden": _int_or_zero(args.agent_count_overridden) == 1,
    }
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=path.parent,
            prefix=f".{path.name}.",
            delete=False,
        ) as output:
            temporary = Path(output.name)
            json.dump(payload, output, indent=2, sort_keys=True)
        os.replace(temporary, path)
    finally:
        if temporary is not None:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass
    return 0


def _cmd_format_waste(args: argparse.Namespace) -> int:
    parsed = _parse_waste(args.telemetry)
    parts = [
        f"bytes={_fmt_count(parsed.get('tool_bytes'))}",
        f"max={_fmt_count(parsed.get('max_output'))}",
    ]
    over = int(parsed.get("over8k") or 0)
    if over:
        parts.append(f"oversized={over}")
    top = parsed.get("top_commands") or {}
    if top:
        parts.append("top=" + ",".join(
            f"{name}:{count}" for name, count in list(top.items())[:5]
        ))
    native = {k: v for k, v in (parsed.get("native_tools") or {}).items() if v}
    if native:
        parts.append("native=" + ",".join(f"{name}:{count}" for name, count in native.items()))
    largest = parsed.get("largest") or "none"
    if largest != "none":
        parts.append("largest=" + json.dumps(str(largest), ensure_ascii=False))
    print("tool output: " + " ".join(parts))
    return 0


def _cmd_cluster_count(args: argparse.Namespace) -> int:
    prefixes = tuple(prefix for prefix in args.exclude_prefixes.split(",") if prefix)
    try:
        data = json.load(sys.stdin)
        clusters = data.get("clusters") or []
        count = 0
        for cluster in clusters:
            status = str(cluster.get("status", "") or "").upper()
            if prefixes and any(status.startswith(prefix) for prefix in prefixes):
                continue
            count += 1
    except (AttributeError, TypeError, ValueError, json.JSONDecodeError):
        return 1
    print(count)
    return 0


_FINDING_LABELS = {
    "summary": "summary", "classification": "classification",
    "root cause": "root_cause", "file and function": "location",
    "location": "location", "bug class": "class", "class": "class",
    "input shape and reach path": "input_shape", "input shape": "input_shape",
    "reach path": "reach_path", "guards passed": "guards", "guards": "guards",
    "primitive": "primitive", "falsification attempt": "falsification",
    "boundary": "boundary", "caller controls": "caller_controls",
    "trusted caller actions": "trusted_caller_actions",
    "caller contract": "caller_contract", "trigger source": "trigger_source",
    "strategy": "strategy",
}
_FINDING_LABEL_RE = re.compile(
    r"^\s*(?:[-*]\s*)?(?:\*\*)?"
    r"([A-Za-z][A-Za-z0-9 /_-]{0,80}?)"
    r"(?:\*\*)?\s*:\s*(.*)$"
)


def _finding_label(line: str) -> tuple[str, str] | None:
    match = _FINDING_LABEL_RE.match(line)
    if not match:
        return None
    raw = re.sub(r"\s+", " ", match.group(1).strip()).lower()
    key = _FINDING_LABELS.get(raw)
    if not key:
        return None
    value = match.group(2).strip()
    # Markdown commonly bolds the colon inside the label (`**Class:** x`),
    # leaving the closing marker after the regex's colon separator.
    if value.startswith("**"):
        value = value[2:].lstrip()
    return key, value


def _cmd_markdown_finding(args: argparse.Namespace) -> int:
    text_value = Path(args.path).read_text(encoding="utf-8", errors="replace")
    lines = text_value.splitlines()
    candidate = {"format": "markdown-report", "report_text": text_value.strip()}
    index = 0
    while index < len(lines):
        parsed = _finding_label(lines[index])
        if not parsed:
            index += 1
            continue
        key, value = parsed
        index += 1
        continuation = []
        while index < len(lines):
            if _finding_label(lines[index]) or lines[index].startswith("#"):
                break
            if not lines[index].strip():
                break
            continuation.append(lines[index].strip())
            index += 1
        parts = [part for part in (value, " ".join(continuation).strip()) if part]
        if parts:
            candidate[key] = " ".join(parts)
    print(json.dumps(candidate, ensure_ascii=False))
    return 0


def _cmd_json_field(args: argparse.Namespace) -> int:
    try:
        value = json.load(sys.stdin)
        result = value.get(args.field, "") if isinstance(value, dict) else ""
    except (TypeError, ValueError, json.JSONDecodeError):
        result = ""
    print("" if result is None else result)
    return 0


# ── waste-telemetry ─────────────────────────────────────────────────

_WASTE_OVER_BYTES = 8192
_WASTE_NATIVE_NAMES = ("Read", "Grep", "Glob")
_WASTE_OBSERVABILITY_ONLY = {"update_topic"}
_SHELL_TOOL_NAMES = {"Bash", "bash", "run_shell_command"}


def _text_value(value):
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        parts = []
        for item in value:
            if isinstance(item, str):
                parts.append(item)
            elif isinstance(item, dict):
                for key in ("text", "content", "output", "result", "stderr", "stdout"):
                    if key in item:
                        t = _text_value(item.get(key))
                        if t:
                            parts.append(t)
                            break
        return "\n".join(parts)
    if isinstance(value, dict):
        for key in ("aggregated_output", "output", "stdout", "stderr", "content", "text", "result"):
            if key in value:
                t = _text_value(value.get(key))
                if t:
                    return t
    return ""


def _byte_len(text):
    return len((text or "").encode("utf-8", "replace"))


def _sanitize_label(label):
    label = re.sub(r"\s+", " ", str(label or "")).strip()
    label = label.replace('"', "'")
    if len(label) > 120:
        label = label[:117] + "..."
    return label or "unknown"


def _native_tool_name(name):
    lower = str(name or "").lower()
    if lower == "read":
        return "Read"
    if lower == "grep":
        return "Grep"
    if lower == "glob":
        return "Glob"
    return str(name or "")


def _opencode_tool_event(ev):
    if ev.get("type") != "tool_use":
        return None
    part = ev.get("part")
    if not isinstance(part, dict) or part.get("type") != "tool":
        return None
    state = part.get("state") if isinstance(part.get("state"), dict) else {}
    tool_input = state.get("input") if isinstance(state.get("input"), dict) else {}
    return {
        "name": part.get("tool") or "",
        "input": tool_input,
        "output": _text_value(state.get("output") or state.get("error") or ""),
        "call_id": part.get("callID") or part.get("id") or "",
    }


def _unwrap_shell(cmd):
    cmd = (cmd or "").strip()
    if not cmd:
        return cmd
    try:
        parts = shlex.split(cmd)
    except ValueError:
        parts = []
    for i, part in enumerate(parts[:-1]):
        if part in ("-lc", "-c") and i > 0 and re.search(r"(?:^|/)(?:zsh|bash|sh)$", parts[i - 1]):
            return parts[i + 1].strip()
    return cmd


def _command_pattern(cmd):
    cmd = _unwrap_shell(cmd)
    squashed = re.sub(r"\s+", " ", cmd).strip()
    if not squashed:
        return "unknown"
    m = re.search(
        r"(?:^|[;&| ])(?:env\s+[^;&| ]+\s+)*(rg|grep|sed|cat|ls|find|python3?|jq|awk|head|tail|wc|sort|uniq)\b",
        squashed,
    )
    if m:
        tool = m.group(1)
        return "python" if tool.startswith("python") else tool
    if re.search(r"(?:^|[;&| ])bin/state\s+(?:--help|-h)\b", squashed):
        return "state-help"
    if re.search(r"(?:^|[;&| ])bin/state\s+(?:show-card|list-cards)\b", squashed):
        return "state-card"
    for name in ("probe", "peek", "find-seed", "show-patch", "scratch-status", "scratch-search", "probe-history"):
        if re.search(r"(?:^|[;&| ])bin/" + re.escape(name) + r"\b", squashed):
            return name
    if re.search(r"(?:^|[;&| ])git(?:\s+-C\s+\S+)?\s+show\b", squashed):
        return "git-show"
    if re.search(r"(?:^|[;&| ])hg(?:\s+-R\s+\S+)?\s+diff\b", squashed):
        return "hg-diff"
    if re.search(r"(?:^|[;&| ])hg(?:\s+-R\s+\S+)?\s+log\b", squashed):
        return "hg-log"
    return squashed.split()[0].split("/")[-1][:32]


def _claude_content_items(ev):
    msg = ev.get("message") or {}
    if not isinstance(msg, dict):
        return []
    content = msg.get("content") or []
    return content if isinstance(content, list) else []


def _cmd_waste_telemetry(args: argparse.Namespace) -> int:
    path = args.log_file
    if not os.path.isfile(path):
        print(
            "tool_bytes=0 max_output=0 over8k=0 "
            "native_tools=Read:0,Grep:0,Glob:0 top_cmds=none largest=\"none\""
        )
        return 0

    tool_bytes = 0
    max_output = 0
    over8k = 0
    native = Counter()
    cmd_patterns = Counter()
    largest_label = "none"

    claude_pending = {}
    top_level_pending = {}

    def record_command(cmd):
        if cmd:
            cmd_patterns[_command_pattern(cmd)] += 1

    def record_output(text, label):
        nonlocal tool_bytes, max_output, over8k, largest_label
        size = _byte_len(text)
        if size <= 0:
            return
        tool_bytes += size
        if size > _WASTE_OVER_BYTES:
            over8k += 1
        if size > max_output:
            max_output = size
            largest_label = _sanitize_label(label)

    try:
        f = open(path, "r", encoding="utf-8", errors="replace")
    except OSError:
        print(
            "tool_bytes=0 max_output=0 over8k=0 "
            "native_tools=Read:0,Grep:0,Glob:0 top_cmds=error largest=\"parser-error\""
        )
        return 0

    with f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
            except (json.JSONDecodeError, ValueError):
                continue

            if ev.get("type") == "item.completed":
                item = ev.get("item") or {}
                if item.get("type") == "command_execution":
                    cmd = item.get("command") or ""
                    pattern = _command_pattern(cmd)
                    record_command(cmd)
                    output = _text_value(item.get("aggregated_output") or item.get("output") or item)
                    record_output(output, f"{pattern}: {cmd}")
                continue

            if ev.get("type") == "command_execution":
                cmd = ev.get("command") or ""
                pattern = _command_pattern(cmd)
                record_command(cmd)
                output = _text_value(ev.get("aggregated_output") or ev.get("output") or ev)
                record_output(output, f"{pattern}: {cmd}")
                continue

            if ev.get("type") == "tool_use":
                opencode_tool = _opencode_tool_event(ev)
                if opencode_tool is not None:
                    name = opencode_tool["name"]
                    native_name = _native_tool_name(name)
                    if native_name in _WASTE_NATIVE_NAMES:
                        native[native_name] += 1
                    cmd = opencode_tool["input"].get("command") if isinstance(opencode_tool["input"], dict) else ""
                    if name in _SHELL_TOOL_NAMES:
                        record_command(cmd)
                    output = opencode_tool["output"]
                    if output and name not in _WASTE_OBSERVABILITY_ONLY:
                        label = cmd or name or "tool"
                        record_output(
                            output,
                            f"{_command_pattern(label) if name in _SHELL_TOOL_NAMES else native_name or name}: {label}",
                        )
                    continue

                name = ev.get("tool_name") or ev.get("name") or "unknown"
                native_name = _native_tool_name(name)
                if native_name in _WASTE_NATIVE_NAMES:
                    native[native_name] += 1
                params = ev.get("parameters") or ev.get("input") or {}
                cmd = params.get("command") if isinstance(params, dict) else ""
                if name in _SHELL_TOOL_NAMES:
                    record_command(cmd)
                tool_id = ev.get("tool_id") or ev.get("id")
                if tool_id:
                    label = cmd or name
                    top_level_pending[tool_id] = (name, label)
                continue

            if ev.get("type") == "tool_result":
                tool_id = ev.get("tool_id") or ev.get("tool_use_id") or ev.get("id")
                name, label = top_level_pending.pop(tool_id, ("tool_result", "tool_result"))
                output = _text_value(ev.get("output") or ev.get("content") or ev)
                if name not in _WASTE_OBSERVABILITY_ONLY:
                    record_output(output, f"{_command_pattern(label) if name == 'run_shell_command' else name}: {label}")
                continue

            if ev.get("type") == "assistant" or "message" in ev:
                for item in _claude_content_items(ev):
                    if not isinstance(item, dict) or item.get("type") != "tool_use":
                        continue
                    name = item.get("name") or "unknown"
                    if name in _WASTE_NATIVE_NAMES:
                        native[name] += 1
                    inp = item.get("input") or {}
                    cmd = inp.get("command") if isinstance(inp, dict) else ""
                    if name == "Bash":
                        record_command(cmd)
                    tool_id = item.get("id")
                    if tool_id:
                        claude_pending[tool_id] = (name, cmd or name)

            if ev.get("type") == "user" or "message" in ev:
                for item in _claude_content_items(ev):
                    if not isinstance(item, dict) or item.get("type") != "tool_result":
                        continue
                    tool_id = item.get("tool_use_id")
                    name, label = claude_pending.pop(tool_id, ("tool_result", "tool_result"))
                    output = _text_value(item.get("content") or item)
                    record_output(output, f"{_command_pattern(label) if name == 'Bash' else name}: {label}")


    top_cmds = ",".join(f"{name}:{count}" for name, count in cmd_patterns.most_common(5)) or "none"
    native_text = ",".join(f"{name}:{native.get(name, 0)}" for name in _WASTE_NATIVE_NAMES)
    print(
        f"tool_bytes={tool_bytes} max_output={max_output} over8k={over8k} "
        f"native_tools={native_text} top_cmds={top_cmds} largest=\"{largest_label}\""
    )
    return 0


def _iter_json_events(path):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                except (json.JSONDecodeError, ValueError):
                    continue
                if isinstance(event, dict):
                    yield event
    except OSError:
        return


def _count_tools(path: str) -> dict[str, int]:
    counts = {"command_execution": 0, "all_tools": 0}
    for event in _iter_json_events(path):
        if event.get("type") == "item.completed":
            item = event.get("item") or {}
            item_type = item.get("type")
            if item_type == "command_execution":
                counts["command_execution"] += 1
                counts["all_tools"] += 1
            elif item_type in ("tool_use", "file_change"):
                counts["all_tools"] += 1
            continue

        if event.get("type") == "command_execution":
            counts["command_execution"] += 1
            counts["all_tools"] += 1
            continue

        if event.get("type") == "tool_use":
            opencode_tool = _opencode_tool_event(event)
            if opencode_tool is not None:
                if opencode_tool["name"] in _SHELL_TOOL_NAMES:
                    counts["command_execution"] += 1
                counts["all_tools"] += 1
                continue

            name = event.get("tool_name") or event.get("name") or ""
            if name in _SHELL_TOOL_NAMES:
                counts["command_execution"] += 1
            counts["all_tools"] += 1
            continue

        if event.get("type") == "assistant" or "message" in event:
            for item in _claude_content_items(event):
                if not isinstance(item, dict) or item.get("type") != "tool_use":
                    continue
                name = item.get("name") or ""
                if name == "Bash":
                    counts["command_execution"] += 1
                counts["all_tools"] += 1

    return counts


def _cmd_count_tools(args: argparse.Namespace) -> int:
    print(_count_tools(args.log_file)[args.kind])
    return 0


def _cmd_count_tools_all(args: argparse.Namespace) -> int:
    counts = _count_tools(args.log_file)
    print(f"command_execution={counts['command_execution']}")
    print(f"all_tools={counts['all_tools']}")
    return 0


_RAW_STATUS_ERROR_TYPE_RE = re.compile(r'"type":"(?:error|turn\.failed)"')

# Claude's dedicated provider-status field. It only ever carries a real backend
# HTTP status, so it is trustworthy wherever it appears (it lives in the result
# event, which also embeds model prose we must NOT scan for loose wording).
_PROVIDER_API_ERROR_RE = re.compile(r'"api_error_status"[ \t]*:[ \t]*([0-9]{3})')

# An HTTP status / error code. Trustworthy only inside a backend error event or
# on a provider-CLI plain line — never in assistant prose or tool output, where
# the model and target programs legitimately mention status codes.
_PROVIDER_STATUS_CODE_RE = re.compile(
    r'(?:status|code)\\?"[ \t]*:[ \t]*([0-9]{3})|'
    r'\b(?:status|code|HTTP)[ \t:]+([0-9]{3})\b|'
    r'Server returned ([0-9]{3})',
)

# Capacity / quota wording (429-class): the account or model window is spent.
_PROVIDER_CAPACITY_TEXT_RE = re.compile(
    r'Too Many Requests|RESOURCE_EXHAUSTED|Individual quota reached|'
    r'exceeded your current quota|exhausted your capacity|quota reached|'
    r'quota will reset|rate_limit_error|rate.?limit.*(?:exceeded|reached)',
    re.IGNORECASE,
)

# Transient / overload wording (5xx / transport): a blip that should clear.
_PROVIDER_TRANSIENT_TEXT_RE = re.compile(
    r'\bUNAVAILABLE\b|overload(?:ed)?|high demand|fetch failed|'
    r'EADDRNOTAVAIL|ECONNRESET|ECONNABORTED|ETIMEDOUT|'
    r'TypeError: terminated|terminated stream',
    re.IGNORECASE,
)

# Soft account/usage-limit notice. Codex ("You've hit your usage limit") and
# Claude ("You've hit your session limit · resets 9:40am") surface this as prose
# in an agent_message rather than a status code, so it is the one signal allowed
# in assistant text — but ONLY as a conjunction (an account-limit phrase AND
# retry/reset wording). The phrases are the provider's own account terms ("usage
# limit", "session limit"), which also match the "hit your usage/session limit"
# wording as substrings, so unrelated prose like "hit your recursion limit" is
# not a hit.
_PROVIDER_USAGE_LIMIT_RE = re.compile(r'usage limit|session limit', re.IGNORECASE)
_PROVIDER_RETRY_RE = re.compile(r'try again at|retry after|reset', re.IGNORECASE)

# Provider-CLI dialect markers (gemini/agy). A bare plain-text provider error
# (no JSON event) is trusted only when the log is one of these CLIs, so a stray
# "UNAVAILABLE" / "quota will reset" in unrelated output is not a false hit.
_PROVIDER_DIALECT_RE = re.compile(
    r'Antigravity CLI|antigravity-cli|antigravity\.google|\[agy CLI log tail:|'
    r'YOLO mode is enabled|Ripgrep is not available\. Falling back to GrepTool|'
    r'@google/gemini-cli/|"model"[ \t]*:[ \t]*"gemini-[a-z0-9._-]+"',
    re.IGNORECASE,
)


def _status_class(match) -> str:
    """Map a regex match's first populated 3-digit group to capacity/transient/''."""
    code = next((g for g in match.groups() if g), None)
    if code == "429":
        return "capacity"
    if code and code[0] == "5":
        return "transient"
    return ""


def _provider_issue_from_lines(lines, quota_marker: Path | None = None) -> str:
    """Classify backend/provider failures as none, transient, or capacity_limited.

    Capacity wins over transient when both appear. Detection is scoped so that
    only genuine provider failures count: structured status codes and provider
    wording are credited inside a backend error event or on a provider-CLI plain
    line (gemini stderr), never in tool output or assistant prose. The account
    usage-limit notice is the sole exception and needs a two-part match.
    """

    # The Gemini watchdog observes the live retry stream and writes this marker
    # before terminating a quota-stalled process. It is stronger evidence than
    # transcript classification and therefore also outranks a transient error.
    if quota_marker is not None and quota_marker.is_file():
        return "capacity_limited"

    cap = trans = False              # credited in a backend error context
    cap_plain = trans_plain = False  # seen on a non-JSON (provider-CLI) line
    dialect = False
    usage_limit_notice = False

    for raw_line in lines:
        line = raw_line.strip()
        if not line:
            continue
        event = None
        if line.startswith("{"):
            try:
                parsed = json.loads(line)
                if isinstance(parsed, dict):
                    event = parsed
            except (json.JSONDecodeError, ValueError):
                event = None
        event_type = event.get("type") if event else ""
        is_error_event = event_type in ("error", "turn.failed")
        is_plain = event is None

        if _PROVIDER_DIALECT_RE.search(line):
            dialect = True

        # api_error_status is a dedicated field — trust it anywhere.
        m = _PROVIDER_API_ERROR_RE.search(line)
        if m:
            cls = _status_class(m)
            cap = cap or cls == "capacity"
            trans = trans or cls == "transient"

        if is_error_event:
            m = _PROVIDER_STATUS_CODE_RE.search(line)
            if m:
                cls = _status_class(m)
                cap = cap or cls == "capacity"
                trans = trans or cls == "transient"
            cap = cap or bool(_PROVIDER_CAPACITY_TEXT_RE.search(line))
            trans = trans or bool(_PROVIDER_TRANSIENT_TEXT_RE.search(line))
        elif is_plain:
            m = _PROVIDER_STATUS_CODE_RE.search(line)
            if m:
                cls = _status_class(m)
                cap_plain = cap_plain or cls == "capacity"
                trans_plain = trans_plain or cls == "transient"
            cap_plain = cap_plain or bool(_PROVIDER_CAPACITY_TEXT_RE.search(line))
            trans_plain = trans_plain or bool(_PROVIDER_TRANSIENT_TEXT_RE.search(line))

        # Usage-limit notice: allowed in agent_message / error / plain lines, but
        # only when the account-limit phrase and retry/reset wording appear in
        # the same trusted line. Accumulating the conjunction across the whole
        # log would let unrelated assistant prose plus tool output look like a
        # provider account limit.
        if is_plain or event_type in ("error", "turn.failed", "agent_message"):
            if _PROVIDER_USAGE_LIMIT_RE.search(line) and _PROVIDER_RETRY_RE.search(line):
                usage_limit_notice = True

    if cap or (dialect and cap_plain) or usage_limit_notice:
        return "capacity_limited"
    if trans or (dialect and trans_plain):
        return "transient"
    return "none"


def _raw_status_defaults() -> dict[str, int]:
    return {
        "rate_limit": 0,
        "codex_completed": 0,
        "codex_failed": 0,
        "gemini_success": 0,
    }


def _raw_status_from_lines(lines) -> dict[str, int]:
    raw_lines = list(lines)
    status = {
        "rate_limit": 0,
        "codex_completed": 0,
        "codex_failed": 0,
        "gemini_success": 0,
    }
    gemini_result = False
    gemini_success = False

    if _provider_issue_from_lines(raw_lines) != "none":
        status["rate_limit"] = 1

    for raw_line in raw_lines:
        line = raw_line.strip()
        if not line:
            continue
        event = None
        if line.startswith("{"):
            try:
                parsed = json.loads(line)
                if isinstance(parsed, dict):
                    event = parsed
            except (json.JSONDecodeError, ValueError):
                event = None
        event_type = event.get("type") if event else ""
        event_status = event.get("status") if event else ""
        if event_type in ("error", "turn.failed") or _RAW_STATUS_ERROR_TYPE_RE.search(line):
            status["codex_failed"] = 1
        if event_type == "turn.completed" or '"type":"turn.completed"' in line:
            status["codex_completed"] = 1
        if event_type == "result" or '"type":"result"' in line:
            gemini_result = True
        if event_status == "success" or '"status":"success"' in line:
            gemini_success = True

    if gemini_result and gemini_success:
        status["gemini_success"] = 1

    return status


def _cmd_raw_status(args: argparse.Namespace) -> int:
    try:
        with open(args.log_file, "r", encoding="utf-8", errors="replace") as f:
            status = _raw_status_from_lines(f)
    except OSError:
        status = _raw_status_defaults()

    for key, value in status.items():
        print(f"{key}={value}")
    return 0


def _cmd_provider_issue(args: argparse.Namespace) -> int:
    try:
        with open(args.log_file, "r", encoding="utf-8", errors="replace") as f:
            issue = _provider_issue_from_lines(f)
    except OSError:
        issue = "none"
    print(issue)
    return 0


def _finish_field_defaults() -> dict[str, str]:
    fields = {
        "total_tokens": "",
        "input_tokens": "",
        "cached_input_tokens": "",
        "cache_creation_input_tokens": "",
        "output_tokens": "",
        "duration_ms": "",
        "command_execution": "0",
        "all_tools": "0",
    }
    fields.update({k: str(v) for k, v in _raw_status_defaults().items()})
    return fields


def _cmd_finish_fields(args: argparse.Namespace) -> int:
    fields = _finish_field_defaults()
    try:
        with open(args.log_file, "r", encoding="utf-8", errors="replace") as f:
            raw = f.read()
    except OSError:
        for key, value in fields.items():
            print(f"{key}={value}")
        return 0

    prompt_text = ""
    if args.prompt:
        try:
            with open(args.prompt, "r", encoding="utf-8", errors="replace") as f:
                prompt_text = f.read()
        except OSError:
            prompt_text = ""

    try:
        from llm_usage import extract_fields_from_text

        fields.update(extract_fields_from_text(raw, prompt_text=prompt_text, backend=args.backend))
    except Exception:
        pass

    counts = {"command_execution": 0, "all_tools": 0}
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            event = json.loads(line)
        except (json.JSONDecodeError, ValueError):
            continue
        if not isinstance(event, dict):
            continue

        if event.get("type") == "item.completed":
            item = event.get("item") or {}
            item_type = item.get("type") if isinstance(item, dict) else ""
            if item_type == "command_execution":
                counts["command_execution"] += 1
                counts["all_tools"] += 1
            elif item_type in ("tool_use", "file_change"):
                counts["all_tools"] += 1
            continue

        if event.get("type") == "command_execution":
            counts["command_execution"] += 1
            counts["all_tools"] += 1
            continue

        if event.get("type") == "tool_use":
            opencode_tool = _opencode_tool_event(event)
            if opencode_tool is not None:
                if opencode_tool["name"] in _SHELL_TOOL_NAMES:
                    counts["command_execution"] += 1
                counts["all_tools"] += 1
                continue

            name = event.get("tool_name") or event.get("name") or ""
            if name in _SHELL_TOOL_NAMES:
                counts["command_execution"] += 1
            counts["all_tools"] += 1
            continue

        if event.get("type") == "assistant" or "message" in event:
            for item in _claude_content_items(event):
                if not isinstance(item, dict) or item.get("type") != "tool_use":
                    continue
                name = item.get("name") or ""
                if name == "Bash":
                    counts["command_execution"] += 1
                counts["all_tools"] += 1

    fields["command_execution"] = str(counts["command_execution"])
    fields["all_tools"] = str(counts["all_tools"])
    fields.update({k: str(v) for k, v in _raw_status_from_lines(raw.splitlines()).items()})

    for key, value in fields.items():
        print(f"{key}={value}")
    return 0


def codex_turn_delta(log_file: str | os.PathLike[str], offset: int = 0) -> tuple[int, int]:
    """Count newly completed Codex shell commands without rereading the log."""
    try:
        offset = int(offset)
    except (TypeError, ValueError):
        offset = 0
    if offset < 0:
        offset = 0

    count = 0
    next_offset = offset
    try:
        with open(log_file, "rb") as f:
            size = f.seek(0, os.SEEK_END)
            if offset > size:
                offset = 0
            f.seek(offset)
            chunk = f.read()
    except OSError:
        return 0, offset

    if not chunk:
        return 0, offset

    last_newline = chunk.rfind(b"\n")
    if last_newline < 0:
        return 0, offset

    complete = chunk[: last_newline + 1]
    next_offset = offset + last_newline + 1
    for raw in complete.splitlines():
        if not raw:
            continue
        try:
            ev = json.loads(raw.decode("utf-8", "replace"))
        except (json.JSONDecodeError, UnicodeDecodeError, ValueError):
            continue
        if not isinstance(ev, dict) or ev.get("type") != "item.completed":
            continue
        item = ev.get("item") or {}
        if isinstance(item, dict) and item.get("type") == "command_execution":
            count += 1

    return count, next_offset


def _cmd_codex_turn_delta(args: argparse.Namespace) -> int:
    count, offset = codex_turn_delta(args.log_file, args.offset)
    print(f"count={count}")
    print(f"offset={offset}")
    return 0


# ── provider-reset-at ───────────────────────────────────────────────

# Absolute clock-time reset forms (hour[:minute] am/pm), tried before the
# relative-duration forms. Codex says "try again at 9:01 AM"; Claude's session
# cap says "resets 9:40am" (requires minutes, so a bare "resets 9" duration
# form is not mistaken for a clock time).
_USAGE_CLOCK_PATTERNS = [
    r"try again at\s+([0-9]{1,2})(?::([0-9]{2}))?\s*([AaPp]\.?[Mm]\.?)?",
    r"reset(?:s|ting)?(?:\s+(?:at|around))?\s+([0-9]{1,2}):([0-9]{2})\s*([AaPp]\.?[Mm]\.?)?",
]
_USAGE_DURATION_PATTERNS = [
    r"reset(?:s|ting)?(?: after| in)?\s+([0-9]+)\s*(s|sec|secs|second|seconds|m|min|mins|minute|minutes|h|hour|hours)\b",
    r"retry after\s+([0-9]+)\s*(s|sec|secs|second|seconds|m|min|mins|minute|minutes|h|hour|hours)\b",
]


_CODEX_CLOCK_ROLLOVER_MAX_SECS = 6 * 3600


def _event_reset_at(event) -> int | None:
    if not isinstance(event, dict) or event.get("type") != "rate_limit_event":
        return None
    info = event.get("rate_limit_info")
    if not isinstance(info, dict):
        info = event
    status = str(info.get("status") or "").lower()
    if status in {"allowed", "allowed_warning"}:
        return None
    try:
        reset_at = int(info.get("resetsAt"))
    except (TypeError, ValueError):
        return None
    return reset_at if reset_at > 0 else None


def _latest_rejected_reset_at(lines) -> int | None:
    latest = None
    for raw_line in lines:
        line = raw_line.strip()
        if not line.startswith("{"):
            continue
        try:
            parsed = json.loads(line)
        except (json.JSONDecodeError, ValueError):
            continue
        reset_at = _event_reset_at(parsed)
        if reset_at is not None and (latest is None or reset_at > latest):
            latest = reset_at
    return latest


def _provider_reset_from_text(text: str, now: "_dt.datetime | None" = None) -> "int | None":
    """Next provider reset epoch from a transcript, or None.

    Single source of truth for reset extraction, shared by the provider-reset-at
    CLI and the iteration-provider-status scan. Machine-readable event resetsAt
    wins; a human-text clock/duration is the fallback, resolved against `now`.
    """
    event_reset_at = _latest_rejected_reset_at(text.splitlines())
    if event_reset_at is not None:
        return event_reset_at

    if now is None:
        now = _dt.datetime.now()
    for pat in _USAGE_CLOCK_PATTERNS:
        for m in re.finditer(pat, text, re.IGNORECASE):
            hour = int(m.group(1))
            minute = int(m.group(2) or "0")
            ampm = (m.group(3) or "").lower().replace(".", "")
            if ampm == "pm" and hour != 12:
                hour += 12
            elif ampm == "am" and hour == 12:
                hour = 0
            if not (0 <= hour <= 23 and 0 <= minute <= 59):
                continue
            candidate = now.replace(hour=hour, minute=minute, second=0, microsecond=0)
            if candidate <= now:
                candidate += _dt.timedelta(days=1)
                if (candidate - now).total_seconds() > _CODEX_CLOCK_ROLLOVER_MAX_SECS:
                    continue
            return int(time.mktime(candidate.timetuple()))

    for pat in _USAGE_DURATION_PATTERNS:
        m = re.search(pat, text, re.IGNORECASE)
        if not m:
            continue
        n = int(m.group(1))
        unit = m.group(2).lower()
        if unit.startswith("h"):
            secs = n * 3600
        elif unit.startswith("m"):
            secs = n * 60
        else:
            secs = n
        return int(time.time() + secs)

    return None


def _cmd_provider_reset(args: argparse.Namespace) -> int:
    try:
        with open(args.logfile, "r", encoding="utf-8", errors="replace") as f:
            text = f.read()
    except OSError:
        return 1
    now = None
    if args.now_epoch is not None:
        try:
            now = _dt.datetime.fromtimestamp(int(args.now_epoch))
        except (TypeError, ValueError, OSError, OverflowError):
            return 1
    reset_at = _provider_reset_from_text(text, now)
    if reset_at is None:
        return 1
    print(reset_at)
    return 0


def _iteration_provider_status(raw_dir: str, timestamp: str) -> "tuple[bool, str, int | None]":
    """Aggregate one iteration's provider status across its session raw logs.

    Globs session_<timestamp>_*.log.raw — one wildcard that covers every agent
    and its -rN refills, and cannot silently miss a future role/mode — then, in a
    single pass per file, reuses the same classifier the per-file callers use:
      * rejection gate == (_provider_issue_from_lines != "none"), the exact
        equivalence _raw_status_from_lines encodes, so this stays consistent with
        log_has_rate_limit_rejection;
      * issue is the max over files (capacity_limited > transient > none);
      * reset_at is the max epoch over rejected files.
    Returns (saw_rejection, issue, reset_at|None).
    """
    saw_rejection = False
    issue = "none"
    reset_at: "int | None" = None
    for path in sorted(Path(raw_dir).glob(f"session_{timestamp}_*.log.raw")):
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        file_issue = _provider_issue_from_lines(text.splitlines())
        if file_issue == "none":
            continue
        saw_rejection = True
        if file_issue == "capacity_limited":
            issue = "capacity_limited"
        elif issue != "capacity_limited":
            issue = "transient"
        candidate = _provider_reset_from_text(text)
        if candidate is not None and candidate > 0 and (reset_at is None or candidate > reset_at):
            reset_at = candidate
    return saw_rejection, issue, reset_at


def _cmd_iteration_provider_status(args: argparse.Namespace) -> int:
    saw_rejection, issue, reset_at = _iteration_provider_status(args.raw_dir, args.timestamp)
    print(f"rate_limit={1 if saw_rejection else 0}")
    print(f"issue={issue}")
    if reset_at is not None:
        print(f"reset_at={reset_at}")
    else:
        # A rejection with no parseable reset is "unknown"; no rejection at all
        # leaves reset_at empty so the caller can tell the two apart.
        print("reset_at=unknown" if saw_rejection else "reset_at=")
    return 0


# ── claims-activity-since ───────────────────────────────────────────

def _cmd_claims_activity(args: argparse.Namespace) -> int:
    path = args.claims_file
    try:
        since = int(args.since_epoch)
    except (TypeError, ValueError):
        return 0
    counts: dict[str, int] = {}
    top_cards: list[str] = []
    try:
        f = open(path, encoding="utf-8", errors="replace")
    except OSError:
        return 0
    with f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
            except Exception:
                continue
            ts = ev.get("claimed_at") or ev.get("updated_at") or ""
            if not ts:
                continue
            try:
                dt = _dt.datetime.fromisoformat(ts.replace("Z", "+00:00"))
            except Exception:
                continue
            if dt.timestamp() < since:
                continue
            status = ev.get("status") or "?"
            counts[status] = counts.get(status, 0) + 1
            if status == "claimed" and ev.get("card_id"):
                top_cards.append(ev["card_id"])
    total = sum(counts.values())
    if total == 0:
        return 0
    parts = [f"{k}:{v}" for k, v in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))]
    out = f"total={total} " + " ".join(parts)
    if top_cards:
        head = ",".join(top_cards[:5])
        more = "" if len(top_cards) <= 5 else f"+{len(top_cards) - 5}"
        out += f" claimed_ids=[{head}{more}]"
    print(out)
    return 0


# ── effective-work-cards ────────────────────────────────────────────

def _cmd_effective_work_cards(args: argparse.Namespace) -> int:
    # Lazy import: only this subcommand needs workqueue, and importing it
    # eagerly would couple every audit_helpers invocation to that module.
    try:
        from workqueue import (
            Context,
            card_closed_for_run,
            card_conclusion_counts,
            card_distinct_hypothesis_counts,
            latest_claims_by_card,
            latest_terminal_status_by_card,
            read_jsonl,
            visible_card_status,
            work_card_claim_ttl,
            work_cards_path,
        )
    except Exception:
        return 0
    ctx = Context(
        Path(args.script_root),
        Path(args.target_root),
        args.target_slug,
        Path(args.results_dir),
        "",
    )
    try:
        cards = read_jsonl(work_cards_path(ctx))
        if not cards:
            return 0
        latest = latest_claims_by_card(ctx)
        ttl = work_card_claim_ttl()
        conclusion_counts = card_conclusion_counts(ctx)
        distinct_counts = card_distinct_hypothesis_counts(ctx)
        terminal_status = latest_terminal_status_by_card(ctx)
    except Exception:
        return 0
    out: list[str] = []
    dry_streaks: dict[str, int] = {}
    for card in cards:
        updated = dict(card)
        cid = card.get("id", "")
        claim = latest.get(cid)
        if claim is not None:
            status = visible_card_status(claim, ttl)
            # Single source of truth for "is this card still claimable?":
            # card_closed_for_run keeps the claim path, the explain view, and
            # this audit-facing overlay in agreement. A still-yielding concrete
            # crash/find, a broad crash/find on a still-hot subsystem, and a
            # released lease collapse to "unclaimed" so strategy rotation,
            # queue counts, and diversity recovery see the same reopened cards
            # the claimer does; done/discarded/blocked, mined-out (re-
            # discovered) concrete cards, and dry broad cards stay terminal.
            if status != "claimed":
                if not card_closed_for_run(
                    ctx, card, status,
                    conclusion_counts=conclusion_counts, distinct_counts=distinct_counts,
                    dry_streaks=dry_streaks,
                ):
                    status = "unclaimed"
                elif status in ("released", "unclaimed"):
                    # Closed, but the latest row is a lifecycle mask — surface the
                    # conclusion it hides so this mined card is not counted as
                    # available (status "unclaimed") by the queue consumers.
                    status = terminal_status.get(cid, status)
            updated["status"] = status
        out.append(json.dumps(updated, sort_keys=True))
    if out:
        sys.stdout.write("\n".join(out) + "\n")
    return 0


# ── extract-vote-json ───────────────────────────────────────────────

# Doubles any backslash that does not begin a valid JSON escape (\", \\,
# \/, \b, \f, \n, \r, \t, or \uXXXX). Validators write prose about escape
# sequences ("ESC \\ terminates OSC 8") inside the rationale string, which
# produces bare backslashes that json.loads rejects. The vote field and
# every validly-escaped char are left untouched.
_INVALID_ESCAPE_RE = re.compile(r'\\(?![\\/"bfnrt]|u[0-9a-fA-F]{4})')


def _parse_vote_candidate(candidate: str) -> str | None:
    """Return valid vote JSON (escape-repaired if needed) or None."""
    for attempt in (candidate, _INVALID_ESCAPE_RE.sub(r"\\\\", candidate)):
        try:
            obj = json.loads(attempt)
        except Exception:
            continue
        if isinstance(obj, dict) and obj.get("vote") in ("Promote", "Reject", "Uncertain"):
            return attempt
    return None


def _cmd_extract_vote_json(_args: argparse.Namespace) -> int:
    text = sys.stdin.read()
    i = 0
    n = len(text)
    while i < n:
        if text[i] != "{":
            i += 1
            continue
        depth = 0
        j = i
        in_str = False
        esc = False
        while j < n:
            c = text[j]
            if in_str:
                if esc:
                    esc = False
                elif c == "\\":
                    esc = True
                elif c == '"':
                    in_str = False
            else:
                if c == '"':
                    in_str = True
                elif c == "{":
                    depth += 1
                elif c == "}":
                    depth -= 1
                    if depth == 0:
                        parsed = _parse_vote_candidate(text[i:j + 1])
                        if parsed is not None:
                            print(parsed)
                            return 0
                        break
            j += 1
        i = j + 1 if j < n else i + 1
    return 1


# ── locked appends ──────────────────────────────────────────────────

def _locked_append(path: Path, line: str) -> None:
    """Append one line under an exclusive flock, for files SHARED across
    parallel agents + orchestrator (see docs/development.md logging
    discipline). Short rows are already PIPE_BUF-atomic via POSIX O_APPEND,
    but long payloads can exceed PIPE_BUF and a Python buffered write can
    be split into multiple os.write() syscalls. Take an exclusive flock and
    flush INSIDE the locked region so the actual kernel append happens
    while the lock is held — otherwise the lock would be released before
    close() flushes the userspace buffer. Open/write failures propagate as
    OSError; callers decide whether that is fatal."""
    with path.open("a", encoding="utf-8") as f:
        try:
            fcntl.flock(f.fileno(), fcntl.LOCK_EX)
        except OSError:
            # Lock unsupported (rare: some network FS). Fall through to
            # plain append — single-line writes under PIPE_BUF stay atomic.
            pass
        try:
            f.write(line + "\n")
            f.flush()
        finally:
            try:
                fcntl.flock(f.fileno(), fcntl.LOCK_UN)
            except OSError:
                pass


def _cmd_flock_append(args: argparse.Namespace) -> int:
    # Serializes index.log appends from backgrounded run_agent processes
    # (bin/audit index_log). Best-effort — a lock/open failure must never
    # abort an audit over a log line.
    try:
        _locked_append(Path(args.file), args.line)
    except OSError:
        pass
    return 0


# ── emit-event ──────────────────────────────────────────────────────

def _cmd_emit_event(args: argparse.Namespace) -> int:
    payload: dict = {}
    # Order: defaults (string), then typed overrides. A key declared with
    # --int wins over the same key declared as plain key=value, regardless
    # of argv order, so numeric keys stay JSON numbers.
    for kv in args.kvs or []:
        if "=" not in kv:
            continue
        k, v = kv.split("=", 1)
        if k:
            payload[k] = v
    for kv in args.int_kvs or []:
        if "=" not in kv:
            continue
        k, v = kv.split("=", 1)
        if not k:
            continue
        try:
            payload[k] = int(v)
        except (TypeError, ValueError):
            payload[k] = 0
    for kv in args.bool_kvs or []:
        if "=" not in kv:
            continue
        k, v = kv.split("=", 1)
        if k:
            payload[k] = v.lower() in ("1", "true", "yes", "y", "on")
    payload["created_at"] = _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    payload["event"] = args.event_name

    try:
        events_path = Path(args.events_file)
        events_path.parent.mkdir(parents=True, exist_ok=True)
        _locked_append(events_path,
                       json.dumps(payload, separators=(",", ":"), sort_keys=False))
    except OSError:
        return 0
    return 0


# ── CLI dispatch ────────────────────────────────────────────────────

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="audit_helpers",
        description="Subcommands extracted from bin/audit and bin/validate-finding.",
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("relpath-list", help="Print stdin paths relative to <root> (drops '.').")
    s.add_argument("root")
    s.set_defaults(func=_cmd_relpath_list)

    s = sub.add_parser("sanitize-target-slug",
                       help="Normalize a target path to its output slug.")
    s.add_argument("raw_path")
    s.add_argument("targets_root")
    s.set_defaults(func=_cmd_sanitize_target_slug)

    s = sub.add_parser("write-run-config",
                       help="Atomically write benchmark-consumable run metadata.")
    s.add_argument("path")
    s.add_argument("num_agents")
    s.add_argument("browser_agents")
    s.add_argument("shell_agents")
    s.add_argument("backend")
    s.add_argument("model")
    s.add_argument("target_slug")
    s.add_argument("agent_count_overridden")
    s.set_defaults(func=_cmd_write_run_config)

    s = sub.add_parser("format-waste",
                       help="Format waste telemetry for the human-readable index.")
    s.add_argument("telemetry")
    s.set_defaults(func=_cmd_format_waste)

    s = sub.add_parser("cluster-count",
                       help="Count stdin cluster JSON, excluding status prefixes.")
    s.add_argument("exclude_prefixes")
    s.set_defaults(func=_cmd_cluster_count)

    s = sub.add_parser("markdown-finding",
                       help="convert a Markdown finding report to structured JSON")
    s.add_argument("path")
    s.set_defaults(func=_cmd_markdown_finding)

    s = sub.add_parser("json-field", help="read one top-level JSON field from stdin")
    s.add_argument("field")
    s.set_defaults(func=_cmd_json_field)

    s = sub.add_parser("waste-telemetry", help="Compute waste telemetry from an agent transcript.")
    s.add_argument("log_file")
    s.set_defaults(func=_cmd_waste_telemetry)

    s = sub.add_parser("count-tools", help="Count tool calls in an agent transcript.")
    s.add_argument("log_file")
    s.add_argument("kind", choices=("command_execution", "all_tools"))
    s.set_defaults(func=_cmd_count_tools)

    s = sub.add_parser("count-tools-all",
                       help="Count shell commands and all tools in one transcript pass.")
    s.add_argument("log_file")
    s.set_defaults(func=_cmd_count_tools_all)

    s = sub.add_parser("raw-status",
                       help="Summarize rate-limit and backend status flags in one transcript pass.")
    s.add_argument("log_file")
    s.set_defaults(func=_cmd_raw_status)

    s = sub.add_parser("provider-issue",
                       help="Classify provider failures as none, transient, or capacity_limited.")
    s.add_argument("log_file")
    s.set_defaults(func=_cmd_provider_issue)

    s = sub.add_parser("finish-fields",
                       help="Summarize usage, tool counts, and backend status for agent finish.")
    s.add_argument("log_file")
    s.add_argument("backend")
    s.add_argument("--prompt", default="")
    s.set_defaults(func=_cmd_finish_fields)

    s = sub.add_parser("codex-turn-delta",
                       help="Count newly-appended Codex command_execution completions.")
    s.add_argument("log_file")
    s.add_argument("offset")
    s.set_defaults(func=_cmd_codex_turn_delta)

    s = sub.add_parser("provider-reset-at", help="Parse provider text for next reset epoch.")
    s.add_argument("logfile")
    s.add_argument("--now-epoch")
    s.set_defaults(func=_cmd_provider_reset)

    s = sub.add_parser("iteration-provider-status",
                       help="Aggregate an iteration's rate_limit/issue/reset_at across its session raw logs.")
    s.add_argument("raw_dir")
    s.add_argument("timestamp")
    s.set_defaults(func=_cmd_iteration_provider_status)

    s = sub.add_parser("claims-activity-since", help="Summarize claims.jsonl events since epoch.")
    s.add_argument("claims_file")
    s.add_argument("since_epoch")
    s.set_defaults(func=_cmd_claims_activity)

    s = sub.add_parser("effective-work-cards",
                       help="Print work-cards rows with claim-status overlay (one JSON object per line).")
    s.add_argument("script_root")
    s.add_argument("target_root")
    s.add_argument("target_slug")
    s.add_argument("results_dir")
    s.set_defaults(func=_cmd_effective_work_cards)

    s = sub.add_parser("extract-vote-json",
                       help="Extract first brace-balanced vote JSON object from stdin "
                            "(repairing invalid string escapes if needed).")
    s.set_defaults(func=_cmd_extract_vote_json)

    s = sub.add_parser("flock-append",
                       help="Append one line to a shared file under an exclusive flock.")
    s.add_argument("file")
    s.add_argument("line")
    s.set_defaults(func=_cmd_flock_append)

    s = sub.add_parser("emit-event", help="Append a JSONL observability event.")
    s.add_argument("events_file")
    s.add_argument("event_name")
    s.add_argument("kvs", nargs="*", help="key=value pairs (string-typed)")
    s.add_argument("--int", dest="int_kvs", action="append", default=[],
                   help="key=value (coerced to int; defaults 0 on parse failure)")
    s.add_argument("--bool", dest="bool_kvs", action="append", default=[],
                   help="key=value (truthy if value in {1,true,yes,y,on})")
    s.set_defaults(func=_cmd_emit_event)

    return p


def main(argv=None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
