#!/usr/bin/env python3
"""Helper subcommands extracted from bin/audit and bin/validate-finding.

Each subcommand replaces a one-off `python3 -c` / `python3 - <<PY` block
that used to live inline in the shell driver. The bash driver still owns
its argv plumbing and stdout capture; this module owns the parsing.

Subcommands (run as `python3 lib/audit_helpers.py <name> ...`):

  relpath-list <root>
      Read newline-separated paths from stdin and print each one as a
      path relative to <root>, dropping "." entries.

  waste-telemetry <log_file>
      Stream a raw agent transcript (claude / codex stream-json) and emit
      a single-line `key=value` waste-telemetry summary. Gemini CLI
      stream-json logs are supported; the older Antigravity CLI emits
      plain text and naturally produces empty telemetry.

  count-tools <log_file> <command_execution|all_tools>
      Count shell-command tool calls or all tool calls in a raw transcript.
      Supports Codex, Claude, and Gemini CLI stream-json shapes.

  append-guard-card <work_file> <id> <slug> <subsystem> <guard> <now>
      Append a guard-bypass work-card JSONL row. No-op if a row with the
      same id already exists. Output: nothing.

  codex-usage-reset-at <logfile> [--now-epoch N]
      Parse a codex raw transcript for the next usage-reset epoch.
      Prints the epoch on stdout and exits 0 if found, exits 1 otherwise.

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


# ── waste-telemetry ─────────────────────────────────────────────────

_WASTE_OVER_BYTES = 8192
_WASTE_NATIVE_NAMES = ("Read", "Grep", "Glob")
_WASTE_OBSERVABILITY_ONLY = {"update_topic"}


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
    if re.search(r"(?:^|[;&| ])bin/state\s+(?:--help|-h)\b", squashed):
        return "state-help"
    if re.search(r"(?:^|[;&| ])bin/state\s+(?:show-card|explain-card|list-cards)\b", squashed):
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
    m = re.search(
        r"(?:^|[;&| ])(?:env\s+[^;&| ]+\s+)*(rg|grep|sed|cat|ls|find|python3?|jq|awk|head|tail|wc|sort|uniq)\b",
        squashed,
    )
    if m:
        tool = m.group(1)
        return "python" if tool.startswith("python") else tool
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
                name = ev.get("tool_name") or ev.get("name") or "unknown"
                if name in _WASTE_NATIVE_NAMES:
                    native[name] += 1
                params = ev.get("parameters") or ev.get("input") or {}
                cmd = params.get("command") if isinstance(params, dict) else ""
                if name == "run_shell_command":
                    record_command(cmd)
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


def _cmd_count_tools(args: argparse.Namespace) -> int:
    count = 0
    for event in _iter_json_events(args.log_file):
        if event.get("type") == "item.completed":
            item = event.get("item") or {}
            item_type = item.get("type")
            if args.kind == "command_execution":
                if item_type == "command_execution":
                    count += 1
            elif item_type in ("command_execution", "tool_use", "file_change"):
                count += 1
            continue

        if event.get("type") == "command_execution":
            count += 1
            continue

        if event.get("type") == "tool_use":
            name = event.get("tool_name") or event.get("name") or ""
            if args.kind == "all_tools" or name == "run_shell_command":
                count += 1
            continue

        if event.get("type") == "assistant" or "message" in event:
            for item in _claude_content_items(event):
                if not isinstance(item, dict) or item.get("type") != "tool_use":
                    continue
                name = item.get("name") or ""
                if args.kind == "all_tools" or name == "Bash":
                    count += 1

    print(count)
    return 0


# ── append-guard-card ───────────────────────────────────────────────

def _cmd_append_guard_card(args: argparse.Namespace) -> int:
    path = Path(args.work_file)
    card = {
        "id": args.id,
        "kind": "guard-bypass",
        "target_slug": args.slug,
        "subsystem": args.subsystem,
        "file": "",
        "function": "",
        "mode": "generic",
        "strategy": "S2",
        "score": 100,
        "reason": (
            f"bypass-only: repeated upstream guard {args.guard!r}; "
            "write a testcase that gets past this guard or proves the guard boundary"
        ),
        "status": "unclaimed",
        "created_at": args.now,
    }
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(card, sort_keys=True) + "\n")
    return 0


# ── codex-usage-reset-at ────────────────────────────────────────────

_USAGE_TIME_PATTERNS = [
    r"try again at\s+([0-9]{1,2})(?::([0-9]{2}))?\s*([AaPp]\.?[Mm]\.?)?",
    r"reset(?:s|ting)?(?: after| in)?\s+([0-9]+)\s*(s|sec|secs|second|seconds|m|min|mins|minute|minutes|h|hour|hours)\b",
    r"retry after\s+([0-9]+)\s*(s|sec|secs|second|seconds|m|min|mins|minute|minutes|h|hour|hours)\b",
]


_CODEX_CLOCK_ROLLOVER_MAX_SECS = 6 * 3600


def _cmd_codex_usage_reset(args: argparse.Namespace) -> int:
    try:
        with open(args.logfile, "r", encoding="utf-8", errors="replace") as f:
            text = f.read()
    except OSError:
        return 1

    if args.now_epoch is not None:
        try:
            now = _dt.datetime.fromtimestamp(int(args.now_epoch))
        except (TypeError, ValueError, OSError, OverflowError):
            return 1
    else:
        now = _dt.datetime.now()
    for m in re.finditer(_USAGE_TIME_PATTERNS[0], text, re.IGNORECASE):
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
        print(int(time.mktime(candidate.timetuple())))
        return 0

    for pat in _USAGE_TIME_PATTERNS[1:]:
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
        print(int(time.time() + secs))
        return 0

    return 1


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
            TERMINAL_CARD_STATUSES,
            latest_claims_by_card,
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
    except Exception:
        return 0
    out: list[str] = []
    for card in cards:
        updated = dict(card)
        claim = latest.get(card.get("id", ""))
        if claim is not None:
            status = visible_card_status(claim, ttl)
            # Lease lifecycle rows such as "released" make a card claimable
            # again. Terminal claim rows remain terminal.
            if status != "claimed" and status not in TERMINAL_CARD_STATUSES:
                status = "unclaimed"
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


# ── emit-event ──────────────────────────────────────────────────────

def _cmd_emit_event(args: argparse.Namespace) -> int:
    payload: dict = {}
    # Order: defaults (string), then typed overrides. A key declared with
    # --int wins over the same key declared as plain key=value, regardless
    # of argv order — this mirrors how the bash callers used --argjson
    # for numeric keys to keep them as JSON numbers.
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

    # events.jsonl is SHARED across parallel agents + orchestrator (see
    # docs/development.md logging discipline). Short rows are already
    # PIPE_BUF-atomic via
    # POSIX O_APPEND, but long payloads can exceed PIPE_BUF and a Python
    # buffered write can be split into multiple os.write() syscalls. Take
    # an exclusive flock and flush INSIDE the locked region so the actual
    # kernel append happens while the lock is held — otherwise the lock
    # would be released before close() flushes the userspace buffer.
    try:
        events_path = Path(args.events_file)
        events_path.parent.mkdir(parents=True, exist_ok=True)
        line = json.dumps(payload, separators=(",", ":"), sort_keys=False) + "\n"
        with events_path.open("a", encoding="utf-8") as f:
            try:
                fcntl.flock(f.fileno(), fcntl.LOCK_EX)
            except OSError:
                # Lock unsupported (rare: some network FS). Fall through to
                # plain append — single-line writes under PIPE_BUF stay atomic.
                pass
            try:
                f.write(line)
                f.flush()
            finally:
                try:
                    fcntl.flock(f.fileno(), fcntl.LOCK_UN)
                except OSError:
                    pass
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

    s = sub.add_parser("waste-telemetry", help="Compute waste telemetry from an agent transcript.")
    s.add_argument("log_file")
    s.set_defaults(func=_cmd_waste_telemetry)

    s = sub.add_parser("count-tools", help="Count tool calls in an agent transcript.")
    s.add_argument("log_file")
    s.add_argument("kind", choices=("command_execution", "all_tools"))
    s.set_defaults(func=_cmd_count_tools)

    s = sub.add_parser("append-guard-card", help="Append a guard-bypass work-card row.")
    s.add_argument("work_file")
    s.add_argument("id")
    s.add_argument("slug")
    s.add_argument("subsystem")
    s.add_argument("guard")
    s.add_argument("now")
    s.set_defaults(func=_cmd_append_guard_card)

    s = sub.add_parser("codex-usage-reset-at", help="Parse codex transcript for next usage-reset epoch.")
    s.add_argument("logfile")
    s.add_argument("--now-epoch")
    s.set_defaults(func=_cmd_codex_usage_reset)

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
