#!/usr/bin/env python3
"""Write compact audit log summaries and append structured session index rows."""

import fcntl
import json
import os
import re
import shlex
import sys
from collections import Counter
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

from audit_helpers import (
    _SHELL_TOOL_NAMES,
    _WASTE_NATIVE_NAMES,
    _WASTE_OBSERVABILITY_ONLY,
    _WASTE_OVER_BYTES,
    _byte_len,
    _command_pattern as waste_command_pattern,
    _native_tool_name,
    _opencode_tool_event,
    _sanitize_label,
)


def _fmt_count(value):
    try:
        number = int(value or 0)
    except (TypeError, ValueError):
        return "0"
    if number >= 1_000_000:
        text = f"{number / 1_000_000:.1f}".rstrip("0").rstrip(".")
        return f"{text}M"
    if number >= 1_000:
        return f"{number // 1_000}k"
    return str(number)


def _summary_value(value):
    return "n/a" if value is None or value == "" else str(value)


# Exclusive lock on a sibling .lock file so concurrent agent finish
# handlers don't interleave bytes when their JSON rows exceed PIPE_BUF.
# Mirrors lib/workqueue.py's jsonl_lock pattern for consistency.
@contextmanager
def _index_lock(path):
    lock_path = Path(path).with_name("." + Path(path).name + ".lock")
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with open(lock_path, "a+", encoding="utf-8") as lock:
        try:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
            yield
        finally:
            fcntl.flock(lock.fileno(), fcntl.LOCK_UN)


def env(name, default=""):
    return os.environ.get(name, default)


def int_or_none(value):
    if value is None or value == "":
        return None
    try:
        return int(str(value))
    except ValueError:
        return None


def int_or_zero(value):
    parsed = int_or_none(value)
    return parsed if parsed is not None else 0


def text_value(value):
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        parts = []
        for item in value:
            text = text_value(item)
            if text:
                parts.append(text)
        return "\n".join(parts)
    if isinstance(value, dict):
        for key in ("aggregated_output", "output", "stdout", "stderr", "content", "text", "result"):
            if key in value:
                text = text_value(value.get(key))
                if text:
                    return text
    return ""


def parse_waste(text):
    parsed = dict(tool_bytes=0, max_output=0, over8k=0, native_tools={}, top_commands={}, largest="none")
    try:
        parts = shlex.split(text or "")
    except ValueError:
        parts = []
    for part in parts:
        if "=" not in part:
            continue
        key, value = part.split("=", 1)
        if key in ("tool_bytes", "max_output", "over8k"):
            parsed[key] = int_or_zero(value)
        elif key == "native_tools":
            native = {}
            for entry in value.split(","):
                if ":" in entry:
                    name, count = entry.rsplit(":", 1)
                    native[name] = int_or_zero(count)
            parsed[key] = native
        elif key == "top_cmds":
            top = {}
            if value != "none":
                for entry in value.split(","):
                    if ":" in entry:
                        name, count = entry.rsplit(":", 1)
                        top[name] = int_or_zero(count)
            parsed["top_commands"] = top
        elif key == "largest":
            parsed[key] = value
    return parsed


def command_pattern(cmd):
    squashed = re.sub(r"\s+", " ", (cmd or "")).strip()
    if not squashed:
        return "unknown"
    for name in ("probe", "peek", "find-seed", "show-patch", "scratch-status", "scratch-search", "probe-history"):
        if re.search(r"(?:^|[;&| ])bin/" + re.escape(name) + r"\b", squashed):
            return name
    match = re.search(
        r"(?:^|[;&| ])(?:env\s+[^;&| ]+\s+)*(rg|grep|sed|cat|ls|find|python3?|jq|awk|head|tail|wc|sort|uniq)\b",
        squashed,
    )
    if match:
        tool = match.group(1)
        return "python" if tool.startswith("python") else tool
    return squashed.split()[0].split("/")[-1][:32]


# Canonical probe/sanitizer verdict vocabulary, shared by every backend's
# log scan. Maps each raw `verdict=<TOKEN>` spelling the harness emits to a
# stable bucket. bin/probe emits CRASH/CLEAN/DIFF/NO_EXEC; run-asan and
# lib/quality add EXEC_FAIL and NO_HIT. Aliases (MISSED, DIFFERENTIAL) cover
# spellings other subsystems consume (e.g. lib/workqueue reads a MISSED key).
# Unrelated verdict namespaces — triage Promote/Reject/Uncertain, contract
# flags — are intentionally absent and so resolve to "" (ignored).
_VERDICT_TOKENS = {
    "crash": "crash",
    "clean": "clean",
    "diff": "diff",
    "differential": "diff",
    "no_exec": "no_exec",
    "exec_fail": "exec_fail",
    "no_hit": "missed",
    "missed": "missed",
}
_VERDICT_ALTERNATION = "|".join(sorted(_VERDICT_TOKENS, key=len, reverse=True))

# Cheap pre-filter: does this output look like probe/sanitizer telemetry at
# all? Recognises probe banners, run/rate headers, and any known verdict token
# (case-insensitive) so saved .asan.txt artifacts count even when the shell
# command itself was not bin/probe.
_PROBE_OUTPUT_RE = re.compile(
    r"\[probe\]|bin/probe|ASAN_RUN_HEADER:|SANITIZER_RUN_HEADER:|CRASH_RATE:|EXECUTION_RATE:|"
    r"\bverdict=(?:" + _VERDICT_ALTERNATION + r")\b",
    re.IGNORECASE,
)
_RUN_HEADER_RE = re.compile(r"^(?:ASAN_RUN_HEADER|SANITIZER_RUN_HEADER):.*?\bruns=([0-9]+)\b", re.MULTILINE)
_RUN_LINE_RE = re.compile(r"^=== Run [0-9]+/[0-9]+ ===", re.MULTILINE)
_EXPLICIT_VERDICT_RE = re.compile(r"\bverdict=([A-Za-z][A-Za-z0-9_-]*)\b", re.IGNORECASE)
_BIN_PROBE_COMMAND_RE = re.compile(r"(?:^|[;&| ])bin/probe\b")

# Fallback verdict accounting for probe/sanitizer output that lacks an explicit
# `verdict=` summary — e.g. a raw .asan.txt artifact the agent cat'd. Used only
# when no authoritative verdict token is present. Patterns are anchored on word
# boundaries to avoid matching inside ordinary prose, and the crash detector is
# structural (`ERROR: <name>Sanitizer`) so it covers every sanitizer —
# Address, HWAddress, Memory, Thread, Leak, UndefinedBehavior — not a list that
# rots as new ones appear.
_FALLBACK_VERDICT_PATTERNS = (
    ("crash", re.compile(r"\bERROR: [A-Za-z]+Sanitizer\b|\bCRASH(?:ES)? (?:FOUND|DETECTED)\b")),
    ("diff", re.compile(r"\bDIFFERENTIAL(?:: outputs DIFFER)?\b|\boutputs DIFFER\b")),
    ("clean", re.compile(r"\bNO CRASHES\b|\bEXECUTION VERIFIED\b")),
    ("no_exec", re.compile(r"\bNO_EXEC\b")),
    ("exec_fail", re.compile(r"\bEXEC_FAIL\b")),
    # Only the machine token NO_HIT here — a bare "MISSED" is ordinary English
    # and would match prose. `verdict=MISSED` is still honoured via the token
    # table above.
    ("missed", re.compile(r"\bNO_HIT\b")),
)


def _verdict_key(value):
    normalized = (value or "").strip().lower().replace("-", "_")
    return _VERDICT_TOKENS.get(normalized, "")


def scan_probe_output(output, *, force_probe=False):
    """Return probe metrics visible in one shell/tool output."""
    metrics = dict(probe_outputs=0, asan_invocations=0, verdicts=Counter())
    if not output:
        return metrics

    probe_marker_seen = bool(_PROBE_OUTPUT_RE.search(output))
    if force_probe or probe_marker_seen:
        metrics["probe_outputs"] = 1

    header_runs = [int(match) for match in _RUN_HEADER_RE.findall(output)]
    if header_runs:
        metrics["asan_invocations"] = sum(header_runs)
    else:
        metrics["asan_invocations"] = len(_RUN_LINE_RE.findall(output))

    explicit_verdicts = [_verdict_key(match) for match in _EXPLICIT_VERDICT_RE.findall(output)]
    explicit_verdicts = [value for value in explicit_verdicts if value]
    if explicit_verdicts:
        metrics["verdicts"].update(explicit_verdicts)
        return metrics

    if not (force_probe or probe_marker_seen):
        return metrics

    for key, pattern in _FALLBACK_VERDICT_PATTERNS:
        count = len(pattern.findall(output))
        if count:
            metrics["verdicts"][key] += count
    return metrics


def claude_content_items(event):
    msg = event.get("message") or {}
    content = msg.get("content") if isinstance(msg, dict) else []
    return content if isinstance(content, list) else []


def scan_raw_log(rawfile):
    probe_commands = 0
    probe_outputs = 0
    asan_invocations = 0
    timeouts = 0
    rate_limits = 0
    verdicts = Counter()
    command_patterns = Counter()
    claude_pending = {}
    waste_tool_bytes = 0
    waste_max_output = 0
    waste_over8k = 0
    waste_native = Counter()
    waste_command_patterns = Counter()
    waste_largest_label = "none"
    top_level_pending = {}

    def record_waste_command(cmd):
        if cmd:
            waste_command_patterns[waste_command_pattern(cmd)] += 1

    def record_waste_output(text, label):
        nonlocal waste_tool_bytes, waste_max_output, waste_over8k, waste_largest_label
        size = _byte_len(text)
        if size <= 0:
            return
        waste_tool_bytes += size
        if size > _WASTE_OVER_BYTES:
            waste_over8k += 1
        if size > waste_max_output:
            waste_max_output = size
            waste_largest_label = _sanitize_label(label)

    def record_probe_command(cmd):
        nonlocal probe_commands
        if not cmd:
            return
        command_patterns[command_pattern(cmd)] += 1
        if _BIN_PROBE_COMMAND_RE.search(cmd):
            probe_commands += 1

    def record_probe_output(output, *, force_probe=False):
        nonlocal probe_outputs, asan_invocations
        metrics = scan_probe_output(output, force_probe=force_probe)
        probe_outputs += metrics["probe_outputs"]
        asan_invocations += metrics["asan_invocations"]
        verdicts.update(metrics["verdicts"])

    with open(rawfile, "r", encoding="utf-8", errors="replace") as handle:
        for raw_line in handle:
            line = raw_line.strip()
            if not line:
                continue
            if "rate_limit_error" in line or "rate_limit_event" in line or "RESOURCE_EXHAUSTED" in line:
                rate_limits += 1
            if "Command was automatically cancelled" in line or "exceeded the timeout" in line:
                timeouts += 1
            try:
                event = json.loads(line)
            except (json.JSONDecodeError, ValueError):
                continue

            commands = []
            outputs = []

            if event.get("type") == "item.completed":
                item = event.get("item") or {}
                if item.get("type") == "command_execution":
                    cmd = item.get("command") or ""
                    commands.append(cmd)
                    output = text_value(item.get("aggregated_output") or item.get("output") or item)
                    outputs.append((output, bool(_BIN_PROBE_COMMAND_RE.search(cmd))))
                    pattern = waste_command_pattern(cmd)
                    record_waste_command(cmd)
                    record_waste_output(output, f"{pattern}: {cmd}")
            elif event.get("type") == "command_execution":
                cmd = event.get("command") or ""
                commands.append(cmd)
                output = text_value(event.get("aggregated_output") or event.get("output") or event)
                outputs.append((output, bool(_BIN_PROBE_COMMAND_RE.search(cmd))))
                pattern = waste_command_pattern(cmd)
                record_waste_command(cmd)
                record_waste_output(output, f"{pattern}: {cmd}")
            elif event.get("type") == "tool_use":
                opencode_tool = _opencode_tool_event(event)
                if opencode_tool is not None:
                    name = opencode_tool["name"]
                    native_name = _native_tool_name(name)
                    if native_name in _WASTE_NATIVE_NAMES:
                        waste_native[native_name] += 1
                    cmd = opencode_tool["input"].get("command") if isinstance(opencode_tool["input"], dict) else ""
                    output = opencode_tool["output"]
                    if name in _SHELL_TOOL_NAMES:
                        commands.append(cmd)
                        outputs.append((output, bool(_BIN_PROBE_COMMAND_RE.search(cmd))))
                        record_waste_command(cmd)
                    if output and name not in _WASTE_OBSERVABILITY_ONLY:
                        label = cmd or name or "tool"
                        record_waste_output(
                            output,
                            f"{waste_command_pattern(label) if name in _SHELL_TOOL_NAMES else native_name or name}: {label}",
                        )
                else:
                    name = event.get("tool_name") or event.get("name") or ""
                    native_name = _native_tool_name(name)
                    if native_name in _WASTE_NATIVE_NAMES:
                        waste_native[native_name] += 1
                    params = event.get("parameters") or event.get("input") or {}
                    cmd = params.get("command") if isinstance(params, dict) else ""
                    if name in _SHELL_TOOL_NAMES:
                        commands.append(cmd)
                        record_waste_command(cmd)
                    tool_id = event.get("tool_id") or event.get("id")
                    if tool_id:
                        top_level_pending[tool_id] = (name or "unknown", cmd or name or "unknown")
            elif event.get("type") == "tool_result":
                tool_id = event.get("tool_id") or event.get("tool_use_id") or event.get("id")
                name, label = top_level_pending.pop(tool_id, ("tool_result", "tool_result"))
                output = text_value(event.get("output") or event.get("content") or event)
                # Shell output carries probe/ASan/verdict text. The codex
                # (command_execution) and claude (tool_result) paths both feed it
                # into outputs; the gemini stream-json path must too, or
                # probe/verdict summaries read false-low for gemini runs.
                if name == "run_shell_command":
                    outputs.append((output, bool(_BIN_PROBE_COMMAND_RE.search(label))))
                if name not in _WASTE_OBSERVABILITY_ONLY:
                    record_waste_output(
                        output,
                        f"{waste_command_pattern(label) if name == 'run_shell_command' else name}: {label}",
                    )

            if event.get("type") == "assistant" or "message" in event:
                for item in claude_content_items(event):
                    if not isinstance(item, dict) or item.get("type") != "tool_use":
                        continue
                    name = item.get("name") or "unknown"
                    if name in _WASTE_NATIVE_NAMES:
                        waste_native[name] += 1
                    inp = item.get("input") or {}
                    cmd = inp.get("command") if isinstance(inp, dict) else ""
                    if name == "Bash":
                        commands.append(cmd)
                        record_waste_command(cmd)
                    tool_id = item.get("id")
                    if tool_id:
                        claude_pending[tool_id] = (name, cmd or name)

            if event.get("type") == "user" or "message" in event:
                for item in claude_content_items(event):
                    if not isinstance(item, dict) or item.get("type") != "tool_result":
                        continue
                    tool_id = item.get("tool_use_id")
                    name, label = claude_pending.pop(tool_id, ("tool_result", "tool_result"))
                    output = text_value(item.get("content") or item)
                    outputs.append((output, bool(_BIN_PROBE_COMMAND_RE.search(label))))
                    record_waste_output(output, f"{waste_command_pattern(label) if name == 'Bash' else name}: {label}")

            for cmd in commands:
                record_probe_command(cmd)
            for output, force_probe in outputs:
                record_probe_output(output, force_probe=force_probe)

    top_cmds = ",".join(f"{name}:{count}" for name, count in waste_command_patterns.most_common(5)) or "none"
    native_text = ",".join(f"{name}:{waste_native.get(name, 0)}" for name in _WASTE_NATIVE_NAMES)
    waste_telemetry = (
        f"tool_bytes={waste_tool_bytes} max_output={waste_max_output} over8k={waste_over8k} "
        f"native_tools={native_text} top_cmds={top_cmds} largest=\"{waste_largest_label}\""
    )

    return dict(
        probe_commands=probe_commands,
        probe_outputs=probe_outputs,
        asan_invocations=asan_invocations,
        timeouts=timeouts,
        rate_limits=rate_limits,
        verdicts=dict(verdicts),
        command_patterns=dict(command_patterns.most_common(10)),
        waste_telemetry=waste_telemetry,
    )


def build_payload(rawfile, logfile, summary_md, scan=None, waste_text=None):
    scan = scan or scan_raw_log(rawfile)
    waste = parse_waste(waste_text if waste_text is not None else (env("SESSION_SUMMARY_WASTE") or scan["waste_telemetry"]))
    raw_path = Path(rawfile)
    log_path = Path(logfile)
    return dict(
        schema_version=1,
        created_at=datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        target=env("SESSION_SUMMARY_TARGET"),
        backend=env("SESSION_SUMMARY_BACKEND"),
        model=env("SESSION_SUMMARY_MODEL"),
        agent=int_or_none(env("SESSION_SUMMARY_AGENT")),
        role=env("SESSION_SUMMARY_ROLE"),
        mode=env("SESSION_SUMMARY_MODE"),
        # Fields folded in from the dropped *.prompt.meta.json sidecar.
        # Empty strings mean "not recorded for this session" (e.g., when
        # the build-time stash wasn't available, as in older runs).
        subsystem=env("SESSION_SUMMARY_SUBSYSTEM"),
        suggested_subsystem=env("SESSION_SUMMARY_SUGGESTED_SUBSYSTEM"),
        strategy=env("SESSION_SUMMARY_STRATEGY"),
        launch=env("SESSION_SUMMARY_LAUNCH"),
        exit_code=int_or_none(env("SESSION_SUMMARY_EXIT")),
        tokens=dict(
            # prompt_estimate_build is the byte-based estimate made at
            # prompt-build time (`write_prompt_artifacts` -> .prompt_meta_N
            # stash). prompt_estimate is the historical alias retained for
            # older consumers; new callers should prefer the explicit
            # *_build / *_observed split when available.
            prompt_estimate=int_or_none(env("SESSION_SUMMARY_PROMPT_TOKENS")),
            prompt_estimate_build=int_or_none(env("SESSION_SUMMARY_PROMPT_TOKENS_BUILD")),
            input=int_or_none(env("SESSION_SUMMARY_INPUT_TOKENS")),
            # cache_read = tokens served from cache on this run. For Claude
            # this is `cache_read_input_tokens` summed across all messages;
            # for Codex it's whatever the backend reports as cached. The
            # gemini backend (Antigravity CLI) emits no usage telemetry —
            # this field is None for agy runs.
            cache_read=int_or_none(env("SESSION_SUMMARY_CACHED_INPUT_TOKENS")),
            # cache_creation = tokens written to cache on this run. Claude
            # only; other backends report None/empty.
            cache_creation=int_or_none(env("SESSION_SUMMARY_CACHE_CREATION_TOKENS")),
            # cached_input retained as the historical alias for cache_read so
            # older consumers (dashboards, index.jsonl readers) keep working.
            # New consumers should prefer cache_read + cache_creation.
            cached_input=int_or_none(env("SESSION_SUMMARY_CACHED_INPUT_TOKENS")),
            output=int_or_none(env("SESSION_SUMMARY_OUTPUT_TOKENS")),
            total=int_or_none(env("SESSION_SUMMARY_TOTAL_TOKENS")),
        ),
        runtime=dict(duration_ms=int_or_none(env("SESSION_SUMMARY_DURATION_MS"))),
        tools=dict(
            commands=int_or_zero(env("SESSION_SUMMARY_COMMANDS")),
            total=int_or_zero(env("SESSION_SUMMARY_TOOLS")),
            output_bytes=waste["tool_bytes"],
            max_output_bytes=waste["max_output"],
            outputs_over_8k=waste["over8k"],
            native=waste["native_tools"],
            top_commands=waste["top_commands"],
            largest_output=waste["largest"],
            observed_command_patterns=scan["command_patterns"],
        ),
        probe=dict(
            commands=scan["probe_commands"],
            outputs=scan["probe_outputs"],
            asan_invocations=scan["asan_invocations"],
            verdicts=scan["verdicts"],
        ),
        events=dict(rate_limits=scan["rate_limits"], timeouts=scan["timeouts"]),
        files=dict(
            raw=raw_path.name,
            log=log_path.name,
            summary_md=Path(summary_md).name,
            raw_bytes=raw_path.stat().st_size if raw_path.exists() else 0,
            log_bytes=log_path.stat().st_size if log_path.exists() else 0,
            raw_log_available=raw_path.exists(),
        ),
    )


def write_summary(payload, summary_md, index_jsonl):
    Path(summary_md).parent.mkdir(parents=True, exist_ok=True)
    with open(summary_md, "w", encoding="utf-8") as out:
        out.write("# Session Summary\n\n")
        out.write(
            f"- Session: {payload['role']} agent={payload['agent']} "
            f"backend={payload['backend']} mode={payload['mode']} strategy={_summary_value(payload.get('strategy'))}\n"
        )
        out.write(
            f"- Result: exit={payload['exit_code']} duration={_summary_value(payload['runtime']['duration_ms'])}ms "
            f"subsystem={_summary_value(payload.get('subsystem'))}\n"
        )
        out.write(
            f"- Tokens: total={_summary_value(payload['tokens']['total'])} "
            f"in={_summary_value(payload['tokens']['input'])} "
            f"cache_read={_summary_value(payload['tokens']['cache_read'])} "
            f"cache_create={_summary_value(payload['tokens']['cache_creation'])} "
            f"out={_summary_value(payload['tokens']['output'])}\n"
        )
        out.write(
            f"- Tools: calls={payload['tools']['total']} commands={payload['tools']['commands']} "
            f"output={_fmt_count(payload['tools']['output_bytes'])} "
            f"max={_fmt_count(payload['tools']['max_output_bytes'])} "
            f"oversized={payload['tools']['outputs_over_8k']}\n"
        )
        out.write(
            f"- Probe: commands={payload['probe']['commands']} sanitizer_runs={payload['probe']['asan_invocations']} "
            f"verdicts={json.dumps(payload['probe']['verdicts'], sort_keys=True)}\n"
        )
        out.write(f"- Largest tool output: {payload['tools']['largest_output']}\n")
        raw_hint = f".raw/{payload['files']['raw']}" if payload["files"].get("raw") else "n/a"
        out.write(f"\nRaw transcript: `{raw_hint}`. Open it only for literal backend output.\n")
    Path(index_jsonl).parent.mkdir(parents=True, exist_ok=True)
    # Concurrent agent finish handlers race here. Without flock, rows
    # larger than PIPE_BUF (4096 on Linux/macOS) can interleave; even
    # under that limit the guarantee depends on a single write() syscall
    # which Python's BufferedWriter does not promise across versions.
    # flock makes the append byte-safe regardless of row size.
    with _index_lock(index_jsonl):
        with open(index_jsonl, "a", encoding="utf-8") as out:
            out.write(json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n")


def main(argv):
    if len(argv) != 5:
        print("usage: audit_log_summary.py RAW LOG SUMMARY_MD INDEX_JSONL", file=sys.stderr)
        return 2
    rawfile, logfile, summary_md, index_jsonl = argv[1:5]
    if not Path(rawfile).is_file():
        return 0
    scan = scan_raw_log(rawfile)
    payload = build_payload(rawfile, logfile, summary_md, scan=scan)
    write_summary(payload, summary_md, index_jsonl)
    if env("SESSION_SUMMARY_PRINT_WASTE").lower() not in ("", "0", "false", "no"):
        print(scan["waste_telemetry"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
