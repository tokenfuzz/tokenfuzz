#!/usr/bin/env python3
"""llm_usage.py — shared backend-log → usage object normaliser.

Two clients:

  - bin/benchmark calls this once per cell, asking for a complete
    {tokens, probe, estimated, backend} record that lib/benchmark.py::
    harvest_tokens drops into the cell's index.jsonl.
  - bin/audit calls this once per usage field at session end. Audit
    used to inline a jq pipeline that returned EMPTY for any agy
    plain-text transcript — silently pinning agy sessions to
    tokens=0 and tripping the dead-streak false-positive on every
    productive source-only investigation. The plain-text fallback
    in `_sum_assistant_content_chars` is the fix.

CLI shapes:

  llm_usage.py extract-usage <backend> <raw-log-path> [prompt-file]
      Print one JSON object on stdout: {tokens:{input, cached_input,
      cache_creation, cache_creation_1h, output}, probe:{}, estimated:bool,
      backend}. `cache_creation_1h` is a priced subset of cache_creation.
  llm_usage.py extract-field <field> <backend> <raw-log-path>
                            [--prompt prompt-file]
      Print one integer (or empty string for unknown) on stdout.
      <field> is one of: input_tokens, output_tokens,
      cached_input_tokens, cache_creation_input_tokens, total_tokens,
      duration_ms. Used by bin/audit's extract_usage_field shim.

  llm_usage.py extract-fields <backend> <raw-log-path> [--prompt prompt-file]
      Print the audit hot-path fields as key=value lines in one invocation:
      total_tokens, input_tokens, cached_input_tokens,
      cache_creation_input_tokens, output_tokens, duration_ms.

On any internal failure these commands print empty and exit 0 — a
missing cost number must never fail a benchmark cell or an audit
session.

Extraction paths:

  measured   — terminal/summary usage is reduced according to the backend's
               event contract. `estimated` is false.
  recovered  — a terminal-less Claude stream is summed by stable message id.
               Cache buckets are measured; incomplete fresh-input/output
               buckets make the whole row `estimated: true`. A terminal-less
               Codex stream is read from the rollout the session wrote while
               running, which is measured and stays `estimated: false`.
  estimated  — when a backend reports no usage and a prompt file is supplied,
               tokens are estimated from character counts and the row is
               flagged `estimated: true`. Codex/Claude logs without usable
               telemetry stay unknown rather than estimating from error text.

Token-field aliasing (different backends, different spellings):
  input          ← input_tokens / prompt_tokens / input
  cached_input   ← cached_input_tokens / cache_read_input_tokens / cached_input
  cache_creation ← cache_creation_input_tokens / cache_creation
  output         ← output_tokens / completion_tokens / output
cache_creation is the cache-WRITE counter — Claude reports it; codex
does not, so it stays 0 there. It is captured so the benchmark does not
silently drop a real billed input component (cache writes bill above
cache reads). Claude's explicit one-hour write bucket is retained separately
so it is priced at 2x rather than the five-minute 1.25x rate.
"""

from __future__ import annotations

import json
import math
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

import llm_invoke

_INPUT_KEYS = ("input_tokens", "prompt_tokens", "input")
# gemini-cli's result.stats names its cache-read counter `cached` (no
# `_input` / `_tokens` suffix); without this alias the 55M+ tokens it bills
# as cache reads are silently dropped from the cached_input column.
_CACHED_KEYS = (
    "cached_input_tokens", "cache_read_input_tokens", "total_cached_tokens",
    "cached_input", "cached",
)
_CACHE_CREATION_KEYS = (
    "cache_creation_input_tokens", "cache_write_input_tokens",
    "cache_write_tokens", "cache_creation",
)
_OUTPUT_KEYS = ("output_tokens", "completion_tokens", "output")

# Terminal/summary events carry the cumulative usage for ONE agent
# invocation: Claude Code CLI emits `result`, codex emits `turn.completed`,
# OpenCode emits `step_finish` / `step-finish`, and gemini-cli emits
# `result` (with a `stats` block). A single cell's raw log
# can hold several when the CLI was re-invoked / resumed and appended to the
# same file — the token usage object RESETS per invocation (only the
# stream's total_cost_usd keeps climbing). Their usage must be SUMMED;
# taking only the last terminal event silently drops every earlier
# invocation (observed as a ~100x undercount on a real multi-invocation
# cell). These are CLI event-type names, not target-specific vocabulary.
_TERMINAL_TYPES = ("result", "turn.completed", "step_finish", "step-finish")

# Rough chars-per-token ratio for the estimated path. ~4 is the common
# heuristic for English + code; it is only ever used when a backend (agy/Grok)
# refuses to report real usage, and the row is flagged `estimated`.
_CHARS_PER_TOKEN = 4


def usage_is_complete(usage: dict, returncode: int) -> bool:
    """Return whether a finished invocation supplied usable usage data.

    A zero exit is not enough: Codex and Claude can exit without their
    terminal usage event. Estimated backends remain complete when extraction
    produced an estimate; an all-zero native row is explicitly unknown.
    """
    if returncode != 0 or not isinstance(usage, dict):
        return False
    tokens = usage.get("tokens") or {}
    if not isinstance(tokens, dict):
        return False
    has_tokens = any(
        _nonnegative_int(tokens.get(key))
        for key in ("input", "cached_input", "cache_creation", "output")
    )
    return bool(has_tokens or usage.get("estimated") is True)


def _nonnegative_int(value: object) -> int:
    """Coerce one provider counter without trusting malformed telemetry."""
    if isinstance(value, bool):
        return 0
    try:
        return max(0, int(value or 0))
    except (OverflowError, TypeError, ValueError):
        return 0


def _first_int(d: dict, keys: tuple[str, ...]) -> int:
    for k in keys:
        v = d.get(k)
        if isinstance(v, (int, float)):
            parsed = _nonnegative_int(v)
            if parsed:
                return parsed
    return 0


def _looks_like_usage(d: dict) -> bool:
    return any(k in d for k in _INPUT_KEYS + _OUTPUT_KEYS)


def _cache_int(d: dict, key: str) -> int:
    cache = d.get("cache")
    if not isinstance(cache, dict):
        return 0
    v = cache.get(key)
    if isinstance(v, (int, float)):
        return _nonnegative_int(v)
    return 0


def _input_detail_int(d: dict, *keys: str) -> int:
    details = d.get("input_tokens_details")
    if not isinstance(details, dict):
        return 0
    return _first_int(details, keys)


def _cached_input_int(usage: dict) -> int:
    return (
        _first_int(usage, _CACHED_KEYS)
        or _cache_int(usage, "read")
        or _input_detail_int(usage, "cached_tokens", "cache_read_tokens")
    )


def _cache_write_int(usage: dict) -> int:
    return (
        _first_int(usage, _CACHE_CREATION_KEYS)
        or _cache_int(usage, "write")
        or _input_detail_int(
            usage, "cache_write_tokens", "cache_creation_tokens",
        )
    )


def _cache_creation_1h(usage: dict) -> int:
    """Return Claude's explicitly reported one-hour cache-write tokens."""
    detail = usage.get("cache_creation")
    if not isinstance(detail, dict):
        return 0
    value = detail.get("ephemeral_1h_input_tokens")
    return _nonnegative_int(value)


def _find_usage(obj: object) -> dict | None:
    """Depth-first hunt for the deepest dict that looks like a usage object."""
    if isinstance(obj, dict):
        # An explicit "usage" sub-object is the strongest signal.
        u = obj.get("usage")
        if isinstance(u, dict) and _looks_like_usage(u):
            return u
        if _looks_like_usage(obj):
            return obj
        for v in obj.values():
            found = _find_usage(v)
            if found is not None:
                return found
    elif isinstance(obj, list):
        for v in obj:
            found = _find_usage(v)
            if found is not None:
                return found
    return None


# Claude Code keys `modelUsage` by model plus the cache TTL it billed at, so a
# 1-hour-cache session reports `claude-opus-5[1m]` for a request of
# `claude-opus-5`. Matched to the shape of a TTL rather than to any bracketed
# suffix: `[1m]` is the observed one and the 5m/1h TTLs make siblings likely,
# but a bracket carrying something else is not a decoration to discard. Suffixes
# outside brackets are never stripped -- `gemini-3.5-flash` and
# `gemini-3.5-flash-lite` are different models at different prices.
_MODEL_DECORATION = re.compile(r"\[\d+[mh]\]$")


def model_id_matches(model: str, *model_ids: str) -> bool:
    """Match a model ID or its dated snapshot, without prefix collisions."""
    leaf = model.rsplit("/", 1)[-1].strip().lower()
    normalized = _MODEL_DECORATION.sub("", re.sub(r"\s+", "-", leaf)).strip()
    for model_id in model_ids:
        wanted = re.sub(r"\s+", "-", model_id.rsplit("/", 1)[-1].strip().lower())
        if normalized == wanted:
            return True
        if re.fullmatch(
            rf"{re.escape(wanted)}-(?:\d{{8}}|\d{{4}}-\d{{2}}-\d{{2}})",
            normalized,
        ):
            return True
    return False


# Where each CLI reports the model it actually billed, as {model_id: counters}.
# Claude Code puts `modelUsage` at the top level of its terminal result;
# gemini-cli nests `models` one level down under `stats`. Both are read at
# their exact position and never searched for: a transcript is mostly tool
# output, and an agent that curls an API returning its own "models" object
# would otherwise be read as the provider's billing record.
_SERVED_MODEL_PATHS = (("modelUsage",), ("stats", "models"))
# The per-model block also carries constants -- Claude Code reports
# `contextWindow` and `maxOutputTokens` beside the counters -- so "busiest"
# is decided by the token fields alone, never by every integer in the block.
_SERVED_TOKEN_KEYS = frozenset({
    "inputTokens", "outputTokens", "cacheReadInputTokens",
    "cacheCreationInputTokens", "total_tokens", "input_tokens", "output_tokens",
})


def _served_from_object(obj: object, into: dict[str, int]) -> None:
    if not isinstance(obj, dict):
        return
    for path in _SERVED_MODEL_PATHS:
        block = obj
        for key in path:
            block = block.get(key) if isinstance(block, dict) else None
        if not isinstance(block, dict):
            continue
        for name, counters in block.items():
            if not isinstance(name, str) or not isinstance(counters, dict):
                continue
            total = sum(
                value for key, value in counters.items()
                if key in _SERVED_TOKEN_KEYS
                and isinstance(value, int) and not isinstance(value, bool)
            )
            if total > 0:
                into[name] = into.get(name, 0) + total


def served_models(raw_path: "str | Path") -> dict[str, int]:
    """Models the provider actually billed in a transcript, by token total."""
    served: dict[str, int] = {}
    try:
        with Path(raw_path).open(encoding="utf-8", errors="replace") as stream:
            for line in stream:
                # A transcript is mostly tool output and can reach hundreds of
                # megabytes; only the few lines that could carry the block are
                # worth parsing.
                if "modelUsage" not in line and "models" not in line:
                    continue
                line = line.strip()
                if not line.startswith("{"):
                    continue
                try:
                    _served_from_object(json.loads(line), served)
                except ValueError:
                    continue
    except OSError:
        return {}
    return served


def substituted_model(raw_path: "str | Path", requested: str) -> str:
    """The model a provider served instead of `requested`, or "".

    A CLI that silently falls back answers a wrong `--model` with a cheerful
    success, so exit status cannot detect it. Every downstream number is then
    mislabelled: the row names a model that barely ran, and its traffic is
    priced at the requested model's rate.

    Judged on the busiest served model rather than on whether the requested one
    appears at all. One session legitimately bills more than one model -- Claude
    Code puts a small helper model in `modelUsage` beside the one it was asked
    for, and this harness prices those rows -- so treating any mismatched entry
    as substitution would refuse healthy runs. But a token of the requested
    model beside a million of another is still a mislabelled row, which
    "did it appear?" would wave through. Whichever model did the work is the
    one the row has to be named and priced for.
    """
    if not requested:
        return ""
    served = served_models(raw_path)
    if not served:
        return ""
    busiest = max(served, key=lambda name: served[name])
    return "" if model_id_matches(busiest, requested) else busiest


def _model_usage_tokens(obj: object) -> dict | None:
    """Sum Claude Code's top-level `modelUsage` across models.

    Claude's per-result `usage` reports only the final turn, so a
    multi-turn or resumed session undercounts the model's own spend
    (measured up to ~24x on wide fan-out sessions). `modelUsage` is the
    session-cumulative total keyed by model; its per-model tokens are
    summed here and priced at the cell's model downstream. Top-level
    only, so nested JSON in tool output cannot inflate usage.
    """
    if not isinstance(obj, dict):
        return None
    model_usage = obj.get("modelUsage")
    if not isinstance(model_usage, dict):
        return None
    keymap = {
        "input": "inputTokens",
        "cached_input": "cacheReadInputTokens",
        "cache_creation": "cacheCreationInputTokens",
        "output": "outputTokens",
    }
    out = {"input": 0, "cached_input": 0, "cache_creation": 0, "output": 0}
    for val in model_usage.values():
        if not isinstance(val, dict):
            continue
        for dst, src in keymap.items():
            v = val.get(src)
            if isinstance(v, (int, float)):
                out[dst] += _nonnegative_int(v)
    return out if any(out.values()) else None


def _estimate_tokens(text: str) -> int:
    return math.ceil(len(text) / _CHARS_PER_TOKEN) if text else 0


def _sum_assistant_content_chars(raw: str) -> int:
    """Estimate assistant-content char count from a text/streaming raw log.

    Two shapes show up here:

      stream-json  — gemini-cli and Grok Build emit JSON event streams. When the
                     stream dies before reporting usage (commonly a 429),
                     restricting the estimate to role=="assistant"
                     content avoids billing node.js stack traces and
                     tool-call parameter bodies as output — one observed
                     cell reported 308k "output" tokens against zero
                     assistant messages.

      plain text   — agy --print emits the assistant's reply as a flat
                     stdout transcript with no JSON events at all. In
                     that shape the whole raw log IS the assistant
                     content (mirrors lib/llm_invoke.py::extract_text's
                     agy branch); returning 0 here pins output to 0 for
                     every successful agy cell.

    Discriminator: if any line parses as JSON it is a stream-json
    transcript and the scanner stays restrictive; if no line parses, it
    is an agy plain-text transcript and we fall back to the raw length.
    """
    total = 0
    saw_json_event = False
    for line in raw.splitlines():
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            obj = json.loads(line)
        except ValueError:
            continue
        if not isinstance(obj, dict):
            continue
        saw_json_event = True
        if obj.get("type") == "text" and isinstance(obj.get("data"), str):
            total += len(obj["data"])
            continue
        if obj.get("role") != "assistant":
            continue
        content = obj.get("content")
        if isinstance(content, str):
            total += len(content)
        elif isinstance(content, list):
            for part in content:
                if isinstance(part, dict):
                    text = part.get("text") or part.get("content")
                    if isinstance(text, str):
                        total += len(text)
                elif isinstance(part, str):
                    total += len(part)
    if not saw_json_event:
        return len(raw)
    return total


def _read(path: str) -> str:
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return ""


def find_usage_index(results_dir: str | os.PathLike[str]) -> Path:
    """Return the cost ledger shared by a results tree and its harvester."""
    results = Path(results_dir)
    inside = results / "logs" / "index.jsonl"
    sibling = results.parent / "logs" / "index.jsonl"

    # Harness results always use the standard <backend>/results layout and
    # share the sibling <backend>/logs ledger with the agent pool.  Do not let
    # an incidental results/logs directory redirect finalization into a second
    # ledger.  Model-direct workspaces are the other documented layout and
    # keep their ledger in-tree.
    if sibling.is_file():
        return sibling
    if inside.is_file():
        return inside
    if sibling.parent.is_dir():
        return sibling
    if inside.parent.is_dir():
        return inside
    return inside


def _zero_usage() -> dict:
    return {
        "tokens": {
            "input": 0, "cached_input": 0, "cache_creation": 0,
            "cache_creation_1h": 0, "output": 0,
        },
        "probe": {},
        "estimated": False,
    }


def extract_usage(
    raw_log_path: str,
    prompt_path: str | None = None,
    backend: str = "",
) -> dict:
    """Return a {tokens:{...}, probe:{}, estimated:bool} row."""
    raw = _read(raw_log_path)
    prompt_text = _read(prompt_path) if prompt_path else ""
    return extract_usage_from_text(raw, prompt_text=prompt_text, backend=backend)


def _claude_per_request_usage(raw: str) -> tuple[dict, bool] | None:
    """Sum Claude's per-assistant-message usage, or None if the stream has none.

    Returns (tokens, estimated). Each API request reports its own usage under a
    stable `message.id`; the streamed event for one message can repeat with
    growing counters, so the largest snapshot per id is that request's total and
    those totals sum. Verified against a completed 236-request session: the
    cache-read and cache-creation buckets equal terminal `modelUsage` exactly.
    Fresh input can omit CLI-internal requests, so a terminal-less row is
    always marked estimated even when its generated-content floor is not the
    larger output value.

    Output does not: Claude reports a request's usage as the message begins, so
    `output_tokens` there is a stub (~2% of the real count) and the true figure
    only lands in the terminal event this path exists to replace. Generated
    content — reply text, thinking blocks, and serialized tool calls, all of
    which are billed output — gives a closer floor, so take whichever is
    larger. The row remains estimated because neither the generated-content
    floor nor the visible fresh-input counters are guaranteed complete.
    """
    def _generated_content_chars(content: object) -> int:
        """Conservative generated-content size for one Claude stream event."""
        if not isinstance(content, list):
            return 0
        total = 0
        for block in content:
            if not isinstance(block, dict):
                continue
            block_type = block.get("type")
            if block_type == "text" and isinstance(block.get("text"), str):
                total += len(block["text"])
            elif block_type == "thinking" and isinstance(block.get("thinking"), str):
                total += len(block["thinking"])
            elif block_type == "tool_use":
                name = block.get("name")
                if isinstance(name, str):
                    total += len(name)
                tool_input = block.get("input")
                if isinstance(tool_input, (dict, list)):
                    total += len(json.dumps(tool_input, separators=(",", ":")))
        return total

    per_message: dict[str, dict] = {}
    generated_chars = 0
    for line in raw.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            obj = json.loads(line)
        except ValueError:
            continue
        if not isinstance(obj, dict) or obj.get("type") != "assistant":
            continue
        message = obj.get("message")
        if not isinstance(message, dict):
            continue
        usage = message.get("usage")
        identifier = message.get("id")
        if not isinstance(usage, dict) or not identifier:
            continue
        candidate = {
            "input": _first_int(usage, _INPUT_KEYS),
            "cached_input": _cached_input_int(usage),
            "cache_creation": _cache_write_int(usage),
            "output": _first_int(usage, _OUTPUT_KEYS),
            "cache_creation_1h": _cache_creation_1h(usage),
        }
        if not any(candidate.values()):
            continue
        # Claude emits separate assistant events for the text/thinking/tool
        # blocks of one message id, while repeating that request's same usage
        # counters on each. Sum every generated block, but keep one usage row
        # per id.
        generated_chars += _generated_content_chars(message.get("content"))
        previous = per_message.get(identifier)
        if previous is None:
            per_message[identifier] = candidate
        else:
            per_message[identifier] = {
                key: max(previous[key], candidate[key])
                for key in candidate
            }
    if not per_message:
        return None
    totals = {
        key: sum(row[key] for row in per_message.values())
        for key in ("input", "cached_input", "cache_creation", "output", "cache_creation_1h")
    }
    floor = math.ceil(generated_chars / _CHARS_PER_TOKEN) if generated_chars else 0
    if floor > totals["output"]:
        totals["output"] = floor
    return totals, True


# Tool names that spawn a subagent, per backend transcript dialect. Claude
# Code exposes delegation as the `Agent` tool (`Task` before it was renamed);
# OpenCode's is `task`; Gemini CLI's is `invoke_agent`; Codex issues
# `spawn_agent` in the `collaboration` namespace, but only its rollout shows
# that call — the parent's --json stream never surfaces it, which is why the
# codex count comes from the rollout below.
_CLAUDE_DELEGATION_TOOLS = frozenset({"Agent", "Task"})
_GENERIC_DELEGATION_TOOLS = frozenset({
    "task", "agent", "subagent", "invoke_agent", "spawn_agent",
})
_CODEX_SPAWN_TOOL = "spawn_agent"
# Grok Build names `subagent_start` / `subagent_end` events with a
# `subagent_id` in its CLI binary, beside its hook event names — so they may
# reach hook scripts rather than the streaming-json output. Counted here on
# the chance the stream carries them; not confirmed against a live transcript,
# which is why Grok is also listed as unobservable below.
_GROK_SPAWN_EVENT = "subagent_start"

# Backends whose fan-out this reader cannot be sure to see at all. A row from
# one of these is disclosed as a seat-capacity floor whatever it counted.
_DELEGATION_UNOBSERVABLE = frozenset({"grok"})

# Backends whose delegated work runs where this session's usage cannot see
# it. Codex spawns a separate thread with its own rollout (unlinkable: the
# spawn returns a task name, not a thread id); OpenCode's `task` runs a
# separate session whose events never enter the parent's stream (measured:
# one session id in a transcript that delegated). Claude's subagents run in
# the same session and its terminal `modelUsage` carries them (measured: a
# delegating run reported 3.5x the tokens of a plain one); Gemini CLI's
# `invoke_agent` runs in-process and its `stats` is the session aggregate.
# Grok reports no usage at all (its rows are character estimates), so a
# subagent's spend there is unknown rather than merely unseen. A row for one
# of these backends with any delegation is a spend floor.
_CHILD_SPEND_UNATTRIBUTED = frozenset({"codex", "oss", "grok"})


def _delegation_events_from_text(raw: str, backend: str) -> int:
    """Subagent spawns visible in a streamed transcript, one per call id.

    Observed concurrency, never assumed: a cell recorded as one launch may
    delegate internally at the CLI's default, and the benchmark's seat-hour
    figures need to know when it did. Streams repeat a tool part as its state
    changes (OpenCode emits one `tool_use` per update), so calls are counted
    by id where the event carries one. Codex is counted from its rollout
    instead (see _codex_rollout_usage); its stream shows nothing.
    """
    if backend == "codex":
        return 0
    seen: set[str] = set()
    count = 0

    def note(identifier: object) -> None:
        nonlocal count
        key = str(identifier) if identifier else ""
        if key:
            if key in seen:
                return
            seen.add(key)
        count += 1

    for line in raw.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            event = json.loads(line)
        except ValueError:
            continue
        if not isinstance(event, dict):
            continue
        if backend == "claude":
            message = event.get("message")
            content = message.get("content") if isinstance(message, dict) else None
            for item in content if isinstance(content, list) else ():
                if (
                    isinstance(item, dict) and item.get("type") == "tool_use"
                    and item.get("name") in _CLAUDE_DELEGATION_TOOLS
                ):
                    note(item.get("id"))
            continue
        if backend == "grok":
            if event.get("type") == _GROK_SPAWN_EVENT:
                note(event.get("subagent_id") or event.get("id"))
            continue
        part = event.get("part")
        if isinstance(part, dict):
            if str(part.get("tool") or "").lower() in _GENERIC_DELEGATION_TOOLS:
                note(part.get("callID") or part.get("id"))
            continue
        if event.get("type") in ("tool_use", "tool_call"):
            name = str(
                event.get("tool_name") or event.get("name") or event.get("tool") or ""
            ).lower()
            if name in _GENERIC_DELEGATION_TOOLS:
                note(
                    event.get("tool_call_id") or event.get("call_id")
                    or event.get("tool_use_id") or event.get("id")
                )
    return count


def _mark_delegation(row: dict, backend: str, delegation: int) -> dict:
    """Stamp observed delegation, and the spend floor it implies, on a row.

    `estimated` already means "the counters are real but their coverage is a
    floor" (see the fallback paths below), and the report prints such cost
    with a `~` and withholds per-dollar efficiency, so a row whose delegated
    spend it cannot see joins that class rather than inventing a new one.
    `spend_lower_bound` names the reason.
    """
    row["delegation_events"] = delegation
    if backend in _DELEGATION_UNOBSERVABLE:
        row["delegation_observable"] = False
    if delegation > 0 and backend in _CHILD_SPEND_UNATTRIBUTED:
        row["estimated"] = True
        row["spend_lower_bound"] = True
    return row


def _codex_rollout_usage(raw: str) -> tuple[dict, int] | None:
    """Usage for every Codex thread in this transcript, from their rollouts.

    `turn.completed` is the stream's only usage report, and the harness stops
    half of a run's Codex sessions before it: both the turn soft cap and the
    wall deadline end a session mid-turn, and a model-direct cell always ends
    that way, so a whole audit priced as free. Codex writes a rollout per
    thread as it runs, and its last `token_count` matched a finished session's
    `turn.completed` usage field for field — measured, not estimated. It also
    covers threads the stream never reported, which is why it is preferred
    over the terminal events rather than used only as their fallback.

    All or nothing per transcript: partial coverage cannot be added to stream
    totals without double-counting the threads that appear in both, and a
    rollout that was read but not used is the only surviving record of that
    thread's spend. So unless every thread resolves, nothing is consumed and
    nothing is deleted.

    The residual is one in-flight request: counters land per completed
    request, so a kill mid-request loses that request alone — under a percent
    of a long session, against the whole session this recovers.
    """
    ids = []
    for line in raw.splitlines():
        if '"thread.started"' not in line:
            continue
        try:
            event = json.loads(line.strip())
        except ValueError:
            continue
        tid = event.get("thread_id") if isinstance(event, dict) else None
        if isinstance(tid, str) and tid and tid not in ids:
            ids.append(tid)
    if not ids:
        return None

    home = Path(os.environ.get("CODEX_HOME") or Path.home() / ".codex")
    resolved: dict[str, tuple[dict, int, list[Path]]] = {}
    for tid in ids:
        # Matched on the thread id this transcript reported, so a run never
        # reads or removes another session's rollout.
        paths = sorted(home.glob(f"sessions/**/rollout-*-{tid}.jsonl"))
        for path in paths:
            read = _rollout_last_token_count(path)
            if read is not None:
                usage, spawns = read
                resolved[tid] = (usage, spawns, paths)
                break
    if len(resolved) != len(ids):
        return None

    totals = dict.fromkeys(
        ("input", "cached_input", "cache_creation", "cache_creation_1h", "output"), 0
    )
    delegation = 0
    for usage, spawns, paths in resolved.values():
        totals["input"] += _first_int(usage, _INPUT_KEYS)
        totals["cached_input"] += _cached_input_int(usage)
        totals["cache_creation"] += _cache_write_int(usage)
        totals["output"] += _first_int(usage, _OUTPUT_KEYS)
        delegation += spawns
        for path in paths:
            try:
                path.unlink()
            except OSError:
                pass
    return totals, delegation


def _rollout_last_token_count(path: Path) -> tuple[dict, int] | None:
    """The rollout's last cumulative `token_count`, and its subagent spawns.

    Spawns are read in the same pass because the rollout is deleted once its
    usage is consumed; nothing else could count them afterwards. A spawned
    thread writes its own rollout that this reader cannot link back (the spawn
    call returns a task name, not a thread id), so the child's spend is not
    added here — the count is what makes that gap visible per session.
    """
    last = None
    spawns = 0
    try:
        with path.open(encoding="utf-8", errors="replace") as stream:
            for line in stream:
                if "token_count" not in line and _CODEX_SPAWN_TOOL not in line:
                    continue
                try:
                    event = json.loads(line)
                except ValueError:
                    continue
                payload = event.get("payload") if isinstance(event, dict) else None
                if not isinstance(payload, dict):
                    continue
                if (
                    payload.get("type") == "function_call"
                    and payload.get("name") == _CODEX_SPAWN_TOOL
                ):
                    spawns += 1
                    continue
                if payload.get("type") != "token_count":
                    continue
                info = payload.get("info")
                usage = info.get("total_token_usage") if isinstance(info, dict) else None
                if isinstance(usage, dict) and any(usage.values()):
                    last = usage
    except OSError:
        return None
    if last is None:
        return None
    return last, spawns


def extract_usage_from_text(
    raw: str,
    prompt_text: str = "",
    backend: str = "",
    *,
    estimate_missing: bool = False,
) -> dict:
    """Return a usage row from an already-read raw transcript."""

    reported_cost = 0.0
    delegation = _delegation_events_from_text(raw, backend)

    # Codex: the rollout covers every thread, including any the stream never
    # reported, so it outranks the terminal events below. Codex streams carry
    # no cost field, so returning here forfeits nothing.
    if backend == "codex":
        rollout = _codex_rollout_usage(raw)
        if rollout is not None:
            tokens, delegation = rollout
            return _mark_delegation({
                "tokens": tokens, "probe": {}, "estimated": False,
                "backend": backend,
            }, backend, delegation)

    def with_reported_cost(row: dict) -> dict:
        if reported_cost > 0:
            row["cost_usd"] = reported_cost
            row["cost_source"] = "backend-reported"
        return _mark_delegation(row, backend, delegation)

    # Primary path: SUM the usage of every terminal/summary event. Each
    # such event holds one invocation's cumulative total, and a cell may
    # contain several (re-invoked / resumed agent). Summing is the only
    # correct reduction; see _TERMINAL_TYPES for why last-wins undercounts.
    #
    # Exception: for Claude, prefer the top-level `modelUsage` block. The
    # foreground `usage` covers only the final turn, while `modelUsage` is
    # the session-cumulative total (all turns). It repeats verbatim or grows
    # across terminal events, so the largest snapshot is the session total;
    # summing it would multiply-count the repeats. Other backends emit no
    # modelUsage and fall through to the sum below.
    model_usage_best: dict | None = None
    model_usage_best_1h = 0
    model_usage_best_total = 0
    summed = {
        "input": 0, "cached_input": 0, "cache_creation": 0,
        "cache_creation_1h": 0, "output": 0,
    }
    saw_terminal = False
    for line in raw.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            obj = json.loads(line)
        except ValueError:
            continue
        if not isinstance(obj, dict) or obj.get("type") not in _TERMINAL_TYPES:
            continue
        cost = obj.get("total_cost_usd")
        if isinstance(cost, (int, float)):
            candidate_cost = float(cost)
            if math.isfinite(candidate_cost) and candidate_cost >= 0:
                reported_cost = max(reported_cost, candidate_cost)
        mu = _model_usage_tokens(obj)
        if mu is not None:
            total = sum(mu.values())
            if total > model_usage_best_total:
                model_usage_best = mu
                model_usage_best_total = total
                usage = _find_usage(obj)
                reported_1h = _cache_creation_1h(usage) if usage is not None else 0
                # Claude's terminal result reports the cache TTL split while
                # modelUsage carries the authoritative session total. Retain
                # the explicit overlap without guessing the TTL of any excess.
                model_usage_best_1h = min(mu["cache_creation"], reported_1h)
        usage = _find_usage(obj)
        if usage is None:
            continue
        candidate = {
            "input": _first_int(usage, _INPUT_KEYS),
            "cached_input": _cached_input_int(usage),
            "cache_creation": _cache_write_int(usage),
            "output": _first_int(usage, _OUTPUT_KEYS),
            "cache_creation_1h": _cache_creation_1h(usage),
        }
        if any(candidate.values()):
            saw_terminal = True
            for k in summed:
                summed[k] += candidate[k]
    if model_usage_best is not None:
        model_usage_best["cache_creation_1h"] = model_usage_best_1h
        return with_reported_cost({
            "tokens": model_usage_best, "probe": {}, "estimated": False,
            "backend": backend,
        })
    if saw_terminal:
        return with_reported_cost({
            "tokens": summed, "probe": {}, "estimated": False,
            "backend": backend,
        })

    # Fallback path A: Claude streams one per-request usage object per
    # assistant message, so a session that never reached its terminal event
    # (turn cap, wall-clock kill) can still recover its exact cache buckets and
    # a conservative floor for the rest. Taking the last one instead reports a
    # single request — a ~30x undercount on a long session, which would make a
    # capped run look free.
    per_request = _claude_per_request_usage(raw) if backend == "claude" else None
    if per_request is not None:
        tokens, output_estimated = per_request
        return with_reported_cost({
            "tokens": tokens, "probe": {}, "estimated": output_estimated,
            "backend": backend,
        })

    # Fallback path B: no terminal event carried usage (agent killed before
    # emitting one, or a backend that only streams per-turn usage). The
    # LAST non-zero usage object wins — one turn's counters standing in for
    # the session, so the row is flagged estimated: the counters are real but
    # the coverage is a floor, and reporting it as measured would publish an
    # arbitrarily large undercount as an exact total. A usage object that is
    # all-zero is not real telemetry, so it does not displace an earlier one.
    measured: dict | None = None
    for line in raw.splitlines():
        line = line.strip()
        if not line or not (line.startswith("{") or line.startswith("[")):
            continue
        try:
            obj = json.loads(line)
        except ValueError:
            continue
        usage = _find_usage(obj)
        if usage is not None:
            candidate = {
                "input": _first_int(usage, _INPUT_KEYS),
                "cached_input": _cached_input_int(usage),
                "cache_creation": _cache_write_int(usage),
                "output": _first_int(usage, _OUTPUT_KEYS),
                "cache_creation_1h": _cache_creation_1h(usage),
            }
            if any(candidate.values()):
                measured = candidate
    if measured is not None:
        return with_reported_cost({
            "tokens": measured, "probe": {}, "estimated": True,
            "backend": backend,
        })

    # Estimated path: no usage telemetry (agy/Grok Build). Do not estimate Codex /
    # Claude failures from stderr; those backends have real JSON usage when
    # they actually run, so an absent usage object means "unknown".
    if backend not in ("gemini", "grok") and not estimate_missing:
        return with_reported_cost({**_zero_usage(), "backend": backend})

    assistant_chars = _sum_assistant_content_chars(raw)
    if estimate_missing and raw and not assistant_chars:
        # One-shot decision backends return a plain JSON object. It is valid
        # JSON but not a streaming event with role/content fields, so count the
        # response itself instead of mistaking it for an empty transcript.
        assistant_chars = len(raw)
    tokens = {
        "input": _estimate_tokens(prompt_text),
        "cached_input": 0,
        "cache_creation": 0,
        "output": math.ceil(assistant_chars / _CHARS_PER_TOKEN) if assistant_chars else 0,
    }
    return with_reported_cost({
        "tokens": tokens, "probe": {}, "estimated": True, "backend": backend,
    })


def append_usage_event(
    index_path: str | os.PathLike[str] | None,
    *,
    backend: str,
    model: str,
    kind: str,
    prompt_text: str,
    raw_text: str | None = None,
    raw_path: str | os.PathLike[str] | None = None,
    usage_complete: bool = True,
) -> dict:
    """Append one measured-or-estimated invocation to the shared cost ledger."""
    if raw_text is None:
        raw_text = _read(os.fspath(raw_path)) if raw_path is not None else ""
    usage = extract_usage_from_text(
        raw_text, prompt_text=prompt_text, backend=backend,
        estimate_missing=True,
    )
    usage_complete = bool(usage_complete and usage_is_complete(usage, 0))
    if not index_path:
        return usage
    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "role": kind,
        "backend": backend,
        "model": model,
        "resolved_effort": llm_invoke.default_effort(backend),
        "usage_complete": usage_complete,
        **usage,
    }
    try:
        from workqueue import append_jsonl

        append_jsonl(Path(index_path), event)
    except (ImportError, OSError, ValueError):
        pass
    return usage


# ── Field-name aliases for extract-field so callers can ask for the
# field shape they're used to ("output_tokens", "duration_ms") without
# knowing this module's compact internal keys ("output").
_AUDIT_FIELD_ALIASES = {
    "input_tokens": ("input",),
    "output_tokens": ("output",),
    "cached_input_tokens": ("cached_input",),
    "cache_read_input_tokens": ("cached_input",),
    "cache_creation_input_tokens": ("cache_creation",),
    "total_tokens": ("input", "output"),   # sum of both
}


def extract_field(
    raw_log_path: str,
    field: str,
    backend: str = "",
    prompt_path: str | None = None,
) -> str:
    """Return one usage field as a string ('' for unknown). Scan the whole
    stream and return the maximum candidate
    value (Claude's running totals grow per turn; the LAST/MAX is the
    cumulative final).

    For `total_tokens` (no native field on any backend), sum the input
    and output components from the picked usage record.
    duration_ms is read from provider event fields directly.

    Missing files return '' on every backend — including the gemini
    plain-text path which would otherwise estimate 0. That matches the
    caller contract and keeps "I never wrote a raw log" distinguishable from "the
    agent produced no output."
    """
    if not os.path.isfile(raw_log_path):
        return ""

    if field == "duration_ms":
        return extract_duration_ms(raw_log_path)

    aliases = _AUDIT_FIELD_ALIASES.get(field)
    if aliases is None:
        return ""

    row = extract_usage(raw_log_path, prompt_path, backend=backend)
    tokens = row.get("tokens", {}) if isinstance(row, dict) else {}
    estimated = bool(row.get("estimated", False)) if isinstance(row, dict) else False

    # Distinguish "no telemetry found" from "telemetry says 0". For the
    # measured path (estimated=False) the helper returns an all-zero
    # tokens dict whether a usage block was found AND read as zero
    # (vanishingly rare on Claude/Codex) or no usage block existed at
    # all. The latter is the common case for empty / corrupt / wrong-
    # format raw logs. Return an empty field so callers can distinguish
    # missing telemetry from a measured zero. Distinguish by summing fields:
    # all-zero AND not estimated = nothing to report.
    measured_sum = 0
    for k in ("input", "output", "cached_input", "cache_creation"):
        measured_sum += _nonnegative_int(tokens.get(k))
    if not estimated and measured_sum == 0:
        return ""

    total = 0
    any_present = False
    for key in aliases:
        v = tokens.get(key)
        if isinstance(v, (int, float)):
            total += _nonnegative_int(v)
            any_present = True
    return str(total) if any_present else ""


def extract_fields(
    raw_log_path: str,
    backend: str = "",
    prompt_path: str | None = None,
) -> dict[str, str]:
    """Return every audit usage field without reparsing the raw log per field."""
    if not os.path.isfile(raw_log_path):
        return {
            "total_tokens": "",
            "input_tokens": "",
            "cached_input_tokens": "",
            "cache_creation_input_tokens": "",
            "output_tokens": "",
            "duration_ms": "",
        }

    raw = _read(raw_log_path)
    prompt_text = _read(prompt_path) if prompt_path else ""
    return extract_fields_from_text(raw, prompt_text=prompt_text, backend=backend)


def extract_fields_from_text(
    raw: str,
    prompt_text: str = "",
    backend: str = "",
) -> dict[str, str]:
    """Return every audit usage field from an already-read transcript."""
    fields = (
        "total_tokens",
        "input_tokens",
        "cached_input_tokens",
        "cache_creation_input_tokens",
        "output_tokens",
    )
    out = {field: "" for field in fields}
    out["duration_ms"] = ""

    row = extract_usage_from_text(raw, prompt_text=prompt_text, backend=backend)
    tokens = row.get("tokens", {}) if isinstance(row, dict) else {}
    estimated = bool(row.get("estimated", False)) if isinstance(row, dict) else False

    measured_sum = 0
    for k in ("input", "output", "cached_input", "cache_creation"):
        v = tokens.get(k)
        if isinstance(v, (int, float)):
            measured_sum += int(v)

    if estimated or measured_sum != 0:
        for field in fields:
            aliases = _AUDIT_FIELD_ALIASES.get(field, ())
            total = 0
            any_present = False
            for key in aliases:
                v = tokens.get(key)
                if isinstance(v, (int, float)):
                    total += int(v)
                    any_present = True
            if any_present:
                out[field] = str(total)

    out["duration_ms"] = extract_duration_ms_from_text(raw)
    return out


def extract_duration_ms(raw_log_path: str) -> str:
    """Return max duration_ms, matching extract_field(..., "duration_ms")."""
    if not os.path.isfile(raw_log_path):
        return ""
    return extract_duration_ms_from_text(_read(raw_log_path))


def extract_duration_ms_from_text(raw: str) -> str:
    """Return max duration_ms from an already-read raw transcript."""
    best = -1
    for line in raw.splitlines():
        line = line.strip()
        if not line or not line.startswith(("{", "[")):
            continue
        try:
            obj = json.loads(line)
        except ValueError:
            continue

        def visit(node):
            nonlocal best
            if isinstance(node, dict):
                v = node.get("duration_ms")
                if isinstance(v, (int, float)) and v > best:
                    best = int(v)
                for child in node.values():
                    visit(child)
            elif isinstance(node, list):
                for child in node:
                    visit(child)

        visit(obj)
    return str(best) if best >= 0 else ""


def main(argv: list[str]) -> int:
    if not argv:
        print("{}")
        return 0

    head = argv[0]

    if head == "extract-usage":
        if len(argv) < 3:
            print("{}")
            return 0
        backend = argv[1]
        raw_log = argv[2]
        prompt_path = argv[3] if len(argv) >= 4 else None
        try:
            print(json.dumps(extract_usage(raw_log, prompt_path, backend=backend)))
        except Exception:  # noqa: BLE001
            print("{}")
        return 0

    if head == "extract-field":
        # Form: extract-field <field> <backend> <raw-log> [--prompt path]
        if len(argv) < 4:
            print("")
            return 0
        field = argv[1]
        backend = argv[2]
        raw_log = argv[3]
        prompt_path = None
        # tiny hand-rolled --prompt scan; argparse would import a 20KB
        # module for one optional flag.
        i = 4
        while i < len(argv):
            if argv[i] == "--prompt" and i + 1 < len(argv):
                prompt_path = argv[i + 1]
                i += 2
            else:
                i += 1
        try:
            print(extract_field(raw_log, field, backend=backend, prompt_path=prompt_path))
        except Exception:  # noqa: BLE001
            print("")
        return 0

    if head == "extract-fields":
        # Form: extract-fields <backend> <raw-log> [--prompt path]
        if len(argv) < 3:
            return 0
        backend = argv[1]
        raw_log = argv[2]
        prompt_path = None
        i = 3
        while i < len(argv):
            if argv[i] == "--prompt" and i + 1 < len(argv):
                prompt_path = argv[i + 1]
                i += 2
            else:
                i += 1
        try:
            fields = extract_fields(raw_log, backend=backend, prompt_path=prompt_path)
            for key in (
                "total_tokens",
                "input_tokens",
                "cached_input_tokens",
                "cache_creation_input_tokens",
                "output_tokens",
                "duration_ms",
            ):
                print(f"{key}={fields.get(key, '')}")
        except Exception:  # noqa: BLE001
            for key in (
                "total_tokens",
                "input_tokens",
                "cached_input_tokens",
                "cache_creation_input_tokens",
                "output_tokens",
                "duration_ms",
            ):
                print(f"{key}=")
        return 0

    # Unrecognised subcommand: emit empty result, do not error.
    print("{}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
