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
      cache_creation, output}, probe:{}, estimated:bool, backend}.
      The legacy benchmark form (no `extract-usage` subcommand, the
      first arg is a known backend name) is still accepted so
      pre-rename callers keep working.

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

On any internal failure both shapes print empty and exit 0 — a
missing cost number must never fail a benchmark cell or an audit
session.

Two extraction paths:

  measured  — codex and claude emit a usage object in their JSON event
              stream; it is read directly. `estimated` is false.
  estimated — the gemini backend (Antigravity CLI / agy 1.0.0) emits NO
              usage telemetry on any surface: not in --print output, not
              in ~/.gemini/antigravity-cli/log/, only an undocumented
              protobuf conversation store. When no usage object is found
              and a prompt file is supplied, tokens are ESTIMATED from
              character counts and the row is flagged `estimated: true`
              so the ledger never presents an estimate as a measurement.
              Codex/Claude logs without usage are treated as unknown
              zeroes rather than estimating from error text.

Token-field aliasing (different backends, different spellings):
  input          ← input_tokens / prompt_tokens / input
  cached_input   ← cached_input_tokens / cache_read_input_tokens / cached_input
  cache_creation ← cache_creation_input_tokens / cache_creation
  output         ← output_tokens / completion_tokens / output
cache_creation is the cache-WRITE counter — Claude reports it; codex
does not, so it stays 0 there. It is captured so the benchmark does not
silently drop a real billed input component (cache writes bill above
cache reads). The last usage object seen in the stream wins (backends
emit a running or final cumulative total).
"""

from __future__ import annotations

import json
import math
import os
import sys

_INPUT_KEYS = ("input_tokens", "prompt_tokens", "input")
# gemini-cli's result.stats names its cache-read counter `cached` (no
# `_input` / `_tokens` suffix); without this alias the 55M+ tokens it bills
# as cache reads are silently dropped from the cached_input column.
_CACHED_KEYS = ("cached_input_tokens", "cache_read_input_tokens", "cached_input", "cached")
_CACHE_CREATION_KEYS = ("cache_creation_input_tokens", "cache_creation")
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
# heuristic for English + code; it is only ever used when a backend (agy)
# refuses to report real usage, and the row is flagged `estimated`.
_CHARS_PER_TOKEN = 4


def _first_int(d: dict, keys: tuple[str, ...]) -> int:
    for k in keys:
        v = d.get(k)
        if isinstance(v, (int, float)):
            return int(v)
    return 0


def _looks_like_usage(d: dict) -> bool:
    return any(k in d for k in _INPUT_KEYS + _OUTPUT_KEYS)


def _cache_int(d: dict, key: str) -> int:
    cache = d.get("cache")
    if not isinstance(cache, dict):
        return 0
    v = cache.get(key)
    if isinstance(v, (int, float)):
        return int(v)
    return 0


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


def _model_usage_tokens(obj: object) -> dict | None:
    """Sum Claude Code's top-level `modelUsage` across models.

    Claude's per-result `usage` reports only the final turn, so a
    multi-turn or resumed session undercounts the model's own spend
    (measured up to ~24x on recon slices). `modelUsage` is the
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
                out[dst] += int(v)
    return out if any(out.values()) else None


def _estimate_tokens(text: str) -> int:
    return math.ceil(len(text) / _CHARS_PER_TOKEN) if text else 0


def _sum_assistant_content_chars(raw: str) -> int:
    """Estimate assistant-content char count from a gemini raw log.

    Two shapes show up here:

      stream-json  — gemini-cli emits a JSON event stream. When the
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


def _zero_usage() -> dict:
    return {
        "tokens": {"input": 0, "cached_input": 0, "cache_creation": 0, "output": 0},
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


def extract_usage_from_text(
    raw: str,
    prompt_text: str = "",
    backend: str = "",
) -> dict:
    """Return a usage row from an already-read raw transcript."""

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
    model_usage_best_total = 0
    summed = {"input": 0, "cached_input": 0, "cache_creation": 0, "output": 0}
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
        mu = _model_usage_tokens(obj)
        if mu is not None:
            total = sum(mu.values())
            if total > model_usage_best_total:
                model_usage_best = mu
                model_usage_best_total = total
        usage = _find_usage(obj)
        if usage is None:
            continue
        candidate = {
            "input": _first_int(usage, _INPUT_KEYS),
            "cached_input": _first_int(usage, _CACHED_KEYS) or _cache_int(usage, "read"),
            "cache_creation": _first_int(usage, _CACHE_CREATION_KEYS) or _cache_int(usage, "write"),
            "output": _first_int(usage, _OUTPUT_KEYS),
        }
        if any(candidate.values()):
            saw_terminal = True
            for k in summed:
                summed[k] += candidate[k]
    if model_usage_best is not None:
        return {"tokens": model_usage_best, "probe": {}, "estimated": False,
                "backend": backend}
    if saw_terminal:
        return {"tokens": summed, "probe": {}, "estimated": False,
                "backend": backend}

    # Fallback path: no terminal event carried usage (agent killed before
    # emitting one, or a backend that only streams per-turn usage). The
    # LAST non-zero usage object wins — a floor, not a proven total. A
    # usage object that is all-zero is not real telemetry, so it does not
    # displace an earlier real one.
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
                "cached_input": _first_int(usage, _CACHED_KEYS) or _cache_int(usage, "read"),
                "cache_creation": _first_int(usage, _CACHE_CREATION_KEYS) or _cache_int(usage, "write"),
                "output": _first_int(usage, _OUTPUT_KEYS),
            }
            if any(candidate.values()):
                measured = candidate
    if measured is not None:
        return {"tokens": measured, "probe": {}, "estimated": False,
                "backend": backend}

    # Estimated path: no usage telemetry (agy). Do not estimate Codex /
    # Claude failures from stderr; those backends have real JSON usage when
    # they actually run, so an absent usage object means "unknown".
    if backend != "gemini":
        return {**_zero_usage(), "backend": backend}

    assistant_chars = _sum_assistant_content_chars(raw)
    tokens = {
        "input": _estimate_tokens(prompt_text),
        "cached_input": 0,
        "cache_creation": 0,
        "output": math.ceil(assistant_chars / _CHARS_PER_TOKEN) if assistant_chars else 0,
    }
    return {"tokens": tokens, "probe": {}, "estimated": True, "backend": backend}


# ── Known backends; used to detect the legacy `backend raw [prompt]` form
# (no subcommand). Kept in sync with lib/llm_invoke.py::_KNOWN_BACKENDS.
_KNOWN_BACKENDS = ("claude", "codex", "gemini", "oss")

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
    """Return one usage field as a string ('' for unknown), suitable for
    a bash `$(... )` substitution. Aggregation matches the legacy jq
    pipeline: scan the whole stream, return the MAX of any candidate
    value (Claude's running totals grow per turn; the LAST/MAX is the
    cumulative final).

    For `total_tokens` (no native field on any backend), sum the input
    and output components from the picked usage record.
    duration_ms is read from the legacy field name directly.

    Missing files return '' on every backend — including the gemini
    plain-text path which would otherwise estimate 0. That matches the
    legacy jq-based extract_usage_field's `[ -f "$file" ] || echo ""`
    guard and keeps "I never wrote a raw log" distinguishable from "the
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
    # format raw logs, and the right bash semantic there is the empty
    # string (audit's `$(extract_usage_field …)` consumers all use
    # `${var:-0}` to floor). Distinguish by summing measured fields:
    # all-zero AND not estimated = nothing to report.
    measured_sum = 0
    for k in ("input", "output", "cached_input", "cache_creation"):
        v = tokens.get(k)
        if isinstance(v, (int, float)):
            measured_sum += int(v)
    if not estimated and measured_sum == 0:
        return ""

    total = 0
    any_present = False
    for key in aliases:
        v = tokens.get(key)
        if isinstance(v, (int, float)):
            total += int(v)
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

    # Legacy form: <backend> <raw-log> [prompt-file]
    if head in _KNOWN_BACKENDS:
        if len(argv) < 2:
            print("{}")
            return 0
        backend = head
        raw_log = argv[1]
        prompt_path = argv[2] if len(argv) >= 3 else None
        try:
            print(json.dumps(extract_usage(raw_log, prompt_path, backend=backend)))
        except Exception:  # noqa: BLE001 — cost extraction must never fail a cell
            print("{}")
        return 0

    # Subcommand form: extract-usage / extract-field
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
