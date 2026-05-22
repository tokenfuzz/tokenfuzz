#!/usr/bin/env python3
"""benchmark_model_direct_usage.py — normalise a model-direct-cell backend
log to one index.jsonl row.

The model-direct benchmark condition invokes a backend CLI directly (no
harness), so its token usage is buried in the backend's own JSON event
stream rather than in a harness logs/index.jsonl. This helper scans that
raw log and emits a single index.jsonl-shaped line so
lib/benchmark.py::harvest_tokens scores model-direct cost on the exact
same field as a harness cell.

  usage: benchmark_model_direct_usage.py <backend> <raw-log-path> [prompt-file]

It prints one JSON object to stdout — `{tokens, probe, estimated,
backend}`. `backend` is echoed back so lib/benchmark.py::harvest_tokens
can normalize the row (codex reports `input` as cached+fresh; claude
reports fresh only). On any failure it prints `{}` and exits 0 — a
missing cost number must never fail a benchmark cell.

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
import sys

_INPUT_KEYS = ("input_tokens", "prompt_tokens", "input")
# gemini-cli's result.stats names its cache-read counter `cached` (no
# `_input` / `_tokens` suffix); without this alias the 55M+ tokens it bills
# as cache reads are silently dropped from the cached_input column.
_CACHED_KEYS = ("cached_input_tokens", "cache_read_input_tokens", "cached_input", "cached")
_CACHE_CREATION_KEYS = ("cache_creation_input_tokens", "cache_creation")
_OUTPUT_KEYS = ("output_tokens", "completion_tokens", "output")

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


def _estimate_tokens(text: str) -> int:
    return math.ceil(len(text) / _CHARS_PER_TOKEN) if text else 0


def _sum_assistant_content_chars(raw: str) -> int:
    """Sum the length of `content` from JSON events with role == assistant.

    The estimated path only fires when a backend (agy) produced no usage
    telemetry — usually because it errored before emitting one. Estimating
    output as len(raw_log)/4 in that case folds node.js stack traces, tool
    invocation parameter bodies, and other non-output noise into the bill;
    one observed gemini cell reported 308k "output" tokens while its
    actual assistant content was empty. Restrict the estimate to the
    assistant message stream so an estimate-only cell tracks generated
    text, not error chatter.
    """
    total = 0
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

    # Measured path: scan the whole JSON event stream; the LAST usage
    # object with any non-zero field wins (backends emit a running or
    # final cumulative total). A usage object that is all-zero is not
    # real telemetry, so it does not displace an earlier real one.
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
                "cached_input": _first_int(usage, _CACHED_KEYS),
                "cache_creation": _first_int(usage, _CACHE_CREATION_KEYS),
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

    prompt_text = _read(prompt_path) if prompt_path else ""
    assistant_chars = _sum_assistant_content_chars(raw)
    tokens = {
        "input": _estimate_tokens(prompt_text),
        "cached_input": 0,
        "cache_creation": 0,
        "output": math.ceil(assistant_chars / _CHARS_PER_TOKEN) if assistant_chars else 0,
    }
    return {"tokens": tokens, "probe": {}, "estimated": True, "backend": backend}


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print("{}")
        return 0
    backend = argv[0]
    raw_log = argv[1]
    prompt_path = argv[2] if len(argv) >= 3 else None
    try:
        print(json.dumps(extract_usage(raw_log, prompt_path, backend=backend)))
    except Exception:  # noqa: BLE001 — cost extraction must never fail a cell
        print("{}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
