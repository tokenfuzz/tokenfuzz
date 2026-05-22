#!/usr/bin/env python3
"""Claude Code PostToolUse hook: warn the agent when the conversation context
nears the auto-compaction threshold.

Auto-compaction in this harness fires near ~165K cached input tokens (observed
across libxml2 audit runs). Once it fires, un-checkpointed Working Context is
lost and the agent often re-recons. Warning the agent at ~100K gives it a
chance to write findings to AUDIT_STATE before the runtime collapses history.

Hook input arrives as JSON on stdin; we read transcript_path, scan it for the
latest cache_read_input_tokens value, and emit a hookSpecificOutput with
additionalContext when over CONTEXT_WARN_THRESHOLD (default 100000). Already-
warned thresholds are tracked per session_id so the message fires once per
band, not on every tool call.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

DEFAULT_THRESHOLD = 100_000
DEFAULT_HARD_THRESHOLD = 140_000


def _latest_cache_read(transcript_path: str) -> int:
    """Return the largest cache_read_input_tokens seen in the transcript."""
    p = Path(transcript_path)
    if not p.is_file():
        return 0
    best = 0
    try:
        with p.open("r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except Exception:
                    continue
                # Claude Code transcript shape: {"type":"assistant","message":{"usage":{...}}}
                msg = obj.get("message")
                if not isinstance(msg, dict):
                    continue
                usage = msg.get("usage")
                if not isinstance(usage, dict):
                    continue
                cr = usage.get("cache_read_input_tokens", 0)
                if isinstance(cr, int) and cr > best:
                    best = cr
    except OSError:
        pass
    return best


def _state_dir() -> Path:
    base = os.environ.get("CONTEXT_WARN_STATE_DIR")
    if base:
        return Path(base)
    return Path(os.environ.get("TMPDIR", "/tmp")) / "claude-context-warn"


def _already_warned(session_id: str, band: str) -> bool:
    """Return True iff this (session, band) pair was already warned this run."""
    if not session_id:
        return False
    d = _state_dir()
    try:
        d.mkdir(parents=True, exist_ok=True)
    except OSError:
        return False
    marker = d / f"{session_id}.{band}"
    if marker.exists():
        return True
    try:
        marker.write_text("1")
    except OSError:
        pass
    return False


def main() -> int:
    raw = sys.stdin.read()
    try:
        payload = json.loads(raw) if raw.strip() else {}
    except json.JSONDecodeError:
        return 0

    transcript_path = payload.get("transcript_path") or ""
    session_id = payload.get("session_id") or ""
    if not transcript_path:
        return 0

    threshold = int(os.environ.get("CONTEXT_WARN_THRESHOLD", DEFAULT_THRESHOLD))
    hard = int(os.environ.get("CONTEXT_WARN_HARD_THRESHOLD", DEFAULT_HARD_THRESHOLD))
    cache_read = _latest_cache_read(transcript_path)
    if cache_read < threshold:
        return 0

    band = "hard" if cache_read >= hard else "soft"
    if _already_warned(session_id, band):
        return 0

    if band == "hard":
        msg = (
            f"CONTEXT NEAR COMPACTION ({cache_read:,} cached tokens, hard threshold {hard:,}). "
            "Auto-compaction at ~165K will drop un-checkpointed history. "
            "STOP investigating new threads. Write current findings to your AUDIT_STATE Working Context "
            "via `bin/state add-note --kind context` NOW, then resume. Skip narration."
        )
    else:
        msg = (
            f"Context at {cache_read:,} cached tokens (soft threshold {threshold:,}). "
            "Auto-compaction at ~165K will drop un-checkpointed history. "
            "Checkpoint key data-flow / guard / variant findings to AUDIT_STATE Working Context "
            "via `bin/state add-note --kind context` before continuing."
        )

    print(json.dumps({
        "hookSpecificOutput": {
            "hookEventName": "PostToolUse",
            "additionalContext": msg,
        },
    }))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
