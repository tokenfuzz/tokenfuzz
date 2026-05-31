"""Optional read-time identity keyer for FIND-* findings.

Assigns a canonical root-cause ``dedup_key`` to a finding from its report text
ALONE — no coordination with sibling findings, no dependence on which model
authored the finding. One keyer pass keys every finding it is given with the
same backend, so a benchmark that pools several models' findings gets ONE
shared identity space (run the pass once over the combined pool and every
model's findings are canonicalized by the same brain).

Idempotent: a finding already carrying a current ``.finding-key.json`` is
skipped. Graceful: when no LLM backend is available the keyer is a no-op and
the finding stays on its deterministic ``(class, file, func)`` label, so
clustering never blocks on it.

bin/cluster-findings runs this keyer by DEFAULT (pass ``--no-key`` to skip), so
every finding starts from a root-cause dedup_key and falls back to the
deterministic ``(class, file, func)`` label only when no key could be produced.
Because the keyer no-ops without a backend, the deterministic fallback is also
exactly what you get offline and in tests.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Optional

import finding_signature as _fs

try:  # the LLM decision path; absent only in stripped-down environments
    import llm_decide as _llm
except Exception:  # pragma: no cover
    _llm = None

try:
    import prompt_render as _pr
except Exception:  # pragma: no cover
    _pr = None


CACHE_NAME = ".finding-key.json"
# Bump to re-key every finding after a prompt change. Stored in the cache so a
# key produced under an older rubric is recomputed rather than trusted.
KEY_VERSION = "v1"
_PROMPT = "finding_key.md.j2"
# The keyer uses the same per-decision timeout as other llm_decide calls
# (LLM_DECISION_TIMEOUT, which lib/triage.sh defaults to 45). It is not subject
# to the live-agent call-count budget: keying is a finite cached pass over
# FIND-* directories.
# A slow agentic backend (agy/gemini) routinely needs well over the old
# hardcoded 30s under load, which is what left gemini findings unkeyed.
_TIMEOUT_DEFAULT = 45
_BODY_BYTES = 8000


def _decision_timeout() -> int:
    """Per-decision timeout from LLM_DECISION_TIMEOUT (default 45, matches triage.sh)."""
    raw = os.environ.get("LLM_DECISION_TIMEOUT", "")
    try:
        return int(raw) if raw else _TIMEOUT_DEFAULT
    except ValueError:
        return _TIMEOUT_DEFAULT


def cached_key(find_dir) -> str:
    """Return the cached, current-version dedup_key for a FIND dir, or ""."""
    p = Path(find_dir) / CACHE_NAME
    if not p.is_file():
        return ""
    try:
        data = json.loads(p.read_text("utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError):
        return ""
    if data.get("key_version") != KEY_VERSION:
        return ""
    key = (data.get("dedup_key") or "").strip().lower()
    return key if _fs.is_valid_dedup_key(key) else ""


def ensure_key(find_dir, report_text: Optional[str] = None,
               timeout: Optional[int] = None) -> str:
    """Compute and cache the dedup_key for one FIND dir; return it (or "").

    Idempotent: returns the cached key when present and current. On a fresh
    finding it calls the keyer backend once over the report text alone. Returns
    "" — writing no cache — when no backend is available or the model declines
    a valid key, so the finding keeps its deterministic location label and can
    be keyed on a later pass.

    The ``timeout`` arg defaults to the harness-wide LLM_DECISION_TIMEOUT (45s)
    so the keyer is no more fragile than any other llm_decide call; pass an
    explicit value to override.
    """
    find_dir = Path(find_dir)
    existing = cached_key(find_dir)
    if existing:
        return existing
    if _llm is None or _pr is None:
        return ""
    call_timeout = _decision_timeout() if timeout is None else timeout
    if report_text is None:
        _, report_text = _fs._read_report(find_dir)
    if not report_text:
        return ""
    try:
        prompt = _pr.render_template(_PROMPT, {"body": report_text[:_BODY_BYTES]})
    except Exception:
        return ""
    try:
        result = _llm.llm_decide("finding_key", "dedup_key", prompt, call_timeout)
    except Exception:
        result = None
    if not isinstance(result, dict):
        return ""
    key = (result.get("dedup_key") or "").strip().lower()
    if not _fs.is_valid_dedup_key(key):
        return ""
    try:
        (find_dir / CACHE_NAME).write_text(
            json.dumps({"key_version": KEY_VERSION, "dedup_key": key}) + "\n",
            encoding="utf-8",
        )
    except OSError:
        pass
    return key


def ensure_keys(find_dirs, report_texts=None) -> dict:
    """Key a batch of FIND dirs. Returns {find_dir_name: dedup_key}.

    report_texts maps a dir name to its already-read report body, to avoid a
    second read when the caller has it (bin/cluster-findings does)."""
    report_texts = report_texts or {}
    out: dict[str, str] = {}
    for d in find_dirs:
        d = Path(d)
        out[d.name] = ensure_key(d, report_texts.get(d.name))
    return out
