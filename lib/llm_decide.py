#!/usr/bin/env python3
"""Single-shot LLM JSON decision engine.

This module owns the budget-counter RMW, mock dispatch, backend subprocess
invocation, JSON extraction, and required-key validation. lib/llm_decide.sh
is now a 30-line bash shim that exec's into this module; Python callers
import `llm_decide()` directly.

Subcommands (run as `python3 lib/llm_decide.py <name> ...`):

  decide <decision-name> <required-keys-csv> <timeout-secs>
      Read prompt on stdin. Print the validated JSON on stdout (rc=0) or
      stay silent (rc=1) on any failure (mock missing, budget exhausted,
      backend timeout, unparseable response, missing required keys).

  budget-check [<max-calls>]
      Race-safe per-process budget RMW. Increments the counter file
      atomically under fcntl.flock and exits 0 if under cap, 1 if over.
      Used by the bash shim's `llm_decide_budget_available` function.

Public Python API (for direct import from bin/peer-fix-cards etc.):

  from llm_decide import llm_decide
  result = llm_decide("decision-name", "key1,key2", prompt, timeout=15)
  if result is None:
      # disabled / budget / extract / validate failure — fall back
      ...

Environment knobs (mirrors the prior bash contract exactly):

  LLM_DECIDE_DISABLE=1                   block real backend calls
  LLM_DECIDE_MOCK=<json|@path>           global mock for every decision
  LLM_DECIDE_MOCK_<UPPER>=<json|@path>   per-decision mock (wins over global)
  LLM_DECIDE_COUNTER_FILE=<path>         budget counter file location
  LLM_DECIDE_MAX_CALLS=<n>               budget cap (default 120 when
                                         LOGDIR/counter file is set,
                                         0 = unlimited)
  LLM_DECIDE_LOG=<path>                  audit-trail log file
  ACTIVE_BACKEND=<backend>                 concrete backend to dispatch to
                                           (one of: claude, codex, gemini, oss)
  BACKEND=<backend>                        alias used when ACTIVE_BACKEND is
                                           unset, for standalone helper calls
  MODEL=<name>                           per-backend model override
  CLAUDE_BIN / CODEX_BIN / GEMINI_BIN    backend binary overrides
  USE_GEMINI_CLI=1                       make the gemini backend invoke
                                         Google Gemini CLI instead of agy
"""

from __future__ import annotations

import argparse
import datetime as _dt
import fcntl
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Optional

# Import from llm_invoke.py — single source of truth for backend metadata
# and decide-mode flag construction. The previous version of this file
# duplicated `_backend_flags()` and `_MODEL_DEFAULTS`; both now live in
# lib/llm_invoke.py and are imported here (direct import, not subprocess,
# because both files live in the harness lib/ directory).
sys.path.insert(0, str(Path(__file__).resolve().parent))
from llm_invoke import (  # noqa: E402
    decide_flags as _decide_flags_for_backend,
    default_model as _default_model,
    gemini_default_bin as _gemini_default_bin,
    known_backend as _known_backend,
)


_KNOWN_BACKENDS = ("claude", "codex", "oss", "gemini")


def _utc_iso() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _llm_log(line: str) -> None:
    """Append to the LLM decision audit trail. Best-effort, never raises."""
    target = os.environ.get("LLM_DECIDE_LOG") or f"{os.environ.get('LOGDIR') or '/tmp'}/llm-decisions.log"
    try:
        Path(target).parent.mkdir(parents=True, exist_ok=True)
        with open(target, "a", encoding="utf-8") as f:
            f.write(f"{_utc_iso()} {line}\n")
    except OSError:
        pass


def _decision_upper(decision: str) -> str:
    """Map a kebab-case decision name to its env-var suffix.

    Bash uses `tr '[:lower:]-' '[:upper:]_' | tr -c '[:alnum:]_' '_'`.
    Mirror exactly so existing LLM_DECIDE_MOCK_<UPPER> env vars keep
    working unchanged.
    """
    out = []
    for ch in decision:
        if ch.isalnum() or ch == "_":
            out.append(ch.upper())
        elif ch == "-":
            out.append("_")
        else:
            out.append("_")
    return "".join(out)


def _resolve_mock_value(decision: str) -> str:
    upper = _decision_upper(decision)
    per = os.environ.get(f"LLM_DECIDE_MOCK_{upper}")
    if per is not None and per != "":
        return per
    return os.environ.get("LLM_DECIDE_MOCK", "")


# ── Budget counter (fcntl.flock race-safe) ──────────────────────────

def _counter_file() -> Optional[Path]:
    target = os.environ.get("LLM_DECIDE_COUNTER_FILE") or ""
    if not target:
        logdir = os.environ.get("LOGDIR") or ""
        if not logdir:
            return None
        target = f"{logdir}/llm-decisions.count"
    p = Path(target)
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
    except OSError:
        pass
    return p


def _budget_cap() -> int:
    raw = os.environ.get("LLM_DECIDE_MAX_CALLS", "120")
    try:
        return int(raw)
    except (TypeError, ValueError):
        return 120


def budget_available() -> bool:
    """Atomically consume one budget unit. Return True if under the cap.

    Race-safety: we fcntl.flock-acquire an exclusive lock on the counter
    file itself, RMW the integer it contains, then release. Concurrent
    callers serialize on the lock; lost-update races can't happen
    because the read+write are inside the same lock window.
    """
    cap = _budget_cap()
    if cap == 0:
        return True

    path = _counter_file()
    if path is None:
        # Standalone helpers such as setup-target / suggest-* should not
        # share a stale global /tmp budget across unrelated terminal runs.
        # Audit sessions set LOGDIR (or an explicit counter file), so their
        # decision budget remains session-scoped and persistent.
        return True
    try:
        # O_RDWR | O_CREAT — open without truncating any existing counter.
        fd = os.open(str(path), os.O_RDWR | os.O_CREAT, 0o644)
    except OSError:
        # Lock acquisition failed; fall open so a stuck disk does not
        # wedge the harness. Cost is at most one extra LLM call.
        return True

    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
        except OSError:
            return True
        try:
            os.lseek(fd, 0, os.SEEK_SET)
            blob = os.read(fd, 64).decode("utf-8", "replace").strip()
            try:
                v = int(blob) if blob else 0
            except ValueError:
                v = 0
            if v >= cap:
                return False
            new_blob = str(v + 1).encode("utf-8")
            os.lseek(fd, 0, os.SEEK_SET)
            os.write(fd, new_blob)
            os.ftruncate(fd, len(new_blob))
            return True
        finally:
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            except OSError:
                pass
    finally:
        try:
            os.close(fd)
        except OSError:
            pass


# ── Backend dispatch ────────────────────────────────────────────────
# Flag construction lives in lib/llm_invoke.py (single source of truth
# shared with the bash shim). We just wrap that here for callsite
# clarity — _backend_flags is the local name used in _invoke_backend.

def _backend_flags(backend: str, model: str) -> list[str]:
    return _decide_flags_for_backend(backend, model)


def _which(binary: str) -> Optional[str]:
    """Resolve a command name to an executable path, honoring PATH."""
    # Absolute path: just check executability.
    if os.path.sep in binary or binary.startswith("./"):
        return binary if os.access(binary, os.X_OK) else None
    for d in os.environ.get("PATH", "").split(os.pathsep):
        if not d:
            continue
        candidate = os.path.join(d, binary)
        if os.access(candidate, os.X_OK):
            return candidate
    return None


def _invoke_backend(
    backend: str,
    prompt: str,
    timeout_secs: int,
    decision: str = "",
    required_keys: str = "",
) -> Optional[str]:
    """Run the backend CLI and return its stdout text, or None on failure."""
    model = os.environ.get("MODEL", "") or _default_model(backend)

    if backend == "claude":
        bin_name = os.environ.get("CLAUDE_BIN", "claude")
        flags = _backend_flags("claude", model)
        cmd = [bin_name, *flags]
    elif backend in ("codex", "oss"):
        bin_name = os.environ.get("CODEX_BIN", "codex")
        flags = _backend_flags(backend, model)
        # codex takes `exec` subcommand + flags + `-` for stdin prompt.
        cmd = [bin_name, "exec", *flags, "-"]
    elif backend == "gemini":
        # Gemini backend keeps one name while switching CLI dialects via
        # USE_GEMINI_CLI. Both dialects accept -p "" with the prompt on
        # stdin for non-interactive calls.
        bin_name = os.environ.get("GEMINI_BIN") or _gemini_default_bin()
        flags = _backend_flags("gemini", model)
        # Empty -p arg forces non-interactive mode while the prompt is
        # read from stdin.
        cmd = [bin_name, *flags, "-p", ""]
    else:
        return None

    if _which(bin_name) is None:
        # Caller logs the specific no-<backend>-bin reason.
        raise FileNotFoundError(f"no-{backend}-bin")

    try:
        result = subprocess.run(
            cmd,
            input=prompt,
            capture_output=True,
            text=True,
            timeout=timeout_secs,
        )
    except subprocess.TimeoutExpired:
        raise
    except OSError:
        return None

    if result.returncode != 0:
        # Caller logs the backend-specific rc.
        raise subprocess.CalledProcessError(result.returncode, cmd, output=result.stdout, stderr=result.stderr)
    return result.stdout or ""


# ── JSON extraction & key validation ────────────────────────────────

_FENCE_RE = re.compile(r"^```", re.MULTILINE)


def _try_load(text: str):
    try:
        return json.loads(text)
    except (json.JSONDecodeError, ValueError, TypeError):
        return None


def _extract_first_fence(raw: str) -> Optional[str]:
    """If raw contains ``` fences, return the body of the first fence."""
    if not _FENCE_RE.search(raw):
        return None
    in_block = False
    out_lines = []
    for line in raw.splitlines():
        if line.startswith("```"):
            if in_block:
                break
            in_block = True
            continue
        if in_block:
            out_lines.append(line)
    body = "\n".join(out_lines).strip()
    return body or None


def _balanced_spans(raw: str, open_ch: str, close_ch: str) -> list[str]:
    """Return every top-level balanced open_ch…close_ch substring, in order.

    Depth is tracked outside of JSON string literals (with backslash-escape
    handling), so a brace/bracket inside a string value never opens or
    closes a span. An unbalanced run is skipped and the scan resumes at the
    next character — a stray `{` cannot swallow the rest of the input.
    """
    spans: list[str] = []
    n = len(raw)
    i = 0
    while i < n:
        if raw[i] != open_ch:
            i += 1
            continue
        depth = 0
        in_str = False
        esc = False
        j = i
        while j < n:
            c = raw[j]
            if in_str:
                if esc:
                    esc = False
                elif c == "\\":
                    esc = True
                elif c == '"':
                    in_str = False
            elif c == '"':
                in_str = True
            elif c == open_ch:
                depth += 1
            elif c == close_ch:
                depth -= 1
                if depth == 0:
                    spans.append(raw[i:j + 1])
                    break
            j += 1
        i = j + 1 if j < n else i + 1
    return spans


def _extract_json(raw: str) -> Optional[str]:
    """Pull the first parseable JSON object/array out of raw LLM output.

    1. Try the entire raw blob.
    2. Try the body of the first ``` fence (LLMs often wrap with ```json…```).
    3. Try the first brace-balanced {…} object span.
    4. Try the first bracket-balanced […] array span.

    Steps 3-4 use a depth-tracking, string-literal-aware scanner rather
    than a greedy `{.*}` / `[.*]` regex. The greedy form spanned from the
    first brace to the *last* one anywhere in the output, so a second
    object or any trailing prose containing a brace made the whole match
    unparseable and a perfectly recoverable first object was lost. Object
    spans are still considered before array spans, preserving the prior
    extraction order.
    """
    if _try_load(raw) is not None:
        return raw

    fenced = _extract_first_fence(raw)
    if fenced and _try_load(fenced) is not None:
        return fenced

    for candidate in _balanced_spans(raw, "{", "}"):
        if _try_load(candidate) is not None:
            return candidate

    for candidate in _balanced_spans(raw, "[", "]"):
        if _try_load(candidate) is not None:
            return candidate

    return None


def _validate_required_keys(parsed, required_csv: str) -> bool:
    """Return True iff every required key is present on the parsed value.

    Object root: each key must appear at top level.
    Array root: every element must contain each key.
    Anything else: fail.
    Empty required_csv: accept any valid JSON.
    """
    if not required_csv:
        return parsed is not None
    keys = [k.strip() for k in required_csv.split(",") if k.strip()]
    if not keys:
        return parsed is not None
    if isinstance(parsed, dict):
        return all(k in parsed for k in keys)
    if isinstance(parsed, list):
        return all(isinstance(el, dict) and all(k in el for k in keys) for el in parsed)
    return False


def _is_string_list(value) -> bool:
    return isinstance(value, list) and all(isinstance(item, str) for item in value)


def _is_bool(value) -> bool:
    return isinstance(value, bool)


def _is_string(value) -> bool:
    return isinstance(value, str)


def _is_optional_string(value) -> bool:
    """True for a string OR JSON null.

    Models routinely emit `"field": null` (rather than "") for an absent
    optional value. An absent key already validates via `.get(k, "")`, but
    an explicit null does not — and rejecting it would discard the WHOLE
    decision (e.g. a find_quality verdict's class/severity/dedup_key) over
    one empty descriptor field, then re-incur the call next pass. Treat
    null as "" for optional fields; required fields keep using _is_string."""
    return value is None or isinstance(value, str)


def _is_int(value) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _validate_decision_shape(decision: str, parsed) -> bool:
    """Validate known decision payload shapes for every backend.

    All backends use the same plain-text JSON contract. This runtime
    validator is the cross-backend guard that prevents a syntactically
    valid but type-wrong object from reaching consumers.
    """
    known_decisions = {
        "strategy_pick", "crash_triage", "crash_confirm", "legit_crash",
        "find_quality", "finding_key", "cluster_expand", "patch_review",
        "work_rerank", "s6-peer-suggest", "threat-model-suggest",
        "s6-peer-distill", "s6-peer-map",
    }
    if decision not in known_decisions:
        return True
    if not isinstance(parsed, dict):
        return False

    if decision == "strategy_pick":
        return _is_string(parsed.get("strategy")) and _is_string(parsed.get("reason"))
    if decision == "crash_triage":
        return _is_bool(parsed.get("keep")) and _is_string(parsed.get("reason"))
    if decision == "crash_confirm":
        concerns = parsed.get("concerns", [])
        return (
            _is_bool(parsed.get("accept"))
            and _is_string(parsed.get("reason"))
            and _is_string_list(concerns)
        )
    if decision == "legit_crash":
        return _is_bool(parsed.get("legitimate")) and _is_string(parsed.get("reason"))
    if decision == "find_quality":
        # find_quality is the QUALITY gate (accept/class/severity). Identity
        # (dedup_key) is no longer its job — it's assigned uniformly at cluster
        # time by the finding_key keyer (lib/finding_keyer.py), so it works the
        # same for harness, recon, and model-direct findings alike.
        return (
            _is_bool(parsed.get("accept"))
            and _is_string(parsed.get("reason"))
            and _is_string(parsed.get("class"))
            and _is_string(parsed.get("severity"))
        )
    if decision == "finding_key":
        # IDENTITY-only: the canonical root-cause key. Tolerates JSON null
        # (the model's common spelling of "absent"); an empty/invalid key just
        # degrades that finding to the deterministic (class, file, func) label.
        return _is_optional_string(parsed.get("dedup_key"))
    if decision == "cluster_expand":
        rows = parsed.get("rows")
        if not isinstance(rows, list):
            return False
        for row in rows:
            if not isinstance(row, dict):
                return False
            if not (
                _is_string(row.get("file"))
                and _is_string(row.get("function"))
                and _is_int(row.get("line"))
                and _is_string(row.get("hypothesis"))
                and _is_string(row.get("category"))
            ):
                return False
        return True
    if decision == "patch_review":
        return _is_string_list(parsed.get("fixed"))
    if decision == "work_rerank":
        cards = parsed.get("cards")
        if not isinstance(cards, list):
            return False
        for card in cards:
            if not isinstance(card, dict):
                return False
            if not (
                _is_string(card.get("id"))
                and _is_int(card.get("boost"))
                and _is_string(card.get("reason"))
            ):
                return False
        return True
    if decision == "s6-peer-suggest":
        return (
            _is_string(parsed.get("domain"))
            and _is_string_list(parsed.get("peers"))
            and _is_string(parsed.get("reasoning", ""))
        )
    if decision == "threat-model-suggest":
        return (
            _is_string_list(parsed.get("attacker_controls"))
            and _is_string(parsed.get("reasoning", ""))
        )
    if decision == "s6-peer-distill":
        return (
            _is_string(parsed.get("class"))
            and _is_string(parsed.get("summary"))
            and _is_string(parsed.get("shape"))
        )
    if decision == "s6-peer-map":
        return _is_string(parsed.get("file")) and _is_string(parsed.get("reason"))

    return True


# ── llm_decide entry points ─────────────────────────────────────────

def _load_mock(mock_val: str) -> Optional[str]:
    """Resolve a mock value, which may be inline JSON or @path/to/file."""
    if mock_val.startswith("@"):
        path = mock_val[1:]
        if not os.path.isfile(path):
            return None
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                return f.read()
        except OSError:
            return None
    return mock_val


def llm_decide(
    decision: str,
    required_keys: str,
    prompt: str,
    timeout: int = 15,
) -> Optional[dict | list]:
    """Run one LLM decision. Returns the parsed JSON, or None on any failure.

    The function pre-validates the mock contract so DISABLE=1 with a mock
    set still runs the mock (matches the prior bash precedence). On real
    backend dispatch, telemetry lines `<decision> <state> bytes=N elapsed=Ns`
    are emitted to the LLM decision log so cost-analysis tooling can sum
    prompt bytes + wall-clock per decision.
    """
    mock_val = _resolve_mock_value(decision)

    if not mock_val and os.environ.get("LLM_DECIDE_DISABLE", "0") == "1":
        _llm_log(f"{decision} SKIP disabled")
        return None

    if not prompt or not prompt.strip():
        # Reject whitespace-only prompts too. The prior bash engine
        # accepted them (bash `[ -n "$prompt" ]` is true for "   "), but
        # the prior Python wrapper rejected them, and existing tests
        # codify the stricter rule.
        # Validated BEFORE budget so a malformed/empty call from a buggy
        # caller does not deduct from the per-session backend budget.
        _llm_log(f"{decision} FAIL empty-prompt")
        return None

    if not budget_available():
        _llm_log(f"{decision} SKIP budget-exhausted max={_budget_cap()}")
        return None

    prompt_bytes = len(prompt.encode("utf-8", "replace"))
    t_start = time.time()

    raw: str = ""
    if mock_val:
        loaded = _load_mock(mock_val)
        if loaded is None:
            _llm_log(f"{decision} FAIL mock-missing {mock_val} bytes={prompt_bytes}")
            return None
        raw = loaded
        elapsed = int(time.time() - t_start)
        _llm_log(f"{decision} MOCK bytes={prompt_bytes} elapsed={elapsed}s")
    else:
        # Treat env-set-to-empty as unset (the bash shim exports vars with
        # default "" to bridge the unexported-variable gap; "" must fall
        # through the same way an unset var would). Require an explicit
        # ACTIVE_BACKEND is the concrete backend selected by bin/audit after
        # resolving AUDIT_BACKEND=all. Standalone helpers may use BACKEND.
        # If both are unset, fail rather than silently preferring a vendor.
        backend = os.environ.get("ACTIVE_BACKEND") or os.environ.get("BACKEND") or ""
        if not backend:
            _llm_log(f"{decision} FAIL no-backend-set bytes={prompt_bytes}")
            return None
        if backend not in _KNOWN_BACKENDS:
            _llm_log(f"{decision} FAIL unknown-backend={backend} bytes={prompt_bytes}")
            return None
        try:
            raw = _invoke_backend(backend, prompt, timeout, decision, required_keys) or ""
        except FileNotFoundError as exc:
            _llm_log(f"{decision} FAIL {exc} bytes={prompt_bytes}")
            return None
        except subprocess.TimeoutExpired:
            elapsed = int(time.time() - t_start)
            _llm_log(
                f"{decision} FAIL {backend}-rc=124 bytes={prompt_bytes} "
                f"elapsed={elapsed}s timeout={timeout}s"
            )
            return None
        except subprocess.CalledProcessError as exc:
            elapsed = int(time.time() - t_start)
            _llm_log(
                f"{decision} FAIL {backend}-rc={exc.returncode} bytes={prompt_bytes} "
                f"elapsed={elapsed}s timeout={timeout}s"
            )
            return None

    elapsed = int(time.time() - t_start)

    json_text = _extract_json(raw)
    if json_text is None:
        _llm_log(f"{decision} FAIL extract-json bytes={prompt_bytes} elapsed={elapsed}s")
        return None
    parsed = _try_load(json_text)
    if not _validate_required_keys(parsed, required_keys):
        _llm_log(f"{decision} FAIL missing-keys={required_keys} bytes={prompt_bytes} elapsed={elapsed}s")
        return None
    if not _validate_decision_shape(decision, parsed):
        _llm_log(f"{decision} FAIL invalid-shape bytes={prompt_bytes} elapsed={elapsed}s")
        return None

    _llm_log(f"{decision} OK bytes={prompt_bytes} elapsed={elapsed}s")
    return parsed


# ── CLI dispatch (used by the bash shim) ────────────────────────────

def _cmd_decide(args) -> int:
    # Mimic bash $(cat) — strip trailing newlines so byte-count telemetry
    # matches the prior bash engine's measurement (echo-piped prompts
    # carry a trailing \n that bash silently drops via command substitution).
    prompt = sys.stdin.read().rstrip("\n")
    result = llm_decide(args.decision, args.required_keys or "", prompt, args.timeout)
    if result is None:
        return 1
    # Emit canonical JSON: object roots in stable key order, no trailing
    # newline (callers may pipe straight into another tool).
    sys.stdout.write(json.dumps(result, separators=(",", ":"), ensure_ascii=False))
    return 0


def _cmd_budget_check(_args) -> int:
    return 0 if budget_available() else 1


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="llm_decide")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("decide")
    s.add_argument("decision")
    s.add_argument("required_keys", nargs="?", default="")
    s.add_argument("timeout", type=int, nargs="?", default=15)
    s.set_defaults(func=_cmd_decide)

    s = sub.add_parser("budget-check")
    s.set_defaults(func=_cmd_budget_check)

    return p


def main(argv=None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
