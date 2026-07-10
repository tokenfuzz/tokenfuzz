#!/usr/bin/env python3
"""Single-shot LLM JSON decision engine.

This module owns the budget-counter RMW, mock dispatch, backend subprocess
invocation, JSON extraction, and required-key validation. Production callers
import `llm_decide()` directly; the CLI exposes the same engine.

Subcommands (run as `python3 lib/llm_decide.py <name> ...`):

  decide <decision-name> <required-keys-csv> <timeout-secs>
      Read prompt on stdin. Print the validated JSON on stdout (rc=0) or
      stay silent (rc=1) on any failure (mock missing, budget exhausted,
      backend timeout, unparseable response, missing required keys).

  budget-check [<max-calls>]
      Race-safe per-process budget RMW. Increments the counter file
      atomically under fcntl.flock and exits 0 if under cap, 1 if over.
      Available to command-line callers that need an explicit budget probe.

Public Python API (for direct import from bin/peer-fix-cards etc.):

  from llm_decide import llm_decide
  result = llm_decide("decision-name", "key1,key2", prompt, timeout=15)
  if result is None:
      # disabled / budget / extract / validate failure — fall back
      ...

Environment controls:

  LLM_DECIDE_DISABLE=1                   block real backend calls
  LLM_DECIDE_MOCK=<json|@path>           global mock for every decision
  LLM_DECIDE_MOCK_<UPPER>=<json|@path>   per-decision mock (wins over global)
  LLM_DECIDE_MOCK_<UPPER>_QUEUE=<path>   sequence-of-verdicts mock — file
                                         holds JSON objects separated by
                                         `\n---\n`; each call pops the next
                                         and a sibling `<path>.idx` file
                                         tracks the cursor. After the queue
                                         is exhausted the last value sticks.
                                         Wins over LLM_DECIDE_MOCK_<UPPER>.
                                         Use for testing multi-vote gates.
  LLM_DECIDE_COUNTER_FILE=<path>         budget counter file location
  LLM_DECIDE_MAX_CALLS=<n>               budget cap (default 1000 when
                                         LOGDIR/counter file is set,
                                         0 = unlimited).
  LLM_DECIDE_FAILCACHE_FILE=<path>       circuit-breaker state file location
                                         (defaults to LOGDIR/llm-decisions.failcache).
  LLM_DECIDE_FAIL_THRESHOLD=<n>          consecutive identical-request failures
                                         before the breaker opens and skips
                                         re-issuing that decision (default 2,
                                         0 = disabled).
  LLM_DECIDE_TYPE_FAIL_THRESHOLD=<n>     consecutive fast backend errors for a
                                         decision type before that whole class
                                         is paused (default 8, 0 = disabled).
  LLM_DECIDE_FAIL_COOLDOWN=<secs>        once tripped, how long a key stays
                                         skipped before one half-open retry is
                                         allowed (so a transiently unhealthy
                                         backend self-heals). 0 = stay open for
                                         the whole session (no retry). Unset,
                                         the default is backend-tiered: 1800s
                                         (30 min) for oss — retries are an
                                         expensive ~180s timeout and failures
                                         are usually deterministic — and 300s
                                         (5 min) for cloud backends, whose
                                         failures are usually transient and
                                         cheap to retry, so a healthy cloud
                                         target recovers fast.
  LLM_DECIDE_LOG=<path>                  audit-trail log file
  ACTIVE_BACKEND=<backend>                 concrete backend to dispatch to
                                           (one of: claude, codex, gemini, grok, oss)
  BACKEND=<backend>                        alias used when ACTIVE_BACKEND is
                                           unset, for standalone helper calls
  MODEL=<name>                           per-backend model override
  CLAUDE_BIN / CODEX_BIN / GEMINI_BIN / GROK_BIN /
  OPENCODE_BIN                           backend binary overrides
  USE_GEMINI_CLI=1                       make the gemini backend invoke
                                         Google Gemini CLI instead of agy
"""

from __future__ import annotations

import argparse
import datetime as _dt
import fcntl
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
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
    extract_text as _extract_backend_text,
    gemini_default_bin as _gemini_default_bin,
    invocation_env as _invocation_env,
    opencode_config as _opencode_config,
)


_KNOWN_BACKENDS = ("claude", "codex", "oss", "gemini", "grok")


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


def _pop_queue_mock(queue_path: str) -> str:
    """Pop the next JSON object from a queue file shared across subprocess calls.

    Verdicts are separated by lines containing exactly `---`. A sibling
    `.idx` file holds the next-call cursor (created on first use). When the
    queue is exhausted the last entry sticks — that way a finite sequence
    can drive an unknown number of votes by ending with the steady-state
    response. Returns "" on any failure so the caller falls back through
    the normal resolution chain.
    """
    try:
        with open(queue_path, "r", encoding="utf-8", errors="replace") as f:
            raw = f.read()
    except OSError:
        return ""
    items = [chunk.strip() for chunk in re.split(r"(?m)^---\s*$", raw) if chunk.strip()]
    if not items:
        return ""
    idx_path = f"{queue_path}.idx"
    try:
        cur = int(Path(idx_path).read_text("utf-8").strip())
    except (OSError, ValueError):
        cur = 0
    if cur < 0:
        cur = 0
    if cur >= len(items):
        # Past the end — return the last entry without advancing.
        return items[-1]
    try:
        Path(idx_path).write_text(str(cur + 1), encoding="utf-8")
    except OSError:
        pass
    return items[cur]


def _resolve_mock_value(decision: str) -> str:
    upper = _decision_upper(decision)
    queue = os.environ.get(f"LLM_DECIDE_MOCK_{upper}_QUEUE")
    if queue:
        popped = _pop_queue_mock(queue)
        if popped:
            return popped
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
    raw = os.environ.get("LLM_DECIDE_MAX_CALLS", "1000")
    try:
        return int(raw)
    except (TypeError, ValueError):
        return 1000


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


# ── Failed-decision circuit breaker ─────────────────────────────────
# A failed decision writes no success marker, so callers can re-issue the
# identical request every pass and re-pay the full backend timeout. We record
# failures keyed by (decision, prompt hash) in a
# session-scoped file beside the budget counter; once a key reaches the
# threshold the breaker opens and identical requests are skipped without a
# backend call. A later success clears the key and re-arms the breaker, so
# the threshold counts *consecutive* failures.
#
# To survive a *transiently* unhealthy backend, the breaker is half-open:
# a tripped key is skipped only until the cooldown elapses since its last
# failure, after which one retry is allowed. If that retry succeeds the key
# clears; if it fails the cooldown restarts. This bounds the waste of a
# permanently-failing decision to ~one attempt per cooldown window while
# letting a recovered backend resume on its own. Each entry is stored as
# [failure_count, last_failure_epoch] (a bare int is also accepted for
# tolerance); any malformed value is read as count 0.
#
# The cooldown default is backend-tiered (see _fail_cooldown): a healthy
# cloud backend that hiccups recovers in minutes, while OSS's expensive,
# usually-deterministic 180s timeouts are retried far less often. The
# breaker only engages after threshold consecutive *identical* failures, so
# a healthy backend never reaches this logic at all.

def _failcache_file() -> Optional[Path]:
    target = os.environ.get("LLM_DECIDE_FAILCACHE_FILE") or ""
    if not target:
        logdir = os.environ.get("LOGDIR") or ""
        if not logdir:
            # Standalone helpers (no session LOGDIR) have no persistent
            # failcache, mirroring the budget counter's scoping.
            return None
        target = f"{logdir}/llm-decisions.failcache"
    p = Path(target)
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
    except OSError:
        pass
    return p


def _fail_threshold() -> int:
    raw = os.environ.get("LLM_DECIDE_FAIL_THRESHOLD", "2")
    try:
        return int(raw)
    except (TypeError, ValueError):
        return 2


def _type_fail_threshold() -> int:
    """Consecutive fast-backend-error count that opens the per-DECISION-TYPE
    breaker. Set higher than the per-prompt threshold: the type breaker
    sidelines a whole decision class (every prompt of it), so it must be sure
    the class — not one unlucky prompt — is the thing failing. A single success
    re-arms it. Set to 0 to disable."""
    raw = os.environ.get("LLM_DECIDE_TYPE_FAIL_THRESHOLD", "8")
    try:
        return int(raw)
    except (TypeError, ValueError):
        return 8


# Backend-tiered cooldown defaults: oss retries pay an expensive (~180s)
# usually-deterministic timeout, so they back off hard; cloud APIs fail
# transiently and retry cheaply, so they recover fast. (The long tier is any
# slow-local-inference backend — only oss today.)
_COOLDOWN_OSS = 1800.0     # 30 min
_COOLDOWN_CLOUD = 300.0    # 5 min


def _fail_cooldown() -> float:
    raw = os.environ.get("LLM_DECIDE_FAIL_COOLDOWN")
    if raw:  # explicit override (the shim force-exports "" when unset)
        try:
            return float(raw)
        except (TypeError, ValueError):
            pass
    backend = os.environ.get("ACTIVE_BACKEND") or os.environ.get("BACKEND") or ""
    return _COOLDOWN_OSS if backend == "oss" else _COOLDOWN_CLOUD


def _failcache_key(decision: str, prompt: str) -> str:
    digest = hashlib.sha1(prompt.encode("utf-8", "replace")).hexdigest()[:16]
    return f"{decision}:{digest}"


def _type_key(decision: str) -> str:
    # Distinct namespace from a per-prompt key ("{decision}:{sha1}") so the
    # per-prompt and per-type breakers never collide in the failcache map.
    return f"__type__:{decision}"


def _entry(value) -> tuple[int, float]:
    """Parse a failcache entry into (failure_count, last_failure_epoch).

    Accepts the [count, ts] shape and tolerates any corrupt, partially written,
    or tampered value (→ (0, 0.0)) so the
    best-effort failcache never raises into the decision path — the same
    "fall open, never crash" discipline as _llm_log and budget_available.
    """
    count, ts = 0, 0.0
    try:
        if not isinstance(value, list):
            return 0, 0.0
        if value:
            count = int(value[0])
        if len(value) >= 2:
            ts = float(value[1])
    except (TypeError, ValueError):
        return 0, 0.0
    return count, ts


def _failcache_update(mutate, default):
    """Run mutate(data) under the failcache's exclusive lock.

    mutate receives the parsed dict (any malformed content is normalized to
    {}) and returns (result, dirty); the file is rewritten only when dirty.
    The exclusive lock — the same fcntl.flock discipline as the budget
    counter — makes the read-decide-write one atomic step, so concurrent
    decide subprocesses cannot lose updates or both claim a half-open retry.
    Returns `default` (without calling mutate) when the failcache is
    unavailable, so callers fall open.
    """
    path = _failcache_file()
    if path is None:
        return default
    try:
        fd = os.open(str(path), os.O_RDWR | os.O_CREAT, 0o644)
    except OSError:
        return default
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
        except OSError:
            return default
        try:
            os.lseek(fd, 0, os.SEEK_SET)
            blob = os.read(fd, 1 << 20).decode("utf-8", "replace").strip()
            try:
                data = json.loads(blob) if blob else {}
            except ValueError:
                data = {}
            if not isinstance(data, dict):
                data = {}
            result, dirty = mutate(data)
            if dirty:
                new_blob = json.dumps(data, separators=(",", ":")).encode("utf-8")
                os.lseek(fd, 0, os.SEEK_SET)
                os.write(fd, new_blob)
                os.ftruncate(fd, len(new_blob))
            return result
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


def _breaker_step(data, key: str, threshold: int, cooldown: float) -> "tuple[bool, bool]":
    """Half-open breaker verdict for one failcache key. Returns (skip, dirty).

    A key at/above `threshold` failures is skipped until `cooldown` elapses
    since its last failure, after which exactly ONE half-open retry is claimed
    (its timestamp stamped to now → dirty=True) and let through; concurrent
    callers then see a fresh window and skip. Below threshold — or threshold
    <= 0 — never skips. Operates on the caller's already-locked `data` so the
    per-prompt and per-type checks share one atomic read-decide-write.
    """
    if threshold <= 0:
        return False, False
    count, last = _entry(data.get(key))
    if count < threshold:
        return False, False      # not tripped → don't skip, no write
    if cooldown <= 0:
        return True, False       # open for the whole session → skip
    if not last or (time.time() - last) >= cooldown:
        data[key] = [count, time.time()]
        return False, True       # claim the single half-open retry
    return True, False           # still cooling down → skip


def _failcache_should_skip(decision: str, prompt: str) -> bool:
    """True iff this decision call should be skipped now.

    Two breakers share one locked read-decide-write. The per-PROMPT breaker
    stops a repeat of the identical (decision, prompt) that keeps failing. The
    per-TYPE breaker stops a whole decision class that is erroring FAST on this
    backend right now (rate-limit / overload) — which the per-prompt breaker
    never catches, because a storm is a stream of DIFFERENT prompts, each a
    fresh key at count 0. Either tripping skips the call; the single locked
    section keeps concurrent decide subprocesses from all claiming a half-open
    retry at once.
    """
    prompt_threshold = _fail_threshold()
    type_threshold = _type_fail_threshold()
    if prompt_threshold <= 0 and type_threshold <= 0:
        return False
    pkey = _failcache_key(decision, prompt)
    tkey = _type_key(decision)
    cooldown = _fail_cooldown()

    def mutate(data):
        skip_p, dirty_p = _breaker_step(data, pkey, prompt_threshold, cooldown)
        if skip_p:
            return True, dirty_p
        skip_t, dirty_t = _breaker_step(data, tkey, type_threshold, cooldown)
        return skip_t, (dirty_p or dirty_t)

    return _failcache_update(mutate, default=False)


def _failcache_note(decision: str, prompt: str, success: bool,
                    backend_error: bool = False) -> None:
    """Record one real-backend outcome.

    success       → clears BOTH the per-prompt and per-type keys: the backend
                    answered, so neither breaker should stay armed.
    failure       → always bumps the per-prompt key (a repeated identical
                    failure is worth short-circuiting). Bumps the per-type key
                    ONLY when `backend_error` — a fast non-zero exit
                    (rate-limit / overload). NOT a timeout (which means "needed
                    more time", addressed by the decision-timeout floors, not by
                    sidelining the class) and NOT a malformed-output parse
                    failure (the backend answered fine; the model's output was
                    bad for THIS prompt only). Keying the type breaker on fast
                    backend errors is what stops it sidelining a gate that is
                    merely slow.

    A success (or a non-backend failure) that touches no existing key rewrites
    nothing — the common path pays nothing.
    """
    prompt_threshold = _fail_threshold()
    type_threshold = _type_fail_threshold()
    if prompt_threshold <= 0 and type_threshold <= 0:
        return
    pkey = _failcache_key(decision, prompt)
    tkey = _type_key(decision)

    def mutate(data):
        dirty = False
        if success:
            for key in (pkey, tkey):
                if key in data:
                    data.pop(key, None)
                    dirty = True
            return None, dirty
        if prompt_threshold > 0:
            count, _ = _entry(data.get(pkey))
            data[pkey] = [count + 1, time.time()]
            dirty = True
        if type_threshold > 0 and backend_error:
            count, _ = _entry(data.get(tkey))
            data[tkey] = [count + 1, time.time()]
            dirty = True
        return None, dirty

    _failcache_update(mutate, default=None)


# ── Backend dispatch ────────────────────────────────────────────────
# Flag construction lives in lib/llm_invoke.py as the single source of truth.
# This local wrapper keeps the invocation callsite concise.

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

    # Empty overrides mean "use the default binary"; get(key, default) would
    # instead pass an empty executable name to subprocess.
    if backend == "claude":
        bin_name = os.environ.get("CLAUDE_BIN") or "claude"
        flags = _backend_flags("claude", model)
        cmd = [bin_name, *flags]
    elif backend == "codex":
        bin_name = os.environ.get("CODEX_BIN") or "codex"
        flags = _backend_flags(backend, model)
        # codex takes `exec` subcommand + flags + `-` for stdin prompt.
        cmd = [bin_name, "exec", *flags, "-"]
    elif backend == "oss":
        bin_name = os.environ.get("OPENCODE_BIN") or "opencode"
        flags = _backend_flags("oss", model)
        cmd = [bin_name, *flags]
    elif backend == "gemini":
        # Gemini backend keeps one name while switching CLI dialects via
        # USE_GEMINI_CLI. Both dialects accept -p "" with the prompt on
        # stdin for non-interactive calls.
        bin_name = os.environ.get("GEMINI_BIN") or _gemini_default_bin()
        flags = _backend_flags("gemini", model)
        # Empty -p arg forces non-interactive mode while the prompt is
        # read from stdin.
        cmd = [bin_name, *flags, "-p", ""]
    elif backend == "grok":
        bin_name = os.environ.get("GROK_BIN") or "grok"
        flags = _backend_flags("grok", model)
        cmd = [bin_name, *flags, "-p", prompt]
    else:
        return None

    if _which(bin_name) is None:
        # Caller logs the specific no-<backend>-bin reason.
        raise FileNotFoundError(f"no-{backend}-bin")

    # Disable each backend's cross-run auto-memory by default, as the agent
    # launch path does. Standalone tools that import llm_decide directly
    # (bin/setup-target, bin/suggest-*, etc.) do not apply the runner's memory
    # policy, so set it here too, keyed on TOKENFUZZ_MEMORY_ENABLED.
    # codex carries its disable as `-c` flags already in the decide flags.
    child_env = os.environ.copy()
    child_env.update(_invocation_env(backend, model))
    temp_dir = None
    run_input = prompt
    if backend == "grok":
        run_input = None
    if backend == "oss":
        # Build the config first: _opencode_config can raise ValueError (no
        # model), and doing it before TemporaryDirectory() avoids leaking an
        # uncleaned temp dir on that error path.
        config_content = json.dumps(_opencode_config(model), separators=(",", ":"))
        temp_dir = tempfile.TemporaryDirectory(prefix="tokenfuzz-opencode-decide-")
        child_env["OPENCODE_CONFIG_CONTENT"] = config_content
        cmd = [*cmd, prompt]
        run_input = None

    try:
        try:
            result = subprocess.run(
                cmd,
                input=run_input,
                capture_output=True,
                text=True,
                timeout=timeout_secs,
                env=child_env,
            )
        except subprocess.TimeoutExpired:
            raise
        except OSError:
            return None

        if result.returncode != 0:
            # Caller logs the backend-specific rc.
            raise subprocess.CalledProcessError(result.returncode, cmd, output=result.stdout, stderr=result.stderr)
        if backend == "oss":
            if temp_dir is None:
                return result.stdout or ""
            raw_path = Path(temp_dir.name) / "opencode.jsonl"
            raw_path.write_text(result.stdout or "", encoding="utf-8")
            return _extract_backend_text("oss", str(raw_path))
        return result.stdout or ""
    finally:
        if temp_dir is not None:
            temp_dir.cleanup()


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


def _is_int(value) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _validate_decision_shape(decision: str, parsed) -> bool:
    """Validate known decision payload shapes for every backend.

    All backends use the same plain-text JSON contract. This runtime
    validator is the cross-backend guard that prevents a syntactically
    valid but type-wrong object from reaching consumers.
    """
    known_decisions = {
        "find_quality", "work_rerank", "s6-peer-suggest", "threat-model-suggest",
        "s6-peer-distill", "s6-peer-map",
    }
    if decision not in known_decisions:
        return True
    if not isinstance(parsed, dict):
        return False

    if decision == "find_quality":
        # find_quality is the QUALITY gate (accept/class/severity). Identity is
        # the deterministic (class, file, line) site computed at cluster time
        # (lib/finding_signature.py), not anything this gate produces.
        return (
            _is_bool(parsed.get("accept"))
            and _is_string(parsed.get("reason"))
            and _is_string(parsed.get("class"))
            and _is_string(parsed.get("severity"))
        )
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
    set still runs the mock. On real
    backend dispatch, telemetry lines `<decision> <state> bytes=N elapsed=Ns`
    are emitted to the LLM decision log so cost-analysis tooling can sum
    prompt bytes + wall-clock per decision.
    """
    mock_val = _resolve_mock_value(decision)

    if not mock_val and os.environ.get("LLM_DECIDE_DISABLE", "0") == "1":
        _llm_log(f"{decision} SKIP disabled")
        return None

    if not prompt or not prompt.strip():
        # Reject whitespace-only prompts before they consume decision budget.
        # Validated BEFORE budget so a malformed/empty call from a buggy
        # caller does not deduct from the per-session backend budget.
        _llm_log(f"{decision} FAIL empty-prompt")
        return None

    # Circuit breaker: skip a real-backend request whose exact (decision,
    # prompt) has already failed the threshold times this session, before
    # consuming budget or paying another backend timeout. Mocks are
    # deterministic test fixtures and are never circuit-broken.
    if not mock_val and _failcache_should_skip(decision, prompt):
        _llm_log(
            f"{decision} SKIP circuit-open prompt_threshold={_fail_threshold()} "
            f"type_threshold={_type_fail_threshold()}"
        )
        return None

    if not budget_available():
        _llm_log(f"{decision} SKIP budget-exhausted max={_budget_cap()}")
        return None

    result, backend_error = _run_decision(decision, required_keys, prompt, timeout, mock_val)

    # Update the breaker on real-backend outcomes only: a success clears the
    # keys, a failure arms the per-prompt key, and a fast backend error
    # (rate-limit / overload) additionally arms the per-type key. Mock outcomes
    # are deterministic and must not arm or disarm the breaker.
    if not mock_val:
        _failcache_note(decision, prompt, success=result is not None,
                        backend_error=backend_error)

    return result


def _maybe_record_provider_limit(*chunks: str) -> None:
    """Record a provider usage-limit reset seen in a failed decide call.

    A decision LLM call has no session log for the shared rate-limit detector to
    scan, so when the find-gate drain wants to pause and resume through an
    account/session cap it needs a signal from here. Opt-in: only writes when the
    caller sets LLM_DECIDE_LIMIT_FILE (the benchmark drain does; the agent and
    bin/audit housekeeping paths do not), so the normal decide path is untouched.
    Detection reuses the same event-scoped classifier the main loop uses
    (audit_helpers), so a cap is judged identically here and there — no divergent
    false positives. Best-effort throughout: any failure leaves the drain to fall
    back to its bounded pass count, never raising into the decision path.
    """
    target = os.environ.get("LLM_DECIDE_LIMIT_FILE")
    if not target:
        return
    raw = "\n".join(part for part in chunks if part)
    if not raw:
        return
    try:
        from audit_helpers import (
            _latest_rejected_reset_at,
            _provider_issue_from_lines,
        )
    except Exception:
        return
    try:
        lines = raw.splitlines()
        # Only a genuine account/session cap is worth pausing for; a transient
        # 5xx blip is retried by the drain's next pass without a long wait.
        if _provider_issue_from_lines(lines) != "capacity_limited":
            return
        reset = _latest_rejected_reset_at(lines)
        with open(target, "a", encoding="utf-8") as f:
            f.write(f"{reset if reset else 'unknown'}\n")
    except Exception:
        return


def _run_decision(
    decision: str,
    required_keys: str,
    prompt: str,
    timeout: int,
    mock_val: str,
) -> "tuple[Optional[dict | list], bool]":
    """Dispatch one decision (mock or real backend) and validate its JSON.

    The disable / empty-prompt / circuit-breaker / budget gates have already
    run in llm_decide(); this is the dispatch+extract+validate body. Returns
    (parsed_json_or_None, backend_error). `backend_error` is True only when the
    backend RAN and exited non-zero (rate-limit / overload / crash) — the fast
    storm signal the per-type breaker keys on. It is deliberately False for an
    rc=124 timeout ("needed more time") and for malformed output (the backend
    answered; the model's JSON was bad for this prompt), so neither sidelines a
    whole decision class.
    """
    prompt_bytes = len(prompt.encode("utf-8", "replace"))
    t_start = time.time()

    raw: str = ""
    if mock_val:
        loaded = _load_mock(mock_val)
        if loaded is None:
            _llm_log(f"{decision} FAIL mock-missing {mock_val} bytes={prompt_bytes}")
            return None, False
        raw = loaded
        elapsed = int(time.time() - t_start)
        _llm_log(f"{decision} MOCK bytes={prompt_bytes} elapsed={elapsed}s")
    else:
        # Treat an empty backend override as unset. Require an explicit
        # ACTIVE_BACKEND is the concrete backend selected by bin/audit after
        # resolving AUDIT_BACKEND=all. Standalone helpers may use BACKEND.
        # If both are unset, fail rather than silently preferring a vendor.
        backend = os.environ.get("ACTIVE_BACKEND") or os.environ.get("BACKEND") or ""
        if not backend:
            _llm_log(f"{decision} FAIL no-backend-set bytes={prompt_bytes}")
            return None, False
        if backend not in _KNOWN_BACKENDS:
            _llm_log(f"{decision} FAIL unknown-backend={backend} bytes={prompt_bytes}")
            return None, False
        try:
            raw = _invoke_backend(backend, prompt, timeout, decision, required_keys) or ""
        except FileNotFoundError as exc:
            # Missing CLI binary — a permanent config error, not a transient
            # backend storm. Don't arm the per-type breaker (backend_error=False):
            # the per-prompt breaker still catches a repeated identical call.
            _llm_log(f"{decision} FAIL {exc} bytes={prompt_bytes}")
            return None, False
        except subprocess.TimeoutExpired:
            # Timeout = "needed more time", not "backend is failing". Addressed
            # by the decision-timeout floors, so it must NOT arm the per-type
            # breaker or it would sideline a gate that is merely slow.
            elapsed = int(time.time() - t_start)
            _llm_log(
                f"{decision} FAIL {backend}-rc=124 bytes={prompt_bytes} "
                f"elapsed={elapsed}s timeout={timeout}s"
            )
            return None, False
        except subprocess.CalledProcessError as exc:
            # The backend RAN and exited non-zero — rate-limit / overload /
            # crash. This is the fast storm signal: backend_error=True so a
            # run of these opens the per-type breaker.
            elapsed = int(time.time() - t_start)
            _llm_log(
                f"{decision} FAIL {backend}-rc={exc.returncode} bytes={prompt_bytes} "
                f"elapsed={elapsed}s timeout={timeout}s"
            )
            # CLIs differ on whether provider caps land on stdout or stderr.
            _maybe_record_provider_limit(exc.output, exc.stderr)
            return None, True

    elapsed = int(time.time() - t_start)

    # Beyond this point the backend answered; any failure is a content problem
    # for THIS prompt (bad/empty/malformed JSON), not a failing decision class,
    # so backend_error stays False — the per-type breaker must not arm.
    json_text = _extract_json(raw)
    if json_text is None:
        _llm_log(f"{decision} FAIL extract-json bytes={prompt_bytes} elapsed={elapsed}s")
        # Some backends surface a usage limit as a rate-limit event on stdout
        # while still exiting 0 (no CalledProcessError); catch that here too.
        _maybe_record_provider_limit(raw)
        return None, False
    parsed = _try_load(json_text)
    if not _validate_required_keys(parsed, required_keys):
        _llm_log(f"{decision} FAIL missing-keys={required_keys} bytes={prompt_bytes} elapsed={elapsed}s")
        return None, False
    if not _validate_decision_shape(decision, parsed):
        _llm_log(f"{decision} FAIL invalid-shape bytes={prompt_bytes} elapsed={elapsed}s")
        return None, False

    _llm_log(f"{decision} OK bytes={prompt_bytes} elapsed={elapsed}s")
    return parsed, False


# ── CLI dispatch ───────────────────────────────────────────────────

def _cmd_decide(args) -> int:
    prompt = sys.stdin.read()
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
