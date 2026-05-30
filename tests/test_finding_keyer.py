#!/usr/bin/env python3
"""Regression tests for lib/finding_keyer.py — the read-time identity keyer.

Exercises:
  * cached_key — reads a current-version .finding-key.json, ignores stale ones
  * ensure_key — assigns a dedup_key from the report via the (mocked) backend,
    caches it, and is idempotent on the second call
  * graceful degradation — no backend (and no mock) → "" and NO cache written,
    so the finding keeps its deterministic (class, file, func) label
  * validation — an invalid key from the model is dropped (returns "")
  * source-independence — the same report yields the same key regardless of
    which "source" produced it (one keyer, one identity space)
  * decision timeout — honors the harness-wide LLM_DECISION_TIMEOUT (default
    45), so the keyer is no more timeout-fragile than any other llm_decide call
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "lib"))

import finding_keyer as fk  # noqa: E402

PASSED = 0
FAILED = 0


def ok(cond: bool, name: str, detail: str = "") -> None:
    global PASSED, FAILED
    if cond:
        PASSED += 1
        print(f"  \033[0;32m✓\033[0m {name}")
    else:
        FAILED += 1
        print(f"  \033[0;31m✗\033[0m {name}")
        if detail:
            print(f"    {detail}")


def mk_find(root: Path, name: str, body: str) -> Path:
    d = root / name
    d.mkdir(parents=True, exist_ok=True)
    (d / "report.md").write_text(body, encoding="utf-8")
    return d


REPORT = """# Stack overflow in callout command construction

File: `targets/pcre2/src/pcre2grep.c`
Function: `pcre2grep_callout`
Bug class: stack-buffer-overflow

The VMS branch strcat()s every caller-controlled argument into a fixed
cmdbuf[500] with no remaining-size check before lib$spawn().
"""


def with_env(**env):
    """Context-free env setter that restores afterward."""
    saved = {k: os.environ.get(k) for k in env}

    def restore():
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
    for k, v in env.items():
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = v
    return restore


tmp = Path(tempfile.mkdtemp(prefix="keyer-test-"))

# ── graceful degradation: no backend, no mock → no key, no cache ───
print("graceful degradation (no backend)")
restore = with_env(LLM_DECIDE_MOCK_FINDING_KEY=None, LLM_DECIDE_MOCK=None,
                   ACTIVE_BACKEND=None, BACKEND=None, LLM_DECIDE_DISABLE="1")
d = mk_find(tmp, "FIND-nobackend", REPORT)
key = fk.ensure_key(d)
ok(key == "", "no backend → ensure_key returns ''")
ok(not (d / fk.CACHE_NAME).is_file(),
   "no backend → no .finding-key.json written (stays on deterministic label)")
restore()

# ── ensure_key with a mocked backend → assigns + caches ────────────
print("\nensure_key with mocked backend")
restore = with_env(LLM_DECIDE_MOCK_FINDING_KEY='{"dedup_key":"vms-callout-cmdbuf-overflow"}',
                   ACTIVE_BACKEND="claude", LLM_DECIDE_LOG="/dev/null",
                   LLM_DECIDE_DISABLE=None)
d = mk_find(tmp, "FIND-keyed", REPORT)
key = fk.ensure_key(d)
ok(key == "vms-callout-cmdbuf-overflow", "mocked key assigned", f"got {key!r}")
ok((d / fk.CACHE_NAME).is_file(), ".finding-key.json written")
cache = json.loads((d / fk.CACHE_NAME).read_text())
ok(cache.get("dedup_key") == "vms-callout-cmdbuf-overflow" and
   cache.get("key_version") == fk.KEY_VERSION, "cache carries key + version")
ok(fk.cached_key(d) == "vms-callout-cmdbuf-overflow", "cached_key reads it back")
restore()

# ── idempotent: second call uses the cache, no backend needed ──────
print("\nidempotent")
restore = with_env(LLM_DECIDE_MOCK_FINDING_KEY=None, LLM_DECIDE_MOCK=None,
                   ACTIVE_BACKEND=None, BACKEND=None, LLM_DECIDE_DISABLE="1")
# Same dir as above (FIND-keyed) already has a cache — must return it even
# though no backend is reachable now.
ok(fk.ensure_key(tmp / "FIND-keyed") == "vms-callout-cmdbuf-overflow",
   "cached finding re-keys to the same value with no backend")
restore()

# ── stale key_version is ignored ───────────────────────────────────
print("\nstale version ignored")
d = mk_find(tmp, "FIND-stale", REPORT)
(d / fk.CACHE_NAME).write_text(
    json.dumps({"key_version": "v0-old", "dedup_key": "outdated-key-here"}),
    encoding="utf-8")
ok(fk.cached_key(d) == "", "cached_key ignores a stale key_version")

# ── invalid model output is dropped → "" ───────────────────────────
print("\ninvalid key dropped")
restore = with_env(LLM_DECIDE_MOCK_FINDING_KEY='{"dedup_key":"oops"}',
                   ACTIVE_BACKEND="claude", LLM_DECIDE_LOG="/dev/null",
                   LLM_DECIDE_DISABLE=None)
d = mk_find(tmp, "FIND-badkey", REPORT)
ok(fk.ensure_key(d) == "", "single-token key rejected → ''")
ok(not (d / fk.CACHE_NAME).is_file(), "invalid key writes no cache")
restore()

# ── source-independence: same report, two "sources" → same key ─────
print("\nsource-independence (one keyer, one identity space)")
restore = with_env(LLM_DECIDE_MOCK_FINDING_KEY='{"dedup_key":"vms-callout-cmdbuf-overflow"}',
                   ACTIVE_BACKEND="claude", LLM_DECIDE_LOG="/dev/null",
                   LLM_DECIDE_DISABLE=None)
harness = mk_find(tmp, "FIND-RECON-deadbeef-harness", REPORT)
direct = mk_find(tmp, "FIND-0001", REPORT)        # a model-direct-style id
k1 = fk.ensure_key(harness)
k2 = fk.ensure_key(direct)
ok(k1 == k2 == "vms-callout-cmdbuf-overflow",
   "recon-harness and model-direct findings get the SAME key from one keyer")
restore()

# ── timeout honors the harness-wide LLM_DECISION_TIMEOUT ────────────
# The keyer hardcoded 30s while every other decision uses LLM_DECISION_TIMEOUT
# (45). That made it the first decision to time out against a slow/throttled
# agentic backend — which is what left the gemini pool with 0 keys.
print("\ndecision timeout (no more fragile than any other llm_decide call)")
restore = with_env(LLM_DECISION_TIMEOUT="90")
ok(fk._decision_timeout() == 90, "LLM_DECISION_TIMEOUT respected")
restore()
restore = with_env(LLM_DECISION_TIMEOUT=None)
ok(fk._decision_timeout() == 45, "unset → default 45 (matches lib/triage.sh)")
restore()
restore = with_env(LLM_DECISION_TIMEOUT="not-an-int")
ok(fk._decision_timeout() == 45, "non-integer → falls back to 45")
restore()

print()
if FAILED:
    print(f"\033[0;31m{FAILED} failed, {PASSED} passed\033[0m")
    sys.exit(1)
print(f"\033[0;32m{PASSED}/{PASSED} passed\033[0m")
