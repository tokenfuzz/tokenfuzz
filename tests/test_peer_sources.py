#!/usr/bin/env python3
"""Tests for lib/peer_sources.py.

Pure-function tests with network mocked out: cache get/put, OSV
response parsing, git shortstat parsing, OSS-Fuzz reference shape, and
the gather_peer_fixes orchestrator path.

Output format matches helpers.sh — `✓ name` for pass / `✗ name` for fail —
so tests/run-tests.sh's pass/fail counter (greps for those marks) keeps
working unchanged.
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import time
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "lib"))
import peer_sources as ps  # noqa: E402

_PASSED = 0
_FAILED = 0
_GREEN = "\033[0;32m"
_RED = "\033[0;31m"
_NC = "\033[0m"


def passed(name: str) -> None:
    global _PASSED
    _PASSED += 1
    print(f"  {_GREEN}✓{_NC} {name}")


def failed(name: str, detail: str = "") -> None:
    global _FAILED
    _FAILED += 1
    print(f"  {_RED}✗{_NC} {name}")
    if detail:
        print(f"    {detail}")


def check(name: str, cond: bool, detail: str = "") -> None:
    if cond:
        passed(name)
    else:
        failed(name, detail)


# ─── Cache ──────────────────────────────────────────────────────────

with tempfile.TemporaryDirectory() as d:
    cache = Path(d)
    check("cache: cold miss returns None", ps._cache_get(cache, "k", 60) is None)
    ps._cache_put(cache, "k", {"v": 1})
    check("cache: warm hit returns value",
          ps._cache_get(cache, "k", 60) == {"v": 1})
    # Force-expire
    for f in cache.iterdir():
        os.utime(f, (time.time() - 3600, time.time() - 3600))
    check("cache: expired entry returns None",
          ps._cache_get(cache, "k", 60) is None)

check("cache: None dir is a no-op (get)", ps._cache_get(None, "k", 60) is None)
ps._cache_put(None, "k", {"x": 1})
passed("cache: None dir is a no-op (put)")

# ─── ISO → epoch ────────────────────────────────────────────────────

check("iso_to_epoch: Z form parses",
      ps._iso_to_epoch("2025-06-15T10:30:00Z") is not None)
check("iso_to_epoch: fractional-second form parses",
      ps._iso_to_epoch("2025-06-15T10:30:00.123Z") is not None)
check("iso_to_epoch: empty returns None", ps._iso_to_epoch("") is None)
check("iso_to_epoch: invalid returns None",
      ps._iso_to_epoch("not-a-date") is None)

# ─── _osv_pick_fix_hash ─────────────────────────────────────────────

check("osv_pick_fix_hash: picks first GIT-fixed event",
      ps._osv_pick_fix_hash({
          "affected": [{
              "ranges": [{
                  "type": "GIT",
                  "events": [{"introduced": "0"}, {"fixed": "abc123def456"}],
              }],
          }],
      }) == "abc123def456")
check("osv_pick_fix_hash: skips non-GIT ranges",
      ps._osv_pick_fix_hash({
          "affected": [{"ranges": [{"type": "SEMVER",
                                     "events": [{"fixed": "1.2.3"}]}]}],
      }) == "")
check("osv_pick_fix_hash: no affected → empty",
      ps._osv_pick_fix_hash({}) == "")

# ─── git shortstat parser ───────────────────────────────────────────

_GIT_SAMPLE = (
    "abc123\tfix overflow in parser\t2025-01-01T00:00:00\n"
    " 1 file changed, 4 insertions(+), 2 deletions(-)\n"
    "def456\trefactor giant feature\t2025-01-02T00:00:00\n"
    " 20 files changed, 800 insertions(+), 400 deletions(-)\n"
    "789xyz\tnotrelevant subject\t2025-01-03T00:00:00\n"
    " 1 file changed, 5 insertions(+)\n"
)
_out = ps._parse_git_shortstat(_GIT_SAMPLE, max_results=10)
check("git_shortstat: keyword + small diff passes",
      len(_out) == 1 and _out[0]["fix_hash"] == "abc123",
      f"got: {_out!r}")
check("git_shortstat: large-diff keyword commit rejected",
      ps._parse_git_shortstat(
          "abc\tfix overflow but huge\t2025-01-01T00:00:00\n"
          " 30 files changed, 5000 insertions(+), 2000 deletions(-)\n",
          max_results=10,
      ) == [])

# ─── env-tunable diff-size knobs ────────────────────────────────────
# The VCS fix-candidate size filter is an exploration knob, not fixed
# policy: a genuine security fix (plus its regression test) can exceed
# a tight bound, so operators can widen the sweep without editing code.
check("vcs diff knobs: defaults are 10 files / 400 lines",
      ps._VCS_MAX_FILES_CHANGED == 10 and ps._VCS_MAX_LINES_CHANGED == 400,
      f"got files={ps._VCS_MAX_FILES_CHANGED} lines={ps._VCS_MAX_LINES_CHANGED}")

check("_env_int: missing var falls back to default",
      ps._env_int("PEER_VCS_TEST_KNOB", 3) == 3)
os.environ["PEER_VCS_TEST_KNOB"] = "400"
check("_env_int: valid env value wins", ps._env_int("PEER_VCS_TEST_KNOB", 3) == 400)
os.environ["PEER_VCS_TEST_KNOB"] = "bogus"
check("_env_int: non-numeric falls back to default",
      ps._env_int("PEER_VCS_TEST_KNOB", 3) == 3)
os.environ["PEER_VCS_TEST_KNOB"] = "0"
check("_env_int: non-positive falls back to default",
      ps._env_int("PEER_VCS_TEST_KNOB", 3) == 3)
del os.environ["PEER_VCS_TEST_KNOB"]

# A fix + substantial regression test (a 2-file, 110-line commit) must
# pass at the generous default cap — the prior 80-line bound dropped it.
_FIX_WITH_TEST = (
    "ccc333\tfix use-after-free in entity parser\t2025-02-01T00:00:00\n"
    " 2 files changed, 60 insertions(+), 50 deletions(-)\n"
)
check("git_shortstat: fix + test (110 lines) passes default cap",
      len(ps._parse_git_shortstat(_FIX_WITH_TEST, max_results=10)) == 1,
      f"got: {ps._parse_git_shortstat(_FIX_WITH_TEST, max_results=10)!r}")

# An 850-line commit is dropped at the default cap but kept once the line
# cap is raised — proves the knob actually drives the filter.
_BIG_FIX = (
    "aaa111\tfix overflow in larger patch\t2025-01-01T00:00:00\n"
    " 4 files changed, 500 insertions(+), 350 deletions(-)\n"
)
check("git_shortstat: 850-line commit rejected at default cap",
      ps._parse_git_shortstat(_BIG_FIX, max_results=10) == [])
_saved_cap = ps._VCS_MAX_LINES_CHANGED
ps._VCS_MAX_LINES_CHANGED = 2000
try:
    check("git_shortstat: same commit passes once the line cap is raised",
          len(ps._parse_git_shortstat(_BIG_FIX, max_results=10)) == 1)
finally:
    ps._VCS_MAX_LINES_CHANGED = _saved_cap

# ─── OSS-Fuzz tracker reference ─────────────────────────────────────

_ref = ps.ossfuzz_tracker_reference("libxml2")
check("ossfuzz_tracker_reference: shape",
      _ref["source"] == "ossfuzz" and "libxml2" in _ref["url"]
      and _ref["fix_hash"] == "")

# ─── OSV query with network mocked ─────────────────────────────────

# A network failure must NOT poison the cache: a negative cache entry is
# byte-identical to a legitimate empty OSV result and would suppress S6
# mining for the full TTL after a single transient failure.
with tempfile.TemporaryDirectory() as d:
    cache = Path(d)
    with mock.patch("peer_sources.urllib.request.urlopen",
                    side_effect=ps.urllib.error.URLError("nope")):
        check("osv_query: network error returns empty",
              ps.osv_query("anything", cache_dir=cache, days=365) == [])
    check("osv_query: network error writes no cache file",
          not any(cache.iterdir()),
          f"unexpected cache files: {list(cache.iterdir())}")
    # Because the failure was not cached, the next call must retry the
    # network rather than serve a poisoned empty result.
    _retried = {"called": False}

    def _mark_called(*a, **k):
        _retried["called"] = True
        raise ps.urllib.error.URLError("still down")

    with mock.patch("peer_sources.urllib.request.urlopen",
                    side_effect=_mark_called):
        ps.osv_query("anything", cache_dir=cache, days=365)
    check("osv_query: network error is retried, not served from cache",
          _retried["called"])

# A *successful* empty response (OSV genuinely has nothing) IS cached —
# that is a real result, not a failure, so repeat calls skip the network.
with tempfile.TemporaryDirectory() as d:
    cache = Path(d)

    class _FakeEmpty:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self):
            return b'{"vulns": []}'

    with mock.patch("peer_sources.urllib.request.urlopen",
                    return_value=_FakeEmpty()):
        check("osv_query: successful empty result returns empty",
              ps.osv_query("anything", cache_dir=cache, days=365) == [])
    with mock.patch("peer_sources.urllib.request.urlopen",
                    side_effect=AssertionError("urlopen should not be called")):
        check("osv_query: successful empty result is cached (no re-fetch)",
              ps.osv_query("anything", cache_dir=cache, days=365) == [])

_fake_resp_body = {
    "vulns": [{
        "id": "CVE-2099-1111",
        "summary": "test fix",
        "modified": "2099-01-01T00:00:00Z",
        "affected": [{
            "ranges": [{
                "type": "GIT",
                "events": [{"fixed": "deadbeef" * 5}],
            }],
        }],
    }],
}


class _FakeResp:
    def __enter__(self):
        return self
    def __exit__(self, *args):
        return False
    def read(self):
        return json.dumps(_fake_resp_body).encode("utf-8")


with tempfile.TemporaryDirectory() as d:
    with mock.patch("peer_sources.urllib.request.urlopen",
                    return_value=_FakeResp()):
        _out = ps.osv_query("peer", cache_dir=Path(d), days=365)
    check("osv_query: parses minimal OSV response",
          len(_out) == 1 and _out[0]["id"] == "CVE-2099-1111"
          and _out[0]["fix_hash"].startswith("deadbeef"))

# ─── find_peer_clone ────────────────────────────────────────────────

with tempfile.TemporaryDirectory() as d:
    root = Path(d)
    (root / "expat" / ".git").mkdir(parents=True)
    got = ps.find_peer_clone("expat", [root])
    check("find_peer_clone: finds git clone",
          got is not None and got.name == "expat")
    check("find_peer_clone: returns None when absent",
          ps.find_peer_clone("nope", [root]) is None)

# ─── gather_peer_fixes ──────────────────────────────────────────────

with tempfile.TemporaryDirectory() as d:
    with mock.patch("peer_sources.osv_query", return_value=[]):
        _out = ps.gather_peer_fixes(
            "obscure", cache_dir=Path(d),
            peer_clone_search_roots=[Path(d)],
        )
    check("gather_peer_fixes: empty OSV falls back to ossfuzz hint",
          len(_out) == 1 and _out[0]["source"] == "ossfuzz")

with tempfile.TemporaryDirectory() as d:
    fake_osv = [
        {"source": "osv", "id": "CVE-1", "fix_hash": "h1",
         "summary": "s1", "url": "u1", "modified": ""},
        {"source": "osv", "id": "CVE-2", "fix_hash": "h2",
         "summary": "s2", "url": "u2", "modified": ""},
    ]
    with mock.patch("peer_sources.osv_query", return_value=fake_osv):
        _out = ps.gather_peer_fixes(
            "peer", cache_dir=Path(d),
            peer_clone_search_roots=[Path(d)],
        )
    check("gather_peer_fixes: passes OSV results through",
          [e["id"] for e in _out] == ["CVE-1", "CVE-2"])


print(f"  {_GREEN if _FAILED == 0 else _RED}{_PASSED}/{_PASSED+_FAILED} passed{_NC}")
sys.exit(0 if _FAILED == 0 else 1)
