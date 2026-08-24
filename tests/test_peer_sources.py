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
import shutil
import subprocess
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

# ─── _osv_pick_git_fix ──────────────────────────────────────────────

check("osv_pick_git_fix: picks first GIT-fixed event",
      ps._osv_pick_git_fix({
          "affected": [{
              "ranges": [{
                  "type": "GIT",
                  "events": [{"introduced": "0"}, {"fixed": "abc123def456"}],
              }],
          }],
      }) == ("abc123def456", "", ""))
check("osv_pick_git_fix: keeps the endpoint's own repository",
      ps._osv_pick_git_fix({
          "affected": [{
              "ranges": [{
                  "type": "GIT",
                  "repo": "https://example.test/peer.git",
                  "events": [{"introduced": "0"}, {"fixed": "abc123def456"}],
              }],
          }],
      }) == ("abc123def456", "https://example.test/peer.git", ""))
check("osv_pick_git_fix: skips non-GIT ranges",
      ps._osv_pick_git_fix({
          "affected": [{"ranges": [{"type": "SEMVER",
                                       "events": [{"fixed": "1.2.3"}]}]}],
      }) == ("", "", ""))
check("osv_pick_git_fix: no affected → empty",
      ps._osv_pick_git_fix({}) == ("", "", ""))
check("osv_pick_git_fix: keeps a matching fixed range",
      ps._osv_pick_git_fix({
          "affected": [{
              "database_specific": {"fixed_range": f"{'b' * 40}:{'a' * 40}"},
              "ranges": [{
                  "type": "GIT", "repo": "https://github.com/peer/project",
                  "events": [{"fixed": "a" * 40}],
              }],
          }],
      }) == ("a" * 40, "https://github.com/peer/project", "b" * 40))
check("github_fix_evidence: derives a fixed-range diff",
      ps._github_fix_evidence(
          "https://github.com/peer/project.git", "a" * 40, "b" * 40,
      ) == (
          f"https://github.com/peer/project/compare/{'b' * 40}...{'a' * 40}.diff",
          "fixed-range",
      ))
check("github_fix_evidence: falls back to the endpoint patch",
      ps._github_fix_evidence(
          "https://github.com/peer/project.git", "a" * 40,
      ) == (f"https://github.com/peer/project/commit/{'a' * 40}.patch", "endpoint"))
check("github_fix_evidence: rejects other hosts",
      ps._github_fix_evidence(
          "https://example.test/peer/project", "a" * 40,
      ) == ("", ""))
check("github_fix_evidence: rejects a non-hash endpoint",
      ps._github_fix_evidence(
          "https://github.com/peer/project", "../../settings",
      ) == ("", ""))

with tempfile.TemporaryDirectory() as d:
    cache = Path(d)

    class _FakePatch:
        def __enter__(self):
            return self
        def __exit__(self, *args):
            return False
        def read(self, limit):
            return b"Subject: exact endpoint evidence\n"[:limit]

    with mock.patch("peer_sources.urllib.request.urlopen", return_value=_FakePatch()):
        _patch = ps.fetch_patch_excerpt(
            "https://github.com/peer/project/commit/" + "a" * 40 + ".patch",
            cache_dir=cache, max_bytes=12,
        )
    check("fetch_patch_excerpt: bounds the fetched evidence", _patch == "Subject: exa")
    with mock.patch("peer_sources.urllib.request.urlopen",
                    side_effect=AssertionError("cached excerpt should avoid a refetch")):
        check("fetch_patch_excerpt: reuses positive evidence cache",
              ps.fetch_patch_excerpt(
                  "https://github.com/peer/project/commit/" + "a" * 40 + ".patch",
                  cache_dir=cache, max_bytes=12,
              ) == _patch)

with tempfile.TemporaryDirectory() as d:
    cache = Path(d)
    with mock.patch("peer_sources.urllib.request.urlopen",
                    side_effect=ps.urllib.error.URLError("offline")):
        check("fetch_patch_excerpt: a transport failure returns no evidence",
              ps.fetch_patch_excerpt(
                  "https://github.com/peer/project/commit/" + "a" * 40 + ".patch",
                  cache_dir=cache,
              ) == "")
    check("fetch_patch_excerpt: a transport failure is not cached",
          not any(cache.iterdir()))

_mixed_diff = (
    "diff --git a/.github/workflow.yml b/.github/workflow.yml\n+ci\n"
    "diff --git a/tests/regression.c b/tests/regression.c\n+test\n"
    "diff --git a/CMakeLists.txt b/CMakeLists.txt\n+build\n"
    "diff --git a/src/parser.c b/src/parser.c\n+guard\n"
)
check("production_diff_excerpt: production hunks precede config and tests",
      ps._production_diff_excerpt(_mixed_diff, 200).startswith(
          "diff --git a/src/parser.c"))
_ranked_diff = (
    "diff --git a/src/other.c b/src/other.c\n+other\n"
    "diff --git a/src/expression_binder.cpp b/src/expression_binder.cpp\n+guard\n"
)
check("production_diff_excerpt: advisory terms prioritize the peer analogue",
      ps._production_diff_excerpt(
          _ranked_diff, 200, "crash in ExpressionBinder::BindExpression",
      ).startswith("diff --git a/src/expression_binder.cpp"))
_test_only_diff = "diff --git a/tests/regression.c b/tests/regression.c\n+test\n"
check("production_diff_excerpt: test-only patches survive as evidence",
      ps._production_diff_excerpt(_test_only_diff, 200) == _test_only_diff)

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
check("git_shortstat: a later memory-safety fix beats a newer leak at the cap",
      [row["fix_hash"] for row in ps._parse_git_shortstat(
          "new\tfix resource leak\t2026-01-01T00:00:00\n"
          " 1 file changed, 2 insertions(+), 2 deletions(-)\n"
          "old\tfix use-after-free in parser\t2025-01-01T00:00:00\n"
          " 1 file changed, 2 insertions(+), 2 deletions(-)\n",
          max_results=1,
      )] == ["old"])

check("git_shortstat: a fix naming the test that caught it is not demoted",
      [row["fix_hash"] for row in ps._parse_git_shortstat(
          "cleanup\tfix compiler warning\t2026-01-01T00:00:00\n"
          " 1 file changed, 2 insertions(+), 2 deletions(-)\n"
          "real\tfix heap overflow found by the fuzz tests\t2025-01-01T00:00:00\n"
          " 1 file changed, 2 insertions(+), 2 deletions(-)\n",
          max_results=1,
      )] == ["real"])
check("git grep pattern is derived from the canonical filter, no drift",
      "\\b" not in ps._VCS_FIX_GREP and "\\d" not in ps._VCS_FIX_GREP
      and ps._VCS_FIX_GREP in ps._VCS_FIX_KEYWORDS.pattern.replace(
          "\\b", "").replace("\\d", "[0-9]"),
      f"got: {ps._VCS_FIX_GREP!r}")

with mock.patch("peer_sources.subprocess.run") as _git_run:
    _git_run.return_value.stdout = _GIT_SAMPLE
    ps._vcs_log_git(Path("/peer"), days=30, timeout=15, max_results=10)
    _git_cmd = _git_run.call_args.args[0]
check("git log: filters commit messages before computing shortstats",
      "--regexp-ignore-case" in _git_cmd
      and "--extended-regexp" in _git_cmd
      and any(arg.startswith("--grep=") for arg in _git_cmd),
      f"got: {_git_cmd!r}")

with tempfile.TemporaryDirectory() as d, \
     mock.patch("peer_sources.subprocess.run") as _show_run:
    _peer = Path(d) / "peer"
    (_peer / ".git").mkdir(parents=True)
    _show_run.return_value.returncode = 0
    _show_run.return_value.stdout = "diff --git a/src/parser.c b/src/parser.c\n+guard\n"
    _diff = ps.fetch_fix_diff(_peer, "abc123")
    _show_cmd = _show_run.call_args.args[0]
check("git diff: production paths precede bulky regression tests",
      _diff.startswith("diff --git")
      and ":(exclude)tests" in _show_cmd
      and ":(exclude)examples" in _show_cmd
      # `--format=` keeps a verbose commit message from spending the excerpt
      # budget before the first hunk.
      and "--format=" in _show_cmd,
      f"got: {_show_cmd!r}")

# Real git: a long message must not crowd out the code, a test-only commit
# must still fall back to its full diff, and a bad revision must stay empty.
with tempfile.TemporaryDirectory() as d:
    _repo = Path(d) / "peer"
    _repo.mkdir()
    def _git(*a):
        return subprocess.run(["git", "-C", str(_repo), *a],
                              capture_output=True, text=True)
    _git("init", "-q", ".")
    _git("config", "user.email", "t@t"); _git("config", "user.name", "t")
    (_repo / "src").mkdir(); (_repo / "tests").mkdir()
    (_repo / "src/a.c").write_text("a\n"); (_repo / "tests/t.c").write_text("t\n")
    _git("add", "-A"); _git("commit", "-qm", "init")
    (_repo / "tests/t.c").write_text("t\nb\n")
    _git("commit", "-qam", "fix overflow in the test only\n\n" + "rationale. " * 200)
    _test_only = _git("rev-parse", "HEAD").stdout.strip()
    (_repo / "src/a.c").write_text("a\nb\n"); (_repo / "tests/t.c").write_text("t\nb\nc\n")
    _git("commit", "-qam", "fix bounds\n\n" + "long rationale. " * 400)
    _verbose = _git("rev-parse", "HEAD").stdout.strip()

    _v = ps.fetch_fix_diff(_repo, _verbose)
    check("git diff: a verbose message does not spend the excerpt budget",
          _v.startswith("diff --git") and "@@" in _v and "long rationale" not in _v,
          f"got {len(_v)} chars: {_v[:60]!r}")
    check("git diff: production-only filter keeps the production hunk",
          "src/a.c" in _v and "tests/t.c" not in _v)
    _t = ps.fetch_fix_diff(_repo, _test_only)
    check("git diff: a test-only commit falls back to its full diff",
          "tests/t.c" in _t and "@@" in _t, f"got: {_t[:80]!r}")
    check("git diff: an unknown revision yields nothing",
          ps.fetch_fix_diff(_repo, "0" * 40) == "")

# ─── Mercurial peer log ─────────────────────────────────────────────
# Same policy as git: keyword-matching but oversized commits are noise.

if shutil.which("hg"):
    with tempfile.TemporaryDirectory() as d:
        _peer = Path(d) / "peer"
        _peer.mkdir()
        _hg_env = os.environ | {"HGUSER": "Test User <test@example.invalid>"}

        def _hg(*arguments: str) -> None:
            subprocess.run(
                ["hg", "--cwd", str(_peer), *arguments],
                check=True, timeout=30, env=_hg_env, capture_output=True,
            )

        subprocess.run(["hg", "init", str(_peer)], check=True, timeout=30)
        (_peer / "small.c").write_text("int a;\nint b;\n", encoding="utf-8")
        _hg("add", "small.c")
        _hg("commit", "-m", "fix overflow in parser")
        (_peer / "huge.c").write_text("".join(f"int v{i};\n" for i in range(600)), encoding="utf-8")
        _hg("add", "huge.c")
        _hg("commit", "-m", "fix overflow across the tree")
        (_peer / "small.c").write_text("int a;\nint c;\n", encoding="utf-8")
        _hg("commit", "-m", "unrelated cleanup")

        _hg_out = ps._vcs_log_hg(_peer, days=30, timeout=30, max_results=10)
        check("hg log: keyword + small diff passes",
              [entry["summary"] for entry in _hg_out] == ["fix overflow in parser"],
              f"got: {_hg_out!r}")
        check("hg log: dispatch reaches the hg backend",
              [entry["summary"] for entry in
               ps.vcs_log_search(_peer, days=30, timeout=30, max_results=10)]
              == ["fix overflow in parser"])

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
                "repo": "https://example.test/peer.git",
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
          and _out[0]["fix_hash"].startswith("deadbeef")
          and _out[0]["repo_url"] == "https://example.test/peer.git"
          and _out[0]["evidence_url"] == ""
          and _out[0]["evidence_kind"] == "")

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

with tempfile.TemporaryDirectory() as d:
    clone = Path(d) / "peer"
    clone.mkdir()
    fake_vcs = [
        {"source": "vcs", "id": "v1", "fix_hash": "v1",
         "summary": "fix bounds check", "url": "", "modified": ""},
    ]
    fake_osv = [
        {"source": "osv", "id": "CVE-1", "fix_hash": "o1",
         "summary": "range endpoint", "url": "u1", "modified": ""},
    ]
    with mock.patch("peer_sources.find_peer_clone", return_value=clone), \
         mock.patch("peer_sources.vcs_log_search", return_value=fake_vcs), \
         mock.patch("peer_sources.osv_query", return_value=fake_osv):
        _out = ps.gather_peer_fixes(
            "peer", cache_dir=Path(d),
            peer_clone_search_roots=[Path(d)],
        )
    check("gather_peer_fixes: exact local commits precede OSV range endpoints",
          [(e["source"], e["id"]) for e in _out]
          == [("vcs", "v1"), ("osv", "CVE-1")])


# ClusterFuzz bisects distinct bugs to the same first-good commit, so an
# advisory is identified by its id, never by where its range happens to end.
with tempfile.TemporaryDirectory() as d:
    _shared = [
        {"source": "osv", "id": "OSV-A", "fix_hash": "same", "summary": "bug A", "url": "a", "modified": ""},
        {"source": "osv", "id": "OSV-B", "fix_hash": "same", "summary": "bug B", "url": "b", "modified": ""},
    ]
    _commit = [
        {"source": "vcs", "id": "same", "fix_hash": "same", "summary": "fix bounds", "url": "", "modified": ""},
    ]
    with mock.patch("peer_sources.find_peer_clone", return_value=Path(d)), \
         mock.patch("peer_sources.vcs_log_search", return_value=_commit), \
         mock.patch("peer_sources.osv_query", return_value=_shared):
        _both = ps.gather_peer_fixes(
            "peer", cache_dir=Path(d), peer_clone_search_roots=[Path(d)],
        )
    check("gather_peer_fixes: advisories sharing a range endpoint both survive",
          [(e["source"], e["id"]) for e in _both]
          == [("vcs", "same"), ("osv", "OSV-A"), ("osv", "OSV-B")],
          repr([(e["source"], e["id"]) for e in _both]))

print(f"  {_GREEN if _FAILED == 0 else _RED}{_PASSED}/{_PASSED+_FAILED} passed{_NC}")
sys.exit(0 if _FAILED == 0 else 1)
