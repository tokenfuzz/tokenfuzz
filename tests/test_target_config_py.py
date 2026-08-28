#!/usr/bin/env python3
"""tests/test_target_config_py.py — exercise the Python target_config API.

Tests the Python module directly: parse_toml, load_toml_into,
find_session_dir, read_session_env,
write_session_env, detect_rev, seed_toml, and the Config helpers.

Output format matches helpers.sh — `✓ name` for pass / `✗ name` for fail —
so tests/run-tests.sh's pass/fail counter (greps for those marks) keeps
working unchanged.
"""

from __future__ import annotations

import os
import plistlib
import sys
import tempfile
import shutil
import subprocess
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "lib"))
import target_config as tc

# ─── Pass/fail bookkeeping (mirrors tests/helpers.sh ✓/✗ output) ────

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


def assert_eq(expected, actual, name: str) -> None:
    if expected == actual:
        passed(name)
    else:
        failed(name, f"expected={expected!r} actual={actual!r}")


def assert_in(needle: str, haystack: str, name: str) -> None:
    if needle in haystack:
        passed(name)
    else:
        failed(name, f"{needle!r} not in: {haystack[:200]!r}")


def assert_not_in(needle: str, haystack: str, name: str) -> None:
    if needle not in haystack:
        passed(name)
    else:
        failed(name, f"{needle!r} unexpectedly in haystack")


# ─── Test fixtures ──────────────────────────────────────────────────

TEST_TMPDIR = Path(tempfile.mkdtemp(prefix="tc-py-"))


def write(name: str, body: str) -> Path:
    p = TEST_TMPDIR / name
    p.write_text(body, encoding="utf-8")
    return p


# ─── 1. parse_toml round-trip on the existing target.toml shapes ────

for slug in ("libxml2", "pcre2", "firefox", "zstd"):
    src = ROOT / "output" / slug / "target.toml"
    if not src.is_file():
        continue
    parsed = tc.parse_toml(src)
    assert_eq(parsed.get("target") or parsed.get("slug"), slug,
              f"parse_toml: target match for {slug}")
    if "threat_model" in parsed:
        ac = parsed["threat_model"].get("attacker_controls", [])
        if isinstance(ac, list) and ac:
            passed(f"parse_toml: {slug} has attacker_controls={ac}")
        else:
            failed(f"parse_toml: {slug} threat_model.attacker_controls present", str(ac))


# ─── 2. load_toml_into populates Config with normalization + defaults ─

cfg = tc.Config()
write("no-tm.toml", 'slug = "demo"\nasan_bin = "build-asan/demo"\n')
tc.load_toml_into(cfg, TEST_TMPDIR / "no-tm.toml")
assert_eq(["bytes"], cfg.attacker_controls,
          "load_toml_into: missing [threat_model] defaults to ['bytes']")
assert_eq("bytes", cfg.attacker_controls_csv(), "csv helper returns 'bytes' when defaulted")

cfg = tc.Config()
write("aliased.toml",
      'slug = "aliased"\n[threat_model]\nattacker_controls = ["bytes", "call-order"]\n')
tc.load_toml_into(cfg, TEST_TMPDIR / "aliased.toml")
assert_eq("bytes,call-sequence", cfg.attacker_controls_csv(),
          "load_toml_into: call-order normalizes to call-sequence")

cfg = tc.Config()
write("dup.toml",
      'slug = "dup"\n[threat_model]\nattacker_controls = ["bytes", "timing", "bytes"]\n')
tc.load_toml_into(cfg, TEST_TMPDIR / "dup.toml")
assert_eq("bytes,timing", cfg.attacker_controls_csv(),
          "csv helper de-duplicates while preserving order")

cfg = tc.Config()
write("empty.toml", 'slug = "empty"\n[threat_model]\nattacker_controls = []\n')
tc.load_toml_into(cfg, TEST_TMPDIR / "empty.toml")
assert_eq(["bytes"], cfg.attacker_controls,
          "load_toml_into: empty attacker_controls defaults to ['bytes']")

cfg = tc.Config()
write(
    "runner-success.toml",
    'slug = "runner-success"\n[runner]\nsuccess_codes = [123, 1, 0, 1, -1, 124, 125, 137, 256, true]\n',
)
tc.load_toml_into(cfg, TEST_TMPDIR / "runner-success.toml")
assert_eq([0, 1, 123], cfg.runner_success_codes,
          "runner success_codes keeps unique non-signal process exit values")
cfg = tc.Config()
tc.load_toml_into(cfg, TEST_TMPDIR / "no-tm.toml")
assert_eq([0], cfg.runner_success_codes,
          "runner success_codes defaults to zero")


# ─── 3. Bad section headers are rejected ───────────────────────────

write("bad-section.toml",
      'slug = "malformed"\n[bad section name with spaces]\nasan_bin = "build-asan/post-bad"\n')
try:
    tc.parse_toml(TEST_TMPDIR / "bad-section.toml")
    failed("parse_toml: bad [section] header rejected by default",
           "parse_toml succeeded unexpectedly")
except Exception:
    passed("parse_toml: bad [section] header rejected by default")

# ─── 4. Invalid attacker_controls token: stderr warning + drop ──────

import io
import contextlib

write("bogus.toml",
      'slug = "bogus"\n[threat_model]\nattacker_controls = ["bytes", "magic-pony", "timing"]\n')
cfg = tc.Config()
buf = io.StringIO()
with contextlib.redirect_stderr(buf):
    tc.load_toml_into(cfg, TEST_TMPDIR / "bogus.toml")
warn = buf.getvalue()
assert_eq(["bytes", "timing"], cfg.attacker_controls,
          "invalid token dropped, others kept")
assert_in("magic-pony", warn, "stderr warning mentions the bad token")


# ─── 6. find_session_dir walks up from a path ───────────────────────

slug_dir = TEST_TMPDIR / "out_root" / "output" / "demo"
slug_dir.mkdir(parents=True)
backend_results = slug_dir / "codex" / "results"
backend_scratch = backend_results / "scratch-1"
backend_scratch.mkdir(parents=True)
(slug_dir / "target.toml").write_text(
    'target = "demo"\n[threat_model]\nattacker_controls = ["timing"]\n',
    encoding="utf-8",
)
(backend_results / ".session-env").write_text(
    "RESULTS_DIR=/backend/results\n"
    "TARGET_ROOT=/target/root\n"
    "TARGET_SLUG=demo\n"
    "TARGET_REV=rev\n"
    "LOGDIR=/backend/logs\n",
    encoding="utf-8",
)
found = tc.find_session_dir(backend_scratch)
assert_eq(backend_results.resolve(), found.resolve() if found else None,
          "find_session_dir prefers backend-local results session env")
loaded = tc.load(backend_scratch)
assert_eq("/backend/results", loaded.results_dir,
          "load uses backend-local session env from testcase path")
assert_eq("timing", loaded.attacker_controls_csv(),
          "load derives target.toml from backend results session dir")

# Report consumers do not require a session env. A benchmark pool carries its
# own target.toml below the original output/<slug> config, and the nearest
# config must win without scanning another target's output tree.
pool_root = slug_dir / "benchmark" / "pool" / "harness"
pool_report = pool_root / "crashes" / "CRASH-001" / "REPORT.md"
pool_report.parent.mkdir(parents=True)
pool_toml = pool_root / "target.toml"
pool_toml.write_text('target = "pooled-demo"\n', encoding="utf-8")
pool_report.write_text("# report\n", encoding="utf-8")
assert_eq(pool_toml.resolve(), tc.find_target_toml(pool_report).resolve(),
          "find_target_toml returns the nearest ancestor config for a pool report")
(slug_dir / "benchmark" / "run.json").write_text(
    '{"target":"demo","target_sha":"feed1234"}\n', encoding="utf-8",
)
assert_eq("feed1234", tc.find_benchmark_target_rev(pool_report, "demo"),
          "find_benchmark_target_rev reads the enclosing run revision")
assert_eq("", tc.find_benchmark_target_rev(pool_report, "other"),
          "find_benchmark_target_rev rejects metadata for another target")

# find_slug_session_dir resolves a known slug dir to a backend session.
slug_session = tc.find_slug_session_dir(slug_dir)
assert_eq(backend_results.resolve(),
          slug_session.resolve() if slug_session else None,
          "find_slug_session_dir returns the backend-local session env")

# find_session_dir reached through an ancestor's output/ tree (a
# CWD-based call, not a testcase path) also prefers backend-local.
found = tc.find_session_dir(TEST_TMPDIR / "out_root")
assert_eq(backend_results.resolve(), found.resolve() if found else None,
          "find_session_dir scan returns backend-local session")

assert_eq(None, tc.find_slug_session_dir(TEST_TMPDIR / "no-such-slug"),
          "find_slug_session_dir returns None when no session exists")

# find_session_dir scans into a NESTED slug (output/samples/sample-x/...)
# reached from an ancestor's output/ tree. output/samples/ is a container, not
# a slug, so the scan must descend into it rather than treat it as a target.
nroot = TEST_TMPDIR / "nested_root"
n_results = nroot / "output" / "samples" / "sample-x" / "codex" / "results"
n_results.mkdir(parents=True)
(nroot / "output" / "samples" / "sample-x" / "target.toml").write_text(
    'target = "samples/sample-x"\n', encoding="utf-8")
(n_results / ".session-env").write_text(
    "RESULTS_DIR=nested\n", encoding="utf-8")
found = tc.find_session_dir(nroot)
assert_eq(n_results.resolve(), found.resolve() if found else None,
          "find_session_dir scan descends into a nested slug container")

# A benchmark repo-root facade under output/benchmark/ carries its own
# output/<slug>/target.toml and session, but is a harness artifact — never a
# real target. Both the enumerator and session discovery must skip it.
facade = (nroot / "output" / "benchmark" / "codex" / "run-1" / "cells"
          / "harness-r1" / "repo-root" / "output" / "cjson")
(facade / "codex" / "results").mkdir(parents=True)
(facade / "target.toml").write_text('target = "cjson"\n', encoding="utf-8")
(facade / "codex" / "results" / ".session-env").write_text(
    "RESULTS_DIR=facade\n", encoding="utf-8")
roots = sorted(str(r.relative_to(nroot / "output"))
               for r in tc.iter_target_roots(nroot / "output"))
assert_eq(["samples/sample-x"], roots,
          "iter_target_roots excludes benchmark repo-root facades")
found = tc.find_session_dir(nroot)
assert_eq(n_results.resolve(), found.resolve() if found else None,
          "find_session_dir skips a benchmark facade and returns the real target")

# A symlinked container dir (e.g. a benchmark repo-root facade linking back to
# the source tree, which carries its own output/) forms a cycle. The walk must
# not descend it — following the link recurses without bound and hangs the scan.
symroot = TEST_TMPDIR / "symloop"
(symroot / "output" / "samples" / "sample-y").mkdir(parents=True)
(symroot / "output" / "samples" / "sample-y" / "target.toml").write_text(
    'target = "samples/sample-y"\n', encoding="utf-8")
(symroot / "output" / "loop").symlink_to(symroot, target_is_directory=True)
roots = sorted(str(r.relative_to(symroot / "output"))
               for r in tc.iter_target_roots(symroot / "output"))
assert_eq(["samples/sample-y"], roots,
          "iter_target_roots skips a symlinked dir cycle and still finds real targets")

# Negative: outside any output/ tree returns None. An unrelated sibling may
# carry a valid-looking results session (as concurrent suites do under /tmp),
# but its parent is not a target root and must never be searched as one.
(TEST_TMPDIR / "unrelated" / "results").mkdir(parents=True)
(TEST_TMPDIR / "unrelated" / "results" / ".session-env").write_text(
    "RESULTS_DIR=unrelated\n", encoding="utf-8")
assert_eq(None, tc.find_slug_session_dir(TEST_TMPDIR),
          "find_slug_session_dir requires a target.toml root marker")
empty = TEST_TMPDIR / "elsewhere"
empty.mkdir()
assert_eq(None, tc.find_session_dir(empty),
          "find_session_dir ignores unrelated sibling sessions outside output/<slug>")

# Regression: the upward walk probes sibling trees under shared ancestors it
# does not own (e.g. snapd's mode-0700 /tmp/snap-private-tmp on CI runners). A
# permission-denied sibling must fall open, not crash the scan. Python <3.14's
# is_file() propagates PermissionError, so this reproduced only off 3.14.
perm_root = TEST_TMPDIR / "permwalk"
start = perm_root / "start"
start.mkdir(parents=True)
denied = perm_root / "denied" / "results"
denied.mkdir(parents=True)
os.chmod(perm_root / "denied", 0o000)
try:
    if os.access(denied, os.R_OK):  # running as root bypasses the mode; skip
        passed("find_session_dir falls open on a permission-denied sibling (skipped: root)")
    else:
        name = "find_session_dir falls open on a permission-denied sibling"
        res = None
        try:
            res = tc.find_session_dir(start)
            ok = res is None
        except OSError:
            ok = False
        if ok:
            passed(name)
        else:
            failed(name, f"raised or returned {res!r}")
finally:
    os.chmod(perm_root / "denied", 0o700)


# ─── 7. read_session_env allowlists keys ────────────────────────────

env_dir = TEST_TMPDIR / "envtest"
env_dir.mkdir()
(env_dir / ".session-env").write_text(
    "# header\nRESULTS_DIR=/path/results\nTARGET_ROOT=/path/root\nUNALLOWED=secret\n",
    encoding="utf-8",
)
env = tc.read_session_env(env_dir)
assert_eq("/path/results", env.get("RESULTS_DIR"),
          "read_session_env: RESULTS_DIR allowed")
assert_eq("/path/root", env.get("TARGET_ROOT"),
          "read_session_env: TARGET_ROOT allowed")
assert_eq(None, env.get("UNALLOWED"),
          "read_session_env: non-allowlisted keys dropped")


# ─── 8. write_session_env round-trips through read_session_env ──────

w_dir = TEST_TMPDIR / "writetest"
tc.write_session_env(w_dir, "/r", "/t", "myslug", "abcd1234", "/log")
re_env = tc.read_session_env(w_dir)
assert_eq("/r", re_env["RESULTS_DIR"], "write_session_env: RESULTS_DIR round-trips")
assert_eq("myslug", re_env["TARGET_SLUG"], "write_session_env: TARGET_SLUG round-trips")
assert_eq("abcd1234", re_env["TARGET_REV"], "write_session_env: TARGET_REV round-trips")

# A running audit reads a backend-local, digest-pinned configuration. Shared
# target.toml edits from another agent or operator apply only to the next run,
# and editing the pinned copy fails loud instead of changing recorded metrics.
pin_root = TEST_TMPDIR / "pin-session"
pin_results = pin_root / "output" / "sampleproj" / "codex" / "results"
pin_results.mkdir(parents=True)
pin_target = pin_root / "target"
pin_target.mkdir()
pin_toml = pin_results.parent.parent / "target.toml"
pin_toml.write_text(
    'target = "sampleproj"\n[threat_model]\nattacker_controls = ["timing"]\n',
    encoding="utf-8",
)
tc.write_session_env(
    pin_results, str(pin_results), str(pin_target), "sampleproj",
    "abcd1234", str(pin_results.parent / "logs"),
)
tc.pin_session_config(pin_results, pin_toml)
pin_report = pin_results / "crashes" / "CRASH-001" / "report.md"
pin_report.parent.mkdir(parents=True)
pin_report.write_text("# report\n", encoding="utf-8")
assert_eq(
    (pin_results / ".target.toml").resolve(),
    tc.find_target_toml(pin_report).resolve(),
    "find_target_toml uses the live session's pinned config",
)
pin_toml.write_text(
    'target = "sampleproj"\n[threat_model]\nattacker_controls = ["bytes"]\n',
    encoding="utf-8",
)
assert_eq(
    ["timing"], tc.load(pin_results).attacker_controls,
    "load uses the pinned config after shared target.toml changes",
)
(pin_results / ".target.toml").write_text(
    'target = "sampleproj"\n[threat_model]\nattacker_controls = ["race"]\n',
    encoding="utf-8",
)
try:
    tc.load(pin_results)
except tc.PinnedConfigError as exc:
    assert_in(
        "changed after audit preflight", str(exc),
        "load rejects a modified pinned target config",
    )
else:
    failed("load rejects a modified pinned target config", "load succeeded")
# The runners fall back to the shared config on ValueError. A pin violation
# must not take that path, or tampering silently retargets the whole session.
assert_eq(
    False, isinstance(
        tc.PinnedConfigError("x"), (ValueError, FileNotFoundError)
    ),
    "a pin violation is not the runners' no-session fallback signal",
)
(pin_results / ".target.toml").unlink()
try:
    tc.load(pin_results)
except tc.PinnedConfigError as exc:
    assert_in(
        "snapshot is missing", str(exc),
        "load rejects a missing pinned target config",
    )
else:
    failed("load rejects a missing pinned target config", "load succeeded")
tc.write_session_env(
    pin_results, str(pin_results), str(pin_target), "sampleproj",
    "abcd1234", str(pin_results.parent / "logs"),
)
assert_eq(
    ["bytes"], tc.load(pin_results).attacker_controls,
    "a new session ignores the previous run's pinned config",
)


# ─── 9. detect_rev returns revisions and the plain-tree sentinel ─────

plain_rev_root = TEST_TMPDIR / "plain-rev-target"
plain_rev_root.mkdir()
assert_eq("none", tc.detect_repo_type(plain_rev_root),
          "detect_repo_type: plain source tree is none")
assert_eq("norev", tc.detect_rev(plain_rev_root),
          "detect_rev: plain source tree uses norev sentinel")
broken_git_root = TEST_TMPDIR / "broken-git-rev-target"
broken_git_root.mkdir()
(broken_git_root / ".git").write_text("gitdir: /no/such/repo\n", encoding="utf-8")
assert_eq("none", tc.detect_repo_type(broken_git_root),
          "detect_repo_type: broken git metadata is none")
assert_eq("", tc.detect_rev(broken_git_root),
          "detect_rev: broken git metadata does not use norev sentinel")
if shutil.which("git"):
    parent_repo = TEST_TMPDIR / "parent-repo"
    nested_plain = parent_repo / "targets" / "nested-plain"
    nested_plain.mkdir(parents=True)
    subprocess.run(["git", "-C", str(parent_repo), "init", "-q"], check=True)
    assert_eq("norev", tc.detect_rev(nested_plain),
              "detect_rev: parent git repo does not make nested target a checkout")
assert_eq("", tc.detect_rev(TEST_TMPDIR / "missing-rev-target"),
          "detect_rev: missing source tree stays empty")
assert_eq("", tc.detect_rev(""),
          "detect_rev: an empty target root never resolves the harness checkout")

# audited_rev: the session's recorded rev is exact for that run and wins; with
# none recorded the checkout's own HEAD is the only honest answer.
_rev_cfg = tc.Config(target_root=str(plain_rev_root), target_rev="feedface")
assert_eq("feedface", tc.audited_rev(_rev_cfg),
          "audited_rev: the session's recorded rev wins")
_rev_cfg.target_rev = ""
assert_eq("norev", tc.audited_rev(_rev_cfg),
          "audited_rev: falls back to the tree's own revision")


# ─── 10. seed_toml emits a parseable file with [threat_model] ───────

seed_root = TEST_TMPDIR / "seed-target"
seed_root.mkdir()
out = TEST_TMPDIR / "seeded.toml"
tc.seed_toml(seed_root, out, "https://example.com/repo")
text = out.read_text(encoding="utf-8")
assert_in('target        = "seed-target"', text,
          "seeded toml has target field")
assert_not_in("pinned_rev", text,
              "seeded toml records no revision (it goes stale; see audited_rev)")
assert_in("[threat_model]", text, "seeded toml has [threat_model] header")
assert_in('attacker_controls = ["bytes"]', text,
          "seeded toml has bytes-only default for non-browser target")
assert_in("outside component a reviewer confirms is not reportable", text,
          "seeded toml explains the reviewed reachability decision")
assert_not_in("demotes it from security to robustness", text,
              "seeded toml omits reverted disposition wording")
# Round-trip back through the loader.
cfg = tc.Config()
tc.load_toml_into(cfg, out)
assert_eq("bytes", cfg.attacker_controls_csv(),
          "seeded generic toml round-trips through loader")

# No curated table is shipped: every non-browser slug seeds the conservative
# byte-only default, and bin/suggest-threat-model (the LLM) derives the real
# model per target (it already produces protocol-state for network targets like
# ffmpeg and byte-only for parsers like pcre2). This loop confirms the byte-only
# seed for a mix of slugs that previously carried hand-curated tokens.
threat_model_tmpdir = TEST_TMPDIR / "threat-model-roundtrip"
threat_model_tmpdir.mkdir()
for slug, expected_csv in [
    ("json", "bytes"),
    ("libxml2", "bytes"),
    ("curl", "bytes"),
    ("c-ares", "bytes"),
    ("pcre2", "bytes"),
    ("zlib", "bytes"),
]:
    root = threat_model_tmpdir / slug
    root.mkdir()
    seeded = threat_model_tmpdir / f"{slug}.toml"
    tc.seed_toml(root, seeded, "")
    cfg = tc.Config()
    tc.load_toml_into(cfg, seeded)
    assert_eq(expected_csv, cfg.attacker_controls_csv(),
              f"seed_toml: {slug} attacker_controls default")

# threat_model_for: the mechanism still reads an OPTIONAL operator-provided
# override file (no such file is shipped). A listed slug returns its tokens; any
# other slug returns [] so the caller falls back to the byte-only default — this
# works for ANY project, with no hardcoded per-project table in lib/.
_tm_override = TEST_TMPDIR / "threat_models_override.toml"
_tm_override.write_text(
    '[mylib]\nattacker_controls = ["bytes", "call-sequence"]\n'
    '[proto]\nattacker_controls = ["bytes", "protocol-state"]\n',
    encoding="utf-8")
assert_eq(["bytes", "call-sequence"], tc.threat_model_for("mylib", _tm_override),
          "threat_model_for: curated slug returns its attacker_controls")
assert_eq([], tc.threat_model_for("never-heard-of-it", _tm_override),
          "threat_model_for: unknown slug returns []")
assert_eq(["bytes"],
          tc.attacker_controls_for_seed("never-heard-of-it", False, _tm_override),
          "attacker_controls_for_seed: unknown non-browser falls back to bytes")
assert_eq(["bytes", "protocol-state"],
          tc.attacker_controls_for_seed("proto", False, _tm_override),
          "attacker_controls_for_seed: curated entry honored")
assert_eq(["bytes", "call-sequence", "timing"],
          tc.attacker_controls_for_seed("proto", True, _tm_override),
          "attacker_controls_for_seed: browser uses structural model, ignores table")
assert_eq([], tc.threat_model_for("mylib", TEST_TMPDIR / "no-such-file.toml"),
          "threat_model_for: missing file degrades to []")
assert_eq([], tc.threat_model_for("libxml2"),
          "threat_model_for: no bundled table shipped → default path resolves nothing")

# Browser target widens the threat model
fx = TEST_TMPDIR / "firefox"
fx.mkdir()
(fx / "mach").write_text("#!/bin/sh\n")
(fx / "mach").chmod(0o755)
fx_out = TEST_TMPDIR / "seeded-browser.toml"
tc.seed_toml(fx, fx_out, "")
fx_text = fx_out.read_text(encoding="utf-8")
assert_in("call-sequence", fx_text, "browser seed includes call-sequence")
assert_in("timing", fx_text, "browser seed includes timing")
cfg = tc.Config()
tc.load_toml_into(cfg, fx_out)
assert_eq("bytes,call-sequence,timing", cfg.attacker_controls_csv(),
          "seeded browser toml round-trips through loader")

# GN is a general build system, not itself evidence that the product accepts
# browser testcases. Explicit browser mode remains available to setup-target.
gn_root = TEST_TMPDIR / "gn-generic"
gn_root.mkdir()
(gn_root / ".gn").write_text('buildconfig = "//build/config/BUILDCONFIG.gn"\n')
gn_out = TEST_TMPDIR / "seeded-gn.toml"
tc.seed_toml(gn_root, gn_out, "")
gn_cfg = tc.Config()
tc.load_toml_into(gn_cfg, gn_out)
assert_eq("0", gn_cfg.is_browser,
          "GN seed remains generic without an explicit browser signal")
tc.seed_toml(gn_root, gn_out, "", browser_mode=True)
tc.load_toml_into(gn_cfg, gn_out)
assert_eq("1", gn_cfg.is_browser,
          "GN seed accepts explicit browser mode")
assert_eq(True, "--enable-logging=stderr" in gn_cfg.runner_args,
          "GN browser seed enables structured console evidence")
assert_eq(True, "--no-sandbox" in gn_cfg.runner_args,
          "GN browser seed keeps dedicated sanitizer logs reachable")
assert_eq(
    sys.platform == "darwin",
    "--use-mock-keychain" in gn_cfg.runner_args,
    "GN browser seed avoids macOS Safe Storage prompts only on Darwin",
)
assert_eq(
    sys.platform == "linux",
    "NSS_DISABLE_UNLOAD=1" in gn_cfg.runner_env,
    "GN browser seed carries Chromium's Linux ASan runtime settings",
)

# Every build-tree path a generic seed persists is the canonical alias, which
# Config.resolve_path maps onto whichever suffixed tree the image is running.
suffixed_seed_root = TEST_TMPDIR / "suffixed-seed"
(suffixed_seed_root / "build-asan-img42" / "include").mkdir(parents=True)
suffixed_seed_out = TEST_TMPDIR / "suffixed-seed.toml"
with mock.patch.dict(os.environ, {"AUDIT_BUILD_SUFFIX": "-img42"}):
    tc.seed_toml(suffixed_seed_root, suffixed_seed_out, "")
    suffixed_seed_cfg = tc.Config(target_root=str(suffixed_seed_root))
    tc.load_toml_into(suffixed_seed_cfg, suffixed_seed_out)
    assert_eq(True, "build-asan/include" in suffixed_seed_cfg.includes,
              "seed_toml persists the canonical include path under a suffix")
    assert_eq(
        str(suffixed_seed_root / "build-asan-img42" / "include"),
        suffixed_seed_cfg.resolve_path("build-asan/include"),
        "canonical include path resolves into the active suffixed tree",
    )
# A configure step writes its answers as headers into the build root, not
# under an `include/`. Seeding only `<build>/include` left a target whose
# public headers include the generated one unable to compile a harness at all.
inc_root = TEST_TMPDIR / "generated-header-root"
(inc_root / "src").mkdir(parents=True)
(inc_root / "CMakeLists.txt").write_text("add_executable(t t.c)\n", encoding="utf-8")
(inc_root / "src" / "api.h").write_text("#include <proj/options.h>\n", encoding="utf-8")
(inc_root / "build-asan" / "proj").mkdir(parents=True)
(inc_root / "build-asan" / "proj" / "options.h").write_text("#define X 1\n", encoding="utf-8")
inc_out = TEST_TMPDIR / "generated-header-root.toml"
tc.seed_toml(inc_root, inc_out, "")
inc_cfg = tc.Config(target_root=str(inc_root))
tc.load_toml_into(inc_cfg, inc_out)
assert_eq(True, "build-asan" in inc_cfg.includes,
          "seed_toml puts the build root on the harness include path")
assert_eq(True, inc_cfg.includes.index("build-asan/include")
          < inc_cfg.includes.index("build-asan"),
          "the build root is searched after its include/ subdirectory")
assert_eq(True, inc_cfg.includes.index("src") < inc_cfg.includes.index("build-asan"),
          "generated headers resolve after the project's own source locations")

assert_not_in("build-asan-img42", suffixed_seed_out.read_text(encoding="utf-8"),
              "seed_toml never writes a physical suffixed build path")


# ─── 9c. S6 peers come only from target.toml ────────────────────────
# seed_toml never emits [s6_peers]. bin/audit --new-target may call
# bin/suggest-peers afterwards, but target_config.py itself does not
# consult any shared bundled peer table.
s6_root = TEST_TMPDIR / "s6-seed"
s6_libxml2 = s6_root / "libxml2"
s6_libxml2.mkdir(parents=True)
s6_out = s6_root / "libxml2.toml"
tc.seed_toml(s6_libxml2, s6_out, "")
s6_text = s6_out.read_text(encoding="utf-8")
if "[s6_peers]" not in s6_text:
    passed("seed_toml: bundled slug emits no [s6_peers] section")
else:
    failed("seed_toml: bundled slug emits no [s6_peers] section",
           f"text snippet: {s6_text[-400:]!r}")

cfg = tc.Config()
tc.load_toml_into(cfg, s6_out)
if cfg.s6_peers == []:
    passed("load_toml_into: missing s6_peers stays empty")
else:
    failed("load_toml_into: missing s6_peers stays empty",
           f"got {cfg.s6_peers!r}")
if cfg.s6_domain == "":
    passed("load_toml_into: missing s6_domain stays empty")
else:
    failed("load_toml_into: missing s6_domain stays empty",
           f"got {cfg.s6_domain!r}")

# Explicit [s6_peers] in target.toml remains authoritative.
explicit_s6 = TEST_TMPDIR / "explicit-s6.toml"
explicit_s6.write_text(
    'target = "libxml2"\n'
    '[s6_peers]\n'
    'domain = "XML / SGML"\n'
    'peers = ["expat", "libxslt", "html5ever"]\n',
    encoding="utf-8",
)
cfg = tc.Config()
tc.load_toml_into(cfg, explicit_s6)
if cfg.s6_peers == ["expat", "libxslt", "html5ever"]:
    passed("load_toml_into: explicit s6_peers round-trips")
else:
    failed("load_toml_into: explicit s6_peers round-trips",
           f"got {cfg.s6_peers!r}")
if cfg.s6_domain == "XML / SGML":
    passed("load_toml_into: explicit s6_domain round-trips")
else:
    failed("load_toml_into: explicit s6_domain round-trips",
           f"got {cfg.s6_domain!r}")

# Existing target.toml without [s6_peers] does not get implicit peers.
minimal_toml = TEST_TMPDIR / "minimal-libxml2.toml"
minimal_toml.write_text(
    'target = "libxml2"\n'
    'build_system = "cmake"\n'
    'asan_bin = "build-asan/xmllint"\n'
    '[threat_model]\n'
    'attacker_controls = ["bytes"]\n',
    encoding="utf-8",
)
cfg = tc.Config()
tc.load_toml_into(cfg, minimal_toml)
if cfg.s6_peers == []:
    passed("load_toml_into: target.toml without s6_peers stays empty")
else:
    failed("load_toml_into: target.toml without s6_peers stays empty",
           f"got s6_peers={cfg.s6_peers!r}")
if cfg.s6_domain == "":
    passed("load_toml_into: target.toml leaves s6_domain empty")
else:
    failed("load_toml_into: target.toml leaves s6_domain empty",
           f"got s6_domain={cfg.s6_domain!r}")

# Operator-explicit empty override (peers = []) disables S6 for that target.
explicit_empty = TEST_TMPDIR / "explicit-empty.toml"
explicit_empty.write_text(
    'target = "libxml2"\n'
    '[s6_peers]\n'
    'peers = []\n',
    encoding="utf-8",
)
cfg = tc.Config()
tc.load_toml_into(cfg, explicit_empty)
if cfg.s6_peers == []:
    passed("load_toml_into: explicit empty peers disables S6")
else:
    failed("load_toml_into: explicit empty peers disables S6",
           f"got {cfg.s6_peers!r}")


# ─── 10b. [sanitizer] section: defaults, parsing, helpers ──────────

cfg = tc.Config()
write("no-san.toml", 'slug = "demo"\n')
tc.load_toml_into(cfg, TEST_TMPDIR / "no-san.toml")
assert_eq(["asan"], cfg.sanitizers_enabled,
          "[sanitizer] absent → defaults to ['asan']")
assert_eq("asan", cfg.sanitizers_enabled_csv(),
          "sanitizers_enabled_csv defaults to 'asan'")
assert_eq(True, cfg.sanitizer_is_enabled("asan"),
          "sanitizer_is_enabled('asan') = True by default")
assert_eq(False, cfg.sanitizer_is_enabled("msan"),
          "sanitizer_is_enabled('msan') = False by default")

cfg = tc.Config()
write("all-san.toml",
      'slug = "all"\n[sanitizer]\nenabled = ["asan", "ubsan", "msan", "tsan"]\n')
tc.load_toml_into(cfg, TEST_TMPDIR / "all-san.toml")
assert_eq("asan,ubsan,msan,tsan", cfg.sanitizers_enabled_csv(),
          "[sanitizer].enabled parses all four sanitizers in order")

# Unknown token: stderr warning + drop.
cfg = tc.Config()
write("bogus-san.toml",
      'slug = "bogus"\n[sanitizer]\nenabled = ["asan", "blortsan", "ubsan"]\n')
buf = io.StringIO()
with contextlib.redirect_stderr(buf):
    tc.load_toml_into(cfg, TEST_TMPDIR / "bogus-san.toml")
warn = buf.getvalue()
assert_eq(["asan", "ubsan"], cfg.sanitizers_enabled,
          "unknown sanitizer dropped, others kept")
assert_in("blortsan", warn, "stderr warning mentions the bad sanitizer token")

# Explicit empty enabled = [] is honored as findings-only mode (no default
# fallback to ["asan"]); the loader marks sanitizers_explicitly_disabled.
cfg = tc.Config()
write("empty-san.toml", 'slug = "empty"\n[sanitizer]\nenabled = []\n')
tc.load_toml_into(cfg, TEST_TMPDIR / "empty-san.toml")
assert_eq([], cfg.sanitizers_enabled,
          "explicit empty enabled list → no sanitizers (findings-only mode)")
assert_eq(True, cfg.sanitizers_explicitly_disabled,
          "explicit empty enabled list → sanitizers_explicitly_disabled=True")
assert_eq("", cfg.sanitizers_enabled_csv(),
          "explicit empty enabled list → empty CSV")

# Section present but `enabled` key absent: still defaults to ['asan'].
cfg = tc.Config()
write("no-enabled-key.toml",
      'slug = "no-enabled"\n[sanitizer]\nasan_options = "verbosity=1"\n')
tc.load_toml_into(cfg, TEST_TMPDIR / "no-enabled-key.toml")
assert_eq(["asan"], cfg.sanitizers_enabled,
          "[sanitizer] without `enabled` key → defaults to ['asan']")
assert_eq(False, cfg.sanitizers_explicitly_disabled,
          "[sanitizer] without `enabled` key → not flagged as explicit-empty")

# Suppressions: relative resolve under target_root; absolute pass-through.
cfg = tc.Config()
cfg.target_root = "/fake/root"
write("sup.toml",
      'slug = "sup"\n[sanitizer]\nenabled = ["asan", "ubsan", "msan", "tsan"]\n'
      'asan_suppressions  = "build-asan/asan.txt"\n'
      'ubsan_suppressions = "build-ubsan/ubsan.txt"\n'
      'msan_suppressions  = "/abs/msan.txt"\n'
      'tsan_suppressions  = "build-tsan/tsan.txt"\n')
tc.load_toml_into(cfg, TEST_TMPDIR / "sup.toml")
assert_eq("/fake/root/build-asan/asan.txt",
          cfg.sanitizer_suppressions_path("asan"),
          "asan suppressions resolved under target_root")
assert_eq("/abs/msan.txt", cfg.sanitizer_suppressions_path("msan"),
          "absolute msan suppressions pass-through")
assert_eq("", cfg.sanitizer_suppressions_path("nonexistent"),
          "unknown sanitizer suppressions path returns empty")

# Per-sanitizer binary overrides.
cfg = tc.Config()
write("bins.toml",
      'slug = "bins"\nasan_bin = "build-asan/foo"\n'
      '[sanitizer]\nenabled = ["asan", "ubsan", "msan", "tsan"]\n'
      'ubsan_bin = "build-ubsan/foo"\n'
      'msan_bin  = "build-msan/foo"\n'
      'tsan_bin  = "build-tsan/foo"\n')
tc.load_toml_into(cfg, TEST_TMPDIR / "bins.toml")
assert_eq("build-asan/foo", cfg.asan_bin, "top-level asan_bin still works")
assert_eq("build-ubsan/foo", cfg.ubsan_bin, "[sanitizer].ubsan_bin parsed")
assert_eq("build-msan/foo", cfg.msan_bin, "[sanitizer].msan_bin parsed")
assert_eq("build-tsan/foo", cfg.tsan_bin, "[sanitizer].tsan_bin parsed")

# Per-sanitizer extra options
cfg = tc.Config()
write("opts.toml",
      'slug = "opts"\n[sanitizer]\nenabled = ["asan"]\n'
      'asan_options = "verbosity=1"\n')
tc.load_toml_into(cfg, TEST_TMPDIR / "opts.toml")
assert_eq("verbosity=1", cfg.sanitizer_options.get("asan", ""),
          "asan_options parsed into sanitizer_options dict")
assert_eq("", cfg.sanitizer_options.get("msan", ""),
          "missing msan_options returns empty default")

# seeded toml emits [sanitizer] with asan default
seed_root2 = TEST_TMPDIR / "seed-san"
seed_root2.mkdir()
out2 = TEST_TMPDIR / "seeded-san.toml"
tc.seed_toml(seed_root2, out2, "")
text2 = out2.read_text(encoding="utf-8")
assert_in("[sanitizer]", text2, "seeded toml has [sanitizer] header")
assert_in('enabled = ["asan"]', text2, "seeded toml defaults enabled to asan only")
cfg = tc.Config()
tc.load_toml_into(cfg, out2)
assert_eq("asan", cfg.sanitizers_enabled_csv(),
          "seeded toml round-trips: asan only")


# ─── 10c. seed_toml comments out asan_lib/asan_bin when not detected ──
#
# Regression: a header-only C++ target (no .a archive in build-asan/)
# used to be seeded with `asan_lib = "build-asan/FILL_ME.a"`. That literal
# placeholder leaked into bin/export-repro's reproduce.sh template, which
# then failed at runtime with "ASan static library not found". Comment
# out the line instead so downstream tools see the field as absent.

seed_root_he = TEST_TMPDIR / "seed-header-only"
seed_root_he.mkdir()
# Deliberately no build-asan/ subtree → seed_toml falls back to "unset".
out_he = TEST_TMPDIR / "seeded-header-only.toml"
tc.seed_toml(seed_root_he, out_he, "")
text_he = out_he.read_text(encoding="utf-8")

# The bad placeholder must not appear as a live TOML key…
assert_not_in('asan_lib      = "build-asan/FILL_ME.a"', text_he,
              "seed_toml: no live asan_lib = FILL_ME.a line when no archive")
assert_not_in('asan_bin      = "build-asan/FILL_ME"', text_he,
              "seed_toml: no live asan_bin = FILL_ME line when no binary")
# …but the FILL_ME token still appears in a comment so bin/setup-target's
# grep-for-FILL_ME refresh trigger keeps working.
assert_in("FILL_ME", text_he,
          "seed_toml: FILL_ME stays in comments for setup-target refresh trigger")
# Round-trip: the loader sees asan_lib/asan_bin as empty.
cfg_he = tc.Config()
tc.load_toml_into(cfg_he, out_he)
assert_eq("", cfg_he.asan_lib,
          "seed_toml round-trip: empty asan_lib when none detected")
assert_eq("", cfg_he.asan_bin,
          "seed_toml round-trip: empty asan_bin when none detected")


# ─── 10d. seed_toml detects a shared library when no static archive ──
#
# Regression: cmake/meson projects (c-ares, pcre2, …) build only a shared
# library, not a .a. seed_toml used to scan for archives only, leaving
# asan_lib unset → export-repro emitted a reproduce.sh that linked nothing
# and the harness failed with undefined symbols. seed_toml must record the
# canonical instrumented .so/.dylib so the harness links it.
for _sh_ext, _versioned in ((".so", "libtgt.so.2.1"), (".dylib", "libtgt.2.1.dylib")):
    seed_root_sh = TEST_TMPDIR / f"seed-shared{_sh_ext}"
    (seed_root_sh / "build-asan" / "lib").mkdir(parents=True)
    libdir = seed_root_sh / "build-asan" / "lib"
    # Canonical unversioned linker name + a versioned SONAME sibling.
    (libdir / f"libtgt{_sh_ext}").write_bytes(b"\x7fELF")
    (libdir / f"{_versioned}").write_bytes(b"\x7fELF")
    out_sh = TEST_TMPDIR / f"seeded-shared{_sh_ext}.toml"
    tc.seed_toml(seed_root_sh, out_sh, "")
    cfg_sh = tc.Config()
    tc.load_toml_into(cfg_sh, out_sh)
    assert_eq(f"build-asan/lib/libtgt{_sh_ext}", cfg_sh.asan_lib,
              f"seed_toml: picks canonical libtgt{_sh_ext} over versioned sibling")

# A static archive still wins over a shared object when both are present.
seed_root_mix = TEST_TMPDIR / "seed-archive-wins"
(seed_root_mix / "build-asan" / "lib").mkdir(parents=True)
(seed_root_mix / "build-asan" / "lib" / "libtgt.a").write_bytes(b"!<arch>\n")
(seed_root_mix / "build-asan" / "lib" / "libtgt.dylib").write_bytes(b"\x7fELF")
out_mix = TEST_TMPDIR / "seeded-archive-wins.toml"
tc.seed_toml(seed_root_mix, out_mix, "")
cfg_mix = tc.Config()
tc.load_toml_into(cfg_mix, out_mix)
assert_eq("build-asan/lib/libtgt.a", cfg_mix.asan_lib,
          "seed_toml: static archive preferred over shared object")

# _detect_sanitizer_lib returns empty for a build dir with no library
# (header-only / CLI-only target) so the field stays a commented placeholder.
assert_eq("", tc._detect_sanitizer_lib(seed_root_he / "build-asan", seed_root_he),
          "_detect_sanitizer_lib: empty when no archive or shared object")

# Product output directories are target-defined and may sit below several
# layers of build-system grouping. Artifact discovery must not turn a complete
# build into a permanent setup failure merely because the product is deep.
deep_root = TEST_TMPDIR / "deep-build-product"
deep_lib = deep_root / "build-asan" / "group" / "platform" / "release" / "libdeep.a"
deep_lib.parent.mkdir(parents=True)
deep_lib.write_bytes(b"!<arch>\n")
assert_eq("build-asan/group/platform/release/libdeep.a",
          tc.detect_sanitizer_build_artifacts(deep_root, "asan")[1],
          "artifact detection reaches target-defined nested output")

# Depth ranks above alphabetical order for generated defaults. The scan walks
# depth-first in name order, so a subdirectory sorting before a root aggregate
# took the slot. This remains a heuristic: a usable configured value is kept.
product_root = TEST_TMPDIR / "shallow-product-wins"
(product_root / "build-asan" / "tools").mkdir(parents=True)
(product_root / "build-asan" / "tools" / "libhelper.a").write_bytes(b"!<arch>\n")
(product_root / "build-asan" / "libsampleproj.a").write_bytes(b"!<arch>\n")
(product_root / "build-asan" / "libsampleproj_extra.a").write_bytes(b"!<arch>\n")
assert_eq("build-asan/libsampleproj.a",
          tc.detect_sanitizer_build_artifacts(product_root, "asan")[1],
          "_detect_sanitizer_lib: a top-level product outranks a nested helper")

# Public headers live by convention, and the conventions are few: include/, the
# root, src/, lib/. A tree that matches none of them still needs a path that
# resolves `<component>/header.h`, which is the root.
def _include_case(name: str, headers: "list[str]") -> "list[str]":
    root = TEST_TMPDIR / f"includes-{name}"
    (root / "build-asan").mkdir(parents=True)
    for relative in headers:
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("int f(void);\n", encoding="utf-8")
    return tc._detect_include_dirs(root, "build-asan")

assert_in("lib", _include_case("lib-layout", ["lib/sampleproj.h"]),
          "_detect_include_dirs: a lib/ layout is a public-header location")
assert_in(".", _include_case("component-layout", ["component/api.h"]),
          "_detect_include_dirs: an unrecognised layout still resolves from the root")
assert_eq(False, "." in _include_case("include-layout", ["include/pub.h"]),
          "_detect_include_dirs: a named layout does not also pull in the root")

# `refresh_detected_build_fields` keeps a configured value that is a usable
# artifact. Re-detection can diagnose a library/header mismatch, but remains a
# weaker signal than an operator choice and must not write past that rule.
repair_root = TEST_TMPDIR / "harness-input-repair"
(repair_root / "build-asan" / "tools").mkdir(parents=True)
(repair_root / "build-asan" / "tools" / "libhelper.a").write_bytes(b"!<arch>\n")
(repair_root / "build-asan" / "libproduct.a").write_bytes(b"!<arch>\n")
(repair_root / "lib").mkdir()
(repair_root / "lib" / "product.h").write_text("int f(void);\n", encoding="utf-8")
repair_toml = repair_root / "target.toml"
repair_toml.write_text(
    'build_system  = "cmake"\n'
    'asan_lib      = "build-asan/tools/libhelper.a"\n'
    'includes      = ["build-asan"]\n',
    encoding="utf-8",
)
detected_lib, detected_includes = tc.detected_harness_inputs(repair_root, "asan")
assert_eq("build-asan/libproduct.a", detected_lib,
          "detected_harness_inputs: reports the product, not the kept helper")
assert_in("lib", detected_includes,
          "detected_harness_inputs: reports the header location")
assert_eq(False, tc.refresh_detected_build_fields(repair_root, repair_toml),
          "refresh_detected_build_fields: still keeps the usable-but-wrong value")
assert_in('asan_lib      = "build-asan/tools/libhelper.a"',
          repair_toml.read_text(encoding="utf-8"),
          "re-detection never overwrites a usable configured library")

# A generated CMake interface export is positive evidence that a successful
# build is header-only, while any imported compiled location keeps the normal
# artifact requirement in force.
header_build = seed_root_he / "build-asan"
header_build.mkdir()
(header_build / "sampleTargets.cmake").write_text(
    "add_library(sample::sample INTERFACE IMPORTED)\n",
    encoding="utf-8",
)
assert_eq(True, tc.cmake_build_is_header_only(header_build),
          "CMake interface-only export identifies a header-only build")
(header_build / "sampleTargets-release.cmake").write_text(
    'set_target_properties(sample::sample PROPERTIES IMPORTED_LOCATION_RELEASE "libsample.a")\n',
    encoding="utf-8",
)
assert_eq(False, tc.cmake_build_is_header_only(header_build),
          "CMake compiled import still requires a selectable artifact")

# A FetchContent dependency ships its own export. Reading it would let a
# header-only dependency vouch for a compiled product the recipe never
# produced, so a build whose only interface export sits under _deps stays a
# build failure.
dep_build = TEST_TMPDIR / "deps-interface-export" / "build-asan"
(dep_build / "_deps" / "dep-build").mkdir(parents=True)
(dep_build / "_deps" / "dep-build" / "depTargets.cmake").write_text(
    "add_library(dep::dep-header-only INTERFACE IMPORTED)\n",
    encoding="utf-8",
)
assert_eq(False, tc.cmake_build_is_header_only(dep_build),
          "a dependency's interface export does not excuse a missing product")

# A test-framework static archive under tests/ (Unity, gtest) must NOT be
# chosen over the project's own shared library at the build root — the
# cjson case: libcjson.dylib at root + tests/libunity.a. Picking the test
# archive made the harness link the wrong library.
seed_root_aux = TEST_TMPDIR / "seed-aux-test-lib"
(seed_root_aux / "build-asan" / "tests").mkdir(parents=True)
(seed_root_aux / "build-asan" / "tests" / "libunity.a").write_bytes(b"!<arch>\n")
(seed_root_aux / "build-asan" / "libproject.dylib").write_bytes(b"\x7fELF")
assert_eq("build-asan/libproject.dylib",
          tc._detect_sanitizer_lib(seed_root_aux / "build-asan", seed_root_aux),
          "_detect_sanitizer_lib: skips a test-dir archive for the project's lib")
# And a _deps/ FetchContent dependency archive is likewise skipped.
seed_root_deps = TEST_TMPDIR / "seed-deps-lib"
(seed_root_deps / "build-asan" / "_deps" / "fmt-build").mkdir(parents=True)
(seed_root_deps / "build-asan" / "_deps" / "fmt-build" / "libfmt.a").write_bytes(b"!<arch>\n")
(seed_root_deps / "build-asan" / "libproject.a").write_bytes(b"!<arch>\n")
assert_eq("build-asan/libproject.a",
          tc._detect_sanitizer_lib(seed_root_deps / "build-asan", seed_root_deps),
          "_detect_sanitizer_lib: skips a _deps dependency archive")


# ─── 10e. refresh_detected_build_fields corrects <san>_bin/<san>_lib ──
#
# seed_toml runs before any build exists, so on a fresh target asan_lib
# stays a commented FILL_ME. The build step materializes the canonical
# build and calls refresh_detected_build_fields to patch the detected
# fields in — without disturbing curated sections.
refresh_root = TEST_TMPDIR / "refresh-target"
(refresh_root / "build-asan" / "lib").mkdir(parents=True)
(refresh_root / "build-asan" / "lib" / "libwidget.a").write_bytes(b"!<arch>\n")
refresh_toml = refresh_root / "target.toml"
refresh_toml.write_text(
    'target        = "widget"\n'
    'build_system  = "cmake"\n'
    '# asan_lib    = "build-asan/FILL_ME.a"    # uncomment + fill if a // HARNESS\n'
    'includes      = ["include", "build-asan/include"]\n'
    'link_libs     = ["-lm", "-lpthread"]\n'
    '\n'
    '[threat_model]\n'
    'attacker_controls = ["bytes", "protocol-state"]\n',
    encoding="utf-8",
)
changed = tc.refresh_detected_build_fields(refresh_root, refresh_toml)
assert_eq(True, changed, "refresh_detected_build_fields: reports a change")
refreshed = refresh_toml.read_text(encoding="utf-8")
assert_in('asan_lib      = "build-asan/lib/libwidget.a"', refreshed,
          "refresh_detected_build_fields: fills asan_lib from the built archive")
assert_not_in("FILL_ME", refreshed,
              "refresh_detected_build_fields: replaces the commented placeholder")
assert_in('attacker_controls = ["bytes", "protocol-state"]', refreshed,
          "refresh_detected_build_fields: leaves the curated [threat_model] intact")
# Round-trips through the loader as a real field.
cfg_refresh = tc.Config()
tc.load_toml_into(cfg_refresh, refresh_toml)
assert_eq("build-asan/lib/libwidget.a", cfg_refresh.asan_lib,
          "refresh_detected_build_fields: asan_lib round-trips through load_toml_into")
# Idempotent: a second pass finds the field already correct.
assert_eq(False, tc.refresh_detected_build_fields(refresh_root, refresh_toml),
          "refresh_detected_build_fields: idempotent once filled")
# No build tree → nothing to fill, no change.
norefresh_root = TEST_TMPDIR / "refresh-nobuild"
norefresh_root.mkdir()
norefresh_toml = norefresh_root / "target.toml"
norefresh_toml.write_text(
    '# asan_lib    = "build-asan/FILL_ME.a"\n', encoding="utf-8")
assert_eq(False, tc.refresh_detected_build_fields(norefresh_root, norefresh_toml),
          "refresh_detected_build_fields: no change when no build tree exists")

# asan_bin pointing into CMakeFiles/ (a CMake compiler probe the old scan
# mis-picked) is scrubbed back to a commented FILL_ME placeholder; a
# plausible asan_bin that detection can't confirm is left alone.
scrub_root = TEST_TMPDIR / "refresh-scrub-bin"
(scrub_root / "build-asan" / "CMakeFiles" / "4.3").mkdir(parents=True)
(scrub_root / "build-asan" / "CMakeFiles" / "4.3" / "probe.bin").write_bytes(b"\x7fELF")
(scrub_root / "build-asan" / "realtool").write_bytes(b"\x7fELF")
scrub_toml = scrub_root / "target.toml"
scrub_toml.write_text(
    'target        = "widget"\n'
    'build_system  = "cmake"\n'
    'asan_bin      = "build-asan/CMakeFiles/4.3/probe.bin"\n',
    encoding="utf-8",
)
assert_eq(True, tc.refresh_detected_build_fields(scrub_root, scrub_toml),
          "refresh_detected_build_fields: scrubs a CMakeFiles probe asan_bin")
scrubbed = scrub_toml.read_text(encoding="utf-8")
assert_not_in("CMakeFiles/4.3/probe.bin", scrubbed,
              "refresh_detected_build_fields: removes the bogus probe path")
assert_in('# asan_bin = "build-asan/FILL_ME"', scrubbed,
          "refresh_detected_build_fields: leaves a commented FILL_ME placeholder")
cfg_scrub = tc.Config()
tc.load_toml_into(cfg_scrub, scrub_toml)
assert_eq("", cfg_scrub.asan_bin,
          "refresh_detected_build_fields: scrubbed asan_bin reads back as unset")

# An executable that detection misses is kept when it remains in the matching
# sanitizer build: this preserves operator choice even for a stripped binary
# whose instrumentation `nm` cannot inspect.
keep_root = TEST_TMPDIR / "refresh-keep-bin"
(keep_root / "build-asan").mkdir(parents=True)
(keep_root / "build-asan" / "mytool").write_bytes(b"\x7fELF")
os.chmod(keep_root / "build-asan" / "mytool", 0o755)
keep_toml = keep_root / "target.toml"
keep_toml.write_text(
    'build_system  = "cmake"\n'
    'asan_bin      = "build-asan/mytool"\n',
    encoding="utf-8",
)
tc.refresh_detected_build_fields(keep_root, keep_toml)
assert_in('asan_bin      = "build-asan/mytool"', keep_toml.read_text(encoding="utf-8"),
          "refresh_detected_build_fields: keeps an operator-set asan_bin in its build")

# Browser refresh must not preserve a background process helper as the main
# runner merely because it is executable and instrumented. App role metadata
# identifies the helper without a product-specific name.
browser_refresh_root = Path("browser-refresh-relative")
browser_refresh_abs = TEST_TMPDIR / browser_refresh_root
for app_name, executable, metadata in (
    ("Helper.app", "Helper", {
        "CFBundleExecutable": "Helper", "LSBackgroundOnly": "1",
    }),
    ("Product.app", "Product", {"CFBundleExecutable": "Product"}),
):
    app = browser_refresh_abs / "build-asan" / app_name / "Contents"
    binary = app / "MacOS" / executable
    binary.parent.mkdir(parents=True, exist_ok=True)
    binary.write_bytes(b"\x7fELF")
    binary.chmod(0o755)
    with (app / "Info.plist").open("wb") as stream:
        plistlib.dump(metadata, stream)
browser_refresh_toml = browser_refresh_abs / "target.toml"
browser_refresh_toml.write_text(
    'build_system = "gn"\n'
    'asan_bin = "build-asan/Helper.app/Contents/MacOS/Helper"\n',
    encoding="utf-8",
)
_saved_uses = tc._binary_uses_sanitizer
tc._binary_uses_sanitizer = lambda path, sanitizer="asan": True
try:
    detected_browser = tc.detect_browser_sanitizer_bin(
        Path(os.path.relpath(browser_refresh_abs, Path.cwd())), "asan"
    )
    assert_eq("build-asan/Product.app/Contents/MacOS/Product",
              detected_browser,
              "browser artifact detection excludes background helper apps")
    assert_eq(True, tc.refresh_detected_build_fields(
        browser_refresh_abs, browser_refresh_toml, is_browser=True
    ), "browser refresh replaces a configured background helper")
finally:
    tc._binary_uses_sanitizer = _saved_uses
assert_in('asan_bin      = "build-asan/Product.app/Contents/MacOS/Product"',
          browser_refresh_toml.read_text(encoding="utf-8"),
          "browser refresh adopts the foreground product executable")

# Browser mode covers both page products and script engines. The fresh-profile
# token already required by the browser runner contract distinguishes them
# without guessing from a binary name or from generic runner arguments.
page_config = tc.Config(build_system="mach")
assert_eq(
    True, tc.browser_page_launch_configured(page_config),
    "native browser defaults describe a page route",
)
page_config.build_system = ""
page_config.runner_args = ["--input", "{TESTCASE}"]
assert_eq(
    False, tc.browser_page_launch_configured(page_config),
    "generic script-engine arguments do not describe a page route",
)
page_config.runner_args = ["--profile={PROFILE}", "{TESTCASE}"]
assert_eq(
    True, tc.browser_page_launch_configured(page_config),
    "an explicit fresh-profile argument describes a page route",
)

# Container suffixes select physical build trees at runtime but must never be
# persisted: the next image resolves the canonical path to its own suffix.
suffixed_browser_root = TEST_TMPDIR / "browser-suffixed"
suffixed_app = (
    suffixed_browser_root / "build-asan-img42"
    / "Product.app" / "Contents"
)
suffixed_binary = suffixed_app / "MacOS" / "Product"
suffixed_binary.parent.mkdir(parents=True)
suffixed_binary.write_bytes(b"\x7fELF")
suffixed_binary.chmod(0o755)
with (suffixed_app / "Info.plist").open("wb") as stream:
    plistlib.dump({"CFBundleExecutable": "Product"}, stream)
_saved_uses = tc._binary_uses_sanitizer
tc._binary_uses_sanitizer = lambda path, sanitizer="asan": True
try:
    with mock.patch.dict(os.environ, {"AUDIT_BUILD_SUFFIX": "-img42"}):
        assert_eq(
            "build-asan/Product.app/Contents/MacOS/Product",
            tc.detect_browser_sanitizer_bin(suffixed_browser_root, "asan"),
            "browser detection canonicalizes container-suffixed build paths",
        )
        suffixed_cfg = tc.Config(
            target_root=str(suffixed_browser_root),
            asan_bin="build-asan/Product.app/Contents/MacOS/Product",
        )
        assert_eq(
            str(suffixed_binary),
            suffixed_cfg.resolve_path(suffixed_cfg.asan_bin),
            "canonical browser path resolves into the active suffixed tree",
        )
    current_app = (
        suffixed_browser_root / "build-asan-img43"
        / "Product.app" / "Contents"
    )
    current_binary = current_app / "MacOS" / "Product"
    current_binary.parent.mkdir(parents=True)
    current_binary.write_bytes(b"\x7fELF")
    current_binary.chmod(0o755)
    with (current_app / "Info.plist").open("wb") as stream:
        plistlib.dump({"CFBundleExecutable": "Product"}, stream)
    stale_toml = suffixed_browser_root / "target.toml"
    stale_toml.write_text(
        'asan_bin = "build-asan-img42/Product.app/Contents/MacOS/Product"\n',
        encoding="utf-8",
    )
    with mock.patch.dict(os.environ, {"AUDIT_BUILD_SUFFIX": "-img43"}):
        assert_eq(
            True,
            tc.refresh_detected_build_fields(
                suffixed_browser_root, stale_toml, is_browser=True
            ),
            "browser refresh replaces a persisted path from an older image",
        )
        assert_in(
            'asan_bin      = "build-asan/Product.app/Contents/MacOS/Product"',
            stale_toml.read_text(encoding="utf-8"),
            "browser refresh persists the canonical build alias",
        )
finally:
    tc._binary_uses_sanitizer = _saved_uses

# A non-bundle browser build with several plausible top-level executables must
# not guess by size; target.toml is the explicit product-selection contract.
ambiguous_browser_root = TEST_TMPDIR / "browser-ambiguous"
(ambiguous_browser_root / "build-asan").mkdir(parents=True)
for name, size in (("small", 4), ("large", 400)):
    binary = ambiguous_browser_root / "build-asan" / name
    binary.write_bytes(b"x" * size)
    binary.chmod(0o755)
_saved_uses = tc._binary_uses_sanitizer
tc._binary_uses_sanitizer = lambda path, sanitizer="asan": True
try:
    assert_eq("", tc.detect_browser_sanitizer_bin(
        ambiguous_browser_root, "asan"
    ), "browser artifact detection rejects ambiguous top-level executables")
finally:
    tc._binary_uses_sanitizer = _saved_uses

# Ambiguity is decided before instrumentation, so a build root full of
# executables costs no `nm` invocations at all.
_probed: list[str] = []
_saved_uses = tc._binary_uses_sanitizer
tc._binary_uses_sanitizer = lambda path, sanitizer="asan": (
    _probed.append(str(path)) or True
)
try:
    tc.detect_browser_sanitizer_bin(ambiguous_browser_root, "asan")
    assert_eq([], _probed,
              "ambiguous build roots are rejected without inspecting binaries")
finally:
    tc._binary_uses_sanitizer = _saved_uses

# The same ambiguity rule applies to foreground app bundles. Helper-role
# metadata can exclude background apps, but two equally shallow products need
# an explicit operator choice.
ambiguous_bundle_root = TEST_TMPDIR / "browser-ambiguous-bundles"
for app_name in ("Alpha.app", "Beta.app"):
    app = ambiguous_bundle_root / "build-asan" / app_name / "Contents"
    binary = app / "MacOS" / app_name.removesuffix(".app")
    binary.parent.mkdir(parents=True, exist_ok=True)
    binary.write_bytes(b"\x7fELF")
    binary.chmod(0o755)
    with (app / "Info.plist").open("wb") as stream:
        plistlib.dump({"CFBundleExecutable": binary.name}, stream)
_saved_uses = tc._binary_uses_sanitizer
tc._binary_uses_sanitizer = lambda path, sanitizer="asan": True
try:
    assert_eq("", tc.detect_browser_sanitizer_bin(
        ambiguous_bundle_root, "asan"
    ), "browser artifact detection rejects equally shallow foreground bundles")
finally:
    tc._binary_uses_sanitizer = _saved_uses

# A configured value detection *would* replace is still kept: it may have come
# from an operator or from bin/suggest-runner validating a launch, and either
# is stronger evidence than the first-match heuristic. Regression: refresh
# adopted any detected value, so every rerun reverted a corrected binary.
curated_root = TEST_TMPDIR / "refresh-curated"
(curated_root / "build-asan").mkdir(parents=True)
(curated_root / "build-asan" / "aaa.a").write_bytes(b"!<arch>\n")
(curated_root / "build-asan" / "zzz.a").write_bytes(b"!<arch>\n")
curated_toml = curated_root / "target.toml"
curated_toml.write_text(
    'build_system  = "cmake"\n'
    'asan_lib      = "build-asan/zzz.a"\n',
    encoding="utf-8",
)
assert_eq("build-asan/aaa.a",
          tc.detect_sanitizer_build_artifacts(curated_root, "asan")[1],
          "detect_sanitizer_build_artifacts: would pick the other archive")
assert_eq(False, tc.refresh_detected_build_fields(curated_root, curated_toml),
          "refresh_detected_build_fields: reports no change over a curated value")
assert_in('asan_lib      = "build-asan/zzz.a"', curated_toml.read_text(encoding="utf-8"),
          "refresh_detected_build_fields: keeps a curated value detection disagrees with")

# The stale-path repair the adopt policy existed for still works: once the
# configured path no longer resolves, detection wins.
curated_toml.write_text(
    'build_system  = "cmake"\n'
    'asan_lib      = "build-asan/gone.a"\n',
    encoding="utf-8",
)
assert_eq(True, tc.refresh_detected_build_fields(curated_root, curated_toml),
          "refresh_detected_build_fields: still replaces a path that no longer exists")
assert_in('asan_lib      = "build-asan/aaa.a"', curated_toml.read_text(encoding="utf-8"),
          "refresh_detected_build_fields: adopts detection for a stale path")

# An existing path is not enough for a binary: it must be an instrumented
# executable in the build tree for the sanitizer its field names. Otherwise a
# typo such as asan_bin=build-ubsan/tool silently defeats ASan and corrupts
# every downstream run/reproduction metric.
wrong_san_root = TEST_TMPDIR / "refresh-wrong-sanitizer"
(wrong_san_root / "build-asan").mkdir(parents=True)
(wrong_san_root / "build-ubsan").mkdir()
_right_asan = wrong_san_root / "build-asan" / "right"
_wrong_ubsan = wrong_san_root / "build-ubsan" / "wrong"
for _p in (_right_asan, _wrong_ubsan):
    _p.write_bytes(b"\x7fELF"); os.chmod(_p, 0o755)
wrong_san_toml = wrong_san_root / "target.toml"
wrong_san_toml.write_text(
    'build_system = "cmake"\n'
    'asan_bin = "build-ubsan/wrong"\n',
    encoding="utf-8",
)
_saved_uses = tc._binary_uses_sanitizer
tc._binary_uses_sanitizer = (
    lambda path, sanitizer="asan":
        sanitizer == "asan" and Path(path) == _right_asan
)
try:
    assert_eq(True, tc.refresh_detected_build_fields(
        wrong_san_root, wrong_san_toml
    ), "refresh_detected_build_fields: repairs a binary from the wrong sanitizer tree")
finally:
    tc._binary_uses_sanitizer = _saved_uses
assert_in('asan_bin      = "build-asan/right"',
          wrong_san_toml.read_text(encoding="utf-8"),
          "refresh_detected_build_fields: restores the instrumented ASan binary")

# With no replacement available, an uninstrumented configured binary is
# unset rather than silently surviving as the ASan runner.
wrong_san_toml.write_text(
    'build_system = "cmake"\n'
    'asan_bin = "build-ubsan/wrong"\n',
    encoding="utf-8",
)
_right_asan.unlink()
assert_eq(True, tc.refresh_detected_build_fields(
    wrong_san_root, wrong_san_toml
), "refresh_detected_build_fields: scrubs an uninstrumented binary")
assert_in('# asan_bin = "build-asan/FILL_ME"',
          wrong_san_toml.read_text(encoding="utf-8"),
          "refresh_detected_build_fields: does not preserve a wrong sanitizer")

# The same sanitizer-ownership rule for libraries, without punishing an
# archive the build never emits: a vendored or prebuilt instrumented library
# is operator provenance and detection has nothing better to offer, while one
# belonging to another sanitizer is the same mismatch rejected above.
vendor_root = TEST_TMPDIR / "refresh-vendored-lib"
(vendor_root / "build-asan").mkdir(parents=True)
(vendor_root / "build-ubsan").mkdir()
(vendor_root / "vendor").mkdir()
(vendor_root / "vendor" / "libfoo-asan.a").write_bytes(b"!<arch>\n")
(vendor_root / "build-ubsan" / "libwrong.a").write_bytes(b"!<arch>\n")
vendor_toml = vendor_root / "target.toml"
vendor_toml.write_text(
    'build_system  = "cmake"\n'
    'asan_lib      = "vendor/libfoo-asan.a"\n',
    encoding="utf-8",
)
assert_eq(False, tc.refresh_detected_build_fields(vendor_root, vendor_toml),
          "refresh_detected_build_fields: reports no change over a vendored asan_lib")
assert_in('asan_lib      = "vendor/libfoo-asan.a"',
          vendor_toml.read_text(encoding="utf-8"),
          "refresh_detected_build_fields: keeps a library the build does not emit")
vendor_toml.write_text(
    'build_system  = "cmake"\n'
    'asan_lib      = "build-ubsan/libwrong.a"\n',
    encoding="utf-8",
)
assert_eq(True, tc.refresh_detected_build_fields(vendor_root, vendor_toml),
          "refresh_detected_build_fields: scrubs a library from another sanitizer")
assert_in('# asan_lib = "build-asan/FILL_ME.a"',
          vendor_toml.read_text(encoding="utf-8"),
          "refresh_detected_build_fields: unsets the mismatched library")


# ─── 10e-bis. set_sanitizer_bin retargets one field ─────────────────
#
# bin/suggest-runner writes the program whose launch it validated. It must
# move that one assignment and nothing else — the file it edits carries the
# LLM-curated [threat_model]/[s6_peers] sections.
setbin_text = (
    'target        = "widget"\n'
    'asan_bin      = "build-asan/runner"\n'
    '# ubsan_bin = "build-ubsan/FILL_ME"\n'
    '\n[threat_model]\nattacker_controls = ["bytes"]\n'
)
setbin_new = tc.set_sanitizer_bin(setbin_text, "asan", "build-asan/wtool")
assert_in('asan_bin      = "build-asan/wtool"', setbin_new,
          "set_sanitizer_bin: retargets the active assignment")
assert_in('attacker_controls = ["bytes"]', setbin_new,
          "set_sanitizer_bin: leaves curated sections intact")
assert_eq(setbin_text, tc.set_sanitizer_bin(setbin_text, "ubsan", "build-ubsan/x"),
          "set_sanitizer_bin: never uncomments an unset field")
_setbin_cfg = tc.Config()
tc.load_toml_into(_setbin_cfg, write("setbin.toml", setbin_new))
assert_eq("build-asan/wtool", _setbin_cfg.asan_bin,
          "set_sanitizer_bin: result round-trips through load_toml_into")
setbin_ubsan = tc.set_sanitizer_bin(
    '[sanitizer]\nenabled = ["ubsan"]\nubsan_bin = "build-ubsan/old"\n',
    "ubsan", "build-ubsan/new",
)
_setbin_ubsan_cfg = tc.Config()
tc.load_toml_into(_setbin_ubsan_cfg, write("setbin-ubsan.toml", setbin_ubsan))
assert_eq("build-ubsan/new", _setbin_ubsan_cfg.ubsan_bin,
          "set_sanitizer_bin: retargets a non-ASan field in [sanitizer]")


# ─── 10f. _detect_cli_bin prunes aux dirs and filters before the cap ──
#
# Regression: the nm-probe cap was applied before the aux filter, so a
# build with a large CMakeFiles/ tree (curl: src/curl sits after dozens of
# probe binaries) exhausted the budget on pruned entries and never reached
# the real tool. Filtering to candidates first fixes it. Lay down 70
# executable CMakeFiles probes (> the cap), a test-dir helper, and the real
# tool at the root; with every executable treated as instrumented, only the
# real tool may be returned.
cli_root = TEST_TMPDIR / "cli-detect"
(cli_root / "build-asan" / "CMakeFiles" / "3.30").mkdir(parents=True)
for _i in range(70):
    _p = cli_root / "build-asan" / "CMakeFiles" / "3.30" / f"probe{_i:02d}.bin"
    _p.write_bytes(b"\x7fELF")
    os.chmod(_p, 0o755)
(cli_root / "build-asan" / "tests").mkdir(parents=True)
_th = cli_root / "build-asan" / "tests" / "aaa_test_runner"
_th.write_bytes(b"\x7fELF"); os.chmod(_th, 0o755)
_tool = cli_root / "build-asan" / "mytool"
_tool.write_bytes(b"\x7fELF"); os.chmod(_tool, 0o755)
_saved_uses = tc._binary_uses_sanitizer
tc._binary_uses_sanitizer = lambda p, s="asan": True  # treat every exe as instrumented
try:
    _got = tc._detect_cli_bin(cli_root / "build-asan", cli_root, "cmake", "asan")
finally:
    tc._binary_uses_sanitizer = _saved_uses
assert_eq("build-asan/mytool", _got,
          "_detect_cli_bin: skips CMakeFiles probes + tests/ helpers and finds "
          "the real tool past the probe cap")


# ─── 10g. cli_candidates offers the whole selectable set ────────────
#
# _detect_cli_bin picks the head of this list; bin/suggest-runner offers all
# of it to the model, because which installed program reads attacker-supplied
# input is a semantic choice the build manifests do not record. A build tree
# holds the project's tools next to its test drivers, so when the manifests
# name the tools the free scan must not dilute them back in.
cand_root = TEST_TMPDIR / "cli-candidates"
(cand_root / "build-asan").mkdir(parents=True)
for _name in ("aaa_test_driver", "wcat", "wtool"):
    _p = cand_root / "build-asan" / _name
    _p.write_bytes(b"\x7fELF"); os.chmod(_p, 0o755)
(cand_root / "CMakeLists.txt").write_text(
    "add_executable(wtool tool.c)\n"
    "add_executable(wcat cat.c)\n"
    "add_executable(aaa_test_driver t.c)\n"
    "install(TARGETS wtool wcat RUNTIME DESTINATION bin)\n",
    encoding="utf-8")
_saved_uses = tc._binary_uses_sanitizer
tc._binary_uses_sanitizer = lambda p, s="asan": True
try:
    _cands = tc.cli_candidates(cand_root, "asan", 8)
    _capped = tc.cli_candidates(cand_root, "asan", 1)
    (cand_root / "CMakeLists.txt").write_text(
        "add_executable(absent nowhere.c)\n", encoding="utf-8")
    _scanned = tc.cli_candidates(cand_root, "asan", 8)
finally:
    tc._binary_uses_sanitizer = _saved_uses
assert_eq(["build-asan/wtool", "build-asan/wcat"], _cands,
          "cli_candidates: returns the installed programs, not the test driver")
assert_eq(["build-asan/wtool"], _capped,
          "cli_candidates: honours the limit")
assert_eq(["build-asan/aaa_test_driver", "build-asan/wcat", "build-asan/wtool"],
          _scanned,
          "cli_candidates: falls back to the free scan when no manifest name matches")

# Generated CMake install metadata resolves target types and computed names.
# A library target that installs no executable must not fall back to selecting
# a root-level test program as its generic byte-input runner.
cmake_api_root = TEST_TMPDIR / "cmake-api-artifacts"
(cmake_api_root / "build-asan").mkdir(parents=True)
(cmake_api_root / "CMakeLists.txt").write_text(
    "cmake_minimum_required(VERSION 3.16)\n"
    "add_executable(c-test test.c)\n",
    encoding="utf-8",
)
_api_lib = cmake_api_root / "build-asan" / "libcmakeapiartifacts.a"
_api_lib.write_bytes(b"!<arch>\n")
_api_test = cmake_api_root / "build-asan" / "c-test"
_api_test.write_bytes(b"\x7fELF"); os.chmod(_api_test, 0o755)
(cmake_api_root / "build-asan" / "cmake_install.cmake").write_text(
    'file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib" TYPE STATIC_LIBRARY '
    f'FILES "{_api_lib}")\n', encoding="utf-8",
)
_saved_uses = tc._binary_uses_sanitizer
tc._binary_uses_sanitizer = lambda p, s="asan": True
try:
    assert_eq([], tc.cli_candidates(cmake_api_root, "asan", 8),
              "cli_candidates: complete CMake install plan keeps an API target library-only")
    _api_toml = cmake_api_root / "target.toml"
    tc.seed_toml(cmake_api_root, _api_toml)
    _api_seed = tc.parse_toml(_api_toml)
    assert_eq(None, _api_seed.get("asan_bin"),
              "seed_toml: API-only CMake build does not persist its test driver")
    assert_eq("build-asan/libcmakeapiartifacts.a", _api_seed.get("asan_lib"),
              "seed_toml: API-only CMake build persists its core archive")
    # CMake writes this script even for a project that declares no install()
    # rule, and that publishes nothing rather than declaring a library-only
    # product. Reading it as one deleted the sole route of an uninstalled CLI.
    (cmake_api_root / "build-asan" / "cmake_install.cmake").write_text(
        "if(CMAKE_INSTALL_COMPONENT)\nendif()\n", encoding="utf-8",
    )
    assert_eq(["build-asan/c-test"], tc.cli_candidates(cmake_api_root, "asan", 8),
              "cli_candidates: a project with no install() rule keeps its route")
    _api_cli = cmake_api_root / "build-asan" / "wtool"
    _api_cli.write_bytes(b"\x7fELF"); os.chmod(_api_cli, 0o755)
    (cmake_api_root / "build-asan" / "cmake_install.cmake").write_text(
        'file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/bin" TYPE EXECUTABLE '
        f'FILES "{_api_cli}")\n', encoding="utf-8",
    )
    assert_eq(["build-asan/wtool"], tc.cli_candidates(cmake_api_root, "asan", 8),
              "cli_candidates: CMake install plan keeps its product executable")
finally:
    tc._binary_uses_sanitizer = _saved_uses

# CMake writes OPTIONAL/PERMISSIONS/RENAME between TYPE and FILES, and a
# FetchContent dependency ships its own install plan under _deps/. Reading
# either wrong drops the product CLI or publishes a dependency's tool as it.
cmake_shapes_root = TEST_TMPDIR / "cmake-install-shapes"
_shapes_build = cmake_shapes_root / "build-asan"
(_shapes_build / "_deps" / "dep-build").mkdir(parents=True)
(cmake_shapes_root / "CMakeLists.txt").write_text(
    "cmake_minimum_required(VERSION 3.16)\n", encoding="utf-8",
)
(_shapes_build / "libcmakeinstallshapes.a").write_bytes(b"!<arch>\n")
_shapes_cli = _shapes_build / "wtool"
_shapes_cli.write_bytes(b"\x7fELF"); os.chmod(_shapes_cli, 0o755)
_shapes_dep = _shapes_build / "_deps" / "dep-build" / "depgen"
_shapes_dep.write_bytes(b"\x7fELF"); os.chmod(_shapes_dep, 0o755)
# Both rules live in the reachable top-level script: `_find_under` never
# descends into _deps, so a dependency path can only arrive as file content.
(_shapes_build / "cmake_install.cmake").write_text(
    'file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/bin" TYPE EXECUTABLE '
    f'FILES "{_shapes_dep}")\n'
    'file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/bin" TYPE EXECUTABLE '
    'OPTIONAL PERMISSIONS OWNER_READ OWNER_EXECUTE RENAME "wtool" '
    f'FILES "{_shapes_cli}")\n', encoding="utf-8",
)
_saved_uses = tc._binary_uses_sanitizer
tc._binary_uses_sanitizer = lambda p, s="asan": True
try:
    assert_eq(["build-asan/wtool"],
              tc.cli_candidates(cmake_shapes_root, "asan", 8),
              "cli_candidates: install keywords between TYPE and FILES still name the product, "
              "and a dependency's installed tool is not the target's CLI")
finally:
    tc._binary_uses_sanitizer = _saved_uses

# A same-named product archive beats a sibling wrapper archive at the same
# depth. The CMake project identity, not an arbitrary operator slug, supplies
# the name; punctuation is intentionally insignificant.
named_lib_root = TEST_TMPDIR / "audit-alias"
(named_lib_root / "build-asan").mkdir(parents=True)
(named_lib_root / "build-asan" / "CMakeCache.txt").write_text(
    "CMAKE_PROJECT_NAME:STATIC=named-lib\n", encoding="utf-8",
)
(named_lib_root / "build-asan" / "libaudit-alias.a").write_bytes(b"!<arch>\n")
(named_lib_root / "build-asan" / "libnamed-lib-c.a").write_bytes(b"!<arch>\n")
(named_lib_root / "build-asan" / "libnamedlib.a").write_bytes(b"!<arch>\n")
assert_eq(
    "build-asan/libnamedlib.a",
    tc.detect_sanitizer_build_artifacts(named_lib_root, "asan")[1],
    "detect_sanitizer_build_artifacts: project-named core archive beats slug and wrapper siblings",
)
# A half-written cache carries the key with no value. That names nothing, so
# the directory name must still decide; the archive it names sorts last here,
# so an empty override would be visible.
blank_cache_root = TEST_TMPDIR / "wtool-core"
(blank_cache_root / "build-asan").mkdir(parents=True)
(blank_cache_root / "build-asan" / "CMakeCache.txt").write_text(
    "CMAKE_PROJECT_NAME:STATIC=\n", encoding="utf-8",
)
(blank_cache_root / "build-asan" / "libaaa.a").write_bytes(b"!<arch>\n")
(blank_cache_root / "build-asan" / "libwtoolcore.a").write_bytes(b"!<arch>\n")
assert_eq(
    "build-asan/libwtoolcore.a",
    tc.detect_sanitizer_build_artifacts(blank_cache_root, "asan")[1],
    "detect_sanitizer_build_artifacts: a value-less cache key keeps the directory name",
)


# ─── 11. Fallback parser works without tomllib ─────────────────────

saved_tomllib = tc.tomllib
tc.tomllib = None
try:
    fallback_path = write(
        "fallback.toml",
        'slug = "fallback"\n'
        'upstream_url = "https://example.test/repo#main"\n'
        'includes = ["include,with,commas", "build#asan/include"] # trailing comment\n'
        '[threat_model]\n'
        'attacker_controls = ["bytes", "timing"]\n',
    )
    parsed = tc.parse_toml(fallback_path)
    assert_eq("https://example.test/repo#main", parsed.get("upstream_url"),
              "fallback parser preserves # inside quoted strings")
    assert_eq(["include,with,commas", "build#asan/include"], parsed.get("includes"),
              "fallback parser splits arrays outside quotes only")
    cfg = tc.Config()
    tc.load_toml_into(cfg, fallback_path)
    assert_eq("bytes,timing", cfg.attacker_controls_csv(),
              "fallback parser round-trips through load_toml_into")
finally:
    tc.tomllib = saved_tomllib


# ─── 12. declared_cli_names derives CLI names from build manifests ──
# Replaces the old hardcoded _GENERIC_BIN_NAMES table: candidate binary
# names must come from the target's own build files, never a per-project
# list baked into the shared harness.

DCN_DIR = TEST_TMPDIR / "declared-cli"
DCN_DIR.mkdir()

# autotools: bin_PROGRAMS is installed, check_PROGRAMS is not.
am_root = DCN_DIR / "autotools-proj"
(am_root / "src").mkdir(parents=True)
(am_root / "configure.ac").write_text("AC_INIT([proj],[1])\n", encoding="utf-8")
(am_root / "src" / "Makefile.am").write_text(
    "bin_PROGRAMS = mytool myhelper$(EXEEXT)\n"
    "check_PROGRAMS = unittest\n"
    "noinst_PROGRAMS = scratch\n",
    encoding="utf-8")
dcn = tc.declared_cli_names(am_root, "autotools")
assert_eq(["mytool", "myhelper"], dcn,
          "declared_cli_names: autotools reads bin_PROGRAMS, drops $(EXEEXT)")
if "unittest" not in dcn and "scratch" not in dcn:
    passed("declared_cli_names: autotools excludes check_/noinst_PROGRAMS")
else:
    failed("declared_cli_names: autotools excludes check_/noinst_PROGRAMS", str(dcn))

# autotools: backslash line-continuation in bin_PROGRAMS.
am_cont = DCN_DIR / "autotools-cont"
am_cont.mkdir()
(am_cont / "configure.ac").write_text("AC_INIT([c],[1])\n", encoding="utf-8")
(am_cont / "Makefile.am").write_text(
    "bin_PROGRAMS = first \\\n\tsecond \\\n\tthird\n", encoding="utf-8")
assert_eq(["first", "second", "third"], tc.declared_cli_names(am_cont, "autotools"),
          "declared_cli_names: autotools joins backslash continuations")

# cmake: only install(TARGETS ...) executables, not test-only ones.
cm_root = DCN_DIR / "cmake-proj"
cm_root.mkdir()
(cm_root / "CMakeLists.txt").write_text(
    "add_executable(cli main.c)\n"
    "add_executable(runtests t.c)\n"
    "add_library(mylib lib.c)\n"
    "install(TARGETS cli mylib RUNTIME DESTINATION bin)\n",
    encoding="utf-8")
dcn_cm = tc.declared_cli_names(cm_root, "cmake")
assert_eq(["cli"], dcn_cm,
          "declared_cli_names: cmake keeps installed executable, drops lib + test exe")

# cmake: an ALIAS or IMPORTED declaration names a reference, not a binary the
# build emits. Regression: the name was truncated at `::`, so the phantom
# collided with the same-named library in install(TARGETS ...) — a non-empty
# result that suppressed the fallback and hid every real program.
cm_alias = DCN_DIR / "cmake-alias"
cm_alias.mkdir()
(cm_alias / "CMakeLists.txt").write_text(
    "add_library(Widget widget.c)\n"
    "install(TARGETS Widget EXPORT Widget ARCHIVE DESTINATION lib)\n"
    "add_executable(wtool tool.c)\n"
    "add_executable(wcat cat.c)\n"
    "add_executable(prebuilt IMPORTED)\n"
    "foreach(PROGRAM ${PROGRAMS})\n"
    "    add_executable(Widget::${PROGRAM} ALIAS ${PROGRAM})\n"
    "    install(TARGETS ${PROGRAM} EXPORT Widget RUNTIME DESTINATION bin)\n"
    "endforeach()\n",
    encoding="utf-8")
assert_eq(["wcat", "wtool"], tc.declared_cli_names(cm_alias, "cmake"),
          "declared_cli_names: cmake drops ALIAS/IMPORTED declarations")

# cmake: no install(TARGETS) → fall back to declared executables.
cm_noinst = DCN_DIR / "cmake-noinstall"
cm_noinst.mkdir()
(cm_noinst / "CMakeLists.txt").write_text(
    "add_executable(alpha a.c)\nadd_executable(beta b.c)\n", encoding="utf-8")
assert_eq(["alpha", "beta"], tc.declared_cli_names(cm_noinst, "cmake"),
          "declared_cli_names: cmake falls back to all declared executables")

# meson: executable() first argument.
ms_root = DCN_DIR / "meson-proj"
ms_root.mkdir()
(ms_root / "meson.build").write_text(
    "project('p', 'c')\nexecutable('mcli', 'm.c', install: true)\n",
    encoding="utf-8")
assert_eq(["mcli"], tc.declared_cli_names(ms_root, "meson"),
          "declared_cli_names: meson reads executable() name")

# A computed program name is a hole in the extraction, and the caller has to be
# told: a project that names one target through a variable had every executable
# it ships beside that one silently excluded from consideration.
cm_var = DCN_DIR / "cmake-computed-name"
cm_var.mkdir()
(cm_var / "CMakeLists.txt").write_text(
    "add_executable(visible v.c)\n"
    'set(TOOL_NAME hidden)\n'
    'add_executable("${TOOL_NAME}" h.c)\n',
    encoding="utf-8")
names, complete = tc.declared_cli_extraction(cm_var, "cmake")
assert_eq(["visible"], names,
          "declared_cli_extraction: cmake still reads the literal name")
assert_eq(False, complete,
          "declared_cli_extraction: cmake reports an unread computed name")
assert_eq(["visible"], tc.declared_cli_names(cm_var, "cmake"),
          "declared_cli_names: the list-only view is unchanged")

# The same hole one character further along: a name that *starts* literal but
# is computed after. Reading the prefix invents a target no build produced and
# stops the site being counted as one the extractor could not read.
cm_partial = DCN_DIR / "cmake-half-computed-name"
cm_partial.mkdir()
(cm_partial / "CMakeLists.txt").write_text(
    "add_executable(tool_${ARCH} source.c)\nadd_executable(helper helper.c)\n",
    encoding="utf-8")
names, complete = tc.declared_cli_extraction(cm_partial, "cmake")
assert_eq(["helper"], names,
          "declared_cli_extraction: cmake does not invent a name from a prefix")
assert_eq(False, complete,
          "declared_cli_extraction: cmake reports a half-computed name unread")

ms_partial = DCN_DIR / "meson-half-computed-name"
ms_partial.mkdir()
(ms_partial / "meson.build").write_text(
    "project('p', 'c')\nexecutable('tool_' + suffix, 's.c')\n"
    "executable('helper', 'h.c')\n", encoding="utf-8")
names, complete = tc.declared_cli_extraction(ms_partial, "meson")
assert_eq(["helper"], names,
          "declared_cli_extraction: meson does not invent a name from a prefix")
assert_eq(False, complete,
          "declared_cli_extraction: meson reports a half-computed name unread")

# A quoted literal is still a literal, and a commented-out declaration is not
# a declaration. Treating either as unread widened the candidate scan for
# nothing.
cm_quoted = DCN_DIR / "cmake-quoted-literal"
cm_quoted.mkdir()
(cm_quoted / "CMakeLists.txt").write_text(
    'add_executable("tool" source.c)\n', encoding="utf-8")
assert_eq((["tool"], True), tc.declared_cli_extraction(cm_quoted, "cmake"),
          "declared_cli_extraction: cmake reads a quoted literal name")

cm_comment = DCN_DIR / "cmake-commented-out"
cm_comment.mkdir()
(cm_comment / "CMakeLists.txt").write_text(
    "# add_executable(${OLD_TOOL} old.c)\nadd_executable(real real.c)\n",
    encoding="utf-8")
assert_eq((["real"], True), tc.declared_cli_extraction(cm_comment, "cmake"),
          "declared_cli_extraction: a commented-out cmake declaration is none")

ms_comment = DCN_DIR / "meson-commented-out"
ms_comment.mkdir()
(ms_comment / "meson.build").write_text(
    "project('p', 'c')\n# executable(old_name, 'old.c')\n"
    "executable('real', 'real.c')\n", encoding="utf-8")
assert_eq((["real"], True), tc.declared_cli_extraction(ms_comment, "meson"),
          "declared_cli_extraction: a commented-out meson declaration is none")

# A `#` inside a quoted name is not a comment.
cm_hash = DCN_DIR / "cmake-hash-in-string"
cm_hash.mkdir()
(cm_hash / "CMakeLists.txt").write_text(
    'add_executable(real real.c)\nset(X "a # b")\n', encoding="utf-8")
assert_eq((["real"], True), tc.declared_cli_extraction(cm_hash, "cmake"),
          "declared_cli_extraction: a quoted # does not start a comment")

ms_var = DCN_DIR / "meson-computed-name"
ms_var.mkdir()
(ms_var / "meson.build").write_text(
    "project('p', 'c')\n"
    "executable('mcli', 'm.c')\n"
    "executable(tool_name, 't.c')\n",
    encoding="utf-8")
assert_eq(False, tc.declared_cli_extraction(ms_var, "meson")[1],
          "declared_cli_extraction: meson reports an unread computed name")

am_var = DCN_DIR / "autotools-computed-name"
(am_var / "src").mkdir(parents=True)
(am_var / "configure.ac").write_text("AC_INIT([proj],[1])\n", encoding="utf-8")
(am_var / "src" / "Makefile.am").write_text(
    "bin_PROGRAMS = mytool $(EXTRA_TOOLS)\n", encoding="utf-8")
assert_eq(False, tc.declared_cli_extraction(am_var, "autotools")[1],
          "declared_cli_extraction: autotools reports an unread computed name")

# A manifest read in full stays authoritative — this is what keeps a project's
# own tool from being averaged in with the test drivers beside it.
assert_eq(True, tc.declared_cli_extraction(cm_noinst, "cmake")[1],
          "declared_cli_extraction: a fully literal manifest reads complete")
assert_eq(True, tc.declared_cli_extraction(am_root, "autotools")[1],
          "declared_cli_extraction: autotools literal PROGRAMS read complete")

# Unknown / language-ecosystem build systems yield nothing (free scan handles them).
assert_eq([], tc.declared_cli_names(am_root, "cargo"),
          "declared_cli_names: non-native build system returns []")
assert_eq([], tc.declared_cli_names(DCN_DIR / "does-not-exist", "cmake"),
          "declared_cli_names: missing tree returns []")


# ─── TOML escaping helpers (toml_basic_string / toml_comment_lines) ─
# These back the suggest-peers / suggest-threat-model writers and the
# seed scalars in seed_target_toml. They are the only thing standing
# between an LLM-supplied string and a corrupted target.toml, so they
# get round-trip + edge-case coverage here.

# Plain ASCII values round-trip through tomllib/tomli.
try:
    import tomllib  # noqa: E402 — local import keeps this section self-contained
except ModuleNotFoundError:  # pragma: no cover - Python < 3.11
    import tomli as tomllib  # type: ignore[no-redef]

def _loads_basic(value: str):
    rendered = tc.toml_basic_string(value)
    parsed = tomllib.loads(f"k = {rendered}")
    return parsed["k"]

assert_eq("hello",            _loads_basic("hello"),            "toml_basic_string: plain ASCII round-trips")
assert_eq('say "hi"',         _loads_basic('say "hi"'),         "toml_basic_string: embedded double-quote round-trips")
assert_eq("path\\to\\thing",  _loads_basic("path\\to\\thing"),  "toml_basic_string: backslash round-trips")
assert_eq("a\nb",             _loads_basic("a\nb"),             "toml_basic_string: newline escaped to \\n")
assert_eq("a\tb",             _loads_basic("a\tb"),             "toml_basic_string: tab escaped to \\t")
assert_eq("a\rb",             _loads_basic("a\rb"),             "toml_basic_string: CR escaped to \\r")
assert_eq("\x01\x1fend",      _loads_basic("\x01\x1fend"),      "toml_basic_string: control bytes go through \\uXXXX")
assert_eq("",                 _loads_basic(""),                 "toml_basic_string: empty string round-trips")

# Non-string scalars stringify rather than raise — keeps the writers from
# crashing on a stray int/None at the wrong layer.
assert_eq("42", _loads_basic(42),         "toml_basic_string: int stringified")  # type: ignore[arg-type]
assert_eq("",   _loads_basic(None),       "toml_basic_string: None stringified to empty")  # type: ignore[arg-type]

# Always wrapped in quotes — callers concatenate without adding any of their own.
assert_in('"',  tc.toml_basic_string("x"), "toml_basic_string: always quoted (open)")
assert_eq(2,    tc.toml_basic_string("x").count('"'), "toml_basic_string: always quoted (pair)")

# toml_comment_lines: multi-line input cannot escape the comment context.
single = tc.toml_comment_lines("Reasoning: parses byte input")
assert_eq("# Reasoning: parses byte input", single,
          "toml_comment_lines: single line gets one leading '# '")
multi = tc.toml_comment_lines("first\n[evil_section]\nkey = \"boom\"")
for line in multi.splitlines():
    if not line.startswith("# "):
        failed("toml_comment_lines: every line starts with '# '",
               f"offending line: {line!r}")
        break
else:
    passed("toml_comment_lines: every line of multi-line text is commented")
# Confirm the result, embedded in a TOML doc, parses with no leaked section.
doc = multi + "\n[real]\nk = 1\n"
parsed = tomllib.loads(doc)
assert_eq({"k": 1}, parsed.get("real"),
          "toml_comment_lines: fake [evil_section] is comment-only")
if "evil_section" in parsed:
    failed("toml_comment_lines: evil_section leaked into TOML root")
else:
    passed("toml_comment_lines: evil_section did not leak into TOML root")

# Empty / None inputs degrade to a bare '#' (preserves layout).
assert_eq("#", tc.toml_comment_lines(""),   "toml_comment_lines: empty string → bare '#'")
assert_eq("#", tc.toml_comment_lines(None), "toml_comment_lines: None → bare '#'")  # type: ignore[arg-type]


# ─── seed_target_toml escapes scalar header fields ──────────────────
# A target slug that contains a TOML-significant character must be
# escaped, not silently broken. Slug validation upstream usually rejects
# these, but the seed writer must also be safe — defence in depth.

import io as _io  # noqa: E402

seed_root = TEST_TMPDIR / "evil-slug-target"
seed_root.mkdir()
(seed_root / "CMakeLists.txt").write_text(
    "cmake_minimum_required(VERSION 3.16)\nproject(p)\nadd_executable(p p.c)\n",
    encoding="utf-8")
# Simulate a generator that received an awkward upstream URL with quote +
# backslash. This is exactly the shape an LLM-suggested override might
# wedge into the seed path on a custom target.
written = TEST_TMPDIR / "evil_seed.toml"
buf = _io.StringIO()
# seed_toml takes a target root and the destination path. We patch
# the upstream URL through the public seed helper.
tc.seed_toml(seed_root, written,
             upstream_url='https://ex.com/q?a="b"&c=\\d')
parsed = tomllib.loads(written.read_text(encoding="utf-8"))
assert_eq('https://ex.com/q?a="b"&c=\\d', parsed["upstream_url"],
          "seed_target_toml: upstream_url with quote+backslash round-trips")


# ─── load_toml_into strips target_root prefix from path fields ───────
# auto-repair-target-toml can accept
# absolute audit-machine paths in asan_lib / asan_bin / link_libs.
# Downstream consumers (bin/export-repro's _strip_sanitizer_build_prefix,
# the build/lib resolution code) use target_root-relative form. The loader
# normalizes these paths at the boundary.
strip_dir = TEST_TMPDIR / "strip_root"
strip_dir.mkdir(parents=True, exist_ok=True)
strip_root = strip_dir / "targets" / "sampleproj"
strip_root.mkdir(parents=True, exist_ok=True)
strip_toml = strip_dir / "absolute-paths.toml"
strip_toml.write_text(
    f'target = "sampleproj"\n'
    f'asan_bin = "{strip_root}/build-asan/bin/apptool"\n'
    f'asan_lib = "{strip_root}/build-asan/lib/libsample-helper.a"\n'
    f'link_libs = ["{strip_root}/build-asan/lib/libsample.a", "-lm", "/elsewhere/lib.a"]\n',
    encoding="utf-8")
cfg_strip = tc.Config()
cfg_strip.target_root = str(strip_root)
tc.load_toml_into(cfg_strip, strip_toml)
assert_eq("build-asan/bin/apptool", cfg_strip.asan_bin,
          "load_toml_into: absolute asan_bin under target_root → relative")
assert_eq("build-asan/lib/libsample-helper.a", cfg_strip.asan_lib,
          "load_toml_into: absolute asan_lib under target_root → relative")
assert_eq(
    ["build-asan/lib/libsample.a", "-lm", "/elsewhere/lib.a"],
    cfg_strip.link_libs,
    "load_toml_into: link_libs strips under-root, keeps flags + foreign abs paths"
)

# Same input but without a target_root in cfg — nothing to strip against,
# so values pass through unchanged.
cfg_no_root = tc.Config()
tc.load_toml_into(cfg_no_root, strip_toml)
assert_eq(f"{strip_root}/build-asan/lib/libsample-helper.a", cfg_no_root.asan_lib,
          "load_toml_into: no target_root → asan_lib pass-through")


# ─── is_unpinned_rev / is_placeholder_url (shared sentinel helpers) ──
# Single source of truth consumed by bin/export-repro + lib/report_enrich
# for report/link text. Keep these in lockstep with those consumers.
for _rev in ("norev", "NoRev", " norev ", "no-vcs", "unknown", "?", "", None):
    assert_eq(True, tc.is_unpinned_rev(_rev),
              f"is_unpinned_rev: {_rev!r} is a sentinel")
for _rev in ("abcdef1234567890", "v1.2.3", "main"):
    assert_eq(False, tc.is_unpinned_rev(_rev),
              f"is_unpinned_rev: {_rev!r} is a usable ref")
# HEAD is the documented exception: usable, not unpinned (it clones and
# resolves to a forge default branch).
assert_eq(False, tc.is_unpinned_rev("HEAD"),
          "is_unpinned_rev: HEAD is usable (documented exception)")
for _url in ("", "FILL_ME", " fill_me ", None):
    assert_eq(True, tc.is_placeholder_url(_url),
              f"is_placeholder_url: {_url!r} is a placeholder")
assert_eq(False, tc.is_placeholder_url("https://github.com/acme/widgets"),
          "is_placeholder_url: a real URL is not a placeholder")


# ─── config_has_live_placeholder (structured re-seed trigger) ───────
# Replaces bin/setup-target's bare `grep FILL_ME`, which re-seeded (and wiped
# operator edits) on every rerun because the seed always leaves commented
# FILL_ME example lines and local-only targets keep upstream_url = "FILL_ME".
def _write_toml(name: str, body: str) -> Path:
    p = TEST_TMPDIR / name
    p.write_text(body, encoding="utf-8")
    return p

# Whether a FILL_ME upstream is resolvable is asked of the tree, not of a
# recorded sentinel: a plain tree has no upstream to detect, a checkout does.
_plain_tree = TEST_TMPDIR / "placeholder-plain"
_plain_tree.mkdir()
_checkout = TEST_TMPDIR / "placeholder-checkout"
_checkout.mkdir()
subprocess.run(["git", "-C", str(_checkout), "init", "-q"], check=True)

# Local-only steady state: upstream FILL_ME on a non-VCS tree → NOT a placeholder.
_local_only = _write_toml("local_only.toml",
    'target = "x"\nupstream_url = "FILL_ME"\n'
    '# ubsan_lib = "build-ubsan/FILL_ME.a"\nlink_libs = ["-lm"]\n')
assert_eq(False, tc.config_has_live_placeholder(_local_only, _plain_tree),
          "config_has_live_placeholder: local-only FILL_ME upstream is steady state")

# Commented example FILL_ME only (fully-configured target) → NOT a placeholder.
_commented = _write_toml("commented.toml",
    'target = "x"\nupstream_url = "https://h/r"\n'
    'asan_bin = "build-asan/x"\n# msan_lib = "build-msan/FILL_ME.a"\n')
assert_eq(False, tc.config_has_live_placeholder(_commented, _checkout),
          "config_has_live_placeholder: commented FILL_ME lines are not placeholders")

# Active FILL_ME in a build field → IS a placeholder needing refresh.
_active = _write_toml("active.toml",
    'target = "x"\nupstream_url = "https://h/r"\n'
    'asan_lib = "build-asan/FILL_ME.a"\n')
assert_eq(True, tc.config_has_live_placeholder(_active, _checkout),
          "config_has_live_placeholder: an active FILL_ME build field needs refresh")

# FILL_ME URL on a real checkout → re-detect it (not local-only).
_url_unfilled = _write_toml("url_unfilled.toml",
    'target = "x"\nupstream_url = "FILL_ME"\n')
assert_eq(True, tc.config_has_live_placeholder(_url_unfilled, _checkout),
          "config_has_live_placeholder: FILL_ME upstream on a checkout still refreshes")


# ─── build_freshness / build_write_stamp ────────────────────────────
#
# bin/audit and bin/benchmark use these to (re)build a stale or missing
# native sanitizer tree lazily, so a checkout that moved since the last
# build is never audited against the wrong binary. The classifier must err
# toward "stale" (a needless rebuild) and never toward "fresh".
import time  # noqa: E402

_bf_root = TEST_TMPDIR / "freshness"
_bf_root.mkdir()
(_bf_root / "main.c").write_text("int main(void){return 0;}\n")

# Non-native (no CMakeLists/configure/meson) → freshness is N/A.
assert_eq("skip", tc.build_freshness(_bf_root, "asan"),
          "build_freshness: non-native target reports skip")

# Native target, no build tree yet → missing.
(_bf_root / "CMakeLists.txt").write_text("cmake_minimum_required(VERSION 3.16)\n")
assert_eq("missing", tc.build_freshness(_bf_root, "asan"),
          "build_freshness: native target with no build-asan reports missing")

# Build dir present but never stamped → stale (built before stamping existed).
(_bf_root / "build-asan").mkdir()
assert_eq("stale", tc.build_freshness(_bf_root, "asan"),
          "build_freshness: build-asan without a stamp reports stale")

# Stamp it → fresh.
assert_eq(True, tc.build_write_stamp(_bf_root, "asan"),
          "build_write_stamp: writes the stamp when build-asan exists")
assert_eq("fresh", tc.build_freshness(_bf_root, "asan"),
          "build_freshness: stamped build with no newer source reports fresh")

# The recipe is build input just like source. A recipe repair must invalidate
# the artifact produced by the old recipe, even though .audit/ is intentionally
# excluded from the broad source signature.
(_bf_root / ".audit").mkdir()
_bf_recipe = _bf_root / ".audit" / "build.sh"
_bf_recipe.write_text("#!/bin/sh\n# first recipe\n")
tc.build_write_stamp(_bf_root, "asan")
assert_eq("fresh", tc.build_freshness(_bf_root, "asan"),
          "build_freshness: stamp includes the current canonical recipe")
_bf_recipe.write_text("#!/bin/sh\n# repaired recipe\n")
assert_eq("stale", tc.build_freshness(_bf_root, "asan"),
          "build_freshness: a changed canonical recipe reports stale")
tc.build_write_stamp(_bf_root, "asan")
_bf_recipe.unlink()
assert_eq("stale", tc.build_freshness(_bf_root, "asan"),
          "build_freshness: deleting the producing recipe reports stale")
_bf_recipe.write_text("#!/bin/sh\n# repaired recipe\n")
tc.build_write_stamp(_bf_root, "asan")

# The prior stamp format had a source signature but no recipe digest. It must
# remain usable across the migration; a later successful build will add line 3.
_bf_stamp = _bf_root / "build-asan" / ".audit-build-stamp"
_bf_stamp.write_text("\n".join(_bf_stamp.read_text().splitlines()[:2]) + "\n")
assert_eq("fresh", tc.build_freshness(_bf_root, "asan"),
          "build_freshness: legacy two-line stamp remains fresh")

# Non-native targets ordinarily skip freshness, but an explicit hand-authored
# sanitizer recipe opts one into the same source/recipe tracking.
_bf_lang = TEST_TMPDIR / "freshness-language"
(_bf_lang / ".audit").mkdir(parents=True)
(_bf_lang / "build-asan").mkdir()
(_bf_lang / "main.rs").write_text("fn main() {}\n")
_bf_lang_recipe = _bf_lang / ".audit" / "build.sh"
_bf_lang_recipe.write_text("#!/bin/sh\n")
assert_eq(True, tc.build_write_stamp(
    _bf_lang, "asan", recipe_path=_bf_lang_recipe
), "build_write_stamp: explicit language recipe is stamped")
assert_eq("fresh", tc.build_freshness(
    _bf_lang, "asan", recipe_path=_bf_lang_recipe
), "build_freshness: explicit language recipe opts into freshness")

# A source edit after the stamp → stale (the core staleness signal).
(_bf_root / "main.c").write_text("int main(void){return 1;}\n")
assert_eq("stale", tc.build_freshness(_bf_root, "asan"),
          "build_freshness: an edited source file reports stale")

# Identity is content, not mtime: a file whose bytes did not change cannot
# stale a build no matter how new it looks. Without this, any command that
# rewrites a timestamp in the tree forces a rebuild, and on a shared checkout
# a rebuild replaces the binary a concurrent run is auditing.
tc.build_write_stamp(_bf_root, "asan")
newer = time.time() + 1
os.utime(_bf_root / "main.c", (newer, newer))
assert_eq("fresh", tc.build_freshness(_bf_root, "asan"),
          "build_freshness: touching a source file without editing it stays fresh")

# A sibling sanitizer build compiled after the asan stamp must NOT read as a
# source edit (only the canonical build-<san> trees are pruned from the walk).
tc.build_write_stamp(_bf_root, "asan")
(_bf_root / "build-ubsan").mkdir()
(_bf_root / "build-ubsan" / "obj.o").write_bytes(b"\0")
assert_eq("fresh", tc.build_freshness(_bf_root, "asan"),
          "build_freshness: a newer sibling build-<san> tree does not mark asan stale")

# A source-support dir whose name merely STARTS WITH "build-" (build-aux/ is
# the canonical autotools example, also build-scripts/, build-tools/) is real
# source: a change under it MUST register as stale. Over-pruning every
# "build-*" dir would hide it and produce a false "fresh" — the one direction
# this check must never take.
tc.build_write_stamp(_bf_root, "asan")
(_bf_root / "build-aux").mkdir()
(_bf_root / "build-aux" / "config.guess").write_text("#!/bin/sh\n")
assert_eq("stale", tc.build_freshness(_bf_root, "asan"),
          "build_freshness: a change under build-aux/ (source-support) reports stale")

# Deletion-only change: removing a source file leaves no remaining file newer
# than the build, so a max-mtime check would falsely report "fresh". The
# source-state signature must catch the vanished path. (Renames are the same
# class — a path disappears and another appears.)
(_bf_root / "doomed.c").write_text("int doomed(void){return 0;}\n")
tc.build_write_stamp(_bf_root, "asan")
assert_eq("fresh", tc.build_freshness(_bf_root, "asan"),
          "build_freshness: re-stamped tree with a known file reports fresh")
(_bf_root / "doomed.c").unlink()
assert_eq("stale", tc.build_freshness(_bf_root, "asan"),
          "build_freshness: deleting a source file (nothing newer) reports stale")

# build_write_stamp is a no-op (False) when the build dir is absent.
assert_eq(False, tc.build_write_stamp(_bf_root, "msan"),
          "build_write_stamp: no-op when build-<san> does not exist")


# ─── build_freshness on a VCS checkout ──────────────────────────────
#
# On a git checkout the VCS decides what counts as source. Anything it ignores
# is build output, and a target that writes into its own tree while running its
# own tests (a rewritten test log) must not stale the build that produced it —
# that false signal is what made concurrent runs rebuild each other's binaries.
_bf_git = TEST_TMPDIR / "freshness-git"
_bf_git.mkdir()


def _git(*args: str) -> None:
    subprocess.run(
        ["git", "-c", "user.email=t@example.invalid", "-c", "user.name=t",
         "-c", "init.defaultBranch=main", "-C", str(_bf_git), *args],
        check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )


(_bf_git / "CMakeLists.txt").write_text("cmake_minimum_required(VERSION 3.16)\n")
(_bf_git / "main.c").write_text("int main(void){return 0;}\n")
(_bf_git / ".gitignore").write_text("/testsuite.log\n")
_git("init", "-q")
_git("add", "-A")
_git("commit", "-qm", "init")
(_bf_git / "build-asan").mkdir()
tc.build_write_stamp(_bf_git, "asan")
assert_eq("fresh", tc.build_freshness(_bf_git, "asan"),
          "build_freshness(git): a stamped clean checkout reports fresh")

# The incident: a test run rewrites an ignored log inside the source tree.
(_bf_git / "testsuite.log").write_text("run 1: ok\n")
assert_eq("fresh", tc.build_freshness(_bf_git, "asan"),
          "build_freshness(git): rewriting an ignored file stays fresh")

# .audit/ is untracked-but-not-ignored in a real target and is rewritten by
# every build, so the prune has to survive the move to a VCS answer or a build
# would stale itself.
(_bf_git / ".audit").mkdir(exist_ok=True)
(_bf_git / ".audit" / "build-materialize-asan.log").write_text("=== build ===\n")
assert_eq("fresh", tc.build_freshness(_bf_git, "asan"),
          "build_freshness(git): .audit/ churn stays fresh")

# Benchmark source identity is narrower than build freshness. An arbitrary
# untracked artifact is not product source merely because Git can see it; no
# filename or extension taxonomy is involved. Staging it makes it tracked and
# therefore part of the source state a benchmark pins.
_tracked_base = tc.vcs_source_signature(_bf_git, include_untracked=False)
(_bf_git / "scratch-artifact").write_text("generated bytes\n")
assert_eq(_tracked_base, tc.vcs_source_signature(_bf_git, include_untracked=False),
          "tracked source signature(git): untracked artifact changes nothing")
assert_eq([], tc.source_changed_paths(_bf_git, include_untracked=False),
          "tracked source paths(git): untracked artifact is omitted")
assert_eq("stale", tc.build_freshness(_bf_git, "asan"),
          "build_freshness(git): untracked input remains conservative")
_git("add", "scratch-artifact")
assert_eq(True, tc.vcs_source_signature(_bf_git, include_untracked=False) != _tracked_base,
          "tracked source signature(git): staged addition changes identity")
assert_eq(["scratch-artifact"],
          tc.source_changed_paths(_bf_git, include_untracked=False),
          "tracked source paths(git): staged addition is reported")
_git("reset", "-q", "HEAD", "scratch-artifact")
(_bf_git / "scratch-artifact").unlink()

# A real edit stales, and reverting it returns to fresh without a rebuild —
# the edit/restore cycle an agent performs while preparing a patch.
(_bf_git / "main.c").write_text("int main(void){return 1;}\n")
assert_eq("stale", tc.build_freshness(_bf_git, "asan"),
          "build_freshness(git): a tracked content edit reports stale")
assert_eq(True, tc.vcs_source_signature(_bf_git, include_untracked=False) != _tracked_base,
          "tracked source signature(git): tracked edit changes identity")
assert_eq(["main.c"], tc.source_changed_paths(_bf_git, include_untracked=False),
          "tracked source paths(git): tracked edit is reported")
(_bf_git / "main.c").write_text("int main(void){return 0;}\n")
assert_eq("fresh", tc.build_freshness(_bf_git, "asan"),
          "build_freshness(git): reverting the edit returns to fresh")

# Untracked-and-not-ignored source is source.
(_bf_git / "extra.c").write_text("void extra(void){}\n")
assert_eq("stale", tc.build_freshness(_bf_git, "asan"),
          "build_freshness(git): a new untracked source file reports stale")
(_bf_git / "extra.c").unlink()

# Deletion and commit-level movement both register.
(_bf_git / "main.c").unlink()
assert_eq("stale", tc.build_freshness(_bf_git, "asan"),
          "build_freshness(git): deleting a tracked file reports stale")
_git("checkout", "--", "main.c")
assert_eq("fresh", tc.build_freshness(_bf_git, "asan"),
          "build_freshness(git): restoring the deleted file returns to fresh")
(_bf_git / "main.c").write_text("int main(void){return 2;}\n")
_git("add", "-A")
_git("commit", "-qm", "second")
assert_eq("stale", tc.build_freshness(_bf_git, "asan"),
          "build_freshness(git): a new commit reports stale")

# Identity is the working tree, not the index. Staging a change alters status
# letters and index oids without altering the bytes a build compiles, and
# rebuilding for that is pure waste — agents stage while preparing patches.
tc.build_write_stamp(_bf_git, "asan")
(_bf_git / "main.c").write_text("int main(void){return 3;}\n")
_unstaged = tc._source_state_signature(_bf_git)
_git("add", "main.c")
assert_eq(_unstaged, tc._source_state_signature(_bf_git),
          "source signature(git): staging the same bytes does not change identity")
_git("reset", "-q", "HEAD", "main.c")
_git("checkout", "--", "main.c")

# A submodule's directory cannot hash to a constant: the parent's status says
# only "something changed", which is the same string for every possible change
# inside it, so distinct dirty contents would have read as unchanged.
_bf_sub = _bf_git / "vendor"
_bf_sub.mkdir()
(_bf_sub / "x.c").write_text("int x(void){return 0;}\n")
_sub_first = tc._content_digest(_bf_sub)
(_bf_sub / "x.c").write_text("int x(void){return 1;}\n")
assert_eq(True, _sub_first.startswith("sub:"),
          "content digest: a submodule directory carries its own signature")
assert_eq(True, _sub_first != tc._content_digest(_bf_sub),
          "content digest: distinct dirty submodule contents differ")

# A VCS that cannot answer must not switch identity scheme. Reporting the
# whole-tree walk instead would change the value without the source changing,
# which reads as drift and could discard a finished cell.
_bf_saved_records = tc._git_status_records
tc._git_status_records = lambda root, **kwargs: None
_bf_unknown = tc._source_state_signature(_bf_git)
_bf_unknown_again = tc._source_state_signature(_bf_git)
_bf_cheap = tc.vcs_source_signature(_bf_git)
_bf_stale_when_unknown = tc.build_freshness(_bf_git, "asan")
tc._git_status_records = _bf_saved_records
assert_eq(tc._VCS_UNAVAILABLE_SIGNATURE, _bf_unknown,
          "source signature(git): an unreadable status reports one constant unknown")
assert_eq(_bf_unknown, _bf_unknown_again,
          "source signature(git): the unknown value is stable across calls")
assert_eq("", _bf_cheap,
          "vcs_source_signature: reports no answer rather than a wrong one")
assert_eq("stale", _bf_stale_when_unknown,
          "build_freshness(git): an unreadable status errs toward stale")

# "Unknown" is an admission, not an identity. Stamping it would make the next
# unknown answer match, so a tree edited while the VCS stayed down would read as
# fresh — the one direction this classifier must never take.
tc._git_status_records = lambda root, **kwargs: None
tc.build_write_stamp(_bf_git, "asan")
_bf_unknown_stamped = tc.build_freshness(_bf_git, "asan")
(_bf_git / "main.c").write_text("int main(void){return 9;}\n")
_bf_edit_while_unknown = tc.build_freshness(_bf_git, "asan")
tc._git_status_records = _bf_saved_records
assert_eq("stale", _bf_unknown_stamped,
          "build_write_stamp: a stamp written while the VCS was down is not fresh")
assert_eq("stale", _bf_edit_while_unknown,
          "build_freshness: a real edit during VCS downtime never reads as fresh")
tc.build_write_stamp(_bf_git, "asan")
assert_eq("fresh", tc.build_freshness(_bf_git, "asan"),
          "build_write_stamp: a stamp written with a real answer is fresh again")

# Tracked-only identity applies recursively. Git can report a submodule dirty
# solely because it contains an unknown artifact; that must not invalidate a
# benchmark, while a tracked edit inside the same submodule must.
_sub_origin = TEST_TMPDIR / "tracked-submodule-origin"
_sub_parent = TEST_TMPDIR / "tracked-submodule-parent"
_sub_origin.mkdir()
_sub_parent.mkdir()


def _repo_git(root: Path, *args: str) -> None:
    subprocess.run(
        ["git", "-c", "user.email=t@example.invalid", "-c", "user.name=t",
         "-c", "init.defaultBranch=main", "-C", str(root), *args],
        check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )


_repo_git(_sub_origin, "init", "-q")
(_sub_origin / "tracked-file").write_text("original\n")
_repo_git(_sub_origin, "add", "-A")
_repo_git(_sub_origin, "commit", "-qm", "init")
_repo_git(_sub_parent, "init", "-q")
_repo_git(
    _sub_parent, "-c", "protocol.file.allow=always", "submodule", "add", "-q",
    str(_sub_origin), "vendor",
)
_repo_git(_sub_parent, "commit", "-qam", "add submodule")
_submodule_base = tc.vcs_source_signature(_sub_parent, include_untracked=False)
(_sub_parent / "vendor" / "scratch-artifact").write_text("generated bytes\n")
assert_eq(_submodule_base,
          tc.vcs_source_signature(_sub_parent, include_untracked=False),
          "tracked source signature(git): untracked submodule artifact changes nothing")
(_sub_parent / "vendor" / "tracked-file").write_text("edited\n")
assert_eq(True,
          tc.vcs_source_signature(_sub_parent, include_untracked=False) != _submodule_base,
          "tracked source signature(git): tracked submodule edit changes identity")

# A checkout that configures submodule content away — common on large git trees
# — must not be able to hide that edit. The policy is named on the command line
# for exactly this reason, so config cannot answer for us.
_submodule_edited = tc.vcs_source_signature(_sub_parent, include_untracked=False)
_repo_git(_sub_parent, "config", "diff.ignoreSubmodules", "dirty")
assert_eq(_submodule_edited,
          tc.vcs_source_signature(_sub_parent, include_untracked=False),
          "tracked source signature(git): diff.ignoreSubmodules cannot hide the edit")
_repo_git(_sub_parent, "config", "submodule.vendor.ignore", "all")
assert_eq(_submodule_edited,
          tc.vcs_source_signature(_sub_parent, include_untracked=False),
          "tracked source signature(git): submodule.<name>.ignore cannot hide it either")

# No HEAD means either an empty repository, where nothing is tracked, or a git
# that could not answer. Tracked-only has no identity to offer in either case:
# a constant would be silent blindness, and a value that moved with the failure
# would discard a finished cell. Say "no cheap answer" instead. The conservative
# policy still sees every file, because all of them are untracked.
_unborn = TEST_TMPDIR / "unborn-head"
_unborn.mkdir()
_repo_git(_unborn, "init", "-q")
(_unborn / "main.c").write_text("int main(void){return 0;}\n")
_unborn_base = tc.vcs_source_signature(_unborn)
assert_eq("", tc.vcs_source_signature(_unborn, include_untracked=False),
          "tracked source signature(git): an unborn HEAD has no cheap answer")
assert_eq([], tc.source_changed_paths(_unborn, include_untracked=False),
          "tracked source paths(git): an unborn HEAD reports nothing")
(_unborn / "main.c").write_text("int main(void){return 1;}\n")
assert_eq(True, tc.vcs_source_signature(_unborn) != _unborn_base,
          "vcs_source_signature(git): an unborn HEAD still tracks content")

# Mercurial is what browser-sized checkouts use, so pinning and drift detection
# have to work there too rather than silently doing nothing.
if shutil.which("hg"):
    _hg_root = TEST_TMPDIR / "freshness-hg"
    _hg_root.mkdir()

    def _hg(*args: str) -> None:
        subprocess.run(
            ["hg", "--cwd", str(_hg_root), *args], check=True,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            env={**os.environ, "HGPLAIN": "1"},
        )

    (_hg_root / "CMakeLists.txt").write_text("cmake_minimum_required(VERSION 3.16)\n")
    (_hg_root / "main.c").write_text("int main(void){return 0;}\n")
    (_hg_root / ".hgignore").write_text("syntax: glob\ntestsuite.log\n")
    _hg("init", ".")
    _hg("add", ".")
    _hg("commit", "-u", "test", "-m", "init")
    assert_eq("hg", tc.detect_repo_type(_hg_root),
              "detect_repo_type: an hg checkout is recognised")
    _hg_base = tc.vcs_source_signature(_hg_root)
    _hg_tracked_base = tc.vcs_source_signature(
        _hg_root, include_untracked=False,
    )
    assert_eq(True, bool(_hg_base),
              "vcs_source_signature(hg): a Mercurial checkout has a cheap signature")
    (_hg_root / "scratch-artifact").write_text("generated bytes\n")
    assert_eq(True, tc.vcs_source_signature(_hg_root) != _hg_base,
              "vcs_source_signature(hg): untracked input remains conservative")
    assert_eq(_hg_tracked_base,
              tc.vcs_source_signature(_hg_root, include_untracked=False),
              "tracked source signature(hg): untracked artifact changes nothing")
    assert_eq([], tc.source_changed_paths(_hg_root, include_untracked=False),
              "tracked source paths(hg): untracked artifact is omitted")
    (_hg_root / "scratch-artifact").unlink()
    (_hg_root / "testsuite.log").write_text("run 1: ok\n")
    assert_eq(_hg_base, tc.vcs_source_signature(_hg_root),
              "vcs_source_signature(hg): rewriting an ignored file changes nothing")
    _hg_newer = time.time() + 1
    os.utime(_hg_root / "main.c", (_hg_newer, _hg_newer))
    assert_eq(_hg_base, tc.vcs_source_signature(_hg_root),
              "vcs_source_signature(hg): touching a file changes nothing")
    (_hg_root / "main.c").write_text("int main(void){return 1;}\n")
    assert_eq(True, tc.vcs_source_signature(_hg_root) != _hg_base,
              "vcs_source_signature(hg): a content edit changes the signature")
    assert_eq(True,
              tc.vcs_source_signature(_hg_root, include_untracked=False)
              != _hg_tracked_base,
              "tracked source signature(hg): tracked edit changes identity")
    assert_eq(["main.c"], tc.source_changed_paths(_hg_root),
              "source_changed_paths(hg): reports the edited path")
    assert_eq(["main.c"],
              tc.source_changed_paths(_hg_root, include_untracked=False),
              "tracked source paths(hg): reports the edited path")
    (_hg_root / "main.c").write_text("int main(void){return 0;}\n")
    assert_eq(_hg_base, tc.vcs_source_signature(_hg_root),
              "vcs_source_signature(hg): reverting returns to the original signature")


# ─── seed_toml(preserve_curated=...) ────────────────────────────────
#
# A placeholder refresh re-renders the template but must carry curated
# [threat_model].attacker_controls and the whole [s6_peers] section (which a
# plain seed never emits) forward — see bin/setup-target. preserve_curated=False
# (the full-reseed default) resets them.
_seed_root = TEST_TMPDIR / "seed-preserve"
_seed_root.mkdir()
(_seed_root / "CMakeLists.txt").write_text("cmake_minimum_required(VERSION 3.16)\n")
_seed_out = _seed_root / "target.toml"
_curated = (
    'target = "seed-preserve"\n'
    'build_system = "cmake"\n'
    '[threat_model]\n'
    'attacker_controls = ["bytes", "call-sequence", "protocol-state"]\n'
    '[s6_peers]\n'
    'domain = "JSON"\n'
    'peers = ["rapidjson", "simdjson"]\n'
)

# preserve_curated=True keeps both curated sections.
_seed_out.write_text(_curated, encoding="utf-8")
tc.seed_toml(_seed_root, _seed_out, preserve_curated=True)
_kept = tc.parse_toml(_seed_out)
assert_eq(["bytes", "call-sequence", "protocol-state"],
          _kept.get("threat_model", {}).get("attacker_controls"),
          "seed_toml(preserve_curated=True): keeps curated attacker_controls")
assert_eq(["rapidjson", "simdjson"], _kept.get("s6_peers", {}).get("peers"),
          "seed_toml(preserve_curated=True): keeps curated [s6_peers] peers")
assert_eq("JSON", _kept.get("s6_peers", {}).get("domain"),
          "seed_toml(preserve_curated=True): keeps curated s6 domain")

# preserve_curated=False (default) resets attacker_controls to the seed default
# and drops [s6_peers] entirely.
_seed_out.write_text(_curated, encoding="utf-8")
tc.seed_toml(_seed_root, _seed_out)
_reset = tc.parse_toml(_seed_out)
assert_eq(None, _reset.get("s6_peers"),
          "seed_toml(default): a full re-seed drops [s6_peers]")
if _reset.get("threat_model", {}).get("attacker_controls") != [
        "bytes", "call-sequence", "protocol-state"]:
    passed("seed_toml(default): a full re-seed resets attacker_controls")
else:
    failed("seed_toml(default): a full re-seed resets attacker_controls",
           "curated controls survived a non-preserving seed")

# A preserved control containing a double-quote must be TOML-escaped on
# re-render, not emitted raw (which would corrupt the whole file). The value
# must survive the round-trip intact.
_seed_out.write_text(
    'target = "x"\nbuild_system = "cmake"\n'
    '[threat_model]\nattacker_controls = ["a\\"b", "bytes"]\n',
    encoding="utf-8")
tc.seed_toml(_seed_root, _seed_out, preserve_curated=True)
try:
    _esc = tc.parse_toml(_seed_out)
    assert_eq(['a"b', "bytes"], _esc.get("threat_model", {}).get("attacker_controls"),
              "seed_toml(preserve): a quoted attacker_control round-trips, valid TOML")
except Exception as _e:  # noqa: BLE001
    failed("seed_toml(preserve): a quoted attacker_control round-trips, valid TOML",
           f"re-render produced invalid TOML: {_e}")


# ─── Cleanup + summary ──────────────────────────────────────────────

shutil.rmtree(TEST_TMPDIR, ignore_errors=True)

total = _PASSED + _FAILED
if _FAILED == 0:
    print(f"  {_GREEN}{_PASSED}/{total} passed{_NC}")
    sys.exit(0)
else:
    print(f"  {_RED}{_PASSED}/{total} passed, {_FAILED} failed{_NC}")
    sys.exit(1)
