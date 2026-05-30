#!/usr/bin/env python3
"""tests/test_target_config_py.py — exercise the Python target_config API.

Runs alongside the existing tests/test_target_threat_model.sh, which
covers the bash-shim interface. This file tests the Python module
directly: parse_toml, load_toml_into, find_session_dir, read_session_env,
write_session_env, detect_rev, seed_toml, and the Config helpers.

Output format matches helpers.sh — `✓ name` for pass / `✗ name` for fail —
so tests/run-tests.sh's pass/fail counter (greps for those marks) keeps
working unchanged.
"""

from __future__ import annotations

import os
import sys
import tempfile
import shutil
import subprocess
from pathlib import Path

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


# ─── 3. Bad section header is strict by default, lenient only by env ───

write("bad-section.toml",
      'slug = "malformed"\n[bad section name with spaces]\nasan_bin = "build-asan/post-bad"\n')
try:
    tc.parse_toml(TEST_TMPDIR / "bad-section.toml")
    failed("parse_toml: bad [section] header rejected by default",
           "parse_toml succeeded unexpectedly")
except Exception:
    passed("parse_toml: bad [section] header rejected by default")

cfg = tc.Config()
os.environ["TARGET_TOML_LENIENT"] = "1"
try:
    tc.load_toml_into(cfg, TEST_TMPDIR / "bad-section.toml")
finally:
    os.environ.pop("TARGET_TOML_LENIENT", None)
assert_eq("build-asan/post-bad", cfg.asan_bin,
          "bad [section] header requires TARGET_TOML_LENIENT=1")


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
(slug_dir / ".session-env").write_text("RESULTS_DIR=foo\n", encoding="utf-8")
nested = slug_dir / "results" / "scratch-1"
nested.mkdir(parents=True)
found = tc.find_session_dir(nested)
assert_eq(slug_dir.resolve(), found.resolve() if found else None,
          "find_session_dir walks up to slug dir")
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

# find_slug_session_dir resolves a known slug dir, preferring the
# backend-local results/.session-env over the legacy slug-dir copy
# (both exist here — the slug dir got a .session-env earlier).
slug_session = tc.find_slug_session_dir(slug_dir)
assert_eq(backend_results.resolve(),
          slug_session.resolve() if slug_session else None,
          "find_slug_session_dir prefers the backend-local session env")

# find_session_dir reached through an ancestor's output/ tree (a
# CWD-based call, not a testcase path) also prefers backend-local.
found = tc.find_session_dir(TEST_TMPDIR / "out_root")
assert_eq(backend_results.resolve(), found.resolve() if found else None,
          "find_session_dir scan prefers backend-local over legacy")

# With only the legacy copy present, find_slug_session_dir falls back
# to the slug dir itself; with neither copy it returns None.
legacy_only = TEST_TMPDIR / "out_root" / "output" / "legacyonly"
legacy_only.mkdir(parents=True)
(legacy_only / ".session-env").write_text(
    "RESULTS_DIR=leg\n", encoding="utf-8")
ses = tc.find_slug_session_dir(legacy_only)
assert_eq(legacy_only.resolve(), ses.resolve() if ses else None,
          "find_slug_session_dir falls back to the legacy slug dir")
assert_eq(None, tc.find_slug_session_dir(TEST_TMPDIR / "no-such-slug"),
          "find_slug_session_dir returns None when neither copy exists")

# Negative: outside any output/ tree returns None.
empty = TEST_TMPDIR / "elsewhere"
empty.mkdir()
assert_eq(None, tc.find_session_dir(empty),
          "find_session_dir returns None when no output/<slug> ancestor")


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


# ─── 10. seed_toml emits a parseable file with [threat_model] ───────

seed_root = TEST_TMPDIR / "seed-target"
seed_root.mkdir()
out = TEST_TMPDIR / "seeded.toml"
tc.seed_toml(seed_root, out, "https://example.com/repo")
text = out.read_text(encoding="utf-8")
assert_in('target        = "seed-target"', text,
          "seeded toml has target field")
assert_in('pinned_rev    = "norev"', text,
          "seeded toml uses norev for plain source tree")
assert_in("[threat_model]", text, "seeded toml has [threat_model] header")
assert_in('attacker_controls = ["bytes"]', text,
          "seeded toml has bytes-only default for non-browser target")
# Round-trip back through the loader.
cfg = tc.Config()
tc.load_toml_into(cfg, out)
assert_eq("bytes", cfg.attacker_controls_csv(),
          "seeded generic toml round-trips through loader")

# Curated library slugs get a target-specific starter threat model,
# sourced from .agents/references/threat_models.toml; uncurated slugs
# (pcre2, zlib) fall back to the byte-only default. This end-to-end loop
# also exercises the bundled references file.
threat_model_tmpdir = TEST_TMPDIR / "threat-model-roundtrip"
threat_model_tmpdir.mkdir()
for slug, expected_csv in [
    ("json", "bytes,call-sequence"),
    ("libxml2", "bytes,call-sequence"),
    ("curl", "bytes,call-sequence,protocol-state"),
    ("c-ares", "bytes,call-sequence,protocol-state"),
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

# threat_model_for: reads the operator-curated references file directly.
# A curated slug returns its list; any uncurated slug returns [] so the
# caller falls back to the byte-only default — this works for ANY project,
# with no hardcoded per-project table in lib/.
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
assert_eq(["bytes", "call-sequence"], tc.threat_model_for("libxml2"),
          "threat_model_for: bundled threat_models.toml resolves libxml2")

# Browser target widens the threat model
fx = TEST_TMPDIR / "firefox"
fx.mkdir()
fx_out = TEST_TMPDIR / "seeded-browser.toml"
tc.seed_toml(fx, fx_out, "")
fx_text = fx_out.read_text(encoding="utf-8")
assert_in("call-sequence", fx_text, "browser seed includes call-sequence")
assert_in("timing", fx_text, "browser seed includes timing")
cfg = tc.Config()
tc.load_toml_into(cfg, fx_out)
assert_eq("bytes,call-sequence,timing", cfg.attacker_controls_csv(),
          "seeded browser toml round-trips through loader")

# ─── 9b. seed_toml emits [s4_diff_pairs] for browser engines ────────
# Per-engine JIT flags come from _S4_DIFF_PAIRS_TAXONOMY. Verify each
# browser slug seeds a section and that the values round-trip through
# load_toml_into into cfg.s4_diff_pairs.
# Note: seed_toml derives slug from root.name, and only firefox/chromium/
# webkit/servo are in _BROWSER_SLUGS — use those exact dir names.
# (The existing "firefox" test dir above is already used; avoid colliding.)
S4_BROWSER_TMPDIR = TEST_TMPDIR / "s4-roundtrip"
S4_BROWSER_TMPDIR.mkdir()
for browser_slug, expected_off, expected_eager in [
    ("firefox", "--no-ion", "--ion-eager"),
    ("chromium", "--no-turbofan", "--always-turbofan"),
    ("webkit", "--useJIT=false", "--thresholdForJITAfterWarmUp=0"),
    ("servo", "--no-ion", "--ion-eager"),
]:
    br = S4_BROWSER_TMPDIR / browser_slug
    br.mkdir()
    br_out = S4_BROWSER_TMPDIR / f"{browser_slug}.toml"
    tc.seed_toml(br, br_out, "")
    br_text = br_out.read_text(encoding="utf-8")
    assert_in("[s4_diff_pairs]", br_text,
              f"seed_toml: {browser_slug} has [s4_diff_pairs] section")
    assert_in(expected_off, br_text,
              f"seed_toml: {browser_slug} has expected jit_off flag")
    assert_in(expected_eager, br_text,
              f"seed_toml: {browser_slug} has expected jit_eager flag")
    cfg = tc.Config()
    tc.load_toml_into(cfg, br_out)
    if expected_off in (cfg.s4_diff_pairs.get("jit_off") or []):
        passed(f"load_toml_into: {browser_slug} jit_off round-trips")
    else:
        failed(f"load_toml_into: {browser_slug} jit_off round-trips",
               f"got {cfg.s4_diff_pairs!r}")
    if expected_eager in (cfg.s4_diff_pairs.get("jit_eager") or []):
        passed(f"load_toml_into: {browser_slug} jit_eager round-trips")
    else:
        failed(f"load_toml_into: {browser_slug} jit_eager round-trips",
               f"got {cfg.s4_diff_pairs!r}")

# Non-browser target gets NO s4_diff_pairs section (no JS shell to diff).
generic_root = TEST_TMPDIR / "s4-generic"
generic_root.mkdir()
generic_out = TEST_TMPDIR / "s4-generic.toml"
tc.seed_toml(generic_root, generic_out, "")
generic_text = generic_out.read_text(encoding="utf-8")
if "[s4_diff_pairs]" not in generic_text:
    passed("seed_toml: non-browser target has no [s4_diff_pairs] section")
else:
    failed("seed_toml: non-browser target has no [s4_diff_pairs] section",
           "section unexpectedly present")

# s4_diff_pairs_for() returns {} for unknown slug, dict for known.
if tc.s4_diff_pairs_for("firefox").get("jit_off") == ["--no-ion"]:
    passed("s4_diff_pairs_for: firefox jit_off")
else:
    failed("s4_diff_pairs_for: firefox jit_off",
           f"got {tc.s4_diff_pairs_for('firefox')!r}")
if tc.s4_diff_pairs_for("unknown-target") == {}:
    passed("s4_diff_pairs_for: unknown slug returns empty")
else:
    failed("s4_diff_pairs_for: unknown slug returns empty",
           f"got {tc.s4_diff_pairs_for('unknown-target')!r}")


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
legacy_toml = TEST_TMPDIR / "legacy-libxml2.toml"
legacy_toml.write_text(
    'target = "libxml2"\n'
    'build_system = "cmake"\n'
    'asan_bin = "build-asan/xmllint"\n'
    '[threat_model]\n'
    'attacker_controls = ["bytes"]\n',
    encoding="utf-8",
)
cfg = tc.Config()
tc.load_toml_into(cfg, legacy_toml)
if cfg.s6_peers == []:
    passed("load_toml_into: legacy target.toml without s6_peers stays empty")
else:
    failed("load_toml_into: legacy target.toml without s6_peers stays empty",
           f"got s6_peers={cfg.s6_peers!r}")
if cfg.s6_domain == "":
    passed("load_toml_into: legacy target.toml leaves s6_domain empty")
else:
    failed("load_toml_into: legacy target.toml leaves s6_domain empty",
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


# ─── 10. Subcommand CLI parity with the bash shim's NUL stream ──────

# parse-toml subcommand emits the same NUL-delimited KEY\0VALUE\0 stream
# the bash _target_parse_toml has always produced.
write("link.toml",
      'slug = "linked"\nlink_libs = ["-lm", "-lpthread"]\n')
out = subprocess.run(
    ["python3", str(ROOT / "lib" / "target_config.py"),
     "parse-toml", str(TEST_TMPDIR / "link.toml")],
    capture_output=True, check=True,
)
stream = out.stdout
# Should contain TARGET_LINK_LIBS_LIST tokens.
if b"TARGET_LINK_LIBS_LIST\x00" in stream:
    passed("parse-toml CLI: TARGET_LINK_LIBS_LIST emitted")
else:
    target_keys = [
        s for s in stream.split(b"\x00")
        if s.startswith(b"TARGET_")
    ][:6]
    failed("parse-toml CLI: TARGET_LINK_LIBS_LIST emitted",
           f"keys present: {target_keys}")

# read-session-env subcommand emits eval-safe `export K='v'` lines.
out = subprocess.run(
    ["python3", str(ROOT / "lib" / "target_config.py"),
     "read-session-env", str(env_dir)],
    capture_output=True, text=True, check=True,
)
assert_in("export RESULTS_DIR=", out.stdout, "read-session-env CLI: emits RESULTS_DIR export")
assert_in("export TARGET_ROOT=", out.stdout, "read-session-env CLI: emits TARGET_ROOT export")
assert_not_in("UNALLOWED", out.stdout, "read-session-env CLI: drops non-allowlisted keys")


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
# stays a commented FILL_ME. setup-target --bootstrap materializes the
# canonical build and calls refresh_detected_build_fields to patch the
# detected fields in — without disturbing curated sections.
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

# A plausible asan_bin (real, non-aux path) detection can't confirm is kept.
keep_root = TEST_TMPDIR / "refresh-keep-bin"
(keep_root / "build-asan").mkdir(parents=True)
(keep_root / "build-asan" / "mytool").write_bytes(b"\x7fELF")
keep_toml = keep_root / "target.toml"
keep_toml.write_text(
    'build_system  = "cmake"\n'
    'asan_bin      = "build-asan/mytool"\n',
    encoding="utf-8",
)
tc.refresh_detected_build_fields(keep_root, keep_toml)
assert_in('asan_bin      = "build-asan/mytool"', keep_toml.read_text(encoding="utf-8"),
          "refresh_detected_build_fields: keeps a plausible operator-set asan_bin")


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
# auto-repair-target-toml occasionally accepts (or older runs stored)
# absolute audit-machine paths in asan_lib / asan_bin / link_libs.
# Downstream consumers (bin/export-repro's _strip_sanitizer_build_prefix,
# the build/lib resolution shell snippet) only handle target_root-relative
# form. The loader normalizes silently so legacy target.toml files keep
# working without manual repair.
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


# ─── Cleanup + summary ──────────────────────────────────────────────

shutil.rmtree(TEST_TMPDIR, ignore_errors=True)

total = _PASSED + _FAILED
if _FAILED == 0:
    print(f"  {_GREEN}{_PASSED}/{total} passed{_NC}")
    sys.exit(0)
else:
    print(f"  {_RED}{_PASSED}/{total} passed, {_FAILED} failed{_NC}")
    sys.exit(1)
