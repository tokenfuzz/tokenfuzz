#!/usr/bin/env python3
"""Tests for lib/prompt_render.py — `{{ var }}` template substitution.

The renderer is the boundary between the bash prompt orchestrator
(lib/prompt.sh) and the .md.j2 templates under lib/prompts/. Tests
cover: clean substitution, missing keys render empty, multi-line values
survive, repeated placeholders all substitute, embedded `{{` in values
is NOT recursively substituted (mirrors prior bash heredoc semantics).
"""

from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RENDER = ROOT / "lib" / "prompt_render.py"

PASSED = 0
FAILED = 0


def ok(cond, name, detail=""):
    global PASSED, FAILED
    if cond:
        PASSED += 1
        print(f"  \033[0;32m✓\033[0m {name}")
    else:
        FAILED += 1
        print(f"  \033[0;31m✗\033[0m {name}")
        if detail:
            print(f"    {detail}")


def assert_eq(expected, actual, name):
    ok(expected == actual, name, f"expected={expected!r} actual={actual!r}")


def render(template_text: str, vars_dict: dict[str, str]) -> tuple[int, str]:
    with tempfile.NamedTemporaryFile("w", suffix=".md.j2", delete=False) as f:
        f.write(template_text)
        path = f.name
    cmd = [sys.executable, str(RENDER), path]
    for k, v in vars_dict.items():
        cmd.extend(["--var", f"{k}={v}"])
    proc = subprocess.run(cmd, capture_output=True, text=True)
    Path(path).unlink()
    return proc.returncode, proc.stdout


# ── Basic substitution ──────────────────────────────────────────────
print("basic substitution")
rc, out = render("Hello {{ name }}!", {"name": "World"})
assert_eq(0, rc, "rc=0")
assert_eq("Hello World!", out, "simple substitution")

rc, out = render("{{ a }} + {{ b }} = {{ c }}", {"a": "1", "b": "2", "c": "3"})
assert_eq("1 + 2 = 3", out, "multiple placeholders")


# ── Whitespace tolerance ────────────────────────────────────────────
print("\nwhitespace inside braces")
rc, out = render("{{name}} | {{ name }} | {{   name   }}", {"name": "X"})
assert_eq("X | X | X", out, "any inner whitespace matches the same key")


# ── Missing keys render empty ───────────────────────────────────────
print("\nmissing keys")
rc, out = render("before {{ unknown }} after", {})
assert_eq(0, rc, "missing key rc=0")
assert_eq("before  after", out, "missing renders empty")

rc, out = render("{{ a }}{{ b }}{{ c }}", {"a": "X", "c": "Z"})
assert_eq("XZ", out, "missing middle renders empty")


# ── Repeated placeholders ───────────────────────────────────────────
print("\nrepeated placeholders")
rc, out = render("{{ x }}-{{ x }}-{{ x }}", {"x": "Q"})
assert_eq("Q-Q-Q", out, "same key substituted everywhere")


# ── Multi-line values survive ───────────────────────────────────────
print("\nmulti-line values")
multiline = "line one\nline two\nline three"
rc, out = render("Before:\n{{ block }}\nAfter.", {"block": multiline})
assert_eq("Before:\nline one\nline two\nline three\nAfter.", out, "multiline value preserved")


# ── No recursive expansion ──────────────────────────────────────────
print("\nno recursive expansion")
# A value that itself contains a placeholder must NOT be re-expanded.
# Bash heredocs have the same semantics — string interpolation runs
# once over the literal heredoc body.
rc, out = render("{{ outer }}", {"outer": "{{ inner }}", "inner": "should-not-appear"})
assert_eq("{{ inner }}", out, "value containing {{ … }} is NOT re-expanded")


# ── Non-placeholder braces left alone ───────────────────────────────
print("\nliteral braces")
rc, out = render("{not a placeholder} { also not } {{ x }}", {"x": "Y"})
assert_eq("{not a placeholder} { also not } Y", out, "single braces preserved")

# Triple-brace pattern: the inner `{{ … }}` is a valid placeholder,
# the extra leading `{` stays literal.
rc, out = render("{{{ x }}}", {"x": "Z"})
assert_eq("{Z}", out, "extra braces around placeholder stay literal")


# ── value with `=` survives the --var split ─────────────────────────
print("\nvalues with = survive")
rc, out = render("{{ pair }}", {"pair": "key=value=more"})
assert_eq("key=value=more", out, "value tail preserved past first '='")


# ── Missing template file errors with rc=2 ──────────────────────────
print("\nmissing template")
proc = subprocess.run(
    [sys.executable, str(RENDER), "/no/such/template.md.j2"],
    capture_output=True, text=True,
)
assert_eq(2, proc.returncode, "missing template rc=2")
ok("cannot read" in proc.stderr.lower(), "missing template stderr explains why", proc.stderr)


# ── Bare filename resolves under lib/prompts/ ───────────────────────
print("\nbare-name resolution")
proc = subprocess.run(
    [sys.executable, str(RENDER), "cold_start.md.j2",
     "--var", "agent_num=42", "--var", "role=analysis", "--var", "mode=generic"],
    capture_output=True, text=True,
)
assert_eq(0, proc.returncode, "bare filename resolves under lib/prompts/")
ok("Agent 42" in proc.stdout and "role=analysis" in proc.stdout,
   "cold_start.md.j2 rendered with the provided vars", proc.stdout[:200])


# ── Undecodable bytes in a --var value round-trip, don't crash ──────
print("\nsurrogate-escaped bytes round-trip")
# A --var value carrying a byte that is not valid UTF-8 (here a lone 0xC2,
# the kind of latin-1 / mojibake artifact that leaks in from target strings)
# reaches Python's argv as the surrogate \udcc2. The renderer must emit the
# original byte rather than crash strict-UTF-8 stdout with "surrogates not
# allowed". subprocess argv is bytes, so we drive it directly and read raw
# stdout bytes to verify the round-trip.
with tempfile.NamedTemporaryFile("w", suffix=".md.j2", delete=False) as f:
    f.write("X {{ blob }} Y")
    _tpath = f.name
proc = subprocess.run(
    [sys.executable.encode(), str(RENDER).encode(), _tpath.encode(),
     b"--var", b"blob=lead\xc2tail"],
    capture_output=True,
)
Path(_tpath).unlink()
assert_eq(0, proc.returncode, "undecodable byte rc=0 (no crash)")
assert_eq(b"X lead\xc2tail Y", proc.stdout, "raw 0xC2 byte round-trips to output")


print(f"\n  \033[1m{PASSED}/{PASSED + FAILED} passed\033[0m")
sys.exit(0 if FAILED == 0 else 1)
