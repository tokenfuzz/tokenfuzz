#!/usr/bin/env python3
"""Tests for lib/prompt_render.py — `{{ var }}` template substitution.

The renderer is the boundary between the Python prompt orchestrator
(lib/prompt.py) and the .md.j2 templates under lib/prompts/. Tests
cover: clean substitution, missing keys render empty, multi-line values
survive, repeated placeholders all substitute, and embedded `{{` in values
is NOT recursively substituted.
"""

from __future__ import annotations

import re
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


# ── Caller-buffer taxonomy in the two crash-gating prompts ──────────
# Behaviour changes under lib/prompts/ require matching assertions. These
# render the real templates and pin the truthful-buffer taxonomy, so
# deleting a REJECT or KEEP clause fails the suite. Blockquote prefixes and
# line wrapping are collapsed so a clause matches regardless of where it wraps.
print("\ncaller-buffer taxonomy (crash-gating prompts)")


def render_named(name: str, vars_dict: dict[str, str]) -> tuple[int, str]:
    cmd = [sys.executable, str(RENDER), name]
    for k, v in vars_dict.items():
        cmd.extend(["--var", f"{k}={v}"])
    proc = subprocess.run(cmd, capture_output=True, text=True)
    return proc.returncode, re.sub(r"[>\s]+", " ", proc.stdout)


rc, sf = render_named("safety_framing.md.j2", {"results_dir": "/r"})
ok(rc == 0, "safety_framing renders")
ok("misdescribes its OWN buffer" in sf, "safety: buffer-overclaim reject clause")
ok("must match what it actually allocated" in sf, "safety: truthfulness, not allocation provenance")
ok("Deriving that size from untrusted input is fine" in sf, "safety: attacker-derived truthful size kept")
ok("you MUST still file" in sf, "safety: KEEP mirror (accurate-len / truthful capacity)")
ok("requires a NUL-terminated C string" in sf, "safety: documented C-string qualifier")
ok("no untrusted byte sets" not in sf, "safety: absolute allocation-provenance wording removed")
ok("CVSS `MAT:P`" in sf, "safety: outside controls use the live CVSS mechanism")
ok("demotes a crash from security to robustness" not in sf and "×0.7" not in sf,
   "safety: reverted robustness/multiplier wording stays removed")

rc, vp = render_named("validate_trigger_provenance.md.j2", {"target_path": "/t"})
ok(rc == 0, "validate_trigger_provenance renders")
ok("MISDESCRIBE its OWN buffer" in vp, "validator: buffer-overclaim reject clause")
ok("honoring an ACCURATE value" in vp, "validator: accurate-length KEEP")
ok("destination capacity passed TRUTHFULLY that the library overruns" in vp,
   "validator: truthful-capacity KEEP")
ok("never on shipped-caller convention alone" in vp, "validator: output minimum must be documented, not convention")
ok("PUBLIC contract requires a NUL-terminated C string" in vp, "validator: documented C-string qualification")
ok("keep it (Uncertain)" in vp, "validator: ambiguous minimum preserved as Uncertain")


# ─── Closed class vocabulary and threat-model semantics ────────────
print("\nclass vocabulary and threat-model semantics")
rc, fq = render_named("triage_find_quality.md.j2", {"body": "sample finding"})
ok(rc == 0, "finding-quality prompt renders")
ok("protocol, supply-chain, other" in fq, "quality taxonomy includes protocol and supply-chain")
ok("do not invent a new top-level" in fq, "quality taxonomy closes top-level label drift")

rc, tm = render_named("suggest_threat_model.md.j2", {
    "slug": "sampleproj", "upstream_url": "https://example.invalid",
    "readme": "sample", "api_surface": "sample.h",
})
ok(rc == 0, "threat-model prompt renders")
ok("`MAT:P` precondition" in tm, "threat-model prompt names the live CVSS mechanism")
ok("demoted from security to robustness" not in tm,
   "threat-model prompt does not describe the reverted disposition")

agents = (ROOT / "AGENTS.md").read_text(encoding="utf-8")
ok("×0.7" not in agents and "CVSS `MAT:P`" in agents,
   "runtime agent contract matches scorer semantics")


print(f"\n  \033[1m{PASSED}/{PASSED + FAILED} passed\033[0m")
sys.exit(0 if FAILED == 0 else 1)
