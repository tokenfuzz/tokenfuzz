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
ok("a source reviewer reads the code and" in sf
   and "crosses no security boundary" in sf,
   "safety: outside controls go to a source reviewer, not a fixed demotion")
ok("must make sure" in sf and "A recommendation that does not define accepted input" in sf,
   "safety: documented normative preconditions are caller contracts")
ok("demotes a crash from security to robustness" not in sf and "×0.7" not in sf,
   "safety: reverted robustness/multiplier wording stays removed")

# An operator-enabled non-default mode is application configuration, not
# attacker input. Both halves must hold or the precondition is lost: the emit
# side has to record it, and triage has to make the final report/Low decision.
# Without them a crash reachable only under a non-default filter or codec
# rates as if the input bytes alone reached it.
ok("`Parameter control: application-supplied`" in sf,
   "safety: non-default mode authored in the field bin/severity reads")
rc, rf = render_named("triage_reachability_fields.md.j2", {})
ok(rc == 0, "triage_reachability_fields renders")
ok("that selection is application configuration, not attacker input" in rf,
   "reach-fields: operator-enabled mode is configuration")
ok('set parameter_control to "application-supplied"' in rf,
   "reach-fields: non-default setup reaches the triage decision")

rc, ff = render_named("find_first_directive.md.j2",
                      {"results_dir": "/r", "report_prose": ""})
ok(rc == 0, "find_first_directive renders")
ok("AND show the demand surviving the project's own allocation" in ff,
   "find-first: unsized resource exhaustion is not a FIND")

rc, vp = render_named("validate_trigger_provenance.md.j2", {"target_path": "/t"})
ok(rc == 0, "validate_trigger_provenance renders")
ok("MISDESCRIBE its OWN buffer" in vp, "validator: buffer-overclaim reject clause")
ok("honoring an ACCURATE value" in vp, "validator: accurate-length KEEP")
ok("destination capacity passed TRUTHFULLY that the library overruns" in vp,
   "validator: truthful-capacity KEEP")
ok("never on shipped-caller convention alone" in vp, "validator: output minimum must be documented, not convention")
ok("PUBLIC contract requires a NUL-terminated C string" in vp, "validator: documented C-string qualification")
ok("keep it (Uncertain)" in vp, "validator: ambiguous minimum preserved as Uncertain")
ok("must make sure" in vp and "does not make a documented-invalid node type supported" in vp,
   "validator: documented node-type preconditions reject caller misuse")
ok("exact claimed security consequence" in vp,
   "validator: source review covers the report's exact consequence")
ok("consequence-disproved" in vp,
   "validator: affirmative consequence disproof has a closed rejection kind")
ok("different scenario" in vp,
   "validator: an alternate scenario cannot rescue a refuted report")
# Scope is what the whole trigger fit needs, not what any one component
# contributes: on a bytes-only target, crafted bytes plus an application call
# order the attacker cannot issue is out of the model, and publication follows
# this answer directly.
ok("cover ALL of them" in vp and "never sufficient" in vp,
   "validator: trigger fit needs every required component covered")
ok("AND a specific application call order is `outside`" in vp,
   "validator: a mixed bytes-plus-call-order trigger is out of a bytes model")
ok("calling the documented entry point that consumes the input" in vp,
   "validator: ordinary fixed setup is not a trigger component")


# ─── Closed class vocabulary and threat-model semantics ────────────
print("\nclass vocabulary and threat-model semantics")
rc, fq = render_named("triage_find_quality.md.j2", {"body": "sample finding"})
ok(rc == 0, "finding-quality prompt renders")
ok("protocol, supply-chain, other" in fq, "quality taxonomy includes protocol and supply-chain")
ok("do not invent a new top-level" in fq, "quality taxonomy closes top-level label drift")
# A disclosure claim that never says where the bytes come from is unfalsifiable:
# source review can neither confirm nor refute it, so the reports that named
# their allocation were rejected while the vague ones survived.
ok("uninitialized, stale, or leftover memory" in fq,
   "quality gate names the unsourced residual-disclosure reject bucket")
ok("MUST name" in fq and "the allocation that memory comes from" in fq,
   "quality gate requires a disclosure claim to name its memory source")
ok("known value" in fq,
   "quality gate exempts disclosure of an already-named value")

rc, reach = render_named("triage_reachability_fields.md.j2", {"body": "sample report"})
ok(rc == 0, "reach-field prompt renders for disclosure classification")
ok("not already observable to the attacking principal" in reach,
   "cross-principal is defined from the attacker's knowledge")
ok("non-sensitive public constant" in reach and "happens to be fixed" in reach,
   "fixed-or-zero cannot silently classify a fixed secret as harmless")

rc, tm = render_named("suggest_threat_model.md.j2", {
    "slug": "sampleproj", "upstream_url": "https://example.invalid",
    "readme": "sample", "api_surface": "sample.h",
})
ok(rc == 0, "threat-model prompt renders")
ok("a source reviewer confirms leaves the" in tm and "not reportable" in tm,
   "threat-model prompt names the reviewed reportable/not-reportable decision")
ok("demoted from security to robustness" not in tm,
   "threat-model prompt does not describe the reverted disposition")

agents = (ROOT / "AGENTS.md").read_text(encoding="utf-8")
ok("×0.7" not in agents and "a source reviewer decides" in agents
   and "no numeric CVSS score" in agents,
   "runtime agent contract matches the reviewed publication decision")


print(f"\n  \033[1m{PASSED}/{PASSED + FAILED} passed\033[0m")
sys.exit(0 if FAILED == 0 else 1)
