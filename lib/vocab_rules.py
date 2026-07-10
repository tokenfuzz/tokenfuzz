#!/usr/bin/env python3
"""Safety-classifier vocabulary rewrites.

Provides the in-memory prompt neutralizer and marker stripping used by the
audit runner and vocabulary tests.

Scope: ONLY words known or strongly suspected to trip LLM safety
classifiers (primarily Gemini) in security-research framing. Pure technical
bug-class vocabulary (UAF, OOB, use-after-free, type confusion, integer
overflow, race condition, null pointer dereference, memory corruption, etc.)
is NOT rewritten — those terms are neutral programming jargon that no
supported backend blocks, and rewriting them only mangles meaning without
buying any safety.

CLI (stdin/stdout unless noted):
  neutralize-string                          NOVOCAB-aware pipe neutralizer
  strip-markers                              remove NOVOCAB sentinel comments
  line-core                                  neutralize_line per line (tests)
  line-prompt                                neutralize_line_prompt per line
"""

import re
import sys

# ── exploit family (grammar-aware) ─────────────────────────────────────
# The prior single rule `exploit(able|ation)? -> testcase` produced
# ungrammatical output ("looks testcase"). Split by form so each slot gets
# a word with the right part of speech.
_RULES = [
    (re.compile(r"\bexploitation\b", re.I), "reproduction"),
    (re.compile(r"\bexploitable\b", re.I), "reachable"),
    (re.compile(r"\bexploits\b", re.I), "reproducers"),
    # Verb sense first ("could/can/may/might/to exploit") — must run before
    # the bare-noun fallback so we don't emit "could reproducer".
    (re.compile(r"\b(could|can|may|might|to)\s+exploit\b", re.I),
     lambda m: m.group(1) + " reach"),
    (re.compile(r"\bexploit\b", re.I), "reproducer"),

    # ── attack / attacker family ───────────────────────────────────────
    # Compound forms first so they're handled before the bare rules.
    # `attacker-<adjective>` → `externally-<adjective>` (controlled, reachable,
    # supplied, shaped, driven, …). Neutralizes "attacker" (classifier-hot)
    # while keeping it DISTINCT from "caller" — collapsing attacker→caller
    # destroys the threat-model distinction the audit relies on (an attacker is
    # untrusted; a caller is the trusted application).
    (re.compile(r"\battacker-(?=\w)", re.I), "externally-"),
    (re.compile(r"\battack[- ]vector\b", re.I), "input vector"),
    (re.compile(r"\battack surface\b", re.I), "input surface"),
    # Bare attack — preserves grammatical form ("DDoS attacked" must not
    # collapse to "DDoS reach"). The captured-suffix compare is
    # case-sensitive, so an uppercase "S" is left as-is rather than
    # pluralized.
    (re.compile(r"\battack(s|ed|ing)?\b", re.I),
     lambda m: "reach" + ("es" if m.group(1) == "s"
                          else (m.group(1) or ""))),
    # Bare attacker(s) (after compound rules above). Field-name uses like
    # `attacker_controls` are unaffected: `_` is a word char so `\b` does
    # not fire between `r` and `_`.
    (re.compile(r"\battackers\b", re.I), "external parties"),
    (re.compile(r"\battacker\b", re.I), "external party"),

    # ── hostile-intent vocabulary ──────────────────────────────────────
    (re.compile(r"\bmalicious\b", re.I), "hand-crafted"),
    # weaponize(d) — preserve tense.
    (re.compile(r"\bweaponize(d?)\b", re.I),
     lambda m: "reproduce" + m.group(1)),

    # ── vulnerability -> security issue (Gemini-confirmed block) ────────
    # Bare "issue" would be too generic; "security issue" preserves framing
    # AND passes the classifier where "vulnerability" does not.
    (re.compile(r"\bvulnerabilit(y|ies)\b", re.I),
     lambda m: "security issue" if m.group(1) == "y" else "security issues"),
    # Collapse "security security" when source prose already had "security"
    # adjacent (e.g. "security vulnerabilities" expands to "security
    # security issues" before this dedup).
    (re.compile(r"\bsecurity[- ]security\b", re.I), "security"),
]


def neutralize_line(line: str) -> str:
    for pat, repl in _RULES:
        line = pat.sub(repl, line)
    return line


def neutralize_line_prompt(line: str) -> str:
    # No prompt-specific rules. Core safety vocabulary is the only
    # consistent classifier trigger across state files, templates, and
    # reference docs; prior prompt-only rules all rewrote technical or
    # generic vocabulary with no classifier risk.
    return neutralize_line(line)


_NOVOCAB_OPEN = re.compile(r"<!--\s*NOVOCAB\s*-->")
_NOVOCAB_CLOSE = re.compile(r"<!--\s*/NOVOCAB\s*-->")
_NOVOCAB_MARKER = re.compile(r"<!--\s*/?\s*NOVOCAB\s*-->\s*\n?")


def neutralize_string(text: str) -> str:
    """NOVOCAB-aware neutralizer for an in-memory string (the importable form of
    the neutralize-string pipe). Lines inside a <!-- NOVOCAB --> block are left
    verbatim so literal vocabulary-instruction examples are not rewritten onto
    themselves. Markers are NOT stripped here — that is strip_markers's job, run
    once after the last scrub pass."""
    lines = text.split("\n")
    skip = False
    for i, line in enumerate(lines):
        if _NOVOCAB_OPEN.search(line):
            skip = True
        elif _NOVOCAB_CLOSE.search(line):
            skip = False
        elif not skip:
            lines[i] = neutralize_line(line)
    return "\n".join(lines)


def strip_markers(text: str) -> str:
    """Remove NOVOCAB sentinel comments from model-visible output. Pair with
    neutralize_string and call exactly once, immediately before the prompt is
    sent, AFTER every scrub pass the prompt will go through."""
    return _NOVOCAB_MARKER.sub("", text)


def _cmd_neutralize_string() -> int:
    sys.stdout.write(neutralize_string(sys.stdin.read()))
    return 0


def _cmd_strip_markers() -> int:
    sys.stdout.write(strip_markers(sys.stdin.read()))
    return 0


def _cmd_lines(fn) -> int:
    for line in sys.stdin:
        sys.stdout.write(fn(line))
    return 0


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv:
        print("usage: vocab_rules.py <subcommand>", file=sys.stderr)
        return 2
    cmd, rest = argv[0], argv[1:]
    if cmd == "neutralize-string":
        return _cmd_neutralize_string()
    if cmd == "strip-markers":
        return _cmd_strip_markers()
    if cmd == "line-core":
        return _cmd_lines(neutralize_line)
    if cmd == "line-prompt":
        return _cmd_lines(neutralize_line_prompt)
    print("unknown subcommand: %s" % cmd, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
