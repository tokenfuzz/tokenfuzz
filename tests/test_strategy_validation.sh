#!/usr/bin/env bash
# Validates strategy files exist, strategy rotation is complete,
# AGENTS.md structural rules, and reference file integrity
set -o pipefail
source "$(dirname "$0")/helpers.sh"
setup_test_env

STRATEGIES_DIR="$SCRIPT_ROOT/.agents/references/strategies"
REFERENCES_DIR="$SCRIPT_ROOT/.agents/references"

# ═══════════════════════════════════════════════════════════════
# 1. All strategies in rotation order have corresponding files
# ═══════════════════════════════════════════════════════════════

for letter in S1 S2 S3 S4 S5 S6 S7 S8; do
  file=$(strategy_file_for_letter "$letter")
  if [ -n "$file" ] && [ -f "$STRATEGIES_DIR/$file" ]; then
    pass "strategy $letter file exists: $file"
  else
    fail "strategy $letter file missing: $file" "expected at $STRATEGIES_DIR/$file"
  fi
done

# REF is a reference, not a strategy — should have file too
ref_file=$(strategy_file_for_letter REF)
if [ -n "$ref_file" ] && [ -f "$STRATEGIES_DIR/$ref_file" ]; then
  pass "reference REF file exists: $ref_file"
else
  fail "reference REF file missing: $ref_file"
fi

# ═══════════════════════════════════════════════════════════════
# 2. Strategy README exists
# ═══════════════════════════════════════════════════════════════

if [ -f "$STRATEGIES_DIR/README.md" ]; then
  pass "strategies README.md exists"
else
  fail "strategies README.md missing"
fi

# ═══════════════════════════════════════════════════════════════
# 3. strategy_file_for_letter — invalid letters return empty
# ═══════════════════════════════════════════════════════════════

assert_eq "" "$(strategy_file_for_letter INVALID)" "invalid letter → empty"
assert_eq "" "$(strategy_file_for_letter "")" "empty letter → empty"
assert_eq "" "$(strategy_file_for_letter B)" "B (not in rotation) → empty"
assert_eq "" "$(strategy_file_for_letter C)" "C (not in rotation) → empty"

# ═══════════════════════════════════════════════════════════════
# 4. Strategy rotation is complete cycle
# ═══════════════════════════════════════════════════════════════

STRATEGY_ROTATION_ORDER=(S1 S2 S3 S4 S5 S6 S7 S8)
next_strategy_in_rotation() {
  local current="$1" found=0 first=""
  for s in "${STRATEGY_ROTATION_ORDER[@]}"; do
    [ -z "$first" ] && first="$s"
    if [ "$found" -eq 1 ]; then echo "$s"; return; fi
    [ "$s" = "$current" ] && found=1
  done
  echo "${first:-S2}"
}

# Verify full cycle S1→S2→S3→S4→S5→S6→S7→S8→S1
current="S1"
visited=("$current")
for i in $(seq 1 8); do
  current=$(next_strategy_in_rotation "$current")
  visited+=("$current")
done
expected="S1 S2 S3 S4 S5 S6 S7 S8 S1"
actual="${visited[*]}"
assert_eq "$expected" "$actual" "full rotation cycle: S1→...→S8→S1"

# ═══════════════════════════════════════════════════════════════
# 5. Core reference files exist
# ═══════════════════════════════════════════════════════════════

for ref_file in session-rules.md; do
  if [ -f "$REFERENCES_DIR/$ref_file" ]; then
    pass "reference file exists: $ref_file"
  else
    fail "reference file missing: $ref_file"
  fi
done

# ═══════════════════════════════════════════════════════════════
# 6. AGENTS.md exists and has required sections
# ═══════════════════════════════════════════════════════════════

AGENTS_MD="$SCRIPT_ROOT/AGENTS.md"
if [ -f "$AGENTS_MD" ]; then
  pass "AGENTS.md exists"
  assert_file_contains "$AGENTS_MD" "ROLES" "AGENTS.md has ROLES section"
  assert_file_contains "$AGENTS_MD" "CRITICAL RULES" "AGENTS.md has CRITICAL RULES"
  assert_file_contains "$AGENTS_MD" "STRATEGY" "AGENTS.md mentions strategy"
  assert_file_contains "$AGENTS_MD" "REPRODUCTION" "AGENTS.md has reproduction section"
  assert_file_contains "$AGENTS_MD" "CRASH" "AGENTS.md mentions crash"
  assert_file_contains "$AGENTS_MD" "FIND" "AGENTS.md mentions findings"
  assert_file_contains "$AGENTS_MD" "STATE" "AGENTS.md mentions state"
else
  fail "AGENTS.md missing"
fi

# ═══════════════════════════════════════════════════════════════
# 7. Strategy files are non-empty and have meaningful content
# ═══════════════════════════════════════════════════════════════

for letter in S1 S2 S3 S4 S5 S6 S7 S8 REF; do
  file=$(strategy_file_for_letter "$letter")
  if [ -z "$file" ]; then
    fail "strategy $letter file mapping is empty"
    continue
  fi
  path="$STRATEGIES_DIR/$file"
  if [ ! -f "$path" ]; then
    fail "strategy $letter file not found: $path"
    continue
  fi
  size=$(wc -c < "$path" | tr -d ' ')
  if [ "$size" -gt 100 ]; then
    pass "strategy $letter has content (${size}B)"
  else
    fail "strategy $letter too small (${size}B)" "expected > 100 bytes"
  fi
done

# ═══════════════════════════════════════════════════════════════
# 9. session-rules.md has key workflow rules
# ═══════════════════════════════════════════════════════════════

rules="$REFERENCES_DIR/session-rules.md"
if [ -f "$rules" ]; then
  assert_file_contains "$rules" "coverage" "rules mention coverage"
  assert_file_contains "$rules" "testcase" "rules mention testcase"
  assert_file_contains "$rules" "ASan" "rules mention ASan"
  assert_file_contains "$rules" "guard" "rules mention guards"
else
  fail "session-rules.md missing"
fi

# ═══════════════════════════════════════════════════════════════
# 10. directory-lookup.md is retired
# ═══════════════════════════════════════════════════════════════

lookup="$REFERENCES_DIR/directory-lookup.md"
if [ ! -f "$lookup" ]; then
  pass "directory-lookup.md retired; subsystem candidates come from code/overlays"
else
  fail "directory-lookup.md should not exist" "target-specific subsystem priors belong in target overlays"
fi

# ═══════════════════════════════════════════════════════════════
# 11. S1 threshold is defined and greater than generic threshold
# ═══════════════════════════════════════════════════════════════

if [ -n "${STRATEGY_S1_DRY_STREAK_THRESHOLD:-}" ]; then
  pass "STRATEGY_S1_DRY_STREAK_THRESHOLD is defined"
else
  fail "STRATEGY_S1_DRY_STREAK_THRESHOLD not defined in test env"
fi

if [ "${STRATEGY_S1_DRY_STREAK_THRESHOLD:-0}" -gt "${STRATEGY_DRY_STREAK_THRESHOLD:-0}" ]; then
  pass "S1 threshold ($STRATEGY_S1_DRY_STREAK_THRESHOLD) > generic threshold ($STRATEGY_DRY_STREAK_THRESHOLD)"
else
  fail "S1 threshold should be greater than generic threshold" \
    "S1=$STRATEGY_S1_DRY_STREAK_THRESHOLD generic=$STRATEGY_DRY_STREAK_THRESHOLD"
fi

# ═══════════════════════════════════════════════════════════════
# 12. S6→S5 merge: S5 now contains state machine content (Class 4)
# ═══════════════════════════════════════════════════════════════

s5_file="$STRATEGIES_DIR/S5-reentrancy.md"
assert_file_contains "$s5_file" "Class 4.*State Machine" "S5 has Class 4 (state machine from old S6)"
assert_file_contains "$s5_file" "Class 1.*Re-entrancy" "S5 still has Class 1 (re-entrancy)"
assert_file_contains "$s5_file" "Class 2.*Error-Path" "S5 still has Class 2 (error paths)"
assert_file_contains "$s5_file" "Class 3.*Thread Race" "S5 still has Class 3 (races)"
assert_file_contains "$s5_file" "mState" "S5 state machine section has mState grep pattern"

# ═══════════════════════════════════════════════════════════════
# 13. Old S6 file (state-machine) must not exist
# ═══════════════════════════════════════════════════════════════

assert_file_not_exists "$STRATEGIES_DIR/S6-state-machine.md" "old S6-state-machine.md deleted"
assert_file_not_exists "$STRATEGIES_DIR/S7-cross-browser.md" "old S7-cross-browser.md deleted (renamed to S6)"
assert_file_not_exists "$STRATEGIES_DIR/S6-cross-browser.md" "old S6-cross-browser.md deleted (renamed to S6-cross-project)"
assert_file_not_exists "$STRATEGIES_DIR/S8-fuzz-improvement.md" "old S8-fuzz-improvement.md deleted (renamed to S7)"

# ═══════════════════════════════════════════════════════════════
# 14. Renumbered files have correct headings
# ═══════════════════════════════════════════════════════════════

assert_file_contains "$STRATEGIES_DIR/S6-cross-project.md" "Strategy S6" "S6 file heading says S6"
assert_file_contains "$STRATEGIES_DIR/S7-fuzz-improvement.md" "Strategy S7" "S7 file heading says S7"

# ═══════════════════════════════════════════════════════════════
# 15. S8 (property-based oracles) is a first-class strategy
# ═══════════════════════════════════════════════════════════════

assert_eq "S8-property-based.md" "$(strategy_file_for_letter S8)" "S8 → S8-property-based.md"

# ═══════════════════════════════════════════════════════════════
# 16. S7 (adversarial input) has required content sections
# ═══════════════════════════════════════════════════════════════

s7_file="$STRATEGIES_DIR/S7-fuzz-improvement.md"
assert_file_contains "$s7_file" "Part A.*Adversarial" "S7 has Part A (adversarial inputs)"
assert_file_contains "$s7_file" "Part B.*Seed" "S7 has Part B (seed engineering)"
assert_file_contains "$s7_file" "Truncation" "S7 covers truncation technique"
assert_file_contains "$s7_file" "Size issue" "S7 covers size issue in size/length fields"
assert_file_contains "$s7_file" "Encoding.*charset" "S7 covers encoding boundary cases"
assert_file_contains "$s7_file" "Format confusion" "S7 covers format confusion / polyglot"
assert_file_contains "$s7_file" "bin/probe" "S7 Part A uses normal ASan pipeline"
assert_file_contains "$s7_file" "Do NOT run the fuzzer yourself" "S7 warns against running browser fuzzers"

# ═══════════════════════════════════════════════════════════════
# 17. S8 (property-based oracles) has required content sections
# ═══════════════════════════════════════════════════════════════

s8_file="$STRATEGIES_DIR/S8-property-based.md"
assert_file_contains "$s8_file" "Strategy S8" "S8 file heading says S8"
assert_file_contains "$s8_file" "Category 1.*Inverse" "S8 Category 1 (inverse operations)"
assert_file_contains "$s8_file" "Category 2.*Idempotence" "S8 Category 2 (idempotence)"
assert_file_contains "$s8_file" "Category 3.*Injectivity" "S8 Category 3 (injectivity)"
assert_file_contains "$s8_file" "Category 4.*Numerical" "S8 Category 4 (numerical domain)"
assert_file_contains "$s8_file" "Category 5.*Format" "S8 Category 5 (format compliance)"
assert_file_contains "$s8_file" "generator step" "S8 covers the generator step"
assert_file_contains "$s8_file" "Hypothesis" "S8 mentions the Hypothesis library"
assert_file_contains "$s8_file" "proptest|QuickCheck" "S8 mentions proptest / QuickCheck"
assert_file_contains "$s8_file" "shrink" "S8 mentions shrinking"
assert_file_contains "$s8_file" "PROPERTY:" "S8 documents the PROPERTY header field"
assert_file_contains "$s8_file" "bin/probe" "S8 delivers through normal bin/probe pipeline"

# ═══════════════════════════════════════════════════════════════
# 18. No stale old filenames in strategy files or references
# ═══════════════════════════════════════════════════════════════

for f in "$STRATEGIES_DIR"/*.md "$REFERENCES_DIR"/*.md "$SCRIPT_ROOT/AGENTS.md"; do
  [ -f "$f" ] || continue
  if grep -qE 'S6-state-machine|S6-cross-browser|S7-cross-browser|S8-fuzz' "$f" 2>/dev/null; then
    fail "no stale filenames: $(basename "$f") references old file"
  fi
done
pass "no stale old filenames in strategy/reference files"

# ═══════════════════════════════════════════════════════════════
# 19. No shared directory lookup with target-specific priors
# ═══════════════════════════════════════════════════════════════

lookup="$REFERENCES_DIR/directory-lookup.md"
assert_file_not_exists "$lookup" "directory-lookup.md retired"

# ═══════════════════════════════════════════════════════════════
# 20. Strategy README matches the 8-strategy set
# ═══════════════════════════════════════════════════════════════

readme="$STRATEGIES_DIR/README.md"
assert_file_contains "$readme" "8 strategies" "README says 8 strategies"
assert_file_not_contains "$readme" "7 strategies " "README does not say 7 strategies (regression guard)"
assert_file_contains "$readme" "S7.*Adversarial" "README S7 row says adversarial"
assert_file_contains "$readme" "S8.*Property-based" "README S8 row says property-based"
assert_file_not_contains "$readme" "State machine sequences" "README has no old S6 row"

# AGENTS.md priority table must also list 8 strategies
assert_file_contains "$AGENTS_MD" "8 strategies" "AGENTS.md says 8 strategies"
assert_file_contains "$AGENTS_MD" "S8: Property-based" "AGENTS.md lists S8 in priority table"

# ═══════════════════════════════════════════════════════════════
# 21. S6 doc — 3-year time window
# ═══════════════════════════════════════════════════════════════

s6_file="$STRATEGIES_DIR/S6-cross-project.md"
assert_file_contains "$s6_file" "3 years" "S6 doc says 3 years"
assert_file_not_contains "$s6_file" "6.12 months" "S6 doc no stale 6-12 months window"
assert_file_not_contains "$s6_file" "12 months ago" "S6 doc no stale 12-months-ago since="
assert_file_not_contains "$s6_file" '\-d "-365"' "S6 doc no stale hg -365 day window"
assert_file_contains "$s6_file" "since=\"3 years ago\"" "S6 doc git --since 3 years"
assert_file_contains "$s6_file" '\-d "-1095"' "S6 doc hg -1095 day window (3 years)"

# ═══════════════════════════════════════════════════════════════
# 22. S6 doc — corrected jq filter and pagination note
# ═══════════════════════════════════════════════════════════════

assert_file_contains "$s6_file" '\.fixed // empty' "S6 jq drops null fix events"
assert_file_not_contains "$s6_file" '\.events\[\]?\.fixed\]\[0\]' \
  "S6 jq no longer uses naive [.events[]?.fixed][0]"
assert_file_contains "$s6_file" "next_page_token" "S6 doc covers OSV pagination"
assert_file_contains "$s6_file" "page_token" "S6 doc shows page_token re-POST"
assert_file_contains "$s6_file" '^CUTOFF=' "S6 OSV query defines CUTOFF variable"
assert_file_contains "$s6_file" 'select\(\(.modified' \
  "S6 OSV query filters on .modified time"

# ═══════════════════════════════════════════════════════════════
# 23. S6 doc — git show comment correctness
# ═══════════════════════════════════════════════════════════════

assert_file_contains "$s6_file" "\-\-name-only" \
  "S6 doc shows git show --name-only for files-only"
assert_file_not_contains "$s6_file" "\-\-stat   # files only" \
  "S6 doc no longer claims --stat is files-only"

# ═══════════════════════════════════════════════════════════════
# 24. S6 doc — GitHub /advisories framed as severity fallback
# ═══════════════════════════════════════════════════════════════

assert_file_contains "$s6_file" "Severity fallback" \
  "S6 doc reframes GitHub /advisories as severity fallback"
assert_file_contains "$s6_file" "database_specific" \
  "S6 doc mentions OSV database_specific severity"

# ═══════════════════════════════════════════════════════════════
# 25. S6 doc — directionality of mapping examples is explicit
# ═══════════════════════════════════════════════════════════════

assert_file_contains "$s6_file" "peer .* fix .*target" \
  "S6 doc spells out peer→target direction"
assert_file_contains "$s6_file" "cross-listed" \
  "S6 doc notes libwebp is cross-listed across image rows"

# ═══════════════════════════════════════════════════════════════
# 26. S6 STRATEGY_KEYWORDS regex — production-grade properties
# ═══════════════════════════════════════════════════════════════

# These properties are validated against the live regex by importing
# workqueue.py. We verify (a) classification still works for representative
# peer/cross-project terms, (b) no keyword is duplicated within S6's
# alternation, and (c) the regex does not falsely match unrelated text.
keyword_check=$(PYTHONPATH="$SCRIPT_ROOT/lib" python3 - <<'PY'
import re
import sys
import workqueue as wq

S6_pat, S6_weight = wq.STRATEGY_KEYWORDS["S6"]
src = S6_pat.pattern

# --- (a1) vocabulary-half must match on its own (no specific vendor) ---
# These exercise the industry-wide S6 vocabulary that lives hardcoded in
# the regex. Concrete peer/vendor names live only in output/<slug>/target.toml
# and are not part of classification.
vocab_match = [
    "found analogue in the X.509 parser",
    "peer-fix from last year",
    "cross-project mining of the lossless codec",
    "upstream advisory CVE-2024-12345",
    "same class in another parser",
    "oss-fuzz issue 12345 references this",
    "peer impl shares the same gap",
]
for text in vocab_match:
    if not S6_pat.search(text):
        print(f"FAIL: S6 vocabulary regression — did not match: {text!r}")
        sys.exit(2)

# --- (b) no duplicate alternation tokens within the S6 pattern ---
# Strip the outer (?:...) wrapper and split on '|' that aren't inside
# bracket groups. We walk char-by-char to honor escapes and [...].
def split_alts(p: str) -> list[str]:
    depth_paren = 0
    depth_brack = 0
    parts: list[str] = []
    buf: list[str] = []
    i = 0
    while i < len(p):
        c = p[i]
        if c == "\\" and i + 1 < len(p):
            buf.append(p[i:i+2])
            i += 2
            continue
        if c == "[":
            depth_brack += 1
        elif c == "]":
            depth_brack -= 1
        elif c == "(" and depth_brack == 0:
            depth_paren += 1
        elif c == ")" and depth_brack == 0:
            depth_paren -= 1
        if c == "|" and depth_paren == 0 and depth_brack == 0:
            parts.append("".join(buf))
            buf = []
            i += 1
            continue
        buf.append(c)
        i += 1
    parts.append("".join(buf))
    return parts

# Drop the leading `\b(?:` and trailing `)` from the pattern body.
m = re.match(r"^\\b\(\?:(.*)\)$", src, re.DOTALL)
if not m:
    print(f"FAIL: S6 pattern shape changed unexpectedly: {src!r}")
    sys.exit(2)
body = m.group(1)
alts = split_alts(body)

# Normalize: strip leading/trailing whitespace, drop empty.
norm = [a.strip() for a in alts if a.strip()]
seen: dict[str, int] = {}
for a in norm:
    seen[a] = seen.get(a, 0) + 1
dups = {k: v for k, v in seen.items() if v > 1}
if dups:
    print(f"FAIL: duplicate alternation tokens in S6 regex: {dups}")
    sys.exit(2)

# --- (c) negative matches: don't false-match unrelated terms ---
must_not_match = [
    "ordinary memcpy bug in this file",
    "MOZ_ASSERT failed at runtime",
    "lifetime issue in destructor",
    "spec compliance question",
    "firefox bug here",
    "the libressl patch",
]
for text in must_not_match:
    if S6_pat.search(text):
        print(f"FAIL: S6 regex falsely matched: {text!r}")
        sys.exit(2)

# Weight unchanged (S6 is weak signal).
if S6_weight != 1:
    print(f"FAIL: S6 weight changed: {S6_weight}")
    sys.exit(2)

print("ok")
PY
)
assert_eq "ok" "$keyword_check" "S6 STRATEGY_KEYWORDS regex: classifies, no dups, no false positives"

# ═══════════════════════════════════════════════════════════════
# 27. S8 STRATEGY_KEYWORDS regex — property categories classified
# ═══════════════════════════════════════════════════════════════

s8_keyword_check=$(PYTHONPATH="$SCRIPT_ROOT/lib" python3 - <<'PY'
import sys
import workqueue as wq

if "S8" not in wq.STRATEGY_KEYWORDS:
    print("FAIL: S8 not registered in STRATEGY_KEYWORDS")
    sys.exit(2)

S8_pat, S8_weight = wq.STRATEGY_KEYWORDS["S8"]

# Each of the 5 property categories from the blog must have at least
# one phrase that matches the regex. This is the canonical contract:
# if a category is mentioned in an agent's notes, S8 evidence counter
# must increment.
category_phrases = {
    "inverse":           ["round-trip serialization", "decode then encode again", "inverse operation on the parser"],
    "idempotence":       ["function is idempotent on canonical input", "idempotency check on normalize"],
    "injectivity":       ["collision resistance over 32-bit domain", "injective hash over the documented domain"],
    "numerical-domain":  ["numerical domain invariant violated", "output left the declared numerical bounds"],
    "format-compliance": ["format compliance regex on emitter", "URL format compliance check"],
}
for cat, phrases in category_phrases.items():
    for text in phrases:
        if not S8_pat.search(text):
            print(f"FAIL: S8 regex did not match '{cat}' phrase: {text!r}")
            sys.exit(2)

# Generator/tooling vocabulary the agent commonly uses in notes.
must_match = [
    "wrote a Hypothesis strategy for this domain",
    "used proptest with a custom shrinker",
    "ran a QuickCheck property over 10000 inputs",
    "fixed point not reached under canonicalization",
    "round-trip property failed at this boundary",
]
for text in must_match:
    if not S8_pat.search(text):
        print(f"FAIL: S8 regex did not match: {text!r}")
        sys.exit(2)

# Negative: do not falsely match unrelated language.
must_not_match = [
    "memcpy bounds bug in this parser",
    "MOZ_ASSERT failed in release",
    "thread race on the dispatch table",
    "spec says MUST reject",
    "JIT differential check via ion-eager",
]
for text in must_not_match:
    if S8_pat.search(text):
        print(f"FAIL: S8 regex falsely matched: {text!r}")
        sys.exit(2)

# Evidence weight: properties take real work, so S8 weight should be
# in the strong-signal band (>= 2) like S1/S2/S5/S7.
if S8_weight < 2:
    print(f"FAIL: S8 weight too low: {S8_weight} (expected >= 2)")
    sys.exit(2)

print("ok")
PY
)
assert_eq "ok" "$s8_keyword_check" "S8 STRATEGY_KEYWORDS regex: categories classified, no false positives, weight >= 2"

# ═══════════════════════════════════════════════════════════════
# 28. S8 wiring — bin/audit help, validation, prompt all mention S8
# ═══════════════════════════════════════════════════════════════

AUDIT_BIN="$SCRIPT_ROOT/bin/audit"
help_out=$("$AUDIT_BIN" --help 2>&1)
assert_match 'S1,S2,S3,S4,S5,S6,S7,S8' "$help_out" "bin/audit --strategy accepts S8"
PYTHONPATH="$SCRIPT_ROOT/lib" python3 - <<'PY'
import prompt
assert list(prompt._STRATEGIES) == ["S1", "S2", "S3", "S4", "S5", "S6", "S7", "S8", "REF"]
assert "Property oracle" in prompt.strategy_brief("S8", prompt.SCRIPT_ROOT / ".agents" / "references")
PY
assert_eq 0 $? "Python prompt strategy registry includes S8 and REF"

teardown_test_env
summary
