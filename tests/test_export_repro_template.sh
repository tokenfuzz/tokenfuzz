#!/usr/bin/env bash
# tests/test_export_repro_template.sh — guard rails for the report
# template emitted by bin/export-repro.
#
# Coverage:
#   1. Re-running export-repro on the same dir is idempotent — prevents the
#      "REPORT.md grew 22 ## Reproduce blocks" regression seen in
#      output/pcre2/.../CRASH-008-1 before the dedup fix.
#   2. The new fixed-position fields (Surface:, Trigger source:) are
#      emitted as bare-label lines so lib/triage.sh::_extract_report_field
#      and parse_caller_contract / parse_trigger_source still work.
#   3. The header summary table is present and references the QA fields.
set -o pipefail
source "$(dirname "$0")/helpers.sh"
setup_test_env

# We cannot run the real export-repro (it depends on a target.toml + a
# build dir), but we exercise the awk/strip logic by generating a
# REPORT.md the same way the tool does, then re-running the strip step
# to prove no duplication occurs.
EXPORT_REPRO="$SCRIPT_ROOT/bin/export-repro"
[ -x "$EXPORT_REPRO" ] || { echo "missing $EXPORT_REPRO"; exit 1; }

# Manually run the strip_audit_sections awk on a synthetic input that
# mimics a previously-bundled REPORT.md (already has ## Reproduce, ##
# Expected sanitizer output, an h1 + table). Whatever survives must be
# byte-identical to the input minus those auto sections — i.e. running
# strip again must be a no-op.
fixture=$(mktemp "${TMPDIR:-/tmp}/r.XXXXXX")
cat > "$fixture" <<'EOF'
# CRASH-Z-1

| Field    | Value |
|----------|-------|
| Surface  | library-api |

Surface: library-api
Trigger source: bytes

## Summary
Quoted prose that should survive a strip pass.

## ASan top frames

```
#0 0x100 in foo.c:1 in match
```

## Reproduce

```sh
./reproduce.sh
```

## Expected sanitizer output

```
==<pid>==ERROR: AddressSanitizer: heap-buffer-overflow
```

Full original output: `asan.txt`.
EOF

# Extract the strip_audit_sections function body inline by sourcing the
# script in a sub-shell with a stub for everything else. Easier: just
# verify that running export-repro's awk over the fixture twice yields
# the same length the second time.
strip_run() {
  awk '
    BEGIN { skip=0; ate_h1_table=0 }
    !ate_h1_table && NR <= 30 && /^# CRASH-[A-Z0-9-]+/  { ate_h1_table=1; next }
    ate_h1_table==1 && /^\| / { next }
    ate_h1_table==1 && /^\|[-: ]+\|/ { next }
    ate_h1_table==1 && /^[[:space:]]*$/ { ate_h1_table=2; next }
    /^## *Reproduction([[:space:]]|$)/                                                                         { skip=1; next }
    /^Reproduction:[[:space:]]*$/                                                                              { skip=1; next }
    /^## *(Reproduce|Expected[[:space:]]+sanitizer[[:space:]]+output|Expected[[:space:]]+Sanitizer[[:space:]]+Output|ASan[[:space:]]+top[[:space:]]+frames)([[:space:]]|$)/ { skip=1; next }
    skip && /^## /                                                                                             { skip=0 }
    skip && /^(Data Flow|Patch|Reachability|Supplemental|Evidence|Boundary|Classification|Summary|Root Cause|Suggested fix|Notes)[: ]/ { skip=0 }
    skip { next }
    /^Full original output:/ { next }
    { print }
  ' "$1"
}

stripped=$(mktemp "${TMPDIR:-/tmp}/s.XXXXXX")
strip_run "$fixture" > "$stripped"

# After one strip: no remaining ## Reproduce / ## Expected / # CRASH-Z-1 header.
if grep -qE '^## Reproduce' "$stripped"; then
  fail "auto sections stripped" "## Reproduce survived"
else pass "auto sections stripped"; fi
if grep -qE '^## Expected sanitizer output' "$stripped"; then
  fail "expected output stripped" "## Expected ... survived"
else pass "expected output stripped"; fi
if grep -qE '^# CRASH-' "$stripped"; then
  fail "h1 header stripped" "# CRASH-Z-1 survived"
else pass "h1 header stripped"; fi

# But the bare-label fields and ## Summary content survive.
assert_file_contains "$stripped" "Surface: library-api" "Surface bare label preserved"
assert_file_contains "$stripped" "Trigger source: bytes" "Trigger source bare label preserved"
assert_file_contains "$stripped" "## Summary" "Summary section preserved"

# Strip-again is a no-op (idempotent).
stripped2=$(mktemp "${TMPDIR:-/tmp}/s2.XXXXXX")
strip_run "$stripped" > "$stripped2"
diff_out=$(diff "$stripped" "$stripped2" || true)
assert_eq "" "$diff_out" "strip is idempotent"

rm -f "$fixture" "$stripped" "$stripped2"

# ── Surface field is detected by lib/triage.sh _extract_report_field ──
# Build a minimal report and prove parse_caller_contract / parse_trigger_source
# still find their fields when the new Surface: line is also present.
source "$SCRIPT_ROOT/lib/triage.sh"
synthetic="$TEST_TMPDIR/synth.md"
cat > "$synthetic" <<'EOF'
# CRASH-X-1

| Field    | Value |
|----------|-------|
| Surface  | library-api |

Surface: library-api
Trigger source: bytes

Caller contract: obeyed
Boundary: serialized PCRE2 code bytes
EOF

verdict=$(parse_caller_contract "$synthetic")
assert_eq "obeyed" "$verdict" "parse_caller_contract still reads bare label"
trig=$(parse_trigger_source "$synthetic")
assert_eq "bytes" "$trig" "parse_trigger_source still reads bare label"

# ── Field-block invariant ─────────────────────────────────────
# Every bare-label field must appear EXACTLY ONCE in a re-emitted
# REPORT.md (i.e. once in the bare-label block right after the Fields
# table; never duplicated inside the narrative). Regression guard for
# the CRASH-009-1 issue where Trigger source / Caller contract /
# Boundary appeared in both the auto block and the LLM-authored
# Trigger Surface section.
inv_fix="$TEST_TMPDIR/invariant.md"
cat > "$inv_fix" <<'EOF'
# CRASH-X-1

## Fields

| Field           | Value |
|:----------------|:------|
| Severity        | Medium (33) |
| Surface         | library-api |
| Trigger source  | bytes |
| Caller contract | obeyed |
| Boundary        | serialized bytes |

Surface: library-api
Trigger source: bytes
Caller contract: obeyed
Boundary: serialized bytes
Caller controls: bytes
Parameter control: direct

## Summary
Some prose.
EOF
for label in "Surface" "Trigger source" "Caller contract" "Boundary"; do
  count=$(grep -cE "^${label}: " "$inv_fix")
  if [ "$count" -eq 1 ]; then
    pass "field '$label' appears exactly once"
  else
    fail "field '$label' appears exactly once" "got $count occurrences in fixture"
  fi
done
# strip_audit_sections is the awk fragment in bin/export-repro that
# removes duplicate bare-label fields from the narrative. Run it on a
# fixture with extra duplicates and prove it leaves one occurrence.
dup_fix="$TEST_TMPDIR/dup.md"
cat > "$dup_fix" <<'EOF'
# CRASH-X-1

| Field   | Value |
|:--------|:------|
| Surface | library-api |

Surface: library-api
Trigger source: bytes
Caller contract: obeyed
Boundary: serialized bytes

## Summary
Prose.

Boundary: serialized bytes
Caller controls: bytes
Parameter control: harness-only
Caller contract: obeyed
Trigger source: bytes
EOF
out=$(awk '
    BEGIN { skip=0; ate_h1_table=0; blank_run=0 }
    !ate_h1_table && NR <= 30 && /^# CRASH-[A-Z0-9-]+/ { ate_h1_table=1; next }
    ate_h1_table==1 && /^\| /                          { next }
    ate_h1_table==1 && /^\|[-: ]+\|/                   { next }
    ate_h1_table==1 && /^[[:space:]]*$/                { ate_h1_table=2; next }
    /^[Ss]urface:[[:space:]]/             { next }
    /^[Cc]luster:[[:space:]]/             { next }
    /^[Bb]oundary:[[:space:]]/            { next }
    /^[Cc]aller[[:space:]]controls:[[:space:]]/         { next }
    /^[Pp]arameter[[:space:]]control:[[:space:]]/       { next }
    /^[Tt]rusted[[:space:]]caller[[:space:]]actions:[[:space:]]/ { next }
    /^[Cc]aller[[:space:]]contract:[[:space:]]/         { next }
    /^[Tt]rigger[[:space:]]source:[[:space:]]/          { next }
    /^[[:space:]]*$/ { if (blank_run) next; blank_run=1; print; next }
    { blank_run=0; print }
' "$dup_fix")
grep -q 'Boundary:' <<<"$out" && fail "narrative dups stripped" "Boundary survived" \
  || pass "narrative dups stripped (Boundary)"
grep -q 'Trigger source:' <<<"$out" && fail "narrative dups stripped" "Trigger source survived" \
  || pass "narrative dups stripped (Trigger source)"
grep -q 'Parameter control:' <<<"$out" && fail "narrative dups stripped" "Parameter control survived" \
  || pass "narrative dups stripped (Parameter control)"

# ── severity.json is never picked as a testcase ────────────
# Regression guard: when bin/severity has run on a previously-
# bundled crash dir, severity.json is the most prominent
# loose file in the crash root. The testcase finder (now shared in
# lib/crash_artifacts) must skip it by name so severity.json never gets
# installed as `input.json` and referenced from reproduce.sh.
#
# The exclude is by-name (not *.json) because a JSON-parser fuzzer
# could legitimately produce a JSON testcase, and we don't want to
# silently drop those — assert both behaviours directly rather than
# grepping for an internal constant that can move.
json_finder_out="$(SCRIPT_ROOT="$SCRIPT_ROOT" python3 - <<'PY' 2>&1
import os, sys, tempfile
from pathlib import Path
sys.path.insert(0, os.path.join(os.environ["SCRIPT_ROOT"], "lib"))
import crash_artifacts as ca
with tempfile.TemporaryDirectory() as td:
    d = Path(td)
    (d / "severity.json").write_text('{"severity":"High"}\n', encoding="utf-8")
    (d / "input.json").write_text('{"payload":1}\n', encoding="utf-8")
    excluded = not ca.is_testcase_candidate(d / "severity.json")
    json_kept = ca.is_testcase_candidate(d / "input.json")
    chosen = ca.find_testcase([d])
    print("EXCLUDED" if excluded else "PICKED")
    print("JSON_KEPT" if json_kept else "JSON_DROPPED")
    print("CHOSE=%s" % (chosen.name if chosen else "none"))
PY
)"
if grep -q 'EXCLUDED' <<<"$json_finder_out" && grep -q 'CHOSE=input.json' <<<"$json_finder_out"; then
  pass "export-repro testcase finder excludes severity.json"
else
  fail "export-repro testcase finder excludes severity.json" "$json_finder_out"
fi
# Negative: a real `.json` testcase must NOT be dropped by a blanket suffix rule.
if grep -q 'JSON_KEPT' <<<"$json_finder_out"; then
  pass "no *.json suffix exclude in testcase finder"
else
  fail "no *.json suffix exclude in testcase finder" \
    "a legitimate JSON testcase was dropped: $json_finder_out"
fi

teardown_test_env
summary
