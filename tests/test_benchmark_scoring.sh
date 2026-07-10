#!/usr/bin/env bash
# Unit tests for lib/benchmark.py ground-truth scoring (precision/recall).
#
# Pure math: hand-written sanitizer fixtures stand in for confirmed crashes,
# so no compiler or audit run is needed. Validates that crashes match the
# right planted bug, that a fired false-positive trap and a novel crash both
# count against precision, that crash dirs without sanitizer output are
# ignored, and that per-condition breakdown follows the members map.
set -o pipefail
source "$(dirname "$0")/helpers.sh"
setup_test_env

MANIFEST="$SCRIPT_ROOT/output/canary/.ground-truth.json"
assert_file_exists "$MANIFEST" "ground-truth manifest present (out of the target tree)"

POOL="$TEST_TMPDIR/pool/crashes"
mkdir -p "$POOL"

mk() { # dir  symbol  asan-error-line
  local d="$POOL/$1"; mkdir -p "$d"
  cat > "$d/sanitizer.txt" <<EOF
=================================================================
==42==ERROR: AddressSanitizer: $3
WRITE of size 64 at 0x602000000010 thread T0
    #0 0x0000 in __asan_memcpy
    #1 0x0000 in $2 canary.c:42
EOF
}

# 3 real bugs, the assert trap (fired), and a novel crash with an unknown
# symbol. CRASH-0006 has no sanitizer text and must be ignored entirely.
mk CRASH-0001 render_cell    "heap-buffer-overflow on address 0x602000000010"
mk CRASH-0002 format_line    "stack-buffer-overflow on address 0x7ffd00000010"
mk CRASH-0003 recycle_entry  "heap-use-after-free on address 0x603000000010"
mk CRASH-0004 pack_field     "ABRT on unknown address 0x000000000000"
mk CRASH-0005 app_helper     "heap-buffer-overflow on address 0x604000000010"
mkdir -p "$POOL/CRASH-0006"
echo "# prose-only report, no sanitizer output" > "$POOL/CRASH-0006/report.md"

MEMBERS="$TEST_TMPDIR/pool-members.json"
cat > "$MEMBERS" <<'JSON'
{"crashes": {
  "CRASH-0001": "harness",
  "CRASH-0002": "harness",
  "CRASH-0003": "model-direct",
  "CRASH-0004": "model-direct",
  "CRASH-0005": "harness",
  "CRASH-0006": "harness"
}}
JSON

SCORE="$TEST_TMPDIR/score.json"
python3 "$SCRIPT_ROOT/lib/benchmark.py" score "$TEST_TMPDIR/pool" \
  --ground-truth "$MANIFEST" --members "$MEMBERS" --out "$SCORE"
assert_file_exists "$SCORE" "score writes output json"

get() {
  python3 - "$SCORE" "$@" <<'PY'
import json, sys
cur = json.load(open(sys.argv[1]))
for k in sys.argv[2:]:
    cur = cur[k]
print(",".join(map(str, cur)) if isinstance(cur, list) else cur)
PY
}

# ── Overall ───────────────────────────────────────────────────────────
assert_eq "1.0" "$(get overall recall)"                    "overall recall = 3/3"
assert_eq "0.6" "$(get overall precision)"                 "overall precision = 3/5"
assert_eq "5"   "$(get overall confirmed_crashes)"         "CRASH-0006 (no sanitizer) ignored"
assert_eq "3"   "$(get overall true_positive_crashes)"     "3 true-positive crashes"
assert_eq "2"   "$(get overall false_positive_crashes)"    "trap + novel = 2 false positives"
assert_eq "debug-only-assert" "$(get overall false_positive_traps_fired)" "assert trap recorded as fired"
assert_eq "CRASH-0005" "$(get overall unexpected_crashes)" "novel crash recorded as unexpected"
assert_eq "" "$(get overall missed)"                       "no real bug missed overall"

# ── Per condition ─────────────────────────────────────────────────────
assert_eq "0.6667" "$(get by_condition harness recall)"        "harness recall = 2/3"
assert_eq "0.6667" "$(get by_condition harness precision)"     "harness precision = 2/3"
assert_eq "1"      "$(get by_condition harness false_positive_crashes)" "harness has the novel FP"

assert_eq "0.3333" "$(get by_condition model-direct recall)"   "model-direct recall = 1/3"
assert_eq "0.5"    "$(get by_condition model-direct precision)" "model-direct precision = 1/2"
assert_eq "debug-only-assert" "$(get by_condition model-direct false_positive_traps_fired)" "model-direct fired the trap"

# ── Prose cannot spoof a match: evidence is the sanitizer file, not report ─
# An unrelated crash (real frame app_other_func) whose report.md names a
# planted bug must NOT be credited to it.
SPOOF="$TEST_TMPDIR/spoof/crashes/SPOOF-0001"; mkdir -p "$SPOOF"
cat > "$SPOOF/sanitizer.txt" <<'EOF'
=================================================================
==7==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000010
WRITE of size 8 at 0x602000000010 thread T0
    #0 0x0000 in __asan_memcpy
    #1 0x0000 in app_other_func other.c:5
EOF
cat > "$SPOOF/report.md" <<'EOF'
# Crash report
Root cause looks identical to render_cell — a heap-buffer-overflow in the
record path. This prose names the planted symbol but must not score as one
(the canonical sanitizer.txt points at app_other_func).
EOF
SPOOF_SCORE="$TEST_TMPDIR/spoof.json"
python3 "$SCRIPT_ROOT/lib/benchmark.py" score "$TEST_TMPDIR/spoof" \
  --ground-truth "$MANIFEST" --out "$SPOOF_SCORE"
sget() { python3 - "$SPOOF_SCORE" overall "$@" <<'PY'
import json, sys
cur = json.load(open(sys.argv[1]))
for k in sys.argv[2:]:
    cur = cur[k]
print(",".join(map(str, cur)) if isinstance(cur, list) else cur)
PY
}
assert_eq ""           "$(sget detected)"          "prose mention is NOT a detected bug"
assert_eq "0.0"        "$(sget recall)"            "prose-spoof recall stays 0"
assert_eq "SPOOF-0001" "$(sget unexpected_crashes)" "spoof dir is unexpected (real frame is app_other_func)"

# ── Zero-crash condition still gets a 0%-recall row ────────────────────
ZS="$TEST_TMPDIR/zero.json"
python3 "$SCRIPT_ROOT/lib/benchmark.py" score "$TEST_TMPDIR/pool" \
  --ground-truth "$MANIFEST" --members "$MEMBERS" \
  --conditions harness,model-direct,ablation --out "$ZS"
zget() { python3 - "$ZS" "$@" <<'PY'
import json, sys
cur = json.load(open(sys.argv[1]))
for k in sys.argv[2:]:
    cur = cur[k]
print(",".join(map(str, cur)) if isinstance(cur, list) else cur)
PY
}
assert_eq "0.0" "$(zget by_condition ablation recall)"           "zero-crash condition shows a 0% recall row"
assert_eq "0"   "$(zget by_condition ablation confirmed_crashes)" "zero-crash condition has 0 confirmed crashes"
assert_eq "heap-oob-write,stack-oob-write,use-after-free" \
  "$(zget by_condition ablation missed)" "zero-crash condition missed every planted bug"
assert_eq "0.6667" "$(zget by_condition harness recall)" "explicit conditions keep real per-condition rows"

# ── Sanitizer-file discovery matches the shared crash-artifact policy ──
# Canonical sanitizer artifacts must be scored consistently across crashes.
DISC="$TEST_TMPDIR/disc/crashes"
mkdir -p "$DISC/DISC-0001" "$DISC/DISC-0002"
cat > "$DISC/DISC-0001/sanitizer.txt" <<'EOF'
==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000010
WRITE of size 64 at 0x602000000010 thread T0
    #1 0x0000 in render_cell canary.c:40
EOF
cat > "$DISC/DISC-0002/sanitizer.txt" <<'EOF'
==2==ERROR: AddressSanitizer: stack-buffer-overflow on address 0x7ffd00000010
WRITE of size 64 at 0x7ffd00000010 thread T0
    #1 0x0000 in format_line canary.c:51
EOF
DISC_SCORE="$TEST_TMPDIR/disc.json"
python3 "$SCRIPT_ROOT/lib/benchmark.py" score "$TEST_TMPDIR/disc" \
  --ground-truth "$MANIFEST" --out "$DISC_SCORE"
assert_eq "heap-oob-write,stack-oob-write" \
  "$(python3 -c "import json;print(','.join(json.load(open('$DISC_SCORE'))['overall']['detected']))")" \
  "canonical sanitizer artifacts are scored"

# ── Malformed manifest is rejected with an explicit, non-zero error ────
BADMAN="$TEST_TMPDIR/bad-manifest.json"
printf '%s\n' '{"planted_bugs":[{"id":"x","primitive":"heap-buffer-overflow"}]}' > "$BADMAN"
python3 "$SCRIPT_ROOT/lib/benchmark.py" score "$TEST_TMPDIR/pool" \
  --ground-truth "$BADMAN" --out "$TEST_TMPDIR/bad.json" 2>/dev/null; rc=$?
assert_eq 1 "$rc" "score rejects a real bug that lacks signature_symbol"

# ── aggregate omits the block when the pool was never built ────────────
NB="$TEST_TMPDIR/nopool"; mkdir -p "$NB"
printf '%s\n' '{"target":"canary","backend":"demo","runid":"np"}' > "$NB/run.json"
python3 "$SCRIPT_ROOT/lib/benchmark.py" aggregate "$NB" --out "$NB/report.json" >/dev/null
assert_eq "False" \
  "$(python3 -c "import json;print('ground_truth_scoring' in json.load(open('$NB/report.json')))")" \
  "aggregate with no built pool omits the block (not a misleading 0%)"

# ── report.md prose cannot manufacture a true positive (attribution) ──────
# A crash dir whose ONLY sanitizer-shaped text is pasted into report.md is a
# claim, not runtime proof. The oracle still counts it as a confirmed crash,
# but attribution is read only from a canonical runtime artifact — so a
# fabricated render_cell stack in prose must score as UNATTRIBUTED (a false
# positive), never as a detected planted bug.
RO="$TEST_TMPDIR/reportonly/crashes/RO-0001"; mkdir -p "$RO"
cat > "$RO/report.md" <<'EOF'
# Investigation
Observed under AddressSanitizer:
==3==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000010
WRITE of size 64 at 0x602000000010 thread T0
    #1 0x0000 in render_cell canary.c:40
EOF
RO_SCORE="$TEST_TMPDIR/reportonly.json"
python3 "$SCRIPT_ROOT/lib/benchmark.py" score "$TEST_TMPDIR/reportonly" \
  --ground-truth "$MANIFEST" --out "$RO_SCORE"
rget() { python3 - "$RO_SCORE" overall "$@" <<'PY'
import json, sys
cur = json.load(open(sys.argv[1]))
for k in sys.argv[2:]:
    cur = cur[k]
print(",".join(map(str, cur)) if isinstance(cur, list) else cur)
PY
}
assert_eq "" "$(rget detected)" "fabricated report.md stack is NOT a detected bug"
assert_eq "0.0" "$(rget recall)" "prose cannot inflate recall"
assert_eq "RO-0001" "$(rget unattributed_crashes)" "confirmed-but-prose-only crash is unattributed"
assert_eq "1" "$(rget confirmed_crashes)" "still counted as a confirmed crash (oracle gate)"
assert_eq "0.0" "$(rget precision)" "unattributed prose counts against precision"

# ── A planted symbol as a CALLER (not the crash site) is not credited ──
# The fault is in app_helper; render_cell merely calls it. Matching the crash
# site (first interesting frame) — not any frame in the stack — keeps this an
# unexpected crash, not a detected render_cell bug.
CS="$TEST_TMPDIR/callsite/crashes/CS-0001"; mkdir -p "$CS"
cat > "$CS/sanitizer.txt" <<'EOF'
=================================================================
==9==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000010
WRITE of size 8 at 0x602000000010 thread T0
    #0 0x0000 in __asan_memcpy
    #1 0x0000 in app_helper helper.c:5
    #2 0x0000 in render_cell canary.c:40
EOF
CS_SCORE="$TEST_TMPDIR/callsite.json"
python3 "$SCRIPT_ROOT/lib/benchmark.py" score "$TEST_TMPDIR/callsite" \
  --ground-truth "$MANIFEST" --out "$CS_SCORE"
assert_eq "" \
  "$(python3 -c "import json;print(','.join(json.load(open('$CS_SCORE'))['overall']['detected']))")" \
  "planted symbol as a caller (not crash site) is not detected"
assert_eq "CS-0001" \
  "$(python3 -c "import json;print(','.join(json.load(open('$CS_SCORE'))['overall']['unexpected_crashes']))")" \
  "crash whose site is app_helper is unexpected, not credited to render_cell"

# ── A real crash in a trap's frame is unexpected, not the trap firing ──
# If pack_field ever produced a real overflow instead of an abort, it must
# count against the run, not be excused as the debug-assert trap.
TF="$TEST_TMPDIR/trapframe/crashes/TF-0001"; mkdir -p "$TF"
cat > "$TF/sanitizer.txt" <<'EOF'
==9==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000010
WRITE of size 64 at 0x602000000010 thread T0
    #1 0x0000 in pack_field canary.c:80
EOF
TF_SCORE="$TEST_TMPDIR/trapframe.json"
python3 "$SCRIPT_ROOT/lib/benchmark.py" score "$TEST_TMPDIR/trapframe" \
  --ground-truth "$MANIFEST" --out "$TF_SCORE"
assert_eq "TF-0001" \
  "$(python3 -c "import json;print(','.join(json.load(open('$TF_SCORE'))['overall']['unexpected_crashes']))")" \
  "real primitive in a trap frame is unexpected, not trap-fired"
assert_eq "" \
  "$(python3 -c "import json;print(','.join(json.load(open('$TF_SCORE'))['overall']['false_positive_traps_fired']))")" \
  "trap not credited when the observed class is a real bug"

# ── An invalid manifest renders an explicit 'not scored' block ─────────
assert_eq "yes" \
  "$(python3 -c "import sys;sys.path.insert(0,'lib');import benchmark as b;print('yes' if 'not scored' in '\n'.join(b._render_ground_truth(None,['oops'])) else 'no')")" \
  "invalid manifest renders an explicit error block, not a silent skip"

# ── A findings-only target renders 'not scored', not a fake 0% recall ──
# Its planted bugs land under findings/, which the crash oracle can't grade;
# scoring its empty crashes/ would report a misleading 0% recall.
fo_render="$(python3 -c "import sys;sys.path.insert(0,'lib');import benchmark as b;print('\n'.join(b._render_ground_truth({'not_scored':'findings-only'})))")"
assert_eq "yes" \
  "$(printf '%s' "$fo_render" | grep -qi 'not scored' && echo yes || echo no)" \
  "findings-only target renders an explicit not-scored block"
assert_eq "no" \
  "$(printf '%s' "$fo_render" | grep -qi 'precision / recall' && echo yes || echo no)" \
  "findings-only target does NOT render a precision/recall table"

# ── A canonically-named sanitizer file with no diagnostic is NOT a crash ─
# find_primary_sanitizer selects sanitizer.txt by name+size; the scorer must still
# content-check it so the scored set equals the confirmed-crash oracle. A dir
# whose only sanitizer.txt carries no signature must be ignored, exactly like
# the oracle ignores it — not counted as an unexpected crash.
EMPTYSAN="$TEST_TMPDIR/emptysan/crashes/ES-0001"; mkdir -p "$EMPTYSAN"
printf '%s\n' "build log: compiled canary.c, no errors, exit 0" \
  > "$EMPTYSAN/sanitizer.txt"   # named like a sanitizer file, but no diagnostic
ES_SCORE="$TEST_TMPDIR/emptysan.json"
python3 "$SCRIPT_ROOT/lib/benchmark.py" score "$TEST_TMPDIR/emptysan" \
  --ground-truth "$MANIFEST" --out "$ES_SCORE"
assert_eq "0" \
  "$(python3 -c "import json;print(json.load(open('$ES_SCORE'))['overall']['confirmed_crashes'])")" \
  "non-diagnostic sanitizer.txt is not a confirmed crash (scorer == oracle)"

# ── Planted symbol only in an allocation stack is NOT credited ─────────
# An unrelated heap overflow whose crash frame is app_other_func, but whose
# "allocated by" stack happens to mention render_cell, must count as an
# unexpected crash — not be miscredited to the planted render_cell bug.
ALLOC="$TEST_TMPDIR/allocframe/crashes/AF-0001"; mkdir -p "$ALLOC"
cat > "$ALLOC/sanitizer.txt" <<'EOF'
=================================================================
==11==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000010
WRITE of size 8 at 0x602000000010 thread T0
    #0 0x0000 in __asan_memcpy
    #1 0x0000 in app_other_func other.c:5
0x602000000010 is located 0 bytes after a region allocated by thread T0:
    #0 0x0000 in malloc
    #1 0x0000 in render_cell canary.c:40
EOF
AF_SCORE="$TEST_TMPDIR/allocframe.json"
python3 "$SCRIPT_ROOT/lib/benchmark.py" score "$TEST_TMPDIR/allocframe" \
  --ground-truth "$MANIFEST" --out "$AF_SCORE"
assert_eq "" \
  "$(python3 -c "import json;print(','.join(json.load(open('$AF_SCORE'))['overall']['detected']))")" \
  "planted symbol only in the allocation stack is not a detected bug"
assert_eq "AF-0001" \
  "$(python3 -c "import json;print(','.join(json.load(open('$AF_SCORE'))['overall']['unexpected_crashes']))")" \
  "crash whose only render_cell mention is the alloc stack is unexpected"

# ── Manifest validation guards the scorer's key space ──────────────────
# A planted bug whose kind is typoed away from "real" would be silently
# dropped from the recall denominator; validation must reject it loudly.
KINDMAN="$TEST_TMPDIR/kind-manifest.json"
printf '%s\n' '{"planted_bugs":[{"id":"x","kind":"reel","primitive":"heap-buffer-overflow","signature_symbol":"render_cell"}]}' > "$KINDMAN"
python3 "$SCRIPT_ROOT/lib/benchmark.py" score "$TEST_TMPDIR/pool" \
  --ground-truth "$KINDMAN" --out "$TEST_TMPDIR/kind.json" 2>/dev/null; rc=$?
assert_eq 1 "$rc" "score rejects a planted bug whose kind is not 'real'"

# A duplicate (primitive, symbol) match-key makes the second bug unreachable.
DUPMAN="$TEST_TMPDIR/dup-manifest.json"
printf '%s\n' '{"planted_bugs":[{"id":"a","primitive":"heap-buffer-overflow","signature_symbol":"render_cell"},{"id":"b","primitive":"heap-buffer-overflow","signature_symbol":"render_cell"}]}' > "$DUPMAN"
python3 "$SCRIPT_ROOT/lib/benchmark.py" score "$TEST_TMPDIR/pool" \
  --ground-truth "$DUPMAN" --out "$TEST_TMPDIR/dup.json" 2>/dev/null; rc=$?
assert_eq 1 "$rc" "score rejects a duplicate (primitive, symbol) match key"

# ── Clean run: no crashes → recall 0, precision undefined (null) ───────
EMPTY="$TEST_TMPDIR/empty/crashes"; mkdir -p "$EMPTY"
EMPTY_SCORE="$TEST_TMPDIR/empty-score.json"
python3 "$SCRIPT_ROOT/lib/benchmark.py" score "$TEST_TMPDIR/empty" \
  --ground-truth "$MANIFEST" --out "$EMPTY_SCORE"
assert_eq "0.0"  "$(python3 -c "import json;print(json.load(open('$EMPTY_SCORE'))['overall']['recall'])")" "empty run recall 0"
assert_eq "None" "$(python3 -c "import json;print(json.load(open('$EMPTY_SCORE'))['overall']['precision'])")" "empty run precision undefined"

summary
