#!/usr/bin/env bash
# Tests for target-agnostic work cards, S1 patch cards, structured state, probe.
set -o pipefail
source "$(dirname "$0")/helpers.sh"
setup_test_env

RANK_WORK="$SCRIPT_ROOT/bin/rank-work"
PATCH_CARDS="$SCRIPT_ROOT/bin/patch-cards"
STATE="$SCRIPT_ROOT/bin/state"
PROBE="$SCRIPT_ROOT/bin/probe"

# Extract the "id" value from a JSON document without spawning python3
# (interpreter startup dominates this suite's wall time). jq keeps this
# structured: malformed JSON, a missing id, or trailing/multi-document
# stdout all surface as an empty or mismatching value instead of a regex
# guess, matching the old `python3 -c 'json.load(...)["id"]'` strictness.
json_id() {
  jq -r '.id // empty' <<<"$1"
}

# Replicate `bin/state init` (state dir + five empty jsonl stores) for
# fixture dirs where init itself is NOT the behavior under test — init is
# asserted once against $RESULTS_DIR below. Saves a bin/state startup per
# fixture dir.
mk_state_dir() {
  mkdir -p "$1/state"
  touch "$1/state/hypotheses.jsonl" "$1/state/runs.jsonl" \
        "$1/state/claims.jsonl" "$1/state/events.jsonl" "$1/state/notes.jsonl"
}

probe_help="$("$PROBE" --help)"
assert_match 'bin/probe .*--confirm.*--dry-run' "$probe_help" "probe help: lists confirm and dry-run"
assert_match 'TARGET: <file' "$probe_help" "probe help: documents TARGET header"
assert_match 'HYPOTHESIS-ID: H<n>' "$probe_help" "probe help: documents hypothesis header"
assert_match 'HARNESS: harness.c' "$probe_help" "probe help: documents HARNESS header"
assert_match 'PROBE_SANITIZER=asan\|ubsan\|msan\|tsan\|race\|runner' "$probe_help" \
  "probe help: documents sanitizer override"

mkdir -p \
  "$TARGET_ROOT/alpha/core" \
  "$TARGET_ROOT/beta/io" \
  "$TARGET_ROOT/delta/public" \
  "$TARGET_ROOT/epsilon/scan" \
  "$TARGET_ROOT/gamma/deep/path/more" \
  "$TARGET_ROOT/tests" \
  "$TARGET_ROOT/maint" \
  "$TARGET_ROOT/fuzz" \
  "$TARGET_ROOT/generated" \
  "$TARGET_ROOT/third_party/vendor/lib" \
  "$TARGET_ROOT/tools"

cat > "$TARGET_ROOT/alpha/core/ThingProcessor.cpp" <<'CPP'
#include <stdint.h>
#include <string.h>
bool ThingProcessorRead(const uint8_t* data, uint32_t len) {
  MOZ_ASSERT(data);
  uint8_t buf[16];
  if (len > 0) {
    memcpy(buf, data, len);
  }
  return len != 0;
}
CPP

cat > "$TARGET_ROOT/beta/io/plain.c" <<'C'
int helper(int x) {
  return x + 1;
}
C

cat > "$TARGET_ROOT/delta/public/api.c" <<'C'
#define DEMO_PUBLIC_API __attribute__((visibility("default")))
DEMO_PUBLIC_API int demo_public_decode_api(const unsigned char *data, unsigned long len) {
  return data && len > 0;
}
C

cat > "$TARGET_ROOT/epsilon/scan/matcher.c" <<'C'
int compile_pattern_for_matcher(const char *pattern, unsigned long len) {
  return pattern && len > 0;
}
C

cat > "$TARGET_ROOT/gamma/deep/path/more/plainlow.c" <<'C'
int plainlow(int x) {
  return x;
}
C

cat > "$TARGET_ROOT/maint/tool.c" <<'C'
#include <string.h>
void maint_tool(char *dst, const char *src, unsigned n) { memcpy(dst, src, n); }
C

cat > "$TARGET_ROOT/fuzz/regexp.c" <<'C'
#include <string.h>
void fuzz_entry(char *dst, const char *src, unsigned n) { memcpy(dst, src, n); }
C

cat > "$TARGET_ROOT/generated/table.c" <<'C'
#include <string.h>
void generated_table(char *dst, const char *src, unsigned n) { memcpy(dst, src, n); }
C

cat > "$TARGET_ROOT/third_party/vendor/lib/mirror.c" <<'C'
#include <string.h>
void vendored_mirror(char *dst, const char *src, unsigned n) { memcpy(dst, src, n); }
C

cat > "$TARGET_ROOT/tools/devtool.c" <<'C'
#include <string.h>
void dev_tool(char *dst, const char *src, unsigned n) { memcpy(dst, src, n); }
C

cat > "$TARGET_ROOT/testdict.c" <<'C'
#include <string.h>
void test_dict(char *dst, const char *src, unsigned n) { memcpy(dst, src, n); }
C

cat > "$TARGET_ROOT/harness11.c" <<'C'
#include <string.h>
void harness_entry(char *dst, const char *src, unsigned n) { memcpy(dst, src, n); }
C

cat > "$TARGET_ROOT/config.h" <<'H'
#define GENERATED_CONFIG_VALUE 1
H

# Python-language source: regression guard for the pyyaml bug where
# rank-work's hardcoded SOURCE_EXTS excluded .py and any Python target
# yielded zero work cards (queue exhausted on session 1). The new
# behaviour pulls extensions from lib/languages.py; this fixture asserts
# the union includes .py and the regex scorer fires on input-consumer
# entrypoints in pure Python files.
mkdir -p "$TARGET_ROOT/alpha/pylib"
cat > "$TARGET_ROOT/alpha/pylib/PyParser.py" <<'PY'
def PyParserDecode(data, length):
    assert data is not None
    buf = bytearray(16)
    if length > 0:
        buf[:length] = data[:length]
    return length != 0
PY

cat > "$RESULTS_DIR/patch-cards.jsonl" <<'JSONL'
{"id":"PATCH-local","kind":"s1-patch","target_slug":"testproject","touched_files":["alpha/core/ThingProcessor.cpp"],"score":70,"fix_hashes":["abc123"],"testcase_hashes":["def456"],"subsystem":"alpha/core","description":"local prior fix","reason":"test prior fix"}
{"id":"PATCH-maint-only","kind":"s1-patch","target_slug":"testproject","touched_files":["maint/tool.c"],"score":999,"fix_hashes":["badmaint"],"testcase_hashes":[],"subsystem":"maint","description":"maint: build fix for helper","reason":"maintenance"}
{"id":"PATCH-coverage","kind":"s1-patch","target_slug":"testproject","touched_files":["alpha/core/ThingProcessor.cpp"],"score":999,"fix_hashes":["badcoverage"],"testcase_hashes":[],"subsystem":"alpha/core","description":"Improvements to CI code coverage","reason":"coverage"}
JSONL

if command -v git >/dev/null 2>&1; then
  git_target="$TEST_TMPDIR/git-target"
  git_results="$TEST_TMPDIR/git-results"
  mkdir -p "$git_target/src" "$git_results"
  git -C "$git_target" init -q
  git -C "$git_target" config user.email "test@example.invalid"
  git -C "$git_target" config user.name "Test User"
  # Six commits, oldest first. The three OLDEST name a real defect class
  # (high score); the three NEWEST are bland churn (low score). A scan
  # window equal to the output limit would only ever see the newest
  # three and miss every real fix — exactly the firefox failure mode.
  _mkcommit() {  # subject  file  content
    printf '%s\n' "$3" > "$git_target/src/$2"
    git -C "$git_target" add "src/$2"
    git -C "$git_target" commit -q -m "$1"
  }
  _mkcommit "Fix out-of-bounds write in alpha" alpha.c   "int a;"
  _mkcommit "Fix use-after-free in beta"        beta.c    "int b;"
  _mkcommit "Fix integer overflow in gamma"     gamma.c   "int g;"
  _mkcommit "Adjust delta default settings"     delta.c   "int d;"
  _mkcommit "Update epsilon label strings"      epsilon.c "int e;"
  _mkcommit "Rework zeta accessor naming"       zeta.c    "int z;"

  # ── builds S1 cards from VCS log ──
  git_cards="$TEST_TMPDIR/git-patch-cards.jsonl"
  TARGET_ROOT="$git_target" TARGET_SLUG="git-target" TARGET_REPO_TYPE=git RESULTS_DIR="$git_results" \
    "$PATCH_CARDS" --limit 50 --inspect-commits 50 \
    --output "$git_cards" --quiet
  # ── scan window reaches fixes older than --limit ──
  # --limit 3 emits 3 cards; the 3 highest-scored commits are the 3
  # OLDEST (defect-keyword) commits. A window capped at --limit (the old
  # behaviour) could not see them — the decoupled window can.
  window_cards="$TEST_TMPDIR/git-window-cards.jsonl"
  TARGET_ROOT="$git_target" TARGET_SLUG="git-target" TARGET_REPO_TYPE=git RESULTS_DIR="$git_results" \
    "$PATCH_CARDS" --limit 3 --inspect-commits 50 \
    --output "$window_cards" --quiet

  # ── inspect budget targets highest-signal commit, not newest ──
  # Budget of 1 → exactly one commit_files lookup. It must land on a
  # defect-keyword commit (the three oldest), never on the newer churn.
  budget_cards="$TEST_TMPDIR/git-budget-cards.jsonl"
  TARGET_ROOT="$git_target" TARGET_SLUG="git-target" TARGET_REPO_TYPE=git RESULTS_DIR="$git_results" \
    "$PATCH_CARDS" --limit 50 --inspect-commits 1 \
    --output "$budget_cards" --quiet

  # The three read-only verifications run in ONE python invocation
  # (interpreter startup dominates); each check prints its own labeled
  # ok/failure line so the assertions below stay independent.
  git_checks=$(python3 - "$git_cards" "$window_cards" "$budget_cards" <<'PY'
import json
import sys
from pathlib import Path

def load(p):
    return [json.loads(line) for line in Path(p).read_text().splitlines() if line.strip()]

def check(label, fn):
    try:
        fn()
        print(f"{label}:ok")
    except AssertionError as exc:
        print(f"{label}:FAIL {exc}")

def vcs():
    cards = load(sys.argv[1])
    assert cards, "no patch cards produced from VCS log"
    card = next((c for c in cards if "alpha" in (c.get("description") or "").lower()), None)
    assert card, cards
    assert card["source"] == "vcs-log", card
    assert card["touched_files"] == ["src/alpha.c"], card
    assert card["fix_hashes"], card

def window():
    cards = load(sys.argv[2])
    files = {f for c in cards for f in c.get("touched_files", [])}
    assert "src/alpha.c" in files, files   # oldest commit, position 6 of 6
    assert "src/gamma.c" in files, files

def budget():
    cards = load(sys.argv[3])
    inspected = [c for c in cards if c.get("touched_files")]
    assert len(inspected) == 1, [c.get("touched_files") for c in cards]
    keyword = {"src/alpha.c", "src/beta.c", "src/gamma.c"}
    assert set(inspected[0]["touched_files"]) & keyword, inspected[0]
    churn = {"src/delta.c", "src/epsilon.c", "src/zeta.c"}
    for c in cards:
        assert not (set(c.get("touched_files", [])) & churn), c

check("vcs", vcs)
check("window", window)
check("budget", budget)
PY
)
  case "$git_checks" in *"vcs:ok"*) vcs_patch_cards=ok ;; *) vcs_patch_cards="$git_checks" ;; esac
  case "$git_checks" in *"window:ok"*) window_ok=ok ;; *) window_ok="$git_checks" ;; esac
  case "$git_checks" in *"budget:ok"*) budget_ok=ok ;; *) budget_ok="$git_checks" ;; esac
  assert_eq "ok" "$vcs_patch_cards" "patch-cards: builds S1 cards from VCS log"
  assert_eq "ok" "$window_ok" "patch-cards: scan window reaches fixes older than --limit"
  assert_eq "ok" "$budget_ok" "patch-cards: inspect budget targets highest-signal commit, not newest"

  # ── PATCH_SCAN_WINDOW / --scan-window cap the scan ──
  capped_cards="$TEST_TMPDIR/git-capped-cards.jsonl"
  PATCH_SCAN_WINDOW=2 TARGET_ROOT="$git_target" TARGET_SLUG="git-target" TARGET_REPO_TYPE=git RESULTS_DIR="$git_results" \
    "$PATCH_CARDS" --limit 50 --inspect-commits 50 \
    --output "$capped_cards" --quiet
  assert_eq 2 "$(grep -c . "$capped_cards" 2>/dev/null || echo 0)" \
    "patch-cards: PATCH_SCAN_WINDOW caps commits scanned"
  cli_cards="$TEST_TMPDIR/git-cli-window.jsonl"
  TARGET_ROOT="$git_target" TARGET_SLUG="git-target" TARGET_REPO_TYPE=git RESULTS_DIR="$git_results" \
    "$PATCH_CARDS" --limit 50 --inspect-commits 50 --scan-window 2 \
    --output "$cli_cards" --quiet
  assert_eq 2 "$(grep -c . "$cli_cards" 2>/dev/null || echo 0)" \
    "patch-cards: --scan-window flag caps commits scanned"

  # ── shallow-clone warning ──
  shallow_src="$TEST_TMPDIR/shallow-src"
  shallow_clone="$TEST_TMPDIR/shallow-clone"
  cp -R "$git_target" "$shallow_src"
  git clone -q --depth 1 "file://$shallow_src" "$shallow_clone" 2>/dev/null
  if [ -f "$shallow_clone/.git/shallow" ]; then
    shallow_out=$(TARGET_ROOT="$shallow_clone" TARGET_SLUG="shallow-target" TARGET_REPO_TYPE=git RESULTS_DIR="$git_results" \
      "$PATCH_CARDS" --limit 10 --output "$TEST_TMPDIR/shallow-cards.jsonl" --quiet 2>&1)
    assert_match 'shallow clone' "$shallow_out" "patch-cards: warns on shallow clone"
    assert_match 'fetch --unshallow' "$shallow_out" "patch-cards: shallow warning names the remedy"
  else
    pass "patch-cards: shallow-clone warning (shallow clone unavailable here)"
  fi
else
  pass "patch-cards: VCS patch-cards skipped (git unavailable)"
fi

# Two stateless workqueue unit checks share ONE python invocation (the
# workqueue import is the expensive part); each prints a labeled ok line
# so the two assertions below remain independent.
# 1) _patch_scan_window: a positive env knob is honoured verbatim (so the
#    scan can be deliberately narrowed); junk values fall back to default.
# 2) is_auditable_source_path: centralized bad-path exclusions (asserted
#    further below, next to the rank-work output checks it mirrors).
wq_unit_checks=$(PYTHONPATH="$SCRIPT_ROOT/lib" python3 - <<'PY'
import os
import workqueue as wq

def check(label, fn):
    try:
        fn()
        print(f"{label}:ok")
    except (AssertionError, SystemExit) as exc:
        print(f"{label}:FAIL {exc}")

def scan_window():
    assert wq._patch_scan_window(80) == 80 * 25, wq._patch_scan_window(80)
    os.environ["PATCH_SCAN_WINDOW"] = "500"
    assert wq._patch_scan_window(80) == 500, wq._patch_scan_window(80)
    os.environ["PATCH_SCAN_WINDOW"] = "10"        # honoured verbatim, even < limit
    assert wq._patch_scan_window(80) == 10, wq._patch_scan_window(80)
    os.environ["PATCH_SCAN_WINDOW"] = "bogus"     # non-numeric → default
    assert wq._patch_scan_window(80) == 80 * 25, wq._patch_scan_window(80)
    os.environ["PATCH_SCAN_WINDOW"] = "0"         # non-positive → default
    assert wq._patch_scan_window(80) == 80 * 25, wq._patch_scan_window(80)
    del os.environ["PATCH_SCAN_WINDOW"]

def policy():
    # Audit-scope set (lib/audit_scope.EXCLUDED_PATH_SEGMENTS) is narrow:
    # only doc/example/test/fuzz families exclude by directory name.
    # Test-shaped *file names* still exclude regardless of location.
    bad = [
        "fuzz/regexp.c",
        "testdict.c",
        "harness11.c",
        "src/pcre2test.c",
        "src/pcre2test_inc.h",
        "src/pcre2_fuzzsupport.c",
        "config.h",
    ]
    good = [
        "alpha/core/ThingProcessor.cpp",
        "beta/io/plain.c",
        "src/pcre2_compile.c",
        "parser.c",
        "third_party/vendor/lib/mirror.c",
        # Deliberately auditable now: vendored deps, tools, scripts,
        # build outputs, generated code, maintenance scripts.
        "maint/tool.c",
        "generated/table.c",
        "tools/devtool.c",
        "build/foo.c",
        "scripts/munge.c",
        "external/lib/bar.c",
    ]
    if any(wq.is_auditable_source_path(p) for p in bad):
        raise SystemExit("bad path accepted")
    if any(not wq.is_auditable_source_path(p) for p in good):
        raise SystemExit("good path rejected")

check("scan_window", scan_window)
check("policy", policy)
PY
)
case "$wq_unit_checks" in *"scan_window:ok"*) scan_window_check=ok ;; *) scan_window_check="$wq_unit_checks" ;; esac
case "$wq_unit_checks" in *"policy:ok"*) policy_check=ok ;; *) policy_check="$wq_unit_checks" ;; esac
assert_eq "ok" "$scan_window_check" "patch-cards: _patch_scan_window resolves the env knob"

# --limit must exceed the fixture's own size: 7 auditable files, each
# of which can legitimately fan out into companion cards (one per
# strategy its code features seed). A limit below files×(1+companions)
# silently truncates real source out of the queue.
compact_output=$(TARGET_ROOT="$TARGET_ROOT" RESULTS_DIR="$RESULTS_DIR" "$RANK_WORK" --limit 40 --summary-limit 3 2>&1)
assert_match 'rank-work: wrote [0-9]+ card\(s\)' "$compact_output" "rank-work: default stdout is a compact summary"
assert_match 'inspect with bin/state list-cards --limit N or rerun with --jsonl' "$compact_output" "rank-work: compact summary points at bounded inspection"
compact_lines=$(printf '%s\n' "$compact_output" | wc -l | tr -d ' ')
if [ "$compact_lines" -le 7 ]; then
  pass "rank-work: compact summary stays bounded (lines=$compact_lines)"
else
  fail "rank-work: compact summary emitted too many lines" "$compact_output"
fi

output=$(TARGET_ROOT="$TARGET_ROOT" RESULTS_DIR="$RESULTS_DIR" "$RANK_WORK" --limit 40 --jsonl 2>&1)
assert_file_exists "$RESULTS_DIR/work-cards.jsonl" "rank-work: writes default output"
first_card=$(sed -n '1p' "$RESULTS_DIR/work-cards.jsonl")
assert_match '"id": "PATCH-local"' "$first_card" "rank-work: prioritizes concrete S1 patch cards"
assert_match 'ThingProcessor.cpp' "$output" "rank-work: finds arbitrary target source"
assert_match '"kind": "s1-patch"' "$output" "rank-work: includes patch cards as first-class work"
assert_match 'input-consumption entrypoint|raw memory operation|asserted invariant' "$output" "rank-work: scores by code features"
assert_match 'exported API surface' "$output" "rank-work: scores exported API surfaces"
assert_not_match 'js/src|dom/|parser/html|image/decoders' "$output" "rank-work: no baked-in subsystem paths"
assert_match 'plainlow.c' "$output" "rank-work: diversity floor includes regex-undervalued source"
assert_match 'diversity floor' "$output" "rank-work: diversity floor is explicit"
assert_not_match 'PATCH-maint-only|PATCH-coverage' "$output" "rank-work: drops maintenance/coverage patch cards"
# After the lib/audit_scope simplification, only fuzz/ (one of the
# four canonical doc/example/test/fuzz families) still excludes by
# segment name. maint/, generated/, tools/ are auditable now —
# explicitly asserted via the matching `good` cases below.
assert_not_match 'fuzz/regexp\.c' "$output" "rank-work: excludes fuzz/ path cards"
assert_match 'maint/tool\.c' "$output" "rank-work: maint/ is auditable post-simplification"
assert_match 'generated/table\.c' "$output" "rank-work: generated/ is auditable post-simplification"
assert_match 'tools/devtool\.c' "$output" "rank-work: tools/ is auditable post-simplification"
assert_match 'third_party/vendor/lib/mirror\.c' "$output" "rank-work: allows vendored source path cards"
assert_not_match 'testdict\.c|harness11\.c|config\.h' "$output" "rank-work: excludes test harness and generated config root files"
assert_match 'PyParser\.py' "$output" "rank-work: includes Python sources (registry-driven SOURCE_EXTS)"

# rank-work must preserve recon-hypothesis cards across a refresh.
# lib/recon_to_cards.py seeds those separately into work-cards.jsonl; a
# plain overwrite on the next work-card refresh would strand every recon
# lead before it can be probed (the benchmark bug that drove findings to 0).
cat >> "$RESULTS_DIR/work-cards.jsonl" <<'JSONL'
{"id": "RECON-deadbeef-asan-S5", "kind": "recon-hypothesis", "strategy": "S5", "status": "unclaimed", "score": 55, "recon": {"id": "RECON-deadbeef", "confidence": "NEEDS-VERIFICATION"}}
JSONL
TARGET_ROOT="$TARGET_ROOT" RESULTS_DIR="$RESULTS_DIR" "$RANK_WORK" --limit 40 --quiet >/dev/null 2>&1
refreshed_cards=$(cat "$RESULTS_DIR/work-cards.jsonl")
assert_match '"id": "RECON-deadbeef-asan-S5"' "$refreshed_cards" \
  "rank-work: preserves recon-hypothesis cards across a refresh"
assert_match '"kind": "recon-hypothesis"' "$refreshed_cards" \
  "rank-work: recon-hypothesis kind survives re-rank"

# P7 (F): the new allowed_strategies field on a consolidated Promote
# recon card must survive a rank-work refresh. Without explicit
# preservation, the row-verbatim merge in bin/rank-work would have
# silently dropped any new fields, undoing the P7 consolidation.
# Use an isolated results dir so the injected Promote card doesn't
# contaminate the rest of the suite via P3 precedence (which would
# otherwise steal the next claim from the parent test fixture).
f_results="$TEST_TMPDIR/p7-rankwork-survival"
mkdir -p "$f_results/state"
: > "$f_results/state/claims.jsonl"
: > "$f_results/state/runs.jsonl"
: > "$f_results/state/events.jsonl"
: > "$f_results/state/notes.jsonl"
: > "$f_results/state/hypotheses.jsonl"
# Start from an empty work-cards file and inject only the Promote card;
# rank-work re-runs over the (empty) target tree and merges our seeded
# recon card from the existing file.
cat > "$f_results/work-cards.jsonl" <<'JSONL'
{"id": "RECON-cafebabe-asan", "kind": "recon-hypothesis", "strategy": "S7", "allowed_strategies": ["S5", "S7"], "status": "unclaimed", "score": 1000, "recon": {"id": "RECON-cafebabe", "confidence": "CONFIRMED-HIGH", "validator_verdict": "Promote"}}
JSONL
TARGET_ROOT="$TARGET_ROOT" RESULTS_DIR="$f_results" "$RANK_WORK" --limit 40 --quiet >/dev/null 2>&1
# One python reads back both preserved fields ("allowed|verdict").
preserved_pair=$(python3 -c "
import json
for line in open('$f_results/work-cards.jsonl'):
    line=line.strip()
    if not line: continue
    c = json.loads(line)
    if c.get('id') == 'RECON-cafebabe-asan':
        allowed = ','.join(c.get('allowed_strategies') or [])
        verdict = (c.get('recon') or {}).get('validator_verdict','')
        print(allowed + '|' + verdict)
        break
")
preserved_allowed=${preserved_pair%%|*}
preserved_verdict=${preserved_pair##*|}
assert_eq "S5,S7" "$preserved_allowed" \
  "F: rank-work refresh preserves allowed_strategies on Promote recon cards"
# Sanity belt: Promote-verdict survives too (the field that distinguishes
# precedence-eligible cards from ordinary recon cards).
assert_eq "Promote" "$preserved_verdict" \
  "F: rank-work refresh preserves recon.validator_verdict on Promote cards"

# rank-work must merge S6 peer-fix cards. bin/peer-fix-cards writes them
# to a separate s6-peer-cards.jsonl; without an explicit merge they are
# generated and then orphaned — never reaching work-cards.jsonl, so no
# agent can ever claim an S6 lead.
cat > "$RESULTS_DIR/s6-peer-cards.jsonl" <<'EOF'
{"id": "S6-PEER-abc123def456", "kind": "s6-peer-fix", "strategy": "S6", "status": "unclaimed", "score": 40, "file": "alpha/core/ThingProcessor.cpp", "peer_project": "somepeer", "bug_class": "bounds: peer fix"}
{"id": "S6-PEER-skipme000000", "kind": "not-an-s6-card", "strategy": "S6", "status": "unclaimed"}
EOF
TARGET_ROOT="$TARGET_ROOT" RESULTS_DIR="$RESULTS_DIR" "$RANK_WORK" --limit 40 --quiet >/dev/null 2>&1
s6_merged_cards=$(cat "$RESULTS_DIR/work-cards.jsonl")
assert_match '"id": "S6-PEER-abc123def456"' "$s6_merged_cards" \
  "rank-work: merges S6 peer-fix cards into the work queue"
assert_match '"kind": "s6-peer-fix"' "$s6_merged_cards" \
  "rank-work: s6-peer-fix kind survives the merge"
assert_not_match 'S6-PEER-skipme000000' "$s6_merged_cards" \
  "rank-work: non-s6-peer-fix kinds in the s6 file are ignored"
# Idempotent: a second refresh must not duplicate the merged S6 card.
TARGET_ROOT="$TARGET_ROOT" RESULTS_DIR="$RESULTS_DIR" "$RANK_WORK" --limit 40 --quiet >/dev/null 2>&1
s6_count=$(grep -c 'S6-PEER-abc123def456' "$RESULTS_DIR/work-cards.jsonl" || true)
assert_eq 1 "$s6_count" "rank-work: S6 merge is idempotent across refreshes"

mkdir -p "$RESULTS_DIR/coverage"
cat > "$RESULTS_DIR/coverage/edges-agent-1.journal" <<'EOF'
ThingProcessorRead|alpha/core/ThingProcessor.cpp:3
EOF
output=$(TARGET_ROOT="$TARGET_ROOT" RESULTS_DIR="$RESULTS_DIR" "$RANK_WORK" --limit 20 --llm-top-n 0 --jsonl 2>&1)
assert_match 'coverage gap subsystem' "$output" "rank-work: expands toward coverage-gap subsystems"

# (computed in the merged wq_unit_checks python invocation above)
assert_eq "ok" "$policy_check" "workqueue policy: centralized bad path exclusions"

jsonl_concurrency=$(PYTHONPATH="$SCRIPT_ROOT/lib" python3 - "$RESULTS_DIR/state/concurrent.jsonl" <<'PY'
import multiprocessing
import sys
from pathlib import Path

from workqueue import read_jsonl, update_jsonl, write_jsonl

try:
    multiprocessing.set_start_method("fork", force=True)
except RuntimeError:
    pass

path = Path(sys.argv[1])
write_jsonl(path, [])

def worker(i: int) -> None:
    def mutate(rows):
        rows.append({"i": i})
    update_jsonl(path, mutate)

procs = [multiprocessing.Process(target=worker, args=(i,)) for i in range(40)]
for proc in procs:
    proc.start()
for proc in procs:
    proc.join()
failed = [proc.exitcode for proc in procs if proc.exitcode]
if failed:
    raise SystemExit(f"child failures: {failed}")
rows = read_jsonl(path)
got = sorted(row["i"] for row in rows)
if got != list(range(40)):
    raise SystemExit(f"lost or duplicated rows: {got}")
leftovers = list(path.parent.glob(f".{path.name}.*.tmp"))
if leftovers:
    raise SystemExit(f"leftover tmp files: {leftovers}")
print("ok")
PY
)
assert_eq "ok" "$jsonl_concurrency" "workqueue JSONL: read-modify-write uses unique locked rewrites"

export LLM_DECIDE_MOCK_WORK_RERANK='{"cards":[{"id":"WORK-doesnotexist","boost":30,"reason":"ignored bad id"}]}'
output=$(TARGET_ROOT="$TARGET_ROOT" RESULTS_DIR="$RESULTS_DIR" "$RANK_WORK" --limit 40 --llm-top-n 10 --jsonl 2>&1)
assert_file_exists "$RESULTS_DIR/work-cards.jsonl" "rank-work: LLM rerank still writes output"
assert_not_match 'llm-rerank' "$output" "rank-work: LLM rerank ignores unknown IDs"
unset LLM_DECIDE_MOCK_WORK_RERANK

work_id=$(jq -r 'select(.kind=="ranked-source") | .id' "$RESULTS_DIR/work-cards.jsonl" | head -1)
export LLM_DECIDE_MOCK_WORK_RERANK="{\"cards\":[{\"id\":\"$work_id\",\"boost\":20,\"reason\":\"parser/state boundary\"}]}"
output=$(TARGET_ROOT="$TARGET_ROOT" RESULTS_DIR="$RESULTS_DIR" "$RANK_WORK" --limit 40 --llm-top-n 10 --jsonl 2>&1)
assert_match 'llm-rerank: parser/state boundary' "$output" "rank-work: LLM rerank annotates selected cards"
unset LLM_DECIDE_MOCK_WORK_RERANK

# Rerank memoization: an identical candidate set (same rendered prompt,
# same mock) must replay the cached boosts instead of re-invoking the
# decision engine — the engine call is a 10-20s LLM round-trip in real
# runs, paid at every iteration boundary before this cache existed.
export LLM_DECIDE_MOCK_WORK_RERANK="{\"cards\":[{\"id\":\"$work_id\",\"boost\":20,\"reason\":\"cached boundary\"}]}"
rerank_log="$TEST_TMPDIR/rerank-decisions.log"
rm -f "$rerank_log"
output=$(LLM_DECIDE_LOG="$rerank_log" TARGET_ROOT="$TARGET_ROOT" RESULTS_DIR="$RESULTS_DIR" \
  "$RANK_WORK" --limit 40 --llm-top-n 10 --jsonl 2>&1)
assert_match 'llm-rerank: cached boundary' "$output" "rank-work: rerank cache — first run annotates"
assert_file_exists "$RESULTS_DIR/state/.work-rerank-cache.json" "rank-work: rerank cache file written"
output=$(LLM_DECIDE_LOG="$rerank_log" TARGET_ROOT="$TARGET_ROOT" RESULTS_DIR="$RESULTS_DIR" \
  "$RANK_WORK" --limit 40 --llm-top-n 10 --jsonl 2>&1)
assert_match 'llm-rerank: cached boundary' "$output" "rank-work: rerank cache — repeat run still annotates"
rerank_calls=$(grep -c 'work_rerank MOCK' "$rerank_log" 2>/dev/null || true)
assert_eq 1 "$rerank_calls" "rank-work: identical candidate set hits the boost cache (one engine call, not two)"
unset LLM_DECIDE_MOCK_WORK_RERANK

# Malformed mock → llm_decide rejects → rerank short-circuits, cards unchanged.
export LLM_DECIDE_MOCK_WORK_RERANK='not json at all'
output=$(TARGET_ROOT="$TARGET_ROOT" RESULTS_DIR="$RESULTS_DIR" "$RANK_WORK" --limit 40 --llm-top-n 10 --jsonl 2>&1)
assert_not_match 'llm-rerank' "$output" "rank-work: malformed mock → no rerank annotation"
unset LLM_DECIDE_MOCK_WORK_RERANK

# DISABLE=1 + no mock → rerank short-circuits, cards unchanged.
output=$(LLM_DECIDE_DISABLE=1 TARGET_ROOT="$TARGET_ROOT" RESULTS_DIR="$RESULTS_DIR" \
  "$RANK_WORK" --limit 40 --llm-top-n 10 --jsonl 2>&1)
assert_not_match 'llm-rerank' "$output" "rank-work: DISABLE=1 → no rerank annotation"

batch_results="$TEST_TMPDIR/batch-results"
mkdir -p "$batch_results"
TARGET_ROOT="$TARGET_ROOT" RESULTS_DIR="$batch_results" "$RANK_WORK" \
  --target-path "$TARGET_ROOT" --target-slug "$TARGET_SLUG" --results-dir "$batch_results" \
  --limit 1 --llm-top-n 0 --quiet >/dev/null
# Setup-only state init (init itself is asserted on $RESULTS_DIR below):
# replicate init_state = state dir + five empty jsonl stores.
mk_state_dir "$batch_results"
IFS= read -r first_batch_line < "$batch_results/work-cards.jsonl"
first_batch_id=$(json_id "$first_batch_line")
WORK_CARD_ALLOW_NORUNS_DISCARD=1 \
"$STATE" --results-dir "$batch_results" --target-path "$TARGET_ROOT" --target-slug "$TARGET_SLUG" \
  update-card --card-id "$first_batch_id" --status discarded >/dev/null
if "$STATE" --results-dir "$batch_results" --target-path "$TARGET_ROOT" --target-slug "$TARGET_SLUG" \
    next-card --agent 1 --mode generic --peek >/dev/null 2>&1; then
  fail "batch queue: exhausted one-card batch has no eligible work" "next-card unexpectedly found work"
else
  pass "batch queue: exhausted one-card batch has no eligible work"
fi
TARGET_ROOT="$TARGET_ROOT" RESULTS_DIR="$batch_results" "$RANK_WORK" \
  --target-path "$TARGET_ROOT" --target-slug "$TARGET_SLUG" --results-dir "$batch_results" \
  --limit 5 --llm-top-n 0 --quiet >/dev/null
expanded_card=$("$STATE" --results-dir "$batch_results" --target-path "$TARGET_ROOT" --target-slug "$TARGET_SLUG" \
  next-card --agent 1 --mode generic --peek)
assert_match '"id": "(PATCH-|WORK-)' "$expanded_card" "batch queue: expanded rank window exposes new eligible work"

strategy_mode_results="$TEST_TMPDIR/strategy-mode-results"
mkdir -p "$strategy_mode_results/state"
: > "$strategy_mode_results/state/claims.jsonl"
: > "$strategy_mode_results/state/hypotheses.jsonl"
cat > "$strategy_mode_results/work-cards.jsonl" <<'JSONL'
{"id":"WORK-S1-JS","kind":"ranked-source","file":"lib/a.js","subsystem":"lib","strategy":"S1","mode":"js","score":50,"auditable":true}
{"id":"WORK-S7-JS","kind":"ranked-source","file":"lib/b.js","subsystem":"lib2","strategy":"S7","mode":"js","score":49,"auditable":true}
JSONL
strategy_js_card=$("$STATE" --results-dir "$strategy_mode_results" --target-path "$TARGET_ROOT" --target-slug "$TARGET_SLUG" \
  next-card --agent 1 --mode generic --strategy S7 --peek)
assert_match '"id": "WORK-S7-JS"' "$strategy_js_card" "state: generic agents can claim js-mode cards with matching strategy"
if "$STATE" --results-dir "$strategy_mode_results" --target-path "$TARGET_ROOT" --target-slug "$TARGET_SLUG" \
    next-card --agent 1 --mode generic --strategy S2 --peek >/dev/null 2>&1; then
  fail "state: strategy filter rejects mismatched cards" "next-card returned a non-S2 card"
else
  pass "state: strategy filter rejects mismatched cards"
fi

strategy_list=$("$STATE" --results-dir "$strategy_mode_results" --target-path "$TARGET_ROOT" --target-slug "$TARGET_SLUG" \
  list-cards --mode generic --strategy S7 --limit 0)
assert_match '"id": "WORK-S7-JS"' "$strategy_list" "state: list-cards can filter by strategy server-side"
assert_not_match '"id": "WORK-S1-JS"' "$strategy_list" "state: list-cards strategy filter avoids client grep"
assert_not_match '"fix_hashes": \[\]' "$strategy_list" "state: list-cards omits empty optional arrays"
strategy_shown=$("$STATE" --results-dir "$strategy_mode_results" --target-path "$TARGET_ROOT" --target-slug "$TARGET_SLUG" \
  show-card WORK-S7-JS)
assert_match '"fix_hashes": \[\]' "$strategy_shown" "state: show-card keeps full single-card detail"

subsystem_list=$("$STATE" --results-dir "$strategy_mode_results" --target-path "$TARGET_ROOT" --target-slug "$TARGET_SLUG" \
  list-cards --mode generic --subsystem lib2 --limit 0)
assert_match '"id": "WORK-S7-JS"' "$subsystem_list" "state: list-cards can filter by subsystem substring"
assert_not_match '"id": "WORK-S1-JS"' "$subsystem_list" "state: list-cards subsystem filter avoids unrelated rows"

contains_list=$("$STATE" --results-dir "$strategy_mode_results" --target-path "$TARGET_ROOT" --target-slug "$TARGET_SLUG" \
  list-cards --mode generic --contains b.js --limit 0)
assert_match '"id": "WORK-S7-JS"' "$contains_list" "state: list-cards can filter compact card text"
assert_not_match '"id": "WORK-S1-JS"' "$contains_list" "state: list-cards contains filter avoids unrelated rows"

"$STATE" --results-dir "$RESULTS_DIR" --target-path "$TARGET_ROOT" --target-slug "$TARGET_SLUG" init
assert_dir_exists "$RESULTS_DIR/state" "state: init creates state dir"
assert_file_exists "$RESULTS_DIR/state/notes.jsonl" "state: init creates notes store"

card=$("$STATE" --results-dir "$RESULTS_DIR" --target-path "$TARGET_ROOT" --target-slug "$TARGET_SLUG" \
  next-card --agent 1 --mode generic --role reproduce)
assert_match '"id": "(PATCH-|WORK-)' "$card" "state: claims next generic-compatible card"
card_id=$(json_id "$card")
assert_match '"expires_at":' "$(tail -1 "$RESULTS_DIR/state/claims.jsonl")" "state: card claim has a lease expiry"

shown_card=$("$STATE" --results-dir "$RESULTS_DIR" --target-path "$TARGET_ROOT" --target-slug "$TARGET_SLUG" \
  show-card "$card_id")
assert_match "\"id\": \"$card_id\"" "$shown_card" "state: show-card accepts positional card id"
assert_match '"why_ranked":' "$shown_card" "state: show-card emits compact ranking context"
assert_not_match 'usage: state' "$shown_card" "state: show-card does not fall through to argparse help"

shown_card_flag=$("$STATE" --results-dir "$RESULTS_DIR" --target-path "$TARGET_ROOT" --target-slug "$TARGET_SLUG" \
  show-card --card-id "$card_id" --mode generic)
assert_match "\"id\": \"$card_id\"" "$shown_card_flag" "state: show-card accepts --card-id"
show_card_src=$(awk '
  /^def show_work_card\(/ { in_func=1 }
  in_func { print }
  /^def list_work_cards\(/ { exit }
' "$SCRIPT_ROOT/lib/workqueue.py")
assert_match '_status_rows_by_card\(ctx, mode, cards=cards\)' "$show_card_src" \
  "state: show-card reuses preloaded work cards for status rows"
show_card_reads=$(grep -c 'read_jsonl(work_cards_path(ctx))' <<< "$show_card_src" || true)
assert_eq "1" "$show_card_reads" "state: show-card keeps one work-cards JSONL read"

explained_card=$("$STATE" --results-dir "$RESULTS_DIR" --target-path "$TARGET_ROOT" --target-slug "$TARGET_SLUG" \
  explain-card --card-id "$card_id")
assert_eq "$shown_card" "$explained_card" "state: explain-card is a show-card alias"

patch_only=$("$STATE" --results-dir "$RESULTS_DIR" --target-path "$TARGET_ROOT" --target-slug "$TARGET_SLUG" \
  show-card PATCH-maint-only)
assert_match '"id": "PATCH-maint-only"' "$patch_only" "state: show-card falls back to patch-cards.jsonl"
assert_match '"reason": "patch-card"' "$patch_only" "state: patch-card fallback is explicit"

listed_cards=$("$STATE" --results-dir "$RESULTS_DIR" --target-path "$TARGET_ROOT" --target-slug "$TARGET_SLUG" \
  list-cards --mode generic --limit 2)
listed_count=$(printf '%s\n' "$listed_cards" | grep -c '^{' || true)
assert_eq "2" "$listed_count" "state: list-cards honors --limit"
assert_match '"id": "(PATCH-|WORK-)' "$listed_cards" "state: list-cards emits compact JSONL cards"
assert_not_match '"why_ranked":' "$listed_cards" "state: list-cards default omits prose-heavy ranking detail"
assert_not_match 'usage: state' "$listed_cards" "state: list-cards does not fall through to argparse help"

verbose_cards=$("$STATE" --results-dir "$RESULTS_DIR" --target-path "$TARGET_ROOT" --target-slug "$TARGET_SLUG" \
  list-cards --mode generic --limit 2 --verbose)
assert_match '"why_ranked":' "$verbose_cards" "state: list-cards --verbose restores ranking detail"

contains_rank_reason=$("$STATE" --results-dir "$RESULTS_DIR" --target-path "$TARGET_ROOT" --target-slug "$TARGET_SLUG" \
  list-cards --mode generic --contains 'raw memory operation' --limit 1)
assert_match '"id": "(PATCH-|WORK-)' "$contains_rank_reason" "state: list-cards --contains still filters hidden ranking text"

eligible_cards=$("$STATE" --results-dir "$RESULTS_DIR" --target-path "$TARGET_ROOT" --target-slug "$TARGET_SLUG" \
  list-cards --mode generic --status eligible --limit 3)
assert_match '"reason": "eligible"' "$eligible_cards" "state: list-cards can filter by queue reason"

dumped_queue=$("$STATE" --results-dir "$RESULTS_DIR" --target-path "$TARGET_ROOT" --target-slug "$TARGET_SLUG" \
  dump-queue --mode generic --status eligible --limit 2)
dumped_count=$(printf '%s\n' "$dumped_queue" | grep -c '^{' || true)
assert_eq "2" "$dumped_count" "state: dump-queue alias honors --limit"
assert_match '"reason": "eligible"' "$dumped_queue" "state: dump-queue alias preserves list-cards filtering"
assert_not_match 'usage: state' "$dumped_queue" "state: dump-queue alias does not fall through to argparse help"
list_cards_src=$(awk '
  /^def list_work_cards\(/ { in_func=1 }
  in_func { print }
  /^def _markdown_cells\(/ { exit }
' "$SCRIPT_ROOT/lib/workqueue.py")
assert_match '_queue_status_row\(' "$list_cards_src" \
  "state: list-cards computes queue status lazily"
assert_not_match '_status_rows_by_card' "$list_cards_src" \
  "state: list-cards avoids eager status rows for every card"
list_card_reads=$(grep -c 'read_jsonl(work_cards_path(ctx))' <<< "$list_cards_src" || true)
assert_eq "1" "$list_card_reads" "state: list-cards keeps one work-cards JSONL read"

mkdir -p "$RESULTS_DIR/crashes/CRASH-900-1" "$RESULTS_DIR/findings/FIND-900-demo"
cat > "$RESULTS_DIR/crashes/CRASH-900-1/REPORT.md" <<'MD'
# CRASH-900-1

## Fields

| Field | Value |
| :-- | :-- |
| Primitive | heap-use-after-free |
| Surface | library-api — public API |
| Severity | Medium (42) |
| Crash site | demoCrash file.c:12 |
| Dedup frames | demoCrash file.c:12 -> caller file.c:44 |
| Cluster | CL-demo |

## Details
Large report body that agents should not read for queue triage.
MD
cat > "$RESULTS_DIR/crashes/CRASH-900-1/reproduce.sh" <<'SH'
#!/usr/bin/env sh
exit 0
SH
cat > "$RESULTS_DIR/findings/FIND-900-demo/report.md" <<'MD'
Cluster: FCL-demo
Dedup key: [llm] demo-key

# FIND-900 Demo

## Fields

| Field | Value |
| :-- | :-- |
| Surface | Public C API |
| Class | logic:validation-bypass |
| Severity | Low (21) |

## Classification
- **Location**: demo.c:demoValidate:99
MD
cat > "$RESULTS_DIR/findings/FIND-900-demo/repro.c" <<'C'
int main(void) { return 0; }
C

shown_crash=$("$STATE" --results-dir "$RESULTS_DIR" --target-path "$TARGET_ROOT" --target-slug "$TARGET_SLUG" \
  show-crash CRASH-900-1)
assert_match '"id": "CRASH-900-1"' "$shown_crash" "state: show-crash accepts positional crash id"
assert_match '"cluster": "CL-demo"' "$shown_crash" "state: show-crash emits cluster"
assert_match '"surface": "library-api"' "$shown_crash" "state: show-crash emits compact surface"
assert_match '"severity": "Medium \(42\)"' "$shown_crash" "state: show-crash emits severity"
assert_match '"location": "demoCrash file.c:12"' "$shown_crash" "state: show-crash emits crash location"
assert_match 'CRASH-900-1/reproduce.sh' "$shown_crash" "state: show-crash emits repro path"
assert_not_match 'Large report body' "$shown_crash" "state: show-crash does not dump report body"

listed_crashes=$("$STATE" --results-dir "$RESULTS_DIR" --target-path "$TARGET_ROOT" --target-slug "$TARGET_SLUG" \
  list-crashes --status OK --limit 1)
assert_match '"id": "CRASH-900-1"' "$listed_crashes" "state: list-crashes filters by status"
crash_lines=$(printf '%s\n' "$listed_crashes" | grep -c '^{' || true)
assert_eq "1" "$crash_lines" "state: list-crashes honors --limit"
listed_crashes_agent=$("$STATE" --results-dir "$RESULTS_DIR" --target-path "$TARGET_ROOT" --target-slug "$TARGET_SLUG" \
  list-crashes --agent 3 --status OK --limit 1)
assert_match '"id": "CRASH-900-1"' "$listed_crashes_agent" "state: list-crashes accepts legacy --agent filter"

missing_crash=$("$STATE" --results-dir "$RESULTS_DIR" --target-path "$TARGET_ROOT" --target-slug "$TARGET_SLUG" \
  show-crash CRASH-does-not-exist 2>&1 || true)
assert_match 'crash not found' "$missing_crash" "state: show-crash unknown id is friendly"

shown_finding=$("$STATE" --results-dir "$RESULTS_DIR" --target-path "$TARGET_ROOT" --target-slug "$TARGET_SLUG" \
  show-finding --finding-id FIND-900-demo)
assert_match '"id": "FIND-900-demo"' "$shown_finding" "state: show-finding accepts --finding-id"
assert_match '"cluster": "FCL-demo"' "$shown_finding" "state: show-finding emits cluster"
assert_match '"dedup": "\[llm\] demo-key"' "$shown_finding" "state: show-finding emits dedup key"
assert_match '"surface": "Public C API"' "$shown_finding" "state: show-finding emits surface"
assert_match '"location": "demo.c:demoValidate:99"' "$shown_finding" "state: show-finding emits location"
assert_match 'FIND-900-demo/repro.c' "$shown_finding" "state: show-finding emits repro path"
assert_not_match 'Large report body' "$shown_finding" "state: show-finding does not dump report body"

listed_findings=$("$STATE" --results-dir "$RESULTS_DIR" --target-path "$TARGET_ROOT" --target-slug "$TARGET_SLUG" \
  list-findings --status OK --limit 1)
assert_match '"id": "FIND-900-demo"' "$listed_findings" "state: list-findings filters by status"
finding_lines=$(printf '%s\n' "$listed_findings" | grep -c '^{' || true)
assert_eq "1" "$finding_lines" "state: list-findings honors --limit"
listed_findings_agent=$("$STATE" --results-dir "$RESULTS_DIR" --target-path "$TARGET_ROOT" --target-slug "$TARGET_SLUG" \
  list-findings --agent 3 --status OK --limit 1)
assert_match '"id": "FIND-900-demo"' "$listed_findings_agent" "state: list-findings accepts legacy --agent filter"

fresh_claim_next=$("$STATE" --results-dir "$RESULTS_DIR" --target-path "$TARGET_ROOT" --target-slug "$TARGET_SLUG" \
  next-card --agent 2 --mode generic --role reproduce --peek)
fresh_claim_next_id=$(json_id "$fresh_claim_next")
if [ "$fresh_claim_next_id" = "$card_id" ]; then
  fail "state: fresh claim lease blocks duplicate card assignment" "next-card returned freshly claimed card $card_id"
else
  pass "state: fresh claim lease blocks duplicate card assignment"
fi

printf '{"agent":"1","card_id":"%s","claimed_at":"2000-01-01T00:00:00Z","expires_at":"2000-01-01T01:00:00Z","mode":"generic","role":"reproduce","status":"claimed"}\n' "$card_id" >> "$RESULTS_DIR/state/claims.jsonl"
reclaimed=$("$STATE" --results-dir "$RESULTS_DIR" --target-path "$TARGET_ROOT" --target-slug "$TARGET_SLUG" \
  next-card --agent 2 --mode generic --role reproduce)
reclaimed_id=$(json_id "$reclaimed")
assert_eq "$card_id" "$reclaimed_id" "state: stale card claim lease does not hide work permanently"

blocked_card=$("$STATE" --results-dir "$RESULTS_DIR" --target-path "$TARGET_ROOT" --target-slug "$TARGET_SLUG" \
  update-card --agent 1 --card-id "$card_id" --status blocked --note "feature unavailable in this configured build" --json)
assert_match '"status": "blocked"' "$blocked_card" "state: records blocked card status"
after_block_next=$("$STATE" --results-dir "$RESULTS_DIR" --target-path "$TARGET_ROOT" --target-slug "$TARGET_SLUG" \
  next-card --agent 2 --mode generic --role reproduce --peek)
after_block_next_id=$(json_id "$after_block_next")
if [ "$after_block_next_id" = "$card_id" ]; then
  fail "state: blocked work card is not re-offered in same result set" "next-card returned blocked card $card_id"
else
  pass "state: blocked work card is not re-offered in same result set"
fi

hyp=$("$STATE" --results-dir "$RESULTS_DIR" --target-path "$TARGET_ROOT" --target-slug "$TARGET_SLUG" \
  add-hyp --agent 1 --card-id "$card_id" --hypothesis "issue in ThingProcessorRead" \
  --file "alpha/core/ThingProcessor.cpp:ThingProcessorRead:3" --input-shape "generic byte input" \
  --guard-gap "length check" --diagnostic bounds --strategy S7 --json)
assert_match '"status": "PENDING"' "$hyp" "state: adds hypothesis row"
hyp_id=$(json_id "$hyp")

printf '{"agent":"1","card_id":"%s","claimed_at":"2000-01-01T00:00:00Z","expires_at":"2000-01-01T01:00:00Z","mode":"generic","role":"reproduce","status":"claimed"}\n' "$card_id" >> "$RESULTS_DIR/state/claims.jsonl"
while_hyp_active=$("$STATE" --results-dir "$RESULTS_DIR" --target-path "$TARGET_ROOT" --target-slug "$TARGET_SLUG" \
  next-card --agent 2 --mode generic --role reproduce --peek)
while_hyp_active_id=$(json_id "$while_hyp_active")
if [ "$while_hyp_active_id" = "$card_id" ]; then
  fail "state: active hypothesis reserves work card" "next-card returned active hypothesis card $card_id"
else
  pass "state: active hypothesis reserves work card"
fi

python3 - "$RESULTS_DIR/work-cards.jsonl" "$card_id" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
active_id = sys.argv[2]
rows = [json.loads(l) for l in path.read_text().splitlines() if l.strip()]
active = next(r for r in rows if r["id"] == active_id)
dup = dict(active)
dup["id"] = "WORK-DUPLICATE-SURFACE"
dup["score"] = int(active.get("score", 0)) + 1000
dup["status"] = "unclaimed"
path.write_text("\n".join(json.dumps(r, sort_keys=True) for r in [dup, *rows]) + "\n")
PY
surface_claim_next=$("$STATE" --results-dir "$RESULTS_DIR" --target-path "$TARGET_ROOT" --target-slug "$TARGET_SLUG" \
  next-card --agent 2 --mode generic --role reproduce --peek)
surface_claim_next_id=$(json_id "$surface_claim_next")
if [ "$surface_claim_next_id" = "WORK-DUPLICATE-SURFACE" ]; then
  fail "state: active hypothesis reserves duplicate file surface" "next-card returned duplicate surface"
else
  pass "state: active hypothesis reserves duplicate file surface"
fi

run=$("$STATE" --results-dir "$RESULTS_DIR" --target-path "$TARGET_ROOT" --target-slug "$TARGET_SLUG" \
  add-run --agent 1 --hypothesis-id "$hyp_id" --card-id "$card_id" --mode generic \
  --testcase "$RESULTS_DIR/scratch-1/tc.input" --asan-output "$RESULTS_DIR/scratch-1/tc.asan.txt" \
  --verdict CLEAN --json)
assert_match '"verdict": "CLEAN"' "$run" "state: records run row"

note=$("$STATE" --results-dir "$RESULTS_DIR" --target-path "$TARGET_ROOT" --target-slug "$TARGET_SLUG" \
  add-note --agent 1 --hypothesis-id "$hyp_id" --card-id "$card_id" --kind data-flow \
  --text "ThingProcessorRead copies input-shaped length into a fixed buffer" --json)
assert_match '"kind": "data-flow"' "$note" "state: records structured note"
assert_match "$hyp_id" "$note" "state: note links to hypothesis"

compat_hyp=$("$STATE" --results-dir "$RESULTS_DIR" --target-path "$TARGET_ROOT" --target-slug "$TARGET_SLUG" \
  add-hyp --agent 1 --card-id "$card_id" --hypothesis "legacy flag shape" \
  --file "alpha/core/Legacy.cpp" --function "LegacyRead" --line 9 \
  --input-shape "legacy byte input" --guard-gap "legacy guard" \
  --expected-diagnostic bounds --strategy S1 --json)
assert_match '"diagnostic": "bounds"' "$compat_hyp" "state: add-hyp accepts --expected-diagnostic alias"
assert_match 'alpha/core/Legacy.cpp:LegacyRead:9' "$compat_hyp" "state: add-hyp folds legacy function/line flags into file"

compat_note=$("$STATE" --results-dir "$RESULTS_DIR" --target-path "$TARGET_ROOT" --target-slug "$TARGET_SLUG" \
  add-note --agent 1 --card-id "$card_id" --kind working-context \
  --text "legacy context note without hypothesis id" --json)
assert_match '"kind": "context"' "$compat_note" "state: add-note maps working-context to context"

compat_validation_note=$("$STATE" --results-dir "$RESULTS_DIR" --target-path "$TARGET_ROOT" --target-slug "$TARGET_SLUG" \
  add-note --agent 1 --hypothesis-id "$hyp_id" --card-id "$card_id" --kind validation \
  --text "legacy validation note kind" --json)
assert_match '"kind": "validation"' "$compat_validation_note" "state: add-note accepts validation note kind"

compat_update=$("$STATE" --results-dir "$RESULTS_DIR" --target-path "$TARGET_ROOT" --target-slug "$TARGET_SLUG" \
  update-hyp "$hyp_id" --agent 1 --status INVESTIGATING --reason "legacy reason alias" --json)
assert_match '"status": "INVESTIGATING"' "$compat_update" "state: update-hyp accepts positional id"
assert_match 'legacy reason alias' "$compat_update" "state: update-hyp maps --reason to note"

# Anti-fabrication gate: update-card --status discarded must refuse before
# the runs.jsonl trail meets the floor (default 2 runs + 1 hypothesis).
# We only logged one run above, so this attempt should be rejected.
refuse_out=$("$STATE" --results-dir "$RESULTS_DIR" --target-path "$TARGET_ROOT" --target-slug "$TARGET_SLUG" \
  update-card --agent 1 --card-id "$card_id" --status discarded --note "premature" 2>&1 || true)
assert_match 'refuses discard' "$refuse_out" "state: discard refused with insufficient run trail"
assert_not_match "\"status\": \"discarded\"" "$(tail -1 "$RESULTS_DIR/state/claims.jsonl")" "state: refused discard does not enter claims"

# Add more evidence so the stricter production discard floor is met, then
# discard succeeds. The mutators themselves (add-run/add-hyp/add-note) are
# exercised above; this is pure setup, so append rows directly in the exact
# shape lib/workqueue's add_run/add_hypothesis/add_note write — zero forks
# instead of four bin/state startups.
second_hyp_id="H-2nd0000001"
printf '{"id": "%s", "agent": "1", "card_id": "%s", "hypothesis": "ThingProcessorClose frees during callback", "file": "alpha/core/ThingProcessor.cpp:close:88", "input_shape": "callback closes owner", "guard_gap": "state flag checked after callback", "diagnostic": "lifetime", "strategy": "S5", "status": "PENDING", "created_at": "2026-06-01T00:00:01Z", "updated_at": "2026-06-01T00:00:01Z"}\n' \
  "$second_hyp_id" "$card_id" >> "$RESULTS_DIR/state/hypotheses.jsonl"
printf '{"id": "NOTE-2nd000001", "agent": "1", "hypothesis_id": "%s", "card_id": "%s", "kind": "data-flow", "text": "ThingProcessorRead copies into callback-owned state before close", "created_at": "2026-06-01T00:00:01Z"}\n' \
  "$second_hyp_id" "$card_id" >> "$RESULTS_DIR/state/notes.jsonl"
{
  printf '{"id": "RUN-floor00001", "agent": "1", "hypothesis_id": "%s", "card_id": "%s", "mode": "generic", "testcase": "%s/scratch-1/tc.input", "testcase_sha1": "", "asan_output": "%s/scratch-1/tc.asan.txt", "verdict": "CLEAN", "asan_runs": 1, "created_at": "2026-06-01T00:00:01Z"}\n' \
    "$hyp_id" "$card_id" "$RESULTS_DIR" "$RESULTS_DIR"
  printf '{"id": "RUN-floor00002", "agent": "1", "hypothesis_id": "%s", "card_id": "%s", "mode": "generic", "testcase": "%s/scratch-1/tc2.input", "testcase_sha1": "", "asan_output": "%s/scratch-1/tc2.asan.txt", "verdict": "CLEAN", "asan_runs": 1, "created_at": "2026-06-01T00:00:02Z"}\n' \
    "$second_hyp_id" "$card_id" "$RESULTS_DIR" "$RESULTS_DIR"
} >> "$RESULTS_DIR/state/runs.jsonl"
card_update=$("$STATE" --results-dir "$RESULTS_DIR" --target-path "$TARGET_ROOT" --target-slug "$TARGET_SLUG" \
  update-card --agent 1 --card-id "$card_id" --status discarded --note "variants clean" --json)
assert_match '"status": "discarded"' "$card_update" "state: updates card status"
assert_match "$card_id" "$(tail -1 "$RESULTS_DIR/state/claims.jsonl")" "state: card status appended to claims"
compat_discard_card=$("$STATE" --results-dir "$RESULTS_DIR" --target-path "$TARGET_ROOT" --target-slug "$TARGET_SLUG" \
  update-card --agent 1 --card-id "$card_id" --status DISCARDED --note "legacy uppercase discard" --json)
assert_match '"status": "discarded"' "$compat_discard_card" "state: update-card normalizes uppercase terminal statuses"
compat_find_card=$("$STATE" --results-dir "$RESULTS_DIR" --target-path "$TARGET_ROOT" --target-slug "$TARGET_SLUG" \
  update-card --agent 1 --card-id "$card_id" --status FIND-123 --note "promoted finding" --json)
assert_match '"status": "find"' "$compat_find_card" "state: update-card maps FIND-* status to find"
assert_match 'artifact=FIND-123' "$compat_find_card" "state: update-card preserves mapped FIND-* artifact id in note"
compat_env_card=$("$STATE" --results-dir "$RESULTS_DIR" --target-path "$TARGET_ROOT" --target-slug "$TARGET_SLUG" \
  update-card --agent 1 --card-id "$card_id" --status ENV-BLOCKED --note "legacy env block" --json)
assert_match '"status": "blocked"' "$compat_env_card" "state: update-card maps ENV-BLOCKED to blocked"
compat_mode_card=$("$STATE" --results-dir "$RESULTS_DIR" --target-path "$TARGET_ROOT" --target-slug "$TARGET_SLUG" \
  update-card --agent 1 --card-id "$card_id" --status mode-incompatible:asan --note "legacy mode wall" --json)
assert_match '"status": "blocked"' "$compat_mode_card" "state: update-card maps mode-incompatible:* to blocked"
compat_reason_card=$("$STATE" --results-dir "$RESULTS_DIR" --target-path "$TARGET_ROOT" --target-slug "$TARGET_SLUG" \
  update-card --agent 1 --card-id "$card_id" --status blocked --reason "legacy card reason alias" --json)
assert_match '"status": "blocked"' "$compat_reason_card" "state: update-card accepts --reason alias"
assert_match 'legacy card reason alias' "$compat_reason_card" "state: update-card maps --reason to note"
compat_pos_card=$("$STATE" --results-dir "$RESULTS_DIR" --target-path "$TARGET_ROOT" --target-slug "$TARGET_SLUG" \
  update-card "$card_id" --agent 1 --status done --note "legacy positional card id" --json)
assert_match '"status": "done"' "$compat_pos_card" "state: update-card accepts positional card id"

# ─────────────────────────────────────────────────────────────────────
# Terse OK-line default for state mutators.
#
# The agent's own arguments are already in its conversation context, so
# re-echoing the full JSON row on every add-hyp/update-hyp/update-card/
# add-note/add-run wastes tokens. The default output is now a single
# line carrying the fields the agent CANNOT derive client-side:
# server-assigned ids and the server-normalized status (which differs
# from the agent's argument for CRASH-*/FIND-*/ENV-BLOCKED inputs and
# would otherwise be silently lost). Pass `--json` to opt back into the
# full row when a parser needs it; the JSON form is unchanged.
#
# Uses a dedicated results dir so the extra rows do not contaminate
# count-based assertions later in this file (recent-hyps / recent-runs).
# ─────────────────────────────────────────────────────────────────────
ok_results="$TEST_TMPDIR/ok-line-defaults"
mkdir -p "$ok_results/scratch-1"
: > "$ok_results/scratch-1/tc.input"
: > "$ok_results/scratch-1/tc.asan.txt"
mk_state_dir "$ok_results"
ok_card_id="PATCH-okline"
ok_hyp=$("$STATE" --results-dir "$ok_results" --target-path "$TARGET_ROOT" --target-slug "$TARGET_SLUG" \
  add-hyp --agent 1 --card-id "$ok_card_id" --hypothesis "ok-default check" \
  --file "alpha/core/ThingProcessor.cpp:ok:1" --input-shape "x" --guard-gap "y" \
  --diagnostic bounds --strategy S1)
assert_match '^OK: add-hyp id=H-[0-9a-f]{10} card='"$ok_card_id"' strategy=S1 status=PENDING file=' "$ok_hyp" \
  "state: add-hyp default emits terse OK line with id+card+strategy+status+file"
assert_not_match '"hypothesis":' "$ok_hyp" \
  "state: add-hyp default does NOT re-echo the full JSON row"
ok_hyp_id=$(printf '%s\n' "$ok_hyp" | sed -nE 's/.*id=(H-[0-9a-f]+).*/\1/p')
assert_match '^H-[0-9a-f]{10}$' "$ok_hyp_id" "state: OK line id is parseable"

ok_update=$("$STATE" --results-dir "$ok_results" --target-path "$TARGET_ROOT" --target-slug "$TARGET_SLUG" \
  update-hyp "$ok_hyp_id" --agent 1 --status DISCARDED --note "ok-default check")
assert_match '^OK: update-hyp id='"$ok_hyp_id"' status=DISCARDED' "$ok_update" \
  "state: update-hyp default emits terse OK line with id+status"

ok_note=$("$STATE" --results-dir "$ok_results" --target-path "$TARGET_ROOT" --target-slug "$TARGET_SLUG" \
  add-note --agent 1 --hypothesis-id "$ok_hyp_id" --card-id "$ok_card_id" --kind guard \
  --text "ok-default")
assert_match '^OK: add-note id=NOTE-[0-9a-f]{10} kind=guard hyp='"$ok_hyp_id" "$ok_note" \
  "state: add-note default emits terse OK line"

ok_run=$("$STATE" --results-dir "$ok_results" --target-path "$TARGET_ROOT" --target-slug "$TARGET_SLUG" \
  add-run --agent 1 --hypothesis-id "$ok_hyp_id" --card-id "$ok_card_id" --mode generic \
  --testcase "$ok_results/scratch-1/tc.input" --asan-output "$ok_results/scratch-1/tc.asan.txt" \
  --verdict CLEAN)
assert_match '^OK: add-run id=RUN-[0-9a-f]{10} verdict=CLEAN hyp='"$ok_hyp_id" "$ok_run" \
  "state: add-run default emits terse OK line"

# update-card MUST surface the server-normalized status in the OK line
# (CRASH-* / FIND-* / ENV-BLOCKED / mode-incompatible:* inputs get rewritten);
# without this the agent loses the only signal that normalization happened.
ok_card=$("$STATE" --results-dir "$ok_results" --target-path "$TARGET_ROOT" --target-slug "$TARGET_SLUG" \
  update-card --agent 1 --card-id "$ok_card_id" --status FIND-OK --note "ok-default")
assert_match '^OK: update-card card='"$ok_card_id"' status=find ' "$ok_card" \
  "state: update-card OK line carries server-normalized status (FIND-* → find)"
assert_match 'artifact=FIND-OK' "$ok_card" \
  "state: update-card OK line carries pre-normalization artifact in note"

ok_card_env=$("$STATE" --results-dir "$ok_results" --target-path "$TARGET_ROOT" --target-slug "$TARGET_SLUG" \
  update-card --agent 1 --card-id "$ok_card_id" --status ENV-BLOCKED --note "ok-default env")
assert_match 'status=blocked' "$ok_card_env" \
  "state: update-card OK line normalizes ENV-BLOCKED to blocked"

# --json opt-in restores the full JSON row for callers that parse it.
ok_card_json=$("$STATE" --results-dir "$ok_results" --target-path "$TARGET_ROOT" --target-slug "$TARGET_SLUG" \
  update-card --agent 1 --card-id "$ok_card_id" --status FIND-OK2 --note "json-opt-in" --json)
assert_match '"status": "find"' "$ok_card_json" \
  "state: --json opt-in restores full JSON row"
assert_not_match '^OK:' "$ok_card_json" \
  "state: --json opt-in suppresses the OK line"

# `bin/state summary` was removed (zero callers in production logs); the
# cheat sheet now lives in .agents/references/session-rules.md as the
# single source of truth. The subcommand should error out cleanly.
"$STATE" --results-dir "$RESULTS_DIR" --target-path "$TARGET_ROOT" --target-slug "$TARGET_SLUG" \
  summary >/dev/null 2>&1; rc=$?
assert_neq "0" "$rc" "state: 'summary' subcommand removed (returns non-zero)"
unset rc

resume=$("$STATE" --results-dir "$RESULTS_DIR" --target-path "$TARGET_ROOT" --target-slug "$TARGET_SLUG" \
  resume --agent 1 --mode generic --role reproduce)
assert_match 'Structured Resume' "$resume" "state: resume renders structured startup brief"
assert_match "$hyp_id" "$resume" "state: resume includes active hypothesis"
assert_match 'Recent Runs' "$resume" "state: resume includes recent runs section"
assert_match 'Recent Notes' "$resume" "state: resume includes recent notes section"
assert_match 'ThingProcessorRead copies' "$resume" "state: resume includes structured note text"
assert_match 'Queue Health' "$resume" "state: resume includes queue health"
# Token-cost trim: cheat sheet lives in session-rules.md, not in every
# resume payload. Recent Tried Inputs is opt-in via env var.
assert_not_match 'Quick reference' "$resume" "state: resume does not embed cheat sheet (now in session-rules)"
assert_not_match 'Recent Tried Inputs' "$resume" "state: resume omits recent tried inputs by default"

# No-card resume must not nudge agents back into bin/rank-work. A fresh empty
# results dir has no hypotheses and no eligible cards, so the no-card branch
# fires. Guard against reintroducing the "expand/rerank the queue" nudge that
# conflicts with the prompt's "explain-queue and stop" guidance.
nocard_results="$TEST_TMPDIR/nocard-resume-results"
mkdir -p "$nocard_results"
nocard_resume=$("$STATE" --results-dir "$nocard_results" --target-path "$TARGET_ROOT" --target-slug "$TARGET_SLUG" \
  resume --agent 9 --mode generic --role reproduce)
assert_match 'no eligible work card' "$nocard_resume" "state: no-card resume reports no eligible work"
assert_match 'explain-queue' "$nocard_resume" "state: no-card resume points at explain-queue"
assert_not_match 'expand/rerank' "$nocard_resume" "state: no-card resume drops the expand/rerank nudge"
assert_file_contains "$SCRIPT_ROOT/lib/workqueue.py" 'recent_hypotheses\(ctx, limit=resume_limit, agent=agent, rows=hyps\)' \
  "state: resume reuses preloaded hypothesis rows"
assert_file_contains "$SCRIPT_ROOT/lib/workqueue.py" 'recent_runs\(ctx, limit=resume_limit, agent=agent, hypothesis_id=hyp_id, card_id=card_id, rows=runs\)' \
  "state: resume reuses preloaded run rows"
assert_file_contains "$SCRIPT_ROOT/lib/workqueue.py" 'recent_notes\(ctx, limit=resume_limit, agent=agent, hypothesis_id=hyp_id, rows=notes\)' \
  "state: resume reuses preloaded note rows"
assert_file_contains "$SCRIPT_ROOT/lib/workqueue.py" 'last_terminal_reason\(ctx, agent, rows=hyps\)' \
  "state: resume reuses preloaded rows for terminal reason"

resume_with_tried=$(STATE_RESUME_INCLUDE_TRIED=1 "$STATE" \
  --results-dir "$RESULTS_DIR" --target-path "$TARGET_ROOT" --target-slug "$TARGET_SLUG" \
  resume --agent 1 --mode generic --role reproduce)
assert_match 'Recent Tried Inputs' "$resume_with_tried" "state: STATE_RESUME_INCLUDE_TRIED=1 re-enables tried-inputs section"
assert_not_match 'Quick reference' "$resume_with_tried" "state: cheat sheet stays out even when tried section is on"

# ── Resume limit: defaults to 5 (down from 8), tunable via env. Build 7
#    additional notes for agent 2 (so the recent-notes view has plenty of
#    rows to clip), then count rows under "## Recent Notes" in the resume
#    output. ──
limit_results="$TEST_TMPDIR/limit-results"
mkdir -p "$limit_results"
mk_state_dir "$limit_results"
# Seed one PENDING hypothesis so resume has an active hypothesis to anchor
# the notes section to, plus 9 notes for it. add-hyp/add-note are exercised
# above; this is pure setup, so append rows directly in the shape
# lib/workqueue writes — zero bin/state startups for 10 rows.
limit_hyp_id="H-limit00001"
printf '{"id": "%s", "agent": "2", "card_id": "", "hypothesis": "limit-probe", "file": "alpha.c:foo:1", "input_shape": "bytes", "guard_gap": "none", "diagnostic": "state", "strategy": "S1", "status": "PENDING", "created_at": "2026-06-01T00:00:00Z", "updated_at": "2026-06-01T00:00:00Z"}\n' \
  "$limit_hyp_id" >> "$limit_results/state/hypotheses.jsonl"
i=1
while [ "$i" -le 9 ]; do
  printf '{"id": "NOTE-limit%04d", "agent": "2", "hypothesis_id": "%s", "card_id": "", "kind": "data-flow", "text": "note number %d for limit testing", "created_at": "2026-06-01T00:01:%02dZ"}\n' \
    "$i" "$limit_hyp_id" "$i" "$i" >> "$limit_results/state/notes.jsonl"
  i=$((i + 1))
done

# Default limit (3): the Recent Notes section should show exactly 3 data rows.
limit_resume=$("$STATE" --results-dir "$limit_results" --target-path "$TARGET_ROOT" --target-slug "$TARGET_SLUG" \
  resume --agent 2 --mode generic --role analysis)
notes_data_rows=$(printf '%s\n' "$limit_resume" \
  | awk '/^## Recent Notes$/{flag=1; next} /^## /{flag=0} flag' \
  | grep -c '^NOTE-' || true)
assert_eq "5" "$notes_data_rows" "state: resume defaults to 5 recent-notes rows"

# Override: STATE_RESUME_RECENT_LIMIT=2 clips further.
limit_resume_2=$(STATE_RESUME_RECENT_LIMIT=2 "$STATE" \
  --results-dir "$limit_results" --target-path "$TARGET_ROOT" --target-slug "$TARGET_SLUG" \
  resume --agent 2 --mode generic --role analysis)
notes_data_rows_2=$(printf '%s\n' "$limit_resume_2" \
  | awk '/^## Recent Notes$/{flag=1; next} /^## /{flag=0} flag' \
  | grep -c '^NOTE-' || true)
assert_eq "2" "$notes_data_rows_2" "state: STATE_RESUME_RECENT_LIMIT=2 honored"

# Standalone `bin/state recent-notes` is unaffected by the resume limit.
standalone_notes=$("$STATE" --results-dir "$limit_results" --target-path "$TARGET_ROOT" --target-slug "$TARGET_SLUG" \
  recent-notes --agent 2)
standalone_count=$(printf '%s\n' "$standalone_notes" | grep -c '^NOTE-' || true)
[ "$standalone_count" -ge 9 ] && pass "state: standalone recent-notes ignores resume limit (got ${standalone_count})" \
  || fail "state: standalone recent-notes should return all 9 rows, got ${standalone_count}"

health_results="$TEST_TMPDIR/health-results"
mk_state_dir "$health_results"
# Active claims must lie in the future relative to wall-clock now;
# `claim_blocks_card` collapses expired claims back to "eligible".
# One python prints both timestamps ("now|now+1h").
claim_window=$(python3 -c 'from datetime import datetime, timezone, timedelta
now = datetime.now(timezone.utc)
fmt = "%Y-%m-%dT%H:%M:%SZ"
print(now.strftime(fmt) + "|" + (now + timedelta(hours=1)).strftime(fmt))')
claimed_at=${claim_window%%|*}
expires_at=${claim_window##*|}
expires_year=${expires_at%%-*}
for n in 1 2 3 4 5 6 7 8 9 10; do
  printf '{"id":"WORK-health-%s","kind":"ranked-source","target_slug":"%s","file":"beta/io/plain.c","subsystem":"beta/io","mode":"generic","strategy":"S1","score":1,"reason":"test","status":"unclaimed"}\n' \
    "$n" "$TARGET_SLUG" >> "$health_results/work-cards.jsonl"
  printf '{"agent":"%s","card_id":"WORK-health-%s","claimed_at":"%s","expires_at":"%s","mode":"generic","role":"reproduce","status":"claimed"}\n' \
    "$n" "$n" "$claimed_at" "$expires_at" >> "$health_results/state/claims.jsonl"
done
printf '{"id":"WORK-health-done","kind":"ranked-source","target_slug":"%s","file":"epsilon/scan/matcher.c","subsystem":"epsilon/scan","mode":"generic","strategy":"S1","score":1,"reason":"test","status":"unclaimed"}\n' \
  "$TARGET_SLUG" >> "$health_results/work-cards.jsonl"
printf '{"agent":"1","card_id":"WORK-health-done","status":"discarded","updated_at":"%s"}\n' \
  "$claimed_at" >> "$health_results/state/claims.jsonl"
health_resume=$(STATE_RESUME_QUEUE_HEALTH_LIMIT=1 "$STATE" \
  --results-dir "$health_results" --target-path "$TARGET_ROOT" --target-slug "$TARGET_SLUG" \
  resume --agent 1 --mode generic --role reproduce)
assert_match 'claimed-until: 10' "$health_resume" "state: resume aggregates claimed-until timestamps"
assert_not_match "claimed-until:${expires_year}-" "$health_resume" "state: resume hides volatile claim expiry timestamps"
assert_match 'more reason\(s\), 1 card\(s\)' "$health_resume" "state: resume caps queue health rows"

# ── recent-hyps: slim listing replaces tail -80 hypotheses.jsonl ──
recent=$("$STATE" --results-dir "$RESULTS_DIR" --target-path "$TARGET_ROOT" --target-slug "$TARGET_SLUG" recent-hyps)
assert_match '^id\|status\|agent\|strategy\|file\|card_id\|hypothesis$' "$recent" "recent-hyps: header row"
assert_match "$hyp_id" "$recent" "recent-hyps: includes existing hypothesis"
assert_match 'PENDING' "$recent" "recent-hyps: shows status column"
recent_lines=$(printf '%s\n' "$recent" | grep -c '^H' || true)
assert_eq "3" "$recent_lines" "recent-hyps: three data rows for three hypothesis shapes"

# Add a few extra rows so filters and --limit have something to cut.
# Pure setup (add-hyp/update-hyp are exercised above and below): append the
# post-update rows directly — H-ALPHA already DISCARDED — like the H-DUP
# literal rows below, instead of three bin/state round-trips.
{
  printf '{"id":"H-ALPHA","agent":"2","card_id":"%s","hypothesis":"alpha lifetime in foo","file":"alpha/core/ThingProcessor.cpp:foo:42","input_shape":"any","guard_gap":"any","diagnostic":"lifetime","strategy":"S2","status":"DISCARDED","created_at":"2026-06-01T00:00:03Z","updated_at":"2026-06-01T00:00:05Z"}\n' "$card_id"
  printf '{"id":"H-BETA","agent":"1","card_id":"%s","hypothesis":"beta uninit at bar","file":"beta/io/plain.c:bar:7","input_shape":"any","guard_gap":"any","diagnostic":"uninit","strategy":"S1","status":"PENDING","created_at":"2026-06-01T00:00:04Z","updated_at":"2026-06-01T00:00:04Z"}\n' "$card_id"
} >> "$RESULTS_DIR/state/hypotheses.jsonl"

dup_add=$("$STATE" --results-dir "$RESULTS_DIR" --target-path "$TARGET_ROOT" --target-slug "$TARGET_SLUG" \
  add-hyp --id "H-BETA" --agent 2 --card-id "$card_id" --hypothesis "duplicate beta" \
  --file "beta/io/plain.c:baz:8" --input-shape "any" --guard-gap "any" \
  --diagnostic bounds --strategy S1 2>&1 || true)
assert_match 'hypothesis id already exists: H-BETA' "$dup_add" \
  "state: add-hyp rejects duplicate explicit ids"

cat >> "$RESULTS_DIR/state/hypotheses.jsonl" <<'JSONL'
{"id":"H-DUP","agent":"1","card_id":"PATCH-dup","hypothesis":"dup one","file":"dup/a.c:f:1","input_shape":"any","guard_gap":"any","diagnostic":"bounds","strategy":"S1","status":"PENDING","created_at":"2026-05-22T00:00:00Z","updated_at":"2026-05-22T00:00:00Z"}
{"id":"H-DUP","agent":"2","card_id":"PATCH-dup","hypothesis":"dup two","file":"dup/b.c:f:2","input_shape":"any","guard_gap":"any","diagnostic":"bounds","strategy":"S1","status":"PENDING","created_at":"2026-05-22T00:00:00Z","updated_at":"2026-05-22T00:00:00Z"}
JSONL
ambig_update=$("$STATE" --results-dir "$RESULTS_DIR" --target-path "$TARGET_ROOT" --target-slug "$TARGET_SLUG" \
  update-hyp --id "H-DUP" --status DISCARDED --note "ambiguous" 2>&1 || true)
assert_match 'hypothesis id H-DUP is ambiguous' "$ambig_update" \
  "state: update-hyp refuses ambiguous ids without agent scope"
dup_statuses=$(python3 - "$RESULTS_DIR/state/hypotheses.jsonl" <<'PY'
import json, sys
rows = [json.loads(line) for line in open(sys.argv[1]) if line.strip()]
print("|".join(f"{r['agent']}:{r['status']}" for r in rows if r.get("id") == "H-DUP"))
PY
)
assert_eq "1:PENDING|2:PENDING" "$dup_statuses" \
  "state: ambiguous update-hyp leaves duplicate rows untouched"
scoped_update=$("$STATE" --results-dir "$RESULTS_DIR" --target-path "$TARGET_ROOT" --target-slug "$TARGET_SLUG" \
  update-hyp --id "H-DUP" --agent 2 --status DISCARDED --note "scoped" --json 2>&1)
assert_match '"agent": "2"' "$scoped_update" "state: update-hyp --agent updates selected duplicate row"
dup_statuses=$(python3 - "$RESULTS_DIR/state/hypotheses.jsonl" <<'PY'
import json, sys
rows = [json.loads(line) for line in open(sys.argv[1]) if line.strip()]
print("|".join(f"{r['agent']}:{r['status']}" for r in rows if r.get("id") == "H-DUP"))
PY
)
assert_eq "1:PENDING|2:DISCARDED" "$dup_statuses" \
  "state: scoped update-hyp changes only matching agent row"
compat_hyp_card=$("$STATE" --results-dir "$RESULTS_DIR" --target-path "$TARGET_ROOT" --target-slug "$TARGET_SLUG" \
  update-hyp --id "H-DUP" --agent 2 --card-id "$card_id" --status CRASH-001 --note "legacy extra card-id" --json)
assert_match '"status": "CRASH-001"' "$compat_hyp_card" "state: update-hyp accepts legacy --card-id"
assert_match "legacy extra card-id" "$compat_hyp_card" "state: update-hyp keeps note with legacy --card-id"

# --agent filter
recent_a1=$("$STATE" --results-dir "$RESULTS_DIR" --target-path "$TARGET_ROOT" --target-slug "$TARGET_SLUG" \
  recent-hyps --agent 1)
assert_match 'H-BETA' "$recent_a1" "recent-hyps --agent: keeps agent=1"
assert_not_match 'H-ALPHA' "$recent_a1" "recent-hyps --agent: drops agent=2"

# --status regex filter
recent_pending=$("$STATE" --results-dir "$RESULTS_DIR" --target-path "$TARGET_ROOT" --target-slug "$TARGET_SLUG" \
  recent-hyps --status '^PENDING$')
assert_match 'H-BETA' "$recent_pending" "recent-hyps --status: keeps PENDING"
assert_not_match 'H-ALPHA' "$recent_pending" "recent-hyps --status: drops DISCARDED"

# --card-id filter
recent_card=$("$STATE" --results-dir "$RESULTS_DIR" --target-path "$TARGET_ROOT" --target-slug "$TARGET_SLUG" \
  recent-hyps --card-id "$card_id")
assert_match 'H-BETA' "$recent_card" "recent-hyps --card-id: matches card"
recent_nocard=$("$STATE" --results-dir "$RESULTS_DIR" --target-path "$TARGET_ROOT" --target-slug "$TARGET_SLUG" \
  recent-hyps --card-id "PATCH-bogus-does-not-exist")
nocard_lines=$(printf '%s\n' "$recent_nocard" | grep -c '^H' || true)
assert_eq "0" "$nocard_lines" "recent-hyps --card-id: unknown card returns no rows"

# --limit caps rows
recent_lim=$("$STATE" --results-dir "$RESULTS_DIR" --target-path "$TARGET_ROOT" --target-slug "$TARGET_SLUG" \
  recent-hyps --limit 1)
lim_lines=$(printf '%s\n' "$recent_lim" | grep -c '^H' || true)
assert_eq "1" "$lim_lines" "recent-hyps --limit 1: returns exactly one data row"

# Hypothesis text containing pipe characters is sanitized for the column
# delimiter. add-hyp stores the text verbatim (sanitization is in the
# recent-hyps renderer), so seed the raw row directly.
printf '{"id":"H-PIPE","agent":"1","card_id":"%s","hypothesis":"issue|with|pipes","file":"alpha/core/ThingProcessor.cpp:f:1","input_shape":"any","guard_gap":"any","diagnostic":"state","strategy":"S1","status":"PENDING","created_at":"2026-06-01T00:00:06Z","updated_at":"2026-06-01T00:00:06Z"}\n' \
  "$card_id" >> "$RESULTS_DIR/state/hypotheses.jsonl"
recent_pipe=$("$STATE" --results-dir "$RESULTS_DIR" --target-path "$TARGET_ROOT" --target-slug "$TARGET_SLUG" \
  recent-hyps --status '^PENDING$' --limit 50)
assert_match 'H-PIPE' "$recent_pipe" "recent-hyps: includes pipe-bearing row"
pipe_row=$(printf '%s\n' "$recent_pipe" | grep '^H-PIPE')
pipe_cols=$(printf '%s' "$pipe_row" | awk -F'|' '{print NF}')
assert_eq "7" "$pipe_cols" "recent-hyps: pipes in hypothesis text don't break column count"

# Invalid --status regex returns a friendly error, not a Python traceback.
bad_status=$("$STATE" --results-dir "$RESULTS_DIR" --target-path "$TARGET_ROOT" --target-slug "$TARGET_SLUG" \
  recent-hyps --status '[unclosed' 2>&1 || true)
assert_match 'invalid --status regex' "$bad_status" "recent-hyps: bad regex reported, not raised"

# ── recent-runs: slim listing of runs.jsonl ──
# We've already added one CLEAN run via add-run above. Add a CRASH run too
# so verdict filtering has something to discriminate on. add-run itself is
# exercised above; seed these reader fixtures directly.
{
  printf '{"id": "RUN-recent0001", "agent": "1", "hypothesis_id": "H-BETA", "card_id": "%s", "mode": "generic", "testcase": "%s/scratch-1/tc-crash.input", "testcase_sha1": "", "asan_output": "%s/scratch-1/tc-crash.asan.txt", "verdict": "CRASH", "asan_runs": 1, "created_at": "2026-06-01T00:00:07Z"}\n' \
    "$card_id" "$RESULTS_DIR" "$RESULTS_DIR"
  printf '{"id": "RUN-recent0002", "agent": "2", "hypothesis_id": "H-ALPHA", "card_id": "%s", "mode": "browser", "testcase": "%s/scratch-2/tc.html", "testcase_sha1": "", "asan_output": "%s/scratch-2/tc.asan.txt", "verdict": "CLEAN", "asan_runs": 1, "created_at": "2026-06-01T00:00:08Z"}\n' \
    "$card_id" "$RESULTS_DIR" "$RESULTS_DIR"
} >> "$RESULTS_DIR/state/runs.jsonl"

recent_runs=$("$STATE" --results-dir "$RESULTS_DIR" --target-path "$TARGET_ROOT" --target-slug "$TARGET_SLUG" recent-runs)
assert_match '^id\|verdict\|mode\|agent\|hypothesis_id\|card_id\|testcase$' "$recent_runs" "recent-runs: header row"
assert_match '\|CRASH\|' "$recent_runs" "recent-runs: includes CRASH row"
assert_match '\|CLEAN\|' "$recent_runs" "recent-runs: includes CLEAN row"
runs_data_lines=$(printf '%s\n' "$recent_runs" | grep -c '^RUN-' || true)
# 5 runs: 1 initial + 2 added to satisfy the discard-gate floor + 2 added here.
assert_eq "5" "$runs_data_lines" "recent-runs: counts all 5 runs"

# --verdict regex
recent_runs_crash=$("$STATE" --results-dir "$RESULTS_DIR" --target-path "$TARGET_ROOT" --target-slug "$TARGET_SLUG" \
  recent-runs --verdict '^CRASH$')
assert_match '\|CRASH\|' "$recent_runs_crash" "recent-runs --verdict: keeps CRASH"
assert_not_match '\|CLEAN\|' "$recent_runs_crash" "recent-runs --verdict: drops CLEAN"

# --agent
recent_runs_a2=$("$STATE" --results-dir "$RESULTS_DIR" --target-path "$TARGET_ROOT" --target-slug "$TARGET_SLUG" \
  recent-runs --agent 2)
a2_lines=$(printf '%s\n' "$recent_runs_a2" | grep -c '^RUN-' || true)
assert_eq "1" "$a2_lines" "recent-runs --agent 2: returns one row"
assert_match 'browser' "$recent_runs_a2" "recent-runs --agent 2: includes the browser-mode run"

# --hypothesis-id
recent_runs_beta=$("$STATE" --results-dir "$RESULTS_DIR" --target-path "$TARGET_ROOT" --target-slug "$TARGET_SLUG" \
  recent-runs --hypothesis-id "H-BETA")
beta_lines=$(printf '%s\n' "$recent_runs_beta" | grep -c '^RUN-' || true)
assert_eq "1" "$beta_lines" "recent-runs --hypothesis-id: filters to one run"

# --limit caps
recent_runs_lim=$("$STATE" --results-dir "$RESULTS_DIR" --target-path "$TARGET_ROOT" --target-slug "$TARGET_SLUG" \
  recent-runs --limit 1)
lim_lines=$(printf '%s\n' "$recent_runs_lim" | grep -c '^RUN-' || true)
assert_eq "1" "$lim_lines" "recent-runs --limit 1: returns exactly one"

# Bad regex error path
bad_v=$("$STATE" --results-dir "$RESULTS_DIR" --target-path "$TARGET_ROOT" --target-slug "$TARGET_SLUG" \
  recent-runs --verdict '[bad' 2>&1 || true)
assert_match 'invalid --verdict regex' "$bad_v" "recent-runs: bad regex reported, not raised"

# Runtime feedback is report-only guidance from recent probe artifacts.
mkdir -p "$RESULTS_DIR/scratch-3"
cat > "$RESULTS_DIR/scratch-3/coverage-near.txt" <<'EOF'
COVERAGE_GATE: MISSED — ASan skipped. Revise testcase (closest: Mock::near_target)
EOF
cat > "$RESULTS_DIR/scratch-3/format.txt" <<'EOF'
parse error: invalid magic while decoding testcase
EOF
cat > "$RESULTS_DIR/scratch-3/sanitizer.txt" <<'EOF'
==12345==ERROR: AddressSanitizer: heap-buffer-overflow on address 0xdeadbeef
EOF
feedback_out=$(PYTHONPATH="$SCRIPT_ROOT/lib" python3 - "$RESULTS_DIR" "$TARGET_ROOT" "$TARGET_SLUG" <<'PY'
import sys
from pathlib import Path
from workqueue import Context, runtime_feedback

results = Path(sys.argv[1])
ctx = Context(Path("."), Path(sys.argv[2]), sys.argv[3], results, "none")
print(runtime_feedback(ctx, rows=[
    {"verdict": "CLEAN", "agent": "1", "asan_output": str(results / "scratch-3/clean-1.txt"), "created_at": "2026-06-01T00:00:11Z"},
    {"verdict": "CLEAN", "agent": "1", "asan_output": str(results / "scratch-3/clean-2.txt"), "created_at": "2026-06-01T00:00:12Z"},
]), end="")
print(runtime_feedback(ctx, rows=[
    {"verdict": "NO_HIT", "agent": "1", "asan_output": str(results / "scratch-3/coverage-near.txt"), "created_at": "2026-06-01T00:00:13Z"},
]), end="")
print(runtime_feedback(ctx, rows=[
    {"verdict": "CLEAN", "agent": "1", "asan_output": str(results / "scratch-3/format.txt"), "created_at": "2026-06-01T00:00:14Z"},
]), end="")
# A parse rejection recorded as NO_HIT must still get the precise seed advice,
# not the generic coverage-routing fallback (format-reject before coverage).
print(runtime_feedback(ctx, rows=[
    {"verdict": "NO_HIT", "agent": "1", "asan_output": str(results / "scratch-3/format.txt"), "created_at": "2026-06-01T00:00:15Z"},
]), end="")
# A sanitizer banner in saved output under a non-crash verdict must flag a
# possible missed crash (artifact-mismatch), not be silently treated as clean.
print(runtime_feedback(ctx, rows=[
    {"verdict": "CLEAN", "agent": "1", "asan_output": str(results / "scratch-3/sanitizer.txt"), "created_at": "2026-06-01T00:00:16Z"},
]), end="")
PY
)
assert_match 'scope\|recent_verdicts\|runtime_signals\|diagnosis\|feedback' "$feedback_out" \
  "runtime feedback: header includes signal and diagnosis columns"
assert_match 'clean-no-diagnostic.*CLEAN-only evidence' "$feedback_out" \
  "runtime feedback: repeated clean probes trigger variant guidance"
assert_match 'coverage-near-miss=1.*near-miss-targeting.*closest reached frame' "$feedback_out" \
  "runtime feedback: coverage near misses trigger closest-frame guidance"
assert_match 'format-reject=1.*seed-format.*bin/find-seed' "$feedback_out" \
  "runtime feedback: format rejects trigger seed-first guidance"
assert_match 'NO_HIT=1.*format-reject=1.*seed-format' "$feedback_out" \
  "runtime feedback: format reject under NO_HIT verdict keeps precise seed advice"
assert_match 'crash-signal=1.*artifact-mismatch' "$feedback_out" \
  "runtime feedback: sanitizer banner under non-crash verdict flags artifact-mismatch"

# ── show-recent: one-call compact session snapshot ──
show_recent=$("$STATE" --results-dir "$RESULTS_DIR" --target-path "$TARGET_ROOT" --target-slug "$TARGET_SLUG" \
  show-recent --hyps 1 --runs 1 --claims 1)
assert_match '^# recent-hyps$' "$show_recent" "show-recent: includes hypothesis section"
assert_match '^# recent-runs$' "$show_recent" "show-recent: includes run section"
assert_match '^# recent-claims$' "$show_recent" "show-recent: includes claim section"
show_hyp_rows=$(printf '%s\n' "$show_recent" | grep -c '^H-' || true)
show_run_rows=$(printf '%s\n' "$show_recent" | grep -c '^RUN-' || true)
show_claim_rows=$(printf '%s\n' "$show_recent" | grep -c -E '^[0-9]{4}-.*\|' || true)
assert_eq "1" "$show_hyp_rows" "show-recent --hyps 1: caps hypothesis rows"
assert_eq "1" "$show_run_rows" "show-recent --runs 1: caps run rows"
assert_eq "1" "$show_claim_rows" "show-recent --claims 1: caps claim rows"
show_recent_no_notes=$("$STATE" --results-dir "$RESULTS_DIR" --target-path "$TARGET_ROOT" --target-slug "$TARGET_SLUG" \
  show-recent --hyps 0 --runs 0 --claims 0)
assert_not_match 'usage: state' "$show_recent_no_notes" "show-recent: prompt-advised command parses without help fallback"
assert_not_match '# recent-notes' "$show_recent" "show-recent: notes stay opt-in by default"

# ── recent-notes: structured working context without markdown state ──
# add-note stores text verbatim (pipe sanitization is in the recent-notes
# renderer) and is exercised above; seed these reader fixtures directly.
{
  printf '{"id": "NOTE-recent001", "agent": "1", "hypothesis_id": "H-BETA", "card_id": "%s", "kind": "guard", "text": "guard|text with delimiter is sanitized", "created_at": "2026-06-01T00:00:09Z"}\n' "$card_id"
  printf '{"id": "NOTE-recent002", "agent": "2", "hypothesis_id": "H-ALPHA", "card_id": "%s", "kind": "variants", "text": "variant note for agent two", "created_at": "2026-06-01T00:00:10Z"}\n' "$card_id"
} >> "$RESULTS_DIR/state/notes.jsonl"
recent_notes=$("$STATE" --results-dir "$RESULTS_DIR" --target-path "$TARGET_ROOT" --target-slug "$TARGET_SLUG" recent-notes)
assert_match '^id\|kind\|agent\|hypothesis_id\|card_id\|text$' "$recent_notes" "recent-notes: header row"
assert_match 'data-flow' "$recent_notes" "recent-notes: includes data-flow note"
assert_match 'guard.text with delimiter' "$recent_notes" "recent-notes: sanitizes pipe delimiters"
recent_notes_a2=$("$STATE" --results-dir "$RESULTS_DIR" --target-path "$TARGET_ROOT" --target-slug "$TARGET_SLUG" \
  recent-notes --agent 2)
assert_match 'variant note for agent two' "$recent_notes_a2" "recent-notes --agent: keeps matching agent"
assert_not_match 'ThingProcessorRead copies' "$recent_notes_a2" "recent-notes --agent: drops other agent"
recent_notes_beta=$("$STATE" --results-dir "$RESULTS_DIR" --target-path "$TARGET_ROOT" --target-slug "$TARGET_SLUG" \
  recent-notes --hypothesis-id H-BETA)
assert_match 'H-BETA' "$recent_notes_beta" "recent-notes --hypothesis-id: keeps selected hypothesis"
recent_notes_kind=$("$STATE" --results-dir "$RESULTS_DIR" --target-path "$TARGET_ROOT" --target-slug "$TARGET_SLUG" \
  recent-notes --kind variants)
assert_match 'variants' "$recent_notes_kind" "recent-notes --kind: filters kind"
list_notes_a2=$("$STATE" --results-dir "$RESULTS_DIR" --target-path "$TARGET_ROOT" --target-slug "$TARGET_SLUG" \
  list-notes --agent 2)
assert_eq "$recent_notes_a2" "$list_notes_a2" "state: list-notes is a recent-notes alias"

# ── recent-tried: parses tried-inputs-N.log key=value records ──
TRIED_LOG="$RESULTS_DIR/tried-inputs-1.log"
{
  printf '2026-05-02T01:00:00Z verdict=CLEAN mode=generic testcase=%s hash=aaa111 runs=1 crashes=0 execs=1 hypothesis=H1 target=%s closest=<none> hits_verdict=?\n' \
    "$RESULTS_DIR/scratch-1/v1.xml" "alpha/core/ThingProcessor.cpp:func:1"
  printf '2026-05-02T02:00:00Z verdict=CRASH mode=generic testcase=%s hash=bbb222 runs=1 crashes=1 execs=1 hypothesis=H2 target=%s closest=<none> hits_verdict=?\n' \
    "$RESULTS_DIR/scratch-1/v2.xml" "alpha/core/Other.cpp:func2:1"
  printf '2026-05-02T03:00:00Z verdict=NO_HIT mode=browser testcase=%s hash=ccc333 runs=0 crashes=0 execs=0 hypothesis=H3 target=%s closest=%q hits_verdict=MISSED\n' \
    "$RESULTS_DIR/scratch-1/v3.html" "beta/io/plain.c:helper:1" "Mock::near_target"
  printf '2026-05-02T03:30:00Z verdict=NO_HIT mode=browser testcase=%s hash=eee555 runs=0 crashes=0 execs=0 hypothesis=H4 target=%s closest=<none> hits_verdict=MISSED\n' \
    "$RESULTS_DIR/scratch-1/v3.html" "beta/io/plain.c:helper:1"
} > "$TRIED_LOG"

# Default: --agent N parses one log, returns most-recent first.
recent_tried=$("$STATE" --results-dir "$RESULTS_DIR" --target-path "$TARGET_ROOT" --target-slug "$TARGET_SLUG" \
  recent-tried --agent 1)
assert_match '^timestamp\|verdict\|mode\|hash\|hypothesis\|target\|closest\|testcase$' "$recent_tried" "recent-tried: header row"
assert_match 'aaa111' "$recent_tried" "recent-tried: contains hash 1"
assert_match 'bbb222' "$recent_tried" "recent-tried: contains hash 2"
assert_match 'ccc333' "$recent_tried" "recent-tried: contains hash 3"
assert_match 'Mock::near_target' "$recent_tried" "recent-tried: preserves closest reached frame"
# Sorted desc by timestamp — first data row should be eee555 (03:30:00).
first_data=$(printf '%s\n' "$recent_tried" | sed -n '2p')
assert_match 'eee555' "$first_data" "recent-tried: sorted most-recent first"

# Verdict filter
tried_crash=$("$STATE" --results-dir "$RESULTS_DIR" --target-path "$TARGET_ROOT" --target-slug "$TARGET_SLUG" \
  recent-tried --agent 1 --verdict '^CRASH$')
assert_match 'bbb222' "$tried_crash" "recent-tried --verdict: keeps CRASH row"
assert_not_match 'aaa111' "$tried_crash" "recent-tried --verdict: drops CLEAN"
assert_not_match 'ccc333' "$tried_crash" "recent-tried --verdict: drops NO_HIT"

# Hypothesis filter
tried_h2=$("$STATE" --results-dir "$RESULTS_DIR" --target-path "$TARGET_ROOT" --target-slug "$TARGET_SLUG" \
  recent-tried --agent 1 --hypothesis H2)
h2_data_lines=$(printf '%s\n' "$tried_h2" | grep -c -E '^[0-9]{4}' || true)
assert_eq "1" "$h2_data_lines" "recent-tried --hypothesis: one match"
assert_match 'bbb222' "$tried_h2" "recent-tried --hypothesis: correct row"

# Target substring filter
tried_alpha=$("$STATE" --results-dir "$RESULTS_DIR" --target-path "$TARGET_ROOT" --target-slug "$TARGET_SLUG" \
  recent-tried --agent 1 --target alpha/core)
alpha_data_lines=$(printf '%s\n' "$tried_alpha" | grep -c -E '^[0-9]{4}' || true)
assert_eq "2" "$alpha_data_lines" "recent-tried --target: substring filter matches alpha/core entries"

# --limit
tried_lim=$("$STATE" --results-dir "$RESULTS_DIR" --target-path "$TARGET_ROOT" --target-slug "$TARGET_SLUG" \
  recent-tried --agent 1 --limit 1)
lim_data_lines=$(printf '%s\n' "$tried_lim" | grep -c -E '^[0-9]{4}' || true)
assert_eq "1" "$lim_data_lines" "recent-tried --limit 1: one row"

# --agent all reads every per-agent log under RESULTS_DIR.
TRIED_LOG_2="$RESULTS_DIR/tried-inputs-2.log"
printf '2026-05-02T04:00:00Z verdict=CLEAN mode=js testcase=%s hash=ddd444 runs=1 crashes=0 execs=1 hypothesis=HX target=other closest=<none> hits_verdict=?\n' \
  "$RESULTS_DIR/scratch-2/x.js" > "$TRIED_LOG_2"
tried_all=$("$STATE" --results-dir "$RESULTS_DIR" --target-path "$TARGET_ROOT" --target-slug "$TARGET_SLUG" \
  recent-tried --agent all)
assert_match 'aaa111' "$tried_all" "recent-tried --agent all: includes agent-1 row"
assert_match 'ddd444' "$tried_all" "recent-tried --agent all: includes agent-2 row"

# Missing per-agent log returns header only — graceful, not a crash.
tried_missing=$("$STATE" --results-dir "$RESULTS_DIR" --target-path "$TARGET_ROOT" --target-slug "$TARGET_SLUG" \
  recent-tried --agent 99)
missing_data_lines=$(printf '%s\n' "$tried_missing" | grep -c -E '^[0-9]{4}' || true)
assert_eq "0" "$missing_data_lines" "recent-tried: missing log = no data rows"
assert_match 'timestamp\|verdict\|mode' "$tried_missing" "recent-tried: header still printed"

# Bad regex error path
bad_tv=$("$STATE" --results-dir "$RESULTS_DIR" --target-path "$TARGET_ROOT" --target-slug "$TARGET_SLUG" \
  recent-tried --agent 1 --verdict '[bad' 2>&1 || true)
assert_match 'invalid --verdict regex' "$bad_tv" "recent-tried: bad regex reported, not raised"

# Cheat sheet's canonical home is now .agents/references/session-rules.md.
# Verify it documents every accessor the agents need.
SESSION_RULES="$SCRIPT_ROOT/.agents/references/session-rules.md"
assert_file_exists "$SESSION_RULES" "cheat-sheet: session-rules.md exists"
sr_content=$(cat "$SESSION_RULES")
assert_match 'bin/state recent-hyps' "$sr_content" "cheat-sheet: session-rules lists recent-hyps"
assert_match 'bin/state recent-runs' "$sr_content" "cheat-sheet: session-rules lists recent-runs"
assert_match 'bin/state show-recent' "$sr_content" "cheat-sheet: session-rules lists show-recent"
assert_match 'bin/state recent-tried' "$sr_content" "cheat-sheet: session-rules lists recent-tried"
assert_match 'bin/state dump-queue' "$sr_content" "cheat-sheet: session-rules lists dump-queue"
assert_match 'bin/state list-notes' "$sr_content" "cheat-sheet: session-rules lists list-notes"
assert_match 'bin/state recent-tried --agent N --limit 40' "$sr_content" "cheat-sheet: session-rules uses recent-tried for tried-inputs memory"
assert_not_match 'tail -40 <RESULTS_DIR>/tried-inputs-N.log' "$sr_content" "cheat-sheet: session-rules does not recommend raw tried-input tails"
assert_match 'bin/state explain-queue' "$sr_content" "cheat-sheet: session-rules lists explain-queue"
assert_match 'explain-queue .*--strategy S' "$sr_content" "cheat-sheet: explain-queue documents strategy filter"
assert_match 'bin/state show-crash' "$sr_content" "cheat-sheet: session-rules lists show-crash"
assert_match 'bin/state list-findings' "$sr_content" "cheat-sheet: session-rules lists list-findings"
assert_match 'bin/state add-hyp' "$sr_content" "cheat-sheet: session-rules lists add-hyp"
assert_match 'bin/state add-note' "$sr_content" "cheat-sheet: session-rules lists add-note"
assert_match 'bin/rg-safe' "$sr_content" "cheat-sheet: session-rules lists rg-safe"
assert_match 'bin/show-patch' "$sr_content" "cheat-sheet: session-rules lists show-patch"
assert_match 'bin/peek' "$sr_content" "cheat-sheet: session-rules lists peek"

cat > "$RESULTS_DIR/scratch-1/tc.js" <<'JS'
// TARGET: alpha/core/ThingProcessor.cpp:ThingProcessorRead:3
// HYPOTHESIS-ID: H1
// CATEGORY: bounds
// MODE: js-diff
print('TESTCASE_EXECUTED');
JS

dry=$("$PROBE" --dry-run "$RESULTS_DIR/scratch-1/tc.js")
assert_match 'mode=js-diff' "$dry" "probe: honors explicit MODE header"
assert_match 'run-asan js-diff' "$dry" "probe: picks differential command from header"
assert_match 'want=' "$dry" "probe: dry-run shows want field"

mock_js="$TEST_TMPDIR/mock-js-diff"
cat > "$mock_js" <<'EOF_JS'
#!/usr/bin/env bash
case "$1" in
  --ion-eager) echo ion ;;
  --no-ion) echo noion ;;
esac
EOF_JS
chmod +x "$mock_js"
output=$(ASAN_JS="$mock_js" "$PROBE" "$RESULTS_DIR/scratch-1/tc.js" 2>&1)
rc=$?
assert_eq "1" "$rc" "probe: js-diff divergence returns nonzero"
assert_file_contains "$RESULTS_DIR/scratch-1/tc.asan.txt" "outputs DIFFER" "probe: js-diff writes output artifact"
assert_match "outputs DIFFER" "$output" "probe: js-diff still prints output"

runner_results="$TEST_TMPDIR/runner-results"
mkdir -p "$runner_results/scratch-1" "$runner_results/state"
cat > "$runner_results/work-cards.jsonl" <<'JSONL'
{"id":"WORK-runner","kind":"ranked-source","target_slug":"testproject","file":"alpha/core/ThingProcessor.cpp","subsystem":"alpha/core","status":"unclaimed","strategy":"S3"}
JSONL
# add-hyp is exercised above; seed the hypothesis row probe will act on
# directly (the row shape lib/workqueue's add_hypothesis writes).
mk_state_dir "$runner_results"
printf '{"id": "H-runner", "agent": "1", "card_id": "WORK-runner", "hypothesis": "runner diagnostic stays active", "file": "alpha/core/ThingProcessor.cpp:ThingProcessorRead:3", "input_shape": "shell runner emits a runtime diagnostic", "guard_gap": "findings-only runner has no sanitizer crash bundle yet", "diagnostic": "state", "strategy": "S3", "status": "PENDING", "created_at": "2026-06-01T00:00:00Z", "updated_at": "2026-06-01T00:00:00Z"}\n' \
  >> "$runner_results/state/hypotheses.jsonl"
# Seed the claim-on-adopt row add-hyp would have written, so the
# "does not terminal-close card" negative grep below runs against a
# populated claims file rather than passing vacuously on an empty one.
printf '{"card_id": "WORK-runner", "agent": "1", "mode": "", "role": "", "status": "claimed", "claimed_at": "2026-06-01T00:00:00Z", "expires_at": "2026-06-01T01:00:00Z", "source": "add-hyp", "hypothesis_id": "H-runner"}\n' \
  >> "$runner_results/state/claims.jsonl"
cat > "$runner_results/scratch-1/runner-diagnostic.sh" <<'EOF_TC'
#!/usr/bin/env bash
# TARGET: alpha/core/ThingProcessor.cpp:ThingProcessorRead:3
# HYPOTHESIS-ID: H-runner
# CARD-ID: WORK-runner
# CATEGORY: state
echo "panic: runtime error: index out of range" >&2
exit 1
EOF_TC
chmod +x "$runner_results/scratch-1/runner-diagnostic.sh"
RESULTS_DIR="$runner_results" PROBE_SANITIZER=runner \
  TARGET_SANITIZERS_EXPLICITLY_DISABLED=1 ASAN_GENERIC_BIN=bash \
  "$PROBE" "$runner_results/scratch-1/runner-diagnostic.sh" >/dev/null 2>&1 || true
# One python reads back both outcomes ("<run verdict>|<hyp status>").
runner_pair=$(python3 - "$runner_results/state/runs.jsonl" "$runner_results/state/hypotheses.jsonl" <<'PY'
import json, sys
verdict = ""
for line in open(sys.argv[1], encoding="utf-8"):
    row = json.loads(line)
    if row.get("hypothesis_id") == "H-runner":
        verdict = row.get("verdict", "")
status = ""
for line in open(sys.argv[2], encoding="utf-8"):
    row = json.loads(line)
    if row.get("id") == "H-runner":
        status = row.get("status", "")
print(verdict + "|" + status)
PY
)
runner_run_verdict=${runner_pair%%|*}
runner_hyp_status=${runner_pair##*|}
assert_eq "CRASH" "$runner_run_verdict" \
  "probe: runner diagnostic is still recorded as a crash-like run"
assert_eq "PENDING" "$runner_hyp_status" \
  "probe: findings-only runner diagnostic does not terminal-close hypothesis"
if grep -q '"card_id": "WORK-runner".*"status": "crash"' "$runner_results/state/claims.jsonl" 2>/dev/null; then
  fail "probe: findings-only runner diagnostic does not terminal-close card" \
    "WORK-runner was marked crash"
else
  pass "probe: findings-only runner diagnostic does not terminal-close card"
fi

cat > "$RESULTS_DIR/scratch-1/tc.dat" <<'EOF_TC'
TARGET: alpha/core/ThingProcessor.cpp:ThingProcessorRead:3
HYPOTHESIS-ID: H2
CATEGORY: bounds
abc
EOF_TC
dry=$("$PROBE" --dry-run "$RESULTS_DIR/scratch-1/tc.dat")
assert_match 'mode=generic' "$dry" "probe: generic fallback for data input"

cat > "$RESULTS_DIR/scratch-1/rel-probe.dat" <<'EOF_TC'
TARGET: alpha/core/ThingProcessor.cpp:ThingProcessorRead:3
HYPOTHESIS-ID: H-rel
CATEGORY: bounds
abc
EOF_TC
dry=$(cd "$TEST_TMPDIR" && "$PROBE" --dry-run scratch-1/rel-probe.dat)
assert_match 'asan_output=.*/results/scratch-1/rel-probe.asan.txt' \
  "$dry" "probe: relative scratch-N resolves to active RESULTS_DIR"

mkdir -p "$TEST_TMPDIR/scratch-1"
cat > "$TEST_TMPDIR/scratch-1/rel-probe.dat" <<'EOF_TC'
TARGET: wrong/root-scratch.c:Wrong:1
HYPOTHESIS-ID: H-root
CATEGORY: state
root
EOF_TC
ambiguous_rc=0
ambiguous_out=$(cd "$TEST_TMPDIR" && "$PROBE" --dry-run scratch-1/rel-probe.dat 2>&1) || ambiguous_rc=$?
assert_eq "2" "$ambiguous_rc" "probe: ambiguous relative scratch-N exits 2"
assert_match 'ambiguous scratch path' "$ambiguous_out" \
  "probe: ambiguous relative scratch-N explains cwd/results conflict"

cat > "$TEST_TMPDIR/outside-probe.dat" <<'EOF_TC'
TARGET: alpha/core/ThingProcessor.cpp:ThingProcessorRead:3
HYPOTHESIS-ID: H-outside
CATEGORY: bounds
abc
EOF_TC
outside_rc=0
outside_out=$("$PROBE" --dry-run "$TEST_TMPDIR/outside-probe.dat" 2>&1) || outside_rc=$?
assert_eq "2" "$outside_rc" "probe: external testcase exits 2"
assert_match 'testcase must live under RESULTS_DIR/scratch-N' "$outside_out" \
  "probe: external testcase explains scratch dir requirement"
dry=$(PROBE_ALLOW_EXTERNAL_TESTCASE=1 "$PROBE" --dry-run "$TEST_TMPDIR/outside-probe.dat")
assert_match 'asan_output=.*/outside-probe.asan.txt' "$dry" \
  "probe: external testcase override preserves local experiments"

dry=$("$PROBE" --dry-run --want auto "$RESULTS_DIR/scratch-1/tc.dat")
assert_match 'want=ThingProcessorRead' "$dry" "probe: --want auto derives function from TARGET"

cat > "$RESULTS_DIR/scratch-1/operator.dat" <<'EOF_TC'
TARGET: alpha/core/Thing.cpp:mozilla::Thing::operator+():7
HYPOTHESIS-ID: H-operator
EOF_TC
dry=$("$PROBE" --dry-run --want auto "$RESULTS_DIR/scratch-1/operator.dat")
assert_match 'want=mozilla::Thing::operator\\\+\\\(\\\)' "$dry" "probe: --want auto escapes regex metacharacters"

cat > "$RESULTS_DIR/scratch-1/browser.html" <<'EOF_TC'
<!-- TARGET: alpha/dom/Thing.cpp:RenderThing:9 -->
<!-- HYPOTHESIS-ID: H-browser -->
<!-- CATEGORY: state -->
<script>console.log('TESTCASE_EXECUTED');</script>
EOF_TC
dry=$("$PROBE" --dry-run --want auto "$RESULTS_DIR/scratch-1/browser.html")
assert_match 'run-sanitizer-multi asan browser' "$dry" "probe: browser uses run-sanitizer-multi coverage owner"
assert_not_match 'hits-then-asan' "$dry" "probe: browser avoids duplicate coverage wrapper"

: > "$RESULTS_DIR/state/claims.jsonl"
source "$SCRIPT_ROOT/lib/structured_state.sh"
source "$SCRIPT_ROOT/lib/prompt.sh"
# Enable build_work_card_directive's stderr diagnostic so that if this
# block ever flakes again (it has, historically — see SIGPIPE fix in
# tests/helpers.sh and the relative-bin/state path fix), the captured
# output explains *why* the directive came back empty.
export WORK_CARD_DIRECTIVE_DEBUG=1
directive=$(build_work_card_directive 1 2>/tmp/wcd-debug-block.$$ )
debug_block=$(cat /tmp/wcd-debug-block.$$ 2>/dev/null); rm -f /tmp/wcd-debug-block.$$
assert_eq "" "$directive" "prompt: structured active hypothesis blocks new card claim${debug_block:+ (debug: $debug_block)}"
export WORK_CARD_FORCE_CLAIM=1
directive=$(build_work_card_directive 1 2>/tmp/wcd-debug-render.$$ )
debug_render=$(cat /tmp/wcd-debug-render.$$ 2>/dev/null); rm -f /tmp/wcd-debug-render.$$
unset WORK_CARD_FORCE_CLAIM
unset WORK_CARD_DIRECTIVE_DEBUG
assert_match 'ASSIGNED WORK CARD' "$directive" "prompt: work card directive renders${debug_render:+ (debug: $debug_render)}"
assert_match '\*\*File:\*\* `' "$directive" "prompt: work card directive includes file"
assert_match '\*\*Fix commits:\*\* ' "$directive" "prompt: work card directive includes fix-hash field"
assert_match 'PATCH-\* is only the work-card id, not a VCS revision' "$directive" \
  "prompt: work card directive warns not to use card id as commit"
wcd_src=$(awk '
  /^build_work_card_directive\(\) \{/ { in_func=1 }
  in_func { print }
  in_func && $0 == "}" { exit }
' "$SCRIPT_ROOT/lib/prompt.sh")
wcd_card_jq_calls=$(grep -cF 'printf '\''%s'\'' "$card" | jq' <<< "$wcd_src" || true)
assert_eq "1" "$wcd_card_jq_calls" "prompt: work card directive parses card JSON in one jq pass"

prompt_claim_results="$TEST_TMPDIR/prompt-claim-results"
mkdir -p "$prompt_claim_results/state"
mk_state_dir "$prompt_claim_results"
cat > "$prompt_claim_results/work-cards.jsonl" <<'JSONL'
{"id":"WORK-PROMPT-A","kind":"ranked-source","target_slug":"testproject","subsystem":"alpha","file":"alpha/a.c","mode":"generic","strategy":"S1","score":100,"status":"unclaimed"}
{"id":"WORK-PROMPT-B","kind":"ranked-source","target_slug":"testproject","subsystem":"beta","file":"beta/b.c","mode":"generic","strategy":"S1","score":90,"status":"unclaimed"}
JSONL
prompt_claim_a=$(RESULTS_DIR="$prompt_claim_results" build_work_card_directive 1)
prompt_claim_b=$(RESULTS_DIR="$prompt_claim_results" build_work_card_directive 2)
prompt_claim_a_id=$(printf '%s\n' "$prompt_claim_a" | sed -n 's/^- \*\*ID:\*\* //p' | head -1)
prompt_claim_b_id=$(printf '%s\n' "$prompt_claim_b" | sed -n 's/^- \*\*ID:\*\* //p' | head -1)
assert_eq "WORK-PROMPT-A" "$prompt_claim_a_id" "prompt: first work card directive claims top card"
assert_eq "WORK-PROMPT-B" "$prompt_claim_b_id" "prompt: second work card directive skips freshly claimed card"
prompt_claim_rows=$(grep -c '"status": "claimed"' "$prompt_claim_results/state/claims.jsonl" 2>/dev/null || true)
assert_eq "2" "$prompt_claim_rows" "prompt: work card directive records prompt-time leases"

prompt_fields_results="$TEST_TMPDIR/prompt-fields-results"
mkdir -p "$prompt_fields_results/state"
mk_state_dir "$prompt_fields_results"
cat > "$prompt_fields_results/work-cards.jsonl" <<'JSONL'
{"id":"WORK-FIELDS","kind":"recon-hypothesis","target_slug":"testproject","subsystem":"alpha/core","file":"alpha/core/a.c","mode":"generic","strategy":"S1","score":321,"status":"unclaimed","reason":"recon hypothesis | class=bounds | validator=Promote | tricky title with spaces | notes with punctuation: a=b, c/d","seed":"seed with spaces","fix_hashes":["abc123","def456"],"patch_cards":["PATCH-one","PATCH two"],"find_id":"FIND-777","recon":{"id":"RECON-777","class":"bounds","line":77,"validator_verdict":"Promote"}}
JSONL
fields_list=$("$STATE" --results-dir "$prompt_fields_results" --target-path "$TARGET_ROOT" --target-slug "$TARGET_SLUG" \
  list-cards --mode generic --limit 1)
assert_match '"fix_hashes": \["abc123", "def456"\]' "$fields_list" \
  "state: list-cards keeps non-empty fix hashes"
assert_match '"patch_cards": \["PATCH-one", "PATCH two"\]' "$fields_list" \
  "state: list-cards keeps non-empty related patch cards"
assert_match '"seed": "seed with spaces"' "$fields_list" "state: list-cards keeps non-empty seed"
assert_not_match '"invalid_fix_hashes": \[\]' "$fields_list" "state: list-cards drops empty optional hash fields"
prompt_fields=$(RESULTS_DIR="$prompt_fields_results" build_work_card_directive 1)
assert_match 'Seed.*seed with spaces' "$prompt_fields" \
  "prompt: one-pass card parser preserves seed with spaces"
assert_match 'Fix commits.*abc123, def456' "$prompt_fields" \
  "prompt: one-pass card parser joins fix hashes"
assert_match 'Related patch cards.*PATCH-one, PATCH two' "$prompt_fields" \
  "prompt: one-pass card parser joins patch cards"
assert_match 'Recon ID:.*RECON-777' "$prompt_fields" \
  "prompt: one-pass card parser renders recon id"
assert_match 'Line:.*77' "$prompt_fields" \
  "prompt: one-pass card parser renders recon line"
assert_match 'Validator verdict:.*Promote' "$prompt_fields" \
  "prompt: one-pass card parser renders validator verdict"
assert_match 'findings/FIND-777/report.md' "$prompt_fields" \
  "prompt: one-pass card parser renders pre-filed FIND path"

# ── Diagnostic surface for build_work_card_directive ─────────────────
# Each silent-return branch emits a stderr line under
# WORK_CARD_DIRECTIVE_DEBUG=1. Future flakes (the function has six
# return-empty paths) leave evidence in the captured assertion output.

# Branch 1: missing work-cards.jsonl.
diag_tmp=$(mktemp -d)
WORK_CARD_DIRECTIVE_DEBUG=1 RESULTS_DIR="$diag_tmp" \
  build_work_card_directive 1 >/dev/null 2>"$diag_tmp/err"
diag=$(cat "$diag_tmp/err")
assert_match 'work-cards.jsonl missing or empty' "$diag" \
  "build_work_card_directive: debug names missing work-cards.jsonl"
rm -rf "$diag_tmp"

# Branch 2: bin/state absent / not executable.
diag_tmp=$(mktemp -d)
WORK_CARD_DIRECTIVE_DEBUG=1 SCRIPT_ROOT="$diag_tmp" RESULTS_DIR="$diag_tmp" \
  build_work_card_directive 1 >/dev/null 2>"$diag_tmp/err"
diag=$(cat "$diag_tmp/err")
assert_match 'bin/state not executable' "$diag" \
  "build_work_card_directive: debug names missing bin/state"
rm -rf "$diag_tmp"

# Absolute-path resolution: function works regardless of CWD. Run it from
# inside /tmp (where bin/state is not on the relative path) and confirm
# the directive still renders. Prior implementation broke here.
pushd /tmp >/dev/null
export WORK_CARD_FORCE_CLAIM=1
directive_abs=$(build_work_card_directive 1)
unset WORK_CARD_FORCE_CLAIM
popd >/dev/null
assert_match 'ASSIGNED WORK CARD' "$directive_abs" \
  "build_work_card_directive: renders when invoked from non-project CWD (absolute bin/state)"

# ── explain-queue: aggregated default + --all + --top sizing ──
explain_results="$TEST_TMPDIR/explain-queue-results"
mkdir -p "$explain_results"
mk_state_dir "$explain_results"
# Five reasons, varying counts: not-auditable=4, terminal:DISCARDED=2, claimed-until=2, eligible=1, mode-incompatible=1
# (static expansion of a former python generator loop)
cat > "$explain_results/work-cards.jsonl" <<'JSONL'
{"id": "WORK-NA-0", "kind": "ranked-source", "file": "third_party/skip0.c", "subsystem": "skip", "mode": "generic", "score": 1, "reason": "rank"}
{"id": "WORK-NA-1", "kind": "ranked-source", "file": "third_party/skip1.c", "subsystem": "skip", "mode": "generic", "score": 1, "reason": "rank"}
{"id": "WORK-NA-2", "kind": "ranked-source", "file": "third_party/skip2.c", "subsystem": "skip", "mode": "generic", "score": 1, "reason": "rank"}
{"id": "WORK-NA-3", "kind": "ranked-source", "file": "third_party/skip3.c", "subsystem": "skip", "mode": "generic", "score": 1, "reason": "rank"}
{"id": "WORK-TD-0", "kind": "ranked-source", "file": "alpha/term0.c", "subsystem": "alpha", "mode": "generic", "score": 1, "reason": "rank", "status": "discarded"}
{"id": "WORK-TD-1", "kind": "ranked-source", "file": "alpha/term1.c", "subsystem": "alpha", "mode": "generic", "score": 1, "reason": "rank", "status": "discarded"}
{"id": "WORK-CU-0", "kind": "ranked-source", "file": "alpha/claim0.c", "subsystem": "alpha", "mode": "generic", "score": 1, "reason": "rank"}
{"id": "WORK-CU-1", "kind": "ranked-source", "file": "alpha/claim1.c", "subsystem": "alpha", "mode": "generic", "score": 1, "reason": "rank"}
{"id": "WORK-OK-0", "kind": "ranked-source", "file": "alpha/ok.c", "subsystem": "alpha", "mode": "generic", "score": 1, "reason": "rank"}
{"id": "WORK-MI-0", "kind": "ranked-source", "file": "alpha/mode.c", "subsystem": "alpha", "mode": "browser", "score": 1, "reason": "rank"}
JSONL
# Synthesize claims.jsonl entries that are still within TTL for the CU rows
# (reusing the future-dated claim window computed for health_results above).
for explain_claim in 'WORK-CU-0|claimed' 'WORK-CU-1|claimed' 'WORK-TD-0|discarded' 'WORK-TD-1|discarded'; do
  printf '{"agent": "9", "card_id": "%s", "claimed_at": "%s", "expires_at": "%s", "mode": "generic", "role": "reproduce", "status": "%s"}\n' \
    "${explain_claim%%|*}" "$claimed_at" "$expires_at" "${explain_claim##*|}"
done > "$explain_results/state/claims.jsonl"

# Default: aggregated digest, mode=generic. Expect bounded JSONL with count/reason/sample_id.
default_out=$("$STATE" --results-dir "$explain_results" --target-path "$TARGET_ROOT" --target-slug "$TARGET_SLUG" \
  explain-queue --mode generic)
default_lines=$(printf '%s\n' "$default_out" | grep -c '^{')
assert_match '"reason":' "$default_out" "explain-queue: aggregated default has reason field"
assert_match '"count":' "$default_out" "explain-queue: aggregated default has count field"
assert_match '"sample_id":' "$default_out" "explain-queue: aggregated default carries one sample id per reason"
assert_match '"reason": "claimed-until"' "$default_out" "explain-queue: aggregated default normalizes claimed-until:<ts>"
assert_not_match '"file":' "$default_out" "explain-queue: aggregated default suppresses per-card detail"
# claim-rows synthesized for two cards → "claimed-until" bucket has count 2.
assert_match '"count": 2, "reason": "claimed-until"' "$default_out" \
  "explain-queue: claimed-until bucket counts both freshly-claimed cards"

context_out=$("$STATE" --results-dir "$explain_results" --target-path "$TARGET_ROOT" --target-slug "$TARGET_SLUG" \
  explain-queue --agent 3 --mode generic --role reproduce --strategy S3 --top 12)
assert_not_match 'usage: state' "$context_out" "explain-queue: accepts resume-shaped agent/role/strategy flags"
assert_match '"reason": "strategy-incompatible:none"' "$context_out" \
  "explain-queue --strategy: explains otherwise eligible nonmatching cards"
explain_src=$(awk '
  /^def explain_queue\(/ { in_func=1 }
  in_func { print }
  /^def is_promoted_recon_card\(/ { exit }
' "$SCRIPT_ROOT/lib/workqueue.py")
assert_not_match 'active_hypothesis_card_ids|active_hypothesis_surfaces|active_hypothesis_subsystems' "$explain_src" \
  "explain-queue: derives active hypothesis sets from one preloaded state pass"
assert_not_match 'claimed_card_surfaces|claimed_card_subsystems' "$explain_src" \
  "explain-queue: derives claimed sets from one preloaded claims pass"

# --top 2 keeps the two biggest buckets and rolls the rest into a _more tail.
top_out=$("$STATE" --results-dir "$explain_results" --target-path "$TARGET_ROOT" --target-slug "$TARGET_SLUG" \
  explain-queue --mode generic --top 2)
assert_match '"reason": "_more"' "$top_out" "explain-queue: --top truncates and emits _more tail"
assert_match '"reasons_remaining":' "$top_out" "explain-queue: _more tail reports remaining reason count"
top_lines=$(printf '%s\n' "$top_out" | grep -c '^{')
assert_eq "3" "$top_lines" "explain-queue: --top 2 yields 2 kept rows + 1 tail row"

# --all returns the verbose per-card form (used by bin/audit's queue-exhaustion report).
all_out=$("$STATE" --results-dir "$explain_results" --target-path "$TARGET_ROOT" --target-slug "$TARGET_SLUG" \
  explain-queue --all --mode generic)
all_lines=$(printf '%s\n' "$all_out" | grep -c '^{')
assert_eq "10" "$all_lines" "explain-queue: --all emits one row per work card"
assert_match '"file":' "$all_out" "explain-queue: --all includes per-card fields"
assert_not_match '"sample_id":' "$all_out" "explain-queue: --all does not aggregate"

ownership_results="$TEST_TMPDIR/explain-ownership-results"
mkdir -p "$ownership_results"
mk_state_dir "$ownership_results"
cat > "$ownership_results/work-cards.jsonl" <<'JSONL'
{"id":"WORK-ACTIVE","kind":"ranked-source","file":"owned/a.c","subsystem":"owned","mode":"generic","score":10,"reason":"rank"}
{"id":"WORK-ACTIVE-SIBLING","kind":"ranked-source","file":"owned/a.c","subsystem":"fresh","mode":"generic","score":9,"reason":"rank"}
{"id":"WORK-CLAIMED","kind":"ranked-source","file":"claimed/b.c","subsystem":"claimed-sub","mode":"generic","score":8,"reason":"rank"}
{"id":"WORK-CLAIMED-SIBLING","kind":"ranked-source","file":"claimed/b.c","subsystem":"fresh","mode":"generic","score":7,"reason":"rank"}
{"id":"WORK-CLAIMED-SUBSYSTEM","kind":"ranked-source","file":"claimed/c.c","subsystem":"claimed-sub","mode":"generic","score":6,"reason":"rank"}
JSONL
printf '{"id":"H-ACTIVE","agent":"1","card_id":"WORK-ACTIVE","hypothesis":"active","file":"owned/a.c:foo:1","status":"PENDING","created_at":"2026-06-01T00:00:00Z"}\n' \
  > "$ownership_results/state/hypotheses.jsonl"
printf '{"agent":"2","card_id":"WORK-CLAIMED","claimed_at":"%s","expires_at":"%s","status":"claimed"}\n' \
  "$claimed_at" "$expires_at" > "$ownership_results/state/claims.jsonl"
ownership_all=$("$STATE" --results-dir "$ownership_results" --target-path "$TARGET_ROOT" --target-slug "$TARGET_SLUG" \
  explain-queue --all --mode generic)
assert_match '"id": "WORK-ACTIVE", .*"reason": "active-hypothesis"' "$ownership_all" \
  "explain-queue: active card reason preserved after one-pass set derivation"
assert_match '"id": "WORK-ACTIVE-SIBLING", .*"reason": "active-surface"' "$ownership_all" \
  "explain-queue: active surface reason preserved after one-pass set derivation"
assert_match '"id": "WORK-CLAIMED", .*"reason": "claimed-until:' "$ownership_all" \
  "explain-queue: claimed card reason preserved after one-pass set derivation"
assert_match '"id": "WORK-CLAIMED-SIBLING", .*"reason": "claimed-surface"' "$ownership_all" \
  "explain-queue: claimed surface reason preserved after one-pass set derivation"
assert_match '"id": "WORK-CLAIMED-SUBSYSTEM", .*"reason": "claimed-subsystem"' "$ownership_all" \
  "explain-queue: claimed subsystem reason preserved after one-pass set derivation"

# Aggregated default should be byte-thrifty: well under per-card form.
default_bytes=$(printf '%s' "$default_out" | wc -c | tr -d ' ')
all_bytes=$(printf '%s' "$all_out" | wc -c | tr -d ' ')
if [ "$default_bytes" -lt "$all_bytes" ]; then
  pass "explain-queue: aggregated default smaller than --all ($default_bytes < $all_bytes)"
else
  fail "explain-queue: aggregated default smaller than --all" "default=$default_bytes all=$all_bytes"
fi

diversity_results="$TEST_TMPDIR/diversity-results"
mkdir -p "$diversity_results/state"
mk_state_dir "$diversity_results"
# Deterministic card set (was a python generator loop; the expansion is
# static, so write the rows directly): five include/nlohmann cards scored
# 99..95 and four src/parser cards scored 19..16, strategies S1..S5/S1..S4.
{
  for i in 1 2 3 4 5; do
    printf '{"id": "WORK-ALPHA-%d", "kind": "ranked-source", "target_slug": "testproject", "subsystem": "include/nlohmann", "file": "include/nlohmann/json%d.hpp", "mode": "generic", "strategy": "S%d", "score": %d, "status": "unclaimed"}\n' \
      "$i" "$i" "$i" "$((100 - i))"
  done
  for i in 1 2 3 4; do
    printf '{"id": "WORK-BETA-%d", "kind": "ranked-source", "target_slug": "testproject", "subsystem": "src/parser", "file": "src/parser/p%d.cpp", "mode": "generic", "strategy": "S%d", "score": %d, "status": "unclaimed"}\n' \
      "$i" "$i" "$i" "$((20 - i))"
  done
} > "$diversity_results/work-cards.jsonl"
cat > "$diversity_results/state/hypotheses.jsonl" <<'JSONL'
{"id":"H-alpha","agent":"1","card_id":"WORK-ALPHA-1","status":"PENDING","file":"include/nlohmann/json1.hpp","subsystem":"include/nlohmann"}
JSONL
diverse_card=$("$STATE" --results-dir "$diversity_results" --target-path "$TARGET_ROOT" --target-slug "$TARGET_SLUG" \
  next-card --agent 2 --mode generic --role reproduce --peek)
assert_match '"subsystem": "src/parser"' "$diverse_card" "state: generic card claims prefer different subsystem when queue has depth"

printf 'include/nlohmann\n' > "$diversity_results/.guard_saturated_subsystems"
guard_diverse_card=$("$STATE" --results-dir "$diversity_results" --target-path "$TARGET_ROOT" --target-slug "$TARGET_SLUG" \
  next-card --agent 3 --mode generic --role reproduce --peek)
assert_match '"subsystem": "src/parser"' "$guard_diverse_card" "state: guard-saturated subsystem is skipped while alternatives exist"

# Small queues still enforce one subsystem/card per agent. This covers the
# regression where the diversity floor allowed overlap whenever fewer than
# WORK_CARD_SUBSYSTEM_DIVERSITY_MIN_ELIGIBLE cards remained.
disjoint_results="$TEST_TMPDIR/disjoint-results"
mkdir -p "$disjoint_results/state"
: > "$disjoint_results/state/claims.jsonl"
: > "$disjoint_results/state/runs.jsonl"
: > "$disjoint_results/state/events.jsonl"
: > "$disjoint_results/state/notes.jsonl"
cat > "$disjoint_results/work-cards.jsonl" <<'JSONL'
{"id":"WORK-A1","kind":"ranked-source","target_slug":"testproject","subsystem":"alpha/core","file":"alpha/core/a.c","mode":"generic","strategy":"S1","score":3,"status":"unclaimed"}
{"id":"WORK-A2","kind":"ranked-source","target_slug":"testproject","subsystem":"alpha/core","file":"alpha/core/b.c","mode":"generic","strategy":"S2","score":2,"status":"unclaimed"}
{"id":"WORK-B1","kind":"ranked-source","target_slug":"testproject","subsystem":"beta/io","file":"beta/io/c.c","mode":"generic","strategy":"S1","score":1,"status":"unclaimed"}
JSONL
cat > "$disjoint_results/state/hypotheses.jsonl" <<'JSONL'
{"id":"H-alpha","agent":"1","card_id":"WORK-A1","status":"PENDING","file":"alpha/core/a.c","subsystem":"alpha/core"}
JSONL
small_disjoint_card=$("$STATE" --results-dir "$disjoint_results" --target-path "$TARGET_ROOT" --target-slug "$TARGET_SLUG" \
  next-card --agent 2 --mode generic --role reproduce --peek)
assert_match '"subsystem": "beta/io"' "$small_disjoint_card" "state: small queue enforces disjoint subsystem assignment"
small_explain=$("$STATE" --results-dir "$disjoint_results" --target-path "$TARGET_ROOT" --target-slug "$TARGET_SLUG" \
  explain-queue --mode generic)
assert_match '"reason": "claimed-subsystem".*"sample_id": "WORK-A2"' "$small_explain" \
  "state: explain-queue reports same-subsystem cards as claimed-subsystem"

only_alpha_results="$TEST_TMPDIR/only-alpha-results"
mkdir -p "$only_alpha_results/state"
: > "$only_alpha_results/state/claims.jsonl"
: > "$only_alpha_results/state/runs.jsonl"
: > "$only_alpha_results/state/events.jsonl"
: > "$only_alpha_results/state/notes.jsonl"
grep 'WORK-A' "$disjoint_results/work-cards.jsonl" > "$only_alpha_results/work-cards.jsonl"
cp "$disjoint_results/state/hypotheses.jsonl" "$only_alpha_results/state/hypotheses.jsonl"
# Subsystem ownership is a SOFT preference, not a hard skip: when the
# queue contains ONLY same-subsystem cards, the second agent must still
# fall back and claim one rather than starve. Without that fallback a
# focused area with one parallel agent would block all other agents.
overlap_card=$("$STATE" --results-dir "$only_alpha_results" --target-path "$TARGET_ROOT" --target-slug "$TARGET_SLUG" \
  next-card --agent 2 --mode generic --role reproduce --peek 2>/dev/null || true)
if grep -q '"subsystem": "alpha/core"' <<<"$overlap_card"; then
  pass "state: same-subsystem-only queue falls back to overlap rather than starving the agent"
else
  fail "state: same-subsystem-only queue falls back to overlap rather than starving the agent" "got: $overlap_card"
fi

# Focused-mode co-investigation: a focused-mode agent assigned to a hot
# subsystem must be allowed to co-investigate alongside a sibling
# generic agent that owns it. The subsystem-ownership soft preference
# only applies in generic mode; otherwise we'd block focused agents
# from doing exactly the parallel exploration they're for.
focused_results="$TEST_TMPDIR/focused-coinvest-results"
mkdir -p "$focused_results/state"
: > "$focused_results/state/claims.jsonl"
: > "$focused_results/state/runs.jsonl"
: > "$focused_results/state/events.jsonl"
: > "$focused_results/state/notes.jsonl"
cat > "$focused_results/work-cards.jsonl" <<'JSONL'
{"id":"WORK-FOCUS-A1","kind":"ranked-source","target_slug":"testproject","subsystem":"hot/parser","file":"hot/parser/x.c","mode":"compile","strategy":"S1","score":5,"status":"unclaimed"}
{"id":"WORK-FOCUS-A2","kind":"ranked-source","target_slug":"testproject","subsystem":"hot/parser","file":"hot/parser/y.c","mode":"compile","strategy":"S2","score":4,"status":"unclaimed"}
{"id":"WORK-FOCUS-B1","kind":"ranked-source","target_slug":"testproject","subsystem":"cold/io","file":"cold/io/a.c","mode":"compile","strategy":"S1","score":1,"status":"unclaimed"}
JSONL
cat > "$focused_results/state/hypotheses.jsonl" <<'JSONL'
{"id":"H-hot","agent":"1","card_id":"WORK-FOCUS-A1","status":"PENDING","file":"hot/parser/x.c","subsystem":"hot/parser"}
JSONL
focused_card=$("$STATE" --results-dir "$focused_results" --target-path "$TARGET_ROOT" --target-slug "$TARGET_SLUG" \
  next-card --agent 2 --mode compile --role reproduce --peek 2>/dev/null || true)
if grep -q '"subsystem": "hot/parser"' <<<"$focused_card"; then
  pass "state: focused-mode agent can co-investigate owned subsystem with a sibling"
else
  fail "state: focused-mode agent can co-investigate owned subsystem with a sibling" \
       "got: $focused_card (expected hot/parser to remain claimable)"
fi

# ── P3: validator-Promoted recon card precedence ───────────────────
# When the deep-validator marks a recon hypothesis Promote, that card
# must be claimed by at least one agent before the strategy filter
# applies. Without this, an agent pinned to S2 by rotation drains S2
# patch cards while a Promote-S7 sits unclaimed in the queue — exactly
# the failure mode that drove the May-23 pcre2 benchmark to 0 crashes.
promoted_results="$TEST_TMPDIR/promoted-recon-results"
mkdir -p "$promoted_results/state"
: > "$promoted_results/state/claims.jsonl"
: > "$promoted_results/state/runs.jsonl"
: > "$promoted_results/state/events.jsonl"
: > "$promoted_results/state/notes.jsonl"
: > "$promoted_results/state/hypotheses.jsonl"
cat > "$promoted_results/work-cards.jsonl" <<'JSONL'
{"id":"WORK-PROMO-S7","kind":"recon-hypothesis","target_slug":"testproject","subsystem":"src/parser","file":"src/parser/p.c","mode":"generic","strategy":"S7","score":1000,"status":"unclaimed","recon":{"id":"RECON-aaa","validator_verdict":"Promote","line":42,"class":"OOB-write","strategies":["S5","S7"]}}
{"id":"WORK-PROMO-S5","kind":"recon-hypothesis","target_slug":"testproject","subsystem":"src/parser","file":"src/parser/p.c","mode":"generic","strategy":"S5","score":1000,"status":"unclaimed","recon":{"id":"RECON-aaa","validator_verdict":"Promote","line":42,"class":"OOB-write","strategies":["S5","S7"]}}
{"id":"WORK-RECON-NV-S7","kind":"recon-hypothesis","target_slug":"testproject","subsystem":"src/codec","file":"src/codec/c.c","mode":"generic","strategy":"S7","score":200,"status":"unclaimed","recon":{"id":"RECON-bbb","validator_verdict":"NEEDS-VERIFICATION","line":12,"class":"OOB-read","strategies":["S5","S7"]}}
{"id":"WORK-PATCH-S2","kind":"s1-patch","target_slug":"testproject","subsystem":"src/match","file":"src/match/m.c","mode":"generic","strategy":"S2","score":140,"status":"unclaimed","description":"S2 patch card"}
{"id":"WORK-PATCH-S3","kind":"s1-patch","target_slug":"testproject","subsystem":"src/parse","file":"src/parse/q.c","mode":"generic","strategy":"S3","score":130,"status":"unclaimed","description":"S3 patch card"}
JSONL

# Agent pinned to S2 (the rotation-trap case) MUST be diverted onto the
# Promoted card even though no S7 was requested. This is the headline
# P3 behaviour.
promo_claim_a=$("$STATE" --results-dir "$promoted_results" --target-path "$TARGET_ROOT" --target-slug "$TARGET_SLUG" \
  next-card --agent 1 --mode generic --role reproduce --strategy S2)
promo_claim_a_id=$(json_id "$promo_claim_a")
case "$promo_claim_a_id" in
  WORK-PROMO-S7|WORK-PROMO-S5)
    pass "state: P3 precedence steers S2-pinned agent onto Promote-recon card"
    ;;
  *)
    fail "state: P3 precedence steers S2-pinned agent onto Promote-recon card" \
         "got: $promo_claim_a_id (expected WORK-PROMO-S5 or WORK-PROMO-S7)"
    ;;
esac

# A second agent calling claim sees that the Promote pool now has an
# active holder — precedence falls through and the strategy filter
# applies as normal. The S2-pinned agent should now receive WORK-PATCH-S2.
promo_claim_b=$("$STATE" --results-dir "$promoted_results" --target-path "$TARGET_ROOT" --target-slug "$TARGET_SLUG" \
  next-card --agent 2 --mode generic --role reproduce --strategy S2)
promo_claim_b_id=$(json_id "$promo_claim_b")
assert_eq "WORK-PATCH-S2" "$promo_claim_b_id" \
  "state: P3 precedence releases once one Promote card is actively held"

# Non-Promote recon cards (NEEDS-VERIFICATION etc.) do NOT activate the
# precedence gate. Build a fresh fixture without any Promote card and
# verify the strategy filter applies straight away.
unpromo_results="$TEST_TMPDIR/unpromoted-recon-results"
mkdir -p "$unpromo_results/state"
: > "$unpromo_results/state/claims.jsonl"
: > "$unpromo_results/state/runs.jsonl"
: > "$unpromo_results/state/events.jsonl"
: > "$unpromo_results/state/notes.jsonl"
: > "$unpromo_results/state/hypotheses.jsonl"
grep -v PROMO "$promoted_results/work-cards.jsonl" > "$unpromo_results/work-cards.jsonl"
unpromo_claim=$("$STATE" --results-dir "$unpromo_results" --target-path "$TARGET_ROOT" --target-slug "$TARGET_SLUG" \
  next-card --agent 1 --mode generic --role reproduce --strategy S2)
unpromo_claim_id=$(json_id "$unpromo_claim")
assert_eq "WORK-PATCH-S2" "$unpromo_claim_id" \
  "state: NEEDS-VERIFICATION recon does NOT trigger Promote precedence"

# Operator opt-out: WORK_CARD_PROMOTED_RECON_PRECEDENCE=0 disables the
# gate even when a Promote card is unclaimed. Useful for A/B comparing
# the old behaviour without code changes.
optout_results="$TEST_TMPDIR/promoted-optout-results"
mkdir -p "$optout_results/state"
: > "$optout_results/state/claims.jsonl"
: > "$optout_results/state/runs.jsonl"
: > "$optout_results/state/events.jsonl"
: > "$optout_results/state/notes.jsonl"
: > "$optout_results/state/hypotheses.jsonl"
cp "$promoted_results/work-cards.jsonl" "$optout_results/work-cards.jsonl"
optout_claim=$(WORK_CARD_PROMOTED_RECON_PRECEDENCE=0 "$STATE" --results-dir "$optout_results" --target-path "$TARGET_ROOT" --target-slug "$TARGET_SLUG" \
  next-card --agent 1 --mode generic --role reproduce --strategy S2)
optout_claim_id=$(json_id "$optout_claim")
assert_eq "WORK-PATCH-S2" "$optout_claim_id" \
  "state: WORK_CARD_PROMOTED_RECON_PRECEDENCE=0 disables the gate"

# ── P3 (G): override gracefully falls through on surface block ──────
# When every unclaimed Promote card shares an owned surface (an agent
# already has a hypothesis on the same file), the precedence override's
# first pass yields no candidate. The claim helper must fall through
# to the normal queue rather than deadlock — otherwise an agent that
# happened to land on the same file as a Promote card before the gate
# armed would starve every other agent for the rest of the iteration.
g_results="$TEST_TMPDIR/p3-surface-block"
mkdir -p "$g_results/state"
: > "$g_results/state/claims.jsonl"
: > "$g_results/state/runs.jsonl"
: > "$g_results/state/events.jsonl"
: > "$g_results/state/notes.jsonl"
# Three Promote cards, all on the SAME file (src/cluster/p.c). Agent 1
# holds an active hypothesis on that surface, so it owns the surface
# from the queue's perspective.
cat > "$g_results/work-cards.jsonl" <<'JSONL'
{"id":"WORK-G-PROMO-A","kind":"recon-hypothesis","target_slug":"tg","subsystem":"src/cluster","file":"src/cluster/p.c","mode":"generic","strategy":"S7","allowed_strategies":["S5","S7"],"score":1000,"status":"unclaimed","recon":{"id":"RECON-g-a","validator_verdict":"Promote","line":10,"class":"OOB-write"}}
{"id":"WORK-G-PROMO-B","kind":"recon-hypothesis","target_slug":"tg","subsystem":"src/cluster","file":"src/cluster/p.c","mode":"generic","strategy":"S7","allowed_strategies":["S5","S7"],"score":1000,"status":"unclaimed","recon":{"id":"RECON-g-b","validator_verdict":"Promote","line":20,"class":"OOB-write"}}
{"id":"WORK-G-PROMO-C","kind":"recon-hypothesis","target_slug":"tg","subsystem":"src/cluster","file":"src/cluster/p.c","mode":"generic","strategy":"S7","allowed_strategies":["S5","S7"],"score":1000,"status":"unclaimed","recon":{"id":"RECON-g-c","validator_verdict":"Promote","line":30,"class":"OOB-write"}}
{"id":"WORK-G-PATCH","kind":"s1-patch","target_slug":"tg","subsystem":"src/other","file":"src/other/q.c","mode":"generic","strategy":"S2","score":80,"status":"unclaimed","description":"fallback patch card"}
JSONL
cat > "$g_results/state/hypotheses.jsonl" <<'JSONL'
{"id":"H-owner","agent":"2","card_id":"WORK-G-PROMO-A","status":"PENDING","file":"src/cluster/p.c","subsystem":"src/cluster"}
JSONL

# Agent 2 owns the cluster surface via PENDING hypothesis. An agent 1
# claim under --strategy S2 would normally be blocked by P3 from the
# S2 card (Promote precedence outranks the strategy filter), so the
# override tries Promote first → all three Promote cards are gated
# off because their surface is owned. Fallback must engage and pick
# WORK-G-PATCH rather than returning nothing.
g_claim=$("$STATE" --results-dir "$g_results" --target-path "$TARGET_ROOT" --target-slug "$TARGET_SLUG" \
  next-card --agent 1 --mode generic --role reproduce --strategy S2 --peek)
g_claim_id=$(json_id "$g_claim" || true)
assert_eq "WORK-G-PATCH" "$g_claim_id" \
  "G: P3 override falls through to normal queue when every Promote shares an owned surface"

# Cross-check: the *owner* agent (agent 2) should still be able to claim
# additional cards on its own subsystem. The productive-subsystem and
# own_active_claim relaxations allow that — verifies the surface-block
# fallback doesn't accidentally close that door too.
# Mark agent 2 as having produced a CRASH on the same subsystem so the
# productive-subsystem relaxation lets it co-investigate siblings.
cat > "$g_results/state/hypotheses.jsonl" <<'JSONL'
{"id":"H-owner","agent":"2","card_id":"WORK-G-PROMO-A","status":"CRASH-001-1","file":"src/cluster/p.c","subsystem":"src/cluster"}
JSONL
mkdir -p "$g_results/crashes/CRASH-001-1"
g_owner_claim=$("$STATE" --results-dir "$g_results" --target-path "$TARGET_ROOT" --target-slug "$TARGET_SLUG" \
  next-card --agent 2 --mode generic --role reproduce --peek)
g_owner_claim_id=$(json_id "$g_owner_claim" || true)
# Any of the three Promote cards is acceptable — once the productive
# CRASH cleared the active-hypothesis lock, the queue is free to hand
# back A or any of its siblings. The point is that the agent isn't
# starved out of the subsystem after producing a hit there.
case "$g_owner_claim_id" in
  WORK-G-PROMO-A|WORK-G-PROMO-B|WORK-G-PROMO-C)
    pass "G: productive agent can still claim Promote cards on its owned subsystem" ;;
  *)
    fail "G: productive agent can still claim Promote cards on its owned subsystem" \
         "got '$g_owner_claim_id'" ;;
esac

# Edge case: every Promote surface-blocked AND no fallback card exists →
# claim returns nothing rather than spinning.
g_empty="$TEST_TMPDIR/p3-surface-block-empty"
mkdir -p "$g_empty/state"
: > "$g_empty/state/claims.jsonl"
: > "$g_empty/state/runs.jsonl"
: > "$g_empty/state/events.jsonl"
: > "$g_empty/state/notes.jsonl"
# Only Promote cards, all on a surface owned by another agent.
grep PROMO "$g_results/work-cards.jsonl" > "$g_empty/work-cards.jsonl"
cat > "$g_empty/state/hypotheses.jsonl" <<'JSONL'
{"id":"H-block","agent":"2","card_id":"WORK-G-PROMO-A","status":"PENDING","file":"src/cluster/p.c","subsystem":"src/cluster"}
JSONL
g_empty_claim=$("$STATE" --results-dir "$g_empty" --target-path "$TARGET_ROOT" --target-slug "$TARGET_SLUG" \
  next-card --agent 1 --mode generic --role reproduce --strategy S2 --peek 2>/dev/null || true)
if [ -z "$g_empty_claim" ] || ! grep -q '"id"' <<<"$g_empty_claim"; then
  pass "G: surface-blocked Promote with no fallback returns no card (no deadlock)"
else
  fail "G: surface-blocked Promote with no fallback returns no card (no deadlock)" \
       "got: $g_empty_claim"
fi

# ── P5: do-not-revisit marker after a crash rejection ──────────────
# When the triage gate moves a crash to crashes-rejected/, the
# orchestrator calls `bin/state mark-card-reject-skip` to record the
# (card_id, agent) pair the queue should never re-offer. This stops
# the codex-r2 failure mode where an agent kept filing the same
# REG_STARTEND caller-misuse crashes against the same card and the
# queue kept handing it back.
p5_results="$TEST_TMPDIR/p5-reject-skip"
mkdir -p "$p5_results/state"
: > "$p5_results/state/claims.jsonl"
: > "$p5_results/state/runs.jsonl"
: > "$p5_results/state/events.jsonl"
: > "$p5_results/state/notes.jsonl"
cat > "$p5_results/work-cards.jsonl" <<'JSONL'
{"id":"WORK-P5-A","kind":"ranked-source","target_slug":"testproject","subsystem":"src/a","file":"src/a/x.c","mode":"generic","strategy":"S2","score":50,"status":"unclaimed"}
{"id":"WORK-P5-B","kind":"ranked-source","target_slug":"testproject","subsystem":"src/b","file":"src/b/y.c","mode":"generic","strategy":"S2","score":40,"status":"unclaimed"}
JSONL
cat > "$p5_results/state/hypotheses.jsonl" <<'JSONL'
{"id":"H-p5","agent":"1","card_id":"WORK-P5-A","status":"CRASH-001-1","file":"src/a/x.c","hypothesis":"caller-misuse hyp","updated_at":"2026-05-23T00:00:00Z"}
JSONL

# Pre-reject: agent 1 would receive WORK-P5-A normally (highest score
# on the matching strategy).
pre_reject=$("$STATE" --results-dir "$p5_results" --target-path "$TARGET_ROOT" --target-slug "$TARGET_SLUG" \
  next-card --agent 1 --mode generic --role reproduce --strategy S2 --peek)
pre_reject_id=$(json_id "$pre_reject")
assert_eq "WORK-P5-A" "$pre_reject_id" "P5: pre-rejection, agent receives the top-scored card"

# Apply the do-not-revisit marker via the CLI.
mark_out=$("$STATE" --results-dir "$p5_results" --target-path "$TARGET_ROOT" --target-slug "$TARGET_SLUG" \
  mark-card-reject-skip --crash-id CRASH-001-1 --reason "caller-misuse REG_STARTEND")
assert_match '"card_id": "WORK-P5-A"' "$mark_out" "P5: mark-card-reject-skip resolves card_id via hypothesis lookup"
assert_match '"agent": "1"' "$mark_out" "P5: mark-card-reject-skip resolves agent via hypothesis lookup"

# Post-reject: agent 1 must be steered to WORK-P5-B; agent 2 still gets
# WORK-P5-A (the skip is per-agent, not global).
post_reject_a1=$("$STATE" --results-dir "$p5_results" --target-path "$TARGET_ROOT" --target-slug "$TARGET_SLUG" \
  next-card --agent 1 --mode generic --role reproduce --strategy S2 --peek)
post_reject_a1_id=$(json_id "$post_reject_a1")
assert_eq "WORK-P5-B" "$post_reject_a1_id" "P5: post-rejection, agent 1 skips the rejected card"
post_reject_a2=$("$STATE" --results-dir "$p5_results" --target-path "$TARGET_ROOT" --target-slug "$TARGET_SLUG" \
  next-card --agent 2 --mode generic --role reproduce --strategy S2 --peek)
post_reject_a2_id=$(json_id "$post_reject_a2")
assert_eq "WORK-P5-A" "$post_reject_a2_id" "P5: post-rejection, other agents still see the card"

# mark-card-reject-skip --card-id/--agent path (no crash_id needed) still works.
explicit_out=$("$STATE" --results-dir "$p5_results" --target-path "$TARGET_ROOT" --target-slug "$TARGET_SLUG" \
  mark-card-reject-skip --card-id WORK-P5-B --agent 3 --reason "another-misuse")
assert_match '"card_id": "WORK-P5-B"' "$explicit_out" "P5: mark-card-reject-skip works with explicit --card-id/--agent"

# ── P7: consolidated promoted-recon card accepts allowed_strategies ─
# After P7, a Promote finding emits one card whose primary `strategy`
# is S7 but whose `allowed_strategies` covers [S5, S7]. The claim
# filter must accept the card under EITHER strategy filter without
# breaking the legacy single-strategy comparison for non-recon cards.
p7_results="$TEST_TMPDIR/p7-allowed-strategies"
mkdir -p "$p7_results/state"
: > "$p7_results/state/claims.jsonl"
: > "$p7_results/state/runs.jsonl"
: > "$p7_results/state/events.jsonl"
: > "$p7_results/state/notes.jsonl"
: > "$p7_results/state/hypotheses.jsonl"
cat > "$p7_results/work-cards.jsonl" <<'JSONL'
{"id":"WORK-P7-PROMO","kind":"recon-hypothesis","target_slug":"tp","subsystem":"src/a","file":"src/a/x.c","mode":"generic","strategy":"S7","allowed_strategies":["S5","S7"],"score":1000,"status":"unclaimed","recon":{"id":"RECON-p7","validator_verdict":"Promote","line":10,"class":"OOB-write"}}
{"id":"WORK-P7-S2","kind":"s1-patch","target_slug":"tp","subsystem":"src/b","file":"src/b/y.c","mode":"generic","strategy":"S2","score":50,"status":"unclaimed","description":"plain S2"}
JSONL

# (a) S5-filtered agent must receive the Promote card via P3 precedence
# anyway, but if we disable precedence to isolate P7, the S5 claim still
# matches the multi-strategy card.
p7_s5=$(WORK_CARD_PROMOTED_RECON_PRECEDENCE=0 "$STATE" --results-dir "$p7_results" --target-path "$TARGET_ROOT" --target-slug "$TARGET_SLUG" \
  next-card --agent 1 --mode generic --role reproduce --strategy S5 --peek)
p7_s5_id=$(json_id "$p7_s5")
assert_eq "WORK-P7-PROMO" "$p7_s5_id" "P7: --strategy S5 matches via allowed_strategies"

# (b) S7-filtered agent matches via primary strategy (unchanged semantics).
p7_s7=$(WORK_CARD_PROMOTED_RECON_PRECEDENCE=0 "$STATE" --results-dir "$p7_results" --target-path "$TARGET_ROOT" --target-slug "$TARGET_SLUG" \
  next-card --agent 2 --mode generic --role reproduce --strategy S7 --peek)
p7_s7_id=$(json_id "$p7_s7")
assert_eq "WORK-P7-PROMO" "$p7_s7_id" "P7: --strategy S7 matches via primary strategy"

# (c) Non-recon S2 card is still gated by exact strategy match (legacy
# single-strategy behaviour preserved).
p7_s2=$(WORK_CARD_PROMOTED_RECON_PRECEDENCE=0 "$STATE" --results-dir "$p7_results" --target-path "$TARGET_ROOT" --target-slug "$TARGET_SLUG" \
  next-card --agent 3 --mode generic --role reproduce --strategy S2 --peek)
p7_s2_id=$(json_id "$p7_s2")
assert_eq "WORK-P7-S2" "$p7_s2_id" "P7: non-recon S2 cards still use exact-match comparison"

# (d) An unrelated strategy (S3) finds neither card — allowed_strategies
# only matches the explicit list, not "all".
p7_s3=$(WORK_CARD_PROMOTED_RECON_PRECEDENCE=0 "$STATE" --results-dir "$p7_results" --target-path "$TARGET_ROOT" --target-slug "$TARGET_SLUG" \
  next-card --agent 4 --mode generic --role reproduce --strategy S3 --peek 2>/dev/null || true)
if [ -z "$p7_s3" ] || ! grep -q '"id"' <<<"$p7_s3"; then
  pass "P7: strategy outside allowed_strategies returns no card"
else
  fail "P7: strategy outside allowed_strategies returns no card" "got: $p7_s3"
fi

# Sanitizer-mode cards are still reproduce work for generic agents. The
# validator emits ASan-mode Promote cards for sanitizer targets; bin/audit
# launches generic reproduce agents, so mode compatibility must not strand
# the highest-score cards behind lower-signal generic work.
p7_mode_results="$TEST_TMPDIR/p7-sanitizer-mode"
mkdir -p "$p7_mode_results/state"
: > "$p7_mode_results/state/claims.jsonl"
: > "$p7_mode_results/state/runs.jsonl"
: > "$p7_mode_results/state/events.jsonl"
: > "$p7_mode_results/state/notes.jsonl"
: > "$p7_mode_results/state/hypotheses.jsonl"
cat > "$p7_mode_results/work-cards.jsonl" <<'JSONL'
{"id":"WORK-P7-ASAN-PROMO","kind":"recon-hypothesis","target_slug":"tp","subsystem":"src/a","file":"src/a/asan.c","mode":"asan","strategy":"S7","allowed_strategies":["S5","S7"],"score":1000,"status":"unclaimed","recon":{"id":"RECON-p7-asan","validator_verdict":"Promote","line":10,"class":"bounds"}}
{"id":"WORK-P7-GENERIC-S2","kind":"s1-patch","target_slug":"tp","subsystem":"src/b","file":"src/b/generic.c","mode":"generic","strategy":"S2","score":50,"status":"unclaimed","description":"plain S2"}
JSONL
p7_asan=$(WORK_CARD_PROMOTED_RECON_PRECEDENCE=0 "$STATE" --results-dir "$p7_mode_results" --target-path "$TARGET_ROOT" --target-slug "$TARGET_SLUG" \
  next-card --agent 5 --mode generic --role reproduce --strategy S7 --peek)
p7_asan_id=$(json_id "$p7_asan")
assert_eq "WORK-P7-ASAN-PROMO" "$p7_asan_id" "P7: generic agents can claim sanitizer-mode Promote cards"

# A bogus crash_id with no resolving hypothesis surfaces an error.
bad_out=$("$STATE" --results-dir "$p5_results" --target-path "$TARGET_ROOT" --target-slug "$TARGET_SLUG" \
  mark-card-reject-skip --crash-id CRASH-DOES-NOT-EXIST --reason "x" 2>&1; echo "rc=$?")
case "$bad_out" in
  *"no hypothesis row"*"rc=1"*) pass "P5: mark-card-reject-skip rejects unknown crash_id" ;;
  *) fail "P5: mark-card-reject-skip rejects unknown crash_id" "got: $bad_out" ;;
esac

# Caller without a strategy filter (the cold-start / open claim path)
# should also receive a Promote card first when one is unclaimed.
nostrat_results="$TEST_TMPDIR/promoted-nostrat-results"
mkdir -p "$nostrat_results/state"
: > "$nostrat_results/state/claims.jsonl"
: > "$nostrat_results/state/runs.jsonl"
: > "$nostrat_results/state/events.jsonl"
: > "$nostrat_results/state/notes.jsonl"
: > "$nostrat_results/state/hypotheses.jsonl"
cp "$promoted_results/work-cards.jsonl" "$nostrat_results/work-cards.jsonl"
nostrat_claim=$("$STATE" --results-dir "$nostrat_results" --target-path "$TARGET_ROOT" --target-slug "$TARGET_SLUG" \
  next-card --agent 1 --mode generic --role reproduce)
nostrat_claim_id=$(json_id "$nostrat_claim")
case "$nostrat_claim_id" in
  WORK-PROMO-S7|WORK-PROMO-S5)
    pass "state: P3 precedence applies to filter-less claims as well"
    ;;
  *)
    fail "state: P3 precedence applies to filter-less claims as well" \
         "got: $nostrat_claim_id"
    ;;
esac

# Compact structured resume: no active hypothesis means the agent sees the
# assigned card, last 3 runs, last terminal reason, and guard notes only.
resume_results="$TEST_TMPDIR/resume-results"
mkdir -p "$resume_results/state"
: > "$resume_results/state/claims.jsonl"
: > "$resume_results/state/events.jsonl"
cat > "$resume_results/work-cards.jsonl" <<'JSONL'
{"id":"WORK-R1","kind":"s1-patch","target_slug":"testproject","subsystem":"gamma/parse","file":"gamma/parse/r.c","mode":"generic","strategy":"S1","score":1,"status":"unclaimed","reason":"resume test","fix_hashes":["abc123"],"patch_cards":["WORK-R1"]}
JSONL
cat > "$resume_results/state/hypotheses.jsonl" <<'JSONL'
{"id":"H-old","agent":"1","card_id":"WORK-R1","status":"DISCARDED","file":"gamma/parse/old.c","hypothesis":"old terminal","note":"three clean variants; guard holds","updated_at":"2026-05-01T00:00:00Z"}
JSONL
cat > "$resume_results/state/runs.jsonl" <<'JSONL'
{"id":"R-old","agent":"1","hypothesis_id":"H-old","card_id":"WORK-R1","verdict":"CLEAN","mode":"generic","testcase":"old.input","created_at":"2026-05-01T00:00:00Z"}
{"id":"R-1","agent":"1","hypothesis_id":"H-old","card_id":"WORK-R1","verdict":"CLEAN","mode":"generic","testcase":"v1.input","created_at":"2026-05-02T00:00:00Z"}
{"id":"R-2","agent":"1","hypothesis_id":"H-old","card_id":"WORK-R1","verdict":"CLEAN","mode":"generic","testcase":"v2.input","created_at":"2026-05-03T00:00:00Z"}
{"id":"R-3","agent":"1","hypothesis_id":"H-old","card_id":"WORK-R1","verdict":"CLEAN","mode":"generic","testcase":"v3.input","created_at":"2026-05-04T00:00:00Z"}
{"id":"R-4","agent":"1","hypothesis_id":"H-old","card_id":"WORK-R1","verdict":"CLEAN","mode":"generic","testcase":"v4.input","created_at":"2026-05-05T00:00:00Z"}
{"id":"R-5","agent":"1","hypothesis_id":"H-old","card_id":"WORK-R1","verdict":"CLEAN","mode":"generic","testcase":"v5.input","created_at":"2026-05-06T00:00:00Z"}
{"id":"R-6","agent":"1","hypothesis_id":"H-old","card_id":"WORK-R1","verdict":"CLEAN","mode":"generic","testcase":"v6.input","created_at":"2026-05-07T00:00:00Z"}
JSONL
cat > "$resume_results/state/notes.jsonl" <<'JSONL'
{"id":"N-old","kind":"guard","agent":"1","hypothesis_id":"H-old","card_id":"WORK-R1","text":"old guard note","created_at":"2026-05-01T00:00:00Z"}
{"id":"N-1","kind":"guard","agent":"1","hypothesis_id":"H-old","card_id":"WORK-R1","text":"guard one","created_at":"2026-05-02T00:00:00Z"}
{"id":"N-2","kind":"guard","agent":"1","hypothesis_id":"H-old","card_id":"WORK-R1","text":"guard two","created_at":"2026-05-03T00:00:00Z"}
{"id":"N-3","kind":"guard","agent":"1","hypothesis_id":"H-old","card_id":"WORK-R1","text":"guard three","created_at":"2026-05-04T00:00:00Z"}
{"id":"N-4","kind":"guard","agent":"1","hypothesis_id":"H-old","card_id":"WORK-R1","text":"guard four","created_at":"2026-05-05T00:00:00Z"}
{"id":"N-5","kind":"guard","agent":"1","hypothesis_id":"H-old","card_id":"WORK-R1","text":"guard five","created_at":"2026-05-06T00:00:00Z"}
{"id":"N-6","kind":"guard","agent":"1","hypothesis_id":"H-old","card_id":"WORK-R1","text":"guard six","created_at":"2026-05-07T00:00:00Z"}
{"id":"N-data","kind":"data-flow","agent":"1","hypothesis_id":"H-old","card_id":"WORK-R1","text":"verbose data flow should not appear in guard notes","created_at":"2026-05-08T00:00:00Z"}
JSONL
claims_before_resume=$(wc -l < "$resume_results/state/claims.jsonl" 2>/dev/null | tr -d ' ')
resume_out=$("$STATE" --results-dir "$resume_results" --target-path "$TARGET_ROOT" --target-slug "$TARGET_SLUG" \
  resume --agent 1 --mode generic --role reproduce)
claims_after_resume=$(wc -l < "$resume_results/state/claims.jsonl" 2>/dev/null | tr -d ' ')
assert_match "## Assigned Work Card" "$resume_out" "state resume: no-active resume includes assigned card"
assert_match "Fix commits: abc123" "$resume_out" "state resume: assigned card includes fix commits"
assert_match "PATCH-\\*.*not a VCS revision" "$resume_out" "state resume: warns card ids are not revisions"
if [ "$claims_after_resume" -gt "$claims_before_resume" ]; then
  pass "state resume: assigned work card is leased by default"
else
  fail "state resume: assigned work card is leased by default" \
       "claims.jsonl unchanged after resume (before=$claims_before_resume after=$claims_after_resume)"
fi
assert_match "## Last Terminal Reason" "$resume_out" "state resume: includes last terminal reason"
assert_match "three clean variants; guard holds" "$resume_out" "state resume: terminal reason includes note"
assert_match "R-6" "$resume_out" "state resume: includes newest run"
assert_not_match "R-old" "$resume_out" "state resume: limits recent runs to last 5"
assert_match "## Runtime Feedback" "$resume_out" "state resume: includes runtime feedback"
assert_match "clean-no-diagnostic" "$resume_out" "state resume: runtime feedback summarizes repeated clean probes"
assert_match "## Guard Notes" "$resume_out" "state resume: includes guard notes section"
assert_match "guard six" "$resume_out" "state resume: includes newest guard note"
assert_not_match "old guard note|verbose data flow" "$resume_out" "state resume: guard notes are filtered and limited"

resume_claim_results="$TEST_TMPDIR/resume-claim-results"
mkdir -p "$resume_claim_results/state"
: > "$resume_claim_results/state/claims.jsonl"
: > "$resume_claim_results/state/events.jsonl"
: > "$resume_claim_results/state/hypotheses.jsonl"
: > "$resume_claim_results/state/runs.jsonl"
: > "$resume_claim_results/state/notes.jsonl"
cat > "$resume_claim_results/work-cards.jsonl" <<'JSONL'
{"id":"WORK-LEASE-1","kind":"ranked-source","target_slug":"testproject","subsystem":"lease/one","file":"lease/one/a.c","mode":"generic","strategy":"S1","score":10,"status":"unclaimed"}
{"id":"WORK-LEASE-2","kind":"ranked-source","target_slug":"testproject","subsystem":"lease/two","file":"lease/two/b.c","mode":"generic","strategy":"S1","score":9,"status":"unclaimed"}
JSONL
resume_claim_one=$("$STATE" --results-dir "$resume_claim_results" --target-path "$TARGET_ROOT" --target-slug "$TARGET_SLUG" \
  resume --agent 1 --mode generic --role reproduce)
resume_claim_two=$("$STATE" --results-dir "$resume_claim_results" --target-path "$TARGET_ROOT" --target-slug "$TARGET_SLUG" \
  resume --agent 2 --mode generic --role reproduce)
assert_match "WORK-LEASE-1" "$resume_claim_one" "state resume: first no-active agent receives top eligible card"
assert_match "WORK-LEASE-2" "$resume_claim_two" "state resume: second no-active agent skips first agent's lease"
resume_claim_lines=$(wc -l < "$resume_claim_results/state/claims.jsonl" 2>/dev/null | tr -d ' ')
assert_eq "2" "$resume_claim_lines" "state resume: consecutive assigned cards each append a lease"

resume_reuse_results="$TEST_TMPDIR/resume-reuse-results"
mkdir -p "$resume_reuse_results/state"
: > "$resume_reuse_results/state/claims.jsonl"
: > "$resume_reuse_results/state/events.jsonl"
: > "$resume_reuse_results/state/hypotheses.jsonl"
: > "$resume_reuse_results/state/runs.jsonl"
: > "$resume_reuse_results/state/notes.jsonl"
cat > "$resume_reuse_results/work-cards.jsonl" <<'JSONL'
{"id":"WORK-REUSE-1","kind":"ranked-source","target_slug":"testproject","subsystem":"reuse/one","file":"reuse/one/a.c","mode":"generic","strategy":"S1","score":10,"status":"unclaimed"}
{"id":"WORK-REUSE-2","kind":"ranked-source","target_slug":"testproject","subsystem":"reuse/two","file":"reuse/two/b.c","mode":"generic","strategy":"S1","score":9,"status":"unclaimed"}
JSONL
prompt_claim=$("$STATE" --results-dir "$resume_reuse_results" --target-path "$TARGET_ROOT" --target-slug "$TARGET_SLUG" \
  next-card --agent 1 --mode generic --role reproduce)
resume_reuse_one=$("$STATE" --results-dir "$resume_reuse_results" --target-path "$TARGET_ROOT" --target-slug "$TARGET_SLUG" \
  resume --agent 1 --mode generic --role reproduce)
resume_reuse_two=$("$STATE" --results-dir "$resume_reuse_results" --target-path "$TARGET_ROOT" --target-slug "$TARGET_SLUG" \
  resume --agent 2 --mode generic --role reproduce)
assert_match "WORK-REUSE-1" "$prompt_claim" "state resume: setup prompt-time claim picked top card"
assert_match "WORK-REUSE-1" "$resume_reuse_one" "state resume: same agent reuses its active prompt-time lease"
assert_match "WORK-REUSE-2" "$resume_reuse_two" "state resume: other agent skips the first agent's active lease"

resume_peek_results="$TEST_TMPDIR/resume-peek-results"
mkdir -p "$resume_peek_results/state"
: > "$resume_peek_results/state/claims.jsonl"
: > "$resume_peek_results/state/events.jsonl"
: > "$resume_peek_results/state/hypotheses.jsonl"
: > "$resume_peek_results/state/runs.jsonl"
: > "$resume_peek_results/state/notes.jsonl"
cat > "$resume_peek_results/work-cards.jsonl" <<'JSONL'
{"id":"WORK-PEEK-1","kind":"ranked-source","target_slug":"testproject","subsystem":"peek/one","file":"peek/one/a.c","mode":"generic","strategy":"S1","score":1,"status":"unclaimed"}
JSONL
resume_peek_out=$("$STATE" --results-dir "$resume_peek_results" --target-path "$TARGET_ROOT" --target-slug "$TARGET_SLUG" \
  resume --agent 1 --mode generic --role reproduce --peek)
resume_peek_lines=$(wc -l < "$resume_peek_results/state/claims.jsonl" 2>/dev/null | tr -d ' ')
assert_match "WORK-PEEK-1" "$resume_peek_out" "state resume: --peek still renders an assigned card"
assert_eq "0" "$resume_peek_lines" "state resume: --peek does not append a lease"

# ── CODE_PATTERNS: target-agnostic strategy-mapping unit tests ──────
# Regression cover for the signal table after de-browserification:
# snake_case parser detection (the old CamelCase-only regex missed it),
# a structural assert family that needs no MOZ_/DCHECK enumeration, and
# direct S5/S8 seeding (previously never produced by any code feature).
# This and the two stateless checks below (iter_source_files, S8 feature
# coverage) share ONE python invocation — the workqueue import is the
# expensive part. Each prints a labeled ok/failure line so the three
# assertions stay independent.
wq_feature_checks=$(PYTHONPATH="$SCRIPT_ROOT/lib" python3 - "$TEST_TMPDIR" <<'PY'
import sys, tempfile, pathlib
import workqueue as W

results = []

def reasons(t):
    return W.code_feature_reasons(t)[1]

def run(label, fn):
    bad = fn()
    results.append(f"{label}:ok" if not bad else f"{label}:FAIL: " + " | ".join(bad))

def cfr():
    # (label, snippet, expected reason tag, expected primary strategy)
    checks = [
        ("snake_case parser is detected (CamelCase-only regression)",
         "int parse_uri(const char *s){return 0;}",
         "input-consumption entrypoint", "S7"),
        ("leading-position verb is detected",
         "void ReadBuffer(char *p){}",
         "input-consumption entrypoint", "S7"),
        ("assert family is target-agnostic (no MOZ_ token needed)",
         "static_assert(sizeof(int)==4); CHECK_EQ(a,b);",
         "asserted invariant", "S2"),
        ("lifetime ops seed S5 directly",
         "void g(T *p){ free(p); }",
         "lifetime/ownership operation", "S5"),
        ("unsafe islands seed S5",
         "unsafe { *p = 1; }",
         "unmanaged escape hatch", "S5"),
        ("round-trip code seeds S8",
         "char *base64_encode(const char *s);",
         "round-trip property surface", "S8"),
        ("deserialization sink seeds S7",
         "ois.readObject();",
         "deserialization sink", "S7"),
        # multi-language coverage: not just C/C++
        ("Go panic is an asserted invariant",
         "func f(){ panic(\"unreachable\") }",
         "asserted invariant", "S2"),
        ("Go exec.Command is a command/injection surface",
         "c := exec.Command(\"sh\", \"-c\", arg)",
         "command/injection surface", "S7"),
        ("Rust unsafe block seeds S5",
         "unsafe fn raw(p: *mut u8) { *p = 0; }",
         "unmanaged escape hatch", "S5"),
    ]
    bad = []
    for label, snip, want_reason, want_strat in checks:
        r = reasons(snip)
        s = W.strategy_for(r)
        if want_reason not in r or s != want_strat:
            bad.append(f"{label}: reasons={r} strategy={s}")

    # concurrency keywords must not be misread as input-consumption
    for fp in ("pthread_create(&t);", "int thread_local_x;"):
        if "input-consumption entrypoint" in reasons(fp):
            bad.append(f"false-positive: {fp!r} flagged input-consumption")
    return bad

# ─── iter_source_files: no cap scans the whole repo ─────────────────
# RANK_WORK_MAX_FILES is gone — the ranker must never go blind past a
# fixed walk position. The default (and an explicit 0) means unbounded;
# a positive max_files still bounds the sample-only callers (peer-fix-cards).
def itf():
    root = pathlib.Path(tempfile.mkdtemp(dir=sys.argv[1]))
    src = root / "lib"
    src.mkdir()
    for i in range(12):
        (src / f"src{i:02d}.c").write_text("int f(void){return 0;}\n")
    all_default = list(W.iter_source_files(root))
    all_zero = list(W.iter_source_files(root, max_files=0))
    bounded = list(W.iter_source_files(root, max_files=4))
    if len(all_default) == 12 and len(all_zero) == 12 and len(bounded) == 4:
        return []
    return [f"default={len(all_default)} zero={len(all_zero)} bounded={len(bounded)}"]

# S8 source-feature coverage: injectivity, idempotence (sanitize/dedupe), and
# numerical-domain surfaces must seed an S8 angle, while container plumbing and
# bare numeric code must NOT. Guards against both the missing-coverage gap and
# the over-broadening Codex flagged. strategy_for returns the primary; the S8
# reason may surface as a companion when a higher-signal feature co-occurs, so
# the oracle is "an S8 reason is present", not "primary == S8".
def s8():
    S8 = {"round-trip property surface", "hash/injectivity surface",
          "numerical-domain surface"}
    positives = {
        # injectivity — distinctive families and the generic hash/digest token
        "murmur_hash":   "uint32_t murmur_hash(const char* p){return murmur_hash(p);}",
        "compute_digest":"void compute_digest(const char* p){compute_digest(p);}",
        "hash_bytes":    "uint64_t hash_bytes(const void* p, size_t n);",
        "hash_string":   "uint32_t hash_string(const char* s);",
        "hashString":    "int hashString(const char* s);",
        "digest_update": "void digest_update(ctx* c, const void* p);",
        "sha512_init":   "void sha512_init(ctx* c);",
        "cache_key":     "char* cache_key(req* r){return cache_key(r);}",
        "make_id":       "long make_id(void){ return make_id(); }",
        "generate_id":   "long generate_id(void);",
        "id_for":        "long id_for(obj* o);",
        # idempotence
        "sanitize_html": "char* sanitize_html(char* s){return sanitize_html(s);}",
        "dedupe_path":   "char* dedupe_path(char* p){return dedupe_path(p);}",
        # numerical-domain — declared language + enforcement calls
        "clamp_sample":  "double clamp_sample(double x){return clamp_sample(x);}",
        "nonneg_prose":  "// returns a non-negative count\nint count_items(set* s);",
        "prob_prose":    "/* result is a probability in [0,1] */\ndouble score(model* m);",
        "isfinite_use":  "double f(double v){ if (isfinite(v)) return v; return 0; }",
    }
    negatives = {
        # injectivity — container plumbing must NOT match
        "hashmap_insert":   "void hashmap_insert(map* m, int k){ insert(m,k); }",
        "hashtable_get":    "void* hashtable_get(map* m, int k){ return 0; }",
        "rehash_table":     "void rehash_table(map* m){ rehash_table(m); }",
        "hash_table_lookup":"void* hash_table_lookup(map* m, int k){ return 0; }",
        # numerical — non-numeric prose must NOT match (Codex FP cases)
        "finite_state":     "// drive the finite state machine forward\nvoid step(sm* m);",
        "finite_element":   "/* finite element mesh refinement */\nvoid refine(mesh* m);",
        # generic
        "to_string":        "char* to_string(int x){ return fmt(x); }",
        "plain_compute":    "int compute(int x){ return x + 1; }",
    }
    bad = []
    for name, body in positives.items():
        _, rs = W.code_feature_reasons(body)
        if not (S8 & set(rs)):
            bad.append(f"positive {name} missing S8 reason: {rs}")
    for name, body in negatives.items():
        _, rs = W.code_feature_reasons(body)
        if S8 & set(rs):
            bad.append(f"negative {name} wrongly got S8 reason: {rs}")

    # Ranking regression: a repetition-dense S8 file must NOT outrank a single
    # high-signal S7 input-consumption entrypoint. Presence-only scoring (the
    # S8 rows score once, not per-match) is what holds this invariant.
    s7_score, _ = W.code_feature_reasons("int parse_doc(const char* p);")
    s8_dense, _ = W.code_feature_reasons(
        "double a(double x){clamp(x);} double b(){clamp(0);} "
        "double c(){clamp(1);} double d(){clamp(2);}")
    if s8_dense >= s7_score:
        bad.append(f"clamp-dense S8 ({s8_dense}) outranks single S7 ({s7_score})")
    return bad

run("cfr", cfr)
run("itf", itf)
run("s8", s8)
print("\n".join(results))
PY
)
case "$wq_feature_checks" in *"cfr:ok"*) cfr_out=ok ;; *) cfr_out="$wq_feature_checks" ;; esac
case "$wq_feature_checks" in *"itf:ok"*) itf_out=ok ;; *) itf_out="$wq_feature_checks" ;; esac
case "$wq_feature_checks" in *"s8:ok"*) s8_coverage=ok ;; *) s8_coverage="$wq_feature_checks" ;; esac
assert_eq "ok" "$cfr_out" "code_feature_reasons: target-agnostic patterns map to right strategies"
assert_eq "ok" "$itf_out" \
  "iter_source_files: default/0 scans whole repo, positive max_files bounds it"
assert_eq "ok" "$s8_coverage" \
  "code_feature_reasons: S8 covers injectivity/idempotence/numerical-domain, skips plumbing, never outranks S7"

teardown_test_env
summary
