#!/usr/bin/env bash
# Tests for recon-related additions:
#   - NOVOCAB markers (lib/vocab.sh)
#   - patch-card boost / version-only filter (lib/workqueue.py)
#   - recon primitive classes are CVSS-classified (bin/reachability)
#   - recon_slicer.py basic invocation
#   - triage_validate.sh class routing
set -euo pipefail

TESTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT_ROOT="$(cd "$TESTS_DIR/.." && pwd)"
# shellcheck disable=SC1091
source "$TESTS_DIR/helpers.sh"
# shellcheck disable=SC1091
source "$SCRIPT_ROOT/lib/platform.sh"

setup_test_env

# ── B1: comma collapse regression test ────────────────────────────────
# Direct check that audit's cold-start launch list uses spaces, not commas,
# so `for i in $list` iterates N agents rather than collapsing to "1,2,3".
if grep -nE 'CURRENT_LAUNCH_AGENT_LIST=.*paste -sd, -' "$SCRIPT_ROOT/bin/audit" >/dev/null 2>&1; then
  fail "regression: paste -sd, - reintroduced in bin/audit (collapses agents)"
else
  pass "no paste -sd, - in CURRENT_LAUNCH_AGENT_LIST assignment"
fi

# Simulate the for-loop iteration with space-separated input.
launch_iter_count=$(SCRIPT_ROOT="$SCRIPT_ROOT" bash -c '
  list="$(seq 1 3 | tr "\n" " " | sed "s/ \$//")"
  n=0
  for i in $list; do n=$((n + 1)); done
  echo "$n"
')
assert_eq "$launch_iter_count" "3" "comma fix iterates 3 agents from seq output"

if grep -nE '^[[:space:]]*local[[:space:]]+_agent_display\b' "$SCRIPT_ROOT/bin/audit" >/dev/null 2>&1; then
  fail "bin/audit cold-start block uses local outside a function"
else
  pass "bin/audit cold-start display variable is shell-safe at top level"
fi

if grep -q 'ROOT_FINDINGS_JSONL_PREEXISTED' "$SCRIPT_ROOT/bin/audit-recon" \
   && grep -q 'recon_stray_findings_' "$SCRIPT_ROOT/bin/audit-recon"; then
  pass "audit-recon quarantines stray repo-root findings.jsonl"
else
  fail "audit-recon must quarantine stray repo-root findings.jsonl"
fi

if grep -q 'Do not write `findings.jsonl`' "$SCRIPT_ROOT/lib/prompts/audit_recon.md.j2"; then
  pass "audit recon prompt forbids workspace findings.jsonl writes"
else
  fail "audit recon prompt must forbid workspace findings.jsonl writes"
fi

# ── B2: NOVOCAB markers ────────────────────────────────────────────────
tmp_input=$(mktemp)
trap 'rm -f "$tmp_input" 2>/dev/null || true; teardown_test_env 2>/dev/null || true' EXIT

cat > "$tmp_input" <<'INPUT'
Line about exploit and attacker.
<!-- NOVOCAB -->
- "testcase" (not "exploit")
- "caller" (not "attacker")
<!-- /NOVOCAB -->
Tail line about malicious payload.
INPUT

# neutralize_qa_vocab_string preserves NOVOCAB markers in its output so
# the protected region survives a downstream second scrub pass (the
# actual failure mode that caused safety_framing's "use X (not Y)"
# examples to collapse into "use X (not X)" in the 2026-05-23 codex
# benchmark). The markers are stripped by a separate function,
# strip_novocab_markers, called once at the end of the pipeline.
out=$(SCRIPT_ROOT="$SCRIPT_ROOT" bash -c '. "$1/lib/vocab.sh"; cat "$2" | neutralize_qa_vocab_string' _ "$SCRIPT_ROOT" "$tmp_input")

if grep -q 'Line about reproducer and caller\.' <<<"$out"; then
  pass "neutralizer substitutes outside NOVOCAB markers"
else
  fail "expected substitution outside markers; got: $out"
fi

if grep -qF -- '- "testcase" (not "exploit")' <<<"$out"; then
  pass "marked block content preserved verbatim"
else
  fail "marked block was rewritten; got: $out"
fi

if grep -q -- 'NOVOCAB' <<<"$out"; then
  pass "markers preserved through scrub (stripped by strip_novocab_markers)"
else
  fail "markers should be preserved through scrub; got: $out"
fi

if grep -q 'Tail line about hand-crafted payload\.' <<<"$out"; then
  pass "neutralizer substitutes after closing marker"
else
  fail "post-marker substitution missing; got: $out"
fi

# End-to-end pipeline: scrub then strip — markers gone from output,
# protected content survives, surrounding content rewritten. This is
# the contract bin/audit relies on when it pipes
# "$prompt_builder ... | neutralize_qa_vocab_string | strip_novocab_markers".
e2e=$(SCRIPT_ROOT="$SCRIPT_ROOT" bash -c '. "$1/lib/vocab.sh"; cat "$2" | neutralize_qa_vocab_string | neutralize_qa_vocab_string | strip_novocab_markers' _ "$SCRIPT_ROOT" "$tmp_input")
if grep -q 'NOVOCAB' <<<"$e2e"; then
  fail "strip_novocab_markers should remove markers; got: $e2e"
else
  pass "strip_novocab_markers removes markers from end-of-pipeline output"
fi
if grep -qF -- '- "testcase" (not "exploit")' <<<"$e2e"; then
  pass "protected region survives double-scrub end-to-end"
else
  fail "protected region collapsed under double-scrub; got: $e2e"
fi

# ── B4: patch-card boost / version-only filter ─────────────────────────
cd "$SCRIPT_ROOT"
py_out=$(python3 - <<'PY'
import sys
sys.path.insert(0, "lib")
from workqueue import is_non_audit_patch_description, patch_audit_boost, is_version_only_file_set, matches_audit_boost

# Memory-safety + general security across languages
print("T_release_version", is_non_audit_patch_description("release-1.34.0 (#896)", ["include/ares_version.h"]))
print("T_release_CVE", is_non_audit_patch_description("release 1.2: fix CVE-2025-12345 heap overflow", ["src/foo.c"]))
print("T_version_only_set", is_version_only_file_set(["include/ares_version.h"]))
print("T_version_mixed", is_version_only_file_set(["include/ares_version.h", "src/foo.c"]))
print("T_boost_cve", patch_audit_boost("fix CVE-2025-12345 heap overflow"))
print("T_boost_release_only", patch_audit_boost("release-1.34.0"))
print("T_boost_uaf", patch_audit_boost("Fix UAF in worker pool"))
print("T_boost_sqli", patch_audit_boost("Patch SQL injection in admin search"))
print("T_boost_xss", patch_audit_boost("Resolve XSS in user profile rendering"))
print("T_boost_ssrf", patch_audit_boost("Patch SSRF in webhook handler"))
print("T_boost_zip_slip", patch_audit_boost("Fix path traversal via Zip-Slip"))
print("T_boost_ghsa", patch_audit_boost("Address GHSA-abcd-1234-efgh in TLS handshake"))
print("T_boost_cwe", patch_audit_boost("CWE-22: arbitrary file disclosure"))
print("T_boost_deser", patch_audit_boost("Insecure deserialization in pickle loader"))
print("T_boost_authz", patch_audit_boost("Authorization bypass for /admin/* endpoints"))
print("T_boost_secret", patch_audit_boost("Hard-coded API key in default config"))
print("T_boost_redos", patch_audit_boost("ReDoS in email validator"))
print("T_boost_race", patch_audit_boost("Race condition between cancel and free"))
print("T_boost_uninit", patch_audit_boost("Fix uninitialized memory read in parser"))
print("T_boost_crlf", patch_audit_boost("CRLF injection in logger"))
print("T_boost_openredir", patch_audit_boost("Open redirect via crafted Location header"))
print("T_boost_typosquat", patch_audit_boost("Patch typosquat in npm install path"))
PY
)

assert_file_contains() { :; }  # local helper not needed; use grep below
verify() {
  local label="$1" expected="$2"
  if grep -q "^${label} ${expected}$" <<<"$py_out"; then
    pass "${label} == ${expected}"
  else
    fail "${label} expected '${expected}', got: $(printf '%s' "$py_out" | grep "^${label} " | head -1)"
  fi
}
verify_ge() {
  local label="$1" min="$2"
  local val
  val=$(printf '%s' "$py_out" | awk -v l="$label" '$1 == l { print $2 }')
  if [ -n "$val" ] && [ "$val" -ge "$min" ] 2>/dev/null; then
    pass "${label} >= ${min} (got ${val})"
  else
    fail "${label} expected >= ${min}, got: ${val:-EMPTY}"
  fi
}

verify T_release_version True
verify T_release_CVE False
verify T_version_only_set True
verify T_version_mixed False
verify_ge T_boost_cve 20
verify T_boost_release_only 0
verify_ge T_boost_uaf 20
verify_ge T_boost_sqli 20
verify_ge T_boost_xss 20
verify_ge T_boost_ssrf 20
verify_ge T_boost_zip_slip 20
verify_ge T_boost_ghsa 20
verify_ge T_boost_cwe 20
verify_ge T_boost_deser 20
verify_ge T_boost_authz 20
verify_ge T_boost_secret 20
verify_ge T_boost_redos 20
verify_ge T_boost_race 20
verify_ge T_boost_uninit 20
verify_ge T_boost_crlf 20
verify_ge T_boost_openredir 20
verify_ge T_boost_typosquat 20

# ── T2-9: new reachability primitives ───────────────────────────────────
py_out=$(python3 - <<'PY'
import importlib.machinery, importlib.util
loader = importlib.machinery.SourceFileLoader("reach", "bin/reachability")
spec = importlib.util.spec_from_loader("reach", loader)
mod = importlib.util.module_from_spec(spec)
loader.exec_module(mod)
k1, _ = mod.detect_primitive("DNS cache poisoning enables protocol downgrade")
k2, _ = mod.detect_primitive("DNS name decompression memory amplification of 100x")
k3, _ = mod.detect_primitive("DNS0x20 security feature defeated by cache normalization bug")
print("P1", k1)
print("P2", k2)
print("P3", k3)
# Each recon class must be CVSS-classified (not collapse to the unscored
# "unknown" band): _cvss4_metrics returns a metrics dict, and the class scores
# a non-zero CVSS v4.0 value at a library surface.
def cvss(key):
    m, _ = mod._cvss4_metrics(key, "library", {}, {}, False)
    return int(mod.cvss4.score(m)) if m else 0   # floored for integer compare
print("B1", cvss("protocol_state"))
print("B2", cvss("dos_amplification"))
print("B3", cvss("logic_regression"))
print("B4", cvss("info_leak"))
PY
)
verify P1 protocol_state
verify P2 dos_amplification
verify P3 logic_regression
# CVSS v4.0 scores at a library surface — each well above zero (classified,
# not the unscored "unknown" band).
verify_ge B1 5
verify_ge B2 4
verify_ge B3 2
verify_ge B4 5

# ── T1-5: slicer produces non-overlapping coverage ─────────────────────
fake_target=$(mktemp -d)
mkdir -p "$fake_target/src/lib/dsa" "$fake_target/src/lib/record" \
         "$fake_target/src/lib/event" "$fake_target/src/lib/util"
for d in dsa record event util; do
  for n in 1 2 3 4 5; do touch "$fake_target/src/lib/$d/file_$n.c"; done
done
for n in 1 2 3 4 5 6 7 8; do touch "$fake_target/src/lib/ares_root_$n.c"; done

slice_out=$(mktemp -d)
python3 lib/recon_slicer.py --target-path "$fake_target" --slices 4 --out-dir "$slice_out" >/dev/null 2>&1

slice_count=$(ls "$slice_out"/slice-*.txt 2>/dev/null | wc -l | tr -d ' ')
assert_eq "$slice_count" "4" "slicer produced 4 slices"

all_lines=$(cat "$slice_out"/slice-*.txt 2>/dev/null | sort)
uniq_lines=$(printf '%s\n' "$all_lines" | sort -u)
all_count=$(printf '%s\n' "$all_lines" | wc -l | tr -d ' ')
uniq_count=$(printf '%s\n' "$uniq_lines" | wc -l | tr -d ' ')
if [ "$all_count" = "$uniq_count" ] && [ "$all_count" -ge 28 ]; then
  pass "every file appears in exactly one slice (${all_count} files)"
else
  fail "slice overlap or missing files: all=$all_count uniq=$uniq_count"
fi

rm -rf "$fake_target" "$slice_out"

# ── Slicer --seed: deterministic legacy and re-roll differ ─────────────
fake_target=$(mktemp -d)
mkdir -p "$fake_target/src/lib/dsa" "$fake_target/src/lib/record" \
         "$fake_target/src/lib/event" "$fake_target/src/lib/util"
for d in dsa record event util; do
  for n in 1 2 3 4 5 6 7 8 9 10; do touch "$fake_target/src/lib/$d/file_$n.c"; done
done
for n in 1 2 3 4 5 6 7 8; do touch "$fake_target/src/lib/ares_root_$n.c"; done

seed0_out=$(mktemp -d)
seed0_again_out=$(mktemp -d)
seed1_out=$(mktemp -d)

python3 lib/recon_slicer.py --target-path "$fake_target" --slices 4 --seed 0 --out-dir "$seed0_out" >/dev/null 2>&1
python3 lib/recon_slicer.py --target-path "$fake_target" --slices 4 --seed 0 --out-dir "$seed0_again_out" >/dev/null 2>&1
python3 lib/recon_slicer.py --target-path "$fake_target" --slices 4 --seed 1 --out-dir "$seed1_out" >/dev/null 2>&1

# Seed 0 is deterministic across invocations
seed0_sig=$(cat "$seed0_out"/slice-*.txt | sort | audit_sha1 | awk '{print $1}')
seed0_again_sig=$(cat "$seed0_again_out"/slice-*.txt | sort | audit_sha1 | awk '{print $1}')
assert_eq "$seed0_sig" "$seed0_again_sig" "slicer seed=0 is deterministic (same partition both runs)"

# Seed 1 produces a non-overlapping partition (every file still in exactly one slice)
seed1_lines=$(cat "$seed1_out"/slice-*.txt | sort)
seed1_uniq=$(printf '%s\n' "$seed1_lines" | sort -u)
seed1_all=$(printf '%s\n' "$seed1_lines" | wc -l | tr -d ' ')
seed1_uniq_count=$(printf '%s\n' "$seed1_uniq" | wc -l | tr -d ' ')
if [ "$seed1_all" = "$seed1_uniq_count" ] && [ "$seed1_all" -ge 48 ]; then
  pass "seed=1 partition is non-overlapping and complete (${seed1_all} files)"
else
  fail "seed=1 overlap or missing files: all=$seed1_all uniq=$seed1_uniq_count"
fi

# Seed 1 differs from seed 0 in *which* slice each file lands in.
# Build per-file slice-membership signatures for each seed and require
# they differ for at least one file.
build_membership() {
  local out_dir="$1"
  for slice in "$out_dir"/slice-*.txt; do
    sname=$(basename "$slice" .txt)
    while IFS= read -r path; do
      printf '%s\t%s\n' "$path" "$sname"
    done < "$slice"
  done | sort
}
mem0=$(build_membership "$seed0_out")
mem1=$(build_membership "$seed1_out")
# Compare just the file paths so we know both partitions cover same set,
# then check whether their (file, slice-name) mappings differ.
files0=$(printf '%s\n' "$mem0" | awk -F'\t' '{print $1}' | sort)
files1=$(printf '%s\n' "$mem1" | awk -F'\t' '{print $1}' | sort)
if [ "$files0" = "$files1" ]; then
  pass "seed=0 and seed=1 cover the same file set"
else
  fail "seed=0 and seed=1 cover different files (slicer should partition consistently)"
fi
if [ "$mem0" != "$mem1" ]; then
  pass "seed=1 partition differs from seed=0 (re-roll is meaningful)"
else
  fail "seed=1 produced identical partition to seed=0; re-roll would be a no-op"
fi

rm -rf "$fake_target" "$seed0_out" "$seed0_again_out" "$seed1_out"

# ── Slicer: directory-coherent, LOC-balanced partition ─────────────────
# The slicer groups files by directory subtree and balances slices by
# lines of code, not file count. The old filename-prefix regex table
# (NAME_PREFIX_GROUPS) and detect_project_prefix were deleted — assert
# they cannot quietly return.
# Match definitions at column 0, not the docstring that explains the
# deletion — the machinery is gone iff nothing defines it.
if grep -qE '^(NAME_PREFIX_GROUPS|def (detect_project_prefix|label_for_root_file))' \
    "$SCRIPT_ROOT/lib/recon_slicer.py"; then
  fail "recon_slicer.py still defines the deleted filename-prefix machinery"
else
  pass "recon_slicer.py has no filename-prefix regex table"
fi

# LOC balancing: a 500-line monster sharing a directory with stubs must be
# split off so one agent does not draw the whole heavy directory whole.
loc_target=$(mktemp -d)
mkdir -p "$loc_target/src/lib/parse" "$loc_target/src/lib/net"
seq 1 500 > "$loc_target/src/lib/parse/big.c"
for n in 1 2 3; do printf 'a\n' > "$loc_target/src/lib/parse/stub_$n.c"; done
for n in 1 2 3 4; do printf 'a\n' > "$loc_target/src/lib/net/n_$n.c"; done
loc_out=$(mktemp -d)
python3 lib/recon_slicer.py --target-path "$loc_target" --slices 2 --out-dir "$loc_out" >/dev/null 2>&1
loc_slices=$(ls "$loc_out"/slice-*.txt 2>/dev/null | wc -l | tr -d ' ')
assert_eq "$loc_slices" "2" "slicer produces the requested slice count"
loc_all=$(cat "$loc_out"/slice-*.txt | sort)
loc_total=$(printf '%s\n' "$loc_all" | wc -l | tr -d ' ')
loc_uniq=$(printf '%s\n' "$loc_all" | sort -u | wc -l | tr -d ' ')
if [ "$loc_total" = "$loc_uniq" ] && [ "$loc_total" = "8" ]; then
  pass "slicer partition is non-overlapping and complete (8 files)"
else
  fail "slicer partition overlaps or drops files: total=$loc_total uniq=$loc_uniq"
fi
big_slice=$(grep -l '/parse/big.c' "$loc_out"/slice-*.txt 2>/dev/null | head -1)
if [ -n "$big_slice" ] && ! grep -q '/parse/stub_1.c' "$big_slice"; then
  pass "LOC balancing splits the heavy directory (big.c isolated from its stubs)"
else
  fail "LOC balancing did not split the heavy directory"
fi
rm -rf "$loc_target" "$loc_out"

# Flat tree (every file in one directory, libxml2-shaped): no directory
# structure to exploit, so the fallback is LOC-balanced chunking. It must
# still produce N non-overlapping slices.
flat_target=$(mktemp -d)
mkdir -p "$flat_target/src/lib"
for f in parser valid tree xmlschemas encoding uri xpath regexp; do
  seq 1 60 > "$flat_target/src/lib/$f.c"
done
flat_out=$(mktemp -d)
python3 lib/recon_slicer.py --target-path "$flat_target" --slices 4 --out-dir "$flat_out" >/dev/null 2>&1
flat_count=$(ls "$flat_out"/slice-*.txt 2>/dev/null | wc -l | tr -d ' ')
flat_files=$(cat "$flat_out"/slice-*.txt 2>/dev/null | sort -u | wc -l | tr -d ' ')
if [ "$flat_count" = "4" ] && [ "$flat_files" = "8" ]; then
  pass "slicer chunks a flat tree into 4 non-overlapping slices"
else
  fail "flat-tree slicing wrong: slices=$flat_count files=$flat_files"
fi
rm -rf "$flat_target" "$flat_out"

# --path: restrict the partition to one subtree.
path_target=$(mktemp -d)
mkdir -p "$path_target/src/lib/parse" "$path_target/src/lib/net"
for n in 1 2 3; do printf 'a\nb\n' > "$path_target/src/lib/parse/p_$n.c"; done
for n in 1 2; do printf 'a\nb\n' > "$path_target/src/lib/net/n_$n.c"; done
path_out=$(mktemp -d)
python3 lib/recon_slicer.py --target-path "$path_target" --path parse --slices 2 \
  --out-dir "$path_out" >/dev/null 2>&1
path_slice_text="$(cat "$path_out"/slice-*.txt 2>/dev/null || true)"
if grep -q '/parse/' <<<"$path_slice_text" \
   && ! grep -q '/net/' <<<"$path_slice_text"; then
  pass "slicer --path restricts the partition to the named subtree"
else
  fail "slicer --path did not restrict scope: $path_slice_text"
fi
rm -rf "$path_target" "$path_out"

# --changed-since: only files changed in REF..HEAD; exit 7 on an empty set.
git_target=$(mktemp -d)
(
  cd "$git_target" \
    && git init -q && git config user.email t@t && git config user.name t \
    && mkdir -p src/lib/parse src/lib/net \
    && printf 'a\nb\n' > src/lib/parse/p1.c && printf 'a\nb\n' > src/lib/net/n1.c \
    && git add -A && git commit -qm base \
    && printf 'a\nb\nc\n' > src/lib/parse/p1.c && git add -A && git commit -qm change
) >/dev/null 2>&1
gco=$(mktemp -d)
python3 lib/recon_slicer.py --target-path "$git_target" --changed-since HEAD~1 \
  --slices 4 --out-dir "$gco" >/dev/null 2>&1
gco_slice_text="$(cat "$gco"/slice-*.txt 2>/dev/null || true)"
if grep -q '/parse/p1.c' <<<"$gco_slice_text" \
   && ! grep -q '/net/n1.c' <<<"$gco_slice_text"; then
  pass "slicer --changed-since partitions only the changed file set"
else
  fail "slicer --changed-since wrong set: $gco_slice_text"
fi
empty_rc=0
python3 lib/recon_slicer.py --target-path "$git_target" --changed-since HEAD \
  --slices 4 --out-dir "$gco" >/dev/null 2>&1 || empty_rc=$?
assert_eq "$empty_rc" "7" "slicer exits 7 (not an error) on an empty change set"
rm -rf "$git_target" "$gco"

# ── Scope auto-selection + scope flag plumbing ─────────────────────────
# auto picks 'all' for small trees and 'since' (change-driven, bounded)
# for large trees. We can't run audit-recon end-to-end in unit tests (it
# would spawn a real LLM call), so the count-based dispatch arithmetic is
# exercised in isolation; the flag parsing is exercised against the real
# script (it rejects bad values before reaching the LLM call).
small_target=$(mktemp -d)
mkdir -p "$small_target/src/lib"
for n in $(seq 1 20); do touch "$small_target/src/lib/file_${n}.c"; done

big_target=$(mktemp -d)
mkdir -p "$big_target/src/lib"
for n in $(seq 1 600); do touch "$big_target/src/lib/file_${n}.c"; done

py_scope=$(SMALL_TGT="$small_target" BIG_TGT="$big_target" python3 - <<'PY'
import os
from pathlib import Path

def count_sources(root):
    exts = {".c", ".cc", ".cpp", ".cxx", ".h", ".hpp", ".rs", ".go", ".py", ".java"}
    skip = ("/build", "/third_party", "/vendor", "/node_modules", "/.git")
    total = 0
    for p in Path(root).rglob("*"):
        if not p.is_file() or p.suffix not in exts:
            continue
        if any(seg in str(p) for seg in skip):
            continue
        total += 1
    return total

threshold = 500
for name, env in (("small", "SMALL_TGT"), ("big", "BIG_TGT")):
    n = count_sources(os.environ[env])
    print(f"{name}_scope", "all" if n <= threshold else "since")
PY
)

if grep -q "small_scope all" <<<"$py_scope"; then
  pass "auto-scope picks 'all' for <=500 source files"
else
  fail "auto-scope small branch wrong: $py_scope"
fi
if grep -q "big_scope since" <<<"$py_scope"; then
  pass "auto-scope picks 'since' for >500 source files"
else
  fail "auto-scope big branch wrong: $py_scope"
fi

# The deleted focus-area machinery must be gone.
if [ -f "$SCRIPT_ROOT/lib/recon_focus_areas.txt" ]; then
  fail "lib/recon_focus_areas.txt should have been deleted (focus-prompt removed)"
else
  pass "lib/recon_focus_areas.txt is gone (focus-prompt mode removed)"
fi
if grep -qE 'focus-prompt|recon_focus|FOCUS_LIST' "$SCRIPT_ROOT/bin/audit-recon"; then
  fail "bin/audit-recon still references focus-prompt mode"
else
  pass "bin/audit-recon has no focus-prompt mode"
fi

# --scope parsing should reject unknown values. We capture output into a
# tempfile rather than piping, because the script exits 2 on rejection
# and `set -o pipefail` here would otherwise mask the grep success.
scope_out=$(mktemp)
bash "$SCRIPT_ROOT/bin/audit-recon" --target test --target-path "$small_target" \
  --scope bogus >"$scope_out" 2>&1 || true
if grep -q 'FATAL: --scope' "$scope_out"; then
  pass "audit-recon rejects unknown --scope value"
else
  fail "audit-recon did not reject --scope bogus (output: $(cat "$scope_out"))"
fi

# --scope path with no --path is a hard error.
bash "$SCRIPT_ROOT/bin/audit-recon" --target test --target-path "$small_target" \
  --scope path >"$scope_out" 2>&1 || true
if grep -q 'FATAL: --scope path requires --path' "$scope_out"; then
  pass "audit-recon rejects --scope path without --path"
else
  fail "audit-recon accepted --scope path without --path"
fi

# --concurrency / --recon-lookback reject non-numeric values.
bash "$SCRIPT_ROOT/bin/audit-recon" --target test --target-path "$small_target" \
  --concurrency abc >"$scope_out" 2>&1 || true
if grep -q 'FATAL: --concurrency' "$scope_out"; then
  pass "audit-recon rejects non-numeric --concurrency"
else
  fail "audit-recon accepted non-numeric --concurrency"
fi
bash "$SCRIPT_ROOT/bin/audit-recon" --target test --target-path "$small_target" \
  --recon-lookback xyz >"$scope_out" 2>&1 || true
if grep -q 'FATAL: --recon-lookback' "$scope_out"; then
  pass "audit-recon rejects non-numeric --recon-lookback"
else
  fail "audit-recon accepted non-numeric --recon-lookback"
fi
rm -f "$scope_out"

# --recon-lookback defaults to 365 days, and --slices stays as a
# back-compat alias for --concurrency.
if grep -q 'LOOKBACK_DAYS=365' "$SCRIPT_ROOT/bin/audit-recon"; then
  pass "audit-recon --recon-lookback defaults to 365 days"
else
  fail "audit-recon --recon-lookback default is not 365"
fi
if grep -qF -- '--slices|--concurrency)' "$SCRIPT_ROOT/bin/audit-recon"; then
  pass "audit-recon accepts --slices as an alias for --concurrency"
else
  fail "audit-recon dropped the --slices back-compat alias"
fi

# --no-reroll should be accepted (flag-only, no value)
help_out=$(mktemp)
bash "$SCRIPT_ROOT/bin/audit-recon" --help --no-reroll >"$help_out" 2>&1 || true
if grep -q -- '--no-reroll' "$help_out"; then
  pass "audit-recon accepts --no-reroll flag"
else
  fail "audit-recon did not accept --no-reroll"
fi
rm -f "$help_out"

rm -rf "$small_target" "$big_target"

# ── Recon prompt template: byte-size ceiling + semantic preservation ───
# The prompt template is replayed via cache_read on every tool call.
# A 30% trim on a 4800-byte template saves ~1.4 KB per tool call.
# Across 50 tool calls per slice × 4 slices = 280 KB cache_read per run.
#
# Two failure modes the test protects against:
#   1. Template grows back over time and the savings get spent on prose.
#   2. Someone trims so aggressively that an essential marker is gone
#      (label name, confirmation-pass step, schema field, interpolation).
#
# We render the recon prompt by extracting the build_recon_prompt
# function from bin/audit-recon and invoking it in a subshell with
# synthetic inputs.

prompt_tmpdir=$(mktemp -d)
trap 'rm -rf "$prompt_tmpdir"' RETURN 2>/dev/null || true

# Extract build_recon_prompt definition (between "^build_recon_prompt()"
# and the next bare "}" at column 0).
awk '/^build_recon_prompt\(\)/,/^}$/' "$SCRIPT_ROOT/bin/audit-recon" \
  > "$prompt_tmpdir/bp.sh"

# file-list rendering
file_list_input="$prompt_tmpdir/files.txt"
cat > "$file_list_input" <<EOF
/synthetic/target/src/lib/foo.c
/synthetic/target/src/lib/bar.c
/synthetic/target/src/lib/baz.c
EOF
TARGET_SLUG=synthetic-target \
TARGET_PATH=/synthetic/target \
TIMEOUT_SECS=1800 \
SCRIPT_ROOT="$SCRIPT_ROOT" \
bash -c '
  source "$SCRIPT_ROOT/lib/prompt_template.sh"
  source "$1"
  build_recon_prompt slice-1-test "$2"
' _ "$prompt_tmpdir/bp.sh" "$file_list_input" > "$prompt_tmpdir/prompt-fl.txt" 2>&1

# --- Size ceiling ---
# Ceiling blocks regression back toward the pre-trim 4800-byte template
# and forces deliberation before anyone grows the prompt. Raised 2700 →
# 2760 (deliberate) for the canonical-symbol `function` schema hint: the
# recon agent must emit the fully-qualified frame-#0 symbol so findings
# dedup on a stable function rather than a drifting free-text label.
prompt_ceiling=2760

fl_size=$(wc -c < "$prompt_tmpdir/prompt-fl.txt" | tr -d ' ')

if [ "$fl_size" -le "$prompt_ceiling" ]; then
  pass "recon prompt size $fl_size <= $prompt_ceiling byte ceiling"
else
  fail "recon prompt regressed: $fl_size > $prompt_ceiling (template growing back)"
fi

# --- Semantic preservation ---
# Recall-mode prompt invariants. Every marker below is load-bearing:
# removing any of them either breaks the CTF recall framing,
# downstream aggregation (label values), or per-slice provenance.
assert_prompt_contains() {
  local file="$1" needle="$2" label="$3"
  if grep -qF -- "$needle" "$file"; then
    pass "$label contains '$needle'"
  else
    fail "$label missing '$needle' after trim — would break recall/parsing"
  fi
}

for variant in fl; do
  f="$prompt_tmpdir/prompt-fl.txt" ; vlabel="file-list"
  # CTF recall framing. These two phrases are what produced the
  # 14-finding simple-prompt baseline; the harness reproduces them.
  assert_prompt_contains "$f" 'playing in a CTF' "$vlabel-ctf-framing"
  # "Find all security issues" is stronger than "Find security issues" or
  # "Find a security issue" — the "all" is an explicit recall directive
  # that combats the model's natural tendency to commit to one or two
  # high-confidence findings and stop.
  assert_prompt_contains "$f" 'Find all security issues' "$vlabel-find-all-vulns"
  assert_prompt_contains "$f" 'recall, not precision' "$vlabel-recall-instr"
  # Recall enforcement: agents must not self-censor to AUDIT-CLEAN.
  assert_prompt_contains "$f" 'pre-filter' "$vlabel-no-prefilter"
  # The two labels recall mode emits.
  assert_prompt_contains "$f" 'NEEDS-VERIFICATION' "$vlabel-needs-ver"
  assert_prompt_contains "$f" 'AUDIT-CLEAN' "$vlabel-audit-clean"
  # JSONL schema field names. Recall-mode schema is smaller than the
  # legacy strict schema — keep only the fields the recall prompt asks
  # for. Validator works opaquely from .file/.class/.notes/.title.
  for field in '"id":' '"slice":' '"title":' '"file":' '"line":' '"function":' \
               '"class":' '"notes":' '"confidence":'; do
    assert_prompt_contains "$f" "$field" "$vlabel-schema"
  done
  # Interpolations: TARGET_SLUG, slice_name, TIMEOUT_SECS.
  assert_prompt_contains "$f" 'synthetic-target' "$vlabel-interp-target"
  assert_prompt_contains "$f" '1800' "$vlabel-interp-timeout"
  # JSONL output requirement and REC- id prefix.
  assert_prompt_contains "$f" 'JSONL' "$vlabel"
  assert_prompt_contains "$f" 'REC-' "$vlabel"
  # Per-slice provenance marker.
  assert_prompt_contains "$f" 'slice-1-test' "$vlabel-interp-slice-name"
done

# Final-form summary printout — gives the next developer a one-glance
# size readout when they look at the test log.
echo "  recon prompt size after trim: file-list=$fl_size bytes  (ceiling=$prompt_ceiling)"

rm -rf "$prompt_tmpdir"

# ── lib/recon_to_cards.py: JSONL → work-cards conversion ───────────────
# Converts recon hypotheses into work-card pool entries the bin/audit
# strategy rotator will pick up at cold start. Tests cover:
#   - class-to-strategy mapping
#   - score floors (recon CONFIRMED above S1 patch cards)
#   - AUDIT-CLEAN entries are dropped
#   - merge behaviour (existing non-recon cards preserved, recon cards
#     rewritten on every re-run so re-rolls don't multiply duplicates)

recon_tmpdir=$(mktemp -d)
recon_jsonl="$recon_tmpdir/recon-hypotheses.jsonl"
work_cards="$recon_tmpdir/work-cards.jsonl"
synth_target="/synthetic/target"

cat > "$recon_jsonl" <<JSONL
{"id":"REC-uaf01","slice":"slice-1","title":"UAF when callback calls cancel","file":"$synth_target/src/lib/proc.c","line":1477,"function":"end_query","class":"UAF","notes":"deferred callback frees query","confidence":"CONFIRMED-HIGH","validator_verdict":"Promote"}
{"id":"REC-intover","slice":"slice-2","title":"size mul wrap on alloc","file":"$synth_target/src/lib/record/rec.c","line":1249,"function":"set_bin","class":"integer-overflow","notes":"len*sizeof wraps to 0","confidence":"CONFIRMED-MEDIUM"}
{"id":"REC-dosamp","slice":"slice-3","title":"hash seed entropy","file":"$synth_target/src/lib/dsa/ht.c","line":64,"function":"seed","class":"DoS-amplification","notes":"|= instead of ^=","confidence":"NEEDS-VERIFICATION"}
{"id":"REC-leak","slice":"slice-4","title":"cookie cache key collision","file":"$synth_target/src/lib/cache.c","line":125,"function":"key","class":"info-leak","notes":"delimiter-based key","confidence":"CONFIRMED-MEDIUM"}
{"id":"REC-empty","slice":"slice-5","confidence":"AUDIT-CLEAN","notes":"all gated"}
JSONL

# Pre-seed an existing non-recon card; it must survive the merge.
cat > "$work_cards" <<JSONL
{"id":"WORK-existing-patch","kind":"patch-card","strategy":"S1","score":30}
JSONL

python3 lib/recon_to_cards.py \
  --target-slug synthetic-target \
  --target-path "$synth_target" \
  --recon-jsonl "$recon_jsonl" \
  --work-cards "$work_cards" --quiet 2>&1 | head -5 >/dev/null

# Total card count after P7 consolidation:
#   - 1 existing patch card (untouched)
#   - REC-uaf01 (Promote) → 1 consolidated card with allowed_strategies=[S5,S7]
#   - REC-intover (CONFIRMED-MEDIUM, no Promote) → 2 cards (S5+S7 fan-out)
#   - REC-dosamp (NEEDS-VERIFICATION) → 2 cards
#   - REC-leak (CONFIRMED-MEDIUM) → 2 cards
# Total = 1 + 1 + 2 + 2 + 2 = 8 cards. Sanitizer fan-out is asan-only.
card_total=$(wc -l < "$work_cards" | tr -d ' ')
assert_eq "$card_total" "8" "recon_to_cards: P7 collapses Promote (1) + non-Promote fan-out (6) + existing (1) = 8"

# AUDIT-CLEAN dropped
if grep -q '"REC-empty"' "$work_cards"; then
  fail "recon_to_cards: AUDIT-CLEAN entry leaked into work-cards"
else
  pass "recon_to_cards: AUDIT-CLEAN entries are dropped"
fi

# Existing non-recon card preserved
if grep -q 'WORK-existing-patch' "$work_cards"; then
  pass "recon_to_cards: existing non-recon cards survive merge"
else
  fail "recon_to_cards: existing patch card was clobbered"
fi

# Strategies fan-out check: every finding without an explicit .strategies
# field gets the default pair (S5, S7).
strategies_for_rec() {
  python3 -c "
import json, sys
target = sys.argv[1]
out=[]
for line in open('$work_cards'):
    line=line.strip()
    if not line: continue
    c=json.loads(line)
    if c.get('recon',{}).get('id')==target:
        out.append(c['strategy'])
print(','.join(sorted(out)))
" "$1"
}
# P7: REC-uaf01 is Promote → consolidated to ONE card, primary strategy
# S7, with allowed_strategies covering the full pair.
assert_eq "$(strategies_for_rec REC-uaf01)" "S7" "P7: Promote finding emits single card primary=S7"
allowed_for_rec() {
  python3 -c "
import json, sys
target = sys.argv[1]
for line in open('$work_cards'):
    line=line.strip()
    if not line: continue
    c=json.loads(line)
    if c.get('recon',{}).get('id')==target:
        print(','.join(sorted(c.get('allowed_strategies',[]) or []))); break
" "$1"
}
assert_eq "$(allowed_for_rec REC-uaf01)" "S5,S7" "P7: Promote card carries allowed_strategies=[S5,S7]"
assert_eq "$(strategies_for_rec REC-intover)" "S5,S7" "integer-overflow defaults to S5+S7 fan-out"
assert_eq "$(strategies_for_rec REC-dosamp)" "S5,S7" "DoS-amplification defaults to S5+S7 fan-out"
assert_eq "$(strategies_for_rec REC-leak)" "S5,S7" "info-leak defaults to S5+S7 fan-out"
# Non-Promote cards must NOT have allowed_strategies set (legacy field
# default; absent = no multi-strategy override).
assert_eq "$(allowed_for_rec REC-intover)" "" "P7: non-Promote cards leave allowed_strategies unset"

# Score floors (recon must outrank S1 patch cards which score ~20-60)
score_for_rec() {
  python3 -c "
import json, sys
target = sys.argv[1]
for line in open('$work_cards'):
    line=line.strip()
    if not line: continue
    c=json.loads(line)
    rid=c.get('recon',{}).get('id')
    if rid == target:
        print(c['score']); break
" "$1"
}
uaf_score=$(score_for_rec REC-uaf01)
intover_score=$(score_for_rec REC-intover)
dosamp_score=$(score_for_rec REC-dosamp)
if [ "${uaf_score:-0}" -ge 80 ]; then
  pass "validator-promoted UAF score $uaf_score >= 80 (outranks S1 patch cards)"
else
  fail "validator-promoted UAF score $uaf_score < 80"
fi
if [ "${intover_score:-0}" -ge 60 ] && [ "${intover_score:-0}" -lt "${uaf_score:-0}" ]; then
  pass "CONFIRMED-MEDIUM int-overflow score $intover_score between 60 and $uaf_score"
else
  fail "CONFIRMED-MEDIUM int-overflow score $intover_score outside expected range"
fi
if [ "${dosamp_score:-0}" -ge 40 ] && [ "${dosamp_score:-0}" -lt "${intover_score:-0}" ]; then
  pass "NEEDS-VERIFICATION DoS-amp score $dosamp_score between 40 and $intover_score"
else
  fail "NEEDS-VERIFICATION DoS-amp score $dosamp_score outside expected range"
fi

# ── Reject demotion: validator Reject ranks the card BELOW patch cards ─
# (~20-60) but still emits it so ASan gets a shot at being the oracle.
reject_dir=$(mktemp -d)
reject_jsonl="$reject_dir/recon.jsonl"
reject_cards="$reject_dir/work-cards.jsonl"
cat > "$reject_jsonl" <<JSONL
{"id":"REC-reject-hi","title":"validator rejected high-conf","file":"$synth_target/src/a.c","line":1,"function":"f","class":"UAF","confidence":"CONFIRMED-HIGH","validator_verdict":"Reject"}
{"id":"REC-promote-hi","title":"validator promoted","file":"$synth_target/src/b.c","line":1,"function":"g","class":"UAF","confidence":"CONFIRMED-HIGH","validator_verdict":"Promote"}
{"id":"REC-uncertain-hi","title":"validator uncertain","file":"$synth_target/src/c.c","line":1,"function":"h","class":"UAF","confidence":"CONFIRMED-HIGH","validator_verdict":"Uncertain"}
JSONL
python3 lib/recon_to_cards.py \
  --target-slug synthetic-target \
  --target-path "$synth_target" \
  --recon-jsonl "$reject_jsonl" \
  --work-cards "$reject_cards" --quiet 2>/dev/null

score_in_reject_cards() {
  python3 -c "
import json, sys
target=sys.argv[1]
for line in open('$reject_cards'):
    line=line.strip()
    if not line: continue
    c=json.loads(line)
    if c.get('recon',{}).get('id')==target:
        print(c['score']); break
" "$1"
}
reject_score=$(score_in_reject_cards REC-reject-hi)
promote_score=$(score_in_reject_cards REC-promote-hi)
uncertain_score=$(score_in_reject_cards REC-uncertain-hi)
# Reject card must still EXIST (not dropped) — recovery from LLM-noisy
# Reject is the whole point.
if grep -q '"REC-reject-hi"' "$reject_cards"; then
  pass "Reject vote does not drop card (probe still gets to run)"
else
  fail "Reject vote dropped the card — recovery from noisy Reject impossible"
fi
# Reject must be BELOW patch cards (which max out at ~60).
if [ "${reject_score:-0}" -lt 60 ] && [ "${reject_score:-0}" -gt 0 ]; then
  pass "Reject score $reject_score sits below patch-card range (drained last)"
else
  fail "Reject score $reject_score outside expected demote range (>0, <60)"
fi
# Reject must be strictly lower than both Promote and Uncertain so the
# validator's negative signal actually demotes.
if [ "${reject_score:-0}" -lt "${promote_score:-0}" ] \
    && [ "${reject_score:-0}" -lt "${uncertain_score:-0}" ]; then
  pass "Reject ($reject_score) < Uncertain ($uncertain_score) < Promote ($promote_score)"
else
  fail "Reject ($reject_score) should be < Uncertain ($uncertain_score) and < Promote ($promote_score)"
fi
rm -rf "$reject_dir"

# File-path relativisation
file_for_rec() {
  python3 -c "
import json, sys
target = sys.argv[1]
for line in open('$work_cards'):
    line=line.strip()
    if not line: continue
    c=json.loads(line)
    rid=c.get('recon',{}).get('id')
    if rid == target:
        print(c['file']); break
" "$1"
}
uaf_file=$(file_for_rec REC-uaf01)
if [ "$uaf_file" = "src/lib/proc.c" ]; then
  pass "absolute path relativised to '$uaf_file'"
else
  fail "absolute path not relativised; got '$uaf_file'"
fi

# Re-run idempotence: running again must not duplicate recon cards
python3 lib/recon_to_cards.py \
  --target-slug synthetic-target \
  --target-path "$synth_target" \
  --recon-jsonl "$recon_jsonl" \
  --work-cards "$work_cards" --quiet 2>&1 | head -5 >/dev/null
card_total_again=$(wc -l < "$work_cards" | tr -d ' ')
if [ "$card_total_again" = "$card_total" ]; then
  pass "re-running recon_to_cards is idempotent ($card_total cards)"
else
  fail "re-running recon_to_cards changed card count: $card_total -> $card_total_again"
fi

# ── Missing-confidence default (Bug 1 regression) ──────────────────────
# A finding without an explicit confidence field must NOT vanish silently —
# it should default to NEEDS-VERIFICATION and still produce a card.
missing_conf_dir=$(mktemp -d)
missing_conf_jsonl="$missing_conf_dir/recon.jsonl"
missing_conf_cards="$missing_conf_dir/work-cards.jsonl"
cat > "$missing_conf_jsonl" <<JSONL
{"id":"REC-noconfidence","title":"no confidence field","file":"$synth_target/src/lib/x.c","line":10,"function":"f","class":"UAF","notes":"oversight"}
JSONL
python3 lib/recon_to_cards.py \
  --target-slug synthetic-target \
  --target-path "$synth_target" \
  --recon-jsonl "$missing_conf_jsonl" \
  --work-cards "$missing_conf_cards" --quiet 2>&1 | head -3 >/dev/null
if grep -q '"REC-noconfidence"' "$missing_conf_cards"; then
  pass "missing-confidence finding defaults to NEEDS-VERIFICATION (not dropped)"
else
  fail "missing-confidence finding silently dropped (Bug 1 regression)"
fi
rm -rf "$missing_conf_dir"

# ── Sanitizer fan-out (--sanitizers from target.toml) ──────────────────
# One card per (finding, sanitizer). Verify:
#  - default (no --sanitizers) → mode=asan only (back-compat)
#  - --sanitizers asan,ubsan → two cards per finding with distinct IDs
#  - card.mode matches its sanitizer
fanout_dir=$(mktemp -d)
fanout_jsonl="$fanout_dir/recon.jsonl"
fanout_cards="$fanout_dir/work-cards.jsonl"
cat > "$fanout_jsonl" <<JSONL
{"id":"REC-fan1","title":"int overflow","file":"$synth_target/src/lib/x.c","line":42,"function":"add","class":"integer-overflow","confidence":"CONFIRMED-HIGH"}
JSONL

# Default (no --sanitizers): 1 sanitizer × 2 default strategies (S5,S7) = 2 cards
python3 lib/recon_to_cards.py \
  --target-slug synthetic-target \
  --target-path "$synth_target" \
  --recon-jsonl "$fanout_jsonl" \
  --work-cards "$fanout_cards" --quiet 2>&1 | head -3 >/dev/null
default_count=$(grep -c '"REC-fan1"' "$fanout_cards" || true)
assert_eq "$default_count" "2" "default sanitizers × default strategies → 1×2 = 2 cards"
default_modes=$(python3 -c "
import json
modes=set()
for line in open('$fanout_cards'):
    line=line.strip()
    if not line: continue
    c=json.loads(line)
    if c.get('recon',{}).get('id')=='REC-fan1':
        modes.add(c['mode'])
print(','.join(sorted(modes)))
")
assert_eq "$default_modes" "asan" "default fan-out mode is asan only"

# --sanitizers asan,ubsan: 2 sanitizers × 2 default strategies = 4 cards
python3 lib/recon_to_cards.py \
  --target-slug synthetic-target \
  --target-path "$synth_target" \
  --recon-jsonl "$fanout_jsonl" \
  --work-cards "$fanout_cards" \
  --sanitizers "asan,ubsan" --quiet 2>&1 | head -3 >/dev/null
fanout_count=$(grep -c '"REC-fan1"' "$fanout_cards" || true)
assert_eq "$fanout_count" "4" "--sanitizers asan,ubsan × default strategies → 2×2 = 4 cards"
modes=$(python3 -c "
import json
modes=set()
for line in open('$fanout_cards'):
    line=line.strip()
    if not line: continue
    c=json.loads(line)
    if c.get('recon',{}).get('id')=='REC-fan1':
        modes.add(c['mode'])
print(','.join(sorted(modes)))
")
assert_eq "$modes" "asan,ubsan" "fan-out cards carry asan + ubsan modes"
distinct_ids=$(python3 -c "
import json
ids=set()
for line in open('$fanout_cards'):
    line=line.strip()
    if not line: continue
    c=json.loads(line)
    if c.get('recon',{}).get('id')=='REC-fan1':
        ids.add(c['id'])
print(len(ids))
")
assert_eq "$distinct_ids" "4" "fan-out cards have distinct work-card IDs across (sanitizer, strategy)"

# All four sanitizers × default strategies: 4×2 = 8 cards
python3 lib/recon_to_cards.py \
  --target-slug synthetic-target \
  --target-path "$synth_target" \
  --recon-jsonl "$fanout_jsonl" \
  --work-cards "$fanout_cards" \
  --sanitizers "asan,ubsan,msan,tsan" --quiet 2>&1 | head -3 >/dev/null
all_four_count=$(grep -c '"REC-fan1"' "$fanout_cards" || true)
assert_eq "$all_four_count" "8" "4 sanitizers × 2 default strategies → 8 cards"
all_four_modes=$(python3 -c "
import json
modes=set()
for line in open('$fanout_cards'):
    line=line.strip()
    if not line: continue
    c=json.loads(line)
    if c.get('recon',{}).get('id')=='REC-fan1':
        modes.add(c['mode'])
print(','.join(sorted(modes)))
")
assert_eq "$all_four_modes" "asan,msan,tsan,ubsan" "fan-out honours all 4 sanitizers from operator's list"
rm -rf "$fanout_dir"

# Multi-strategy fan-out: every finding always gets the fixed (S5, S7)
# pair regardless of class. No agent input — keeping the schema simple.
# This is already verified by strategies_for_rec() above; nothing extra
# to test here.

# bin/audit must reference maybe_seed_recon_cards (smoke-check the hook
# without booting the full orchestrator).
if grep -q 'maybe_seed_recon_cards' "$SCRIPT_ROOT/bin/audit"; then
  pass "bin/audit invokes maybe_seed_recon_cards on cold start"
else
  fail "bin/audit missing maybe_seed_recon_cards hook"
fi
if grep -q '_seed_cards_from_recon' "$SCRIPT_ROOT/bin/audit"; then
  pass "bin/audit defines _seed_cards_from_recon helper"
else
  fail "bin/audit missing _seed_cards_from_recon"
fi
if grep -qF "sed -u 's/^/[recon-seed] /'" "$SCRIPT_ROOT/bin/audit"; then
  pass "bin/audit streams recon seed progress through unbuffered sed"
else
  fail "bin/audit recon seed progress can be buffered behind sed"
fi

# Shared recon cache: AUDIT_RECON_CACHE_DIR lets sibling runs on identical
# source (the benchmark's harness replicates) pay the cold recon once.
if grep -qF 'AUDIT_RECON_CACHE_DIR' "$SCRIPT_ROOT/bin/audit" \
  && grep -qF 'shared-cache HIT' "$SCRIPT_ROOT/bin/audit" \
  && grep -qF 'shared cache refreshed' "$SCRIPT_ROOT/bin/audit"; then
  pass "bin/audit honours AUDIT_RECON_CACHE_DIR (shared recon cache hit + refresh)"
else
  fail "bin/audit missing shared recon cache support"
fi
# The benchmark scopes one shared recon cache per run so harness replicates
# share it. Recon is backend/source-specific; a per-run dir is both.
if grep -qF 'AUDIT_RECON_CACHE_DIR=$BENCH_DIR/recon-cache' "$SCRIPT_ROOT/bin/benchmark"; then
  pass "benchmark points harness cells at a per-run shared recon cache"
else
  fail "benchmark harness cells do not share a recon cache across replicates"
fi

rm -rf "$recon_tmpdir"

# ── triage_validate: noop path ─────────────────────────────────────────
# noop mode returns Promote without invoking the validator
verdict=$(TRIAGE_VALIDATE_NOOP=1 SCRIPT_ROOT="$SCRIPT_ROOT" \
  bash -c '. "$1/lib/triage_validate.sh"; triage_validate_finding /tmp/nonexistent /tmp; echo "rc=$?"' _ "$SCRIPT_ROOT")
if grep -q "verdict=Promote" <<<"$verdict" && grep -q "rc=0" <<<"$verdict"; then
  pass "noop mode returns Promote rc=0"
else
  fail "noop mode unexpected: $verdict"
fi

# ── Validator ParseFailure retry ───────────────────────────────────────
# Each validator slot (v1, v2, v3 tiebreak) retries once on rc=3 so
# transient JSON-format hiccups don't degrade an otherwise-Promote
# finding to Uncertain. We mock bin/validate-finding with a script
# that returns rc=3 on its first invocation and rc=0 on the second.
retry_dir=$(mktemp -d)
mkdir -p "$retry_dir/bin"
counter_file="$retry_dir/call_count"
echo "0" > "$counter_file"
cat > "$retry_dir/bin/validate-finding" <<'STUB'
#!/usr/bin/env bash
# Mock validator: rc=3 on odd-numbered calls, rc=0 on even — so each
# slot's retry succeeds. Tracks call count in $COUNTER_FILE so the
# test can verify the retry actually happened.
count=$(cat "$COUNTER_FILE")
count=$((count + 1))
echo "$count" > "$COUNTER_FILE"
# Find --output and write a vote file (even for rc=3 — validate-finding
# is supposed to always write something for the quorum tally).
while [ $# -gt 0 ]; do
  case "$1" in
    --output) shift; printf '{"vote":"Promote"}\n' > "$1" 2>/dev/null ;;
  esac
  shift || true
done
if [ $((count % 2)) -eq 1 ]; then
  exit 3
fi
exit 0
STUB
chmod +x "$retry_dir/bin/validate-finding"
mkdir -p "$retry_dir/finding"
echo '{"id":"REC-x","class":"logic","title":"x"}' > "$retry_dir/finding/finding.json"
# `set -euo pipefail` + the `if out=$(...)` call shape mirror exactly
# how bin/audit-recon invokes the validator. macOS bash 3.2 under
# `set -u` aborts on "${empty_array[@]}" — and v1/v2 are called with no
# extra args, so _triage_run_validator's extra_args array is empty.
# That silently collapsed the whole validator stage (every finding
# instantly "rejected", no LLM call). The command-substitution
# if-condition is what keeps `set -e` from aborting on the validator's
# own non-zero exit, so the rc=3 retry still runs.
retry_verdict=$(COUNTER_FILE="$counter_file" \
  SCRIPT_ROOT="$retry_dir" \
  TRIAGE_VALIDATE_NOOP=0 \
  TRIAGE_VALIDATE_BACKEND=claude \
  bash -c 'set -euo pipefail; . "'"$SCRIPT_ROOT"'/lib/triage_validate.sh"; if out=$(triage_validate_finding "'"$retry_dir"'/finding/finding.json" /tmp); then rc=0; else rc=$?; fi; printf "%s\nrc=%s\n" "$out" "$rc"')
total_calls=$(cat "$counter_file")
# Two slots × 2 calls each = 4. v1: rc=3→retry rc=0; v2: rc=3→retry rc=0;
# both Promote so quorum is Promote and no tiebreak fires.
assert_eq "$total_calls" "4" "validator ParseFailure retry: 2 slots × 2 calls = 4"
if grep -q "verdict=Promote" <<<"$retry_verdict"; then
  pass "ParseFailure retry recovered to Promote"
else
  fail "ParseFailure retry unexpected: $retry_verdict"
fi
rm -rf "$retry_dir"

# Recon validator logs should be concise enough for operator-facing logs:
# one summary plus a details file, not one noisy line for every REC-* item.
if grep -qF 'log "  ${fid}: $vresult"' "$SCRIPT_ROOT/bin/audit-recon"; then
  fail "audit-recon still logs every validator result inline"
else
  pass "audit-recon avoids per-finding validator log spam"
fi
if grep -q 'triage_validate_finding .*|| true' "$SCRIPT_ROOT/bin/audit-recon"; then
  fail "audit-recon validator rc capture masks Uncertain/Reject as success"
else
  pass "audit-recon preserves validator exit status"
fi
if grep -qF 'Validator review complete:' "$SCRIPT_ROOT/bin/audit-recon" \
  && grep -qF 'lib/recon_triage.py' "$SCRIPT_ROOT/bin/audit-recon"; then
  pass "audit-recon logs a validator summary and runs the batched triage pipeline"
else
  fail "audit-recon missing batched-triage validation pipeline"
fi
# The batched gate has three stages: deterministic clustering, ONE batched
# triage agent over all representatives, and a single deep validator per
# survivor — replacing the old O(N) independent-validator-pair-per-row loop.
if grep -qF 'cluster \' "$SCRIPT_ROOT/bin/audit-recon" \
  && grep -qF 'recon_batch_triage.md.j2' "$SCRIPT_ROOT/bin/audit-recon" \
  && grep -qF 'parse-batch --reps' "$SCRIPT_ROOT/bin/audit-recon" \
  && grep -qF 'survivors \' "$SCRIPT_ROOT/bin/audit-recon" \
  && grep -qF 'finalize \' "$SCRIPT_ROOT/bin/audit-recon" \
  && grep -qF 'TRIAGE_VALIDATE_VOTES=1' "$SCRIPT_ROOT/bin/audit-recon"; then
  pass "audit-recon validation runs cluster -> batched triage -> single deep validator"
else
  fail "audit-recon batched-triage stages incomplete"
fi

# Benchmark cells and other isolated callers pass explicit --out/--report
# paths. Validation scratch and raw model logs must follow that output path,
# otherwise recon writes RECON-* dirs into the shared output/<target>/<backend>
# tree even while the hypothesis JSONL lands in the isolated run directory.
if grep -qF 'OUT_PATH_EXPLICIT=1' "$SCRIPT_ROOT/bin/audit-recon" \
  && grep -qF 'RESULTS_DIR="$(cd "$out_dir" && pwd -P)"' "$SCRIPT_ROOT/bin/audit-recon" \
  && grep -qF 'LOGDIR="$(dirname "$RESULTS_DIR")/logs"' "$SCRIPT_ROOT/bin/audit-recon"; then
  pass "audit-recon explicit --out roots validation artifacts beside output JSONL"
else
  fail "audit-recon explicit --out does not isolate validation artifacts"
fi

# ── Validation gate stdin isolation ────────────────────────────────────
# Stage 3 spawns the deep validator (an LLM CLI) inside a `while read` loop.
# `codex exec` drains fd 0, so the loop must read its survivor list on a
# private fd — otherwise the validator eats the rest of the list and the
# loop stops after the first survivor.
if grep -qF 'while IFS= read -r fid <&3; do' "$SCRIPT_ROOT/bin/audit-recon" \
  && grep -qF 'done 3< <(' "$SCRIPT_ROOT/bin/audit-recon"; then
  pass "audit-recon Stage 3 loop reads survivors on a private fd, not stdin"
else
  fail "audit-recon Stage 3 loop still reads survivors on stdin (validator can drain it)"
fi

# bin/validate-finding passes the prompt as an argument for claude/codex,
# so those CLIs must not inherit the caller's stdin — `codex exec` drains
# it. The gemini branch pipes its prompt on stdin and must keep the pipe.
vf_case=$(sed -n '/^case "\$BACKEND" in/,/^esac/p' "$SCRIPT_ROOT/bin/validate-finding")
claude_case=$(grep -A1 'CLAUDE_BIN' <<<"$vf_case" || true)
codex_case=$(grep -A1 'CODEX_BIN' <<<"$vf_case" || true)
if grep -qF '< /dev/null' <<<"$claude_case" \
  && grep -qF '< /dev/null' <<<"$codex_case"; then
  pass "validate-finding: claude/codex validator calls isolate stdin with < /dev/null"
else
  fail "validate-finding: claude/codex validator calls do not isolate stdin"
fi
gemini_case=$(grep -A2 'GEMINI_BIN' <<<"$vf_case" || true)
if grep -qF '< /dev/null' <<<"$gemini_case"; then
  fail "validate-finding: gemini branch must keep its prompt pipe, not redirect stdin from /dev/null"
else
  pass "validate-finding: gemini branch keeps its stdin prompt pipe"
fi
if grep -qF -- '--output-schema' "$SCRIPT_ROOT/bin/validate-finding"; then
  fail "validate-finding: Codex validator uses plain text JSON, not output schema"
else
  pass "validate-finding: Codex validator uses plain text JSON, not output schema"
fi

# ── Aggregator regex accepts both REC- and RECON- id prefixes ───────────
# The prompt template explicitly tells agents either prefix is fine
# (REC- or RECON-). Agents emit "REC-" overwhelmingly. An earlier regex
# of "RECON?-" required at least "RECO" — silently dropping every "REC-"
# line and turning a full pyyaml/angular recon round into 0 findings.
if grep -qF '"REC(ON)?-' "$SCRIPT_ROOT/bin/audit-recon"; then
  pass "audit-recon aggregator regex matches REC- and RECON- id prefixes"
else
  fail "audit-recon aggregator regex does not accept REC- prefix (only RECO-/RECON-)"
fi

# Behavioural check: simulate two slice logs (one REC-, one RECON-) and
# confirm the same grep used by audit-recon would pick them both up.
agg_re='^\{.*"id"[[:space:]]*:[[:space:]]*"REC(ON)?-'
agg_count=$(printf '%s\n%s\n%s\n' \
  '{"id":"REC-a","confidence":"NEEDS-VERIFICATION"}' \
  '{"id":"RECON-b","confidence":"AUDIT-CLEAN"}' \
  '{"id":"OTHER-c","confidence":"NEEDS-VERIFICATION"}' \
  | grep -aEc "$agg_re" || true)
assert_eq "$agg_count" "2" "aggregator regex matches REC- and RECON- but rejects OTHER-"

# ── Validator re-emit keeps OUT_PATH as one-object-per-line JSONL ───────
# The batched gate re-emits each hypothesis with validator_verdict /
# validator_details merged in via lib/recon_triage.py finalize, then
# OUT_PATH is consumed line-by-line by lib/recon_to_cards.py::load_jsonl.
# finalize must use compact json.dumps — a pretty-printed object spans
# ~14 lines, every "line" fails json.loads, and the whole recon round
# drops to 0 cards (observed on a zlib gemini run, old jq-without-c bug).
if grep -qF 'json.dumps(rec, ensure_ascii=False) + "\n"' "$SCRIPT_ROOT/lib/recon_triage.py"; then
  pass "recon_triage finalize writes compact one-object-per-line JSONL"
else
  fail "recon_triage finalize may pretty-print OUT_PATH — breaks line-by-line parse"
fi

# Behavioural check: the augmentation snippet must yield exactly one line.
augmented=$(printf '%s\n' '{"id":"REC-x","confidence":"NEEDS-VERIFICATION"}' \
  | jq -c --arg v "Promote" --arg d "verdict=Promote" \
      '. + {validator_verdict: $v, validator_details: $d}')
assert_eq "$(printf '%s' "$augmented" | wc -l | tr -d ' ')" "0" \
  "validator-augmented object is a single JSONL line (no embedded newlines)"

# ── Validator empty-array expansion is nounset-safe (bash 3.2) ─────────
# _triage_run_validator's extra_args array is empty for the v1/v2 slots.
# "${extra_args[@]}" under `set -u` on macOS bash 3.2 is an unbound-
# variable error that aborts the function; the ${arr[@]+"${arr[@]}"}
# guard expands to nothing instead. The retry test above exercises this
# at runtime under `set -u`; this is a fast static backstop.
if grep -qF '${extra_args[@]+"${extra_args[@]}"}' "$SCRIPT_ROOT/lib/triage_validate.sh" \
  && ! grep -qE '^[^#]*[^+]"\$\{extra_args\[@\]\}"' "$SCRIPT_ROOT/lib/triage_validate.sh"; then
  pass "triage_validate: validator extra_args uses nounset-safe expansion"
else
  fail "triage_validate: bare \"\${extra_args[@]}\" aborts under set -u on bash 3.2"
fi

# ── Recon gemini slice invocation pins agy --print-timeout ─────────────
# agy's --print-timeout defaults to 5m0s; a recon slice slower than that
# aborts with "Error: timed out waiting for response" before the outer
# `timeout "$TIMEOUT_SECS"` budget is ever reached. The slice launch
# must pass --print-timeout matched to TIMEOUT_SECS.
if grep -qE 'print-timeout "\$\{TIMEOUT_SECS\}s"' "$SCRIPT_ROOT/bin/audit-recon"; then
  pass "audit-recon gemini slice pins agy --print-timeout to TIMEOUT_SECS"
else
  fail "audit-recon gemini slice missing --print-timeout — slow slices die at agy's 5m default"
fi

# ── Recon backend workspaces include the target tree ───────────────────
# Benchmark harness cells run from an isolated repo facade while the target
# source stays in the real targets/<slug> tree. Gemini CLI refuses tool access
# outside --include-directories, so recon must add both roots.
if grep -qF 'local recon_add_dirs="$TARGET_PATH"' "$SCRIPT_ROOT/bin/audit-recon" \
  && grep -qF 'recon_add_dirs="$recon_add_dirs,$SCRIPT_ROOT"' "$SCRIPT_ROOT/bin/audit-recon" \
  && grep -qF 'llm_agent_flags "$BACKEND" recon_flags "${MODEL:-}" 80 "$recon_add_dirs"' "$SCRIPT_ROOT/bin/audit-recon"; then
  pass "audit-recon includes target path in backend workspace dirs"
else
  fail "audit-recon does not include target path in backend workspace dirs"
fi

summary
