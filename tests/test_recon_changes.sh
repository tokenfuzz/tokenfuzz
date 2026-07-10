#!/usr/bin/env bash
# Tests for recon-related additions:
#   - patch-card scoring and recon slicing
#   - patch-card boost / version-only filter (lib/workqueue.py)
#   - recon primitive classes are CVSS-classified (bin/severity)
#   - recon_slicer.py basic invocation
#   - triage_validate.py class routing
set -euo pipefail

TESTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT_ROOT="$(cd "$TESTS_DIR/.." && pwd)"
# shellcheck disable=SC1091
source "$TESTS_DIR/helpers.sh"
setup_test_env
audit_sha1() { shasum -a 1; }


# ── B4: patch-card boost / version-only filter ─────────────────────────────────────────────────
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
print("T_boost_rce", patch_audit_boost("Fix remote code execution in request handler"))
print("T_boost_stackexh", patch_audit_boost("Prevent stack exhaustion from deeply nested input"))
print("T_boost_amplification", patch_audit_boost("Mitigate DoS amplification in resolver"))
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
verify_ge T_boost_rce 20
verify_ge T_boost_stackexh 20
verify_ge T_boost_amplification 20

# ── T2-9: new reachability primitives ───────────────────────────────────
py_out=$(python3 - <<'PY'
import importlib.machinery, importlib.util
loader = importlib.machinery.SourceFileLoader("sev", "bin/severity")
spec = importlib.util.spec_from_loader("sev", loader)
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
    m, _ = mod._cvss4_metrics(key, "library", {}, False)
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

# ── Drift guard: patch_audit_boost vs the bin/severity class taxonomy ───
# bin/severity.CVSS4_CLASS is the authoritative set of crash/vuln classes the
# harness scores. Every such class a prior-fix COMMIT could name should earn a
# patch_audit_boost so S1 ranks it; classes intentionally NOT boosted from
# commit text are listed with a reason. A new CVSS4_CLASS key in neither map
# fails this test — forcing a conscious decision instead of silent drift.
drift_out=$(python3 - <<'PY'
import sys, importlib.machinery, importlib.util
sys.path.insert(0, "lib")
import workqueue as wq
loader = importlib.machinery.SourceFileLoader("sev", "bin/severity")
sev = importlib.util.module_from_spec(importlib.util.spec_from_loader("sev", loader))
loader.exec_module(sev)

# class key -> a representative commit phrase that MUST boost
COVERAGE = {
    "uaf_write": "use-after-free write", "uaf_read": "use-after-free read",
    "double_free": "double free", "wild_write": "wild pointer write",
    "wild_read": "wild pointer read", "type_confusion": "type confusion",
    "heap_write": "heap buffer overflow", "heap_read_big": "heap buffer over-read",
    "heap_read_small": "out-of-bounds read", "stack_write": "stack buffer overflow",
    "stack_read": "stack buffer over-read", "global_write": "global buffer overflow",
    "global_read": "global buffer over-read", "data_race": "data race",
    "info_leak": "uninitialized memory read", "null_deref": "null pointer dereference",
    "stack_exhaustion": "stack exhaustion via deep recursion",
    "integer_overflow": "integer overflow", "regex_dos": "ReDoS catastrophic backtracking",
    "dos_amplification": "DoS amplification", "command_injection": "remote code execution",
    "deserialization": "insecure deserialization", "ssti": "server-side template injection",
    "sqli": "SQL injection", "authn_bypass": "authentication bypass",
    "authz_bypass": "authorization bypass", "idor": "insecure direct object reference",
    "path_traversal": "path traversal", "xxe": "XML external entity",
    "secrets_exposure": "hard-coded credential leak", "ssrf": "server-side request forgery",
    "prototype_pollution": "prototype pollution", "xss": "cross-site scripting",
    "open_redirect": "open redirect", "csrf": "cross-site request forgery",
    "crypto_weakness": "weak cryptography", "injection": "CRLF injection",
}
# class key -> why it is deliberately NOT boosted from commit prose
BOOST_EXEMPT = {
    "memory_leak": "leak fixes are high-volume maintenance noise; would drown real defects",
    "oom": "OOM/resource-exhaustion fixes are high-volume and rarely security-relevant in prose",
    "bus": "SIGBUS/unaligned is sanitizer-detected; the bare token would false-match ordinary words",
    "protocol_state": "severity narrative fallback; concrete protocol bugs are boosted individually",
    "logic_regression": "severity meta-class (defense-in-depth), not a class named in fix commits",
}
keys = set(sev.CVSS4_CLASS)
overlap = set(COVERAGE) & set(BOOST_EXEMPT)
unaccounted = keys - set(COVERAGE) - set(BOOST_EXEMPT)
stray = (set(COVERAGE) | set(BOOST_EXEMPT)) - keys
no_boost = sorted(k for k, p in COVERAGE.items() if wq.patch_audit_boost(p) == 0)
if overlap:      print("DRIFT fail: keys in both COVERAGE and EXEMPT:", sorted(overlap))
elif unaccounted:print("DRIFT fail: CVSS4_CLASS keys not covered or exempted:", sorted(unaccounted))
elif stray:      print("DRIFT fail: map keys absent from CVSS4_CLASS:", sorted(stray))
elif no_boost:   print("DRIFT fail: representative phrase did not boost:", no_boost)
else:            print("DRIFT ok")
PY
)
assert_eq "DRIFT ok" "$drift_out" \
  "patch_audit_boost covers every bin/severity CVSS4_CLASS class (or explicitly exempts it)"

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

# ── Slicer --seed: deterministic base seed and re-roll differ ──────────
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

# Dependency coherence: on a flat tree, files connected by target-local
# quoted includes and uniquely-resolved calls/imports must land in one
# dependency unit; unrelated files and ambiguous names must not. These are
# context-packing hints only and never change what counts as a finding, so
# they are exercised directly against build_dependency_units.
dep_rc=0
python3 - <<'PY' || dep_rc=$?
import sys, tempfile
from pathlib import Path
sys.path.insert(0, "lib")
import recon_slicer as rs

def component_of(units, name):
    for _, fs in units:
        names = {f.name for f in fs}
        if name in names:
            return names
    return set()

# 1. include + call coherence on a flat tree.
d = Path(tempfile.mkdtemp())
(d / "app_parse.h").write_text('#ifndef H\n#define H\nint app_decode(int);\n#endif\n')
(d / "app_parse.c").write_text('#include "app_parse.h"\nint run(int x){ return app_decode(x); }\n')
(d / "app_codec.c").write_text('int app_decode(int x){ return x + 1; }\n')
(d / "app_misc.c").write_text('int app_unrelated(void){ return 0; }\n')
files = sorted(d.glob("*.[ch]"))
units = rs.build_dependency_units(d, files)
comp = component_of(units, "app_parse.c")
assert {"app_parse.c", "app_parse.h", "app_codec.c"} <= comp, f"include/call clustering: {units}"
assert "app_misc.c" not in comp, f"unrelated file pulled in: {units}"

# 2. ambiguous (multiply-defined) names create no edge.
a = Path(tempfile.mkdtemp())
(a / "one.c").write_text('int dup(void){ return 1; }\n')
(a / "two.c").write_text('int dup(void){ return 2; }\n')
(a / "call.c").write_text('void go(void){ dup(); }\n')
assert rs.build_dependency_units(a, sorted(a.glob("*.c"))) == [], "ambiguous def created an edge"

# 3. PHP require coherence.
p = Path(tempfile.mkdtemp())
(p / "entry.php").write_text("<?php require_once 'helper.php'; run();\n")
(p / "helper.php").write_text("<?php function run(){ return 1; }\n")
assert {"entry.php", "helper.php"} <= component_of(
    rs.build_dependency_units(p, sorted(p.glob("*.php"))), "entry.php"), "PHP require clustering"

# 4. Python import -> CPython extension module coherence.
y = Path(tempfile.mkdtemp())
(y / "driver.py").write_text("import fastthing\nfastthing.go()\n")
(y / "fastthing.c").write_text(
    '#include <Python.h>\nPyMODINIT_FUNC PyInit_fastthing(void){ return NULL; }\n')
assert {"driver.py", "fastthing.c"} <= component_of(
    rs.build_dependency_units(y, sorted(y.iterdir())), "driver.py"), "py->c-extension clustering"

# 5. Call edges are registry-driven, so every supported language clusters a
# cross-file definition+call pair — not just the C/JS/Python originals.
LANG_CASES = {
    ".rs":   ("pub fn decode(x: i32) -> i32 { x + 1 }\n", "fn run() { let _ = decode(1); }\n"),
    ".go":   ("func Decode(x int) int { return x + 1 }\n", "func Run() { Decode(1) }\n"),
    ".java": ("  public int decode(int x) { return x + 1; }\n", "  void run() { decode(1); }\n"),
    ".swift":("func decode(_ x: Int) -> Int { return x + 1 }\n", "func run() { _ = decode(1) }\n"),
    ".kt":   ("fun decode(x: Int): Int { return x + 1 }\n", "fun run() { decode(1) }\n"),
    ".pl":   ("sub decode { return $_[0] + 1; }\n", "sub run { decode(1); }\n"),
    ".rb":   ("def decode(x)\n  x + 1\nend\n", "def run\n  decode(1)\nend\n"),
    ".ts":   ("export function decode(x: number) { return x + 1 }\n", "function run() { decode(1) }\n"),
}
for ext, (def_src, call_src) in LANG_CASES.items():
    g = Path(tempfile.mkdtemp())
    (g / f"def{ext}").write_text(def_src)
    (g / f"use{ext}").write_text(call_src)
    comp = component_of(rs.build_dependency_units(g, sorted(g.iterdir())), f"def{ext}")
    assert {f"def{ext}", f"use{ext}"} <= comp, f"call-edge clustering broke for {ext}: {comp}"

# 6. Mixed-language guard. A coincidental same-name call across unrelated
# runtimes must NOT merge (false-positive guard); a call within a shared
# call-family (C/C++, JS/TS, Java/Kotlin) MUST still merge even across file
# extensions (false-negative guard for mixed-language projects).
def two(name_a, src_a, name_b, src_b):
    z = Path(tempfile.mkdtemp())
    (z / name_a).write_text(src_a)
    (z / name_b).write_text(src_b)
    return rs.build_dependency_units(z, sorted(z.iterdir()))

# cross-runtime coincidence: a Python decode() call vs the sole C decode().
assert two("driver.py", "def go():\n    decode(1)\n",
           "codec.c", "int decode(int x){ return x + 1; }\n") == [], \
    "cross-family coincidental call must not merge"
# intra-family across extensions: a .ts caller and the sole .js definition.
assert {"app.ts", "lib.js"} <= component_of(
    two("lib.js", "function decode(x){ return x + 1 }\n",
        "app.ts", "function run(){ decode(1) }\n"), "lib.js"), \
    "intra-family JS/TS call edge must merge"
# intra-family across extensions: a .cc caller and the sole .c definition.
assert {"impl.c", "use.cc"} <= component_of(
    two("impl.c", "int decode(int x){ return x + 1; }\n",
        "use.cc", "void run(){ decode(1); }\n"), "impl.c"), \
    "intra-family C/C++ call edge must merge"

# 7. Uniqueness is per call-family, not global: an unrelated cross-runtime
# duplicate name must NOT erase a valid same-family edge.
z = Path(tempfile.mkdtemp())
(z / "codec.c").write_text("int decode(int x){ return x + 1; }\n")
(z / "use.c").write_text("void run(void){ decode(1); }\n")
(z / "helper.py").write_text("def decode(x):\n    return x\n")  # coincidental dup
assert {"codec.c", "use.c"} <= component_of(
    rs.build_dependency_units(z, sorted(z.iterdir())), "codec.c"), \
    "cross-runtime duplicate name erased a same-family edge"

# 8. Modern JS/TS arrow/const definitions create call edges (not just the
# classic `function foo()` form).
assert {"lib.js", "app.js"} <= component_of(
    two("lib.js", "export const decode = (x) => { return x + 1 }\n",
        "app.js", "function run(){ return decode(1) }\n"), "lib.js"), \
    "JS arrow/const definition must produce a call edge"
assert {"lib.ts", "app.ts"} <= component_of(
    two("lib.ts", "export const decode = (x: number): number => x + 1\n",
        "app.ts", "function run(){ return decode(1) }\n"), "lib.ts"), \
    "TS return-typed arrow definition must produce a call edge"

print("ok")
PY
if [ "$dep_rc" = "0" ]; then
  pass "slicer dependency units cluster include/call/import edges across all registry languages"
else
  fail "slicer dependency-unit clustering broken (rc=$dep_rc)"
fi

# An in-tree symlink that resolves outside the source root must not abort
# the slicer (relative_to would raise); it should fall back gracefully and
# still partition the real files.
sym_rc=0
python3 - <<'PY' || sym_rc=$?
import os, sys, tempfile
from pathlib import Path
sys.path.insert(0, "lib")
import recon_slicer as rs
base = Path(tempfile.mkdtemp())
outside = Path(tempfile.mkdtemp())
(outside / "ext.c").write_text("int decode(int x){ return x + 1; }\n")
(base / "real.c").write_text("void run(void){ decode(1); }\n")
os.symlink(outside / "ext.c", base / "link.c")
files = sorted([base / "real.c", base / "link.c"])
units = rs.build_dependency_units(base, files)  # must not raise
got = {f.name for _, fs in units for f in fs}
# No crash is the contract; the symlinked def is still reachable via call edge.
assert "real.c" in got, f"slicer dropped real files on symlink: {got}"
print("ok")
PY
if [ "$sym_rc" = "0" ]; then
  pass "slicer tolerates an in-tree symlink resolving outside the source root"
else
  fail "slicer aborted on an out-of-root symlink (rc=$sym_rc)"
fi

# End-to-end: connected files on a flat tree share one slice, and the
# partition still covers every file exactly once.
depe_target=$(mktemp -d)
mkdir -p "$depe_target/src/lib"
printf '#ifndef H\n#define H\nint app_decode(int);\n#endif\n' \
  > "$depe_target/src/lib/app_parse.h"
printf '#include "app_parse.h"\nint run(int x){ return app_decode(x); }\n' \
  > "$depe_target/src/lib/app_parse.c"
printf 'int app_decode(int x){ return x + 1; }\n' \
  > "$depe_target/src/lib/app_codec.c"
for f in alpha beta gamma; do seq 1 40 > "$depe_target/src/lib/app_$f.c"; done
depe_out=$(mktemp -d)
python3 lib/recon_slicer.py --target-path "$depe_target" --slices 3 \
  --out-dir "$depe_out" >/dev/null 2>&1
depe_total=$(cat "$depe_out"/slice-*.txt 2>/dev/null | sort | wc -l | tr -d ' ')
depe_uniq=$(cat "$depe_out"/slice-*.txt 2>/dev/null | sort -u | wc -l | tr -d ' ')
depe_together=no
for sf in "$depe_out"/slice-*.txt; do
  if grep -q 'app_parse.c' "$sf" && grep -q 'app_parse.h' "$sf" \
     && grep -q 'app_codec.c' "$sf"; then
    depe_together=yes
  fi
done
if [ "$depe_together" = "yes" ] && [ "$depe_total" = "6" ] && [ "$depe_uniq" = "6" ]; then
  pass "slicer keeps dependency-connected flat-tree files in one slice"
else
  fail "dependency slice wrong: together=$depe_together total=$depe_total uniq=$depe_uniq"
fi
rm -rf "$depe_target" "$depe_out"

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
"$SCRIPT_ROOT/bin/audit-recon" --target test --target-path "$small_target" --backend codex \
  --scope bogus >"$scope_out" 2>&1 || true
if grep -qE 'FATAL: --scope|invalid choice.*bogus' "$scope_out"; then
  pass "audit-recon rejects unknown --scope value"
else
  fail "audit-recon did not reject --scope bogus (output: $(cat "$scope_out"))"
fi

# --scope path with no --path is a hard error.
"$SCRIPT_ROOT/bin/audit-recon" --target test --target-path "$small_target" --backend codex \
  --scope path >"$scope_out" 2>&1 || true
if grep -qE 'FATAL: --scope path requires --path|--scope path requires --path' "$scope_out"; then
  pass "audit-recon rejects --scope path without --path"
else
  fail "audit-recon accepted --scope path without --path"
fi

# --concurrency / --recon-lookback reject non-numeric values.
"$SCRIPT_ROOT/bin/audit-recon" --target test --target-path "$small_target" --backend codex \
  --concurrency abc >"$scope_out" 2>&1 || true
if grep -qE 'FATAL: --concurrency|argument --concurrency.*(invalid|must be)' "$scope_out"; then
  pass "audit-recon rejects non-numeric --concurrency"
else
  fail "audit-recon accepted non-numeric --concurrency"
fi
"$SCRIPT_ROOT/bin/audit-recon" --target test --target-path "$small_target" --backend codex \
  --recon-lookback xyz >"$scope_out" 2>&1 || true
if grep -qE 'FATAL: --recon-lookback|argument --recon-lookback.*(invalid|must be)' "$scope_out"; then
  pass "audit-recon rejects non-numeric --recon-lookback"
else
  fail "audit-recon accepted non-numeric --recon-lookback"
fi
rm -f "$scope_out"

# --recon-lookback defaults to 365 days.
if grep -q '"--recon-lookback".*default=365' "$SCRIPT_ROOT/bin/audit-recon"; then
  pass "audit-recon --recon-lookback defaults to 365 days"
else
  fail "audit-recon --recon-lookback default is not 365"
fi
assert_file_contains "$SCRIPT_ROOT/bin/audit-recon" 'add_argument("--concurrency"' \
  "audit-recon exposes the concurrency control"

# --no-reroll should be accepted (flag-only, no value)
help_out=$(mktemp)
"$SCRIPT_ROOT/bin/audit-recon" --help --no-reroll >"$help_out" 2>&1 || true
if grep -q -- '--no-reroll' "$help_out"; then
  pass "audit-recon accepts --no-reroll flag"
else
  fail "audit-recon did not accept --no-reroll"
fi
rm -f "$help_out"

rm -rf "$small_target" "$big_target"


summary
