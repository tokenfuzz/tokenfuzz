#!/usr/bin/env bash
# Regression tests for AUDIT_BUILD_SUFFIX wiring.
#
# AUDIT_BUILD_SUFFIX is set by bin/audit-container-shell to a short
# container image ID so different container images get isolated sanitizer
# build trees. Outside a container it is empty and paths stay plain
# build-asan/build-ubsan/.... This suite locks in the contract for every
# code path that composes or filters sanitizer build dirs (except the
# Firefox ff-* skills, which intentionally don't know about the suffix).
set -o pipefail
source "$(dirname "$0")/helpers.sh"
setup_test_env

# ───────────────────────────────────────────────────────────────────
# lib/sanitizer.sh::sanitizer_build_dir helper
# ───────────────────────────────────────────────────────────────────
source "$SCRIPT_ROOT/lib/sanitizer.sh"

TARGET_ROOT="$TEST_TMPDIR/target"

unset AUDIT_BUILD_SUFFIX
assert_eq "$TARGET_ROOT/build-asan"     "$(sanitizer_build_dir asan)"     "sanitizer_build_dir asan: no suffix"
assert_eq "$TARGET_ROOT/build-ubsan"    "$(sanitizer_build_dir ubsan)"    "sanitizer_build_dir ubsan: no suffix"
assert_eq "$TARGET_ROOT/build-msan"     "$(sanitizer_build_dir msan)"     "sanitizer_build_dir msan: no suffix"
assert_eq "$TARGET_ROOT/build-tsan"     "$(sanitizer_build_dir tsan)"     "sanitizer_build_dir tsan: no suffix"
assert_eq "$TARGET_ROOT/build-asan-cov" "$(sanitizer_build_dir asan-cov)" "sanitizer_build_dir asan-cov: no suffix"

export AUDIT_BUILD_SUFFIX="-abc123"
assert_eq "$TARGET_ROOT/build-asan-abc123"     "$(sanitizer_build_dir asan)"     "sanitizer_build_dir asan: with suffix"
assert_eq "$TARGET_ROOT/build-ubsan-abc123"    "$(sanitizer_build_dir ubsan)"    "sanitizer_build_dir ubsan: with suffix"
assert_eq "$TARGET_ROOT/build-msan-abc123"     "$(sanitizer_build_dir msan)"     "sanitizer_build_dir msan: with suffix"
assert_eq "$TARGET_ROOT/build-tsan-abc123"     "$(sanitizer_build_dir tsan)"     "sanitizer_build_dir tsan: with suffix"
assert_eq "$TARGET_ROOT/build-asan-cov-abc123" "$(sanitizer_build_dir asan-cov)" "sanitizer_build_dir asan-cov: with suffix"

# Custom root via second arg
assert_eq "/custom/build-asan-abc123" "$(sanitizer_build_dir asan /custom)" "sanitizer_build_dir: custom root"

unset AUDIT_BUILD_SUFFIX

# ───────────────────────────────────────────────────────────────────
# target_resolve_path (sh) + Config.resolve_path (py) apply
# AUDIT_BUILD_SUFFIX to bare build-{san}/ first segments so target.toml
# stays portable between host (no suffix) and per-image container builds.
# Cases (input → expected, given AUDIT_BUILD_SUFFIX=-img42):
#   build-asan/lib/foo.a       → /r/build-asan-img42/lib/foo.a   rewrite
#   build-ubsan                → /r/build-ubsan-img42            bare-segment rewrite
#   include                    → /r/include                      non-build untouched
#   build-asan-other/foo       → /r/build-asan-other/foo         literal pre-suffix untouched
#   /abs/build-asan/foo        → /abs/build-asan/foo             absolute untouched
# ───────────────────────────────────────────────────────────────────
source "$SCRIPT_ROOT/lib/target_config.sh"
TARGET_ROOT=/r

check_resolve() {
  local input="$1" expected="$2" label="$3"
  assert_eq "$expected" "$(target_resolve_path "$input")" "target_resolve_path: $label"
}

unset AUDIT_BUILD_SUFFIX
check_resolve 'build-asan/lib/foo.a' '/r/build-asan/lib/foo.a' 'no suffix → no rewrite'
check_resolve 'include'              '/r/include'              'no suffix → non-build unchanged'

export AUDIT_BUILD_SUFFIX="-img42"
for san in asan ubsan msan tsan; do
  check_resolve "build-${san}/lib/foo.a" "/r/build-${san}-img42/lib/foo.a" "build-${san}/... rewrite"
  check_resolve "build-${san}"           "/r/build-${san}-img42"           "bare build-${san} rewrite"
done
check_resolve 'include'                '/r/include'                'non-build path untouched'
check_resolve 'build-asan-other/foo'   '/r/build-asan-other/foo'   'literal pre-suffix passes through'
check_resolve '/abs/build-asan/foo'    '/abs/build-asan/foo'       'absolute path untouched'
unset AUDIT_BUILD_SUFFIX

# Python mirror: lib/target_config.py::Config.resolve_path follows the
# same rule (used by sanitizer_suppressions_path).
python3 - <<'PY' || { fail "Config.resolve_path suffix coverage"; exit 1; }
import os, sys, importlib
sys.path.insert(0, "lib")

def fresh_cfg(suffix):
    os.environ.pop("AUDIT_BUILD_SUFFIX", None)
    if suffix:
        os.environ["AUDIT_BUILD_SUFFIX"] = suffix
    import target_config; importlib.reload(target_config)
    return target_config.Config(target_root="/r")

cases_with_suffix = [
    ("build-asan/lib/foo.a",   "/r/build-asan-img42/lib/foo.a"),
    ("build-ubsan",            "/r/build-ubsan-img42"),
    ("include",                "/r/include"),
    ("build-asan-other/foo",   "/r/build-asan-other/foo"),
    ("/abs/build-asan/foo",    "/abs/build-asan/foo"),
]
cfg = fresh_cfg("-img42")
for inp, exp in cases_with_suffix:
    got = cfg.resolve_path(inp)
    assert got == exp, f"with suffix: {inp!r} → {got!r}, expected {exp!r}"

cfg = fresh_cfg("")
assert cfg.resolve_path("build-asan/lib/foo.a") == "/r/build-asan/lib/foo.a"
print("OK")
PY
pass "Config.resolve_path mirrors AUDIT_BUILD_SUFFIX rewriting"

# ───────────────────────────────────────────────────────────────────
# bin/run-{asan,ubsan,msan,tsan} + bin/hits resolve build dirs through
# the shared sanitizer_build_dir helper. Grep is the right tool here:
# sourcing the runners would execute their full body, but the contract
# we care about is that they call the helper rather than inlining the
# suffix expansion (which would drift).
# ───────────────────────────────────────────────────────────────────
for entry in \
    "run-asan ASAN_BUILD_DIR asan" \
    "run-ubsan UBSAN_BUILD_DIR ubsan" \
    "run-msan MSAN_BUILD_DIR msan" \
    "run-tsan TSAN_BUILD_DIR tsan"; do
  read -r runner var san <<< "$entry"
  _CURRENT_TEST="$runner uses sanitizer_build_dir for $var"
  if grep -qE "^${var}=\"\\\$\\(sanitizer_build_dir ${san}\\)\"" \
       "$SCRIPT_ROOT/bin/$runner"; then
    pass
  else
    fail "$_CURRENT_TEST" \
      "expected '${var}=\"\$(sanitizer_build_dir ${san})\"' in bin/$runner"
  fi
done

_CURRENT_TEST="bin/hits uses sanitizer_build_dir for asan + asan-cov"
if grep -qE '^ASAN_BUILD_DIR="\$\(sanitizer_build_dir asan\)"' "$SCRIPT_ROOT/bin/hits" \
   && grep -qE '^COV_BUILD_DIR="\$\(sanitizer_build_dir asan-cov\)"' "$SCRIPT_ROOT/bin/hits"; then
  pass
else
  fail "$_CURRENT_TEST" "bin/hits doesn't route both build dirs through sanitizer_build_dir"
fi

# ───────────────────────────────────────────────────────────────────
# bin/audit detect_sanitizer_builds: ASAN_BUILD_DIR default uses suffix
# ───────────────────────────────────────────────────────────────────
_CURRENT_TEST="bin/audit ASAN_BUILD_DIR default honours suffix"
# detect_sanitizer_builds is referenced in bin/audit at the prelude; grep
# the literal default expression rather than executing the big script.
audit_default=$(grep -n 'ASAN_BUILD_DIR="\${ASAN_BUILD_DIR:-' "$SCRIPT_ROOT/bin/audit" | head -1)
if grep -qE 'build-asan\$\{AUDIT_BUILD_SUFFIX:-\}' <<<"$audit_default"; then
  pass
else
  fail "$_CURRENT_TEST" "bin/audit ASAN_BUILD_DIR default missing suffix: $audit_default"
fi

for san in ubsan msan tsan; do
  SAN_UPPER=$(printf '%s' "$san" | tr '[:lower:]' '[:upper:]')
  _CURRENT_TEST="bin/audit ${SAN_UPPER}_BUILD_DIR default honours suffix"
  line=$(grep -nE "${SAN_UPPER}_BUILD_DIR:-\\\$\\{TARGET_ROOT\\}/build-${san}" "$SCRIPT_ROOT/bin/audit" | head -1)
  if grep -qE "build-${san}\\\$\\{AUDIT_BUILD_SUFFIX:-\\}" <<<"$line"; then
    pass
  else
    fail "$_CURRENT_TEST" "missing suffix in: $line"
  fi
done

_CURRENT_TEST="bin/audit firefox preflight path honours suffix"
ff_line=$(grep -n "_ff_asan_dir=" "$SCRIPT_ROOT/bin/audit" | head -1)
if grep -qE 'build-asan\$\{AUDIT_BUILD_SUFFIX:-\}' <<<"$ff_line"; then
  pass
else
  fail "$_CURRENT_TEST" "missing suffix in: $ff_line"
fi

# ───────────────────────────────────────────────────────────────────
# lib/workqueue.py is_excluded_path_part: suffixed sanitizer dirs excluded
# ───────────────────────────────────────────────────────────────────
python3 - <<'PY' || { fail "workqueue.is_excluded_path_part suffix coverage"; exit 1; }
import sys
sys.path.insert(0, "lib")
from workqueue import is_excluded_path_part

for san in ("asan", "ubsan", "msan", "tsan"):
    for variant in (f"build-{san}", f"build-{san}-abc1234", f"build-{san}-img-42"):
        assert is_excluded_path_part(variant), f"expected {variant!r} excluded"

# A plain "build" segment is NOT auto-excluded — lib/audit_scope was
# simplified to only doc/example/test/fuzz families so vendored deps
# and plain build/ outputs stay in scope. Only the suffixed sanitizer
# build dirs (build-asan*, build-ubsan*, ...) are auto-excluded via
# the prefix rule above.
assert not is_excluded_path_part("build"), "plain 'build' should be auditable now"
# Unrelated dirs not excluded.
for ok in ("src", "include", "parser"):
    assert not is_excluded_path_part(ok), f"unexpected exclusion of {ok!r}"

print("OK")
PY
pass "workqueue.is_excluded_path_part covers AUDIT_BUILD_SUFFIX variants"

# ───────────────────────────────────────────────────────────────────
# lib/recon_slicer.py SKIP_DIR_PREFIXES: suffixed dirs skipped
# ───────────────────────────────────────────────────────────────────
python3 - <<'PY' || { fail "recon_slicer SKIP_DIR_PREFIXES suffix coverage"; exit 1; }
import sys
sys.path.insert(0, "lib")
from recon_slicer import _is_skipped_dir, SKIP_DIR_PREFIXES

# Helper covers literal sanitizer names and suffixed variants.
for san in ("asan", "ubsan", "msan", "tsan"):
    for variant in (f"build-{san}", f"build-{san}-abc1234"):
        assert _is_skipped_dir(variant), f"recon_slicer did not skip {variant!r}"

# SKIP_DIR_PREFIXES tuple is the sole source of suffix-aware exclusions —
# guard against accidental tuple shrinkage.
for expected in ("build-asan", "build-ubsan", "build-msan", "build-tsan"):
    assert expected in SKIP_DIR_PREFIXES, f"SKIP_DIR_PREFIXES missing {expected}"

# Source dirs not skipped.
for ok in ("src", "include", "parser"):
    assert not _is_skipped_dir(ok)

print("OK")
PY
pass "recon_slicer.SKIP_DIR_PREFIXES covers AUDIT_BUILD_SUFFIX variants"

# ───────────────────────────────────────────────────────────────────
# lib/target_config.py seed_toml respects AUDIT_BUILD_SUFFIX
# ───────────────────────────────────────────────────────────────────
python3 - <<PY || { fail "target_config.seed_toml suffix coverage"; exit 1; }
import os, sys, tempfile, pathlib
os.environ["AUDIT_BUILD_SUFFIX"] = "-img42"
sys.path.insert(0, "lib")
import importlib, target_config
importlib.reload(target_config)
from target_config import seed_toml

root = pathlib.Path("${TEST_TMPDIR}/seed-target")
root.mkdir(parents=True, exist_ok=True)
out = root.parent / "seed-target.toml"
seed_toml(root, out)
text = out.read_text()
assert "build-asan-img42" in text, f"seeded toml missing suffixed asan dir:\\n{text}"
assert "build-ubsan-img42" in text or "ubsan_bin" not in text, "ubsan path missing suffix"
print("OK")
PY
pass "target_config.seed_toml emits AUDIT_BUILD_SUFFIX-aware paths"
unset AUDIT_BUILD_SUFFIX

# ───────────────────────────────────────────────────────────────────
# bin/export-repro strips suffixed sanitizer build prefixes when
# target.toml was generated inside a container (paths look like
# "build-asan-<image-id>/foo" instead of plain "build-asan/foo").
# ───────────────────────────────────────────────────────────────────
python3 - <<'PY' || { fail "export-repro suffix prefix-strip coverage"; exit 1; }
import sys, importlib.machinery, importlib.util, pathlib
sys.path.insert(0, "lib")
loader = importlib.machinery.SourceFileLoader("export_repro_mod", "bin/export-repro")
spec = importlib.util.spec_from_loader("export_repro_mod", loader)
er = importlib.util.module_from_spec(spec)
spec.loader.exec_module(er)

# _strip_sanitizer_build_prefix should peel "build-<san>(-<suffix>)?/" off.
cases = [
    ("build-asan/foo",            "asan",  "foo"),
    ("build-asan-img42/foo",      "asan",  "foo"),
    ("build-ubsan/lib/libfoo.a",  "ubsan", "lib/libfoo.a"),
    ("build-ubsan-abc/lib/foo.a", "ubsan", "lib/foo.a"),
    ("build-msan-x9/bin/p",       "msan",  "bin/p"),
    ("build-tsan-y2/bin/q",       "tsan",  "bin/q"),
]
for path, san, expected in cases:
    got = er._strip_sanitizer_build_prefix(path, san)
    assert got == expected, f"_strip_sanitizer_build_prefix({path!r}, {san!r}) = {got!r}, expected {expected!r}"

# emit_include_args rewrites suffixed build-*/include to the
# reproduce.sh fresh build dir as well.
out = er.emit_include_args(["include", "build-asan-img7/include"])
assert '"$build"/include' in out, f"emit_include_args didn't rewrite suffixed include: {out}"

print("OK")
PY
pass "bin/export-repro strips AUDIT_BUILD_SUFFIX variants from target.toml paths"

# ───────────────────────────────────────────────────────────────────
# bin/audit-container-shell forwards a host-set AUDIT_BUILD_SUFFIX
# into the container env (visible in --dry-run run-command output)
# ───────────────────────────────────────────────────────────────────
ROOT_FAKE="$TEST_TMPDIR/host-root"
HOST_HOME_FAKE="$TEST_TMPDIR/host-home"
mkdir -p "$ROOT_FAKE" "$HOST_HOME_FAKE"

_CURRENT_TEST="audit-container-shell forwards host AUDIT_BUILD_SUFFIX"
out=$(
  AUDIT_ROOT="$ROOT_FAKE" \
  HOME="$HOST_HOME_FAKE" \
  AUDIT_BUILD_SUFFIX="-hosttoken" \
    "$SCRIPT_ROOT/bin/audit-container-shell" --dry-run --rebuild 2>&1
)
rc=$?
if [ "$rc" -eq 0 ] && \
   grep -q -- "-e AUDIT_BUILD_SUFFIX=-hosttoken" <<<"$out" && \
   grep -q "Forwarding AUDIT_BUILD_SUFFIX=-hosttoken" <<<"$out"; then
  pass
else
  fail "$_CURRENT_TEST" "$out"
fi

_CURRENT_TEST="audit-container-shell help documents AUDIT_BUILD_SUFFIX"
out=$(AUDIT_ROOT="$ROOT_FAKE" HOME="$HOST_HOME_FAKE" \
  "$SCRIPT_ROOT/bin/audit-container-shell" --help 2>&1)
if grep -q "AUDIT_BUILD_SUFFIX" <<<"$out"; then
  pass
else
  fail "$_CURRENT_TEST" "AUDIT_BUILD_SUFFIX missing from --help: $out"
fi

# ───────────────────────────────────────────────────────────────────
# Firefox ff-bsan skill DOES NOT carry AUDIT_BUILD_SUFFIX (deliberate
# scope decision — the build script doesn't need to know).
# ───────────────────────────────────────────────────────────────────
_CURRENT_TEST="ff-bsan skill stays suffix-free"
if grep -rq "AUDIT_BUILD_SUFFIX" "$SCRIPT_ROOT/.agents/skills/ff-bsan" 2>/dev/null; then
  fail "$_CURRENT_TEST" "ff-bsan unexpectedly mentions AUDIT_BUILD_SUFFIX"
else
  pass
fi

teardown_test_env
summary
