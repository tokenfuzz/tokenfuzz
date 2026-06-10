#!/usr/bin/env bash
# tests/test_portability_lint.sh — production shell scripts must not depend
# on GNU-only tooling.
#
# macOS ships neither coreutils `timeout` nor a `realpath` that understands
# `--relative-to`, and docs/getting-started/prerequisites.md explicitly
# promises GNU coreutils is NOT required. The harness already has portable
# substitutes: audit_timeout_run (lib/timeout.sh) and python3 os.path.
# This lint keeps bin/ and lib/ from regressing to the GNU-only forms.

set -uo pipefail

TESTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$TESTS_DIR/helpers.sh"

setup_test_env

cd "$SCRIPT_ROOT" || exit 1

# A bare `timeout`/`gtimeout` invocation at a command position — line start
# (after indentation) or right after a pipe. Deliberately does NOT match
# `--timeout` flags, `$TIMEOUT_SECS` variables, or the `audit_timeout_run`
# shim, since none of those are the GNU `timeout` binary.
timeout_re='(^|\|)[[:space:]]*g?timeout[[:space:]]'
realpath_re='realpath[[:space:]]+--relative-to'
readlink_f_re='readlink[[:space:]]+-f([[:space:]]|$)'
find_printf_re='find[^\n]*[[:space:]]-printf[[:space:]]'
stat_fallback_re="stat[[:space:]]+-f[[:space:]]+%[mz][^|;]*[|][|][[:space:]]*stat[[:space:]]+-c[[:space:]]+%[Ys]"

# ── The lint itself ────────────────────────────────────────────────
timeout_hits=$(rg -n "$timeout_re" bin lib 2>/dev/null || true)
assert_eq "" "$timeout_hits" \
  "no bare GNU timeout/gtimeout in bin/ or lib/ — use audit_timeout_run"

realpath_hits=$(rg -n "$realpath_re" bin lib 2>/dev/null || true)
assert_eq "" "$realpath_hits" \
  "no GNU 'realpath --relative-to' in bin/ or lib/"

readlink_f_hits=$(rg -n "$readlink_f_re" bin lib 2>/dev/null || true)
assert_eq "" "$readlink_f_hits" \
  "no GNU 'readlink -f' in bin/ or lib/; use audit_realpath"

find_printf_hits=$(rg -n "$find_printf_re" bin lib 2>/dev/null || true)
assert_eq "" "$find_printf_hits" \
  "no GNU/BSD-incompatible find -printf in bin/ or lib/"

stat_fallback_hits=$(rg -n "$stat_fallback_re" bin lib 2>/dev/null || true)
assert_eq "" "$stat_fallback_hits" \
  "no open-coded 'stat -f ... || stat -c ...' in bin/ or lib — use lib/platform.sh"

# ── Self-check: the patterns must actually fire ────────────────────
# A silently-broken regex would make the lint above pass forever. Run the
# exact patterns against a known-bad sample and confirm they catch the bad
# forms while leaving the portable shim alone.
probe="$TEST_TMPDIR/portability-probe.sh"
printf '%s\n' \
  '        timeout 30 claude -p x' \
  '        audit_timeout_run 30 claude -p x' \
  '  printf x | gtimeout 5 agy' \
  '    rel=$(realpath --relative-to="$A" "$B")' \
  '    abs=$(readlink -f "$d")' \
  '    find "$d" -maxdepth 1 -type f -printf "%f\n"' \
  '    stat -f %m "$f" 2>/dev/null || stat -c %Y "$f"' \
  > "$probe"

probe_timeout=$(rg -n "$timeout_re" "$probe" 2>/dev/null || true)
assert_match "timeout 30 claude" "$probe_timeout" "lint detects a bare timeout call"
assert_match "gtimeout 5 agy"    "$probe_timeout" "lint detects gtimeout after a pipe"
assert_not_match "audit_timeout_run" "$probe_timeout" \
  "lint ignores the portable audit_timeout_run shim"

probe_realpath=$(rg -n "$realpath_re" "$probe" 2>/dev/null || true)
assert_match "realpath --relative-to" "$probe_realpath" \
  "lint detects realpath --relative-to"

probe_readlink_f=$(rg -n "$readlink_f_re" "$probe" 2>/dev/null || true)
assert_match "readlink -f" "$probe_readlink_f" \
  "lint detects readlink -f"

probe_find_printf=$(rg -n "$find_printf_re" "$probe" 2>/dev/null || true)
assert_match "find.*-printf" "$probe_find_printf" \
  "lint detects find -printf"

probe_stat_fallback=$(rg -n "$stat_fallback_re" "$probe" 2>/dev/null || true)
assert_match "stat -f %m" "$probe_stat_fallback" \
  "lint detects open-coded BSD/GNU stat fallback"

# ── Behavioral: the two fixed scripts ──────────────────────────────
# Both must source the portable timeout helper so audit_timeout_run is
# defined when the backend-dispatch case statement runs.
assert_file_contains "$SCRIPT_ROOT/bin/audit-recon" "timeout.sh" \
  "bin/audit-recon sources lib/timeout.sh"
assert_file_contains "$SCRIPT_ROOT/bin/validate-finding" "lib/timeout.sh" \
  "bin/validate-finding sources lib/timeout.sh"

# They must still parse after the edits.
bash -n "$SCRIPT_ROOT/bin/audit-recon"
assert_eq 0 $? "bin/audit-recon parses cleanly"
bash -n "$SCRIPT_ROOT/bin/validate-finding"
assert_eq 0 $? "bin/validate-finding parses cleanly"

# ── Behavioral: the portable realpath replacement ──────────────────
# audit-recon derives a slice's path relative to the target root via
# python3 instead of `realpath --relative-to`. Confirm that mechanism
# yields the same answer GNU realpath would, with no GNU dependency.
rel=$(python3 -c 'import os,sys; print(os.path.relpath(sys.argv[1], sys.argv[2]))' \
  /tmp/proj/libxml2/parser /tmp/proj/libxml2 2>/dev/null)
assert_eq "parser" "$rel" "python relpath yields a correct relative path"

rel_nested=$(python3 -c 'import os,sys; print(os.path.relpath(sys.argv[1], sys.argv[2]))' \
  /tmp/proj/src/dom/media /tmp/proj 2>/dev/null)
assert_eq "src/dom/media" "$rel_nested" "python relpath handles nested directories"

teardown_test_env
summary
