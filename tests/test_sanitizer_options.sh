#!/usr/bin/env bash
# tests/test_sanitizer_options.sh — lib/sanitizer_options.conf is the single
# source of truth for sanitizer *_OPTIONS strings. This suite verifies:
#   1. the shell accessor sanitizer_options_for() returns each conf row,
#   2. an undefined mode falls back to that sanitizer's `full` row,
#   3. bin/export-repro's Python reader sees the identical table,
#   4. no bin/run-* runner re-hardcodes an option string (drift guard).
set -o pipefail
source "$(dirname "$0")/helpers.sh"
setup_test_env
source "$SCRIPT_ROOT/lib/sanitizer.sh"

CONF="$SCRIPT_ROOT/lib/sanitizer_options.conf"
assert_file_exists "$CONF" "sanitizer_options.conf exists"

# ── 1. sanitizer_options_for() returns every declared conf row ──────
rows=0
while read -r f_san f_mode f_opts; do
  case "$f_san" in ''|'#'*) continue ;; esac
  rows=$((rows + 1))
  assert_eq "$f_opts" "$(sanitizer_options_for "$f_san" "$f_mode")" \
    "sanitizer_options_for $f_san $f_mode matches conf row"
done < "$CONF"
[ "$rows" -ge 18 ] && pass "conf has the full sanitizer/mode matrix ($rows rows)" \
  || fail "conf row count" "expected >=18, got $rows"

# ── 2. Undefined mode falls back to the sanitizer's `full` row ──────
assert_eq "$(sanitizer_options_for ubsan full)" "$(sanitizer_options_for ubsan xpcshell)" \
  "ubsan: undefined xpcshell mode falls back to full"
assert_eq "$(sanitizer_options_for msan full)" "$(sanitizer_options_for msan minimal)" \
  "msan: undefined minimal mode falls back to full"
assert_eq "$(sanitizer_options_for tsan full)" "$(sanitizer_options_for tsan xpcshell)" \
  "tsan: undefined xpcshell mode falls back to full"

# halt_on_error polarity is uniform: 1 for full, 0 for fuzz, across all four.
for san in asan ubsan msan tsan; do
  assert_match "halt_on_error=1" "$(sanitizer_options_for "$san" full)" \
    "$san full sets halt_on_error=1"
  assert_match "halt_on_error=0" "$(sanitizer_options_for "$san" fuzz)" \
    "$san fuzz sets halt_on_error=0"
done

# ── 3. export-repro's Python reader sees the identical table ────────
# Dump the conf as `san:mode=opts` from the shell side and from
# bin/export-repro's _load_sanitizer_mode_options(); the sorted views
# must be byte-identical.
shell_view="$(mktemp "$TEST_TMPDIR/shellview-XXXXXX")"
py_view="$(mktemp "$TEST_TMPDIR/pyview-XXXXXX")"
while read -r f_san f_mode f_opts; do
  case "$f_san" in ''|'#'*) continue ;; esac
  printf '%s:%s=%s\n' "$f_san" "$f_mode" "$f_opts"
done < "$CONF" | LC_ALL=C sort > "$shell_view"

python3 - "$SCRIPT_ROOT" > "$py_view" <<'PY'
import importlib.machinery, importlib.util, sys
from pathlib import Path
root = Path(sys.argv[1])
loader = importlib.machinery.SourceFileLoader("er", str(root / "bin" / "export-repro"))
spec = importlib.util.spec_from_loader("er", loader)
er = importlib.util.module_from_spec(spec)
loader.exec_module(er)
rows = []
for san, modes in er.SANITIZER_MODE_OPTIONS.items():
    for mode, opts in modes.items():
        rows.append(f"{san}:{mode}={opts}")
print("\n".join(sorted(rows)))
PY

if diff -u "$shell_view" "$py_view" > "$TEST_TMPDIR/view.diff" 2>&1; then
  pass "shell and export-repro readers agree on the option table"
else
  fail "shell and export-repro readers agree on the option table" \
    "$(cat "$TEST_TMPDIR/view.diff")"
fi

# ── 4. Drift guard: no bin/run-* runner re-hardcodes an option string ─
# After consolidation every *_OPTS_* variable is assigned from a command
# substitution ("$(...)"); a literal value would begin with an option
# name (lowercase letter), which this pattern catches. Comments are immune
# because the pattern anchors on the `VAR="` assignment form.
for runner in run-asan run-ubsan run-msan run-tsan; do
  hits="$(grep -nE '(ASAN|UBSAN|MSAN|TSAN)_OPTS_[A-Z_]+="[^"$]' \
            "$SCRIPT_ROOT/bin/$runner" || true)"
  if [ -z "$hits" ]; then
    pass "bin/$runner does not re-hardcode sanitizer option strings"
  else
    fail "bin/$runner does not re-hardcode sanitizer option strings" "$hits"
  fi
done

# ── 5. Generic-probe RSS ceiling — host-protection cap for probe runs ──
# sanitizer_generic_rss_limit_mb echoes the MB ceiling the generic runners hand
# to audit_timeout_run_rss. The watchdog is allocator-agnostic, so the cap is
# one host policy independent of the sanitizer (unlike the inert ASan flag it
# replaces). Default 5120; PROBE_RSS_LIMIT_MB overrides; 0/empty disables.
assert_eq "5120" "$(sanitizer_generic_rss_limit_mb)" \
  "default generic RSS ceiling is 5120 MB"
assert_eq "2048" "$(PROBE_RSS_LIMIT_MB=2048; sanitizer_generic_rss_limit_mb)" \
  "PROBE_RSS_LIMIT_MB overrides the per-host ceiling"
assert_eq "" "$(PROBE_RSS_LIMIT_MB=0; sanitizer_generic_rss_limit_mb)" \
  "PROBE_RSS_LIMIT_MB=0 disables the ceiling (empty → uncapped)"
assert_eq "" "$(PROBE_RSS_LIMIT_MB=nonsense; sanitizer_generic_rss_limit_mb)" \
  "non-numeric PROBE_RSS_LIMIT_MB → uncapped (empty)"

summary
