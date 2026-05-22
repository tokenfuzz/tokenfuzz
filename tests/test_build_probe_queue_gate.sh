#!/usr/bin/env bash
# Integration test for the workqueue stub-TU gate.
# Verifies that when a features.json manifest lists a TU as a stub,
# work cards on that TU are marked `blocked` and excluded from claiming.
set -o pipefail
source "$(dirname "$0")/helpers.sh"
setup_test_env

# ── Fixture: synthetic work-cards.jsonl + features.json ────────────

mkdir -p "$RESULTS_DIR/state"

cat > "$RESULTS_DIR/work-cards.jsonl" <<'JSONL'
{"id":"CARD-real","kind":"feature","file":"lib/url.c","subsystem":"core","strategy":"S5","reasons":["pointer-arith"],"description":"real TU card"}
{"id":"CARD-stub-openssl","kind":"feature","file":"lib/vtls/openssl.c","subsystem":"vtls","strategy":"S5","reasons":["tls-state"],"description":"stub-TU card on openssl"}
{"id":"CARD-stub-libssh","kind":"feature","file":"lib/vssh/libssh.c","subsystem":"vssh","strategy":"S5","reasons":["protocol-state"],"description":"stub-TU card on libssh"}
JSONL

cat > "$RESULTS_DIR/state/features.json" <<'JSON'
{
  "schema_version": 1,
  "probed_at": "2026-05-24T00:00:00Z",
  "target_root": "/fake",
  "build_dir": "/fake/build-asan",
  "sanitizer": "asan",
  "binary": {"path": "", "version_output": "", "help_output": "", "features": [], "protocols": []},
  "configure_summary": "",
  "stub_tus": ["lib/vtls/openssl.c", "lib/vssh/libssh.c"],
  "compiled_tus": ["lib/url.c"],
  "probed_object_count": 3,
  "notes": []
}
JSON

# ── Test 1: mark_stub_tu_cards_blocked writes blocked claims ───────

gate_out=$(SCRIPT_ROOT="$SCRIPT_ROOT" RESULTS_DIR="$RESULTS_DIR" \
  TARGET_ROOT="$TARGET_ROOT" TARGET_SLUG="$TARGET_SLUG" \
  TARGET_REPO_TYPE="none" \
  PYTHONPATH="$SCRIPT_ROOT/lib" python3 - <<'PY'
import os, sys
from pathlib import Path
from workqueue import Context, mark_stub_tu_cards_blocked
ctx = Context(
    script_root=Path(os.environ["SCRIPT_ROOT"]).resolve(),
    target_root=Path(os.environ["TARGET_ROOT"]).resolve(),
    target_slug=os.environ["TARGET_SLUG"],
    results_dir=Path(os.environ["RESULTS_DIR"]).resolve(),
    repo_type="none",
)
n = mark_stub_tu_cards_blocked(ctx)
print(f"blocked={n}")
PY
)
assert_match 'blocked=2' "$gate_out" "mark_stub_tu_cards_blocked: blocks 2 stub-TU cards"

# Idempotency: a second call should not double-block.
gate_out2=$(SCRIPT_ROOT="$SCRIPT_ROOT" RESULTS_DIR="$RESULTS_DIR" \
  TARGET_ROOT="$TARGET_ROOT" TARGET_SLUG="$TARGET_SLUG" \
  TARGET_REPO_TYPE="none" \
  PYTHONPATH="$SCRIPT_ROOT/lib" python3 - <<'PY'
import os
from pathlib import Path
from workqueue import Context, mark_stub_tu_cards_blocked
ctx = Context(
    script_root=Path(os.environ["SCRIPT_ROOT"]).resolve(),
    target_root=Path(os.environ["TARGET_ROOT"]).resolve(),
    target_slug=os.environ["TARGET_SLUG"],
    results_dir=Path(os.environ["RESULTS_DIR"]).resolve(),
    repo_type="none",
)
n = mark_stub_tu_cards_blocked(ctx)
print(f"second_call_blocked={n}")
PY
)
assert_match 'second_call_blocked=0' "$gate_out2" "mark_stub_tu_cards_blocked: idempotent (no double-block)"

# ── Test 2: claims.jsonl has correct shape ─────────────────────────

assert_file_exists "$RESULTS_DIR/state/claims.jsonl" "claims.jsonl: created"
assert_file_contains "$RESULTS_DIR/state/claims.jsonl" 'CARD-stub-openssl' "claims.jsonl: contains openssl card id"
assert_file_contains "$RESULTS_DIR/state/claims.jsonl" 'CARD-stub-libssh' "claims.jsonl: contains libssh card id"
assert_file_contains "$RESULTS_DIR/state/claims.jsonl" '"status": "blocked"' "claims.jsonl: status=blocked"
assert_file_contains "$RESULTS_DIR/state/claims.jsonl" '"source": "build-probe-stub-tu"' "claims.jsonl: source=build-probe-stub-tu"
assert_file_not_contains "$RESULTS_DIR/state/claims.jsonl" 'CARD-real' "claims.jsonl: real-TU card not blocked"

# ── Test 3: explain_queue reports tu-not-compiled reason ───────────

explain_out=$(SCRIPT_ROOT="$SCRIPT_ROOT" RESULTS_DIR="$RESULTS_DIR" \
  TARGET_ROOT="$TARGET_ROOT" TARGET_SLUG="$TARGET_SLUG" \
  TARGET_REPO_TYPE="none" \
  PYTHONPATH="$SCRIPT_ROOT/lib" python3 - <<'PY'
import os, json
from pathlib import Path
from workqueue import Context, explain_queue
ctx = Context(
    script_root=Path(os.environ["SCRIPT_ROOT"]).resolve(),
    target_root=Path(os.environ["TARGET_ROOT"]).resolve(),
    target_slug=os.environ["TARGET_SLUG"],
    results_dir=Path(os.environ["RESULTS_DIR"]).resolve(),
    repo_type="none",
)
rows = explain_queue(ctx, agent_modes=["generic"])
for r in rows:
    print(f"{r['id']}={r['reason']}")
PY
)
assert_match 'CARD-stub-openssl=tu-not-compiled' "$explain_out" "explain_queue: openssl card reason=tu-not-compiled"
assert_match 'CARD-stub-libssh=tu-not-compiled' "$explain_out" "explain_queue: libssh card reason=tu-not-compiled"
assert_match 'CARD-real=' "$explain_out" "explain_queue: real card present in output"
# real card should NOT be tu-not-compiled
real_reason=$(printf '%s\n' "$explain_out" | grep '^CARD-real=' | head -1)
assert_not_match 'tu-not-compiled' "$real_reason" "explain_queue: real-TU card is not gated"

# ── Test 4: fail-open without features.json ─────────────────────────

empty_results="$TEST_TMPDIR/empty-results"
mkdir -p "$empty_results/state"
cp "$RESULTS_DIR/work-cards.jsonl" "$empty_results/work-cards.jsonl"

failopen_out=$(SCRIPT_ROOT="$SCRIPT_ROOT" RESULTS_DIR="$empty_results" \
  TARGET_ROOT="$TARGET_ROOT" TARGET_SLUG="$TARGET_SLUG" \
  TARGET_REPO_TYPE="none" \
  PYTHONPATH="$SCRIPT_ROOT/lib" python3 - <<'PY'
import os
from pathlib import Path
from workqueue import Context, mark_stub_tu_cards_blocked
ctx = Context(
    script_root=Path(os.environ["SCRIPT_ROOT"]).resolve(),
    target_root=Path(os.environ["TARGET_ROOT"]).resolve(),
    target_slug=os.environ["TARGET_SLUG"],
    results_dir=Path(os.environ["RESULTS_DIR"]).resolve(),
    repo_type="none",
)
n = mark_stub_tu_cards_blocked(ctx)
print(f"no_manifest_blocked={n}")
PY
)
assert_match 'no_manifest_blocked=0' "$failopen_out" "fail-open: no features.json → 0 blocks (does not crash)"

teardown_test_env
summary
