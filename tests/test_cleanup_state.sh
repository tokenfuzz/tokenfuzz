#!/usr/bin/env bash
# tests/test_cleanup_state.sh
#
# Production-grade coverage for bin/cleanup_state — the helper that wipes
# transient audit state inside output/<target>/<backend>/results/ while
# preserving every found/rejected/needs-review crash/finding and learned
# bug-finding signal that should survive between audit iterations.
#
# Each section builds an isolated mock output tree under TEST_TMPDIR/out
# and asserts file-by-file that the right things were preserved or
# removed. Mock trees are torn down between sections so a leaked file
# in one cannot mask a regression in another.

set -o pipefail
source "$(dirname "$0")/helpers.sh"
setup_test_env

CLEANUP="$SCRIPT_ROOT/bin/cleanup_state"

# ── Mock-tree helper ─────────────────────────────────────────────
# Builds a fully-populated results/ directory with every file kind the
# real audit produces, plus the six dirs that must survive cleanup.
mk_mock_results() {
    local root="$1" target="$2" backend="$3"
    local r="$root/$target/$backend/results"
    mkdir -p "$r" "$root/$target/$backend/logs"

    # Preserved siblings (must survive). Each gets an entry inside so we
    # can verify the directory contents are intact, not just the dir.
    # findings/ is unified — vacuous candidates live there too, flagged
    # inline with .needs-attention.
    mkdir -p "$r/crashes/CRASH-001-1" \
             "$r/crashes-rejected/CRASH-002-1" \
             "$r/crashes-needs-review/CRASH-003-1" \
             "$r/findings/FIND-001" \
             "$r/findings/FIND-002-flagged" \
             "$r/findings-rejected/FIND-003" \
             "$r/corpus/foo" \
             "$r/coverage" \
             "$r/fuzz-crashes/FuzzerA"
    echo "asan trace" > "$r/crashes/CRASH-001-1/asan.txt"
    echo "rejected"    > "$r/crashes-rejected/CRASH-002-1/.autodiscard"
    echo "review"      > "$r/crashes-needs-review/CRASH-003-1/.needs-review"
    echo "finding"     > "$r/findings/FIND-001/description.md"
    echo "flagged"     > "$r/findings/FIND-002-flagged/.needs-attention"
    echo "rejected"    > "$r/findings-rejected/FIND-003/description.md"
    echo "promoted"    > "$r/corpus/foo/seed.input"
    echo "edges"       > "$r/coverage/edges-agent-1.journal"
    echo "raw crash"   > "$r/fuzz-crashes/FuzzerA/crash-abc123"
    echo "# leads"     > "$r/fuzz-leads.md"
    echo "# guards"    > "$r/guards-db.md"
    echo "# roi"       > "$r/strategy-roi.md"

    # Transient state (must be wiped). Cover every kind we see in real
    # output dirs: scratch-N, state/, jsonl, .session_seed_*,
    # markdown state, dotfile counters, hidden archive dir.
    mkdir -p "$r/scratch-1" "$r/scratch-2" "$r/scratch-3" \
             "$r/state" "$r/.state_archive"
    printf 'tc bytes' > "$r/scratch-1/tc.input"
    echo  "asan log"  > "$r/scratch-1/tc.asan.txt"
    echo "{}"         > "$r/state/claims.jsonl"
    echo "{}"         > "$r/state/hypotheses.jsonl"
    echo "{}"         > "$r/state/runs.jsonl"
    echo "archived"   > "$r/.state_archive/AUDIT_STATE-1.exhausted.20260101_010101.md"
    echo "{}"         > "$r/work-cards.jsonl"
    echo "{}"         > "$r/patch-cards.jsonl"
    echo "{}"         > "$r/queue-exhaustion-report.jsonl"
    echo "# state"    > "$r/AUDIT_STATE.md"
    echo "# state-1"  > "$r/AUDIT_STATE-1.md"
    echo "tried"      > "$r/tried-inputs-1.log"
    echo "S1"         > "$r/.agent_strategy_1"
    echo "0"          > "$r/.agent_strategy_streak_1"
    echo "0"          > "$r/.subsystem_tenure_1"
    echo "0"          > "$r/.subsystem_dry_streak_src_lib"
    echo "guard"      > "$r/.guard_chain_src_lib"
    echo "fb"         > "$r/.quality_feedback_1"
    echo "1"          > "$r/asan-run-counter-1"
    echo "RESULTS_DIR=$r" > "$r/.session-env"
    # Derived per-backend report (regenerates on next iteration; safe to wipe).
    echo "<html>" > "$r/CLUSTERS.html"
    echo "# clusters" > "$r/CLUSTERS.md"

    # Top-level metadata that lives OUTSIDE results/. Must not be touched.
    echo "[meta]"  > "$root/$target/target.toml"
    echo "<html>"  > "$root/$target/CRASH-CLUSTERS.html"
    echo "# crash" > "$root/$target/CRASH-CLUSTERS.md"
    echo "<html>"  > "$root/$target/FINDING-CLUSTERS.html"
    echo "# find"  > "$root/$target/FINDING-CLUSTERS.md"
    # logs/ is bin/cleanup_logs's responsibility — must not be touched here.
    echo "log"     > "$root/$target/$backend/logs/index.log"
}

# Sentinel paths every assertion checks. Uses indirection so all
# sections can re-use the same fixture builder.
preserved_paths() {
    local r="$1"
    cat <<EOF
$r/crashes/CRASH-001-1/asan.txt
$r/crashes-rejected/CRASH-002-1/.autodiscard
$r/crashes-needs-review/CRASH-003-1/.needs-review
$r/findings/FIND-001/description.md
$r/findings/FIND-002-flagged/.needs-attention
$r/findings-rejected/FIND-003/description.md
$r/corpus/foo/seed.input
$r/coverage/edges-agent-1.journal
$r/fuzz-crashes/FuzzerA/crash-abc123
$r/fuzz-leads.md
$r/guards-db.md
$r/strategy-roi.md
EOF
}

removed_paths() {
    local r="$1"
    cat <<EOF
$r/scratch-1/tc.input
$r/scratch-1/tc.asan.txt
$r/scratch-2
$r/state/claims.jsonl
$r/state/hypotheses.jsonl
$r/state/runs.jsonl
$r/.state_archive/AUDIT_STATE-1.exhausted.20260101_010101.md
$r/work-cards.jsonl
$r/patch-cards.jsonl
$r/queue-exhaustion-report.jsonl
$r/AUDIT_STATE.md
$r/AUDIT_STATE-1.md
$r/tried-inputs-1.log
$r/.agent_strategy_1
$r/.agent_strategy_streak_1
$r/.subsystem_tenure_1
$r/.subsystem_dry_streak_src_lib
$r/.guard_chain_src_lib
$r/.quality_feedback_1
$r/asan-run-counter-1
$r/.session-env
$r/CLUSTERS.html
$r/CLUSTERS.md
EOF
}

assert_paths_exist() {
    local label="$1"; shift
    local p
    while IFS= read -r p; do
        [ -z "$p" ] && continue
        if [ -e "$p" ]; then
            pass "$label: $(basename "$p") preserved"
        else
            fail "$label: $(basename "$p") preserved" "missing: $p"
        fi
    done
}

assert_paths_gone() {
    local label="$1"; shift
    local p
    while IFS= read -r p; do
        [ -z "$p" ] && continue
        if [ ! -e "$p" ]; then
            pass "$label: $(basename "$p") removed"
        else
            fail "$label: $(basename "$p") removed" "still present: $p"
        fi
    done
}

# ── Section 1: default cleanup preserves the right dirs ─────────────
sec1="$TEST_TMPDIR/out1"
mk_mock_results "$sec1" libxml2 codex
mk_mock_results "$sec1" json    codex
mk_mock_results "$sec1" curl    oss

run_out=$("$CLEANUP" --output-root "$sec1" 2>&1)
rc=$?
assert_eq 0 "$rc" "default: clean exits 0 on success"
assert_match 'cleaned=3' "$run_out" "default: reports three cleaned dirs"
assert_match 'failed=0'  "$run_out" "default: zero failures"

for t in libxml2 json; do
    r="$sec1/$t/codex/results"
    preserved_paths "$r" | assert_paths_exist "default $t"
    removed_paths   "$r" | assert_paths_gone  "default $t"
done
r="$sec1/curl/oss/results"
preserved_paths "$r" | assert_paths_exist "default curl oss"
removed_paths   "$r" | assert_paths_gone  "default curl oss"

# results/ itself is kept (so the next audit doesn't have to mkdir).
assert_dir_exists "$sec1/libxml2/codex/results" "default: results/ dir kept"

# Cross-cutting preservation: top-level metadata + logs/ untouched.
assert_file_exists "$sec1/libxml2/target.toml"           "default: target.toml untouched"
assert_file_exists "$sec1/libxml2/CRASH-CLUSTERS.md"     "default: top-level CRASH-CLUSTERS.md untouched"
assert_file_exists "$sec1/libxml2/FINDING-CLUSTERS.md"   "default: top-level FINDING-CLUSTERS.md untouched"
assert_file_exists "$sec1/libxml2/codex/logs/index.log"  "default: logs/ untouched (separate tool)"

# ── Section 2: --dry-run is non-destructive ─────────────────────────
sec2="$TEST_TMPDIR/out2"
mk_mock_results "$sec2" libxml2 codex
dry_out=$("$CLEANUP" --output-root "$sec2" --dry-run 2>&1)
rc=$?
assert_eq 0 "$rc" "dry-run: exits 0"
assert_match 'would remove' "$dry_out" "dry-run: reports what would happen"

# Both transient and preserved files are still present.
preserved_paths "$sec2/libxml2/codex/results" | assert_paths_exist "dry-run: preserved"
# All "to be removed" paths are still on disk.
preserved_paths_no_check=0
while IFS= read -r p; do
    [ -z "$p" ] && continue
    if [ -e "$p" ]; then
        pass "dry-run: $(basename "$p") still present"
    else
        fail "dry-run: $(basename "$p") still present" "unexpectedly removed: $p"
    fi
done < <(removed_paths "$sec2/libxml2/codex/results")

# ── Section 3: --target filter only touches that target ─────────────
sec3="$TEST_TMPDIR/out3"
mk_mock_results "$sec3" libxml2 codex
mk_mock_results "$sec3" json    codex
"$CLEANUP" --output-root "$sec3" --target libxml2 --quiet
# libxml2 cleaned.
assert_file_not_exists "$sec3/libxml2/codex/results/work-cards.jsonl" \
    "target filter: libxml2 transient state removed"
# json untouched.
assert_file_exists "$sec3/json/codex/results/work-cards.jsonl" \
    "target filter: json transient state untouched"
assert_file_exists "$sec3/json/codex/results/state/claims.jsonl" \
    "target filter: json state/ untouched"

# ── Section 4: --backends filter only touches that backend ──────────
sec4="$TEST_TMPDIR/out4"
mk_mock_results "$sec4" libxml2 codex
mk_mock_results "$sec4" libxml2 claude
"$CLEANUP" --output-root "$sec4" --backends codex --quiet
assert_file_not_exists "$sec4/libxml2/codex/results/work-cards.jsonl" \
    "backend filter: codex cleaned"
assert_file_exists "$sec4/libxml2/claude/results/work-cards.jsonl" \
    "backend filter: claude untouched"

# --backend is the singular alias used by the docs.
sec4a="$TEST_TMPDIR/out4a"
mk_mock_results "$sec4a" libxml2 codex
mk_mock_results "$sec4a" libxml2 claude
"$CLEANUP" --output-root "$sec4a" --backend codex --quiet
assert_file_not_exists "$sec4a/libxml2/codex/results/work-cards.jsonl" \
    "backend alias: codex cleaned"
assert_file_exists "$sec4a/libxml2/claude/results/work-cards.jsonl" \
    "backend alias: claude untouched"

# ── Section 5: --keep adds to default preserve list ─────────────────
sec5="$TEST_TMPDIR/out5"
mk_mock_results "$sec5" libxml2 codex
"$CLEANUP" --output-root "$sec5" --keep state --quiet
# corpus is default-preserved, and --keep state preserves structured state.
assert_file_exists "$sec5/libxml2/codex/results/corpus/foo/seed.input" \
    "--keep state: default corpus/ survives"
assert_file_exists "$sec5/libxml2/codex/results/state/claims.jsonl" \
    "--keep state: state/ survives"
# But scratch-N and the rest still wiped.
assert_file_not_exists "$sec5/libxml2/codex/results/work-cards.jsonl" \
    "--keep state: other transient state still removed"
# Defaults still preserved.
assert_file_exists "$sec5/libxml2/codex/results/crashes/CRASH-001-1/asan.txt" \
    "--keep state: default preserves still apply"

# ── Section 6: --keep-only replaces the default preserve list ───────
sec6="$TEST_TMPDIR/out6"
mk_mock_results "$sec6" libxml2 codex
"$CLEANUP" --output-root "$sec6" --keep-only crashes --quiet
# Only crashes/ survives.
assert_dir_exists "$sec6/libxml2/codex/results/crashes" \
    "--keep-only: crashes/ survives"
# crashes-rejected gone (was a default).
assert_dir_not_exists "$sec6/libxml2/codex/results/crashes-rejected" \
    "--keep-only: defaults dropped (crashes-rejected gone)"
assert_dir_not_exists "$sec6/libxml2/codex/results/findings" \
    "--keep-only: defaults dropped (findings gone)"
assert_dir_not_exists "$sec6/libxml2/codex/results/findings-rejected" \
    "--keep-only: defaults dropped (findings-rejected gone)"

# ── Section 7: empty preserve list is rejected ──────────────────────
sec7="$TEST_TMPDIR/out7"
mk_mock_results "$sec7" libxml2 codex
# Capture rc without `|| true` — that would mask the real exit code
# behind the trailing `true`.
empty_rc=0
empty_out=$("$CLEANUP" --output-root "$sec7" --keep-only "" 2>&1) || empty_rc=$?
assert_eq 2 "$empty_rc" "empty preserve list: exits 2"
assert_match 'preserve list is empty' "$empty_out" "empty preserve list: reports"
# Nothing was touched.
assert_file_exists "$sec7/libxml2/codex/results/work-cards.jsonl" \
    "empty preserve list: no destruction occurred"

# ── Section 8: invalid --keep entries (slashes, dots) are rejected ──
sec8="$TEST_TMPDIR/out8"
mk_mock_results "$sec8" libxml2 codex
for bad in "../etc" "/etc" ".git" "."; do
    bad_rc=0
    bad_out=$("$CLEANUP" --output-root "$sec8" --keep "$bad" 2>&1) || bad_rc=$?
    assert_eq 2 "$bad_rc" "invalid --keep '$bad': exits 2"
    assert_match 'invalid --keep' "$bad_out" "invalid --keep '$bad': reports"
done

# ── Section 9: missing output root is rejected ──────────────────────
miss_rc=0
miss_out=$("$CLEANUP" --output-root "$TEST_TMPDIR/no-such-dir" 2>&1) || miss_rc=$?
assert_eq 2 "$miss_rc" "missing output root: exits 2"
assert_match 'output root not found' "$miss_out" "missing output root: reports"

# ── Section 10: empty preserve dirs left in place; .gitkeep survives ─
sec10="$TEST_TMPDIR/out10"
mk_mock_results "$sec10" libxml2 codex
touch "$sec10/libxml2/codex/results/crashes/.gitkeep"
"$CLEANUP" --output-root "$sec10" --quiet
assert_file_exists "$sec10/libxml2/codex/results/crashes/.gitkeep" \
    ".gitkeep inside preserved dir survives cleanup"

# ── Section 11: target with no results/ is silently skipped ─────────
sec11="$TEST_TMPDIR/out11"
mkdir -p "$sec11/orphan/codex/logs"  # no results/ subdir
skip_out=$("$CLEANUP" --output-root "$sec11" --target orphan --quiet 2>&1)
rc=$?
assert_eq 0 "$rc" "no results/ dir: still exits 0"
# Nothing was created where there wasn't already a results dir.
assert_dir_not_exists "$sec11/orphan/codex/results" \
    "no results/ dir: not auto-created"

# ── Section 12: results/ rerun is idempotent ────────────────────────
sec12="$TEST_TMPDIR/out12"
mk_mock_results "$sec12" libxml2 codex
"$CLEANUP" --output-root "$sec12" --quiet
second_run=$("$CLEANUP" --output-root "$sec12" 2>&1)
rc=$?
assert_eq 0 "$rc" "rerun: still exits 0"
assert_match 'already clean' "$second_run" "rerun: reports already clean"

# ── Section 13: subsystem-keyed dotfiles with weird chars survive removal ─
# The audit produces .subsystem_dry_<file>:<func>:<line> and
# .guard_chain_<file>:<func>:<line> with colons and slashes embedded.
# rm -rf -- <path> handles them correctly.
sec13="$TEST_TMPDIR/out13"
mk_mock_results "$sec13" libxml2 codex
weird="$sec13/libxml2/codex/results/.subsystem_dry_xmlstring.c:xmlStrsub:382"
echo "0" > "$weird"
guard_weird="$sec13/libxml2/codex/results/.guard_chain_catalog.c:xmlCatalogConvertEntry:782"
echo "g" > "$guard_weird"
"$CLEANUP" --output-root "$sec13" --quiet
assert_file_not_exists "$weird"       "weird-named dotfile #1 removed"
assert_file_not_exists "$guard_weird" "weird-named dotfile #2 removed"

# ── Section 14: symlink does NOT escape the results/ dir ────────────
# A symlink inside results/ pointing outside is itself removed (the
# link is wiped, not its target). Use a sentinel file outside the tree.
sec14="$TEST_TMPDIR/out14"
mk_mock_results "$sec14" libxml2 codex
sentinel="$TEST_TMPDIR/sentinel.keep"
echo "must-survive" > "$sentinel"
ln -s "$sentinel" "$sec14/libxml2/codex/results/escape-link"
"$CLEANUP" --output-root "$sec14" --quiet
# The symlink itself is gone (it wasn't on the preserve list).
assert_file_not_exists "$sec14/libxml2/codex/results/escape-link" \
    "symlink inside results/ removed"
# The sentinel file outside the tree survives.
assert_file_exists "$sentinel" \
    "symlink target outside tree NOT followed (rm did not chase)"

# ── Section 15: target/backend traversal components are rejected ────
sec15="$TEST_TMPDIR/out15"
mk_mock_results "$sec15" libxml2 codex
trav_rc=0
trav_out=$("$CLEANUP" --output-root "$sec15" --target '../libxml2' 2>&1) || trav_rc=$?
assert_eq 1 "$trav_rc" "invalid target traversal: exits non-zero"
assert_match 'invalid target component' "$trav_out" "invalid target traversal: reports"
assert_file_exists "$sec15/libxml2/codex/results/work-cards.jsonl" \
    "invalid target traversal: no cleanup performed"

bad_backend_rc=0
bad_backend_out=$("$CLEANUP" --output-root "$sec15" --target libxml2 --backends '../codex' 2>&1) || bad_backend_rc=$?
assert_eq 1 "$bad_backend_rc" "invalid backend traversal: exits non-zero"
assert_match 'invalid backend component' "$bad_backend_out" "invalid backend traversal: reports"
assert_file_exists "$sec15/libxml2/codex/results/work-cards.jsonl" \
    "invalid backend traversal: no cleanup performed"

# ── Section 16: cleanup_logs --backend alias and traversal guard ────
CLEANUP_LOGS="$SCRIPT_ROOT/bin/cleanup_logs"
sec16a="$TEST_TMPDIR/out16a"
mk_mock_results "$sec16a" libxml2 codex
mk_mock_results "$sec16a" libxml2 claude
"$CLEANUP_LOGS" --output-root "$sec16a" --target libxml2 --backend codex --quiet
assert_file_not_exists "$sec16a/libxml2/codex/logs/index.log" \
    "cleanup_logs backend alias: codex logs cleared"
assert_file_exists "$sec16a/libxml2/claude/logs/index.log" \
    "cleanup_logs backend alias: claude logs untouched"

sec16b="$TEST_TMPDIR/out16b"
mk_mock_results "$sec16b" libxml2 claude
mk_mock_results "$sec16b" libxml2 codex
mk_mock_results "$sec16b" libxml2 gemini
mk_mock_results "$sec16b" libxml2 oss
"$CLEANUP_LOGS" --output-root "$sec16b" --target libxml2 --quiet
assert_file_not_exists "$sec16b/libxml2/claude/logs/index.log" \
    "cleanup_logs default backends: claude logs cleared"
assert_file_not_exists "$sec16b/libxml2/codex/logs/index.log" \
    "cleanup_logs default backends: codex logs cleared"
assert_file_not_exists "$sec16b/libxml2/gemini/logs/index.log" \
    "cleanup_logs default backends: gemini logs cleared"
assert_file_not_exists "$sec16b/libxml2/oss/logs/index.log" \
    "cleanup_logs default backends: oss logs cleared"

sec16="$TEST_TMPDIR/out16"
mk_mock_results "$sec16" libxml2 codex
logs_rc=0
logs_out=$("$CLEANUP_LOGS" --output-root "$sec16" --target '../libxml2' 2>&1) || logs_rc=$?
assert_eq 1 "$logs_rc" "cleanup_logs invalid target traversal: exits non-zero"
assert_match 'invalid target component' "$logs_out" "cleanup_logs invalid target traversal: reports"
assert_file_exists "$sec16/libxml2/codex/logs/index.log" \
    "cleanup_logs invalid target traversal: no cleanup performed"

teardown_test_env
summary
