#!/usr/bin/env bash
# tests/test_cluster_findings.sh — exercise bin/cluster-findings against
# synthetic FIND-* fixtures. Verifies:
#   (a) Two reports at the same (class, file, line) collapse
#   (b) An *overflow* mechanism label and its memory-safety consequence
#       collapse at one site (class normalization)
#   (c) Same file, different line stays separate (the line discriminator)
#   (d) Distinct sites stay separate; a siteless report becomes a title singleton
#   (e) FINDING-CLUSTERS.md is written, each report gets a Cluster: line stamped
#   (f) Non-canonical members get a .dup-of marker; canonical members don't
#   (g) The Signature column renders (class, file, line) and ` or <crash state>`
#   (h) Idempotent across re-runs; --dry-run writes nothing
#   (i) Cross-agent aggregate stamps reports + .dup-of

set -o pipefail
source "$(dirname "$0")/helpers.sh"
setup_test_env
audit_stat_mtime_epoch() { python3 -c 'import os,sys; print(int(os.stat(sys.argv[1]).st_mtime))' "$1"; }

CLUSTER="$SCRIPT_ROOT/bin/cluster-findings"
[ -x "$CLUSTER" ] || { echo "missing $CLUSTER"; exit 1; }

mk_find() {
  local id="$1" body="$2" llm_class="$3"
  local d="$RESULTS_DIR/findings/$id"
  mkdir -p "$d"
  printf '%s\n' "$body" > "$d/report.md"
  # Synthesize the quality cache directly — we test the clustering logic that
  # reads it, not the LLM path. The gate supplies class (and severity);
  # identity is the deterministic (class, file, line) site.
  if [ -n "$llm_class" ]; then
    local sha1
    sha1=$(shasum -a 1 "$d/report.md" | awk '{print $1}')
    cat > "$d/.llm-find-quality.json" <<EOF
{"decision":"find_quality","decision_version":"v10","content_sha1":"$sha1","accept":true,"reason":"test","class":"$llm_class","severity":"low","cached_at":"2026-05-12T00:00:00Z"}
EOF
  fi
}

# ── Same (class, file, line): two angles on one site collapse ───────
mk_find FIND-A1 \
"# Auth bypass
## Location
\`server/handlers/admin.go:HandleListUsers:42\`

## Classification
- **Class**: auth:bypass" \
  "auth:bypass"

mk_find FIND-A2 \
"# Same handler, different angle
## Location
\`server/handlers/admin.go:HandleListUsers:42\`

## Classification
- **Class**: auth:bypass" \
  "auth:bypass"

# ── Class normalization: *overflow* mechanism folds into memory-safety,
#    so the mechanism label and the consequence label at ONE site merge.
mk_find FIND-B1 \
"# Allocation size can wrap
## Location
\`src/calc.c:compute:88\`

## Classification
- **Class**: integer-overflow" \
  "integer-overflow"

mk_find FIND-B2 \
"# Same wrap, described as the consequence
## Location
\`src/calc.c:compute:88\`

## Classification
- **Class**: memory-safety" \
  "memory-safety"

# ── Mass-scanner safety: 3 distinct sites must NOT collapse ─────────
mk_find FIND-C1 \
"# strcpy site one
## Location
\`a/x.c:f1:1\`

## Classification
- **Class**: memory-safety:bounds" \
  "memory-safety:bounds"

mk_find FIND-C2 \
"# strcpy site two
## Location
\`b/y.c:f2:2\`

## Classification
- **Class**: memory-safety:bounds" \
  "memory-safety:bounds"

mk_find FIND-C3 \
"# strcpy site three
## Location
\`c/z.c:f3:3\`

## Classification
- **Class**: memory-safety:bounds" \
  "memory-safety:bounds"

# ── No-location finding: falls back to title slug ───────────────────
mk_find FIND-D1 \
"# CSP allows unsafe-inline in default config

The default Content-Security-Policy emitted by the framework permits
'unsafe-inline' in script-src, which negates the XSS mitigation." \
  "config:permissive-default"

# ── Existing cluster metadata before H1 must be normalized after H1 ─
mk_find FIND-E1 \
"Cluster: FCL-stale (singleton)
Dedup key: [title] stale
# Metadata should not lead the report

The token reset path accepts stale parser state after a failed parse." \
  "state:parser-reset"

# ── The line is the discriminator: two distinct bugs in ONE function at
#    DIFFERENT lines must NOT merge, even at the same class and file.
mk_find FIND-G1 \
"# Bug one at a shared site
## Location
\`src/shared/util.c:helper:10\`

## Classification
- **Class**: memory-safety:bounds" \
  "memory-safety:bounds"

mk_find FIND-G2 \
"# Bug two at the same function, another line
## Location
\`src/shared/util.c:helper:20\`

## Classification
- **Class**: memory-safety:bounds" \
  "memory-safety:bounds"

# ── Crash-state signal: a report embedding a sanitizer stack renders
#    both (class, file, line) AND the crash state, joined by ` or `.
mk_find FIND-H1 \
"# Heap overflow with a stack
## Location
\`src/render.c:render_draw:77\`

## Classification
- **Class**: memory-safety

\`\`\`
SUMMARY: AddressSanitizer: heap-buffer-overflow
    #0 0x1 in render_draw src/render.c:77
    #1 0x2 in main_loop src/main.c:10
\`\`\`" \
  "memory-safety"

# ── Run cluster-findings ────────────────────────────────────────
out=$(python3 "$CLUSTER" "$RESULTS_DIR" 2>&1) \
  || fail "cluster-findings runs cleanly" "exit nonzero: $out"
pass "cluster-findings runs cleanly"

assert_file_exists "$RESULTS_DIR/findings/FINDING-CLUSTERS.md" "FINDING-CLUSTERS.md written"
assert_file_exists "$RESULTS_DIR/findings/FINDING-CLUSTERS.html" \
  "FINDING-CLUSTERS.html rendered"
assert_file_exists "$RESULTS_DIR/findings/FIND-A1/report.html" \
  "cluster-findings renders member report.html"
assert_file_contains "$RESULTS_DIR/findings/FINDING-CLUSTERS.html" \
  'href="FIND-A1/report.html"' \
  "FINDING-CLUSTERS.html links to rendered member HTML"

# Helper: pull cluster id from a stamped Cluster: line.
cl_id() {
  grep -m1 -E '^Cluster: FCL-' "$RESULTS_DIR/findings/$1/report.md" \
    | sed -E 's/^Cluster: (FCL-[0-9a-f]+).*/\1/'
}

a1=$(cl_id FIND-A1); a2=$(cl_id FIND-A2)
b1=$(cl_id FIND-B1); b2=$(cl_id FIND-B2)
c1=$(cl_id FIND-C1); c2=$(cl_id FIND-C2); c3=$(cl_id FIND-C3)
d1=$(cl_id FIND-D1)
g1=$(cl_id FIND-G1); g2=$(cl_id FIND-G2)

# Auto-merge on a shared (class, file, line) site.
assert_eq "$a1" "$a2" "auto-merge: same (class, file, line) → same cluster"

# Class normalization: integer-overflow folds to memory-safety, so B1/B2 at one
# site share the class and merge.
assert_eq "$b1" "$b2" "overflow fold: integer-overflow + memory-safety at one site → same cluster"
assert_file_contains "$RESULTS_DIR/findings/FINDING-CLUSTERS.md" \
  'memory-safety, src/calc.c, 88' \
  "folded cluster keys on memory-safety (integer-overflow normalized away)"

# The line discriminates: same class+file, different line → separate clusters.
[ "$g1" != "$g2" ] \
  && pass "different line at one function → separate clusters" \
  || fail "different line at one function → separate clusters" "g1=$g1 g2=$g2"

# Mass-scanner safety.
[ "$c1" != "$c2" ] && [ "$c2" != "$c3" ] && [ "$c1" != "$c3" ] \
  && pass "three different sites get three different clusters" \
  || fail "three different sites get three different clusters" \
       "c1=$c1 c2=$c2 c3=$c3"

# A and B clusters are distinct.
[ "$a1" != "$b1" ] && pass "A (auth) and B (memory-safety) clusters differ" \
  || fail "A and B clusters differ" "both=$a1"

# Title-slug fallback singleton.
[ -n "$d1" ] && pass "title-slug fallback produces a cluster" \
  || fail "title-slug fallback produces a cluster" "no Cluster: line in FIND-D1"

# Leading metadata should be moved after the issue title; parsers still get
# the same bare-label lines, but indexes and reviewers see the title first.
e1_first_line=$(sed -n '1p' "$RESULTS_DIR/findings/FIND-E1/report.md")
assert_eq "# Metadata should not lead the report" "$e1_first_line" \
  "finding Cluster metadata is moved after the H1"
e1_title_line=$(grep -n -m1 '^# Metadata should not lead the report$' \
  "$RESULTS_DIR/findings/FIND-E1/report.md" | cut -d: -f1)
e1_cluster_line=$(grep -n -m1 '^Cluster: FCL-' \
  "$RESULTS_DIR/findings/FIND-E1/report.md" | cut -d: -f1)
e1_dedup_line=$(grep -n -m1 '^Dedup key:' \
  "$RESULTS_DIR/findings/FIND-E1/report.md" | cut -d: -f1)
if [ "${e1_cluster_line:-0}" -gt "${e1_title_line:-9999}" ] \
   && [ "${e1_dedup_line:-0}" -gt "${e1_title_line:-9999}" ]; then
  pass "finding Cluster/Dedup labels remain parseable after the H1"
else
  fail "finding Cluster/Dedup labels remain parseable after the H1" \
    "title=$e1_title_line cluster=$e1_cluster_line dedup=$e1_dedup_line"
fi

# .dup-of marker on non-canonical members; canonical members have none.
canon_a=$(grep -m1 -E '^Cluster: FCL-' "$RESULTS_DIR/findings/FIND-A1/report.md" \
          | grep -oE 'duplicate of FIND-[A-Z0-9-]+|canonical')
case "$canon_a" in
  canonical) a_canonical="FIND-A1"; a_dup="FIND-A2" ;;
  duplicate*) a_canonical="FIND-A2"; a_dup="FIND-A1" ;;
  *) a_canonical=""; a_dup="" ;;
esac
[ -n "$a_canonical" ] && pass "canonical/duplicate role tagged in Cluster: line" \
  || fail "canonical/duplicate role tagged in Cluster: line" "role=$canon_a"

if [ -n "$a_dup" ]; then
  assert_file_exists "$RESULTS_DIR/findings/$a_dup/.dup-of" \
    "duplicate FIND has .dup-of marker"
  assert_file_contains "$RESULTS_DIR/findings/$a_dup/.dup-of" "$a_canonical" \
    ".dup-of points at canonical FIND"
  [ ! -f "$RESULTS_DIR/findings/$a_canonical/.dup-of" ] \
    && pass "canonical FIND has NO .dup-of marker" \
    || fail "canonical FIND has NO .dup-of marker" "marker exists"
fi

# FINDING-CLUSTERS.md content.
assert_file_contains "$RESULTS_DIR/findings/FINDING-CLUSTERS.md" 'auth' \
  "FINDING-CLUSTERS.md lists auth class"
# Signature renders the deterministic (class, file, line) site.
assert_file_contains "$RESULTS_DIR/findings/FINDING-CLUSTERS.md" \
  '(auth, server/handlers/admin.go, 42)' \
  "FINDING-CLUSTERS.md Signature shows the (class, file, line) site"
# When a report also embeds a sanitizer stack, the Signature shows the site AND
# the crash state, joined by ' or ' (the H1 fixture).
assert_file_contains "$RESULTS_DIR/findings/FINDING-CLUSTERS.md" \
  'render\.c, 77.* or .*render_draw' \
  "FINDING-CLUSTERS.md Signature joins (class, file, line) and crash state with ' or '"
assert_file_contains "$RESULTS_DIR/findings/FINDING-CLUSTERS.md" 'FIND-A1' \
  "FINDING-CLUSTERS.md links the auth FINDs"
assert_file_contains "$RESULTS_DIR/findings/FINDING-CLUSTERS.md" 'FIND-B1' \
  "FINDING-CLUSTERS.md links the memory-safety FINDs"

# ── Idempotency ─────────────────────────────────────────────────
cp "$RESULTS_DIR/findings/FINDING-CLUSTERS.md" "$TEST_TMPDIR/CLUSTERS.before"
cp "$RESULTS_DIR/findings/FIND-A1/report.md" "$TEST_TMPDIR/A1.before"
python3 "$CLUSTER" "$RESULTS_DIR" >/dev/null 2>&1
diff_clusters=$(diff "$TEST_TMPDIR/CLUSTERS.before" \
                     "$RESULTS_DIR/findings/FINDING-CLUSTERS.md" || true)
assert_eq "" "$diff_clusters" "FINDING-CLUSTERS.md is idempotent"
diff_a1=$(diff "$TEST_TMPDIR/A1.before" \
               "$RESULTS_DIR/findings/FIND-A1/report.md" || true)
assert_eq "" "$diff_a1" "report.md Cluster: line is idempotent"

# ── --dry-run does not write FINDING-CLUSTERS.md ───────────────────
rm "$RESULTS_DIR/findings/FINDING-CLUSTERS.md"
mtime_before=$(audit_stat_mtime_epoch "$RESULTS_DIR/findings/FIND-A1/report.md")
python3 "$CLUSTER" "$RESULTS_DIR" --dry-run >/dev/null 2>&1
[ ! -f "$RESULTS_DIR/findings/FINDING-CLUSTERS.md" ] \
  && pass "--dry-run does not write FINDING-CLUSTERS.md" \
  || fail "--dry-run does not write FINDING-CLUSTERS.md" "file present"
mtime_after=$(audit_stat_mtime_epoch "$RESULTS_DIR/findings/FIND-A1/report.md")
assert_eq "$mtime_before" "$mtime_after" "--dry-run does not touch report.md"

# ── Canonical promotion: bumping severity flips the canonical ────
# Re-add FINDING-CLUSTERS.md by running normally; then upgrade FIND-A2
# severity to High and confirm A2 becomes canonical (highest severity
# wins, ties broken by lex). FIND-A1 should then carry .dup-of.
python3 "$CLUSTER" "$RESULTS_DIR" >/dev/null 2>&1
sha1=$(shasum -a 1 "$RESULTS_DIR/findings/FIND-A2/report.md" | awk '{print $1}')
cat > "$RESULTS_DIR/findings/FIND-A2/.llm-find-quality.json" <<EOF
{"decision":"find_quality","decision_version":"v10","content_sha1":"$sha1","accept":true,"reason":"upgraded","class":"auth:bypass","severity":"high","cached_at":"2026-05-12T00:00:00Z"}
EOF
python3 "$CLUSTER" "$RESULTS_DIR" >/dev/null 2>&1
assert_file_exists "$RESULTS_DIR/findings/FIND-A1/.dup-of" \
  "after severity upgrade, A1 carries .dup-of (A2 is canonical)"
[ ! -f "$RESULTS_DIR/findings/FIND-A2/.dup-of" ] \
  && pass "A2 has NO .dup-of after promotion" \
  || fail "A2 has NO .dup-of after promotion" ".dup-of exists"

# ── Cross-agent aggregate also stamps reports + .dup-of ───────────
agg_root="$TEST_TMPDIR/output/demo"
mkdir -p "$agg_root/claude/results/findings/FIND-AGG-1" \
         "$agg_root/codex/results/findings/FIND-AGG-2"
# A target root is identified by its target.toml (the canonical rule); write
# one so this behaves like a real target root rather than relying on the
# dropped parent==output fallback.
printf 'target = "demo"\n' > "$agg_root/target.toml"
cat > "$agg_root/claude/results/findings/FIND-AGG-1/report.md" <<'EOF'
# Aggregate duplicate A

Location: `src/auth/session.go:ValidateSession:40`
Class: auth:bypass
EOF
cat > "$agg_root/codex/results/findings/FIND-AGG-2/report.md" <<'EOF'
# Aggregate duplicate B

Location: `src/auth/session.go:ValidateSession:40`
Class: auth:bypass
EOF
sha1=$(shasum -a 1 "$agg_root/claude/results/findings/FIND-AGG-1/report.md" | awk '{print $1}')
cat > "$agg_root/claude/results/findings/FIND-AGG-1/.llm-find-quality.json" <<EOF
{"decision":"find_quality","decision_version":"v10","content_sha1":"$sha1","accept":true,"reason":"test","class":"auth:bypass","severity":"low","cached_at":"2026-05-12T00:00:00Z"}
EOF
sha1=$(shasum -a 1 "$agg_root/codex/results/findings/FIND-AGG-2/report.md" | awk '{print $1}')
cat > "$agg_root/codex/results/findings/FIND-AGG-2/.llm-find-quality.json" <<EOF
{"decision":"find_quality","decision_version":"v10","content_sha1":"$sha1","accept":true,"reason":"test","class":"auth:bypass","severity":"high","cached_at":"2026-05-12T00:00:00Z"}
EOF

python3 "$CLUSTER" "$agg_root" >/dev/null 2>&1 \
  || fail "aggregate cluster-findings runs cleanly" "exit nonzero"
assert_file_exists "$agg_root/FINDING-CLUSTERS.md" \
  "aggregate FINDING-CLUSTERS.md written"
assert_file_contains "$agg_root/FINDING-CLUSTERS.md" 'claude/FIND-AGG-1' \
  "aggregate FINDING-CLUSTERS.md links claude member"
assert_file_contains "$agg_root/FINDING-CLUSTERS.md" 'codex/FIND-AGG-2' \
  "aggregate FINDING-CLUSTERS.md links codex member"
assert_file_contains "$agg_root/claude/results/findings/FIND-AGG-1/report.md" \
  'duplicate of codex/FIND-AGG-2' \
  "aggregate duplicate report names cross-agent canonical"
assert_file_exists "$agg_root/claude/results/findings/FIND-AGG-1/.dup-of" \
  "aggregate duplicate gets .dup-of marker"
assert_file_contains "$agg_root/claude/results/findings/FIND-AGG-1/.dup-of" \
  'Canonical: codex/FIND-AGG-2' \
  "aggregate .dup-of points at cross-agent canonical"
[ ! -f "$agg_root/codex/results/findings/FIND-AGG-2/.dup-of" ] \
  && pass "aggregate canonical has NO .dup-of marker" \
  || fail "aggregate canonical has NO .dup-of marker" ".dup-of exists"

agg_nested="$TEST_TMPDIR/output/samples/demo"
mkdir -p "$agg_nested/codex/results/findings/FIND-NEST-1"
printf 'target = "demo"\n' > "$agg_nested/target.toml"
cat > "$agg_nested/codex/results/findings/FIND-NEST-1/report.md" <<'EOF'
# Nested aggregate finding

Location: `src/nested/session.go:Validate:40`
Class: auth:bypass
EOF
sha1=$(shasum -a 1 "$agg_nested/codex/results/findings/FIND-NEST-1/report.md" | awk '{print $1}')
cat > "$agg_nested/codex/results/findings/FIND-NEST-1/.llm-find-quality.json" <<EOF
{"decision":"find_quality","decision_version":"v10","content_sha1":"$sha1","accept":true,"reason":"test","class":"auth:bypass","severity":"low","cached_at":"2026-05-12T00:00:00Z"}
EOF
python3 "$CLUSTER" "$agg_nested" >/dev/null 2>&1 \
  || fail "nested aggregate cluster-findings runs cleanly" "exit nonzero"
assert_file_exists "$agg_nested/FINDING-CLUSTERS.md" \
  "nested aggregate FINDING-CLUSTERS.md written"
assert_file_contains "$agg_nested/FINDING-CLUSTERS.md" 'codex/FIND-NEST-1' \
  "nested aggregate FINDING-CLUSTERS.md links member"

# A nested CONTAINER dir (output/samples/, no target.toml) is NOT a target
# root: identified by target.toml alone, it falls through to plain results-dir
# mode (findings_root key), not the bogus target-root aggregate (target_root
# key) it used to reach via the dropped parent==output fallback.
container_json=$(python3 "$CLUSTER" "$TEST_TMPDIR/output/samples" --json 2>/dev/null)
assert_eq "yes" \
  "$(printf '%s' "$container_json" | python3 -c "import json,sys;d=json.load(sys.stdin);print('yes' if 'findings_root' in d and 'target_root' not in d else 'no')")" \
  "container dir (no target.toml) is not aggregated as a target root"

# ── RC#2: evidence-gated canonical — proven (E:P) wins over unproven (E:U) ──
# Two findings at one site cluster; the higher-severity member is an UNPROVEN
# (E:U) theory, the lower is the PROVEN (E:P) manifestation. The canonical —
# hence the cluster band — must be the proven member, so an unproven claim
# cannot inflate the cluster above what is proven. (Without evidence-gating the
# Medium unproven member would be canonical.)
mk_find FIND-EVU \
"# Unproven escalation theory
## Location
\`src/util.c:resolve_entry:242\`
## Classification
- **Class**: memory-safety
- **Severity**: Medium (CVSS-BTE 4.0: 6.8)

CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:U/CR:M/IR:M/AR:M" \
  "memory-safety"
mk_find FIND-EVP \
"# Proven manifestation at the same site
## Location
\`src/util.c:resolve_entry:242\`
## Classification
- **Class**: memory-safety
- **Severity**: Low (CVSS-BTE 4.0: 2.7)

CVSS:4.0/AV:L/AC:L/AT:P/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N/E:P/CR:M/IR:M/AR:M" \
  "memory-safety"
python3 "$CLUSTER" "$RESULTS_DIR" >/dev/null 2>&1 \
  || fail "cluster-findings (RC#2) re-runs cleanly" "nonzero exit"
assert_eq "$(cl_id FIND-EVU)" "$(cl_id FIND-EVP)" \
  "RC#2: proven + unproven members at one site cluster together"
assert_file_exists "$RESULTS_DIR/findings/FIND-EVU/.dup-of" \
  "RC#2: unproven (E:U) member is non-canonical"
[ ! -f "$RESULTS_DIR/findings/FIND-EVP/.dup-of" ] \
  && pass "RC#2: proven (E:P) member is canonical" \
  || fail "RC#2: proven (E:P) member is canonical" "proven member got .dup-of"

# _derive_target_root scans the <agent>/{results,logs} marker from the RIGHT,
# so a nested slug whose own first component is named "results" or "logs" is not
# mistaken for the structural marker (which would corrupt the strip-prefix and
# split duplicate findings by citation shape).
derive_out=$(python3 - <<'PY'
import importlib.machinery, importlib.util
from pathlib import Path
loader = importlib.machinery.SourceFileLoader("cf", "bin/cluster-findings")
spec = importlib.util.spec_from_loader("cf", loader)
cf = importlib.util.module_from_spec(spec); loader.exec_module(cf)
cases = {
    "/x/output/results/demo/codex/results/findings/FIND-1/report.md": "targets/results/demo",
    "/x/output/samples/sample-c/codex/results/findings/FIND-1/report.md": "targets/samples/sample-c",
    "/x/output/cjson/claude/results/findings/FIND-1/report.md": "targets/cjson",
}
for p, exp in cases.items():
    got = cf._derive_target_root(Path(p))
    print(f"{'OK' if got == exp else 'FAIL'} {p} -> {got}")
PY
)
if printf '%s' "$derive_out" | grep -q FAIL; then
  fail "_derive_target_root scans the results/logs marker from the right" "$derive_out"
else
  pass "_derive_target_root scans the results/logs marker from the right (nested slug named 'results' handled)"
fi

teardown_test_env
summary
