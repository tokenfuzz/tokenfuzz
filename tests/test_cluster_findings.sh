#!/usr/bin/env bash
# tests/test_cluster_findings.sh — exercise bin/cluster-findings against
# synthetic FIND-* fixtures. Verifies:
#   (a) Layer 1 collapses two reports at the same (class, file, func)
#   (b) Layer 2 collapses two reports sharing dedup_key but different sites
#   (c) Distinct (class, file, func) tuples stay separate
#   (d) FINDING-CLUSTERS.md is written next to findings/
#   (e) Each report.md/REPORT.md gets a `Cluster:` line stamped
#   (f) Non-canonical members get a .dup-of marker; canonical members don't
#   (g) Idempotent across re-runs
#   (h) Cluster metadata is kept after the report title, not before it

set -o pipefail
source "$(dirname "$0")/helpers.sh"
setup_test_env
source "$SCRIPT_ROOT/lib/platform.sh"

CLUSTER="$SCRIPT_ROOT/bin/cluster-findings"
[ -x "$CLUSTER" ] || { echo "missing $CLUSTER"; exit 1; }

mk_find() {
  local id="$1" body="$2" llm_class="$3" llm_dedup_key="${4:-}"
  local d="$RESULTS_DIR/findings/$id"
  mkdir -p "$d"
  printf '%s\n' "$body" > "$d/report.md"
  # Synthesize the caches directly — we're not testing the LLM path here, only
  # the clustering logic that reads them. The quality gate supplies class (and
  # severity); identity (dedup_key) is owned by the keyer's .finding-key.json.
  if [ -n "$llm_class" ]; then
    local sha1
    sha1=$(shasum -a 1 "$d/report.md" | awk '{print $1}')
    cat > "$d/.llm-find-quality.json" <<EOF
{"decision":"find_quality","decision_version":"v10","content_sha1":"$sha1","accept":true,"reason":"test","class":"$llm_class","severity":"low","cached_at":"2026-05-12T00:00:00Z"}
EOF
  fi
  if [ -n "$llm_dedup_key" ]; then
    printf '{"key_version":"v1","dedup_key":"%s"}\n' "$llm_dedup_key" > "$d/.finding-key.json"
  fi
}

# ── Layer 1: two reports at same (class, file, func) ────────────────
mk_find FIND-A1 \
"# Auth bypass
## Location
\`server/handlers/admin.go:HandleListUsers:42\`

## Classification
- **Class**: auth:bypass" \
  "auth:bypass" "admin-listusers-authz-bypass"

mk_find FIND-A2 \
"# Same handler, different angle
## Location
\`server/handlers/admin.go:HandleListUsers:55\`

## Classification
- **Class**: auth:bypass" \
  "auth:bypass" "admin-listusers-authz-bypass"

# ── Layer 2: two reports at different file:func, same dedup_key ─────
mk_find FIND-B1 \
"# UAF reached via match path
## Location
\`src/pcre2_match.c:match_internal:1234\`

## Classification
- **Class**: memory-safety:lifetime" \
  "memory-safety:lifetime" "code_start-unbounded"

mk_find FIND-B2 \
"# UAF reached via DFA matcher
## Location
\`src/pcre2_dfa_match.c:dfa_match_internal:5678\`

## Classification
- **Class**: memory-safety:lifetime" \
  "memory-safety:lifetime" "code_start-unbounded"

# ── Mass-scanner safety: 3 strcpy sites must NOT collapse ──────────
mk_find FIND-C1 \
"# strcpy site one
## Location
\`a/x.c:f1:1\`

## Classification
- **Class**: memory-safety:bounds" \
  "memory-safety:bounds" ""

mk_find FIND-C2 \
"# strcpy site two
## Location
\`b/y.c:f2:1\`

## Classification
- **Class**: memory-safety:bounds" \
  "memory-safety:bounds" ""

mk_find FIND-C3 \
"# strcpy site three
## Location
\`c/z.c:f3:1\`

## Classification
- **Class**: memory-safety:bounds" \
  "memory-safety:bounds" ""

# ── No-location finding: falls back to title slug ───────────────────
mk_find FIND-D1 \
"# CSP allows unsafe-inline in default config

The default Content-Security-Policy emitted by the framework permits
'unsafe-inline' in script-src, which negates the XSS mitigation." \
  "config:permissive-default" ""

# ── Existing cluster metadata before H1 must be normalized after H1 ─
mk_find FIND-E1 \
"Cluster: FCL-stale (singleton)
Dedup key: [title] stale
# Metadata should not lead the report

The token reset path accepts stale parser state after a failed parse." \
  "state:parser-reset" ""

# ── Bias-to-separate: same (class,file,func) but NO dedup_key must NOT
#    auto-merge. Only the high-precision signals (shared dedup_key, identical
#    crash state) merge; a shared location alone is not a merge signal, so two
#    distinct bugs in one function stay apart.
mk_find FIND-G1 \
"# Bug one at a shared site
## Location
\`src/shared/util.c:helper:10\`

## Classification
- **Class**: memory-safety:bounds" \
  "memory-safety:bounds" ""

mk_find FIND-G2 \
"# Bug two at the same shared site
## Location
\`src/shared/util.c:helper:20\`

## Classification
- **Class**: memory-safety:bounds" \
  "memory-safety:bounds" ""

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

# Auto-merge on a shared dedup_key (A1/A2 share admin-listusers-authz-bypass).
assert_eq "$a1" "$a2" "auto-merge: shared dedup_key → same cluster"

# Bias-to-separate: same (class,file,func) but NO dedup_key does NOT
# auto-merge — a shared location alone is not a merge signal.
[ "$g1" != "$g2" ] \
  && pass "bias-to-separate: same site, no dedup_key → separate clusters" \
  || fail "bias-to-separate: same site, no dedup_key → separate clusters" \
       "g1=$g1 g2=$g2"

# Layer 2 collapse.
assert_eq "$b1" "$b2" "Layer 2: same dedup_key, different file → same cluster"

# Mass-scanner safety.
[ "$c1" != "$c2" ] && [ "$c2" != "$c3" ] && [ "$c1" != "$c3" ] \
  && pass "three different strcpy sites get three different clusters" \
  || fail "three different strcpy sites get three different clusters" \
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
assert_file_contains "$RESULTS_DIR/findings/FINDING-CLUSTERS.md" 'code_start-unbounded' \
  "FINDING-CLUSTERS.md surfaces the LLM dedup_key signature"
# Signature renders the FULL merge algorithm — dedup_key OR (class, file, line)
# OR crash state — not just the one key that drove the merge. B1's canonical row
# carries both a dedup_key and a (file, line) source site, so both appear,
# joined by " or ".
assert_file_contains "$RESULTS_DIR/findings/FINDING-CLUSTERS.md" 'src/pcre2_match\.c, 1234' \
  "FINDING-CLUSTERS.md Signature shows the (class, file, line) source site"
assert_file_contains "$RESULTS_DIR/findings/FINDING-CLUSTERS.md" 'code_start-unbounded.* or .*src/pcre2_match\.c, 1234' \
  "FINDING-CLUSTERS.md Signature joins dedup_key and source site with ' or '"
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
cat > "$agg_root/claude/results/findings/FIND-AGG-1/report.md" <<'EOF'
# Aggregate duplicate A

Location: `src/auth/session.go:ValidateSession:40`
Class: auth:bypass
EOF
cat > "$agg_root/codex/results/findings/FIND-AGG-2/report.md" <<'EOF'
# Aggregate duplicate B

Location: `src/auth/session.go:ValidateSession:99`
Class: auth:bypass
EOF
sha1=$(shasum -a 1 "$agg_root/claude/results/findings/FIND-AGG-1/report.md" | awk '{print $1}')
cat > "$agg_root/claude/results/findings/FIND-AGG-1/.llm-find-quality.json" <<EOF
{"decision":"find_quality","decision_version":"v10","content_sha1":"$sha1","accept":true,"reason":"test","class":"auth:bypass","severity":"low","cached_at":"2026-05-12T00:00:00Z"}
EOF
printf '{"key_version":"v1","dedup_key":"session-validate-authz-bypass"}\n' \
  > "$agg_root/claude/results/findings/FIND-AGG-1/.finding-key.json"
sha1=$(shasum -a 1 "$agg_root/codex/results/findings/FIND-AGG-2/report.md" | awk '{print $1}')
cat > "$agg_root/codex/results/findings/FIND-AGG-2/.llm-find-quality.json" <<EOF
{"decision":"find_quality","decision_version":"v10","content_sha1":"$sha1","accept":true,"reason":"test","class":"auth:bypass","severity":"high","cached_at":"2026-05-12T00:00:00Z"}
EOF
printf '{"key_version":"v1","dedup_key":"session-validate-authz-bypass"}\n' \
  > "$agg_root/codex/results/findings/FIND-AGG-2/.finding-key.json"

echo "# legacy" > "$agg_root/FIND-CLUSTERS.md"
python3 "$CLUSTER" "$agg_root" >/dev/null 2>&1 \
  || fail "aggregate cluster-findings runs cleanly" "exit nonzero"
assert_file_exists "$agg_root/FINDING-CLUSTERS.md" \
  "aggregate FINDING-CLUSTERS.md written"
assert_file_not_exists "$agg_root/FIND-CLUSTERS.md" \
  "aggregate removes legacy FIND-CLUSTERS.md"
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

teardown_test_env
summary
