#!/usr/bin/env bash
# Doc-neutrality invariant: every checked-in doc the agent reads
# directly via Read/Bash must be a fixed point of `neutralize_line`.
# That is, running the helper over the doc must not change anything.
# This locks vocabulary drift out: any future PR that introduces a
# flagged term in these docs (security fix, malformed, use-after-free,
# bug-rich, etc.) breaks this test until it's neutralized.
set -o pipefail
source "$(dirname "$0")/helpers.sh"
setup_test_env

DOC_TARGETS=(
  "$SCRIPT_ROOT/AGENTS.md"
)
while IFS= read -r -d '' f; do
  DOC_TARGETS+=("$f")
done < <(find "$SCRIPT_ROOT/.agents/references" -type f -name '*.md' -print0 2>/dev/null)

run_helper() {
  perl -e '
    use strict; use warnings;
    require "'"$SCRIPT_ROOT"'/lib/vocab-rules.pl";
    while (my $l = <STDIN>) { neutralize_line(\$l); print $l; }
  '
}

for doc in "${DOC_TARGETS[@]}"; do
  [ -f "$doc" ] || { fail "doc not found: $doc"; continue; }
  rel="${doc#$SCRIPT_ROOT/}"
  before=$(cat "$doc")
  after=$(printf '%s' "$before" | run_helper)
  if [ "$before" = "$after" ]; then
    pass "$rel is helper-canonical (round-trips through neutralize_line)"
  else
    diff_out=$(diff <(printf '%s' "$before") <(printf '%s' "$after") | head -10)
    fail "$rel diverges from helper output" "$diff_out"
  fi
done

teardown_test_env
summary
