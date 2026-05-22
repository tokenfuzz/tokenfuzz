#!/usr/bin/env bash
# Regression test for run_agent's "latest resume log" lookup.
#
# Bug: bin/audit ran `latest=$(ls $LOGDIR/cold-start-N-*.raw $LOGDIR/deep-N-*.raw \
# 2>/dev/null | head -1)` under `set -euo pipefail`. In bash 3.2 with no
# default nullglob, an unmatched second glob stayed literal, ls failed on the
# bogus arg, pipefail propagated, and run_agent aborted before the agent
# could even start. The failure was self-reinforcing: an agent that had
# never produced a deep_investigation log could never produce one because
# every iteration crashed at exactly that line. Observed on libxml2 where
# agents 1 and 2 never advanced past cold-start while agent 3 — which had
# one successful deep run, so both globs matched — ran fine.
#
# This test exercises the replacement (a `for` loop that filters with
# `[ -f ]`) under the same `set -euo pipefail` that bin/audit uses, with
# a directory that contains the cold-start log but no deep_investigation
# log — the exact shape that triggered the original bug.
set -o pipefail
source "$(dirname "$0")/helpers.sh"
setup_test_env

LOGDIR="$TEST_TMPDIR/logs"
mkdir -p "$LOGDIR"

# Fixture: a cold-start log exists for agent 1, but no deep_investigation
# log yet. This is the exact state of a freshly cold-started agent that
# hasn't completed a deep run.
AGENT_NUM=1
touch -t 202605020100.00 "$LOGDIR/session_20260502_010000_cold-start-${AGENT_NUM}-generic.log.raw"

# Run the same loop bin/audit's run_agent uses, under the same shell flags.
# If the bug regresses, the assignment crashes the whole subshell.
output=$(bash -c '
  set -euo pipefail
  LOGDIR="'"$LOGDIR"'"
  agent_num="'"$AGENT_NUM"'"
  latest_resume_log=""
  for _f in "$LOGDIR"/session_*_cold-start-"${agent_num}"-*.log.raw \
            "$LOGDIR"/session_*_deep_investigation-"${agent_num}"-*.log.raw; do
    [ -f "$_f" ] || continue
    if [ -z "$latest_resume_log" ] || [ "$_f" -nt "$latest_resume_log" ]; then
      latest_resume_log="$_f"
    fi
  done
  echo "latest=$latest_resume_log"
  echo "exit_ok"
') 2>&1
rc=$?

assert_eq 0 "$rc" "resume-glob: loop exits 0 even when one glob doesn't match"
assert_match 'cold-start-1-generic.log.raw' "$output" "resume-glob: finds the existing cold-start log"
assert_match 'exit_ok' "$output" "resume-glob: continues past the assignment"

# Counter-test: confirm the OLD pattern actually fails. If this passes,
# bash 3.2's behavior changed and the regression test above no longer
# guards anything meaningful.
old_output=$(bash -c '
  set -euo pipefail
  LOGDIR="'"$LOGDIR"'"
  agent_num="'"$AGENT_NUM"'"
  latest_resume_log=$(ls -1t "$LOGDIR"/session_*_cold-start-"${agent_num}"-*.log.raw \
                       "$LOGDIR"/session_*_deep_investigation-"${agent_num}"-*.log.raw \
                       2>/dev/null | head -1)
  echo "latest=$latest_resume_log"
  echo "exit_ok"
' 2>&1)
old_rc=$?

# We expect the OLD pattern to fail (rc!=0) AND not print "exit_ok".
# If this assertion ever flips, bash semantics changed — review whether
# the fix is still necessary.
assert_neq 0 "$old_rc" "resume-glob: confirm old ls-pipefail pattern still trips set -e (bug witness)"
assert_not_match 'exit_ok' "$old_output" "resume-glob: confirm old pattern aborts before continuing"

# Second case: when BOTH globs match, the new loop picks the newest by mtime.
touch -t 202605020200.00 "$LOGDIR/session_20260502_020000_deep_investigation-${AGENT_NUM}-generic.log.raw"
output=$(bash -c '
  set -euo pipefail
  LOGDIR="'"$LOGDIR"'"
  agent_num="'"$AGENT_NUM"'"
  latest_resume_log=""
  for _f in "$LOGDIR"/session_*_cold-start-"${agent_num}"-*.log.raw \
            "$LOGDIR"/session_*_deep_investigation-"${agent_num}"-*.log.raw; do
    [ -f "$_f" ] || continue
    if [ -z "$latest_resume_log" ] || [ "$_f" -nt "$latest_resume_log" ]; then
      latest_resume_log="$_f"
    fi
  done
  echo "latest=$latest_resume_log"
')
assert_match 'deep_investigation-1-generic.log.raw' "$output" \
  "resume-glob: picks newest log when both globs match"

teardown_test_env
summary
