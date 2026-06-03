#!/usr/bin/env bash
# Regression test for the Firefox update skill: it must not enumerate
# untracked sanitizer build trees when checking local patch conflicts.
set -o pipefail
source "$(dirname "$0")/helpers.sh"
setup_test_env

SKILL="$SCRIPT_ROOT/.agents/skills/ff-update/SKILL.md"
assert_file_exists "$SKILL" "ff-update skill present"
assert_file_contains "$SKILL" "hg -R targets/firefox status -mard" \
  "ff-update: conflict check ignores untracked build outputs"
assert_file_not_contains "$SKILL" '^hg -R targets/firefox status$' \
  "ff-update: no bare hg status that enumerates untracked files"
assert_file_contains "$SKILL" 'hg status -mard' \
  "ff-update: prose names the filtered status command"

teardown_test_env
summary
