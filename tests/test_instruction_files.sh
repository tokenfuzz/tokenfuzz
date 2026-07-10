#!/usr/bin/env bash
# Root auto-loaded instruction files must stay safe for spawned audit agents.
# Development guidance is opt-in and lives in docs/development.md.
set -o pipefail
source "$(dirname "$0")/helpers.sh"
setup_test_env

_CURRENT_TEST="development guide lives outside root auto-loaded instruction files"
assert_file_exists "$SCRIPT_ROOT/docs/development.md" "$_CURRENT_TEST"
assert_file_not_exists "$SCRIPT_ROOT/CLAUDE.md" "$_CURRENT_TEST: no root CLAUDE.md"
assert_file_not_exists "$SCRIPT_ROOT/GEMINI.md" "$_CURRENT_TEST: no root GEMINI.md"

_CURRENT_TEST="AGENTS.md contains runtime audit guidance only"
assert_file_exists "$SCRIPT_ROOT/AGENTS.md" "$_CURRENT_TEST"
assert_file_not_contains "$SCRIPT_ROOT/AGENTS.md" "harness-dev-only" "$_CURRENT_TEST: no dev-only markers"
assert_file_not_contains "$SCRIPT_ROOT/AGENTS.md" "Coding Discipline" "$_CURRENT_TEST: no harness maintainer coding rules"
assert_file_not_contains "$SCRIPT_ROOT/AGENTS.md" "Testing Discipline" "$_CURRENT_TEST: no harness maintainer test rules"
assert_file_not_contains "$SCRIPT_ROOT/AGENTS.md" "Logging Discipline" "$_CURRENT_TEST: no harness maintainer logging rules"

_CURRENT_TEST="bin/audit injects AGENTS.md directly without dev-block stripping"
assert_file_not_contains "$SCRIPT_ROOT/bin/audit" "harness-dev-only" "$_CURRENT_TEST"
assert_file_contains "$SCRIPT_ROOT/lib/audit_runner.py" 'root / "AGENTS.md"' "$_CURRENT_TEST"

_CURRENT_TEST="development docs explain root development-agent startup"
startup_prompt="Read docs/development.md first, then help me with: <task>"
assert_file_not_exists "$SCRIPT_ROOT/docs/contributing.md" "$_CURRENT_TEST: no duplicate contributing page"
assert_file_contains "$SCRIPT_ROOT/docs/development.md" "Read docs/development.md first" "$_CURRENT_TEST"
assert_file_contains "$SCRIPT_ROOT/docs/development.md" "Start your coding agent" "$_CURRENT_TEST"
assert_file_contains "$SCRIPT_ROOT/docs/development.md" '`claude`, `codex`, `gemini`, `grok`' "$_CURRENT_TEST"
assert_file_not_contains "$SCRIPT_ROOT/docs/development.md" "One-shot sessions" "$_CURRENT_TEST"
assert_file_contains "$SCRIPT_ROOT/docs/development.md" "$startup_prompt" "$_CURRENT_TEST: development page carries startup prompt"
assert_file_not_contains "$SCRIPT_ROOT/docs/development.md" "^## Context$" "$_CURRENT_TEST: development page has no redundant context section"
assert_file_contains "$SCRIPT_ROOT/docs/development.md" "Use broad, stable rules" "$_CURRENT_TEST: development page keeps vocabulary guidance as a list item"

summary
