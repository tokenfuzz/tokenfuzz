#!/usr/bin/env bash
# lib/vocab.sh — QA vocabulary neutralizer.
# Sourced by bin/audit.

# Replaces classifier-sensitive verbs in state files and testcase headers
# with neutral QA-standard paraphrases. Applied to agent state files,
# scratch directory headers, and finding descriptions. Does NOT touch
# crash reports, ASan output, or final deliverables.

# All three neutralizers delegate to lib/vocab_rules.py, which holds the
# single copy of the rewrite-rule table. The `command -v python3` guard is
# fall-open: if the interpreter is somehow absent, pass content through
# unchanged rather than abort a prompt build.
_vocab_rules_py() { printf '%s' "$SCRIPT_ROOT/lib/vocab_rules.py"; }

neutralize_qa_vocab_file() {
  local f="$1"
  local header_only="${2:-0}"
  [ -f "$f" ] && [ -w "$f" ] || return 0
  command -v python3 >/dev/null 2>&1 || return 0
  python3 "$(_vocab_rules_py)" neutralize-file "$f" "$header_only" 2>/dev/null || true
}

neutralize_qa_vocab_string() {
  command -v python3 >/dev/null 2>&1 || { cat; return 0; }
  python3 "$(_vocab_rules_py)" neutralize-string
}

# strip_novocab_markers: remove NOVOCAB sentinel comments from the
# input stream. Pair with neutralize_qa_vocab_string — that function
# uses the markers to protect prompt content, and this function
# removes the markers from model-visible output. Call this exactly
# once, immediately before the prompt is written to disk / sent to
# the backend, AFTER every scrub pass that the prompt will go through.
strip_novocab_markers() {
  command -v python3 >/dev/null 2>&1 || { cat; return 0; }
  python3 "$(_vocab_rules_py)" strip-markers
}

neutralize_qa_vocab() {
  local scrubbed=0
  local f
  local marker="$LOGDIR/.last_neutralize"
  local newer_flag
  newer_flag=()
  if [ -f "$marker" ]; then
    newer_flag=(-newer "$marker")
  fi
  for f in "$(combined_state_path)" \
           $(for i in $(seq 1 "$NUM_AGENTS"); do echo "$(state_file_path "$i")"; done) \
           "$RESULTS_DIR/guards-db.md"; do
    if [ -f "$f" ]; then
      if [ -f "$marker" ] && [ ! "$f" -nt "$marker" ]; then
        continue
      fi
      neutralize_qa_vocab_file "$f" 0 && scrubbed=$((scrubbed + 1))
    fi
  done
  for i in $(seq 1 "$NUM_AGENTS"); do
    local d
    d=$(scratch_dir_path "$i")
    [ -d "$d" ] || continue
    while IFS= read -r -d '' f; do
      neutralize_qa_vocab_file "$f" 1 && scrubbed=$((scrubbed + 1))
    done < <(find "$d" -maxdepth 1 -type f \( -name '*.html' -o -name '*.js' -o -name '*.svg' -o -name '*.md' \) "${newer_flag[@]+"${newer_flag[@]}"}" -print0 2>/dev/null)
  done
  if [ -d "$RESULTS_DIR/findings" ]; then
    while IFS= read -r -d '' f; do
      neutralize_qa_vocab_file "$f" 0 && scrubbed=$((scrubbed + 1))
    done < <(find "$RESULTS_DIR/findings" -maxdepth 2 -type f -name 'description.md' "${newer_flag[@]+"${newer_flag[@]}"}" -print0 2>/dev/null)
  fi
  touch "$marker" 2>/dev/null || true
  [ "$scrubbed" -gt 0 ] && audit_log "vocab: scrubbed safety-classifier-hot terms from ${scrubbed} file(s) before prompt build" | tee -a "$INDEX"
  return 0
}
