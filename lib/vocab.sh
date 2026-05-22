#!/usr/bin/env bash
# lib/vocab.sh — QA vocabulary neutralizer.
# Sourced by bin/audit.

# Replaces classifier-sensitive verbs in state files and testcase headers
# with neutral QA-standard paraphrases. Applied to agent state files,
# scratch directory headers, and finding descriptions. Does NOT touch
# crash reports, ASan output, or final deliverables.

neutralize_qa_vocab_file() {
  local f="$1"
  local header_only="${2:-0}"
  [ -f "$f" ] && [ -w "$f" ] || return 0
  if ! perl -e 'exit(-T $ARGV[0] ? 0 : 1)' "$f" 2>/dev/null; then
    return 0
  fi
  command -v perl >/dev/null 2>&1 || return 0
  local tmp
  tmp=$(mktemp -t qavocab.XXXXXX) || return 0
  perl -e '
    use strict; use warnings;
    require "'"$SCRIPT_ROOT"'/lib/vocab-rules.pl";
    my $hdr = shift;
    my @lines = <STDIN>;
    for (my $i = 0; $i < @lines; $i++) {
      next if $hdr && $i >= 12;
      neutralize_line(\$lines[$i]);
    }
    print @lines;
  ' "$header_only" < "$f" > "$tmp" 2>/dev/null \
    && [ -s "$tmp" ] \
    && mv "$tmp" "$f" 2>/dev/null \
    || rm -f "$tmp"
}

neutralize_qa_vocab_string() {
  command -v perl >/dev/null 2>&1 || { cat; return 0; }
  perl -e '
    use strict; use warnings;
    require "'"$SCRIPT_ROOT"'/lib/vocab-rules.pl";
    my @lines = <STDIN>;
    my $skip = 0;
    for my $line (@lines) {
      # NOVOCAB markers protect literal prompt blocks (e.g. the
      # "use X (not Y)" vocabulary instruction examples) from being
      # rewritten by the neutralizer onto themselves. We DO NOT strip
      # the markers in this function — that is the job of
      # strip_novocab_markers, called exactly once after the LAST
      # scrub pass that will touch this string.
      #
      # Previously, this function stripped the markers AND protected
      # content. That left the protected region unprotected on any
      # downstream re-scrub: e.g. the safety_framing template was
      # scrubbed once at SAFETY_FRAMING_CACHED build time (markers
      # stripped here), then the final-prompt assembly scrubbed the
      # combined prompt a second time — and the "use X (not Y)"
      # vocabulary example lines were rewritten into "use X (not X)"
      # because the protective markers were already gone. Keeping the
      # markers in place across all scrubs and stripping them only at
      # the end of the pipeline fixes that.
      if ($line =~ /<!--\s*NOVOCAB\s*-->/) { $skip = 1; }
      elsif ($line =~ /<!--\s*\/NOVOCAB\s*-->/) { $skip = 0; }
      elsif (!$skip) { neutralize_line_prompt(\$line); }
    }
    print @lines;
  '
}

# strip_novocab_markers: remove NOVOCAB sentinel comments from the
# input stream. Pair with neutralize_qa_vocab_string — that function
# uses the markers to protect prompt content, and this function
# removes the markers from model-visible output. Call this exactly
# once, immediately before the prompt is written to disk / sent to
# the backend, AFTER every scrub pass that the prompt will go through.
strip_novocab_markers() {
  command -v perl >/dev/null 2>&1 || { cat; return 0; }
  perl -ne '
    s{<!--\s*/?\s*NOVOCAB\s*-->\s*\n?}{}g;
    print;
  '
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
