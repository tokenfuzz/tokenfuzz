#!/usr/bin/env bash
# Regression coverage for lib/prompts centralization.
set -o pipefail
source "$(dirname "$0")/helpers.sh"
setup_test_env

renderer="$SCRIPT_ROOT/lib/prompt_render.py"

assert_file_exists "$SCRIPT_ROOT/lib/prompt_template.sh" "shared bash prompt renderer exists"
assert_file_contains "$SCRIPT_ROOT/lib/prompt_render.py" "def render_template" \
  "python prompt renderer exposes render_template API"

required_templates=(
  cold_start.md.j2
  compact_fresh.md.j2
  deep_investigation.md.j2
  safety_framing.md.j2
  common_suffix.md.j2
  find_first_directive.md.j2
  strategy_picker.md.j2
  audit_goal_framing.md.j2
  audit_recon.md.j2
  validate_finding.md.j2
  validate_trigger_provenance.md.j2
  suggest_peers.md.j2
  suggest_threat_model.md.j2
  peer_fix_distill.md.j2
  peer_fix_map.md.j2
  work_rerank.md.j2
  auto_repair_target_toml.md.j2
  model_preflight.md.j2
  oss_tool_preflight.md.j2
  triage_legit_crash.md.j2
  triage_crash_trace.md.j2
  triage_crash_confirm.md.j2
  triage_reachability_fields.md.j2
  triage_find_quality.md.j2
  triage_cluster_expand.md.j2
  triage_patch_review.md.j2
)

for t in "${required_templates[@]}"; do
  assert_file_exists "$SCRIPT_ROOT/lib/prompts/$t" "template exists: $t"
done

rendered=$(python3 "$renderer" triage_crash_trace.md.j2 \
  --var $'trace=ASAN: heap-use-after-free\n#0 f')
assert_match "AddressSanitizer trace" "$rendered" "triage trace template renders heading"
assert_match "heap-use-after-free" "$rendered" "triage trace template injects trace"

# triage_crash_confirm criterion 1 must accept the full sanitizer-class
# taxonomy, not just ASan — otherwise the final gate rejects real TSan /
# MSan / Go-race / security-UBSan crashes as out-of-scope (false negatives).
rendered=$(python3 "$renderer" triage_crash_confirm.md.j2)
assert_match "MemorySanitizer use-of-uninitialized-value" "$rendered" \
  "confirm gate accepts MemorySanitizer use-of-uninitialized-value"
assert_match "ThreadSanitizer data race" "$rendered" \
  "confirm gate accepts ThreadSanitizer data races"
assert_match "WARNING: DATA RACE" "$rendered" \
  "confirm gate accepts Go race-detector reports"
assert_match "index-out-of-bounds" "$rendered" \
  "confirm gate accepts security-class UBSan checks"

# oss tool preflight prompt: must drive the file read tool and demand the
# sentinel back verbatim (the local-model tool-use litmus in bin/audit).
rendered=$(python3 "$renderer" oss_tool_preflight.md.j2)
assert_match "file read tool" "$rendered" "oss preflight template asks for the read tool"
assert_match "oss-tool-sentinel.txt" "$rendered" "oss preflight template names the sentinel path"

# Trigger-provenance gate: must interpolate the finding + target and keep the
# recall-safe framing (affirmative disproof only; self-declared fields are not
# evidence) so a future edit can't silently turn it into an eager rejecter.
rendered=$(python3 "$renderer" validate_trigger_provenance.md.j2 \
  --var 'target_path=/tmp/tgt' --var 'candidate_json={"id":"X"}' \
  --var 'skeptic_block=' --var 'timeout_secs=300')
assert_match "/tmp/tgt" "$rendered" "trigger gate interpolates target_path"
assert_match '"id":"X"' "$rendered" "trigger gate interpolates candidate_json"
assert_match "affirmative disproof" "$rendered" "trigger gate keeps the affirmative-disproof rule"
assert_match "NOT evidence" "$rendered" "trigger gate keeps the fields-are-not-evidence guard"
assert_match "runs caller-supplied code by design" "$rendered" \
  "trigger gate can reject trusted extension surfaces with source evidence"
assert_match "private static metadata or internal descriptor tables" "$rendered" \
  "trigger gate can reject forged private metadata prerequisites"
assert_match "semantic-looking finding" "$rendered" \
  "trigger gate rejects semantic-looking feature behavior when source-proven"

# audit_recon pulls its opener from the shared goal_framing partial, the
# same as build_recon_prompt does — render and pass it through here too.
recon_goal_framing=$(python3 "$renderer" audit_goal_framing.md.j2)
rendered=$(python3 "$renderer" audit_recon.md.j2 \
  --var "goal_framing=$recon_goal_framing" \
  --var "target_slug=demo" \
  --var "scope_block=## Scope"$'\n'"- src/a.c" \
  --var "slice_name=slice-1" \
  --var "timeout_secs=1800")
assert_match "Find all security issues" "$rendered" "audit recon template keeps recall framing"
assert_match '"slice": "slice-1"' "$rendered" "audit recon template injects slice"

# triage_reachability_fields: resource-exhaustion converse-guard. The exhausting
# QUANTITY (depth/count/size), not the field values, decides byte-reachability —
# otherwise an API-built deep-recursion DoS whose depth a parser nesting limit
# blocks from untrusted input gets mislabelled trigger_source=bytes (AV:N) and
# over-scored. Recall-safe: only reclassifies when an input bound below the
# exhaustion threshold is shown; genuine byte-driven DoS stays "bytes".
rendered=$(python3 "$renderer" triage_reachability_fields.md.j2 --var 'narrative=x')
assert_match "exhausting quantity, not the field values" "$rendered" \
  "reachability fields: resource-exhaustion classified by exhausting quantity"
assert_match "parser nesting or size limit" "$rendered" \
  "reachability fields: input bound below threshold localises exhaustion to call-sequence"

# triage_reachability_fields: env/fs-state delivery-vs-trust guard. A fuzz input's
# CONTENTS delivered via file/argv/stdin/corpus are attacker bytes, not env/fs-state.
# This rule only steers severity from the RENDERED prompt — it previously lived in a
# {# #} comment stripped at render time, which let a caller-only UAF mislabel env and
# score Medium instead of Low. Assert it survives rendering, and that the "both"
# carveout stays so file-delivered setup + caller sequence is not forced to plain bytes.
assert_match 'argv, stdin, or fuzz corpus are "bytes"' "$rendered" \
  "reachability fields: file/argv/stdin/corpus contents are bytes"
assert_match 'never "env"/"fs-state"' "$rendered" \
  "reachability fields: input-file contents are not env/fs-state"
assert_match "reading a testcase via fopen" "$rendered" \
  "reachability fields: fopen/stdin delivery does not change the trust class"
assert_match 'or "both" when they only set up' "$rendered" \
  "reachability fields: file-delivered setup + caller sequence stays both, not plain bytes"

rendered=$(python3 "$renderer" suggest_threat_model.md.j2 \
  --var "slug=demo" \
  --var "upstream_url=https://example.com/demo" \
  --var "readme=A toy XML parser library." \
  --var "api_surface=include/demo.h")
assert_match "attacker_controls" "$rendered" "threat-model template names attacker_controls"
assert_match "call-sequence" "$rendered" "threat-model template lists the token legend"
assert_match "A toy XML parser library" "$rendered" "threat-model template injects the README"

# Prompt bodies should live in lib/prompts. These patterns intentionally
# allow canonical docs and non-prompt backend-output regexes.
# The `prompt="<literal>` alternative catches short single-line prompt
# strings assigned directly in shell (e.g. the model preflight echo) that
# the triple-quote / heredoc patterns miss; `prompt="$..."` command
# substitutions and `prompt=""` are excluded by the leading [^"$].
prompt_body_re="prompt[[:space:]]*=[[:space:]]*f?\"\"\"|prompt=\\$\\(cat <<|cat <<PROMPT|IFS= read -r -d '' prompt|prompt=\"[^\"\$]|You are |Output a single JSON|Output ONE JSON|Final assistant message"
remaining=$(
  cd "$SCRIPT_ROOT" && rg -n "$prompt_body_re" \
    bin lib .agents \
    --glob '!lib/prompts/*.md.j2' \
    2>/dev/null \
  | grep -v 'bin/run-\(asan\|sanitizer\)-multi:.*headless mode' \
  || true
)
assert_eq "" "$remaining" "no inline prompt bodies remain outside lib/prompts"

# Regression guard for lib/prompts/benchmark_model_direct.md.j2.
# This baseline prompt is load-bearing: the metric "0 crashes for every
# model-direct cell" came back when (a) the CRASH-promotion language got
# tightened away and (b) the prompt told the model to treat the source
# tree as read-only, which the agent over-generalised into "do not
# write build artifacts anywhere". Assertions below pin the structure
# that fixed the regression so a future cleanup PR can't quietly undo
# it. If you genuinely need to remove one of these tokens, update both
# the template and these assertions in the same commit and explain why
# in the message.
md_direct="$SCRIPT_ROOT/lib/prompts/benchmark_model_direct.md.j2"
# Shared purpose/authorization opener: single source of truth in
# audit_goal_framing.md.j2, rendered into BOTH model-direct (ctx) and
# bin/audit-recon (build_recon_prompt). Pinning the wiring here stops the
# benchmark baseline and the recon prompt from drifting apart on framing —
# drift would make the benchmark measure framing, not harness machinery.
goal_framing_rendered=$(python3 "$renderer" audit_goal_framing.md.j2)
assert_match "authorized, owner-run local" "$goal_framing_rendered" \
  "shared goal-framing partial renders the authorized owner-run QA framing"
assert_match "Find all security issues" "$goal_framing_rendered" \
  "shared goal-framing partial renders the find-all-issues goal directive"
assert_file_contains "$md_direct" "{{ goal_framing }}" \
  "model-direct template wires the shared goal_framing placeholder"
recon_tmpl="$SCRIPT_ROOT/lib/prompts/audit_recon.md.j2"
assert_file_contains "$recon_tmpl" "{{ goal_framing }}" \
  "recon template wires the shared goal_framing placeholder"
# The aligned framing replaced model-direct's bare CTF opener; guard it.
if grep -qF -- "CTF-style" "$md_direct"; then
  fail "model-direct reintroduced the bare 'CTF-style' opener (framing drift vs recon)"
else
  pass "model-direct uses the shared authorized-QA opener, not bare CTF"
fi
assert_file_contains "$md_direct" "Primary objective" \
  "model-direct template carries the CRASH-first primary-objective block"
assert_file_contains "$md_direct" "Mode switch after ~5 FINDs" \
  "model-direct template tells the agent to pivot from FIND to CRASH"
assert_file_contains "$md_direct" "{{ crash_objective }}" \
  "model-direct template wires the crash_objective placeholder"
assert_file_contains "$md_direct" "{{ asan_invocation_hint }}" \
  "model-direct template wires the asan_invocation_hint placeholder"
assert_file_contains "$md_direct" "{{ harness_build_recipe }}" \
  "model-direct template wires the harness_build_recipe placeholder"
assert_file_contains "$md_direct" "AI EDITOR WARNING" \
  "model-direct template keeps the sentinel comment that deters drive-by rewrites"
assert_file_contains "$md_direct" "{{ non_audit_dirs }}" \
  "model-direct template wires the non_audit_dirs scope placeholder"
assert_file_contains "$md_direct" "Audit scope" \
  "model-direct template carries the Audit scope section header"
assert_file_contains "$md_direct" "scoping rule for .findings., not for .navigation." \
  "model-direct template separates finding-scope from navigation-scope"
# NEW: the Audit-scope block must scope by ROLE (test/tool binaries,
# generators, CI scripts, binding drivers), not directory name alone, and
# must keep the false-negative-safe "unsure → file it" instruction.
assert_file_contains "$md_direct" "Judge by ROLE" \
  "model-direct scope block judges by role, not directory alone"
assert_file_contains "$md_direct" "separate test or tool binary" \
  "model-direct scope block names test/tool-binary drivers as out of scope"
assert_file_contains "$md_direct" "generators and build/CI scripts" \
  "model-direct scope block names generators and CI scripts as out of scope"
assert_file_contains "$md_direct" "unsure whether a file ships, treat it as" \
  "model-direct scope block keeps the FN-safe unsure-is-in-scope rule"

# NEW: the find-quality gate carries the non-product-surface reject
# category with an explicit keep-on-unsure (Layer 2). Render with a dummy
# body so the {{ body }} placeholder resolves.
fq_rendered=$(python3 "$renderer" triage_find_quality.md.j2 --var "body=stub")
assert_match "Non-product surface" "$fq_rendered" \
  "find-quality gate carries the non-product-surface reject category"
assert_match "language-binding .test driver" "$fq_rendered" \
  "find-quality gate names binding test drivers as non-product"
assert_match "cannot tell whether the file ships" "$fq_rendered" \
  "find-quality gate keeps explicit keep-on-unsure for uncertain shipping"
assert_match "reached from a shipped path" "$fq_rendered" \
  "find-quality gate keeps explicit keep-on-unsure for shipped reachability"
assert_match "OOM-only or allocation-failure-only" "$fq_rendered" \
  "find-quality gate rejects OOM-only cleanup claims without a security primitive"
assert_match "Caller-contract / trusted-caller misuse" "$fq_rendered" \
  "find-quality gate rejects trusted caller contract misuse"
assert_match "Intentional extension or code-execution surface" "$fq_rendered" \
  "find-quality gate rejects trusted extension-surface claims"
assert_match "Internal invariant / static metadata corruption" "$fq_rendered" \
  "find-quality gate rejects forged private metadata claims"
assert_match "source/control/sink/boundary" "$fq_rendered" \
  "find-quality gate requires the Codex-style proof tuple before accept"
assert_match "Dependency presence" "$fq_rendered" \
  "find-quality gate rejects dependency/API/string-match-only claims"
assert_match "call chain is not enough" "$fq_rendered" \
  "find-quality gate rejects partial call chains without boundary proof"

vf_rendered=$(python3 "$renderer" validate_finding.md.j2 \
  --var 'target_path=/tmp/tgt' \
  --var 'candidate_json={"id":"Y"}' \
  --var 'skeptic_block=' \
  --var 'timeout_secs=300')
assert_match "Product surface and boundary" "$vf_rendered" \
  "finding validator requires product surface and boundary verification"
assert_match '"boundary":true\|false' "$vf_rendered" \
  "finding validator emits an explicit boundary verification field"
assert_match "writing around the gap" "$vf_rendered" \
  "finding validator records inconclusive checks instead of writing around them"

# Divergence guard (SMOKE TEST, not a semantic-equivalence proof): the FINDINGS
# gate (triage_find_quality) and the CRASH gates (triage_crash_confirm,
# triage_legit_crash) deliberately use DIFFERENT default postures — crash gates
# lean accept because the sanitizer artifact already proves realness, the
# findings gate defaults to reject because a finding is unproven prose. But the
# security-RELEVANCE rules below are about whether a *real* issue is a security
# issue, so they must read the same way on both paths or the same bug gets
# accepted as a crash and rejected as a finding (or vice-versa). These rules are
# duplicated across the three prompts (no shared partial yet). This asserts only
# that each rule is still PRESENT on every path — it trips when an edit deletes a
# rule from one path (the common drift), but it cannot catch a rule that is
# reworded into a materially different meaning while keeping the trigger word.
# Treat a green result as "nobody dropped a rule," not "the rules are equivalent."
for _div_tpl in triage_find_quality triage_crash_confirm triage_legit_crash; do
  case "$_div_tpl" in
    triage_find_quality) _div_rendered="$fq_rendered" ;;
    *) _div_rendered=$(python3 "$renderer" "$_div_tpl.md.j2") ;;
  esac
  assert_match 'ASSERT|CHECK' "$_div_rendered" \
    "divergence guard: $_div_tpl carries the debug-only-assert reject rule"
  assert_match "conventional" "$_div_rendered" \
    "divergence guard: $_div_tpl keeps inferred/conventional contracts off the reject grounds"
  assert_match "library defect" "$_div_rendered" \
    "divergence guard: $_div_tpl treats public-callback re-entrancy as a library defect, not caller misuse"
done

# End-to-end: render with the audit_scope helper's actual output and
# assert each doc/example/test/fuzz family name shows up in the prompt.
# This is the load-bearing check that the bare CTF agent is told to
# skip filing findings inside test/example/etc dirs — without it,
# codex r1 (2026-05-24) filed a real FIND inside tests/.
audit_scope_dirs=$(python3 -c "
import sys; sys.path.insert(0, '$SCRIPT_ROOT/lib')
from audit_scope import non_audit_dirs_for_prompt
print(non_audit_dirs_for_prompt())
")
md_scope_rendered=$(python3 "$renderer" benchmark_model_direct.md.j2 \
  --var "target_path=/tmp/t" \
  --var "output_dir=/tmp/o" \
  --var "crash_objective=" \
  --var "asan_invocation_hint=" \
  --var "harness_build_recipe=" \
  --var "non_audit_dirs=$audit_scope_dirs")
for token in tests examples fuzz docs; do
  assert_match "$token" "$md_scope_rendered" \
    "model-direct rendered prompt enumerates audit_scope token: $token"
done
# The harness-internal sanitizer-build / install-staging prefix rules
# are scanner concerns and MUST NOT leak into the model-direct prompt
# list — the model still needs to navigate build-asan/ to drive the
# sanitizer binary. The Audit-scope section's own example mentions
# build-asan inside the "navigation is fine" clause, so we anchor on
# the rendered {{ non_audit_dirs }} value instead of grepping the
# whole prompt.
case "$audit_scope_dirs" in
  *build-asan*|*install*)
    fail "non_audit_dirs_for_prompt leaked harness-scanner prefix rule: $audit_scope_dirs"
    ;;
  *)
    pass "non_audit_dirs_for_prompt stays literal-only (no scanner prefix rules)"
    ;;
esac
# Check the RENDERED prompt body, not the source — the sentinel comment
# block legitimately references the old phrase when explaining why it
# was removed.
md_direct_body=$(python3 "$renderer" benchmark_model_direct.md.j2 \
  --var "target_path=/tmp/t" \
  --var "output_dir=/tmp/o" \
  --var "crash_objective=" \
  --var "asan_invocation_hint=" \
  --var "harness_build_recipe=")
if printf '%s' "$md_direct_body" | grep -q "treat the tree as read-only"; then
  fail "model-direct rendered prompt reintroduces the read-only-tree prohibition (kills PoC construction)"
else
  pass "model-direct rendered prompt no longer forbids writing build artifacts"
fi

# End-to-end: render the template with the four substitutions the
# bin/benchmark caller now supplies, and assert the sentinel does NOT
# survive into the model-facing prompt (prompt_render.py strips Jinja
# {# … #} blocks).
md_rendered=$(python3 "$renderer" benchmark_model_direct.md.j2 \
  --var "target_path=/tmp/t" \
  --var "output_dir=/tmp/o" \
  --var "crash_objective=OBJ-MARKER" \
  --var "asan_invocation_hint=HINT-MARKER" \
  --var "harness_build_recipe=RECIPE-MARKER")
assert_match "OBJ-MARKER"    "$md_rendered" "rendered template substitutes crash_objective"
assert_match "HINT-MARKER"   "$md_rendered" "rendered template substitutes asan_invocation_hint"
assert_match "RECIPE-MARKER" "$md_rendered" "rendered template substitutes harness_build_recipe"
if printf '%s' "$md_rendered" | grep -q "AI EDITOR WARNING"; then
  fail "Jinja {# … #} sentinel leaked into the rendered model-direct prompt"
else
  pass "Jinja {# … #} comments are stripped before the prompt reaches the model"
fi

# Regression guard for the gemini-r1 2026-05-24 incident: the prior
# template used `./findings/` and `./crashes/` as write paths, which
# silently mis-routed a real FIND-001 into the source tree when the
# agent `cd`'d before writing. Every WRITE path in the rendered prompt
# must now be absolute under {{ output_dir }}.
#
# Bare `./findings/` / `./crashes/` survive ONLY inside the explicit
# prohibition paragraph that warns against them (so the model knows
# what NOT to do). The bug-shaped pattern is `./crashes/CRASH-N` /
# `./findings/FIND-<n>/...` — a relative path with the agent-coined
# entry prefix attached. That combination should be absent from
# instructional text (it only appears as an example inside the
# prohibition).
md_paths_rendered=$(python3 "$renderer" benchmark_model_direct.md.j2 \
  --var "target_path=/tmp/t" \
  --var "output_dir=/tmp/o" \
  --var "crash_objective=" \
  --var "asan_invocation_hint=" \
  --var "harness_build_recipe=")
# Count relative-path mentions; the prohibition paragraph contains
# exactly THREE (`./findings/` / `./crashes/` in the HARD RULE line,
# one `./findings/FIND-1/report.md` example, and the closing reminder
# in "Output contract"). Anything more is a regression — a new
# instruction sneaking in a relative write path.
rel_count=$(printf '%s' "$md_paths_rendered" \
  | grep -cE '\./findings/|\./crashes/' || true)
if [ "${rel_count:-0}" -le 4 ]; then
  pass "model-direct rendered prompt keeps relative-path mentions to the prohibition paragraph (count=$rel_count, expected <=4)"
else
  fail "model-direct rendered prompt has $rel_count relative-path mentions; expected <=4 (only the explicit prohibition should mention them)"
fi
# Belt-and-suspenders: absolute write paths must actually be present.
assert_match "/tmp/o/findings/" "$md_paths_rendered" \
    "rendered prompt names the absolute findings path under output_dir"
assert_match "/tmp/o/crashes/" "$md_paths_rendered" \
    "rendered prompt names the absolute crashes path under output_dir"

# The python render helper (lib/benchmark_model_direct_render.py) also
# emits ASan-invocation and harness-build hints whose paths must be
# absolute. Render with a fake target that has an asan build, then
# slice OUT the hint blocks (everything from "### Driving the asan
# binary directly" onward) — the surrounding boilerplate already
# contains the legitimate prohibition mentions of `./crashes/`.
render_py="$SCRIPT_ROOT/lib/benchmark_model_direct_render.py"
if [ -f "$render_py" ]; then
  # target.toml lives at output/<slug>/target.toml (the canonical location
  # every other consumer resolves via target_output_root), NOT in the
  # source tree. asan_bin/asan_lib are TARGET_ROOT-relative and carry the
  # build-asan/ prefix in their value — same convention as a real
  # target.toml and as target_resolve_path. (Regression: the helper used
  # to look in-tree and re-join under build-asan/, doubling the prefix, so
  # the hint blocks rendered empty for every real target.)
  hint_root="$(mktemp -d)"
  trap 'rm -rf "$hint_root"' EXIT
  hint_slug="fakeproj"
  hint_target="$hint_root/targets/$hint_slug"
  mkdir -p "$hint_target/build-asan/src"
  cat > "$hint_target/build-asan/src/fake_cli" <<'BIN'
#!/usr/bin/env bash
true
BIN
  chmod +x "$hint_target/build-asan/src/fake_cli"
  mkdir -p "$hint_root/output/$hint_slug"
  cat > "$hint_root/output/$hint_slug/target.toml" <<TOML
asan_bin = "build-asan/src/fake_cli"
TOML
  hint_rendered=$(python3 "$render_py" "$hint_target" /tmp/cell "$hint_root")
  hint_only=$(printf '%s\n' "$hint_rendered" | awk '/### Driving the asan/{found=1} found')
  if [ -z "$hint_only" ]; then
    fail "hint block sentinel not found in rendered prompt — render.py read target.toml from output/<slug>/ and resolved asan_bin?"
  elif printf '%s' "$hint_only" | grep -E '\./crashes/' >/dev/null; then
    fail "benchmark_model_direct_render.py emits a relative './crashes/' path in the asan invocation hint or recipe"
  else
    pass "benchmark_model_direct_render.py reads canonical output/<slug>/target.toml and emits absolute hints"
  fi
  assert_match "/tmp/cell/crashes/CRASH-N" "$hint_rendered" \
    "rendered asan invocation hint uses the absolute output-dir crashes path"
  assert_match "$hint_target/build-asan/src/fake_cli" "$hint_rendered" \
    "asan_bin resolves to TARGET_ROOT/build-asan/... without doubling the prefix"
  # End-to-end: the python helper must inject the shared goal_framing so the
  # baseline opens with the same authorized-QA framing recon uses.
  assert_match "authorized, owner-run local" "$hint_rendered" \
    "benchmark_model_direct_render.py injects the shared goal_framing opener"
  if printf '%s' "$hint_rendered" | grep -qF -- "CTF-style"; then
    fail "rendered model-direct prompt still carries the bare 'CTF-style' opener"
  else
    pass "rendered model-direct prompt opens with the shared authorized-QA framing"
  fi

  # AUDIT_BUILD_SUFFIX (set per container image) must rewrite build-asan/
  # → build-asan<suffix>/ in the rendered paths, matching resolve_path.
  mkdir -p "$hint_target/build-asan-img9/src"
  cp "$hint_target/build-asan/src/fake_cli" "$hint_target/build-asan-img9/src/fake_cli"
  chmod +x "$hint_target/build-asan-img9/src/fake_cli"
  sfx_rendered=$(AUDIT_BUILD_SUFFIX="-img9" \
    python3 "$render_py" "$hint_target" /tmp/cell "$hint_root")
  assert_match "$hint_target/build-asan-img9/src/fake_cli" "$sfx_rendered" \
    "AUDIT_BUILD_SUFFIX rewrites build-asan/ to build-asan<suffix>/ in rendered hints"

  # The hints are NOT asan-only: the primary sanitizer is chosen from
  # [sanitizer].enabled, so a ubsan-only target (ubsan_bin lives UNDER
  # [sanitizer], not top-level) renders -fsanitize=undefined + UBSAN_OPTIONS,
  # not the asan flag or the find-only framing.
  ub_slug="fakeproj-ub"
  ub_target="$hint_root/targets/$ub_slug"
  mkdir -p "$ub_target/build-ubsan/src" "$hint_root/output/$ub_slug" \
    "$hint_root/lib"
  printf '#!/bin/sh\nexit 0\n' > "$ub_target/build-ubsan/src/cli"
  chmod +x "$ub_target/build-ubsan/src/cli"
  # _san_options() reads <script_root>/lib/sanitizer_options.conf (the single
  # source of truth); provide it so the canonical UBSAN_OPTIONS string is
  # exercised end-to-end, as it is when the benchmark passes the real root.
  cp "$SCRIPT_ROOT/lib/sanitizer_options.conf" "$hint_root/lib/"
  cat > "$hint_root/output/$ub_slug/target.toml" <<TOML
target = "$ub_slug"
[sanitizer]
enabled = ["ubsan"]
ubsan_bin = "build-ubsan/src/cli"
TOML
  ub_rendered=$(python3 "$render_py" "$ub_target" /tmp/cell "$hint_root")
  assert_match '### Driving the ubsan binary directly' "$ub_rendered" \
    "render selects ubsan from [sanitizer].enabled (not asan-only)"
  assert_match 'UBSAN_OPTIONS=' "$ub_rendered" \
    "ubsan render uses the UBSAN_OPTIONS env var from sanitizer_options.conf"
  if printf '%s\n' "$ub_rendered" | grep -qE 'fsanitize=address|Driving the asan'; then
    fail "ubsan-only target wrongly rendered asan hints"
  else
    pass "ubsan-only target does not leak asan-specific hints"
  fi

  # Go's race detector is a sanitizer-class signal, but it is driven through
  # [runner] rather than a clang build-<san>/ binary. It must not render as a
  # missing-native-build findings-only prompt when enabled.
  race_slug="fakeproj-race"
  race_target="$hint_root/targets/$race_slug"
  mkdir -p "$race_target" "$hint_root/output/$race_slug"
  cat > "$hint_root/output/$race_slug/target.toml" <<TOML
target = "$race_slug"
[sanitizer]
enabled = ["race"]
[runner]
bin = "go"
args = ["run", "-race", "{TESTCASE}"]
env = ["GORACE=halt_on_error=1"]
TOML
  race_rendered=$(python3 "$render_py" "$race_target" /tmp/cell "$hint_root")
  assert_match '### Driving the race runner directly' "$race_rendered" \
    "race target renders the runner-driven sanitizer hint"
  assert_match 'WARNING: DATA RACE' "$race_rendered" \
    "race target asks for Go race detector output"
  assert_match 'go run -race /tmp/cell/crashes/CRASH-N/testcase.go' "$race_rendered" \
    "race runner args expand {TESTCASE} into the crash directory"
  if printf '%s\n' "$race_rendered" | grep -qE 'No native sanitizer-instrumented build is present|Driving the asan'; then
    fail "race target wrongly rendered findings-only or asan-specific hints"
  else
    pass "race target does not render findings-only or asan hints"
  fi

  # In-tree target.toml is honored as a fallback (committed fixtures), but
  # only when the canonical output/<slug>/ copy is absent.
  rm -rf "$hint_root/output/$hint_slug"
  cat > "$hint_target/target.toml" <<TOML
asan_bin = "build-asan/src/fake_cli"
TOML
  fallback_rendered=$(python3 "$render_py" "$hint_target" /tmp/cell "$hint_root")
  if printf '%s\n' "$fallback_rendered" | grep -qE '### Driving the asan'; then
    pass "benchmark_model_direct_render.py falls back to in-tree target.toml"
  else
    fail "benchmark_model_direct_render.py did not honor in-tree target.toml fallback"
  fi
fi

# find_first_directive must use the absolute results_dir for its write
# instruction — a bare `findings/FIND-NNN-...` resolves against the
# agent's drifted cwd in harness mode the same way the model-direct
# bug did. Render with a fake results_dir and assert it appears.
ffd_rendered=$(python3 "$renderer" find_first_directive.md.j2 \
  --var "results_dir=/tmp/results-fake")
assert_match "/tmp/results-fake/findings/FIND-NNN" "$ffd_rendered" \
  "find_first_directive renders absolute results_dir-based findings path"
if printf '%s' "$ffd_rendered" \
   | grep -E '`findings/FIND-NNN' >/dev/null; then
  fail "find_first_directive still contains a bare relative 'findings/FIND-NNN' write path"
else
  pass "find_first_directive no longer carries a bare relative write path"
fi

# safety_framing wires results_dir through too — its CRASH-promotion
# gate and field-template references must use the absolute path so a
# `cd`'d agent never lands a crash report in the source tree.
sf_rendered=$(python3 "$renderer" safety_framing.md.j2 \
  --var "results_dir=/tmp/results-sf")
assert_match "/tmp/results-sf/crashes/CRASH-" "$sf_rendered" \
  "safety_framing renders absolute results_dir-based crashes path"
assert_match "/tmp/results-sf/findings/FIND-" "$sf_rendered" \
  "safety_framing renders absolute results_dir-based findings path"
assert_match "-DCMAKE_BUILD_TYPE=Release" "$sf_rendered" \
  "safety_framing recommends CMake Release sanitizer builds"
assert_match "meson.*--buildtype=release -Db_ndebug=true" "$sf_rendered" \
  "safety_framing recommends Meson release+ndebug sanitizer builds"
# Lines that still mention a bare `crashes/` or `findings/` (without
# the absolute prefix or NOVOCAB context) would be a regression.
# Tolerance: `output/<slug>/target.toml` legitimately stays bare
# (it's a read-only schematic path, not a write target).
bare_count=$(printf '%s' "$sf_rendered" \
  | grep -cE '`(crashes|findings)/' || true)
if [ "${bare_count:-0}" -eq 0 ]; then
  pass "safety_framing has no remaining bare-relative crashes/findings paths"
else
  fail "safety_framing still has $bare_count bare-relative crashes/ or findings/ references"
fi

# triage_legit_crash must also name the absolute path for the crashes/
# bucket it asks the validator to consider.
tlc_rendered=$(python3 "$renderer" triage_legit_crash.md.j2 \
  --var "results_dir=/tmp/results-tlc" \
  --var "require_web_gate=0" \
  --var "evidence=ASAN: heap-use-after-free")
assert_match "/tmp/results-tlc/crashes/" "$tlc_rendered" \
  "triage_legit_crash renders absolute results_dir-based crashes path"

# Session-rules reference docs must lead with the PATH CONVENTION
# preamble that maps every bare findings/ / crashes/ mention to
# ${RESULTS_DIR}. Without it, an agent that reads the digest will
# happily write to a relative path. The preamble is the
# documentation-level fix for the gemini-r1 2026-05-24 incident.
if grep -q "PATH CONVENTION" "$SCRIPT_ROOT/.agents/references/session-rules.digest.md"; then
  pass "session-rules.digest.md carries the PATH CONVENTION preamble"
else
  fail "session-rules.digest.md missing PATH CONVENTION preamble that maps bare paths to RESULTS_DIR"
fi
if grep -q "PATH CONVENTION" "$SCRIPT_ROOT/.agents/references/session-rules.md"; then
  pass "session-rules.md carries the PATH CONVENTION preamble"
else
  fail "session-rules.md missing PATH CONVENTION preamble that maps bare paths to RESULTS_DIR"
fi
# The "file FIND first" write instruction inside the digest must use
# the absolute path — it's the most-followed instruction in the doc.
if grep -q '`\${RESULTS_DIR}/findings/FIND-NNN' "$SCRIPT_ROOT/.agents/references/session-rules.digest.md"; then
  pass "session-rules.digest.md FIND-first instruction names absolute path"
else
  fail "session-rules.digest.md FIND-first instruction still uses a bare relative 'findings/' path"
fi
if grep -q '`\${RESULTS_DIR}/findings/FIND-NNN' "$SCRIPT_ROOT/.agents/references/session-rules.md"; then
  pass "session-rules.md FIND-first instruction names absolute path"
else
  fail "session-rules.md FIND-first instruction still uses a bare relative 'findings/' path"
fi

# Safety guard: rendering safety_framing or find_first_directive with
# RESULTS_DIR unset would expand `{{ results_dir }}/findings/` to
# `/findings/` (an absolute path under the filesystem root). The bash
# builders must refuse rather than silently emit that. Source lib/prompt.sh
# in a subshell with RESULTS_DIR unset and confirm both error out.
guard_out=$(unset RESULTS_DIR; bash -c '
  set +e
  # shellcheck disable=SC1091
  source "$1/lib/prompt.sh" 2>/dev/null
  build_safety_framing >/dev/null 2>&1
  echo "safety:$?"
  build_find_first_directive >/dev/null 2>&1
  echo "find_first:$?"
' _ "$SCRIPT_ROOT")
if printf '%s' "$guard_out" | grep -q '^safety:1$'; then
  pass "build_safety_framing refuses to render with empty RESULTS_DIR"
else
  fail "build_safety_framing should rc=1 with empty RESULTS_DIR, got: $guard_out"
fi
if printf '%s' "$guard_out" | grep -q '^find_first:1$'; then
  pass "build_find_first_directive refuses to render with empty RESULTS_DIR"
else
  fail "build_find_first_directive should rc=1 with empty RESULTS_DIR, got: $guard_out"
fi

teardown_test_env
summary
