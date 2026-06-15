# Reproducer Templates

Use these patterns when writing testcases that reproduce a hypothesis under
ASan. Adapt to your specific theory of the defect. The goal is to deterministically
surface the suspected sanitizer diagnostic so the maintainer can patch it.

## Maintainer bundle (automatic, post-promotion)

After a CRASH dir passes triage, `bin/export-repro` runs automatically and converts the dir into a maintainer bundle:

```
crashes/CRASH-NNN-N/
├── REPORT.md           # bug summary + root cause + patch
├── reproduce.sh        # one command, no env vars, clones upstream + builds + runs
├── input.<ext>         # testcase bytes (renamed, headers stripped)
├── harness.c           # for // HARNESS: bugs only
├── sanitizer.txt       # original sanitizer output (full log)
└── .audit/             # your scratch artifacts (provenance, gitignored from share)
```

The maintainer runs `./reproduce.sh /path/to/upstream-src` (or no arg to clone fresh). You don't write `reproduce.sh` — it's generated from `target.toml` + your testcase + `// HARNESS:` header. Keep your scratch reproducer.sh / testcase.sh agent-internal; they end up in `.audit/`.

## Testcase header requirements (MANDATORY)

Every testcase file you write MUST start with a header tying it to a
state-file hypothesis. The audit harness greps these markers to detect orphan
testcases — an orphan testcase is discarded and counts against your quality
score. Use this exact comment format (adapt the comment delimiter per file type):

```
// TARGET: <relative/file.cpp>:<Function>:<line>
// HYPOTHESIS-ID: H<n>     (must match an entry in your AUDIT_STATE-<agent>.md)
// CATEGORY: <bounds|lifetime|type|size|uninit|state>
// HARNESS: <relative sibling harness source> (OPTIONAL)
```

Use native comments for testcase headers: `# TARGET: ...` in Python,
`// TARGET: ...` in C/C++/JS shell testcases, and
`<!-- TARGET: ... -->` in HTML.
If the hypothesis ID does not yet exist in your state file, add the hypothesis
row BEFORE writing the testcase. This is the coupling rule.

**`// HARNESS:` API probes:** point to a sibling harness source file.
For `.c`, `.cc`, `.cpp`, `.cxx`, or `.C`, `bin/probe` builds it on demand
using the target's ASan static library, includes, and link libs (read from
`output/<slug>/target.toml`). Probe also supports compiled `.rs`, `.go`,
`.swift`, and `.kt` harnesses plus interpreted harnesses such as
`.py`, `.rb`, `.php`, `.js`, `.mjs`, `.ts`, `.tsx`, `.java`, `.kts`,
`.r`, `.R`, `.sh`, and `.bash`. You no longer
need to write a `testcase.sh` that hand-codes the command.

## Seed corpus — prefer seed-plus-delta when the tree has seeds

Seeds bootstrap mutation. They're pre-validated inputs that already get
past upstream guards — copying one and applying a delta is usually faster
than writing from scratch. Writing from scratch is fine when no seed
matches; the rule is "check first, then choose."

```
# Ranks in-tree seeds by function-name / stem / filename match.
# Seed roots are auto-discovered from $TARGET_ROOT (cached at
# $RESULTS_DIR/.seed-roots) — works for any target, no per-target setup.
bin/find-seed lib/url.c:Curl_disconnect 15
bin/find-seed src/parser.c 20
bin/find-seed editor/libeditor/HTMLEditor.cpp:RemoveInlinePropertyAsAction 15
```

If `bin/find-seed` returns candidates, copy the closest match into your
scratch dir, rename it with your `HYPOTHESIS-ID` prefix, and apply mutations
on top. If it returns nothing relevant, write from scratch — seeds are an
aid, not a prerequisite.

## Coverage validation — coverage gate FIRST, ASan second

Default workflow: `bin/probe <testcase>` chooses the right runner.
For browser/js targets, `run-asan-multi` runs `hits.sh` first (cheap, no launch
lock) and only invokes ASan when the testcase reached the target. This prevents
0/5 variants from burning browser launches per dead-end. Generic C/C++ targets
do not support coverage gating; `bin/probe` uses `run-asan-multi generic` and
saves a sibling `.asan.txt`.

```
# Preferred wrapper — coverage-gated ASan in one call when supported.
# bin/probe reads TARGET / HYPOTHESIS-ID / HARNESS from the testcase header
# and discovers TARGET_ROOT/RESULTS_DIR by walking up to output/<slug>/.session-env.
bin/probe "${RESULTS_DIR}/scratch-1/tc_H3.html"

# Write under `$RESULTS_DIR/scratch-1/...`; do not write repo-root scratch dirs
# or compile root-level harness binaries by hand.

# API harness case (// HARNESS: harness.c in the testcase header):
bin/probe "${RESULTS_DIR}/scratch-1/tc_H3.xml" -- 8 100        # trailing args go to the harness

# exit 0 → HIT + ASan ran cleanly, or generic run completed
# exit 1 → MISSED — ASan SKIPPED. Revise input; don't discard; no budget spent.
# exit 2 → tool/env problem, missing testcase, or no execution evidence
```

Default 1 run (exploration). Add `--confirm` (5 runs) ONLY after you've seen one
crash and need reproducibility proof — timing-dependent UAFs don't crash every
run. A 0/5 exploration variant is 4 wasted browser launches.

```
bin/probe --confirm "${RESULTS_DIR}/scratch-1/tc_H3.html"      # 5 runs to confirm a crash
```

Raw `bin/hits` is still available when you need the coverage verdict
without ASan (e.g., checking whether ANY existing testcase reaches a target):

```
bin/hits --testcase ${RESULTS_DIR}/scratch-1/tc_H3.html \
                --want 'nsTextFrame::ClearTextRun|nsTextFrame.*:.*123' \
                --mode browser
```

Record the HIT/MISSED verdict in your state file's Working Context. A MISSED
result means the hypothesis is not disproven — the input didn't even run the
code. Discarding on a MISSED is invalid.

## Lifetime / re-entrancy reproducer (most common Firefox class)
```html
<script>
console.log('TESTCASE_EXECUTED');
// Phase 1: Create the object whose lifetime is in question
let target = new SomeAPI();
// Phase 2: Register a callback that releases target
someObserver(() => { target.destroy(); gc(); gc(); });
// Phase 3: Trigger the callback while target is still in use
target.operationThatCallsScript();
// Phase 4: Encourage allocator reuse so a stale reference is detected
for (let i = 0; i < 1000; i++) new ArrayBuffer(TARGET_SIZE);
setTimeout(() => window.close(), 10000);
</script>
```

## Allocator-shaping reproducer
```javascript
// Pre-fill the free list with same-size objects so the released slot has a
// deterministic neighbor. This makes a stale-reference access observable
// rather than benign.
let pool = [];
for (let i = 0; i < 500; i++) pool.push(new ArrayBuffer(FREED_OBJ_SIZE));
// Trigger the suspected release
triggerBug();
// Release alternate entries to create holes in the pool
for (let i = 0; i < 500; i += 2) pool[i] = null;
gc();
// Allocate a different-typed but same-size replacement so a use of the
// stale reference reads through the wrong type
for (let i = 0; i < 250; i++) new Float64Array(FREED_OBJ_SIZE / 8);
```

## GC-interleaved operations
```javascript
// Don't just gc() once — interleave with every operation so a pointer
// invalidated by GC after an earlier step is observed by a later step.
obj.step1(); gc(); gc();
obj.step2(); gc(); gc();
obj.step3();
```

## JIT type-assumption reproducer
```javascript
// Warm the JIT with one type pattern so it specializes on assumed bounds,
// then call with a value that violates the assumption.
function f(x) {
  let arr = [1.1, 2.2, 3.3];
  let idx = x & 0x7fffffff;
  return arr[idx];
}
for (let i = 0; i < 100000; i++) f(0);
print(f(-1));  // surfaces a bounds diagnostic if the range check was elided
```

## Irregexp register pressure
```javascript
// Complex pattern with many capture groups exercises the register allocator.
let re = new RegExp('(' + 'a'.repeat(100) + ')'.repeat(100));
try { 'a'.repeat(1000).match(re); } catch(e) {}
```

## DOM re-entrancy reproducer
```html
<script>
console.log('TESTCASE_EXECUTED');
let div = document.createElement('div');
document.body.appendChild(div);
let obs = new MutationObserver(() => {
  div.remove();
  for (let i = 0; i < 10; i++) gc();
  for (let i = 0; i < 1000; i++) new ArrayBuffer(64);
});
obs.observe(div, { attributes: true });
div.setAttribute('class', 'trigger');
setTimeout(() => window.close(), 10000);
</script>
```

## DOM re-entrancy (minimal)
```html
<script>
console.log('TESTCASE_EXECUTED');
let elem = document.createElement("div");
document.body.appendChild(elem);
new ResizeObserver(() => { elem.remove(); gc(); }).observe(elem);
elem.style.width = "200px";
setTimeout(() => window.close(), 10000);
</script>
```
