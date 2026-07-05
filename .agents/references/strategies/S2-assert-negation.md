# Strategy S2: Invariant Negation

**The most mechanical strategy. Developers, algorithms, and preconditions all declare
assumptions. You break them.** In release/optimized builds, debug assertions are removed —
if the assertion was the ONLY check, the violated invariant reaches production code.

**Review gate:** after 20 invariants classified with 0 reachable from untrusted input with security impact, rotate strategy. Do not stop while a reachable invariant still needs a testcase.

## Three Sources of Invariants

### Source 1: Debug Assertions (original AA)

Debug-only checks that vanish in release builds.

```bash
# Bounds asserts — bounds issue if violated in release:
rg -l 'MOZ_ASSERT\(.*< .*\.(Length|Size|Count|Capacity)\(\)\)' --type cpp <dir>/
# Type asserts — type-mismatch if violated:
rg -l 'MOZ_ASSERT\(.*Is<|MOZ_ASSERT\(.*IsA<|MOZ_ASSERT\(.*->Is\(' --type cpp <dir>/
# State asserts — logic bugs if violated:
rg -l 'MOZ_ASSERT\(.*mState\|MOZ_ASSERT\(.*initialized\|MOZ_ASSERT\(.*ready' --type cpp <dir>/
# Size asserts — size issue if violated:
rg -l 'MOZ_ASSERT\(.*<=.*MAX\|MOZ_ASSERT\(.*<.*kMax' --type cpp <dir>/
# For non-Firefox C/C++ projects:
rg -l 'assert\(.*<\|assert\(.*>\|assert\(.*!=\|assert\(.*==' --type cpp <dir>/
rg -l 'DCHECK\(|BSSL_CHECK\(' --type cpp <dir>/   # Chromium/BoringSSL style
```

**Classify each assert:** bounds / type / state / size / null.
Skip null (usually DoS only). Focus on bounds, type, size.

### Source 2: Algorithm Invariants (absorbs Strategy O)

Implicit assumptions in algorithm code — often in comments or a single assert.

| Invariant | Breaks when | Impact |
|-----------|------------|--------|
| Output size <= input size | Dictionary/table fills at capacity | Heap bounds write |
| Counter < MAX | Exactly MAX elements | Size wrap → bounds |
| Array stays sorted | Specific insert-delete sequence | Binary search returns wrong index |
| Size fits in type | Value at 2^N boundary | Truncation → small alloc → bounds |
| Operation is idempotent | Concurrent or re-entrant call | Lifetime issue, state stomp |

```bash
rg -l '// assum|// invariant|// guarantee|// always|// never|// at most' --type cpp <dir>/
```

**Priority:** compression (brotli, zlib, woff2), font parsing (freetype2), image
scaling (gfx/), any "fast path" with a validity comment.

### Source 3: Multi-Precondition Gates (absorbs Strategy N)

Code behind 3+ simultaneous conditions that fuzzers almost never satisfy together.
**LLM advantage:** reason about multiple constraints simultaneously.

```bash
rg -n 'if.*&&.*&&' --type cpp <dir>/ | head -30
rg -n '// edge case|// corner case|// rare|// unlikely' --type cpp <dir>/ | head -20
```

For each gated block: can ALL preconditions be satisfied by untrusted input simultaneously?
If yes → write a testcase that satisfies every condition at once. The code behind the gate
is rarely tested and may contain unchecked operations.

### Source 4: WebIDL / IDL Attribute Mismatches

WebIDL is a W3C standard used by every browser engine. Each binding
generator adds engine-specific extended attributes that the C++ side
is expected to satisfy. A mismatch between the IDL contract and the
implementation is an invariant violation callers may rely on without
realizing it.

| Engine | Throws | Identity / shape | Caller-trust |
|--------|--------|------------------|--------------|
| Gecko (Firefox, SpiderMonkey) | `[Throws]` | `[SameObject]`, `[NewObject]`, `[Pure]` | `[ChromeOnly]`, `[NeedsCallerType]`, `[SecureContext]` |
| Blink (Chromium, V8) | `[RaisesException]` | `[SameObject]`, `[NewObject]`, `[CallWith=...]` | `[Exposed=...]`, `[SecureContext]`, `[CrossOriginIsolated]` |
| WebKit (Safari, JSC) | `[MayThrowException]` | `[NewObject]`, `[SameObject]`, `[ImplementedAs=...]` | `[Exposed=...]`, `[SecureContext]` |

Standard WebIDL attributes shared across engines: `[SameObject]`,
`[NewObject]`, `[Exposed=...]`, `[SecureContext]`, `[Unscopable]`.

```bash
# Engine-agnostic — match common annotations across all .idl/.webidl files:
rg -n '\[Throws\]|\[RaisesException\]|\[MayThrowException\]' <dir>/ 2>/dev/null | head -20
rg -n '\[SameObject\]|\[NewObject\]|\[Pure\]' <dir>/ 2>/dev/null | head -20
rg -n '\[Exposed=|\[SecureContext\]|\[ChromeOnly\]|\[CallWith=' <dir>/ 2>/dev/null | head -20
```

Read the IDL declaration alongside the generated binding and the C++
implementation. Mismatches that violate caller assumptions even without
an explicit assert:
- `[NewObject]` method returns a cached instance → object identity bug
- `[SameObject]` getter allocates fresh on each call → identity bug
- `[Throws]` / `[RaisesException]` method allocates *before* the throw
  path → leak or partial-state escape
- `[SecureContext]` / `[ChromeOnly]` method reachable from an
  unprivileged context → trust-boundary bug
- `[Exposed=Window]` interface accessible from Worker → exposure bug

## Procedure (all four sources)

1. Collect invariants from the target subsystem (assertions + algorithm assumptions + gates + IDL annotations)
2. For EACH: can untrusted input make the assumption false?
3. If yes → in production, code continues with violated invariant → write testcase
4. Prioritize: bounds > size > type > state > null

Once step 3 source-proves a security-relevant defect, file (or augment) its
`findings/FIND-*` before building the reproducer — the testcase is confirmation,
not a precondition (see "FILE FIND FIRST" in session-rules.md).
