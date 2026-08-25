# Strategy S8: Property-Based Oracles

**Sanitizer-free oracles for silent-corruption bugs.** ASan catches memory-safety
violations; UBSan catches undefined behaviour; TSan catches races. None of them
catch *semantic* corruption: encode then decode and get back something different,
an identity key that drops a security discriminator, an idempotent operation
that mutates on the second call, or a function whose output sits outside its
declared numerical domain.

These bugs are real (silent data loss, signature confusion, cache poisoning,
sandbox-policy bypass) and invisible to S1–S7. S8 closes that gap by inferring
*properties* from the target's own type signatures, docstrings, and naming
conventions, then writing testcases whose oracle is the property — not a
sanitizer report.

## Pick the target by its security consumer (do this FIRST)

The property is the oracle; the **consumer** is the filter that decides whether a
counter-example is a finding or quality noise. Most encode/decode/normalize
functions, when a property breaks, produce a *correctness* bug — and the
findings gate (`AGENTS.md` FINDINGS) rejects "roundtrip drops whitespace",
"format differs from spec", and pure data-integrity bugs. Running a property on
every such function generates work the gate throws away. Don't.

Instead, choose what to test by walking *forward* from the function: does its
output reach a security decision — a sanitiser, an ACL / SOP / CSP / auth
check, a cache or signature lookup, an allocation size or resource limit? If
yes, the property is in scope. If the output only reaches display, logging, or
another pure-data path, a counter-example is an upstream correctness bug — record
it with `bin/state add-note` and move on; do **not** file it.
Use local source, call sites, comments, and docs for this filter.

Before testing a boundary value, quote the callee-specific input contract and
trace that value from the configured caller-controlled boundary through a real
caller.
Do not call a framework callback directly with a value its caller guarantees it
never passes. A generic error return does not override a concrete minimum,
buffer-size, or sequencing precondition; violating one is harness misuse, not a
property counter-example.

For managed-runtime oracles, catch only the parser or API's documented
input-rejection exceptions. Let every other exception escape so a shared
unexpected failure cannot be normalized into an apparently equal result.
If a managed testcase prerequisite is absent, print `NO_EXEC: <proof>` and
exit 2; do not raise an exception.

A wrong exception type or one request's uncaught exception is robustness, not
durable denial of service. File it only with proof that it crosses a security
boundary or terminates or blocks a durable service beyond that request.

| Category | In scope when the consumer is… | Security primitive it becomes |
|----------|--------------------------------|-------------------------------|
| Inverse (round-trip) | a trust/parse check enforced on one form but made on the other | smuggle a value past the check (parser/filter desync) |
| Idempotence | a sanitiser / canonicaliser feeding a filter, ACL, or SOP/CSP check | single-pass residual bypasses the check |
| Injectivity | a key/identifier explicitly promised unique within its domain | cache poisoning, identity confusion |
| Numerical domain | an allocation size, index, length, or resource limit | negative→huge-unsigned / `INT_MIN` → OOB or DoS |
| Format compliance | an escaper/emitter whose output crosses into another parser/context | injection across the context boundary |
| Equivalence | two documented-equivalent forms feed an auth, policy, or validation decision | policy bypass or interpretation differential |

Run a category procedure below only on functions with such a consumer. A clean
encode/decode pair that nothing security-sensitive consumes is not worth a
hypothesis. The closing **Delivery** section is the full filing rubric; this
table is the up-front filter so you *generate* security-relevant work instead of
*discarding* it at the end. If a card has no such pair, record the source proof
with `bin/state update-card --card-id <id> --status blocked --note <proof>`;
the queue keeps one card per strategy angle, so this closes only the S8 angle.

When the S8 card floor is complete, discard the card. Then end the model
session instead of claiming the next card. The worker pool relaunches from compact state, avoiding a growing
multi-card context without reducing investigation depth.

## The six property categories

Each category gets its own procedure, search patterns, oracle shape, and
worked-example skeleton. Run the procedure end-to-end on one category before
opening the next; mixing categories within a single hypothesis dilutes evidence.

### Category 1 — Inverse operations

**Property:** `decode(encode(x)) == x` and `encode(decode(y)) == y` for every
`y` the decoder accepts.

**Why this finds bugs:** the encoder and decoder are written by different people
at different times, against different drafts of the spec. Whenever the round trip
loses information (NUL byte in length-delimited container, percent-encoded
slash, surrogate-pair UTF-16 mis-pair, normalised vs raw URL), the asymmetry is
a counter-example regardless of whether anything crashed — and a *finding* when
a security consumer relies on the round trip (see *Pick the target by its
security consumer*).

**Highest yield:** JSON / CBOR / protobuf / msgpack / borsh serialisers, URL and
IDN normalisation, UTF-8↔UTF-16 conversion, HTML / XML round-trips, regex
match-then-replace, image / audio encode→decode, archive create→extract.

```bash
# Find files containing paired operations or an explicit round-trip claim,
# then read only 2-3 matching files:
bin/rg-safe -l '\b(encode|serialize|marshal|write|to_bytes|to_json|to_string)\w*\s*\(' <dir>/
bin/rg-safe -l '\b(decode|deserialize|unmarshal|read|from_bytes|from_json|from_string|parse)\w*\s*\(' <dir>/
bin/rg-safe -l 'round[\s_-]?trip|roundtrip|encode.*decode|decode.*encode|inverse' <dir>/
```

**Procedure:**

1. Pair the encode and decode functions by name (`encode_foo` / `decode_foo`,
   `to_x` / `from_x`).
2. Read both signatures — what types and shapes are accepted on each side?
3. Pick the *intersection* of accepted inputs (everything the encoder can emit
   *and* the decoder must accept) — that is the domain of the property.
4. Generate inputs covering: empty, boundary lengths, every "interesting" byte
   (`0x00`, `0x7F`, `0x80`, `0xFF`, `0xFFFD`), surrogate halves, BOM, deeply
   nested structures, max-int counts.
5. For each: compute `decode(encode(x))` and compare. **Any inequality is a
   counter-example** — bytes differ, length differs, normalisation differs, NUL
   handling differs, escape handling differs. File it only when a security
   consumer relies on the round trip (see *Pick the target by its security
   consumer*); otherwise log it as a correctness note.
6. Repeat with `encode(decode(y))` for every `y` the decoder accepts.

**Oracle:** byte-exact equality. If the spec permits ambiguity (multiple valid
encodings of the same value), the property becomes `decode(encode(x)) == x`
*one-way only* and `encode(decode(y))` is a separate property only valid for
inputs the encoder claims as canonical.

### Category 2 — Idempotence

**Property:** `f(f(x)) == f(x)` for every `x` in the documented domain.

**Why this finds bugs:** "applying again has no effect" is one of the most
common implicit contracts in software (normalisation, canonicalisation,
deduplication, sanitisation, cache fill, retry-safe API calls). Violations are
often state corruption that compounds — the second call observes mid-state from
the first.

**Highest yield:** path canonicalisation, URL normalisation, Unicode NFC/NFD,
HTML sanitisation, SQL identifier quoting, cryptographic key derivation
(`derive(derive(seed)) == derive(seed)` is *not* idempotent — common mistake),
cache warmup, deduplication.

```bash
# Find candidate files, then read only 2-3 with a documented fixed-point claim:
bin/rg-safe -l '\b(idempotent|canonicalize|normalize|sanitize|dedupe|deduplicate|reduce)\w*' <dir>/
```

**Procedure:**

1. Identify the function. Read the docstring for words like "canonical",
   "normalised", "stable", "fixed point", or any phrasing that implies "calling
   twice is the same as calling once."
2. Construct inputs covering the *near-canonical* cases — inputs that are
   *almost* in canonical form but differ from canonical form in a way the first
   call should fix. Examples: `"a//b"` vs `"a/b"` for paths, mixed-case Unicode
   that NFC should fold, comma-separated lists with trailing whitespace.
3. Compute `y1 = f(x)`, then `y2 = f(y1)`. Compare byte-by-byte.
4. A counter-example shape: `f("../a") == "a"` but `f("a") == "/a"` — the second
   call adds something the first call removed.

**Common false-negative:** the function returns the input unchanged for *already*
canonical inputs, so `f(canonical) == canonical` passes trivially. Make sure
your inputs are *non-canonical*.

### Category 3 — Injectivity (uniqueness contracts)

**Property:** for all distinct `x`, `y` in the documented domain,
`f(x) != f(y)` — only when the API explicitly promises uniqueness over that
domain, or when a structured key must preserve every security discriminator.

**Why this finds bugs:** ID generators wrap silently, identifier
canonicalisation collapses identities that policy treats separately, and
cache-key derivation drops a tenant, privilege, method, or origin field.

**Highest yield:** identifier interning, bounded ID allocators, and structured
cache-key derivation used by an authorization-sensitive lookup.

```bash
# Find files containing custom identity/key generation, then read 2-3 callers:
bin/rg-safe -l '\b(intern|symbol_id|gen_id|next_id|allocate_id|cache_key|key_for)\w*\s*\(' <dir>/
```

**Procedure:**

1. Quote the exact uniqueness/key-completeness contract and its domain.
2. For a structured key, vary one security discriminator at a time while
   holding every other field fixed. For a bounded ID allocator, test the
   documented lifetime and wrap boundary.
3. Minimize any pair that maps to the same identity and show the downstream
   lookup treats the pair as one principal/object.

**Never use ordinary hash collisions as an oracle.** A finite-width hash over a
larger domain must collide, and non-cryptographic hashes are not uniqueness
contracts. A collision matters only when the defect is a dropped required key
field or a broken explicit collision-handling contract.

### Category 4 — Numerical-domain invariants

**Property:** `f(x) ∈ [declared_min, declared_max]` for every `x` in the
declared input domain. Variants: `f(x) > 0` for "positive" returns, `f(x)` is
finite (no NaN, no Inf), `f(x)` is normalised (no subnormals), `f(x)` is a
probability (`0 ≤ f(x) ≤ 1`), `sum(f(xs)) ≈ 1.0` for distributions.

**Why this finds bugs:** numerical code accumulates rounding error, signed-
unsigned conversions wrap, intermediate computations overflow into signed
representation, "always positive" comes from a single sign check that misses
`-0.0`, `NaN`, subnormals, or the `INT_MIN` denial-of-service case.

**Highest yield:** statistical / scientific code (random samplers, distribution
fits, regression fits), media codec quantisers and de-quantisers (must stay in
sample range), audio gain pipelines, image colour transforms (must stay in
`[0, 255]` or `[0, 1]`), financial / currency arithmetic (must stay non-negative
for unsigned amounts), geometry / collision math (vectors must stay
normalised).

```bash
# Find files with explicit range/domain claims, then read 2-3 functions and callers:
bin/rg-safe -l 'positive|non[\s_-]?negative|always >= 0|in \[[0-9]|in \(0,|normalized|finite' <dir>/
```

**Procedure:**

1. Pick a function whose return type / doc declares a numerical invariant. Write
   the invariant down explicitly — `out >= 0`, `0 <= out <= 1`, `out finite`.
   Confirm that the tested input is within this function's contract and reaches
   it through a real caller-controlled path; do not invent out-of-contract API
   arguments just because zero, MIN, or MAX is mechanically available.
2. Generate inputs covering: zero, ±0.0, ±1, ±MAX, ±MIN, NaN, ±Inf, smallest
   subnormal, `INT_MIN` (the only int whose `abs()` is itself negative), array
   inputs with cancellation (`[1e18, 1.0, -1e18]` — exact answer 1.0; naive sum
   gives 0.0), array inputs that trigger Kahan-summation differences.
3. For each, evaluate `f(x)` and check the invariant. **Failure shapes:**
   - `f(MIN_NEGATIVE_INT)` returns negative because `abs(INT_MIN) == INT_MIN`
   - `f([1e18, -1e18])` returns 0 not the small residual
   - `f(NaN)` returns a value that *looks* finite but propagates NaN downstream
   - `f(subnormal)` flushes to zero on one platform and not another
4. Any violation is a counter-example; file it when the out-of-domain value
   feeds an allocation size, index, length, or resource limit (see *Pick the
   target by its security consumer*) — that is where it becomes an OOB or DoS
   primitive. Float-comparison tolerance is `f != f` (NaN
   self-inequality) and ULP-distance, never `==` on floats.

### Category 5 — Format-compliance regex

**Property:** every `f(x)` for `x` in the documented domain matches a regex
asserting the output's surface format. Examples: every emitted RGB CSS colour
matches `/^#[0-9a-fA-F]{6}$/`, every emitted JSON value satisfies
`/^(null|true|false|-?\d+(\.\d+)?([eE][-+]?\d+)?|"([^"\\]|\\.)*"|...)$/`, every
generated URL satisfies RFC 3986 ABNF.

**Why this finds bugs:** format generators that produce *almost*-compliant
output. Examples: CSS colour generator that emits `"#abc"` (3-digit) when the
spec required 6-digit; JSON emitter that omits the leading zero on `0.5`
producing `.5` (invalid JSON); URL builder that double-percent-encodes
already-encoded segments; SQL identifier escaper that misses ASCII control
characters.

Format-compliance is the *cheapest* property to write (one regex) and has the
highest false-positive rate (regexes are not full grammars) — so use a parser
when one exists, fall back to regex only for terminal-symbol-shaped formats.

```bash
# Find candidate files, then read 2-3 emitters and their consumers:
bin/rg-safe -l '\b(format|serialize|render|emit|to_string|escape|quote)\w*\s*\(' <dir>/
bin/rg-safe -l 'matches \^|regex.*= |format.*=' <dir>/
```

**Procedure:**

1. Identify the output format. Find the most-authoritative regex or grammar
   reference (RFC ABNF, W3C grammar, project doc).
2. If a parser exists (`url::Url::parse`, `json::from_str`, `cssparser`), use it
   as the oracle: `parser(emitter(x))` must succeed.
3. If no parser exists, write the regex from the spec — and document its
   limitations in the testcase header (regex catches surface format, not nested
   semantics).
4. Generate emitter inputs covering: empty, single byte, every byte 0x00–0xFF,
   non-BMP codepoints, very long strings, structurally nested values.
5. For each: emit, parse-or-regex-match. Failure = counter-example; file it
   when the emitter's output crosses into another parser/context where the
   non-compliant byte becomes an injection (see *Pick the target by its
   security consumer*).

### Category 6 — Semantic equivalence

**Property:** two input forms the public contract treats as equivalent must
produce the same security decision and security-relevant observable state.

Use this for alternate syntax, canonical/non-canonical representations, or
fast/slow paths that reach the same operation. Hold semantics constant, change
one representation feature, and compare the exact auth/policy/validation
result. A difference is a counter-example only after source or documentation
establishes equivalence; similar-looking inputs with different semantics are
not an oracle. This category owns generated differential checks such as
`USING(x)` versus its equivalent explicit join predicate; S3 owns a direct
one-form rule audit.

## The generator step (Hypothesis-style)

S8 is *property-based testing* — it expects an input generator, not a hand-
crafted seed. The generator's job: produce inputs covering the *documented
domain*, with enough adversarial bias that the property either holds or
demonstrates a counter-example within a bounded budget.

**Generator construction order:**

1. **Read the documented domain.** Type signature, docstring, runtime
   precondition checks. The domain is what the function *claims* it accepts —
   not what it *happens* to accept (those would be S2 invariant negations).
2. **Pick the shrinking strategy.** Reduce a counter-example to the smallest
   input and fewest differing fields. Reuse Hypothesis, QuickCheck, or proptest
   only when it is already available; do not install dependencies during an
   audit. A short deterministic generator and manual reducer are enough.
3. **Adversarial bias.** Pure uniform random is wasteful. Bias generators
   toward: empty, single-element, max-length, near-boundary numeric values,
   the documented "interesting" bytes for the format.
4. **Run budget.** Default 1000 cases per property. Bump to 100K for cheap
   pure-function properties (such as normalisation), drop to 100 for expensive
   ones (full encode/decode round-trip on multi-MB inputs).

For C / C++ targets without a property library, generate inputs in the
testcase harness directly (deterministic seeded PRNG → produce N inputs in a
loop → compute property → assert).

## Delivery through the harness

S8 testcases run through `bin/probe` like any other testcase. Two header
shapes:

**Property-as-oracle (no sanitizer crash expected):**
```
// TARGET: file:function:line
// HYPOTHESIS-ID: Hn
// CATEGORY: state                ← logic/state-corruption findings use 'state'
// PROPERTY: inverse|idempotence|injectivity|domain|format|equivalence
// PROPERTY-BUDGET: <N inputs tested>
// PROPERTY-ORACLE: <one-line description of what was compared>
```

**Property + sanitizer (counter-example also crashes ASan — rare bonus):**
```
// TARGET: file:function:line
// HYPOTHESIS-ID: Hn
// CATEGORY: <real category>
// PROPERTY: <one of the six>
```

On a counter-example, print a line beginning exactly `PROPERTY VIOLATION:` and
exit nonzero. `bin/probe` records this as `PROPERTY` (executed oracle evidence,
not a sanitizer crash and not `NO_EXEC`). Then minimize and file only if the
security-consumer test below is satisfied.

For an opaque byte input, keep the bytes exact and provide the fields that
cannot live in a header as flags:
```
bin/probe --hypothesis-id Hn --property inverse <testcase>
```

When the property is violated and ASan is clean, **first decide whether the
violation has a security implication** — the same consumer test from *Pick the
target by its security consumer* (above). Only security-relevant property
violations belong under `findings/FIND-*`. Pure correctness / data-integrity
/ robustness / spec-deviation violations stay in structured state as a note
and are NOT filed — `findings/` is for issues a security QA team needs to
triage, not a wishlist of upstream correctness bugs.

A property violation IS security-relevant if it:
- Crosses or weakens a security boundary (sandbox, SOP, privilege, isolation),
- Lets caller-controlled input change the output of a security-sensitive
  function (sanitiser, normalizer feeding an SOP/CSP/auth check, or structured
  key derivation feeding an authorization-sensitive lookup),
- Leaks data the caller should not see, or
- Lets the caller change interpretation of trusted data in a way an
  external party can leverage.

A property violation is NOT a finding (do not file) if it is:
- "Wrong output for input X" with no security consequence — e.g. an empty
  binary scalar decodes to three zero bytes instead of an empty array,
  a roundtrip drops trailing whitespace, decimal formatting differs from
  spec — these are correctness bugs, not security issues, no matter how
  cleanly they reproduce.
- "An app that trusts this might be confused" with no concrete security
  primitive — the library boundary is the gate. Speculation about
  downstream callers does not promote correctness bugs into findings.

When you do file, `report.md` must describe:

- Which property was checked (one of the six, named explicitly)
- The generator domain (what inputs were sampled, with what bias)
- The counter-example (minimised — run the shrinker before filing)
- The expected output vs actual output (byte-exact diff)
- The oracle (regex / parser / equality check / float-tolerance)
- **The security implication** — which boundary is crossed and how an
  external party can leverage it. If you can't write this paragraph
  concretely, don't file.

**Severity:** property-violation FINDings without a sanitizer crash score on
the same `bin/severity` rubric (impact × reach × confidence) as any other
FIND. Silent corruption in a public-API function reaches Medium ONLY when
that public API is a security-sensitive function (see the list above); in a
core security-boundary function it reaches High. Property violations in
non-security paths should not have been filed at all.

## Cross-strategy interactions

| Other strategy | Interaction |
|----------------|-------------|
| S3 (spec-vs-impl) | If the spec explicitly states the property, S3 finds it via spec-reading. S8 finds it without needing the spec by reading the code's own claims. |
| Cross-configuration comparison | Round-trip is a degenerate comparison (encoder vs decoder). S8 covers same-build property checks. |
| S6 (peer projects) | A property-violation in target X is a near-guaranteed property-violation in peer Y unless Y explicitly defended against it. After confirming an S8 finding, run the same property against peer projects from `output/<slug>/target.toml` `[s6_peers]`. |
| S7 (adversarial input) | S7 generates inputs to crash. S8 generates inputs to violate a property. Same generator infrastructure; different oracle. |

## Token efficiency

- Read ONE function pair (or one function for idempotence/injectivity/domain/
  format) per hypothesis. Do not bulk-load 20 function pairs.
- Keep only runnable H-prefixed testcases at the top of `scratch-N`. Put
  generators and trusted auxiliary data under `scratch-N/generators/`, or have
  the harness create and remove temporary data during its run; otherwise
  orphan enforcement will probe support files as if they were testcases.
- For C/C++ targets, build the property harness with `// HARNESS: harness.c`
  so `bin/probe` caches the compile.
- For interpreted targets (Python, Ruby, Node) the Hypothesis-equivalent
  library is the harness; no compile step.
- Counter-examples must be **shrunk** before filing — an un-minimised
  counter-example is rarely actionable for a maintainer.

## Priority targets

| Target domain | Best categories | Why |
|---------------|----------------|-----|
| Serialisation libraries (JSON, CBOR, MsgPack, protobuf, BSON) | Inverse | Encoder/decoder pairs are the property's natural shape |
| URL / IRI / IDN handling | Idempotence + Inverse | `normalize(normalize(u))` and `parse(format(u))` are both expected to hold |
| Unicode normalisers (NFC/NFD/NFKC/NFKD) | Idempotence | Definition of normalisation is "fixed point under further normalisation" |
| Identity and structured cache-key generators | Injectivity | Required discriminators must survive key construction |
| Codecs (image / audio / video) | Inverse + Domain | Lossy round-trip bounds, sample-range invariants |
| Statistical / numerical libraries | Domain | Documented distribution bounds, finite-output claims |
| HTML / XML / SVG sanitisers | Idempotence + Format | `sanitize(sanitize(x))` and parser-acceptance of output |
| Regex engines (encode-pattern→decode-result) | Inverse + Format | Captured group reconstruction round-trip |
| Crypto: KDF, signature serialisation, key encoding | Inverse + Injectivity | Encoding round-trips; key→identifier uniqueness |
| Cache / memoisation layers | Injectivity | Two requests that should miss must produce different keys |
