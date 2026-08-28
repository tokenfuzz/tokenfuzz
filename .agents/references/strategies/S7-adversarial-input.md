# Strategy S7: Adversarial Input Engineering

Write targeted adversarial inputs that stress parsers and decoders at boundary
conditions, delivered through the normal sanitizer pipeline. No fuzzer and no
fuzz harness: reason backwards from parser code to the input that reaches one
specific error path. A minimal deterministic harness is still the normal
`bin/probe` carrier when the documented boundary is a C/C++ library API.

**Fuzzing belongs to S4.** If this surface deserves a fuzz target — an
untrusted-input entry point on a published API with no harness driving it —
that is a boundary-directed fuzzing card, not a detour here. See
`S4-directed-fuzzing.md`. Do not build a fuzz harness, generate a corpus, or run
a fuzzer under S7.

**Review gate:** after 6 targeted inputs with 0 crashes and no
HIT/NEEDS_TESTCASE lead, rotate strategy. Do not stop while an input is
reaching closer to the intended parser/decoder path.

`DISCARDED` closes one named input shape or effect, not every effect at that
function. When an executed deserialization, reflection, or mutation route is
rejected because the report named only the sink, spend the next hypothesis on
one concrete encoded size/count, loaded type or magic hook, native consequence,
or security consumer at that function. Move elsewhere only after testing one
or recording source/runtime proof that none exists; never refile the sink-only
claim.

When the S7 card floor is complete, discard the card and end the model session
instead of claiming the next card. A concrete card retires; a broad whole-file
card records the dry pass and may be reoffered with its history for a different
trigger or concrete effect until campaign limits.

**Scratch hygiene:** create only the final H-prefixed testcase in `scratch-N`.
Copy or generate a valid seed straight into that path, then mutate it in place;
do not leave unmodified or intermediate seed files there. Housekeeping treats
every scratch input as a runnable testcase and will otherwise probe it again.

**Route gate:** before committing a hypothesis, verify from the configured
runner and build metadata that `bin/probe` can invoke the card's exact parse or
decode surface with the crafted testcase. A runner fixed to another subcommand
does not make the surface reachable merely because the same binary contains
it. If no route exists, run `bin/state update-card --card-id <id> --status
blocked --note <configuration-and-source-proof>`; do
not create a hypothesis or replace the missing route with an undocumented
wrapper, trusted setup, or source-only rule audit. A one-shot API harness is a
valid route only when it faithfully calls a documented public library boundary.
Startup or teardown code that executes identically for every testcase is not
an input route: the testcase bytes must select or shape the named boundary,
not merely cause the process to initialize it.

If a managed testcase prerequisite is absent, print `NO_EXEC: <proof>` and
exit 2; do not raise an exception.

**Direct-input gate:** the trigger must occur during one documented parse or
decode operation on the crafted input. Do not add a dump, encode, round trip,
or other trusted follow-up operation merely to make an output-only surface
reachable; block that card for S7 and leave the surface to its owning strategy.

**Managed runtimes:** catch the parser library's documented rejection
exception around the one target call, even when the crafted input is expected
to be valid. Let every other exception escape. A normal rejection is CLEAN
evidence; an uncaught expected parse error is testcase noise that looks like a
runtime crash. An unexpected exception type is still only a robustness or API
contract defect unless you can show it escaping a real request/process
isolation boundary or causing another concrete security impact; do not confirm
or file it merely because it reproduces. In particular, an exception such as
`RecursionError` that ends only the current parse or request is not durable
denial of service.

## Adversarial Parser/Decoder Inputs

Unlike S3 (spec-vs-impl) which compares spec text to implementation, this approach
needs no spec. Feed adversarial inputs to parsers and decoders, targeting structural
weaknesses in how they handle crafted data.

**LLM advantage:** Reason backwards from parser code to construct inputs that reach
specific error paths, boundary conditions, and allocation patterns — something
random mutation can't do efficiently.

### Technique 1: Truncation at every parse phase

Parsers process input in phases (header → metadata → body → trailer). Truncating
at phase boundaries exercises error-recovery code.

```
1. Read the parser's main loop to identify phase transitions
2. For each phase boundary: construct a valid-up-to-that-point input, then truncate
3. Deliver via `bin/probe "${RESULTS_DIR}/scratch-N/tc.<ext>"` — TARGET / HYPOTHESIS-ID come
   from the testcase header. Opaque bytes stay exact and use
   `bin/probe --hypothesis-id H-... <testcase>`. For generic C/C++ targets, bin/probe selects
   the generic ASan path automatically.
```

**Example (image decoder):**
```html
<script>
// Truncated PNG: valid 8-byte magic + IHDR chunk header, no IHDR data
const hex = '89504E470D0A1A0A0000000D49484452';
const bytes = new Uint8Array(hex.match(/../g).map(h => parseInt(h, 16)));
const blob = new Blob([bytes], {type: 'image/png'});
const img = new Image();
img.src = URL.createObjectURL(blob);
document.body.appendChild(img);
setTimeout(() => window.close(), 5000);
</script>
```

### Technique 2: Size issue in size/length fields

Binary formats embed sizes as integers. Overflow, underflow, or mismatch between
declared size and actual data triggers bounds issues in parsers that trust the field.

```
1. Find size/length fields in the format (grep for Read.*size, Read.*length, Read.*count)
2. Construct inputs where:
   - Declared size = 0 (underflow: zero-length allocation then write)
   - Declared size = 0xFFFFFFFF (overflow: wraps to small allocation)
   - Declared size = actual_size + 1 (off-by-one read past buffer)
   - Declared size = actual_size - 1 (trailing byte left in stream, confuses next parse)
   - Count field = 0x7FFFFFFF (signed overflow when multiplied by element size)
```

**Search patterns:**
```bash
# Size fields read from input:
rg -n 'Read(U32|U16|U8|LE32|BE32|Int).*[Ss]ize\|[Ll]ength\|[Cc]ount' --type cpp <dir>/
# Allocation from input-controlled size:
rg -n 'malloc\|calloc\|new.*\[.*Read\|SetLength\|SetCapacity\|resize' --type cpp <dir>/
# Unchecked multiplication (count * elem_size):
rg -n 'static_cast.*\*\|CheckedInt' --type cpp <dir>/
```

### Technique 3: Encoding/charset boundary cases

Text parsers that handle encoding transitions, BOM detection, or charset fallback
have edge cases at encoding boundaries.

```
Inputs to construct:
- BOM followed by incompatible encoding (UTF-8 BOM + Shift-JIS body)
- Mid-stream encoding switch (valid UTF-8, then raw 0x80-0xFF bytes)
- Overlong UTF-8 sequences (2-byte encoding of ASCII characters)
- Surrogate halves in UTF-16 (unpaired 0xD800 or 0xDC00)
- Null bytes mid-string (C string terminator inside length-delimited data)
- Mixed Latin1/TwoByte in rope strings (SpiderMonkey-specific)
```

### Technique 4: Format confusion / polyglot inputs

When code dispatches on content-type or magic bytes, construct inputs that are
valid in one format but get routed to a different parser.

```
Inputs to construct:
- Wrong MIME type for valid data (image/png with JPEG data)
- Polyglot files (valid as both HTML and SVG)
- Content-length mismatch with Transfer-Encoding
- Nested containers (ZIP inside JAR inside ZIP)
- Magic bytes of format A followed by body of format B
```

### Technique 5: Resource exhaustion boundaries

Not OOM (which is noise) but controlled allocation that hits implementation limits.

```
Inputs to construct:
- Image with 1x(2^31-1) dimensions (huge allocation from small input)
- Deeply nested elements (4096+ nesting depth)
- Millions of small allocations (many small chunks, not one big one)
- Array/table with count=MAX but tiny actual data (sparse allocation)
```

### Delivery

Every testcase goes through the normal pipeline:
```bash
bin/probe "${RESULTS_DIR}/scratch-N/testcase.html"       # TARGET / HYPOTHESIS-ID from header
```

No fuzzer binary needed. No XPCOM init overhead. Same budget as any other
testcase. When a surface resists hand-written inputs because it is guarded by a
format or checksum a reasoned guess cannot satisfy, that is the signal to file
an S4 card for it rather than to keep guessing here.

## Existing parser fixture mutation

Project fixtures are often the best valid seeds. Copy one to the final
H-prefixed testcase, then change only its input bytes: truncate at a field
boundary, alter a length/count, substitute an encoding edge, or deepen a
nested value. Do not mutate test code, call order, synchronization, setup, or
cleanup; those are state/lifetime experiments owned by S5, not S7 inputs.

## Priority targets for adversarial inputs

| Target | Format | Why | Grep |
|--------|--------|-----|------|
| image/decoders | PNG/AVIF/WebP/JXL | Binary formats, size fields everywhere | `ReadUint32\|ReadUint16\|mImageSize` |
| parser/html | HTML | State machine tokenizer, encoding detection | `nsHtml5Tokenizer\|mState` |
| netwerk | HTTP headers | Text protocol, many edge cases | `ParseHeader\|ParseStatusLine` |
| modules/freetype2 | TTF/OTF | Complex binary font parsing | `FT_Stream_Read\|TT_Load` |
| dom/media | MP4/WebM containers | Nested box structures with sizes | `BoxReader\|ReadU32\|mHeaderSize` |
| third_party/libwebrtc | SDP/STUN/RTP | Network protocol parsing | `ParseLine\|ReadStunAttribute` |
