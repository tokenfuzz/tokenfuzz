# Strategy S7: Adversarial Input Engineering

Write targeted adversarial inputs that stress parsers and decoders at boundary
conditions, delivered through the normal sanitizer pipeline. No fuzzer, and no
fuzz harness: reasoning backwards from parser code to the input that reaches a
specific error path is what an LLM does better than mutation, and it needs
nothing built.

**Fuzzing belongs to S4.** If this surface deserves a fuzz target — an
untrusted-input entry point on a published API with no harness driving it —
that is a boundary-directed fuzzing card, not a detour here. See
`S4-directed-fuzzing.md`. Do not build harnesses, generate corpora, or run a
fuzzer under S7.

**Review gate:** after 6 targeted inputs with 0 crashes and no
HIT/NEEDS_TESTCASE lead, rotate strategy. Do not stop while an input is
reaching closer to the intended parser/decoder path.

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

## Existing test mutation

Mutate the project's own test suite to violate preconditions:

| Mutation | What it breaks | Example |
|----------|---------------|---------|
| Remove waits/syncs | Race exposure | Delete `await`, `sleep`, `sync()` |
| Double operations | Lifetime issue/init | `open()` twice, `close()` twice |
| Reverse order | State confusion | Close before open |
| Boundary values | Size issue | Replace `10` with `MAX_INT`, `0`, `-1` |
| Skip cleanup | Leak-to-reuse | Delete `finally`, `cleanup()` |

```bash
# Tests near recent prior fixes:
git log --name-only --diff-filter=M --since="6 months ago" -- "*/test*" | sort -u | head -20
```

## Priority targets for adversarial inputs

| Target | Format | Why | Grep |
|--------|--------|-----|------|
| image/decoders | PNG/AVIF/WebP/JXL | Binary formats, size fields everywhere | `ReadUint32\|ReadUint16\|mImageSize` |
| parser/html | HTML | State machine tokenizer, encoding detection | `nsHtml5Tokenizer\|mState` |
| netwerk | HTTP headers | Text protocol, many edge cases | `ParseHeader\|ParseStatusLine` |
| modules/freetype2 | TTF/OTF | Complex binary font parsing | `FT_Stream_Read\|TT_Load` |
| dom/media | MP4/WebM containers | Nested box structures with sizes | `BoxReader\|ReadU32\|mHeaderSize` |
| third_party/libwebrtc | SDP/STUN/RTP | Network protocol parsing | `ParseLine\|ReadStunAttribute` |
