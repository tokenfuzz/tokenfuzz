# Strategy S7: Adversarial Input & Fuzz Engineering

**Two complementary approaches:** (A) Write targeted adversarial inputs that stress
parsers/decoders at boundary conditions — delivered through the normal ASan pipeline,
no fuzzer needed. (B) Improve existing fuzz harnesses and generate smart seeds for
offline fuzzing.

**Part A is the primary approach.** LLM agents reason about what inputs break parsers;
brute-force mutation is better left to long-running fuzzer jobs.

**Review gate:** after 6 targeted inputs plus 3 fuzz seeds with 0 crashes and no HIT/NEEDS_TESTCASE lead, rotate strategy. Do not stop while a seed reaches the intended parser/decoder path.

## Part A: Adversarial Parser/Decoder Inputs (PRIMARY)

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
3. Deliver via `bin/probe scratch-N/tc.<ext>` — TARGET / HYPOTHESIS-ID come
   from the testcase header. For generic C/C++ targets, bin/probe selects
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

All Part A testcases go through the normal pipeline:
```bash
bin/probe scratch-N/testcase.html       # TARGET / HYPOTHESIS-ID from header
```

No fuzzer binary needed. No XPCOM init overhead. Same budget as any other testcase.

## Part B: Fuzz Harness + Seed Engineering (SECONDARY)

Generate smart seeds and harness improvements for offline fuzzing. Useful when you
encounter a subsystem with existing fuzz targets, but **don't spend more than 20%
of session time here** — seed generation is the deliverable, not fuzzer runtime.

### Smart seed generation

1. Read the fuzz harness source to understand input format requirements
2. Read the target parser code to identify unreached branches
3. Construct minimal seeds that pass header/magic validation and exercise specific branches
4. Write seeds to `scratch-N/fuzz-seeds/<TargetName>/` for offline use

**Do NOT run the fuzzer yourself** for browser-integrated targets (XPCOM init = ~5s/exec,
impractical for short sessions). For JS-only targets (`fuzz-tests` binary), short runs
(60s) are acceptable since init is fast.

### Harness gaps to document

When reading a fuzz harness, note gaps in `scratch-N/fuzz-harness-notes.md`:

| Gap | Impact | Example |
|-----|--------|---------|
| Missing API calls | Unreached code | Decoder tests Decode but not Seek/Reset |
| No multi-step sequences | State confusion unreachable | init→op→op→cleanup not tested |
| Fixed config | Config-dependent bugs missed | Optimizations always on/off |
| MOZ_RELEASE_ASSERT barriers | Fuzzer killed on mutation | Can't mutate past header validation |

These notes are valuable for the human to act on — they identify structural fuzz coverage gaps.

### Existing test mutation

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
