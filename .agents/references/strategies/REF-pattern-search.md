# Pattern Search Reference (P)

**This is NOT a strategy — it's a grep-pattern library.** Use these patterns alongside
any strategy when you need to find specific code patterns in a subsystem. The LLM's
value is reasoning about results, not running the greps.

## Integer Arithmetic & Size Math

```bash
# Allocation with arithmetic (potential overflow):
rg -n '\* sizeof|malloc\(.*\*|calloc\(.*,' --type cpp <dir>/ | head -30
# Checked arithmetic usage (good — means unchecked exists nearby):
rg --count-matches 'CheckedInt|SafeInt|checked_' --type cpp <dir>/
# Signed integer types holding sizes (wraparound risk):
rg -n 'int32_t.*count|int32_t.*len|int32_t.*size' --type cpp <dir>/ | head -30
# Signed-to-unsigned conversions:
rg -n 'static_cast<(uint32_t|uint16_t|size_t)>.*[Ss]ize\|.*[Ll]en\|.*[Cc]ount' --type cpp <dir>/ | head -20
# Narrowing casts near allocation:
rg -n 'uint32_t.*size_t|size_t.*uint32_t|int32_t.*size_t' --type cpp <dir>/ | head -20
```

## Type Conversion Chains (consolidated)

Trace values passing through multiple implicit type conversions. Example:
`-1` as `int64_t` → `int` (truncated) → `unsigned` (wraps to 4B) → `malloc(size * elem)`
(size issue → small allocation) → bounds write.

```bash
# Start from allocation sites and trace size argument backwards:
rg -l 'malloc\(|new \w+\[|moz_xmalloc\(|SetCapacity\(|SetLength\(' --type cpp <dir>/
# Narrowing casts in function signatures:
rg -n 'static_cast<(uint32_t|int32_t|uint16_t)>' --type cpp <dir>/ | head -30
```

At each function boundary: does the type change? Does the caller pass `int64_t` but
the callee receives `int`? Trace 3-5 functions deep.

## Sentinel Value Collision (absorbs Strategy M)

Magic/sentinel values that collide with valid data at boundary inputs.

```bash
rg -l '= -1;|= 0x[fF]{2,}|= UINT(8|16|32|64)_MAX|= SIZE_MAX' --type cpp <dir>/
rg -l 'kInvalid|kNone|kNoIndex|INVALID_|NO_INDEX|npos' --type cpp <dir>/
```

For each sentinel: what's the valid data range? At MAX valid input, can the data
value equal the sentinel? If yes → sentinel check misidentifies valid data.

## Two-Pass TOCTOU

```bash
# SharedArrayBuffer/mmap spans (data can change between passes):
rg -n 'Span.*SharedArrayBuffer|Span.*mmap|Span.*shmem' --type cpp <dir>/ | head -20
```

Look for: pass 1 computes size, pass 2 fills buffer — if data changes between
passes, heap bounds write.

## Rust FFI Boundaries

**Only when targeting a specific FFI boundary.**

```bash
rg -n 'unsafe.*extern|#\[no_mangle\]' --type rust <ffi-dir>/ | head -30
rg -n 'from_raw_parts|Box::from_raw|slice::from_raw' --type rust <ffi-dir>/ | head -30
rg -n 'transmute|as \*const|as \*mut' --type rust <ffi-dir>/ | head -30
```

## Destructor & Allocation Patterns

```bash
rg -l '~[A-Z][a-zA-Z]+\(\)' --type cpp <dir>/
rg -n 'Release\(\)|Destroy\(\)|Shutdown\(\)' --type cpp <dir>/ | head -30
rg -n 'delete this|free\(.*\)|moz_free' --type cpp <dir>/ | head -30
rg -n 'new \w+\[.*[+*]' --type cpp <dir>/ | head -30
```

## Ignored Return + OUT-Parameter Consumption

Functions that return a status (`-1`/`NULL`/`0`/negative `errno`) and write a caller-supplied OUT buffer **only on success** are a classic uninit / partial-init source. When callers discard the return, the OUT buffer remains whatever the stack/heap contained on entry; downstream reads of that buffer can leak data, take a `.`-anchored truncation path through stack bytes, or feed wrong values to bounds math.

```bash
# Call discarded as a statement (no `=` and not inside `if`/`while`):
rg -n '^[[:space:]]+(gethostname|getcwd|realpath|readlink|recv|recvfrom|fread|read|sscanf|fscanf|getlogin_r|getservbyname_r|getaddrinfo|inet_pton|inet_aton)\s*\(' --type c --type cpp <dir>/ | head -30
# Wider sweep — any return-on-failure POSIX API as a bare statement:
rg -n '^[[:space:]]+[a-z_]+_r\s*\(' --type c --type cpp <dir>/ | head -30
# Other languages — error discarded by convention:
rg -n ', _ :=' --type go <dir>/ | head -20
rg -n 'catch\s*\([^)]*\)\s*\{\s*\}' <dir>/ | head -20
```

For each hit: locate the call's OUT parameter (`buf`, `addr`, `out_len`, the `&var` arg). Trace its downstream consumers. If the OUT is read on **any** path that does not first prove the call succeeded — including a `goto cleanup` path that runs the same finaliser as the success path — that is a candidate uninit / partial-init read.

**Family rule (not an exhaustive list):** any function whose documented contract is *"returns N≥0 on success, -1/NULL/negative on failure; OUT parameters mutated only on success"* qualifies. Library wrappers around POSIX `*_r` thread-safe variants are common entry points; `errno`-style C APIs and `Result`/`Option`-shaped wrappers in C++/C that the call site flattens to a raw pointer are the same shape.

**Comment-driven false negative:** comments saying *"never fails on this platform"* or *"we'd only get here if X"* often outlive the platform/condition. Treat them as needing fresh proof, not as a guard.

## Entropy / Mixing Operator Misuse

Identifiers semantically tied to entropy — `seed`, `nonce`, `salt`, `key`, `iv`, `hash`, `cookie`, `token`, `secret` — combined into a single value with non-mixing operators (`|=`, `+=`, `*=`, `&=`) instead of XOR or a real one-way function. OR saturates to ones, AND saturates to zeros, `+=` is biased by carries, `*=` is absorbed by any zero source. None of them mix — they degrade the entropy of the result below the entropy of the best individual source.

```bash
# Compound-assign into an entropy-shaped identifier with a non-XOR operator:
rg -n '\b(seed|nonce|salt|key|iv|hash|cookie|token|secret|entropy|rand_state)\b[[:space:]]*(\|=|\+=|\*=|&=)' --type c --type cpp <dir>/ | head -30
# Comments claiming the code "mixes" / "combines" / "folds" entropy:
rg -n -B1 -A2 '\b(mix|combine|fold|stir)\b.*\b(seed|entropy|hash)\b' --type c --type cpp <dir>/ | head -30
# Same patterns in other languages:
rg -n '\b(seed|nonce|salt|key|iv|hash|cookie|token|secret)\b\s*(\|=|\+=|\*=|&=)' --type rust --type go --type python --type java <dir>/ | head -30
```

For each hit, ask: is this combining **multiple sources** to produce a single output the program later uses as a hash table seed, RNG seed, cryptographic key, anti-collision token, or session identifier? If yes, compute the expected one-bit density of the result for `N` sources of width `W`:
- OR: `1 - 0.5^N` per bit. Three 32-bit OR'd values → ~87.5% ones.
- AND: `0.5^N` per bit. Same saturation, opposite direction.
- `+=`: biased toward the larger operand; collisions probable when sources share low bits.
- `*=`: absorbed by any single zero or low-entropy source.

XOR (`^=`) preserves entropy per bit. A cryptographic / non-cryptographic hash (`SipHash`, `xxhash`, `MurmurHash3` for non-adversarial use; SHA-2 family for adversarial) is the only safe combine when inputs may be caller-influenced.

**False positive to skip:** `|=` setting bit flags into a state word (where the operand is a `_FLAG_` constant, not an entropy source) is the dominant legitimate use of `|=`. Confirm the right-hand side is a varying source before filing.

## Truncation-Unsafe Fixed-Size Sinks

A `char buf[N]` filled by an API whose contract leaves NUL-termination *unspecified or omitted* on truncation, followed by a C-string consumer (`strchr`, `strlen`, `strstr`, `strcpy`, `printf("%s")`, `strcat`). Downstream consumer walks off the end of `buf` into adjacent stack/heap until it finds a stray NUL. Result: bounds read, uninit-byte leak through truncation point, or stack-canary disclosure.

```bash
# Fixed-size char buffers (destination side):
rg -n '\bchar\s+\w+\s*\[\s*[0-9]+\s*\]\s*;' --type c --type cpp <dir>/ | head -30
# Truncation-unsafe filling APIs (NUL guarantee absent or implementation-defined):
rg -n '\b(strncpy|readlink|gethostname|recv|recvfrom|GetEnvironmentVariableA|RegQueryValueExA|read|pread)\s*\(' --type c --type cpp <dir>/ | head -30
# C-string consumers immediately downstream:
rg -n '\b(strchr|strrchr|strstr|strlen|strcpy|strcat|strpbrk|strspn|strcspn)\s*\(' --type c --type cpp <dir>/ | head -30
```

For each hit, confirm three colocations on the same `buf`:
1. Stack/heap declaration of fixed size `N`.
2. A filling call whose contract on truncation is **not** *"always writes a trailing NUL within the first N bytes"*. Specifically:
   - `strncpy(dst, src, N)` does **not** NUL-terminate when `strlen(src) >= N`.
   - POSIX `gethostname` leaves termination *implementation-defined* on truncation; Linux glibc NUL-terminates (since 2.2), macOS / BSD historically did not.
   - `readlink`, `readlinkat` **never** NUL-terminate.
   - `recv`, `recvfrom`, `read`, `pread` return byte counts; they never NUL-terminate.
   - Win32 `GetEnvironmentVariableA` returns required size on truncation but the partial write is not NUL-anchored.
3. A C-string consumer downstream of (2) reading `buf` as a NUL-terminated string.

If all three hold and there is no explicit `buf[N-1] = '\0'` between (2) and (3), the consumer walks past the buffer end whenever the source length equals or exceeds `N`. Combined with caller control of the source length, this is a reachable bounds / uninit read.

**Family rule:** any sink-API whose contract is *"writes up to N bytes; NUL on truncation is unspecified, absent, or platform-dependent"* combined with downstream `<string.h>` consumption is a candidate. The API list above is a starter — verify each candidate by reading its current `man` page rather than trusting the enumeration.

## Dangerous-API Sinks

Use only when you already suspect a specific call path is vulnerable.
Modern C/C++ targets rarely contain raw `strcpy`/`sprintf`, so the
high-signal subset is narrower than the classic list:

```bash
# Raw memory copy where the length is a non-literal expression:
rg -n '\b(memcpy|memmove|bcopy)\s*\([^,]+,[^,]+,\s*[a-zA-Z_]' --type c --type cpp <dir>/ | head -30
# Stack-allocated buffer sized from a non-literal:
rg -n '\balloca\s*\(\s*[a-zA-Z_]|char\s+\w+\[\s*[a-zA-Z_]' --type c --type cpp <dir>/ | head -30
# Format-string sinks where the format argument is a variable (not a literal):
rg -n '\b(printf|fprintf|snprintf|syslog)\s*\([^"]*\b[a-z_]+\s*[,)]' --type c --type cpp <dir>/ | head -20
```

For each hit, ask: does an external boundary (file, network, IPC, argv,
env, JS bridge) influence the *length*, *buffer size*, or *format
string*? If yes → trace back to confirm. If a bounded variant (`memcpy`
with `sizeof(dst)`) is used, check that the size argument is the
*destination* capacity, not the source length — a common swap.
