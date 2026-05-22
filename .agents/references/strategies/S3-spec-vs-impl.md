# Strategy S3: Spec-vs-Implementation & Fast-Path Audit

**LLM-native — no fuzzer or static analyzer can hold spec text and implementation
in context simultaneously and reason about divergence.**

Covers two related bug classes: (1) implementation deviates from spec, and (2)
optimized fast-paths skip validation that the slow-path enforces.

**Review gate:** after 5 spec requirements or fast-path pairs checked and all are correct, rotate strategy. Do not stop while a mismatch still needs a testcase or differential probe.

## Part 1: Spec Compliance Audit

1. Pick a feature with a clear spec (W3C, WHATWG, ECMA, IETF RFC, or project docs)
2. Read the spec section alongside the implementation
3. For each spec requirement, check:

| Spec language | What to verify in code |
|--------------|----------------------|
| "MUST" / "MUST NOT" | Corresponding check exists and covers all call sites |
| Type constraints (unsigned, clamped, finite) | Code uses matching types — no implicit sign extension or truncation |
| Error conditions | All spec-defined error conditions are handled (not just the common ones) |
| Step ordering | Code follows spec ordering — reordering creates windows where invariants don't hold |
| "If X, throw TypeError" | Code actually throws — missing throw → continues with invalid state |

```bash
# Find spec-referencing code:
rg -l '// step |// Step |// https://.*spec|// per spec|// See spec|RFC ' --type cpp <dir>/
rg -l '\.webidl|\.idl' <dir>/
# Find type-sensitive paths:
rg -l 'IsArrayBuffer|IsSharedArrayBuffer|IsDetached|IsResizable' --type cpp <dir>/
```

## Part 2: Fast-Path Divergence (absorbs Strategy F)

Optimized/JIT fast-paths that skip validation the general path enforces.

**The pattern:** slow-path validates input → fast-path checks a subset or nothing →
caller-shaped input takes fast-path with unchecked values.

```bash
# JIT/optimization fast-paths:
rg -l 'MaybeOptimize|FastPath|Inline.*Call|tryOptimize|specialize' --type cpp <dir>/
# Two-pass algorithms where pass 1 computes size, pass 2 fills buffer:
rg -l 'Span.*SharedArrayBuffer|ComputeSize.*Fill|encode.*decode' --type cpp <dir>/
```

For each fast-path:
1. What does the slow-path validate that the fast-path skips?
2. Can caller-controlled input reach the fast-path directly?
3. Does the fast-path assume properties (type, bounds, alignment) that only the slow-path guarantees?

**Two-pass TOCTOU:** If pass 1 computes size and pass 2 fills buffer, can data change
between the two passes? (SharedArrayBuffer, mmap'd files, IPC shared memory)

## Priority targets

**Firefox:** WebCodecs, Streams API, WebGPU, WebTransport, ResizableArrayBuffer, JIT compiler passes.
**General OSS:** TLS state machines (openssl/boringssl), HTTP/2-3 parsers, protocol
negotiation, codec fast-paths, crypto padding/verification.
