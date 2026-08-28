# Strategy S3: Rule-vs-Implementation Audit

**LLM-native — hold the rule and the implementation in context together, then
prove where they diverge.**

The rule may be a security invariant, a published specification, or the
equivalence contract between a general path and an optimized path. These are
one method, not three bug-class lanes:

1. state the exact rule;
2. identify the code that is supposed to enforce it;
3. trace caller-controlled input and the object/state the code later consumes;
4. show the missing, misordered, partial, or wrong-object check; and
5. record the nearest counterevidence and why it does not close this path.

When **Why ranked** names a security decision, start with Part 1. Do not make a
boundary card wait behind a generic standards sweep or fast-path search.

**Review gate:** after 5 distinct enforcement sites relevant to the card have
been checked and all satisfy their rules, rotate strategy. A boundary decision,
published requirement, and fast/slow pair each count as one site. Do not stop
while a mismatch still needs a testcase or differential probe. A source-proven,
security-relevant mismatch is already a finding: file (or augment) its
`findings/FIND-*` first, then pursue the probe (see "FILE FIND FIRST" in
session-rules.md).

## Part 1: Security-Boundary Rules

A security control is a rule with concrete security impact. Read the applicable RFC,
API contract, project documentation, or the invariant demonstrated by the
control's callers and safe siblings. Then trace the exact input, decision, and
effect. A scary sink or security noun is only a lead; the finding is the broken
rule on a reachable path.

| Card surface | Decision to audit | Questions to answer |
|---|---|---|
| access-control decision | who may act; which object/tenant is authorized; what privilege code runs with | Is the check absent on a sibling entrypoint, ordered after the effect, applied to a different object, or based on caller-controlled provenance? |
| identity/origin decision | whose request or peer this is; which origin/cookie/credential scope crosses a redirect | Are host/domain/path comparisons canonical and exact? Are credentials or cookies retained after the trust scope changes? |
| credential/verification decision | whether a password, certificate, host key, signature, token, claim, or assertion is genuine | Is failure fail-closed? Is the verified object the object later consumed? Are issuer, audience, subject, and algorithm bound together? |
| query/template construction | whether input can alter another parser's grammar | Can input change structure rather than values? Is quoting for the exact SQL/LDAP/XPath/template/header context, including identifiers? |
| outbound-request decision | which URL, host, address, scheme, and redirect destination a server-side fetch may reach | Are parsing, canonicalization, DNS/IP checks, redirect policy, and the final network sink enforcing the same destination rule? |
| filesystem path effect | which file is read, written, replaced, or deleted | Does canonicalization precede containment? Are absolute paths, encoded separators, symlinks, archive members, temp promotion, and recovery metadata constrained? |
| command/injection surface | whether caller-shaped data reaches a shell, loader, or interpreter grammar | Which argument is externally shaped? Is quoting assumed rather than enforced, or correct only for a different execution mode? |
| deserialization sink | which types and constructors input may select | Does the allow/deny resolver run before construction on the exact loader instance? Can aliases, containers, or nested values select a different type? |
| external-entity surface | what an XML/parser instance may fetch or expand | Are DTD/entity/external-resource controls mandatory and set on the exact parser, reader, transformer, or factory used by the sink? |

Before closing a path-taking sink, establish its actual grammar: determine
whether it is filesystem-only or a multiprotocol stream API. Some
path-taking language APIs also recognize URI schemes, mode prefixes, or
command channels;
when caller input selects one, audit the resulting network or interpreter
effect rather than treating it as ordinary traversal.

Work high-impact controls before secondary hygiene. Missing headers, weak cookie
flags, generic crypto configuration, or a bare credential field do not outrank
a reachable authorization bypass, injection, cross-host credential leak,
arbitrary file effect, or verification failure without a concrete path to
meaningful impact.

Two precision rules:

- **Counterevidence is part of the result.** Name the guard and why it does or
  does not cover this path. "No check found" is a lead; "the check at line N
  validates object A, but line M consumes caller-selected object B" is a
  finding.
- **A safe sibling does not close the family.** Once one root control is found,
  inspect its sibling routes, handlers, validators, concrete operations, and
  parser instances. Close each with exact evidence; do not infer safety from a
  neighboring hardened path.

Raw socket/TLS read-write endpoints remain S7 adversarial-input work. Protocol
state transitions, rollback, EOF handling, and re-authentication sequences are
S5 state work. S3 owns the security rule that selects a destination, identity,
credential, object, or effect; follow companion cards when the same file also
needs the S7 or S5 method.

## Part 2: Published-Spec Compliance

Pick a feature with a clear specification (W3C, WHATWG, ECMA, IETF RFC, public
API contract, or project documentation) and read the relevant requirement
beside the implementation.

| Spec language | What to verify in code |
|---|---|
| "MUST" / "MUST NOT" | The corresponding check exists and covers every consuming path. |
| Type constraints | Types and conversions preserve signedness, range, finiteness, and width. |
| Error conditions | Every required failure is handled and fails closed where the rule protects a boundary. |
| Step ordering | Reordering does not expose state before its prerequisite check. |
| "If X, throw/reject" | The implementation stops instead of continuing with invalid state. |

```bash
# Find spec-referencing code:
rg -l '// step |// Step |// https://.*spec|// per spec|// See spec|RFC ' --type cpp <dir>/
rg -l '\.webidl|\.idl' <dir>/
# Find type-sensitive paths:
rg -l 'IsArrayBuffer|IsSharedArrayBuffer|IsDetached|IsResizable' --type cpp <dir>/
```

## Part 3: Fast/Slow-Path Equivalence

Optimized paths are implementations of the same rule as the general path. Use
the slow path as executable specification: list its validation and state
transitions, then compare them one by one with the fast path.

```bash
# JIT/optimization fast paths:
rg -l 'MaybeOptimize|FastPath|Inline.*Call|tryOptimize|specialize' --type cpp <dir>/
# Two-pass algorithms where pass 1 computes size and pass 2 fills a buffer:
rg -l 'Span.*SharedArrayBuffer|ComputeSize.*Fill|encode.*decode' --type cpp <dir>/
```

For each pair:

1. What does the slow path validate that the fast path skips?
2. Can caller-controlled input select the fast path directly?
3. Does it assume type, bounds, alignment, identity, or state established only
   by the slow path?
4. For two-pass code, can shared or re-entrant state change between sizing and
   use (shared memory, mmap, IPC, callbacks)?

## Priority Targets

**Firefox:** WebCodecs, Streams API, WebGPU, WebTransport,
ResizableArrayBuffer, JIT compiler passes.

**General OSS:** authentication/authorization controls, HTTP redirect and
credential scoping, outbound fetch policy, TLS identity and protocol gates,
query/template/path construction, recovery/import/archive effects, and
optimized parser or codec paths.
