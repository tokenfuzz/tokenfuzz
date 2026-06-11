# Strategy Reference Files

Read only the strategy file you need, not all of them.

## Token Efficiency Rules (apply to ALL strategies)

- **Batch searches:** Run multiple `rg` commands in one shell turn (`cmd1 && cmd2 && cmd3`).
- **Two-phase search:** Filename-only sweep first (`rg -l`), then inspect only the 2-3 most promising files with `rg -n` or `sed -n`.
- **Scope every search:** Always scope with a directory path or `--glob`. Never search from `.` or scan `output/`.

## Strategy Priority (8 strategies + 1 pattern reference)

| Priority | Strategy | File | When |
|----------|----------|------|------|
| **1st** | **S1: Prior-fix + regression variant** | `S1-prior-fix-review.md` | Always first. 3/7 historical findings. Mines own fixes AND refactors. |
| **2nd** | **S2: Invariant negation** | `S2-assert-negation.md` | Mechanical: asserts, algorithm assumptions, multi-precondition gates. |
| **3rd** | **S3: Spec-vs-impl + fast-paths** | `S3-spec-vs-impl.md` | LLM-native: spec compliance AND optimization fast-path skips. |
| **4th** | **S4: Advanced differential** | `S4-differential.md` | Beyond basic JIT diff (now automatic): GC zeal, wasm tiers, cross-build. |
| **5th** | **S5: Lifetime & state violation** | `S5-reentrancy.md` | Re-entrancy, error-path cleanup, thread races, state machine sequences. |
| **6th** | **S6: Cross-project variant mining** | `S6-cross-project.md` | Mine peer projects' fixes for bug classes in target. |
| **7th** | **S7: Adversarial input & fuzz engineering** | `S7-fuzz-improvement.md` | Targeted parser/decoder boundary inputs + smart seed generation. |
| **8th** | **S8: Property-based oracles** | `S8-property-based.md` | Sanitizer-free oracles: idempotence, injectivity, numerical domain, format compliance, inverse operations. |
| Ref | **REF: Pattern search library** | `REF-pattern-search.md` | Not a strategy — grep patterns for use alongside any strategy. |

**Rotation rule:** The harness may rotate strategy after sustained dry work, with a
longer runway for S1 prior-fix review. Self-rotate only when the current strategy
is not producing concrete leads; keep active HIT / NEEDS_TESTCASE /
NEEDS_DEEPER_PROBE rows alive and stay in the same subsystem.

## Guard Classification (apply when evaluating any hypothesis)

**Friction-class guards (worth probing past):**
- MOZ_ASSERT / assert / DCHECK — compiled out in release; if it's the ONLY check, release is reachable
- Stack canaries — only protect `char[]` arrays; `int32_t[]` overflows can sidestep
- Content Security Policy — implementation-specific quirks

**Hard barriers (don't waste cycles):**
- Process sandbox (Fission, seccomp, pledge) — architectural isolation
- W^X memory pages — hardware-enforced
- Site isolation — process boundary

If only friction-class guards protect it → worth pursuing. If a hard barrier blocks
reachability → lower priority unless you can name a concrete input path past it.

## Proven Patterns (compact lookup)

| ID | Pattern | Strategy |
|----|---------|----------|
| R1 | Two-pass TOCTOU: size in pass 1, fill in pass 2, data mutated between | S3 (fast-path) |
| R2 | Encode/decode counter mismatch | S3 (fast-path) |
| R3 | Signed int wraparound past MAX | REF (pattern ref) |
| R4 | New feature not integrated into all code paths | S1 |
| R5 | Missing IPC constructor check | S1 |
| R6 | JIT fast-path type-mismatch via MaybeOptimize* | S3 (fast-path) |
| R8 | Sentinel collision: -1/0xFFFF/MAX matches valid data | REF (pattern ref) |
| R9 | Multi-precondition gate → fuzzer-unreachable code | S2 |
| R10 | Algorithm invariant violation at edge cases | S2 |
| R11 | Spec says "MUST reject" but code continues | S3 |
| R15 | Assert-only bounds check → bounds issue in release | S2 |
| R16 | Callback destroys held raw ptr during operation | S5 |
| R17 | `decode(encode(x)) != x` round-trip asymmetry a trust/parse check relies on (smuggle past check) | S8 (inverse) |
| R18 | `f(f(x)) != f(x)` non-idempotent sanitiser/canonicaliser feeding a filter/ACL/SOP check (single-pass residual bypass) | S8 (idempotence) |
| R19 | Distinct inputs collide on a hash/cache-key feeding a lookup or identity (hash-flood DoS, cache poisoning) | S8 (injectivity) |
| R20 | Numerical result outside declared domain feeding a size/index/limit (negative→huge-unsigned, NaN, Inf) | S8 (numerical domain) |
| R21 | Ignored return + downstream read of OUT parameter (uninit / partial-init consumption) | REF (pattern ref) |
| R22 | Entropy combiner using `\|=` / `+=` / `*=` / `&=` instead of XOR or a real mixer (seed bias, collision-flood) | REF (pattern ref) |
| R23 | Fixed-size C-string buffer filled by truncation-unsafe API (`strncpy` / `readlink` / `gethostname` / `recv`) then walked by `strchr` / `strlen` (bounds read) | REF (pattern ref) |

## Bug Clustering (after any confirmed finding — MANDATORY)

When you confirm a bug, immediately search the neighborhood:
1. **Same file:** sibling functions with the same pattern
2. **Same subsystem:** related handlers with same bug class
3. **Codebase-wide:** grep for the affected pattern everywhere
4. **Variants:** 3-5 testcase variants through different paths
5. **Multi-strategy:** apply at least 3 other strategies to the area before leaving
