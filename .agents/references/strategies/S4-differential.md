# Strategy S4: Advanced Differential Testing

**Basic differential (--ion-eager vs --no-ion) is now automatic** — `run-sanitizer-multi`
runs it on every js/xpcshell testcase. This strategy covers advanced differential
techniques that require deliberate setup.

**Apply alongside any other strategy** — differential testing is a technique, not
a standalone investigation.

## Advanced Differential Pairs

| Pair | What it catches | Setup |
|------|----------------|-------|
| **Wasm baseline vs optimized** | Wasm codegen bugs | `--wasm-compiler=baseline` vs `--wasm-compiler=optimized` |
| **GC zeal modes** | Use-after-GC, weak ref, barrier bugs | `JS_GC_ZEAL=2` or `JS_GC_ZEAL=7` vs normal |
| **Forced frequent GC** | Timing-dependent UAFs | `JSGC_MAX_BYTES=1048576` vs normal |
| **32-bit vs 64-bit** | Pointer-size-dependent bugs, truncation | Cross-compile or use 32-bit build |
| **Debug vs release** | Assertions that mask real crashes | Compare ASan-debug vs ASan-release output |
| **Different compiler versions** | Undefined behavior manifesting differently | gcc build vs clang build (same source) |
| **Endianness** | Byte-order assumptions | Cross-compile for big-endian target |
| **Different OSes** | Platform-specific assumptions | macOS vs Linux build of same code |
| **Round-trip (encode/decode)** | Serializer/parser asymmetry, lossy normalization, NUL/escape mishandling | Run `decode(encode(x))` and `encode(decode(y))` and diff against the original |

## When to Use (Active, Not Automatic)

1. **After writing any JS/Wasm testcase:** auto-diff handles basic JIT, but you should
   manually try GC zeal and wasm-compiler variants for deeper coverage
2. **When a testcase runs clean under ASan:** differential can find correctness bugs
   (wrong output) that sanitizers miss — value corruption, silent data loss
3. **When investigating JIT/codegen:** exercise ALL optimization tiers, not just on/off
4. **Cross-build comparison:** when you suspect platform-specific assumptions

## Procedure for advanced pairs

```bash
# Wasm baseline vs optimized:
bin/run-asan js --wasm-compiler=baseline testcase.js > /tmp/base.out 2>&1
bin/run-asan js --wasm-compiler=optimized testcase.js > /tmp/opt.out 2>&1
diff /tmp/base.out /tmp/opt.out

# GC stress testing (forces GC at every allocation):
JS_GC_ZEAL=2 bin/run-asan js testcase.js > /tmp/gczeal.out 2>&1
bin/run-asan js testcase.js > /tmp/normal.out 2>&1
diff /tmp/gczeal.out /tmp/normal.out

# Forced memory pressure:
JSGC_MAX_BYTES=1048576 bin/run-asan js testcase.js > /tmp/pressure.out 2>&1
diff /tmp/normal.out /tmp/pressure.out
```

**Key insight:** Disagreement between any two modes IS the bug — you don't need to
know where it is. The divergence points you to the broken optimization/codegen path.

## Round-trip differentials

For encoders / decoders / serializers / parsers, the function pair is its
own oracle: `decode(encode(x)) == x` and `encode(decode(y)) == y`. Any
divergence in bytes, length, or normalization is a finding even without
ASan. Highest yield on JSON / CBOR / protobuf serializers, URL / IDN
normalization, UTF-8 ↔ UTF-16 conversion, HTML / XML round-trips, regex
match-and-replace, and codec encode → decode for image/audio formats.
