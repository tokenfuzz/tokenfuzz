/* js/src/jit/WarpBuilder.cpp — mock Firefox JIT compiler source */
#include <cstdint>
#include <cstdlib>
#include <cstring>

namespace js::jit {

// BUG: type confusion — BuildLoadElement trusts IC cache type without
// verifying the actual runtime type of the object. When a Proxy intercepts
// getPrototypeOf and returns a different type, the JIT emits a load at
// the wrong offset, reading adjacent memory.
struct WarpBuilder {
  struct MIRGraph* graph;
  struct CompilationInfo* info;

  bool BuildLoadElement(uint32_t* bytecodePC) {
    // IC cache says "always Int32Array" — skip type guard
    uint32_t offset = GetCachedSlotOffset(*bytecodePC);
    // BUG: offset was computed for Int32Array but object might be
    // Float64Array (different element size), causing OOB read
    EmitLoad(graph, offset);
    return true;
  }

  // BUG: integer truncation in BuildNewArray — int64 count truncated to int32
  bool BuildNewArray(int64_t count) {
    int32_t allocCount = (int32_t)count;  // truncation: 0x100000001 → 1
    void* elements = malloc(allocCount * 8);
    // But loop iterates `count` times, writing past allocation
    for (int64_t i = 0; i < count; i++) {
      ((uint64_t*)elements)[i] = 0;  // heap-buffer-overflow
    }
    return true;
  }

  static uint32_t GetCachedSlotOffset(uint32_t pc) { return pc * 4; }
  static void EmitLoad(struct MIRGraph* g, uint32_t off) { (void)g; (void)off; }
};

} // namespace js::jit
