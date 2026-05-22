/* js/src/gc/Nursery.cpp — mock GC nursery */
#include <cstdint>
#include <cstdlib>

namespace js::gc {

// BUG: use-after-free — Nursery::Collect moves objects but stale pointers
// in the JIT IC cache still point to the old nursery location.
class Nursery {
public:
  void Collect() {
    // Move surviving objects to tenured heap
    for (uint32_t i = 0; i < mUsed; i++) {
      void* newLoc = malloc(mSlots[i].size);
      memcpy(newLoc, mSlots[i].ptr, mSlots[i].size);
      // BUG: mSlots[i].ptr freed but JIT IC caches still hold old ptr
      free(mSlots[i].ptr);
      mSlots[i].ptr = newLoc;
      // IC cache NOT updated — stale pointer remains
    }
  }

  struct Slot {
    void* ptr;
    uint32_t size;
  };

  Slot* mSlots = nullptr;
  uint32_t mUsed = 0;
  uint32_t mCapacity = 0;
};

} // namespace js::gc
