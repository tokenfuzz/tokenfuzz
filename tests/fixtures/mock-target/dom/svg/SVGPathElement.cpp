/* dom/svg/SVGPathElement.cpp — mock SVG path element */
#include <cstdint>
#include <cstdlib>

namespace mozilla::dom {

// BUG: use-after-free — path data freed during style reflow but
// animation callback still holds reference to old path segments
class SVGPathElement {
public:
  void SetPathData(const float* segments, uint32_t count) {
    free(mSegments);
    mSegments = (float*)malloc(count * sizeof(float));
    memcpy(mSegments, segments, count * sizeof(float));
    mSegmentCount = count;
  }

  void OnStyleReflow() {
    // Invalidates current path
    free(mSegments);     // freed
    mSegments = nullptr;
    mSegmentCount = 0;
    // But pending animation tick still references mSegments via closure
  }

  float GetSegmentAt(uint32_t index) {
    // BUG: called from animation after OnStyleReflow freed mSegments
    return mSegments[index];  // UAF
  }

private:
  float* mSegments = nullptr;
  uint32_t mSegmentCount = 0;
};

} // namespace mozilla::dom
