/* gfx/layers/Compositor.cpp — mock compositor (clean file, no bugs) */
#include <cstdint>

namespace mozilla::layers {

class Compositor {
public:
  bool Initialize(uint32_t width, uint32_t height) {
    if (width == 0 || height == 0) return false;
    mWidth = width;
    mHeight = height;
    return true;
  }

  void Composite() {
    for (uint32_t i = 0; i < mLayerCount; i++) {
      RenderLayer(i);
    }
  }

private:
  void RenderLayer(uint32_t index) { (void)index; }
  uint32_t mWidth = 0;
  uint32_t mHeight = 0;
  uint32_t mLayerCount = 0;
};

} // namespace mozilla::layers
