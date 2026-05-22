/* dom/canvas/CanvasRenderingContext2D.cpp — mock Firefox source */
#include "CanvasRenderingContext2D.h"
#include "mozilla/dom/ImageData.h"

namespace mozilla::dom {

// BUG: heap-buffer-overflow — GetImageData reads past allocation
// when width * height * 4 overflows uint32_t, the allocation is
// too small but the copy loop uses the unclamped product.
void CanvasRenderingContext2D::GetImageData(int32_t sx, int32_t sy,
                                             int32_t sw, int32_t sh,
                                             ImageData& aResult) {
  uint32_t len = sw * sh * 4;  // unchecked overflow
  uint8_t* data = (uint8_t*)malloc(len);
  MOZ_ASSERT(data);
  // Reads from internal surface into data — overflows when len wraps
  memcpy(data, mSurfaceData + (sy * mStride + sx * 4), sw * sh * 4);
  aResult.SetData(data, len);
}

// BUG: use-after-free — PutImageData frees surface then uses it
void CanvasRenderingContext2D::PutImageData(ImageData& aData,
                                             int32_t dx, int32_t dy) {
  if (mSurfaceData) {
    free(mSurfaceData);  // freed here
  }
  // ... but mStride is still read from the freed surface metadata
  uint32_t stride = mStride;  // UAF: mStride was part of freed allocation
  memcpy(mSurfaceData + (dy * stride + dx * 4),
         aData.Data(), aData.Length());
}

// Guard function: this is NOT a bug, just a bounds check
bool CanvasRenderingContext2D::ValidateRect(int32_t x, int32_t y,
                                             int32_t w, int32_t h) {
  if (x < 0 || y < 0 || w <= 0 || h <= 0) return false;
  if (x + w > mWidth || y + h > mHeight) return false;
  return true;
}

} // namespace mozilla::dom
