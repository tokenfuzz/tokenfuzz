/* dom/canvas/CanvasRenderingContext2D.h */
#pragma once
#include <cstdint>
#include <cstdlib>
#include <cstring>

#define MOZ_ASSERT(x) do { if (!(x)) __builtin_trap(); } while(0)

namespace mozilla::dom {

class ImageData {
public:
  void SetData(uint8_t* d, uint32_t l) { mData = d; mLen = l; }
  uint8_t* Data() { return mData; }
  uint32_t Length() { return mLen; }
private:
  uint8_t* mData = nullptr;
  uint32_t mLen = 0;
};

class CanvasRenderingContext2D {
public:
  void GetImageData(int32_t sx, int32_t sy, int32_t sw, int32_t sh, ImageData& aResult);
  void PutImageData(ImageData& aData, int32_t dx, int32_t dy);
  bool ValidateRect(int32_t x, int32_t y, int32_t w, int32_t h);

  uint8_t* mSurfaceData = nullptr;
  uint32_t mStride = 0;
  int32_t mWidth = 0;
  int32_t mHeight = 0;
};

} // namespace mozilla::dom
