/* image/decoders/png/nsPNGDecoder.cpp — mock PNG decoder */
#include <cstdint>
#include <cstdlib>
#include <cstring>

namespace image {

class nsPNGDecoder {
public:
  // BUG: heap-buffer-overflow in ProcessChunk — palette index not bounds-checked
  // against actual palette size. A crafted PNG with palette index > palette entries
  // reads past the palette buffer.
  void ProcessChunk(const uint8_t* data, uint32_t length) {
    for (uint32_t i = 0; i < length; i++) {
      uint8_t paletteIndex = data[i];
      // BUG: no check that paletteIndex < mPaletteSize
      uint32_t color = mPalette[paletteIndex];  // OOB read
      mOutputRow[i] = color;
    }
  }

  // Guard: IDAT CRC validation — not a bug, legitimate error path
  bool ValidateIDATChecksum(uint32_t expected, uint32_t computed) {
    if (expected != computed) {
      mError = true;
      return false;
    }
    return true;
  }

  // BUG: integer overflow in row stride calculation
  uint32_t ComputeRowStride(uint32_t width, uint32_t bpp) {
    return width * bpp;  // no overflow check: 65536 * 4 = 0 (wraps)
  }

private:
  uint32_t* mPalette = nullptr;
  uint32_t mPaletteSize = 0;
  uint32_t* mOutputRow = nullptr;
  bool mError = false;
};

} // namespace image
