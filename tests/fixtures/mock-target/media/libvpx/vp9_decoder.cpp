/* media/libvpx/vp9_decoder.cpp — mock VP9 decoder (clean) */
#include <cstdint>

namespace vpx {

// Clean file — no bugs. Tests that audit doesn't false-positive on
// well-written code with proper bounds checking.
class VP9Decoder {
public:
  bool DecodeFrame(const uint8_t* data, uint32_t size) {
    if (size < 10) return false;  // minimum frame header
    uint32_t width = (data[0] << 8) | data[1];
    uint32_t height = (data[2] << 8) | data[3];
    if (width == 0 || height == 0) return false;
    if (width > 8192 || height > 4320) return false;  // max 8K
    return DecodeInternal(data + 10, size - 10, width, height);
  }

private:
  bool DecodeInternal(const uint8_t* d, uint32_t s, uint32_t w, uint32_t h) {
    (void)d; (void)s; (void)w; (void)h;
    return true;
  }
};

} // namespace vpx
