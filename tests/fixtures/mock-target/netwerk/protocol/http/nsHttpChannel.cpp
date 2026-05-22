/* netwerk/protocol/http/nsHttpChannel.cpp — mock HTTP channel */
#include <cstdint>
#include <cstring>

namespace mozilla::net {

// BUG: heap-buffer-overflow — Content-Length header parsed as int32 but
// body buffer allocated as uint16, truncating large values
class nsHttpChannel {
public:
  bool OnDataAvailable(const uint8_t* data, uint32_t count) {
    if (!mBuffer) {
      // BUG: mContentLength could be > 65535 but allocated as uint16
      uint16_t allocSize = (uint16_t)mContentLength;
      mBuffer = new uint8_t[allocSize];
    }
    // Copies count bytes — overflows if mContentLength was truncated
    memcpy(mBuffer + mOffset, data, count);
    mOffset += count;
    return true;
  }

private:
  uint8_t* mBuffer = nullptr;
  uint32_t mContentLength = 0;
  uint32_t mOffset = 0;
};

} // namespace mozilla::net
