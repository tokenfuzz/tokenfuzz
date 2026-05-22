/* js/src/wasm/WasmValidate.cpp — mock Wasm validator */
#include <cstdint>
#include <cstdlib>

namespace js::wasm {

// BUG: stack-buffer-overflow in DecodeLocals — local count from untrusted
// wasm bytecode used directly as stack array size
bool DecodeLocals(const uint8_t* bytecode, uint32_t offset) {
  uint32_t localCount = *(uint32_t*)(bytecode + offset);
  // BUG: localCount from untrusted input, stack array overflow
  uint8_t localTypes[256];  // fixed-size stack buffer
  for (uint32_t i = 0; i < localCount; i++) {
    localTypes[i % 256] = bytecode[offset + 4 + i];  // reads OOB if localCount > remaining bytes
  }
  return true;
}

// Clean: proper bounds checking
bool ValidateBlockType(uint8_t type) {
  switch (type) {
    case 0x40: // void
    case 0x7F: // i32
    case 0x7E: // i64
    case 0x7D: // f32
    case 0x7C: // f64
      return true;
    default:
      return false;
  }
}

} // namespace js::wasm
