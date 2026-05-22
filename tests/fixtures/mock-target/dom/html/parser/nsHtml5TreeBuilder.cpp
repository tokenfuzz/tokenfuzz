/* dom/html/parser/nsHtml5TreeBuilder.cpp — mock HTML5 parser */
#include <cstdint>

namespace mozilla::dom {

// BUG: re-entrancy — reentering tree construction from a MutationObserver
// callback while the parser is mid-token causes double-free of the
// current token's attribute list.
class nsHtml5TreeBuilder {
public:
  void ProcessToken(uint32_t tokenType) {
    mCurrentToken.type = tokenType;
    mCurrentToken.attrs = AllocateAttrs();

    // Calls into DOM — MutationObserver can re-enter
    InsertElement(mCurrentToken);

    // BUG: if re-entrancy happened, attrs was already freed
    FreeAttrs(mCurrentToken.attrs);  // double-free
  }

  // Guard: EOF handling — not a bug
  void HandleEOF() {
    while (mStackDepth > 0) {
      PopElement();
    }
  }

private:
  struct Token {
    uint32_t type;
    void* attrs;
  };
  Token mCurrentToken;
  uint32_t mStackDepth = 0;

  void* AllocateAttrs() { return malloc(64); }
  void FreeAttrs(void* p) { free(p); }
  void InsertElement(const Token& t) { (void)t; }
  void PopElement() { mStackDepth--; }
};

} // namespace mozilla::dom
