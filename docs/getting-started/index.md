# Getting Started

Follow three pages from a fresh clone to a reviewable smoke-test run:

1. **[Prerequisites](prerequisites.md)** — install the host tools, an
   LLVM toolchain, and one agent backend.
2. **[Add a target](add-a-target.md)** — sync the source, establish a
   sanitizer or language-runner path, and review generated `target.toml`.
3. **[First audit](first-audit.md)** — run one bounded iteration end to
   end and inspect the results.

The first run may produce no finding; success means the backend, target,
structured state, and result paths work together. After that:

- **[Guides](../guides/index.md)** cover ongoing operation.
- **[Concepts](../concepts/index.md)** explain the design.
