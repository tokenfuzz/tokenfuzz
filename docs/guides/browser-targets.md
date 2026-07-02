# Browser Targets

Browser targets use the same harness contract as generic targets, but
their build layout and threat surface are different.

Use browser mode for:

- browsers;
- script engines;
- browser-like runtimes — anything with HTML, JS, event-loop, GC, or
  JIT behaviour.

## Enable browser mode

`bin/setup-target` already sets `is_browser = "1"` automatically when the
target slug is one of the four it recognises as a browser — `firefox`,
`chromium`, `webkit`, or `servo` — and seeds the browser threat model and
binary paths to match. Any other slug (a fork, a rename, a JS engine)
needs the edit below. In `output/<target>/target.toml`:

```toml
is_browser = "1"
asan_bin = "build-asan/dist/Nightly.app/Contents/MacOS/firefox"

[threat_model]
attacker_controls = ["bytes", "call-sequence", "timing"]
```

Both browser and generic targets share the same `build-asan/` layout.
Firefox writes its mach build there via `MOZ_OBJDIR`; CMake / autotools
targets install there with `-DCMAKE_INSTALL_PREFIX` or `--prefix`.
Inside `bin/audit-container-shell`, `AUDIT_BUILD_SUFFIX` makes the
actual build directory `build-asan-<image-id>/`; relative `build-asan/`
paths in `target.toml` resolve through that suffix.

For Firefox on Linux, use the ELF build path instead:

```toml
asan_bin = "build-asan/dist/bin/firefox"
```

Coverage mode, when available, checks `XUL` on macOS or `libxul.so`
on Linux.

## Attacker surface

Browser threat models typically include:

- `bytes` — web content;
- `call-sequence` — Web API call order;
- `timing` — event-loop, GC, JIT tier-up.

Add `protocol-state` only if the target genuinely accepts adversarial
network state.

Triage uses `attacker_controls` to decide whether a crash trigger is
reachable through a normal product input boundary. **Keep it tight.**
A browser-only setup that no real web page can recreate does not
belong in `crashes/`.

## Keep reports product-reachable

Browser targets expose rich controls, but a crash report still needs
a product path. That means one of:

- web content bytes;
- a Web API call sequence;
- JS or Wasm execution;
- event-loop or GC timing;
- protocol or resource-loading state.

If the observation is security-relevant but not crash-reproducible or
not web-reachable, it belongs in `findings/` with the right boundary
language — not in `crashes/`.
