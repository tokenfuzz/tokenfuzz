# `// HARNESS:` toolchain reference

Put a small driver program next to the testcase and reference it from the
testcase header. The harness extension picks the toolchain. The full
table lives in `lib/languages.py`; print it any time with:

```bash
python3 lib/languages.py list
python3 lib/languages.py exts --kind harness-compiled
python3 lib/languages.py exts --kind harness-interpreted
```

Common cases:

```
// HARNESS: harness.c        # C — clang + selected sanitizer lib
// HARNESS: harness.cc       # C++ — clang++
// HARNESS: harness.rs       # Rust — rustc (single file)
// HARNESS: harness.go       # Go — go build
// HARNESS: harness.swift    # Swift — swiftc
// HARNESS: harness.py       # Python — python3 (no build)
// HARNESS: harness.rb       # Ruby — ruby
// HARNESS: harness.js       # Node — node
// HARNESS: harness.ts       # TypeScript — ts-node
// HARNESS: harness.java     # Java — java (JEP 330 single-file)
// HARNESS: harness.kt       # Kotlin — kotlinc + cached java -jar wrapper
// HARNESS: harness.kts      # Kotlin script — kotlinc -script
// HARNESS: harness.php      # PHP — php
// HARNESS: harness.pl       # Perl — perl
// HARNESS: harness.r        # R — Rscript
// HARNESS: harness.sh       # Bash — bash (script)
```

For interpreted extensions `bin/probe` runs `<interpreter> <harness> <testcase>`.
For compiled extensions it builds the harness once (cached) and runs
`<harness-binary> <testcase>`. The single source of truth — including
the interpreter/compiler binary name and the env variable to override
it — is `lib/languages.py`; `bin/probe` dispatches by shelling out to
`python3 lib/languages.py probe-dispatch <ext>`.
