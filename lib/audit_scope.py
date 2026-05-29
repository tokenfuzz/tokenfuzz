"""Single source of truth for what counts as the product's attack surface.

Two consumers:

- ``lib/workqueue.py`` consults this set to filter the work-card pool at
  scan time, so harness agents never pick up out-of-scope files as
  candidates.
- ``lib/benchmark_model_direct_render.py`` renders the same names into
  the model-direct prompt so the bare-CTF agent has the same scoping
  rule as the harness. Before the shared source existed, the harness
  enforced scope as an *input filter* (work-card pool) while
  model-direct enforced nothing — codex r1 filed a real FIND inside a
  ``tests/`` directory.

Scope is deliberately narrow: only directory-name families that are
universally non-product (doc, example, test, fuzz). Build outputs,
vendored deps, tools, scripts, and CI metadata are intentionally NOT
excluded here — auditing vendored libraries and build-generated code
is in scope.

The prefix rules in :func:`is_excluded_path_part` are harness scanner
concerns and are not surfaced into the model-direct prompt. Model-direct
must remain free to navigate ``build-asan/``, ``build-ubsan/``, etc.,
because that's where it runs the sanitizer binaries that produce CRASHes.
"""

from __future__ import annotations


EXCLUDED_PATH_SEGMENTS = frozenset({
    "doc", "docs", "documentation",
    "example", "examples",
    "test", "tests", "testing",
    "fuzz", "fuzzer", "fuzzers", "fuzzing",
})


def is_excluded_path_part(part: str) -> bool:
    """True for a path component that should not enter the work-card pool.

    Combines :data:`EXCLUDED_PATH_SEGMENTS` with pattern rules that cannot
    be expressed as literals:

    - ``build-{asan,ubsan,msan,tsan}*`` — any sibling sanitizer build
      tree, including the suffixed variants the container produces when
      ``AUDIT_BUILD_SUFFIX`` is set.
    - ``*-install`` — CMake install staging.
    - ``cmakefiles`` — CMake's per-build internal cache directory
      (``CMakeFiles`` on disk). Always contains auto-generated artifacts
      (``CMakeCXXCompilerId.cpp``, ``compiler_depend.ts``, object files,
      depfiles, ``CMakeCache.txt``); never the user's target source.
      Inclusion criterion: a directory name reserved by an industry-wide
      build tool that mints its own generated files there.
    - ``cmake-build*`` — JetBrains CLion's IDE-managed build directory
      tree. Same property as ``CMakeFiles`` but at the tree root rather
      than nested.

    Matching is case-insensitive: both production callers in
    ``lib/workqueue.py`` (``is_excluded_work_path`` and the
    ``iter_source_files`` walk-prune) lowercase the path component before
    calling, so a case-sensitive ``CMakeFiles`` literal would never fire
    on a real path — it would silently let ``CMakeFiles/compiler_depend.ts``
    mint a ranked-source work card. Normalize here so the rule holds
    regardless of how the caller cased the segment.

    All pattern rules are harness-internal and do not appear in
    :func:`non_audit_dirs_for_prompt`.
    """
    part = part.lower()
    return (
        part in EXCLUDED_PATH_SEGMENTS
        or part == "cmakefiles"
        or part.startswith(("build-asan", "build-ubsan", "build-msan", "build-tsan", "cmake-build"))
        or part.endswith("-install")
    )


def non_audit_dirs_for_prompt() -> str:
    """Comma-separated literal segment list, rendered into prompts.

    Only the literal segment set is exposed — the sanitizer-build and
    install-staging prefix rules are scanner-internal and stay out of
    operator-facing prompt text.
    """
    return ", ".join(sorted(EXCLUDED_PATH_SEGMENTS))
