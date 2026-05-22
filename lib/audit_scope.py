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
    be expressed as literals: ``build-{asan,ubsan,msan,tsan}*`` (any
    sibling sanitizer build tree, including the suffixed variants the
    container produces when ``AUDIT_BUILD_SUFFIX`` is set) and
    ``*-install`` (CMake install staging). Both pattern rules are
    harness-internal and do not appear in :func:`non_audit_dirs_for_prompt`.
    """
    return (
        part in EXCLUDED_PATH_SEGMENTS
        or part.startswith(("build-asan", "build-ubsan", "build-msan", "build-tsan"))
        or part.endswith("-install")
    )


def non_audit_dirs_for_prompt() -> str:
    """Comma-separated literal segment list, rendered into prompts.

    Only the literal segment set is exposed — the sanitizer-build and
    install-staging prefix rules are scanner-internal and stay out of
    operator-facing prompt text.
    """
    return ", ".join(sorted(EXCLUDED_PATH_SEGMENTS))
