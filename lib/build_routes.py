"""Sanitizer build-route discovery.

Many C/C++ targets ship multiple sanitizer build directories because
different code paths need different configure flags (`--enable-jit`,
``--with-zlib``, 8/16/32-bit width, etc.). `setup-target` only creates
the canonical ``build-asan/``; the alternates (``build-asan-jit/``,
``build-asan-wide/``, ``build-asan-cmake/``, …) accumulate over time as
maintainers or prior agent sessions run additional configure passes.

When ``bin/probe`` runs a testcase through the canonical binary and the
output carries a *feature-disabled* signature ("not compiled in", "JIT
not available", "not supported in this build"), the right answer is
almost never ENV-BLOCKED — it's a sibling build that has the feature
turned on. This module detects that signature and enumerates sibling
candidates so ``bin/probe`` can re-run the testcase against each.

Design notes:

* **Sentinels are industry-wide, not target-specific.** The phrases
  here name a class of *feature-flag failure* common to most autotools
  / cmake projects. No target name, file path, or subsystem keyword
  belongs in the list. New phrases get added when a target produces a
  distinct family of message (e.g. "configured without X support").
* **Routes are runtime state, not config.** Build directories are
  host-local and ephemeral; a route discovered on one host is
  meaningless to CI or to a maintainer reviewing ``target.toml``.
  ``bin/probe`` writes routes to ``RESULTS_DIR/build-routes.jsonl`` so
  later probes skip the rediscovery sweep.
* **No target-specific patterns in the harness.** Sibling builds are
  matched by the canonical ``build-*`` prefix (universal autotools /
  cmake convention) and by sharing the same ``bin/<name>`` leaf as the
  canonical binary.
"""
from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from pathlib import Path

# Industry-wide feature-disabled phrases. Inclusion criterion: the
# phrase names a *configure-time feature flag that wasn't set in this
# build* and would succeed against a sibling build with the flag
# enabled. Missing-library / missing-header phrases live in
# workqueue.ENV_BLOCK_FINGERPRINT_RE and are intentionally NOT here —
# no alternate build saves you when libssl.so is absent.
#
# The expression is a single alternation so callers do one regex pass
# per output. Add new phrases here when a target produces a distinct
# wording for the same class of failure; keep entries general (no
# target slugs, no file basenames, no subsystem keywords).
FEATURE_DISABLED_RE = re.compile(
    r"not\s+compiled\s+in"
    r"|not\s+enabled\s+(?:at\s+configure(?:\s+time)?|in\s+this\s+build)"
    r"|not\s+supported\s+(?:in\s+this\s+build|by\s+this\s+(?:build|binary))"
    r"|JIT\s+(?:not\s+(?:available|supported|compiled)|disabled)"
    r"|just-in-time\s+(?:compiler\s+)?(?:not\s+(?:available|supported|compiled)|disabled)"
    r"|no\s+just-in-time\s+(?:compiler\s+)?support"
    r"|feature\s+(?:is\s+)?disabled"
    r"|(?:built|compiled)\s+without\s+[A-Za-z][A-Za-z0-9_+\-]*\s+support",
    re.IGNORECASE,
)


def output_is_feature_disabled(text: str) -> bool:
    """Return True when ``text`` matches the feature-disabled sentinel.

    The match is intentionally permissive — false positives at this layer
    just trigger an extra build sweep; false negatives leave the user
    stranded on ENV-BLOCKED. When in doubt, add the phrase to
    :data:`FEATURE_DISABLED_RE` so the auto-router catches it next time.
    """
    if not text:
        return False
    return FEATURE_DISABLED_RE.search(text) is not None


def _bin_subpath(asan_bin: Path, build_dir: Path) -> Path | None:
    """Compute the candidate binary path under ``build_dir``.

    ``asan_bin`` is the canonical binary's absolute path (e.g.
    ``$TARGET_ROOT/build-asan/bin/pcre2test``); we want the same
    sub-path under each sibling (``$TARGET_ROOT/build-asan-jit/bin/
    pcre2test``). Returns ``None`` if ``asan_bin`` isn't under the
    canonical build root — without that anchor we can't safely
    extrapolate.
    """
    try:
        # Find the build-* component in asan_bin and rewrite it.
        parts = asan_bin.parts
    except (AttributeError, TypeError):
        return None
    for i, part in enumerate(parts):
        if part.startswith("build-"):
            tail = Path(*parts[i + 1:]) if i + 1 < len(parts) else Path()
            return build_dir / tail if str(tail) else build_dir
    return None


@dataclass(frozen=True)
class BuildCandidate:
    """A sibling build directory with a matching binary subpath."""
    build_dir: Path
    binary: Path

    def exists(self) -> bool:
        return self.binary.is_file() and os.access(self.binary, os.X_OK)


def enumerate_sibling_builds(
    target_root: Path,
    asan_bin: Path,
    *,
    canonical_build_name: str | None = None,
) -> list[BuildCandidate]:
    """Yield sibling ``build-*`` candidates that mirror ``asan_bin``.

    Order: most-recently-modified first (the maintainer's freshest
    build is usually the one they want). The canonical build dir is
    excluded so the caller doesn't re-probe its own original binary.

    ``canonical_build_name`` lets callers exclude an explicit build dir
    name (defaults to the one ``asan_bin`` lives under).
    """
    target_root = Path(target_root)
    asan_bin = Path(asan_bin)
    if not target_root.is_dir():
        return []
    if canonical_build_name is None:
        for p in asan_bin.parts:
            if p.startswith("build-"):
                canonical_build_name = p
                break
    candidates: list[BuildCandidate] = []
    try:
        children = sorted(
            (c for c in target_root.iterdir() if c.is_dir()),
            key=lambda c: c.stat().st_mtime,
            reverse=True,
        )
    except OSError:
        return []
    for child in children:
        name = child.name
        if not name.startswith("build-"):
            continue
        if canonical_build_name and name == canonical_build_name:
            continue
        # Only ASan-family builds — UBSan/MSan/TSan binaries answer a
        # different question and would mask the feature-flag mismatch
        # with an unrelated sanitizer mismatch instead.
        if not name.startswith(("build-asan", "build-ubsan", "build-msan", "build-tsan")):
            # Anchor on "build-asan" only when the canonical binary
            # itself is an ASan build; otherwise allow any build- prefix.
            if canonical_build_name and canonical_build_name.startswith("build-asan"):
                if not name.startswith("build-asan"):
                    continue
        bin_path = _bin_subpath(asan_bin, child)
        if bin_path is None:
            continue
        cand = BuildCandidate(build_dir=child, binary=bin_path)
        if cand.exists():
            candidates.append(cand)
    return candidates


# ── Persistent route cache ──────────────────────────────────────────
# Runtime state, not target.toml. JSONL so concurrent agents can
# append-update without rewriting. One entry per ``(subsystem, feature)``
# pair — the canonical key for "this class of work routes here".

ROUTES_FILENAME = "build-routes.jsonl"


def routes_path(results_dir: Path) -> Path:
    return Path(results_dir) / ROUTES_FILENAME


def load_routes(results_dir: Path) -> dict[str, str]:
    """Return ``{subsystem_or_stem: binary_path}`` from the cache.

    Last entry wins on duplicate keys — newer discoveries override older
    ones, so a re-routed surface picks up the new binary without
    requiring a rewrite of the JSONL.
    """
    path = routes_path(results_dir)
    if not path.is_file():
        return {}
    out: dict[str, str] = {}
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return {}
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(row, dict):
            continue
        key = str(row.get("key", "") or "")
        binary = str(row.get("binary", "") or "")
        if key and binary:
            out[key] = binary
    return out


def record_route(
    results_dir: Path,
    *,
    key: str,
    binary: Path | str,
    feature: str = "",
    canonical_binary: Path | str = "",
) -> None:
    """Append a ``(key, binary)`` route to the cache.

    ``key`` is the routing key — typically the work-card's subsystem or
    the canonical-binary-relative path stem. ``feature`` is the matched
    sentinel name (free-form, for human-readable logs).
    """
    if not key or not binary:
        return
    path = routes_path(results_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    row = {
        "key": key,
        "binary": str(binary),
        "feature": feature,
        "canonical_binary": str(canonical_binary or ""),
    }
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(row, sort_keys=True) + "\n")
        f.flush()


def lookup_route(results_dir: Path, *keys: str) -> str:
    """Return the cached binary for the first key that hits, else ""."""
    routes = load_routes(results_dir)
    for k in keys:
        if k and k in routes:
            return routes[k]
    return ""


# ── CLI ─────────────────────────────────────────────────────────────
# Three subcommands for shell-side callers (bin/probe):
#   sentinel  <file>
#     exit 0 + print "feature_disabled" if the file matches.
#   enumerate <target_root> <asan_bin>
#     print one candidate binary path per line, mtime-desc.
#   lookup    <results_dir> <key> [<key> ...]
#     print the cached binary for the first key that hits, else nothing.
#   record    <results_dir> <key> <binary> [<feature>] [<canonical>]
#     append a route row.

def main(argv: list[str]) -> int:
    import argparse
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_s = sub.add_parser("sentinel")
    p_s.add_argument("path", type=Path)

    p_e = sub.add_parser("enumerate")
    p_e.add_argument("target_root", type=Path)
    p_e.add_argument("asan_bin", type=Path)

    p_l = sub.add_parser("lookup")
    p_l.add_argument("results_dir", type=Path)
    p_l.add_argument("keys", nargs="+")

    p_r = sub.add_parser("record")
    p_r.add_argument("results_dir", type=Path)
    p_r.add_argument("key")
    p_r.add_argument("binary")
    p_r.add_argument("--feature", default="")
    p_r.add_argument("--canonical", default="")

    args = parser.parse_args(argv)

    if args.cmd == "sentinel":
        try:
            text = args.path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return 1
        if output_is_feature_disabled(text):
            print("feature_disabled")
            return 0
        return 1

    if args.cmd == "enumerate":
        cands = enumerate_sibling_builds(args.target_root, args.asan_bin)
        for c in cands:
            print(c.binary)
        return 0

    if args.cmd == "lookup":
        bin_path = lookup_route(args.results_dir, *args.keys)
        if bin_path:
            print(bin_path)
            return 0
        return 1

    if args.cmd == "record":
        record_route(
            args.results_dir,
            key=args.key,
            binary=args.binary,
            feature=args.feature,
            canonical_binary=args.canonical,
        )
        return 0

    return 2


if __name__ == "__main__":
    import sys
    raise SystemExit(main(sys.argv[1:]))
