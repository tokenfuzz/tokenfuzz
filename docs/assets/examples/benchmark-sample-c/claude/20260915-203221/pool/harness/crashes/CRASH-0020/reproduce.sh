#!/usr/bin/env bash
# Reproduces a ASan diagnostic against upstream sources.
# Usage:
#   ./reproduce.sh                     (clones $URL@$REV next to script)
#   ./reproduce.sh /path/to/checkout   (uses an existing checkout)
# Local-only targets (no recorded upstream — a symlinked or plain local source
# tree) carry the FILL_ME url sentinel; for those the clone is skipped and you
# must pass a checkout path.
set -eu
URL=FILL_ME
REV=norev
pin_rev() {
  echo "reproduce.sh: the audit recorded no revision; building $2 as it stands" >&2
  return 0
}

# Audit-tree-relative source path (e.g. targets/<slug>) for a local-only
# target; empty for VCS targets. Kept relative — not a host-absolute path — so
# the bundle stays portable and leaks no host layout. Resolve it against the
# first ancestor of this script that contains it (the audit repo root) so
# `./reproduce.sh` finds the in-place source on the machine that produced the
# bundle; stays empty when the bundle was copied elsewhere.
LOCAL_SRC=targets/samples/sample-c
resolved_local=""
if [ -n "$LOCAL_SRC" ]; then
  _d="$(cd "$(dirname "$0")" && pwd)"
  while :; do
    if [ -d "$_d/$LOCAL_SRC" ]; then resolved_local="$_d/$LOCAL_SRC"; break; fi
    [ "$_d" = "/" ] && break
    _d="$(dirname "$_d")"
  done
fi

default_src="$(dirname "$0")"/samples-sample-c
# Choose the source tree: an explicit argument wins; else the resolved in-place
# source recorded at audit time; else the clone/checkout location next to the
# script.
if [ $# -ge 1 ]; then
  src="$1"
elif [ -n "$resolved_local" ]; then
  src="$resolved_local"
else
  src="$default_src"
fi
# Fetch the source when it is absent — but clone only with a real upstream AND
# a usable revision. FILL_ME / norev are seed sentinels: a local-only or
# unpinned target cannot clone (this mirrors the report, which offers a
# path-based repro in that case), so ask for a checkout instead of attempting a
# doomed `git clone`.
if [ ! -d "$src" ]; then
  can_clone=1
  case "$URL" in FILL_ME|''|norev|no-vcs|unknown) can_clone=0 ;; esac
  case "$REV" in ''|norev|no-vcs|unknown|'?') can_clone=0 ;; esac
  if [ "$can_clone" -eq 1 ]; then
    git clone --recurse-submodules "$URL" "$src"
  else
    echo "reproduce.sh: no source tree at '$src' and no cloneable upstream recorded for this target." >&2
    [ -n "$LOCAL_SRC" ] && echo "Recorded source '$LOCAL_SRC' was not found near this bundle." >&2
    echo "Pass a local checkout: $0 /path/to/src" >&2
    exit 2
  fi
fi
# Pin to the recorded revision when this is a VCS checkout; a plain tree
# (no .git / .hg) is used as-is. Both git and hg are handled so a checkout the
# operator passes in is pinned either way. `.git` is tested with -e, not -d: in
# a git worktree it is a FILE pointing at the real git dir, and -d skipped the
# pin entirely there.
if [ -e "$src/.git" ] && git -C "$src" rev-parse --git-dir >/dev/null 2>&1; then
  pin_rev git "$src"
  # Re-sync submodules after pinning: the recorded REV can point them at
  # different commits than the clone fetched, and an operator-supplied checkout
  # may not have them initialized at all. Submodule-dependent builds (e.g. a JIT
  # engine vendored under deps/) need their sources present. No-op when the repo
  # has no submodules. The update's own exit status is not the test: a repo
  # with none succeeds trivially, and a partial failure can still leave every
  # submodule correct. What decides is the state afterwards — status marks a
  # submodule uninitialized (-), at the wrong commit (+), or conflicted (U),
  # and any of those means this is not the source the audit ran against.
  git -C "$src" submodule update --init --recursive 2>/dev/null || true
  if ! submodule_state=$(git -C "$src" submodule status --recursive 2>&1); then
    echo "reproduce.sh: cannot verify submodule revisions" >&2
    printf '%s
' "$submodule_state" >&2
    exit 3
  fi
  stale=$(printf '%s
' "$submodule_state" | grep -c '^[-+U]' || true)
  if [ "$stale" != "0" ]; then
    echo "reproduce.sh: $stale submodule(s) are not at the commit this tree records" >&2
    echo "  this build would use different dependency sources; fetch them" >&2
    echo "  with: git -C <checkout> submodule update --init --recursive" >&2
    exit 3
  fi
elif [ -d "$src/.hg" ]; then
  pin_rev hg "$src"
fi

# Canonicalize to an absolute path now that the tree exists. Out-of-tree
# autotools builds (and the inlined audit recipe) `cd "$build"` and then run
# "$src/configure", which only resolves when $src is absolute. Running
# `./reproduce.sh` yields a relative src (./<slug>), so resolve it here once;
# $build derives from it and is absolute too.
src="$(cd "$src" && pwd)"
build="$src/build-asan-repro"
# Build recipe inlined from the audit's .audit/build.sh — the EXACT
# script bin/auto-build-script converged on at audit time. Inlined
# verbatim so the reproducer build matches the audit build.
cat > "$src/.audit-build.sh" <<'__AUDIT_BUILD_SCRIPT_EOF__'
#!/usr/bin/env bash
# Build the sample-c RCF decoder with AddressSanitizer.
#
# Asserts stay ENABLED (no -DNDEBUG): the CHECK field's debug-only invariant
# relies on assert() firing so an over-long CHECK field is reported as a
# non-security ABRT rather than a memory-safety overflow. -O0 keeps every
# handler frame on the sanitizer stack (no inlining) so a crash names the
# planted function directly, and -fno-omit-frame-pointer keeps that frame at
# the top of the report.
set -euo pipefail

src="${1:?source root required}"
build="${2:?build dir required}"

cc_bin="${CC:-clang}"
if ! command -v "$cc_bin" >/dev/null 2>&1; then
  cc_bin="cc"
fi

mkdir -p "$build"
"$cc_bin" \
  -O0 -g -fno-omit-frame-pointer -fsanitize=address \
  -I"$src/include" \
  "$src/src/rcfg.c" "$src/src/rcfg_cli.c" \
  -o "$build/rcfg"
__AUDIT_BUILD_SCRIPT_EOF__
chmod +x "$src/.audit-build.sh"
"$src/.audit-build.sh" "$src" "$build"
echo "ASan binary not configured in target.toml" >&2
exit 2

testcase="$(dirname "$0")/input.rcf"
echo "=== running ASan repro: $testcase ===" >&2
rc=0
unset UBSAN_OPTIONS MSAN_OPTIONS TSAN_OPTIONS
ASAN_OPTIONS=detect_leaks=0:halt_on_error=1:quarantine_size_mb=256:redzone=64:print_scariness=1:handle_abort=1:print_full_thread_history=1"${ASAN_OPTIONS:+:$ASAN_OPTIONS}" \
  "$san_bin" "$testcase" || rc=$?
echo "[repro] exit=$rc" >&2
exit "$rc"
