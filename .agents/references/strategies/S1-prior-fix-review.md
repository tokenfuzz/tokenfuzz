# Strategy S1: Prior-Fix & Regression Variant Analysis

**Highest-signal strategy. 3/7 historical findings came from this.**

Mine prior fixes AND large refactors for incomplete patches, reverted fixes, and
unfixed sibling patterns. This combines prior-fix review with regression-window mining.

**Review gate:** after 10+ patches across both fix and refactor categories with 0 unfixed analogues, rotate strategy. Do not rotate away from an active analogue with a plausible guard gap; turn it into a testcase or NEEDS_TESTCASE row first.

## Part 1: Prior Fix Variants

1. Collect recent prior-fix commits:
   ```bash
   # For Mercurial (Firefox): tag-based (works regardless of prose vocab)
   cd <repo> && hg log -k "sec-high" -k "sec-critical" -d "-365" --template "{node|short} {desc|firstline}\n" | head -50
   hg log -k "revert" -k "backout" -d "-120" --template "{node|short} {desc|firstline}\n" | head -40
   # For Git (any OSS project): mine fix-history keywords.
   git log --oneline --all --grep="fix\|regression\|patch" --since="1 year ago" | head -50
   git log --oneline --all --grep="revert\|Revert\|backout" --since="6 months ago" | head -30
   ```
2. Read each fix diff (limit to 200 lines). For each patch check **five things:**

### Incomplete-Fix Taxonomy

| Class | What to check | Example |
|-------|--------------|---------|
| **Partial coverage** | Fix covers path A but not path B (same function, different branch) | Audio fixed, video not (FIND-007) |
| **Reverted fix** | Backout/revert re-opens the original issue | FIND-004, FIND-006 |
| **Missing sibling** | Fix touches handler X but sibling handler Y has the same pattern | IPC Recv handlers, ParamTraits::Read |
| **Multi-file gap** | Fix touches 3/4 files in a multi-file change; 4th left unpatched | New feature not integrated everywhere |
| **Scope-limited** | Fix only handles the exact PoC input; other inputs reach same sink | Integer check added for one type, not another |

## Part 2: Regression-Window Mining (absorbs Strategy S)

Large refactors silently weaken or remove defensive checks.

1. Find recent large refactors in security-relevant subsystems:
   ```bash
   # Mercurial:
   hg log -d "-180" --template "{node|short} {file_adds|count}+{file_dels|count}d {desc|firstline}\n" | awk -F'[+d ]' '$2+$3 > 10' | head -30
   # Git:
   git log --oneline --shortstat --since="6 months ago" | awk '/files? changed/ && ($1+0 > 10)' | head -30
   ```
2. Diff the refactor. Specifically look for:
   - Bounds/null/type checks that **disappeared** in the new code
   - `assert` / `MOZ_ASSERT` statements removed without replacement
   - Error-handling paths simplified (e.g., `goto cleanup` → early `return`)
   - Signature changes that widen parameter types (e.g., `uint16_t` → `uint32_t`)

## Proven patterns

- Reverted fix leaves issue unpatched (Bug 2023443 → FIND-006, Bug 2022576 → FIND-004)
- Partial fix covers one media type but not another (Bug 2025479 → FIND-007)
- Resizable ArrayBuffer accepted by non-WebIDL paths → FIND-002
- SharedArrayBuffer TOCTOU in two-pass algorithms → FIND-003
- Missing IsOtherProcessActor in IPC constructors → FIND-004
- New web features not integrated into all code paths

## Token efficiency

Read ONE patch at a time, analyze it, then move to the next.
Do NOT bulk-inject 50 patch summaries into context.
