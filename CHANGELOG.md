# Changelog

## Unreleased

### Changed

- Unified findings deduplication: every finding — harness-agent, recon, and model-direct (bare-prompt baseline) — now gets one identity computed from its report at cluster time, in one place (`bin/cluster-findings`), so all sources share a single identity space and a single clustering view. `dedup_key` is the primary signal, assigned by `lib/finding_keyer.py` from each report alone (one cached LLM call per fresh finding, on by default; `--no-key` or no backend falls back to the deterministic `(class, file, func)` + crash-state label). One keyer canonicalizes every finding, so a key no longer varies with the model that authored the report and stays comparable across the models a benchmark compares.
- Quality and identity are now separate concerns: the find-quality gate decides only accept/class/severity, and identity is assigned uniformly downstream — there is no per-source dedup path.
- Class extraction recognizes `Bug class:` / `Vulnerability type:` labels, and target-relative path normalization strips a leading `targets/<slug>/` structurally, so model-direct and benchmark findings classify and key correctly.

### Fixed

- Keep pinned `bin/audit --strategy` smoke runs on the requested strategy by passing the strategy filter through structured state resume and work-card selection.
- Allow generic runner agents to claim JavaScript-mode work cards for npm targets such as `js-yaml` and `angular`.
- Avoid a final-summary `set -u` failure when pending-count bookkeeping returns an empty or non-numeric value.

### Tests

- Added workqueue regression coverage for strategy-filtered card selection and generic agents consuming JavaScript-mode cards.
- Added `tests/test_finding_keyer.py` for the read-time identity keyer (assignment, caching, idempotency, graceful no-op without a backend, source-independence); updated finding-signature, cluster-findings, find-quality, and recon-materialization coverage for the unified identity path.
