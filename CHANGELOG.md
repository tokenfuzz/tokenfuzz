# Changelog

## Unreleased

### Fixed

- Keep pinned `bin/audit --strategy` smoke runs on the requested strategy by passing the strategy filter through structured state resume and work-card selection.
- Allow generic runner agents to claim JavaScript-mode work cards for npm targets such as `js-yaml` and `angular`.
- Avoid a final-summary `set -u` failure when pending-count bookkeeping returns an empty or non-numeric value.

### Tests

- Added workqueue regression coverage for strategy-filtered card selection and generic agents consuming JavaScript-mode cards.
