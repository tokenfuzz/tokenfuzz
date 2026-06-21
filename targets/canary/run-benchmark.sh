#!/usr/bin/env bash
# Manual end-to-end check for the canary ground-truth target.
#
# 1. Bootstraps the committed canary into a runnable target. setup-target
#    keeps the committed .audit/build.sh (it only regenerates a recipe with
#    --force), so no LLM backend is needed for the build — it just
#    materializes targets/canary/build-asan and fills the build fields in
#    output/canary/target.toml.
# 2. Runs a short benchmark (1 replicate, 900s/cell) so the ledger gains the
#    "Ground truth (precision / recall)" block.
#
# This is for manual testing only. The automated regression that runs in CI
# lives in tests/test_integration_canary.sh (oracle) and
# tests/test_benchmark_scoring.sh (scorer) — run those with
# `bash tests/run-tests.sh`.
#
# Usage (from anywhere):
#   targets/canary/run-benchmark.sh [extra bin/benchmark args...]
#
# The benchmark needs a model backend; pass it through, e.g.:
#   targets/canary/run-benchmark.sh --backend codex
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"

echo "[canary] building target (keeps committed .audit/build.sh; no LLM)…"
bin/setup-target canary --build --no-llm-config

echo "[canary] running benchmark (1 replicate, 900s/cell budget)…"
bin/benchmark --target canary --replicates 1 --budget-wall 900 "$@"

echo "[canary] done — read the Ground truth (precision / recall) block in the"
echo "[canary] ledger under output/benchmark/. A healthy run: tokenfuzz at"
echo "[canary] high recall and precision; neither FP trap counted as a crash."
