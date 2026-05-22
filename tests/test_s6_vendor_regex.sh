#!/usr/bin/env bash
# Verifies the S6 strategy regex stays target-agnostic. Concrete peer names
# live only in output/<slug>/target.toml and must not be baked into ranking.
set -o pipefail
source "$(dirname "$0")/helpers.sh"
setup_test_env

python3 - <<'PY'
import sys
sys.path.insert(0, "lib")
from workqueue import STRATEGY_KEYWORDS

s6_re = STRATEGY_KEYWORDS["S6"][0]
assert "_S6_VENDOR_ALT" not in dir(__import__("workqueue")), "S6 vendor alternation should be retired"

# Generic vocabulary half still fires without any vendor present.
for vocab in (
    "look at the upstream fix",
    "CVE-2024-12345 affects us too",
    "analogous to another impl",
    "cross-engine variant",
    "same bug in the other library",
    "oss-fuzz reported",
):
    assert s6_re.search(vocab), f"vocabulary regression on: {vocab!r}"

# No spurious matches on unrelated text.
for noise in (
    "fix the typo",
    "rename the variable",
    "update the docs",
    "refactor the parser",
    "the zlib-ng patch",
    "firefox bug here",
):
    assert not s6_re.search(noise), f"S6 false positive on: {noise!r}"

print("OK")
PY
rc=$?
[ "$rc" -eq 0 ] || { echo "FAIL: S6 vendor regex assertions"; exit 1; }
echo "PASS: test_s6_vendor_regex"
