#!/usr/bin/env bash
set -o pipefail
source "$(dirname "$0")/helpers.sh"
setup_test_env

HITS="$SCRIPT_ROOT/bin/hits"

assert_file_contains "$HITS" 'def stat_key' "hits: has binary stat cache key helper"
assert_file_contains "$HITS" 'def cache_dir' "hits: has cache directory helper"
assert_file_contains "$HITS" 'sancov-.*hexdigest' "hits: caches sancov validation by binary key"

order_check=$(awk '
  /^def probe_sancov/ { in_fn=1 }
  in_fn && /cache\.is_file/ { saw_cache=NR }
  in_fn && /otool|readelf|objdump/ { saw_probe=NR }
  in_fn && /^class Hits/ {
    if (saw_cache && saw_probe && saw_cache < saw_probe) print "ok";
    exit
  }
' "$HITS")
assert_eq "ok" "$order_check" "hits: cache is checked before binary section probe"

teardown_test_env
summary
