#!/usr/bin/env bash
# Test runner for audit framework test suite.
# Usage: tests/run-tests.sh [options] [test_file_pattern...]
set -o pipefail

TESTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT_ROOT="$(cd "$TESTS_DIR/.." && pwd)"
export SCRIPT_ROOT

# Block real Claude/Codex calls during tests. Per-decision mocks
# (LLM_DECIDE_MOCK_*) still run — DISABLE only gates the real backend.
export LLM_DECIDE_DISABLE="${LLM_DECIDE_DISABLE:-1}"

usage() {
  cat <<'EOF'
Usage:
  tests/run-tests.sh [options] [test_file_pattern...]
  tests/run-tests.sh --category integration
  tests/run-tests.sh --jobs 4 test_triage.sh test_reachability.sh
  tests/run-tests.sh --image ubuntu:24.04 [options] [test_file_pattern...]

Options:
  -j, --jobs N          Run up to N test files at once (default: CPU count capped at TEST_JOBS_MAX or 8; TEST_JOBS/--jobs override).
  --category NAME       Run one category: decision, integration, python, static, unit, wrapper.
  --list                List matched tests with categories, then exit.
  --image IMAGE          Run the suite inside a Linux container image.
  --runtime NAME         Container runtime: docker (default).
  --no-install-deps      Skip dependency installation inside the image.
  -h, --help            Show this help.

Examples:
  bash tests/run-tests.sh
  bash tests/run-tests.sh --category wrapper
  bash tests/run-tests.sh --image ubuntu:24.04
  bash tests/run-tests.sh --image fedora:latest --jobs 2 test_run_asan.sh
EOF
}

RUN_IMAGE=""
CONTAINER_RUNTIME="${CONTAINER_RUNTIME:-docker}"
INSTALL_DEPS=1
JOBS="${TEST_JOBS:-}"
[ -n "$JOBS" ] && JOBS_EXPLICIT=1 || JOBS_EXPLICIT=0
CATEGORY_FILTER=""
LIST_ONLY=0
PATTERNS=()

while [ "$#" -gt 0 ]; do
  case "$1" in
    -j|--jobs)
      [ "$#" -ge 2 ] || { echo "tests/run-tests.sh: --jobs requires a value" >&2; exit 2; }
      JOBS="$2"; JOBS_EXPLICIT=1; shift 2 ;;
    --jobs=*)
      JOBS="${1#--jobs=}"; JOBS_EXPLICIT=1; shift ;;
    --category)
      [ "$#" -ge 2 ] || { echo "tests/run-tests.sh: --category requires a value" >&2; exit 2; }
      CATEGORY_FILTER="$2"; shift 2 ;;
    --category=*)
      CATEGORY_FILTER="${1#--category=}"; shift ;;
    --list)
      LIST_ONLY=1; shift ;;
    --image)
      [ "$#" -ge 2 ] || { echo "tests/run-tests.sh: --image requires a value" >&2; exit 2; }
      RUN_IMAGE="$2"; shift 2 ;;
    --image=*)
      RUN_IMAGE="${1#--image=}"; shift ;;
    --runtime)
      [ "$#" -ge 2 ] || { echo "tests/run-tests.sh: --runtime requires a value" >&2; exit 2; }
      CONTAINER_RUNTIME="$2"; shift 2 ;;
    --runtime=*)
      CONTAINER_RUNTIME="${1#--runtime=}"; shift ;;
    --no-install-deps)
      INSTALL_DEPS=0; shift ;;
    --install-container-deps)
      # Run installs in a subshell with set -e so a transient apt/dnf network
      # failure fails the step instead of silently leaving the container half-
      # provisioned. Without this the entry script exec's bash -l and bin/audit
      # later dies with "FATAL: missing required tool(s): jq" with no signal
      # that the cause was an apt fetch timeout.
      (
        set -e
        # nodejs+npm are required: bin/audit:gemini_cli_check_bundled_ripgrep
        # uses node for realpath/platform detection, and the npm-based
        # backends (codex, @google/gemini-cli) need npm to install. curl
        # is needed for the Antigravity CLI installer and CA fetches.
        if command -v apt-get >/dev/null 2>&1; then
          export DEBIAN_FRONTEND=noninteractive
          apt-get update
          apt-get install -y --no-install-recommends \
            bash ca-certificates clang curl file git jq libclang-rt-dev llvm mercurial \
            nodejs npm perl procps python3 ripgrep
        elif command -v dnf >/dev/null 2>&1; then
          dnf install -y \
            bash ca-certificates clang coreutils curl diffutils file findutils gawk git \
            grep jq less llvm mercurial nodejs npm perl procps-ng python3 ripgrep sed which \
            || dnf install -y \
              bash ca-certificates clang coreutils curl diffutils file findutils gawk git \
              grep jq less llvm nodejs npm perl procps-ng python3 sed which
        elif command -v microdnf >/dev/null 2>&1; then
          microdnf install -y \
            bash ca-certificates clang coreutils curl diffutils file findutils gawk git \
            grep jq less llvm nodejs npm perl procps-ng python3 sed which
        elif command -v yum >/dev/null 2>&1; then
          yum install -y \
            bash ca-certificates clang coreutils curl diffutils file findutils gawk git \
            grep jq less llvm mercurial nodejs npm perl procps-ng python3 ripgrep sed which \
            || yum install -y \
              bash ca-certificates clang coreutils curl diffutils file findutils gawk git \
              grep jq less llvm nodejs npm perl procps-ng python3 sed which
        else
          echo "tests/run-tests.sh: no supported package manager found; install bash python3 perl file git jq clang llvm ripgrep nodejs npm curl" >&2
          exit 2
        fi
      ) || {
        echo "tests/run-tests.sh: --install-container-deps failed; container is not provisioned." >&2
        echo "tests/run-tests.sh: common cause is a transient apt/dnf fetch timeout from inside the container." >&2
        exit 3
      }
      # Verify the critical tools the audit harness assumes are present.
      # If a fetch silently dropped one of them, fail loudly here so the
      # error message points at the install step, not at bin/audit later.
      missing=()
      for tool in bash python3 perl file git jq clang llvm-ar rg node npm curl; do
        command -v "$tool" >/dev/null 2>&1 || missing+=("$tool")
      done
      if [ "${#missing[@]}" -gt 0 ]; then
        echo "tests/run-tests.sh: --install-container-deps completed but tools still missing: ${missing[*]}" >&2
        echo "tests/run-tests.sh: re-run the container build, or retry inside this container, to fetch them." >&2
        exit 3
      fi
      exit 0 ;;
    -h|--help)
      usage; exit 0 ;;
    --)
      shift
      PATTERNS+=("$@")
      break ;;
    --*)
      echo "tests/run-tests.sh: unknown option: $1" >&2
      usage >&2
      exit 2 ;;
    *)
      PATTERNS+=("$1"); shift ;;
  esac
done

if [ -n "$RUN_IMAGE" ]; then
  case "$CONTAINER_RUNTIME" in docker) ;; *) echo "tests/run-tests.sh: --runtime must be docker" >&2; exit 2 ;; esac
  command -v "$CONTAINER_RUNTIME" >/dev/null 2>&1 || {
    echo "tests/run-tests.sh: $CONTAINER_RUNTIME not found" >&2
    exit 2
  }
  "$CONTAINER_RUNTIME" info >/dev/null 2>&1 || {
    echo "tests/run-tests.sh: $CONTAINER_RUNTIME is installed but not reachable; start the container service and retry" >&2
    exit 2
  }

  inner_args=()
  [ -n "$JOBS" ] && inner_args+=(--jobs "$JOBS")
  [ -n "$CATEGORY_FILTER" ] && inner_args+=(--category "$CATEGORY_FILTER")
  [ "$LIST_ONLY" -eq 1 ] && inner_args+=(--list)
  [ "$INSTALL_DEPS" -eq 0 ] && inner_args+=(--no-install-deps)
  if [ "${#PATTERNS[@]}" -gt 0 ]; then
    inner_args+=("${PATTERNS[@]}")
  fi
  inner_cmd=""
  if [ "${#inner_args[@]}" -gt 0 ]; then
    printf -v inner_cmd '%q ' "${inner_args[@]}"
  fi
  "$CONTAINER_RUNTIME" run --rm \
    -v "$SCRIPT_ROOT:/work" \
    -w /work \
    -e LLM_DECIDE_DISABLE="${LLM_DECIDE_DISABLE:-1}" \
    "$RUN_IMAGE" \
    bash -lc "if [ $INSTALL_DEPS -eq 1 ]; then tests/run-tests.sh --install-container-deps; fi; bash tests/run-tests.sh ${inner_cmd}"
  exit $?
fi

detect_default_jobs() {
  local n max
  n="${JOBS:-}"
  if [ -z "$n" ]; then
    n=$(getconf _NPROCESSORS_ONLN 2>/dev/null || true)
  fi
  if [ -z "$n" ] && command -v sysctl >/dev/null 2>&1; then
    n=$(sysctl -n hw.ncpu 2>/dev/null || true)
  fi
  case "$n" in ''|*[!0-9]*) n=1 ;; esac
  max="${TEST_JOBS_MAX:-8}"
  case "$max" in ''|*[!0-9]*) max=8 ;; esac
  [ "$max" -lt 1 ] && max=1
  [ "$n" -lt 1 ] && n=1
  if [ "${JOBS_EXPLICIT:-0}" -eq 0 ] && [ "$n" -gt "$max" ]; then
    n="$max"
  fi
  echo "$n"
}

test_category() {
  local name="$1"
  case "$name" in
    *.py) echo "python"; return ;;
  esac
  name="${name##*/}"
  name="${name%.sh}"
  name="${name%.py}"
  case "$name" in
    test_decision_*) echo "decision" ;;
    test_integration_*|test_mock_target) echo "integration" ;;
    test_*_py|test_stack_frames|test_target_config_py) echo "python" ;;
    test_doc_neutrality|test_hits_cache_static|test_portability_lint|test_strategy_validation|test_vocab) echo "static" ;;
    test_grep_wrapper|test_rg_wrapper|test_sed_wrapper|test_rg_safe|test_platform|test_timeout|test_zdotdir_shim) echo "wrapper" ;;
    *) echo "unit" ;;
  esac
}

test_weight() {
  local name="$1"
  name="${name##*/}"
  case "$name" in
    test_benchmark.sh) echo 30 ;;
    test_benchmark_cells.sh) echo 25 ;;
    test_audit_core.sh) echo 41 ;;
    test_decision_find_quality.sh) echo 35 ;;
    test_multilang_support.sh) echo 26 ;;
    test_confirm_crash.sh) echo 18 ;;
    test_workqueue.sh) echo 16 ;;
    test_cleanup_state.sh) echo 15 ;;
    test_agent_counts.sh) echo 11 ;;
    test_audit_quality_fixes.sh|test_integration_e2e.sh|test_probe_harness_cpp.sh|test_rg_safe.sh|test_triage.sh) echo 9 ;;
    test_grep_wrapper.sh|test_edges.sh|test_agent_counts_regression.sh|test_asan_multi.sh) echo 8 ;;
    test_triage_reachability.sh) echo 6 ;;
    test_decision_triage.sh|test_s6_consumers.sh|test_integration_triage.sh|test_rg_wrapper.sh|test_decision_strategy_pick.sh) echo 5 ;;
    test_find_seed.sh|test_llm_decide.sh|test_export_repro_run.sh|test_export_repro_lib_discover.sh|test_doc_neutrality.sh|test_timeout.sh|test_run_asan.sh) echo 4 ;;
    test_*.py) echo 1 ;;
    *)
      case "$(test_category "$name")" in
        integration|decision) echo 4 ;;
        wrapper|unit) echo 2 ;;
        static|python) echo 1 ;;
        *) echo 1 ;;
      esac
      ;;
  esac
}

prioritize_parallel_tests() {
  local tf index weight tab line
  local -a heavy=()
  local -a filler=()
  local -a ordered=()
  tab=$(printf '\t')
  index=0
  while IFS= read -r line; do
    weight="${line%%$tab*}"
    tf="${line#*$tab}"
    if [ "$weight" -ge 15 ]; then
      heavy+=("$tf")
    else
      filler+=("$tf")
    fi
  done < <(
    for tf in "${TEST_FILES[@]}"; do
      index=$((index + 1))
      weight=$(test_weight "$tf")
      printf '%06d\t%06d\t%s\n' "$weight" "$index" "$tf"
    done | sort -t "$tab" -k1,1nr -k2,2n | awk -F '\t' '{ print $1 "\t" $3 }'
  )

  local h=0 f=0 n fill
  fill="${TEST_HEAVY_FILLERS:-3}"
  case "$fill" in ''|*[!0-9]*) fill=3 ;; esac
  [ "$fill" -lt 1 ] && fill=1
  while [ "$h" -lt "${#heavy[@]}" ] || [ "$f" -lt "${#filler[@]}" ]; do
    if [ "$h" -lt "${#heavy[@]}" ]; then
      ordered+=("${heavy[$h]}")
      h=$((h + 1))
    fi
    n=0
    while [ "$n" -lt "$fill" ] && [ "$f" -lt "${#filler[@]}" ]; do
      ordered+=("${filler[$f]}")
      f=$((f + 1))
      n=$((n + 1))
    done
  done
  TEST_FILES=("${ordered[@]}")
}

is_exclusive_test() {
  local tf="$1"
  [ "${TEST_ALLOW_HEAVY_PARALLEL:-1}" = "1" ] && return 1
  [ "$(test_weight "$tf")" -ge 15 ]
}

split_exclusive_tests() {
  local tf
  EXCLUSIVE_TEST_FILES=()
  PARALLEL_TEST_FILES=()
  for tf in "${TEST_FILES[@]}"; do
    if is_exclusive_test "$tf"; then
      EXCLUSIVE_TEST_FILES+=("$tf")
    else
      PARALLEL_TEST_FILES+=("$tf")
    fi
  done
}

collect_tests() {
  local pattern tf category seen_key
  local -a seen=()
  if [ "${#PATTERNS[@]}" -eq 0 ]; then
    PATTERNS=(test_*.sh test_*.py)
  fi
  for pattern in "${PATTERNS[@]}"; do
    for tf in "$TESTS_DIR"/$pattern; do
      [ -f "$tf" ] || continue
      seen_key=":$tf:"
      case ":${seen[*]}:" in *"$seen_key"*) continue ;; esac
      category=$(test_category "$tf")
      if [ -n "$CATEGORY_FILTER" ] && [ "$category" != "$CATEGORY_FILTER" ]; then
        continue
      fi
      TEST_FILES+=("$tf")
      seen+=("$tf")
    done
  done
}

TOTAL_PASSED=0
TOTAL_FAILED=0
ERRORS=()
TEST_FILES=()
EXCLUSIVE_TEST_FILES=()
PARALLEL_TEST_FILES=()
TIMINGS=()
TIMING_ROWS=()

# Color output
BOLD='\033[1m'
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

run_test_file() {
  local tf="$1"
  local name
  local category
  local start elapsed
  name=$(basename "$tf")
  name="${name%.sh}"
  name="${name%.py}"
  category=$(test_category "$tf")
  local output
  start=$SECONDS
  case "$tf" in
    *.py) output=$(python3 "$tf" 2>&1) ;;
    *)    output=$(bash "$tf" 2>&1) ;;
  esac
  local rc=$?
  elapsed=$((SECONDS - start))
  printf "${BOLD}=== %s [%s] (%ss) ===${NC}\n" "$name" "$category" "$elapsed"
  echo "$output"
  # Count passes/fails from output
  local p f
  p=$(echo "$output" | grep -c '✓' || true)
  f=$(echo "$output" | grep -c '✗' || true)
  TOTAL_PASSED=$((TOTAL_PASSED + p))
  TOTAL_FAILED=$((TOTAL_FAILED + f))
  if [ "$rc" -ne 0 ]; then
    printf "${RED}  Suite exit code: %s%s\n" "$rc" "$NC"
    ERRORS+=("$name")
  fi
  TIMINGS+=("$elapsed $name")
  TIMING_ROWS+=("$name"$'\t'"$category"$'\t'"$p"$'\t'"$f"$'\t'"$rc"$'\t'"$elapsed"$'\t'"$(test_weight "$tf")"$'\t'"$tf")
  return "$rc"
}

run_test_file_to_dir() {
  local tf="$1" out_dir="$2" index="$3"
  local name category output rc p f start elapsed
  name=$(basename "$tf")
  name="${name%.sh}"
  name="${name%.py}"
  category=$(test_category "$tf")
  start=$SECONDS
  case "$tf" in
    *.py) output=$(python3 "$tf" 2>&1) ;;
    *)    output=$(bash "$tf" 2>&1) ;;
  esac
  rc=$?
  elapsed=$((SECONDS - start))
  p=$(echo "$output" | grep -c '✓' || true)
  f=$(echo "$output" | grep -c '✗' || true)
  printf '%s' "$output" > "$out_dir/$index.out"
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$name" "$category" "$p" "$f" "$rc" "$elapsed" "$tf" > "$out_dir/$index.meta"
}

run_tests_parallel() {
  local out_dir index tf running
  out_dir=$(mktemp -d "${TMPDIR:-/tmp}/audit-tests-run-XXXXXXXX")
  index=0
  for tf in "${TEST_FILES[@]}"; do
    index=$((index + 1))
    while true; do
      running=$(jobs -pr | wc -l | tr -d ' ')
      [ "$running" -lt "$JOBS" ] && break
      sleep 0.05
    done
    run_test_file_to_dir "$tf" "$out_dir" "$index" &
  done
  wait

  local i meta name category p f rc elapsed path
  i=1
  while [ "$i" -le "$index" ]; do
    if [ ! -f "$out_dir/$i.meta" ]; then
      ERRORS+=("missing-result-$i")
      i=$((i + 1))
      continue
    fi
    IFS=$'\t' read -r name category p f rc elapsed path < "$out_dir/$i.meta"
    printf "${BOLD}=== %s [%s] (%ss) ===${NC}\n" "$name" "$category" "$elapsed"
    cat "$out_dir/$i.out"
    echo ""
    TOTAL_PASSED=$((TOTAL_PASSED + p))
    TOTAL_FAILED=$((TOTAL_FAILED + f))
    if [ "$rc" -ne 0 ]; then
      printf "${RED}  Suite exit code: %s%s\n" "$rc" "$NC"
      ERRORS+=("$name")
    fi
    TIMINGS+=("$elapsed $name")
    TIMING_ROWS+=("$name"$'\t'"$category"$'\t'"$p"$'\t'"$f"$'\t'"$rc"$'\t'"$elapsed"$'\t'"$(test_weight "$path")"$'\t'"$path")
    i=$((i + 1))
  done
  rm -rf "$out_dir"
}

write_timing_artifact() {
  [ "${#TIMING_ROWS[@]}" -gt 0 ] || return 0
  local timing_file
  timing_file="${TEST_TIMINGS_FILE:-$SCRIPT_ROOT/output/test-timings.tsv}"
  mkdir -p "$(dirname "$timing_file")" 2>/dev/null || return 0
  {
    printf 'suite\tcategory\tpassed\tfailed\trc\tseconds\tweight\tpath\n'
    printf '%s\n' "${TIMING_ROWS[@]}" | sort -t $'\t' -k6,6nr
  } > "$timing_file" 2>/dev/null || true
}

format_elapsed_seconds() {
  local s="${1:-}"
  case "$s" in ''|*[!0-9]*) printf '?\n'; return ;; esac
  if [ "$s" -lt 60 ]; then
    printf '%ss\n' "$s"
  elif [ "$s" -lt 3600 ]; then
    printf '%dm%02ds\n' "$((s / 60))" "$((s % 60))"
  else
    printf '%dh%02dm%02ds\n' "$((s / 3600))" "$(((s % 3600) / 60))" "$((s % 60))"
  fi
}

RUNNER_START_SECONDS=$SECONDS

collect_tests
if [ "${#TEST_FILES[@]}" -eq 0 ]; then
  echo "tests/run-tests.sh: no tests matched" >&2
  exit 2
fi

if [ "$LIST_ONLY" -eq 1 ]; then
  for tf in "${TEST_FILES[@]}"; do
    printf '%-12s %s\n' "$(test_category "$tf")" "${tf#$TESTS_DIR/}"
  done
  exit 0
fi

JOBS=$(detect_default_jobs)
printf "${BOLD}Running %d test file(s) with %d job(s)${NC}\n\n" "${#TEST_FILES[@]}" "$JOBS"

if [ "$JOBS" -le 1 ] || [ "${#TEST_FILES[@]}" -eq 1 ]; then
  for tf in "${TEST_FILES[@]}"; do
    run_test_file "$tf" || true
    echo ""
  done
else
  split_exclusive_tests
  if [ "${#EXCLUSIVE_TEST_FILES[@]}" -gt 0 ]; then
    printf "${BOLD}Running %d heavyweight suite(s) exclusively${NC}\n\n" "${#EXCLUSIVE_TEST_FILES[@]}"
    for tf in "${EXCLUSIVE_TEST_FILES[@]}"; do
      run_test_file "$tf" || true
      echo ""
    done
  fi
  TEST_FILES=("${PARALLEL_TEST_FILES[@]}")
  prioritize_parallel_tests
  if [ "${#TEST_FILES[@]}" -gt 0 ]; then
    run_tests_parallel
  fi
fi

echo ""
printf "${BOLD}========================================${NC}\n"
if [ "$TOTAL_FAILED" -eq 0 ]; then
  failed_color="$GREEN"
else
  failed_color="$RED"
fi
printf "${BOLD}  RESULTS: ${GREEN}%d passed${NC}, ${failed_color}%d failed${NC}\n" "$TOTAL_PASSED" "$TOTAL_FAILED"
total_elapsed=$((SECONDS - RUNNER_START_SECONDS))
printf "${BOLD}  Total time:${NC} %s (%ss)\n" "$(format_elapsed_seconds "$total_elapsed")" "$total_elapsed"
if [ "${#ERRORS[@]}" -gt 0 ]; then
  printf "${RED}  Failed suites: %s${NC}\n" "${ERRORS[*]}"
fi
if [ "${#TIMINGS[@]}" -gt 0 ]; then
  printf "${BOLD}  Slowest suites:${NC} "
  printf '%s\n' "${TIMINGS[@]}" \
    | sort -rn \
    | awk 'NR<=5 { printf "%s%s(%ss)", (NR==1 ? "" : ", "), $2, $1 } END { print "" }'
  write_timing_artifact
  timing_file="${TEST_TIMINGS_FILE:-$SCRIPT_ROOT/output/test-timings.tsv}"
  [ -f "$timing_file" ] && printf "${BOLD}  Timing artifact:${NC} %s\n" "$timing_file"
fi
printf "${BOLD}========================================${NC}\n"

[ "$TOTAL_FAILED" -eq 0 ] && [ "${#ERRORS[@]}" -eq 0 ]
