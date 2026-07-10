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

# Container shells export AUDIT_BUILD_SUFFIX; fixtures build bare build-<san>/
# trees. Clear it here too — python suites never source tests/helpers.sh.
unset AUDIT_BUILD_SUFFIX

usage() {
  cat <<'EOF'
Usage:
  tests/run-tests.sh [options] [test_file_pattern...]
  tests/run-tests.sh --category integration
  tests/run-tests.sh --jobs 4 test_py_migration_regressions.py test_severity.sh
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
        # nodejs is required: bin/audit:gemini_cli_check_bundled_ripgrep uses
        # node for realpath/platform detection and audit-runner checks
        # asserts its WARN path. CA certificates are needed for HTTPS git/gh
        # traffic in minimal images. npm and curl are backend-install-path
        # dependencies, not test-suite prerequisites.
        if command -v apt-get >/dev/null 2>&1; then
          export DEBIAN_FRONTEND=noninteractive
          apt-get update
          apt-get install -y --no-install-recommends \
            bash binutils ca-certificates clang file gh git jq libclang-rt-dev llvm \
            nodejs procps python3 python3-venv ripgrep
        elif command -v dnf >/dev/null 2>&1; then
          dnf install -y \
            bash binutils ca-certificates clang compiler-rt coreutils diffutils file findutils gawk gh git \
            grep jq llvm nodejs procps-ng python3 python3-pip ripgrep sed \
            || dnf install -y \
              bash binutils ca-certificates clang compiler-rt coreutils diffutils file findutils gawk gh git \
              grep jq llvm nodejs procps-ng python3 python3-pip sed
        elif command -v microdnf >/dev/null 2>&1; then
          microdnf install -y \
            bash binutils ca-certificates clang compiler-rt coreutils diffutils file findutils gawk gh git \
            grep jq llvm nodejs procps-ng python3 python3-pip sed
        elif command -v yum >/dev/null 2>&1; then
          yum install -y \
            bash binutils ca-certificates clang compiler-rt coreutils diffutils file findutils gawk gh git \
            grep jq llvm nodejs procps-ng python3 python3-pip ripgrep sed \
            || yum install -y \
              bash binutils ca-certificates clang compiler-rt coreutils diffutils file findutils gawk gh git \
              grep jq llvm nodejs procps-ng python3 python3-pip sed
        else
          echo "tests/run-tests.sh: no supported package manager found; install bash python3 file git gh jq clang llvm binutils nodejs ripgrep ca-certificates" >&2
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
      # sancov is not checked: the Debian/Ubuntu llvm package does not ship it.
      missing=()
      for tool in bash python3 file git gh jq clang clang++ nm ar node rg llvm-symbolizer; do
        command -v "$tool" >/dev/null 2>&1 || missing+=("$tool")
      done
      venv_probe="$(mktemp -d "${TMPDIR:-/tmp}/tokenfuzz-venv-check.XXXXXX" 2>/dev/null || true)"
      if [ -n "$venv_probe" ]; then
        python3 -m venv "$venv_probe/venv" >/dev/null 2>&1 || missing+=("python3-venv")
        rm -rf "$venv_probe"
      else
        missing+=("mktemp")
      fi
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
    test_grep_wrapper|test_rg_wrapper|test_sed_wrapper|test_rg_safe|test_zdotdir_shim) echo "wrapper" ;;
    *) echo "unit" ;;
  esac
}

# Self-calibrating scheduling weights. A suite's weight is its own
# wall-clock seconds from the previous run, read out of the timing
# artifact the runner already writes (write_timing_artifact). This is
# what lets prioritize_parallel_tests start every job slot on the
# heaviest suites without a hand-maintained table of per-suite numbers
# that silently rots as suites grow, split, or are added.
#
# PRIOR_TIMINGS is a ":name=seconds:" string map (bash 3.2 has no
# associative arrays). Populated once by load_prior_timings.
PRIOR_TIMINGS=""
load_prior_timings() {
  local f="${TEST_TIMINGS_FILE:-$SCRIPT_ROOT/output/test-timings.tsv}"
  [ -f "$f" ] || return 0
  local name secs rest
  # Columns: suite category passed failed rc seconds weight path
  while IFS=$'\t' read -r name _ _ _ _ secs rest; do
    case "$name" in suite|'') continue ;; esac        # skip header/blank
    case "$secs" in ''|*[!0-9]*) continue ;; esac     # need an integer
    PRIOR_TIMINGS="${PRIOR_TIMINGS}:${name}=${secs}"
  done < "$f"
  [ -n "$PRIOR_TIMINGS" ] && PRIOR_TIMINGS="${PRIOR_TIMINGS}:"
}

# Cold-start bootstrap: until a timing artifact exists, only these few
# genuinely slow suites need to lead so the first run still packs well.
# Inclusion criterion: observed > ~10s wall under the parallel runner.
# Everything else falls through to a coarse category default and then
# self-corrects from real timings on the next run.
bootstrap_weight() {
  case "$1" in
    test_workqueue|test_benchmark) echo 25 ;;
    test_severity|test_sanitizer_multi|test_probe_harness_cpp|test_setup_target|test_py_migration_regressions|test_llm_invoke_py) echo 15 ;;
    test_multilang_support|test_benchmark_cells|test_benchmark_reverify|test_recon_changes) echo 10 ;;
    *) echo "" ;;
  esac
}

test_weight() {
  local raw="$1" name
  name="${raw##*/}"; name="${name%.sh}"; name="${name%.py}"
  # 1) Prior measured seconds win — never stale, no list to maintain.
  case "$PRIOR_TIMINGS" in
    *":$name="*)
      local rest="${PRIOR_TIMINGS#*:$name=}"; rest="${rest%%:*}"
      if [ -n "$rest" ]; then echo "$rest"; return; fi
      ;;
  esac
  # 2) Small cold-start bootstrap for the known-heavy suites.
  local boot; boot=$(bootstrap_weight "$name")
  if [ -n "$boot" ]; then echo "$boot"; return; fi
  # 3) Structural fallback by category (no per-suite numbers).
  case "$(test_category "$raw")" in
    integration|decision) echo 4 ;;
    wrapper|unit) echo 2 ;;
    static|python) echo 1 ;;
    *) echo 1 ;;
  esac
}

# Order the parallel batch by weight, longest-processing-time first. The
# launcher starts suites in this order as job slots free, so every slot
# begins on the heaviest suites and short suites backfill as the long
# ones finish — the standard LPT heuristic, which minimises the makespan
# tail. (An earlier heavy/filler interleave queued short suites ahead of
# long ones, so only a couple of long suites started in the first wave
# and the rest piled up at the end, leaving cores idle and stretching the
# run.)
prioritize_parallel_tests() {
  local tf index weight tab line
  local -a ordered=()
  tab=$(printf '\t')
  index=0
  while IFS= read -r line; do
    ordered+=("${line#*$tab}")
  done < <(
    for tf in "${TEST_FILES[@]}"; do
      index=$((index + 1))
      weight=$(test_weight "$tf")
      printf '%06d\t%06d\t%s\n' "$weight" "$index" "$tf"
    done | sort -t "$tab" -k1,1nr -k2,2n | awk -F '\t' '{ print $1 "\t" $3 }'
  )
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

load_prior_timings
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
