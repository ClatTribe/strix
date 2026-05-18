#!/usr/bin/env bash
# benchmarks/run_all.sh — drive every benchmark in one pass.
#
# Orchestrates the per_target + public fixture suites. Emits result
# JSON files into `benchmarks/per_target/baseline/` and
# `benchmarks/public/fixtures/*/baseline/`.
#
# Prerequisites:
#   - `STRIX_LLM` + `LLM_API_KEY` env vars set
#   - Docker daemon running (for fixtures with docker-compose)
#   - strix-sandbox image pulled (`docker pull ghcr.io/usestrix/strix-sandbox:0.1.13` or built locally)
#   - Python venv with pyyaml installed
#
# Usage:
#   ./run_all.sh                                   # full suite
#   ./run_all.sh --suite per_target                # per_target only
#   ./run_all.sh --suite public                    # direct-tool only
#   ./run_all.sh --fixture vampi                   # one fixture
#   ./run_all.sh --scan-mode standard|quick|deep   # per-fixture scan mode
#   ./run_all.sh --dry-run                         # print plan, don't execute
#
# Exit code:
#   0 — every fixture ran (whether or not it hit ceiling recall)
#   1 — at least one fixture failed to run (docker / strix crash)
#   2 — invocation error (missing env, bad arg)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="${SCRIPT_DIR}"
REPO_ROOT="$(cd "${ROOT}/.." && pwd)"

SUITE="all"           # all | per_target | public
SINGLE_FIXTURE=""
SCAN_MODE="standard"
DRY_RUN="0"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --suite)        SUITE="$2"; shift 2 ;;
    --fixture)      SINGLE_FIXTURE="$2"; shift 2 ;;
    --scan-mode)    SCAN_MODE="$2"; shift 2 ;;
    --dry-run)      DRY_RUN="1"; shift ;;
    --help|-h)
      sed -n '2,30p' "$0"
      exit 0
      ;;
    *)              echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

# ---------- Sanity ----------
if [[ -z "${STRIX_LLM:-}" || -z "${LLM_API_KEY:-}" ]]; then
  if [[ "${DRY_RUN}" != "1" ]]; then
    echo "error: STRIX_LLM and LLM_API_KEY must be set." >&2
    echo "example: export STRIX_LLM='anthropic/claude-sonnet-4-6' LLM_API_KEY='sk-ant-...'" >&2
    exit 2
  fi
fi

command -v docker >/dev/null 2>&1 || { echo "error: docker not on PATH" >&2; exit 2; }
command -v python3 >/dev/null 2>&1 || { echo "error: python3 not on PATH" >&2; exit 2; }

# ---------- Per-target fixtures ----------
# Each entry: <name>:<fixture_path_relative_to_per_target>
PER_TARGET_FIXTURES=(
  "juiceshop:fixtures/web/juiceshop"
  "vampi:fixtures/api/vampi"
  "crapi:fixtures/api/crapi"
  "flask-vuln:fixtures/code/flask-vuln"
  "vibe-app:fixtures/web+code/vibe-app"
)

# ---------- Public direct-tool benchmarks ----------
# Each entry: <name>:<runner_script>
PUBLIC_BENCHMARKS=(
  "sast-nodegoat:public/run_sast_benchmark.py"
  "sca-nodegoat:public/run_sca_benchmark.py"
  "iac-dockerfile:public/run_iac_benchmark.py"
)

FAILED=0
RAN=0

run_per_target() {
  local name="$1"
  local rel_path="$2"
  local fixture_dir="${ROOT}/per_target/${rel_path}"
  local baseline_dir="${ROOT}/per_target/baseline"
  local out_file="${baseline_dir}/${name}_${TIMESTAMP}_${SCAN_MODE}.json"

  if [[ ! -f "${fixture_dir}/expected.yaml" ]]; then
    echo "[skip] ${name}: fixture missing (${fixture_dir})" >&2
    return 0
  fi

  mkdir -p "${baseline_dir}"
  echo "[run] per_target/${name} (scan_mode=${SCAN_MODE})"
  echo "      fixture=${fixture_dir}"
  echo "      output=${out_file}"

  if [[ "${DRY_RUN}" == "1" ]]; then
    RAN=$((RAN + 1))
    return 0
  fi

  if ! python3 "${ROOT}/per_target/runner.py" \
        "${fixture_dir}" \
        --scan-mode "${SCAN_MODE}" \
        --output "${out_file}"; then
    echo "[FAIL] ${name} runner exited non-zero" >&2
    FAILED=$((FAILED + 1))
  fi
  RAN=$((RAN + 1))
}

run_public() {
  local name="$1"
  local script="$2"
  local runner_path="${ROOT}/${script}"

  if [[ ! -f "${runner_path}" ]]; then
    echo "[skip] ${name}: runner missing (${runner_path})" >&2
    return 0
  fi

  echo "[run] public/${name}"
  echo "      runner=${runner_path}"

  if [[ "${DRY_RUN}" == "1" ]]; then
    RAN=$((RAN + 1))
    return 0
  fi

  if ! python3 "${runner_path}"; then
    echo "[FAIL] ${name} runner exited non-zero" >&2
    FAILED=$((FAILED + 1))
  fi
  RAN=$((RAN + 1))
}

# ---------- Dispatch ----------
if [[ "${SUITE}" == "all" || "${SUITE}" == "per_target" ]]; then
  for entry in "${PER_TARGET_FIXTURES[@]}"; do
    name="${entry%%:*}"
    path="${entry##*:}"
    if [[ -n "${SINGLE_FIXTURE}" && "${SINGLE_FIXTURE}" != "${name}" ]]; then continue; fi
    run_per_target "${name}" "${path}"
  done
fi

if [[ "${SUITE}" == "all" || "${SUITE}" == "public" ]]; then
  for entry in "${PUBLIC_BENCHMARKS[@]}"; do
    name="${entry%%:*}"
    script="${entry##*:}"
    if [[ -n "${SINGLE_FIXTURE}" && "${SINGLE_FIXTURE}" != "${name}" ]]; then continue; fi
    run_public "${name}" "${script}"
  done
fi

echo
echo "=== summary ==="
echo "ran=${RAN}  failed=${FAILED}  scan_mode=${SCAN_MODE}  llm=${STRIX_LLM:-<unset>}"

if [[ "${FAILED}" -gt 0 ]]; then
  exit 1
fi
exit 0
