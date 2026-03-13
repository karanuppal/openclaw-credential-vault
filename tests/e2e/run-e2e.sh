#!/usr/bin/env bash
# run-e2e.sh — E2E test orchestrator
# Builds Docker images, iterates the install×setup matrix, runs lifecycle suite.
#
# Usage:
#   bash tests/e2e/run-e2e.sh                    # Run all platforms
#   bash tests/e2e/run-e2e.sh --platform ubuntu22 # Run one platform
#   bash tests/e2e/run-e2e.sh --platform macos    # Run macOS (no Docker)
#   bash tests/e2e/run-e2e.sh --dry-run            # Show what would run
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

# Defaults
PLATFORMS=("ubuntu22" "ubuntu24" "debian12" "alpine")
INSTALL_PATHS=("curl" "npm" "pin" "link")
SETUP_PATHS=("machine-inline" "machine-binary" "passphrase-inline" "passphrase-binary")
DRY_RUN=false
SINGLE_PLATFORM=""
IMAGE_PREFIX="vault-e2e"
FAILURES=0
TOTAL=0
SKIPPED=0

# Parse arguments
while [[ $# -gt 0 ]]; do
  case "$1" in
    --platform)
      SINGLE_PLATFORM="$2"
      shift 2
      ;;
    --dry-run)
      DRY_RUN=true
      shift
      ;;
    --help|-h)
      echo "Usage: $0 [--platform <name>] [--dry-run]"
      echo ""
      echo "Platforms: ubuntu22 ubuntu24 debian12 alpine macos"
      echo ""
      echo "Options:"
      echo "  --platform  Run only one platform"
      echo "  --dry-run   Show matrix without running"
      exit 0
      ;;
    *)
      echo "Unknown option: $1"
      exit 1
      ;;
  esac
done

if [[ -n "$SINGLE_PLATFORM" ]]; then
  PLATFORMS=("$SINGLE_PLATFORM")
fi

# --- Matrix validity check ---
# curl script (I1) can't do inline mode (S1/S3) — it always runs vault-setup.sh
is_valid_combination() {
  local install="$1"
  local setup="$2"
  if [[ "$install" == "curl" ]] && [[ "$setup" == *"inline"* ]]; then
    return 1
  fi
  return 0
}

# --- Build Docker images ---
build_images() {
  echo "=== Building Docker images ==="
  for platform in "${PLATFORMS[@]}"; do
    if [[ "$platform" == "macos" ]]; then
      echo "--- Skipping Docker build for macOS (runs natively) ---"
      continue
    fi

    local dockerfile="${SCRIPT_DIR}/Dockerfile.${platform}"
    if [[ ! -f "$dockerfile" ]]; then
      echo "ERROR: Dockerfile not found: $dockerfile"
      exit 1
    fi

    echo "--- Building ${IMAGE_PREFIX}-${platform} ---"
    docker build \
      -f "$dockerfile" \
      -t "${IMAGE_PREFIX}-${platform}" \
      "$REPO_ROOT"
    echo "--- Built ${IMAGE_PREFIX}-${platform} ---"
  done
}

# --- Run a single matrix cell ---
run_cell() {
  local platform="$1"
  local install="$2"
  local setup="$3"
  local label="${platform}/${install}/${setup}"

  TOTAL=$((TOTAL + 1))

  if ! is_valid_combination "$install" "$setup"; then
    echo "=== SKIP: $label (invalid combination) ==="
    SKIPPED=$((SKIPPED + 1))
    return 0
  fi

  if $DRY_RUN; then
    echo "=== WOULD RUN: $label ==="
    return 0
  fi

  echo ""
  echo "=========================================="
  echo "=== Testing: $label ==="
  echo "=========================================="

  local rc=0

  if [[ "$platform" == "macos" ]]; then
    # macOS runs natively (no Docker)
    run_macos_cell "$install" "$setup" || rc=$?
  else
    # Docker platforms
    run_docker_cell "$platform" "$install" "$setup" || rc=$?
  fi

  if [[ "$rc" -ne 0 ]]; then
    echo "=== FAILED: $label (exit code $rc) ==="
    FAILURES=$((FAILURES + 1))
  else
    echo "=== PASSED: $label ==="
  fi
}

# --- Run inside Docker ---
run_docker_cell() {
  local platform="$1"
  local install="$2"
  local setup="$3"

  local env_args=(
    -e "E2E_INSTALL_PATH=${install}"
    -e "E2E_SETUP_MODE=${setup}"
    -e "E2E_PLATFORM=${platform}"
    -e "OPENCLAW_VAULT_PASSPHRASE=e2e-test-passphrase-not-real"
    -e "MOCK_PORT=9876"
  )

  local entrypoint_script='
    set -euo pipefail
    source /e2e/lib/install-paths.sh
    source /e2e/lib/setup-paths.sh

    echo "--- Running install path: '"$install"' ---"
    install_'"$install"'

    echo "--- Running setup path: '"$setup"' ---"
    run_setup "'"$setup"'"

    echo "--- Running lifecycle suite ---"
    bash /e2e/lifecycle-suite.sh
  '

  docker run --rm \
    "${env_args[@]}" \
    "${IMAGE_PREFIX}-${platform}" \
    -c "$entrypoint_script"
}

# --- Run on macOS (no Docker) ---
run_macos_cell() {
  local install="$1"
  local setup="$2"

  export E2E_INSTALL_PATH="$install"
  export E2E_SETUP_MODE="$setup"
  export E2E_PLATFORM="macos"
  export OPENCLAW_VAULT_PASSPHRASE="e2e-test-passphrase-not-real"
  export MOCK_PORT=9876

  # Source install and setup helpers
  source "${SCRIPT_DIR}/lib/install-paths.sh"
  source "${SCRIPT_DIR}/lib/setup-paths.sh"

  # Create temp home for isolation
  local temp_home
  temp_home=$(mktemp -d)
  export HOME="$temp_home"
  export REPO_ROOT="$REPO_ROOT"

  echo "--- Running install path: $install (macOS, HOME=$temp_home) ---"
  "install_${install}"

  echo "--- Running setup path: $setup ---"
  run_setup "$setup"

  echo "--- Running lifecycle suite ---"
  bash "${SCRIPT_DIR}/lifecycle-suite.sh"

  local rc=$?

  # Cleanup temp home
  rm -rf "$temp_home"

  return $rc
}

# --- Main ---
echo "====================================="
echo "  OpenClaw Credential Vault E2E Tests"
echo "====================================="
echo "Platforms: ${PLATFORMS[*]}"
echo "Install paths: ${INSTALL_PATHS[*]}"
echo "Setup paths: ${SETUP_PATHS[*]}"
echo ""

if [[ "${PLATFORMS[0]}" != "macos" ]]; then
  build_images
fi

for platform in "${PLATFORMS[@]}"; do
  for install in "${INSTALL_PATHS[@]}"; do
    for setup in "${SETUP_PATHS[@]}"; do
      run_cell "$platform" "$install" "$setup"
    done
  done
done

# --- Summary ---
echo ""
echo "====================================="
echo "  E2E Test Summary"
echo "====================================="
VALID=$((TOTAL - SKIPPED))
PASSED=$((VALID - FAILURES))
echo "Total cells:  $TOTAL"
echo "Skipped:      $SKIPPED (invalid combinations)"
echo "Ran:          $VALID"
echo "Passed:       $PASSED"
echo "Failed:       $FAILURES"
echo "====================================="

if [[ "$FAILURES" -gt 0 ]]; then
  echo "RESULT: FAIL"
  exit 1
else
  echo "RESULT: PASS"
  exit 0
fi
