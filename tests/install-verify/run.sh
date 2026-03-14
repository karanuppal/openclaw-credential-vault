#!/usr/bin/env bash
#
# Host-side orchestrator for install verification tests.
# Builds the plugin, creates Docker image, runs test combos.
#
# Usage:
#   bash tests/install-verify/run.sh                       # Run all 3 Debian combos
#   bash tests/install-verify/run.sh --platform debian12   # Explicit platform
#   bash tests/install-verify/run.sh --platform debian12 --install I1 --setup S2  # Single combo
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

# Parse args
PLATFORM="debian12"
INSTALL=""
SETUP=""

while [[ $# -gt 0 ]]; do
  case $1 in
    --platform) PLATFORM="$2"; shift 2 ;;
    --install)  INSTALL="$2"; shift 2 ;;
    --setup)    SETUP="$2"; shift 2 ;;
    *) echo "Unknown arg: $1"; exit 1 ;;
  esac
done

IMAGE_NAME="vault-verify-${PLATFORM}"
DOCKERFILE="${SCRIPT_DIR}/Dockerfile.${PLATFORM}"

if [ ! -f "$DOCKERFILE" ]; then
  echo "Error: Dockerfile not found: $DOCKERFILE"
  exit 1
fi

# ── Step 1: Build ──
echo "=== Step 1: npm run build ==="
cd "$PROJECT_DIR"
npm run build

# ── Step 2: Pack ──
echo ""
echo "=== Step 2: npm pack ==="
TARBALL_NAME=$(npm pack --pack-destination /tmp --json 2>/dev/null | jq -r '.[0].filename')
TARBALL_PATH="/tmp/${TARBALL_NAME}"
echo "Tarball: $TARBALL_PATH"

if [ -z "$TARBALL_NAME" ] || [ ! -f "$TARBALL_PATH" ]; then
  echo "Error: npm pack did not create expected tarball at $TARBALL_PATH"
  exit 1
fi

# ── Step 3: Build Docker image (if not cached) ──
echo ""
echo "=== Step 3: Docker image (${IMAGE_NAME}) ==="

# Check if image exists
if docker image inspect "$IMAGE_NAME" &>/dev/null; then
  echo "Image cached, skipping build. Use 'docker rmi ${IMAGE_NAME}' to rebuild."
else
  echo "Building image..."
  docker build \
    -f "$DOCKERFILE" \
    -t "$IMAGE_NAME" \
    "$SCRIPT_DIR"
fi

# ── Step 4: Run combos ──
echo ""

run_combo() {
  local install_path="$1"
  local setup_path="$2"
  local label="${install_path}+${setup_path}"

  echo "=== Running: ${label} on ${PLATFORM} ==="

  docker run --rm \
    -v "${TARBALL_PATH}:/tarball/plugin.tgz:ro" \
    -v "${PROJECT_DIR}/install.sh:/verify/install.sh:ro" \
    -e "INSTALL_PATH=${install_path}" \
    -e "SETUP_PATH=${setup_path}" \
    "$IMAGE_NAME"

  local exit_code=$?
  if [ $exit_code -ne 0 ]; then
    echo "FAILED: ${label}"
    return 1
  fi
  echo ""
  return 0
}

TOTAL=0
PASSED=0
FAILED=0
FAILED_COMBOS=""

run_and_track() {
  TOTAL=$((TOTAL + 1))
  if run_combo "$1" "$2"; then
    PASSED=$((PASSED + 1))
  else
    FAILED=$((FAILED + 1))
    FAILED_COMBOS="${FAILED_COMBOS} $1+$2"
  fi
}

if [ -n "$INSTALL" ] && [ -n "$SETUP" ]; then
  # Single combo mode
  run_and_track "$INSTALL" "$SETUP"
else
  # Run all combos for the platform
  if [ "$PLATFORM" = "debian12" ]; then
    # Debian runs all 3 combos
    run_and_track "I1" "S2"
    run_and_track "I2" "S1"
    run_and_track "I2" "S2"
  else
    # Other platforms: S2 combos only (platform-dependent)
    run_and_track "I1" "S2"
    run_and_track "I2" "S2"
  fi
fi

# ── Summary ──
echo ""
echo "==============================="
echo "  Install Verification Summary"
echo "==============================="
echo "  Platform: ${PLATFORM}"
echo "  Passed:   ${PASSED}/${TOTAL}"
echo "  Failed:   ${FAILED}/${TOTAL}"
if [ -n "$FAILED_COMBOS" ]; then
  echo "  Failed combos:${FAILED_COMBOS}"
fi
echo "==============================="

# Cleanup tarball
rm -f "$TARBALL_PATH"

if [ "$FAILED" -gt 0 ]; then
  exit 1
fi
echo ""
echo "All install verification tests passed!"
