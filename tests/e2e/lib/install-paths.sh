#!/usr/bin/env bash
# install-paths.sh — Install path functions for E2E tests
# Each function installs the credential vault plugin via a different method.
# Assumes OpenClaw + Node are already installed in the base image.
set -euo pipefail

REPO_ROOT="${REPO_ROOT:-/workspace}"
INSTALL_SCRIPT_URL="${INSTALL_SCRIPT_URL:-https://raw.githubusercontent.com/karanuppal/openclaw-credential-vault/main/install.sh}"

# I1: curl | bash — one-liner install script
# Note: this always runs vault-setup.sh with sudo (binary mode)
# So it only pairs with S2/S4, not S1/S3 (inline)
install_curl() {
  echo "--- Install path: curl | bash ---"
  curl -fsSL "$INSTALL_SCRIPT_URL" | bash
  echo "--- Install via curl complete ---"
}

# I2: openclaw plugins install — standard npm install via OpenClaw CLI
install_npm() {
  echo "--- Install path: openclaw plugins install ---"
  openclaw plugins install openclaw-credential-vault
  echo "--- Install via npm complete ---"
}

# I3: openclaw plugins install --pin — npm install with pinned version
install_pin() {
  echo "--- Install path: openclaw plugins install --pin ---"
  openclaw plugins install openclaw-credential-vault --pin
  echo "--- Install via npm --pin complete ---"
}

# I4: git clone + --link — developer source link mode
install_link() {
  echo "--- Install path: git clone + link ---"
  if [[ -d "$REPO_ROOT" ]]; then
    cd "$REPO_ROOT"
    npm install
    npm run build
    openclaw plugins link "$REPO_ROOT"
  else
    echo "ERROR: REPO_ROOT=$REPO_ROOT does not exist"
    return 1
  fi
  echo "--- Install via source link complete ---"
}
