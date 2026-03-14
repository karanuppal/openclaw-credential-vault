#!/usr/bin/env bash
#
# Simulates the curl install script using a local tarball.
# Mirrors what the real install.sh does: plugin install + sudo setup.
#
# Usage: bash install-curl.sh /path/to/plugin.tgz
#
set -euo pipefail

TARBALL="${1:?Usage: install-curl.sh <path-to-tarball>}"

if [ ! -f "$TARBALL" ]; then
  echo "Error: Tarball not found: $TARBALL"
  exit 1
fi

echo "=== Credential Vault — Install Script (local tarball) ==="
echo "Installing from: $TARBALL"

# Step 1: Install the plugin via OpenClaw
echo ""
echo "→ Installing plugin..."
openclaw plugins install "$TARBALL"
echo "✓ Plugin installed"

# Step 2: Run vault init
echo ""
echo "→ Initializing vault..."
openclaw vault init
echo "✓ Vault initialized"

# Step 3: Run sudo setup (installs binary resolver + Perl)
echo ""
echo "→ Running OS-level setup..."
SETUP_SCRIPT=$(find ~/.openclaw -name vault-setup.sh -print -quit 2>/dev/null || true)
if [ -z "$SETUP_SCRIPT" ]; then
  echo "Error: vault-setup.sh not found after plugin install"
  exit 1
fi
sudo bash "$SETUP_SCRIPT"
echo "✓ OS-level setup complete"

echo ""
echo "=== Credential Vault installed and configured ==="
