#!/usr/bin/env bash
#
# OpenClaw Credential Vault — One-Line Installer
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/opscontrol711/openclaw-credential-vault/main/install.sh | bash
#
# What it does:
#   1. Installs the plugin via openclaw plugins install
#   2. Runs the setup script with sudo for OS-level credential isolation
#   3. Gateway auto-restarts to load the plugin
#
set -euo pipefail

echo ""
echo "OpenClaw Credential Vault — Installer"
echo "======================================"
echo ""

# ── Check prerequisites ──
if ! command -v openclaw &>/dev/null; then
  echo "Error: openclaw is not installed."
  echo "Install it first: curl -fsSL https://openclaw.ai/install.sh | bash"
  exit 1
fi

# ── Step 1: Install the plugin ──
echo "Installing plugin..."
openclaw plugins install openclaw-credential-vault

# ── Step 2: Find the setup script ──
# The plugin is installed somewhere under the openclaw state dir.
# Search for the setup script in common locations.
OPENCLAW_DIR="${OPENCLAW_STATE_DIR:-$HOME/.openclaw}"
SETUP_SCRIPT=""

# Search in plugins directory (standard install location)
for candidate in \
  "$OPENCLAW_DIR/plugins/credential-vault/bin/vault-setup.sh" \
  "$OPENCLAW_DIR/plugins/openclaw-credential-vault/bin/vault-setup.sh" \
  "$OPENCLAW_DIR/plugins/"*/bin/vault-setup.sh; do
  if [ -f "$candidate" ]; then
    SETUP_SCRIPT="$candidate"
    break
  fi
done

# Also check npm global paths (in case installed via npm directly)
if [ -z "$SETUP_SCRIPT" ]; then
  NPM_ROOT=$(npm root -g 2>/dev/null || true)
  if [ -n "$NPM_ROOT" ] && [ -f "$NPM_ROOT/openclaw-credential-vault/bin/vault-setup.sh" ]; then
    SETUP_SCRIPT="$NPM_ROOT/openclaw-credential-vault/bin/vault-setup.sh"
  fi
fi

if [ -z "$SETUP_SCRIPT" ]; then
  echo ""
  echo "⚠ Plugin installed, but could not locate vault-setup.sh automatically."
  echo "  Find it with: find ~/.openclaw -name vault-setup.sh"
  echo "  Then run: sudo bash /path/to/vault-setup.sh"
  exit 1
fi

# ── Step 3: Run setup with sudo ──
echo ""
echo "Setting up OS-level credential isolation..."
echo "This creates a dedicated system user — you'll be prompted for your password."
echo ""
sudo bash "$SETUP_SCRIPT"

echo ""
echo "✓ Installation complete!"
echo ""
echo "Next steps:"
echo "  openclaw vault add github --key \"ghp_your_token_here\""
echo "  openclaw vault test github"
echo ""
