#!/usr/bin/env bash
#
# OpenClaw Credential Vault — OS-Level Isolation Setup
#
# This script sets up the Rust resolver binary with setuid permissions
# for OS-level credential isolation. Must be run as root.
#
# Usage:
#   sudo bash /path/to/vault-setup.sh
#
# What it does:
#   1. Creates 'openclaw-vault' system user (no login, no home directory)
#   2. Installs the resolver binary to /usr/local/bin/ with setuid
#   3. Creates /var/lib/openclaw-vault/ with restricted permissions
#   4. Migrates credential files from user vault to system vault
#   5. Updates vault config to use binary resolver mode
#
set -euo pipefail

# ── Require root ──
if [ "$(id -u)" -ne 0 ]; then
  echo "Error: This script must be run as root."
  echo "Usage: sudo bash $0"
  exit 1
fi

# ── Resolve paths ──
# OPENCLAW_VAULT_DIR can be overridden; defaults to ~user/.openclaw/vault
# OPENCLAW_USER is the non-root user who owns the vault
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Auto-detect the calling user (the one who ran sudo)
if [ -n "${SUDO_USER:-}" ]; then
  OPENCLAW_USER="$SUDO_USER"
elif [ -n "${OPENCLAW_USER:-}" ]; then
  OPENCLAW_USER="$OPENCLAW_USER"
else
  echo "Error: Cannot determine the OpenClaw user."
  echo "Run with sudo (which sets SUDO_USER) or set OPENCLAW_USER."
  exit 1
fi

USER_HOME=$(eval echo "~${OPENCLAW_USER}")
VAULT_DIR="${OPENCLAW_VAULT_DIR:-${USER_HOME}/.openclaw/vault}"
SYSTEM_VAULT_DIR="/var/lib/openclaw-vault"
DEST_BINARY="/usr/local/bin/openclaw-vault-resolver"

# ── Find the resolver binary ──
# Search order: bin/<platform>-<arch>/ in package, then dev build paths
ARCH="$(uname -m)"
case "$ARCH" in
  x86_64)  ARCH_DIR="linux-x64" ;;
  aarch64) ARCH_DIR="linux-arm64" ;;
  *)       ARCH_DIR="linux-${ARCH}" ;;
esac

SOURCE_BINARY=""
SEARCH_PATHS=(
  "${SCRIPT_DIR}/${ARCH_DIR}/openclaw-vault-resolver"
  "${SCRIPT_DIR}/../resolver/target/release/openclaw-vault-resolver"
  "${SCRIPT_DIR}/../resolver/target/x86_64-unknown-linux-musl/release/openclaw-vault-resolver"
)

for p in "${SEARCH_PATHS[@]}"; do
  if [ -f "$p" ]; then
    SOURCE_BINARY="$p"
    break
  fi
done

if [ -z "$SOURCE_BINARY" ]; then
  echo "Error: Resolver binary not found for ${ARCH_DIR}."
  echo "Searched:"
  for p in "${SEARCH_PATHS[@]}"; do
    echo "  $p"
  done
  exit 1
fi

echo "OpenClaw Credential Vault — OS-Level Isolation Setup"
echo "===================================================="
echo ""
echo "  User:          ${OPENCLAW_USER}"
echo "  Vault dir:     ${VAULT_DIR}"
echo "  System dir:    ${SYSTEM_VAULT_DIR}"
echo "  Binary:        ${SOURCE_BINARY}"
echo ""

# ── Step 1: Create system user ──
if id openclaw-vault &>/dev/null; then
  echo "✓ System user 'openclaw-vault' already exists"
else
  useradd --system --no-create-home --shell /usr/sbin/nologin openclaw-vault
  echo "✓ Created system user 'openclaw-vault'"
fi

# ── Step 2: Install resolver binary ──
cp "$SOURCE_BINARY" "$DEST_BINARY"
chown openclaw-vault:openclaw-vault "$DEST_BINARY"
chmod u+s,a+rx "$DEST_BINARY"
echo "✓ Resolver binary installed: ${DEST_BINARY} (setuid openclaw-vault)"

# ── Step 3: Create system vault directory ──
mkdir -p "$SYSTEM_VAULT_DIR"
chown openclaw-vault:openclaw-vault "$SYSTEM_VAULT_DIR"
chmod 700 "$SYSTEM_VAULT_DIR"
echo "✓ System vault directory: ${SYSTEM_VAULT_DIR}"

# ── Step 4: Migrate credential files ──
MIGRATED=0
if [ -d "$VAULT_DIR" ]; then
  for f in "$VAULT_DIR"/*.enc "$VAULT_DIR"/.vault-meta.json; do
    [ -f "$f" ] || continue
    BASENAME="$(basename "$f")"
    cp "$f" "${SYSTEM_VAULT_DIR}/${BASENAME}"
    chown openclaw-vault:openclaw-vault "${SYSTEM_VAULT_DIR}/${BASENAME}"
    chmod 600 "${SYSTEM_VAULT_DIR}/${BASENAME}"
    MIGRATED=$((MIGRATED + 1))
  done
fi

if [ "$MIGRATED" -gt 0 ]; then
  echo "✓ Migrated ${MIGRATED} file(s) to ${SYSTEM_VAULT_DIR}"
else
  echo "ℹ No credential files to migrate"
fi

# ── Step 5: Update vault config ──
TOOLS_YAML="${VAULT_DIR}/tools.yaml"
if [ -f "$TOOLS_YAML" ]; then
  # Update resolverMode to binary (simple sed — works for YAML)
  if grep -q "resolverMode:" "$TOOLS_YAML"; then
    sed -i 's/resolverMode:.*/resolverMode: binary/' "$TOOLS_YAML"
  else
    echo "resolverMode: binary" >> "$TOOLS_YAML"
  fi
  # Ensure the file is owned by the original user, not root
  chown "${OPENCLAW_USER}:${OPENCLAW_USER}" "$TOOLS_YAML"
  echo '✓ Config updated: resolverMode = "binary"'
else
  echo "⚠ No tools.yaml found at ${TOOLS_YAML} — run 'openclaw vault init' first"
fi

echo ""
echo "✓ Setup complete — credentials are now isolated behind OS-user separation."
echo "  Run 'openclaw doctor fix' to restart the gateway with the new configuration."
