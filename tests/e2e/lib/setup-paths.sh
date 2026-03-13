#!/usr/bin/env bash
# setup-paths.sh — Setup path functions for E2E tests
# Each function initializes the vault with a different key derivation + resolver mode.
set -euo pipefail

VAULT_SETUP_SCRIPT="${VAULT_SETUP_SCRIPT:-$(openclaw plugins path openclaw-credential-vault 2>/dev/null)/bin/vault-setup.sh}"

# S1: Machine key + inline resolver (no sudo, no binary)
setup_machine_inline() {
  echo "--- Setup path: machine key + inline ---"
  openclaw vault init
  echo "--- Setup complete: machine + inline ---"
}

# S2: Machine key + binary resolver (sudo bash vault-setup.sh)
setup_machine_binary() {
  echo "--- Setup path: machine key + binary ---"
  openclaw vault init

  # Find vault-setup.sh - try multiple locations
  local setup_script=""
  if [[ -f "${VAULT_SETUP_SCRIPT}" ]]; then
    setup_script="${VAULT_SETUP_SCRIPT}"
  else
    # Search common install locations
    for candidate in \
      "$(npm root -g 2>/dev/null)/openclaw-credential-vault/bin/vault-setup.sh" \
      "/usr/local/lib/node_modules/openclaw-credential-vault/bin/vault-setup.sh" \
      "${REPO_ROOT:-/workspace}/bin/vault-setup.sh"; do
      if [[ -f "$candidate" ]]; then
        setup_script="$candidate"
        break
      fi
    done
  fi

  if [[ -z "$setup_script" ]]; then
    echo "WARNING: vault-setup.sh not found, falling back to inline mode"
    return 0
  fi

  sudo bash "$setup_script" || {
    echo "WARNING: vault-setup.sh failed (exit $?), falling back to inline mode"
    return 0
  }
  echo "--- Setup complete: machine + binary ---"
}

# S3: Passphrase + inline resolver (no sudo, no binary)
setup_passphrase_inline() {
  echo "--- Setup path: passphrase + inline ---"
  export OPENCLAW_VAULT_PASSPHRASE="${OPENCLAW_VAULT_PASSPHRASE:-e2e-test-passphrase-not-real}"
  openclaw vault init --passphrase
  echo "--- Setup complete: passphrase + inline ---"
}

# S4: Passphrase + binary resolver (sudo bash vault-setup.sh)
setup_passphrase_binary() {
  echo "--- Setup path: passphrase + binary ---"
  export OPENCLAW_VAULT_PASSPHRASE="${OPENCLAW_VAULT_PASSPHRASE:-e2e-test-passphrase-not-real}"
  openclaw vault init --passphrase

  local setup_script=""
  if [[ -f "${VAULT_SETUP_SCRIPT}" ]]; then
    setup_script="${VAULT_SETUP_SCRIPT}"
  else
    for candidate in \
      "$(npm root -g 2>/dev/null)/openclaw-credential-vault/bin/vault-setup.sh" \
      "/usr/local/lib/node_modules/openclaw-credential-vault/bin/vault-setup.sh" \
      "${REPO_ROOT:-/workspace}/bin/vault-setup.sh"; do
      if [[ -f "$candidate" ]]; then
        setup_script="$candidate"
        break
      fi
    done
  fi

  if [[ -z "$setup_script" ]]; then
    echo "WARNING: vault-setup.sh not found, falling back to inline mode"
    return 0
  fi

  sudo bash "$setup_script" || {
    echo "WARNING: vault-setup.sh failed (exit $?), falling back to inline mode"
    return 0
  }
  echo "--- Setup complete: passphrase + binary ---"
}

# Map setup ID strings to functions
run_setup() {
  local setup_id="$1"
  case "$setup_id" in
    machine-inline)      setup_machine_inline ;;
    machine-binary)      setup_machine_binary ;;
    passphrase-inline)   setup_passphrase_inline ;;
    passphrase-binary)   setup_passphrase_binary ;;
    *)
      echo "ERROR: Unknown setup path: $setup_id"
      return 1
      ;;
  esac
}
