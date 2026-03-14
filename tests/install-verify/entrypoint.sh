#!/usr/bin/env bash
#
# Container entrypoint for install verification tests.
# Runs plugin install + setup + 5 verification commands.
# Outputs TAP-compatible results.
#
set -euo pipefail

INSTALL_PATH="${INSTALL_PATH:-I1}"
SETUP_PATH="${SETUP_PATH:-S2}"
TARBALL="/tarball/plugin.tgz"

# I1 (curl script) always runs sudo setup → always produces S2
if [[ "$INSTALL_PATH" == "I1" && "$SETUP_PATH" != "S2" ]]; then
  echo "# Note: I1 always produces S2 (curl script runs sudo setup). Overriding ${SETUP_PATH} → S2."
  SETUP_PATH="S2"
fi

echo "TAP version 13"
echo "# Install verification: ${INSTALL_PATH} + ${SETUP_PATH}"

# Calculate expected test count
# Base: install(1) + init(1) + add(1) + test(1) + remove(1) = 5
EXPECTED=5
if [[ "$INSTALL_PATH" == "I1" ]]; then
  EXPECTED=$((EXPECTED + 1))  # Perl present check
fi
if [[ "$INSTALL_PATH" != "I1" && "$SETUP_PATH" == "S1" ]] && ! command -v perl &>/dev/null; then
  EXPECTED=$((EXPECTED + 1))  # Perl warning check
fi
if [[ "$INSTALL_PATH" != "I1" && "$SETUP_PATH" == "S2" ]]; then
  EXPECTED=$((EXPECTED + 1))  # setup script step
fi
if [[ "$SETUP_PATH" == "S2" ]]; then
  EXPECTED=$((EXPECTED + 1))  # binary resolver check
fi
echo "1..${EXPECTED}"

TESTS=0
PASS=0
FAIL=0

tap_ok() {
  TESTS=$((TESTS + 1))
  PASS=$((PASS + 1))
  echo "ok ${TESTS} - $1"
}

tap_fail() {
  TESTS=$((TESTS + 1))
  FAIL=$((FAIL + 1))
  echo "not ok ${TESTS} - $1"
  if [ -n "${2:-}" ]; then
    echo "  ---"
    echo "  output: |"
    echo "$2" | sed 's/^/    /'
    echo "  ---"
  fi
}

# ── Step 1: Install ──
echo "# Step 1: Install (${INSTALL_PATH})"

if [[ "$INSTALL_PATH" == "I1" ]]; then
  # I1: real install.sh with local tarball argument — does plugin install + sudo setup
  INSTALL_OUTPUT=$(bash /verify/install.sh "$TARBALL" 2>&1) || {
    tap_fail "I1 install.sh" "$INSTALL_OUTPUT"
    echo "# Failed ${FAIL}/${TESTS}"
    exit 1
  }
  tap_ok "I1 install.sh succeeded"

  # I1 always produces S2 (binary resolver) — verify Perl was installed by setup script
  if command -v perl &>/dev/null; then
    tap_ok "I1 post-install: Perl is present (installed by setup script)"
  else
    tap_fail "I1 post-install: Perl should be present after setup script"
  fi
else
  # I2: standard plugin install
  INSTALL_OUTPUT=$(openclaw plugins install "$TARBALL" 2>&1) || {
    tap_fail "I2 plugin install" "$INSTALL_OUTPUT"
    echo "# Failed ${FAIL}/${TESTS}"
    exit 1
  }
  tap_ok "I2 plugin install succeeded"
fi

# ── Step 2: vault init ──
echo "# Step 2: vault init"

if [[ "$INSTALL_PATH" == "I1" ]]; then
  # I1 already ran vault init + sudo setup — skip separate init
  tap_ok "vault init (handled by I1 install script)"
else
  INIT_OUTPUT=$(openclaw vault init 2>&1) || {
    tap_fail "vault init" "$INIT_OUTPUT"
    echo "# Failed ${FAIL}/${TESTS}"
    exit 1
  }
  tap_ok "vault init succeeded"

  # S1 on images without Perl: vault init should warn about missing Perl
  if [[ "$SETUP_PATH" == "S1" ]] && ! command -v perl &>/dev/null; then
    if echo "$INIT_OUTPUT" | grep -qi "perl"; then
      tap_ok "vault init warns about missing Perl (S1, no Perl)"
    else
      tap_fail "vault init should warn about missing Perl" "$INIT_OUTPUT"
    fi
  fi
fi

# ── Step 3: Setup (S2 only, and only for I2) ──
if [[ "$INSTALL_PATH" != "I1" && "$SETUP_PATH" == "S2" ]]; then
  echo "# Step 3: sudo setup (S2)"
  SETUP_SCRIPT=$(find ~/.openclaw -name vault-setup.sh -print -quit 2>/dev/null || true)
  if [ -z "$SETUP_SCRIPT" ]; then
    tap_fail "vault-setup.sh not found in ~/.openclaw"
    echo "# Failed ${FAIL}/${TESTS}"
    exit 1
  fi
  SETUP_OUTPUT=$(sudo bash "$SETUP_SCRIPT" 2>&1) || {
    tap_fail "sudo vault-setup.sh" "$SETUP_OUTPUT"
    echo "# Failed ${FAIL}/${TESTS}"
    exit 1
  }
  tap_ok "sudo vault-setup.sh succeeded"
fi

# ── Step 4: vault add ──
echo "# Step 4: vault add github"
ADD_OUTPUT=$(openclaw vault add github --key "ghp_FAKETOKEN0123456789abcdefghijklmnop" --yes 2>&1) || {
  tap_fail "vault add github" "$ADD_OUTPUT"
  echo "# Failed ${FAIL}/${TESTS}"
  exit 1
}
tap_ok "vault add github succeeded"

# ── Step 5: vault test ──
echo "# Step 5: vault test github"
TEST_OUTPUT=$(openclaw vault test github 2>&1) || {
  tap_fail "vault test github" "$TEST_OUTPUT"
  echo "# Failed ${FAIL}/${TESTS}"
  exit 1
}
tap_ok "vault test github succeeded"

# S2: verify binary resolver is active
if [[ "$SETUP_PATH" == "S2" ]]; then
  if echo "$TEST_OUTPUT" | grep -q "Binary resolver: OK"; then
    tap_ok "vault test confirms binary resolver (S2)"
  else
    tap_fail "vault test should report 'Binary resolver: OK' for S2" "$TEST_OUTPUT"
  fi
fi

# ── Step 6: vault remove ──
echo "# Step 6: vault remove github --purge"
REMOVE_OUTPUT=$(openclaw vault remove github --purge 2>&1) || {
  tap_fail "vault remove github --purge" "$REMOVE_OUTPUT"
  echo "# Failed ${FAIL}/${TESTS}"
  exit 1
}
tap_ok "vault remove github --purge succeeded"

# ── Summary ──
if [ "$FAIL" -gt 0 ]; then
  echo "# Failed ${FAIL}/${TESTS}"
  exit 1
else
  echo "# All ${TESTS} tests passed: ${INSTALL_PATH} + ${SETUP_PATH}"
  exit 0
fi
