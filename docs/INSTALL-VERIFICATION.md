# Install Verification Tests

## What This Is

Tests that prove the plugin **installs correctly and works** on a clean machine. Not functional testing — the 610 unit + integration tests already prove the code works. This verifies that packaging, installation, and platform-specific setup all succeed.

**The core assumption:** if install + basic usage works on a platform, everything else works. The code logic is platform-independent TypeScript. The only platform-dependent parts are the install process, the setup script, and the Rust binary resolver.

---

## Why These Tests Exist

The existing test suite imports vault modules directly from the source tree (`from "../src/crypto.js"`). This means:

- A file missing from the npm tarball → tests still pass (importing from source, not package)
- A dependency in `devDependencies` instead of `dependencies` → tests still pass (all deps installed in dev)
- `vault-setup.sh` broken on Alpine → tests still pass (never run the setup script)
- Rust binary doesn't compile on ARM → tests still pass (binary is optional, tests skip if missing)

Install verification catches what source-tree testing cannot: **does the packaged artifact work on a real machine?**

---

## Why Docker

The install needs a **clean machine** — no prior plugin install, no existing vault, no dev dependencies. Docker provides a throwaway HOME and a known OS image. The alternative (faking HOME with `HOME=/tmp/fake-user`) is possible but messy with sudo, cleanup, and potential leaks.

Docker also provides **different OS images** for platform-specific testing — which only matters for the parts that are platform-dependent.

---

## What's Platform-Dependent

| Component | Platform-dependent? | Why |
|-----------|---------------------|-----|
| TypeScript vault code | No | Node.js runs the same everywhere |
| `openclaw plugins install` | No | npm install, same everywhere |
| `vault-setup.sh` | **Yes** | Creates system user (`useradd` vs `adduser`), sets file permissions, installs binary. Different syntax on Debian vs Alpine vs macOS. |
| Rust binary resolver | **Yes** | Compiled per architecture. x86_64 Linux binary won't run on ARM or macOS. |
| Perl stdout scrubber | Mostly no | Standard Perl, but pipe behavior could theoretically differ |

**Conclusion:** S1 (inline, no binary) only needs one platform test. S2 (binary resolver) needs every target platform.

---

## Install Paths

- **I1 — Curl install script** (`curl -fsSL ... | bash`): The documented primary path. Runs `openclaw plugins install` + `sudo bash vault-setup.sh` in one step. Always produces S2 (binary resolver).

- **I2 — Plugin install** (`openclaw plugins install <package>`): Standard OpenClaw plugin command. User manually runs `vault init` and optionally `sudo bash vault-setup.sh`.

## Setup Paths

- **S1 — Inline** (`vault init`, no sudo): Machine key encryption, TypeScript-only resolution. No system user, no binary.

- **S2 — Binary resolver** (`vault init` + `sudo bash vault-setup.sh`): Creates dedicated system user, installs setuid binary, full OS-level credential isolation.

## Valid Combinations (3)

| Combo | Install | Setup | Platform-dependent? |
|-------|---------|-------|---------------------|
| I1+S2 | Curl script | Binary (automatic) | **Yes** — tests setup script + binary on target OS |
| I2+S1 | plugins install | Inline | **No** — pure TypeScript, one platform sufficient |
| I2+S2 | plugins install | Binary (manual) | **Yes** — tests binary resolver on target OS |

I1+S1 is invalid — the curl script always runs sudo setup.

---

## What Each Test Verifies

Each combo runs 5 commands inside a clean Docker container:

```
1. Install the plugin (curl script or plugins install)
2. vault init                                    → vault directory created, config written
3. vault add github --key ghp_FAKE... --yes      → credential encrypted + stored, auto-detect works
4. vault test github                             → decryption works, injection rules correct
5. vault remove github --purge                   → credential + config + scrub rules fully cleaned up
```

**Setup-conditional checks:**
- **S2 combos:** step 4 verifies "Binary resolver: OK" in output (Rust binary decrypted the credential)
- **S1 combos:** step 2 verifies Perl warning appears (no Perl in minimal Docker image) and recommends installing Perl or running full setup. On images with Perl pre-installed, verify no warning appears.

**Perl handling by install path:**
- **I1 (curl → setup script):** `vault-setup.sh` auto-installs Perl via the system package manager (apt/apk/yum/dnf). Verify Perl is present after install.
- **I2+S1 (no sudo):** `vault init` warns that Perl is missing and explains the consequence (no real-time pipe scrubbing, after-call scrubber still works). Verify warning text is correct.
- **I2+S2 (manual sudo setup):** `vault-setup.sh` auto-installs Perl. Verify Perl is present after setup.

That's it. **5 commands, ~40 seconds per combo.** If these pass, the package is correctly built, all files are included, dependencies resolve, and platform-specific components work.

---

## Platform Matrix

**S1 combos (platform-independent):** run on Debian 12 only. TypeScript is TypeScript.

**S2 combos (platform-dependent):** run on every target platform where the Rust binary is shipped.

| Platform | I1+S2 | I2+S1 | I2+S2 |
|----------|-------|-------|-------|
| Debian 12 | ✓ | ✓ | ✓ |
| Ubuntu 24 | ✓ | — | ✓ |
| Alpine | ✓ | — | ✓ |
| macOS | When binary ships for ARM | — | When binary ships for ARM |

Total test runs: 3 (Debian) + 2 (Ubuntu) + 2 (Alpine) = **7 runs, ~5 minutes sequential, parallel in CI.**

---

## Running Locally

```bash
npm run verify-install
```

This runs:
1. `npm run build` — compile TypeScript (~5s)
2. `npm pack` — create tarball, same artifact that goes to npm (~2s)
3. Run 3 combos on Debian 12 sequentially (~2 min)

**Total: ~2.5 minutes.**

### Base image (built once)

```dockerfile
FROM debian:12-slim
# Perl intentionally omitted — vault-setup.sh auto-installs it.
# This lets us verify the auto-install works.
RUN apt-get update && apt-get install -y curl sudo jq
RUN curl -fsSL https://deb.nodesource.com/setup_22.x | bash - && apt-get install -y nodejs
RUN npm install -g openclaw
```

Rebuilt only when OpenClaw ships a new major version.

### Container entrypoint

```bash
#!/usr/bin/env bash
set -euo pipefail

INSTALL_PATH="${INSTALL_PATH:-I1}"
SETUP_PATH="${SETUP_PATH:-S2}"

echo "=== Install verification: ${INSTALL_PATH} + ${SETUP_PATH} ==="

# Install
if [[ "$INSTALL_PATH" == "I1" ]]; then
  bash /verify/install.sh /tarball/plugin.tgz
else
  openclaw plugins install /tarball/plugin.tgz
fi

# Setup
openclaw vault init
if [[ "$SETUP_PATH" == "S2" ]]; then
  sudo bash "$(find ~/.openclaw -name vault-setup.sh -print -quit)"
fi

# Verify
openclaw vault add github --key "ghp_FAKETOKEN0123456789abcdefghijklmnop" --yes
openclaw vault test github
openclaw vault remove github

echo "=== PASSED: ${INSTALL_PATH} + ${SETUP_PATH} ==="
```

---

## CI Pipeline

```yaml
name: Install Verification
on: [push, pull_request]

jobs:
  unit-and-integration:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with: { node-version: 22 }
      - run: npm ci && npm test

  verify-install:
    needs: unit-and-integration
    strategy:
      matrix:
        include:
          # All 3 combos on Debian
          - { platform: debian12, install: I1, setup: S2 }
          - { platform: debian12, install: I2, setup: S1 }
          - { platform: debian12, install: I2, setup: S2 }
          # S2 combos on other platforms
          - { platform: ubuntu24, install: I1, setup: S2 }
          - { platform: ubuntu24, install: I2, setup: S2 }
          - { platform: alpine,   install: I1, setup: S2 }
          - { platform: alpine,   install: I2, setup: S2 }
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with: { node-version: 22 }
      - run: npm run verify-install -- --platform ${{ matrix.platform }} --install ${{ matrix.install }} --setup ${{ matrix.setup }}
```

---

## Directory Structure

```
tests/install-verify/
├── run.sh                    # Host-side: build, pack, run combos
├── entrypoint.sh             # Container-side: install + setup + verify
├── Dockerfile.debian12       # Base image
├── Dockerfile.ubuntu24       # Base image
├── Dockerfile.alpine         # Base image
└── README.md                 # How to run, what to do if it fails

# The real install.sh (project root) is mounted into the container at runtime.
# No test-only install script — we test the actual install script.
```

---

## What This Replaces

- `docs/E2E-TEST-DESIGN.md` — replaced by this document
- `tests/e2e/` — 14-combo bash test suite (retired)
- `tests/gate/` — never built, design superseded

## Relationship to Other Tests

- **`npm test` (610 tests, ~37s):** proves the code works — logic, crypto, scrubbing, injection, security. Runs locally from source tree.
- **`npm run verify-install` (3-7 combos, ~2-5 min):** proves the package works — install, setup, and platform-specific components. Runs in Docker.
- **Zero overlap.** They test different things.
