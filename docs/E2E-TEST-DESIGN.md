# Release Gate — Test Design

## The Question This Answers

**"If I publish this version, will users have a working experience?"**

Everything flows from that. Not "do the internal functions work" (610 unit tests already prove that). The release gate proves the product works the way a user actually uses it.

---

## Test Layers

### Layer 1: Unit Tests (610 tests, ~37s, `npm test`)

Already exist. Cover all internal correctness:
- Crypto: encryption, decryption, corruption, key derivation
- Scrubbing: patterns, false positives, literal matching, edge cases
- Hooks: before_tool_call injection, after_tool_call scrubbing
- Registry: auto-detection, known tools, format guessing
- Config: read/write, upsert, remove, migration
- Browser: cookies, passwords, domain pinning
- Security: 54 adversarial attack scenarios
- Sandbox, sub-agent isolation, concurrency

**These do NOT spawn the `openclaw` CLI.** They import modules directly. Fast and thorough, but don't prove the assembled product works.

### Layer 2: Release Gate (this document, `npm run gate`)

**Runs locally before every publish.** Docker containers mimic a real user's first experience across install × setup combinations. Must pass before `npm publish`.

### Layer 3: CI Platform Matrix (GitHub Actions)

Same gate test, multiple OS images. Catches platform-specific issues. Runs on push/PR.

---

## Layer 2: The Release Gate

### What it tests

A real user's journey from install to daily use:

1. Install the plugin (via curl script or `openclaw plugins install`)
2. Initialize the vault and set up security
3. Add credentials (auto-detect, custom, browser)
4. Use them (list, show, test, inject, scrub)
5. Maintain them (rotate, remove)
6. Edge cases (errors, corruption, special chars)

### The Matrix

**Install paths (2):**
- **I1** — Curl install script (`curl -fsSL ... | bash`) — the documented primary install path. **Always runs `sudo bash vault-setup.sh`**, so it always produces binary resolver mode (S2).
- **I2** — Plugin install command (`openclaw plugins install <tarball>`) — the standard OpenClaw plugin install. User manually runs `vault init` and optionally `sudo bash vault-setup.sh`.

**Setup paths (2):**
- **S1** — Machine key + inline (default: `vault init`, no sudo, no binary resolver)
- **S2** — Machine key + binary (`vault init` + `sudo bash vault-setup.sh`, full OS-level isolation)

**Valid combinations: 3 total**

I1×S1 is invalid — the curl install script always runs sudo setup, so I1 always implies S2.

| Combo | Install | Setup | What it proves |
|-------|---------|-------|----------------|
| 1 | I1 (curl) | S2 (binary) | Primary user path — one-line install with full security |
| 2 | I2 (plugins install) | S1 (inline) | Manual install, simplest setup, no sudo |
| 3 | I2 (plugins install) | S2 (binary) | Manual install + opt-in binary resolver |

Each combo runs in a separate Docker container with a clean HOME.

### Why Docker

The gate must run in a **clean environment** — no leftover vault config, no pre-installed plugin, no existing credentials. Docker gives us a fresh OS with nothing but Node + OpenClaw. That's what a new user has.

### Speed strategy

The old design spawned `openclaw vault <cmd>` as a subprocess for every test — 39 invocations × 7s each = 4.5 minutes per combo. CPU profiling showed 99% of that time is loading modules the vault never uses (ajv, zod, baileys/WhatsApp, highlight.js).

The fix: **two phases inside each container.**

**Phase A — CLI smoke tests (real subprocess calls, ~50s):**
The commands a user actually types. 7 subprocess calls that prove the CLI binary works end-to-end.

**Phase B — Functional depth (direct module import, ~5s):**
Import vault modules in a single Node process. Run the deeper tests (injection matching, scrubbing correctness, corruption recovery) without paying the 7s CLI startup tax repeatedly.

**Per combo: ~60 seconds. All 3 combos sequential: ~3 minutes.**

---

### Phase A: CLI Smoke Tests (7 tests)

These spawn `openclaw vault` as a real subprocess. They prove the CLI is wired up correctly — argument parsing, output formatting, exit codes, and that the plugin loads in the full OpenClaw runtime.

```
A1. vault init                              → exit 0, vault dir created
A2. vault add github --key ghp_FAKE... --yes → exit 0, credential stored
A3. vault add amazon --type browser-password --domain .amazon.com --key "p@ss" → exit 0
A4. vault list                              → exit 0, shows github + amazon
A5. vault test github                       → exit 0, shows "configured correctly"
A6. vault rotate github --key ghp_NEW... --yes → exit 0, rotated
A7. vault remove github                     → exit 0, removed from list
```

Setup-conditional behavior:
- **S2 (binary):** A5 additionally checks for "Binary resolver: OK" in output
- **S1 (inline):** A5 checks for inline mode confirmation

### Phase B: Functional Depth (19 tests)

Single Node process imports vault modules from the installed plugin path. Uses a temp vault dir. No subprocess overhead.

**Credential lifecycle:**
```
B1.  Add + decrypt round-trip (machine key)
B2.  Auto-detect: GitHub PAT → correct injection rules
B3.  Auto-detect: npm token → correct injection rules
B4.  Auto-detect: Stripe key → correct injection rules
B5.  Custom credential → generic rules applied
B6.  Browser cookie: store + retrieve JSON payload
B7.  Special characters preserved exactly (p@$$w0rd!#%^&*())
B8.  Long credential (4096 chars) round-trip
B9.  Rotation: new value replaces old, timestamp updated
B10. Remove: credential file deleted, config updated
B11. Remove --purge: scrub rules also removed
```

**Injection + scrubbing:**
```
B12. Matching command → env vars populated with credential
B13. Non-matching command → no injection
B14. Scrubbing: credential value replaced with [VAULT:tool]
B15. Scrubbing: credential absent from output even in compound commands
B16. Multi-credential: two tools injected + scrubbed in same call
```

**Error handling + resilience:**
```
B17. Corrupt .enc file → clear error, other credentials unaffected
B18. Nonexistent tool → clear error message
B19. Rapid cycle: 5 add + 5 remove → clean state, no orphaned files
```

---

### Fake Token Convention

```
ghp_FAKETOKEN0123456789abcdefghijklmnop      # GitHub PAT
ghp_ROTATEDTOKEN9876543210zyxwvutsrqpon       # Rotated GitHub PAT
npm_FAKETOKEN0123456789abcdefghijklmnopqrst   # npm
sk_test_FAKETOKEN0123456789abcdefghijklmnop   # Stripe
```

All tokens are obviously fake but match real format patterns so auto-detect works.

---

## Container Setup

### Base image (built once, cached)

```dockerfile
FROM debian:12-slim
RUN apt-get update && apt-get install -y curl sudo perl jq
RUN curl -fsSL https://deb.nodesource.com/setup_22.x | bash - && apt-get install -y nodejs
RUN npm install -g openclaw
```

Rebuilt only when OpenClaw ships a new major version.

### Gate run

```bash
# npm run gate does:
npm run build
npm pack                              # → openclaw-credential-vault-x.y.z.tgz

COMBOS=("I1:S2" "I2:S1" "I2:S2")

for combo in "${COMBOS[@]}"; do
  IFS=':' read -r install setup <<< "$combo"
  docker run --rm \
    -v ./openclaw-credential-vault-*.tgz:/tarball/plugin.tgz:ro \
    -v ./tests/gate:/gate:ro \
    -e E2E_INSTALL_PATH="$install" \
    -e E2E_SETUP_PATH="$setup" \
    vault-gate-debian12 \
    bash /gate/run-gate.sh
done
```

### Inside the container (`run-gate.sh`)

```bash
#!/usr/bin/env bash
set -euo pipefail

INSTALL_PATH="${E2E_INSTALL_PATH:-I1}"
SETUP_PATH="${E2E_SETUP_PATH:-S2}"

echo "=== Combo: ${INSTALL_PATH} + ${SETUP_PATH} ==="

# Step 1: Install plugin
if [[ "$INSTALL_PATH" == "I1" ]]; then
  # Curl install script — installs plugin + runs sudo setup in one step
  bash /gate/install-curl.sh /tarball/plugin.tgz
else
  # Manual plugin install
  openclaw plugins install /tarball/plugin.tgz
  openclaw vault init
  if [[ "$SETUP_PATH" == "S2" ]]; then
    sudo bash "$(openclaw vault setup-path)/vault-setup.sh"
  fi
fi

# Step 2: Run tests
node /gate/phase-a-cli.mjs
node /gate/phase-b-functional.mjs

echo "=== GATE PASSED: ${INSTALL_PATH} + ${SETUP_PATH} ==="
```

---

## Directory Structure

```
tests/gate/
├── run-gate.sh               # Container entrypoint: install + setup + tests
├── run-all.sh                # Host-side orchestrator: build, pack, run 3 combos
├── install-curl.sh           # Mimics curl install script using local tarball
├── phase-a-cli.mjs           # 7 CLI subprocess tests (TAP output)
├── phase-b-functional.mjs    # 19 direct-import tests (TAP output)
├── Dockerfile.debian12       # Base image
└── README.md                 # How to run, what to do if it fails
```

Old `tests/e2e/` directory and its 14-combo infrastructure are retired.

---

## Layer 3: CI Platform Matrix

Same gate, different OS images. Runs in GitHub Actions on push and PR.

```yaml
name: Release Gate
on: [push, pull_request]

jobs:
  unit-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with: { node-version: 22 }
      - run: npm ci && npm test

  gate:
    needs: unit-tests
    strategy:
      matrix:
        platform: [debian12, ubuntu24, alpine]
        combo: ["I1:S2", "I2:S1", "I2:S2"]
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with: { node-version: 22 }
      - run: npm run gate -- --platform ${{ matrix.platform }} --combo ${{ matrix.combo }}
```

macOS added as a separate job when binary resolver ships for ARM.

---

## What Changed from the Old Design

The old design tested 4 install paths × 4 setup paths = 14 combinations.

**Dropped install paths:**
- I3 (`--pin`) — tests OpenClaw's plugin pinning, not vault functionality
- I4 (source link) — developer workflow for local dev, not a user install path

**Dropped setup paths:**
- S3 (passphrase + inline) — no real security advantage over machine key
- S4 (passphrase + binary) — same; passphrase mode can be added later if needed

**Invalid combo removed:**
- I1×S1 — the curl install script always runs `sudo bash vault-setup.sh`, so I1 always implies S2

**Result: 14 combos → 3 combos.** Each combo runs in ~60s. Total gate: ~3 minutes.

---

## Success Criteria

- `npm test` — 610 unit tests pass
- `npm run gate` — all 3 combos pass (26 tests each: 7 CLI + 19 functional)
- Both must pass before `npm publish`. Any gate failure blocks release.

---

## What This Replaces

- `tests/e2e/lifecycle-suite.sh` (33 bash tests, 39 subprocess calls per combo)
- `tests/e2e/run-e2e.sh` (14-combo orchestrator)
- `tests/e2e/run-combo.sh`
- 4 Dockerfiles (debian12, ubuntu22, ubuntu24, alpine)

All replaced by `tests/gate/` — 3 combos, ~3 minutes total, no redundancy with unit tests.
