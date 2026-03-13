# E2E Test Design — Real User Experience Testing

## Philosophy

These tests simulate a real human typing commands in a terminal. No mocks, no stubs, no simulation. If these tests pass, the product works.

**Speed target: entire matrix completes in <5 minutes per platform.**

---

## Speed Architecture

### The problem
Installing Node + OpenClaw + npm packages from the registry takes 5-10 minutes per Docker image. Multiply by platforms and combos = hours of waiting. That's not a test suite, it's a build pipeline.

### The principle
**Separate what we're testing from what we're not.**

We are NOT testing: npm's download speed, Node.js installation, OpenClaw's core installer.
We ARE testing: our plugin installs, our vault commands work, injection + scrubbing work.

### The solution: pre-built base images + local tarball

1. **Pre-built base images** — one per platform, built once and cached. Contains OS + Node 22 + OpenClaw + Perl + all system deps. Published to GitHub Container Registry (`ghcr.io`). Only rebuilt when OpenClaw releases a new version.

2. **Local tarball install** — at test time, `npm pack` creates a `.tgz` from the repo. All install paths use this local file instead of fetching from the npm registry. Takes <2 seconds vs 5+ minutes.

3. **No network dependency** — tests run fully offline after the base image is pulled. No registry fetches, no downloads, no timeouts.

### Install path mapping (local tarball)
| Path | Original (slow) | Fast equivalent |
|---|---|---|
| I1 (curl script) | Downloads from GitHub + npm | Script pointed at local tarball |
| I2 (npm install) | `openclaw plugins install openclaw-credential-vault` | `openclaw plugins install /e2e/openclaw-credential-vault.tgz` |
| I3 (npm --pin) | Same + `--pin` | `openclaw plugins install /e2e/openclaw-credential-vault.tgz --pin` |
| I4 (source link) | `git clone` + `--link` | `openclaw plugins install --link /workspace` |

All complete in <5 seconds. We're testing that OpenClaw correctly loads the plugin from each install method — not that npm can download files.

---

## The Matrix

### Install paths
| ID | Method | Description |
|---|---|---|
| I1 | Install script | `install.sh` pointed at local tarball |
| I2 | Local tarball | `openclaw plugins install <local.tgz>` |
| I3 | Local tarball + pin | `openclaw plugins install <local.tgz> --pin` |
| I4 | Source link | `openclaw plugins install --link /workspace` |

### Setup paths
| ID | Method | Description |
|---|---|---|
| S1 | Machine key + inline | `vault init` (no sudo, no binary resolver) |
| S2 | Machine key + binary | `vault init` + `sudo bash vault-setup.sh` |
| S3 | Passphrase + inline | `vault init --passphrase` (no binary resolver) |
| S4 | Passphrase + binary | `vault init --passphrase` + `sudo bash vault-setup.sh` |

### Valid combinations
|  | S1 (machine+inline) | S2 (machine+binary) | S3 (passphrase+inline) | S4 (passphrase+binary) |
|---|---|---|---|---|
| **I1** (install script) | ✗ | ✓ | ✗ | ✓ |
| **I2** (local tarball) | ✓ | ✓ | ✓ | ✓ |
| **I3** (tarball + pin) | ✓ | ✓ | ✓ | ✓ |
| **I4** (source link) | ✓ | ✓ | ✓ | ✓ |

14 valid combos per platform. I1 always runs setup (binary mode only).

### Platforms
| Platform | Image | Binary resolver? |
|---|---|---|
| Ubuntu 22.04 | `ghcr.io/karanuppal/vault-e2e-ubuntu22` | Yes |
| Ubuntu 24.04 | `ghcr.io/karanuppal/vault-e2e-ubuntu24` | Yes |
| Debian 12 | `ghcr.io/karanuppal/vault-e2e-debian12` | Yes |
| Alpine | `ghcr.io/karanuppal/vault-e2e-alpine` | No (no glibc) — tests graceful fallback |
| macOS | GitHub Actions runner (no Docker) | No (no Darwin binary) — tests graceful fallback |

---

## Container Lifecycle

```
[Pre-built base image from GHCR: OS + Node + OpenClaw]
  → [Start container, mount local tarball + test scripts]
  → [Run install path (I1/I2/I3/I4) — <5 sec]
  → [Run setup path (S1/S2/S3/S4) — <5 sec]
  → [Run lifecycle test suite — ~30 sec]
  → [Destroy container]
```

**Total per combo: ~40 seconds.**
**Total per platform (14 combos): ~10 minutes.**
**Total all platforms: ~40 minutes** (parallel in CI: ~10 minutes).

---

## Lifecycle Test Suite

Single suite, runs identically on every matrix cell.

### Phase 1: Verify installation (~2 sec)
1. Plugin in `openclaw plugins list` as loaded
2. `openclaw vault` shows help
3. `openclaw vault list` returns empty

### Phase 2: Add credentials (~5 sec)
4. Auto-detect: `vault add github --key "ghp_FAKETOKEN..."` → `.enc` created, rules detected, test passes
5. Custom: `vault add myapi --key "..." --env MY_API_KEY --command "myapp *"` → custom rules stored
6. Browser password: `vault add amazon --type browser-password --domain .amazon.com --key "p@ss!"`
7. Browser cookie: `vault add example --type browser-cookie --domain .example.com`
8. Special chars: `vault add special --key 'p@$$w0rd!#%^&*()'` → preserved exactly

### Phase 3: Read operations (~3 sec)
9. `vault list` → all 5 tools, correct columns, no credential values
10. `vault show github` → rules + metadata, no value
11. `vault test github` → decryption OK, resolver mode matches setup path
12. `vault logs` → access events from above operations

### Phase 4: Modify operations (~3 sec)
13. `vault rotate github --key "ghp_NEWTOKEN..."` → timestamp updated, new value works
14. `vault remove special` → `.enc` deleted, removed from list
15. `vault remove myapi --purge` → system vault copy also deleted if binary mode

### Phase 5: Gateway injection & scrubbing (~15 sec)
**(Mock LLM provider, started in container)**

16. Injection: `gh api user` → `GH_TOKEN` in subprocess env
17. Scrubbing: `echo $GH_TOKEN` → output has `[VAULT:github]`, NOT fake token
18. Multi-credential: compound command → both injected, both scrubbed
19. Non-matching: `ls -la` → no injection, no scrubbing
20. Compound commands: `gh api user && echo done`, pipes, semicolons → all work
21. Error commands: `gh api /nonexistent` → injected, error scrubbed, exit code preserved
22. Hot-reload add: `vault add newcred` → immediate injection, no restart, log shows "hot-reloaded"
23. Hot-reload remove: `vault remove newcred` → immediate de-injection, no crash
24. Binary resolver (S2/S4): credential via setuid binary, non-root can't read `.enc`
25. Inline fallback (S1/S3): credential inline, warning logged
26. Protocol mismatch (S2/S4): tampered binary → actionable error

### Phase 6: Error handling (~5 sec)
27. Empty key: `vault add bad --key ""` → clear error
28. Nonexistent tool: `vault test doesnotexist` → clear error
29. Corrupt `.enc`: corrupt one file → that one errors, others work
30. No init: `vault add` without init → clear error
31. Setup without sudo: `bash vault-setup.sh` → permission error
32. Long credential: 4096 chars → works end-to-end
33. Rapid cycle: 10 adds + 10 removes → clean state

---

## Fake Token Convention

```
ghp_FAKETOKEN0123456789abcdefghijklmnop     # GitHub PAT (triggers auto-detect)
npm_FAKETOKEN0123456789abcdefghijklmnopqrst  # npm token
```

Scrub markers: `[VAULT:github]`, `[VAULT:npm]` (deliberately different — tests can distinguish leaked vs scrubbed)

---

## Implementation

### Base image build (one-time, cached)
```yaml
# .github/workflows/build-e2e-images.yml
# Triggered manually or on OpenClaw version bump
# Pushes to ghcr.io/karanuppal/vault-e2e-<platform>
```

Each base image Dockerfile:
```dockerfile
FROM debian:12
RUN apt-get update && apt-get install -y nodejs npm perl sudo jq git curl
RUN npm install -g openclaw
RUN useradd -m -s /bin/bash testuser && echo "testuser ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers
USER testuser
```

### Test run (fast, every PR)
```bash
# run-e2e.sh
# 1. npm pack → creates local .tgz
# 2. For each platform:
#    For each valid install×setup combo:
#      docker run --rm \
#        -v $(pwd)/openclaw-credential-vault.tgz:/e2e/plugin.tgz \
#        -v $(pwd)/tests/e2e:/e2e \
#        -v $(pwd):/workspace \
#        ghcr.io/karanuppal/vault-e2e-debian12 \
#        bash /e2e/run-combo.sh <install> <setup>
```

### Directory structure
```
tests/e2e/
├── run-e2e.sh              # Orchestrator: npm pack + iterate matrix
├── run-combo.sh            # Single combo: install + setup + lifecycle suite
├── lifecycle-suite.sh      # 33 tests
├── lib/
│   ├── assertions.sh       # TAP helpers
│   ├── install-paths.sh    # I1-I4 functions (all use local tarball)
│   ├── setup-paths.sh      # S1-S4 functions
│   └── mock-provider.js    # Fake LLM (zero deps, Node http module)
├── fixtures/
│   └── fake-tokens.env
├── images/
│   ├── Dockerfile.ubuntu22 # Base image definitions
│   ├── Dockerfile.ubuntu24
│   ├── Dockerfile.debian12
│   └── Dockerfile.alpine
└── RESULTS.md              # Generated by test run
```

### CI pipeline
```yaml
name: E2E Tests
on: [push, pull_request]
jobs:
  e2e:
    strategy:
      matrix:
        platform: [ubuntu22, ubuntu24, debian12, alpine]
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: npm pack  # <1 sec
      - run: bash tests/e2e/run-e2e.sh --platform ${{ matrix.platform }}
        # Pulls cached base image from GHCR, runs 14 combos in ~10 min

  e2e-macos:
    runs-on: macos-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with: { node-version: 22 }
      - run: npm pack && bash tests/e2e/run-e2e.sh --platform macos
```

---

## Success Criteria

All 33 tests pass on all 14 combos on all platforms. One failure blocks release.

**Exceptions:**
- Alpine/macOS: binary tests (24, 26) verify graceful fallback — that fallback IS the pass condition
- Alpine without Perl: scrubbing tests note degraded mode
