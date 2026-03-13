# E2E Test Design — Real User Experience Testing

## Philosophy

These tests simulate a real human typing commands in a terminal. No mocks, no stubs, no simulation. Every command runs exactly as a user would run it.

If these tests pass, the product works. If they fail, something is broken that a real user would hit.

---

## The Matrix

There are **install paths** and **setup paths**. Every combination must work. Once installed and set up, the full lifecycle test suite runs identically regardless of how we got there.

### Install paths
| ID | Method | Description |
|---|---|---|
| I1 | `curl \| bash` | One-liner install script |
| I2 | `openclaw plugins install` | npm install via OpenClaw CLI |
| I3 | `openclaw plugins install --pin` | npm install with pinned version |
| I4 | `git clone` + `--link` | Source link (developer mode) |

### Setup paths
| ID | Method | Description |
|---|---|---|
| S1 | Machine key + inline | `vault init` (default, no sudo, no binary resolver) |
| S2 | Machine key + binary | `vault init` then `sudo bash vault-setup.sh` |
| S3 | Passphrase + inline | `vault init --passphrase` (no binary resolver) |
| S4 | Passphrase + binary | `vault init --passphrase` then `sudo bash vault-setup.sh` |

### The full matrix
Every cell is a fresh container. Each runs the **complete lifecycle test suite**.

|  | S1 (machine+inline) | S2 (machine+binary) | S3 (passphrase+inline) | S4 (passphrase+binary) |
|---|---|---|---|---|
| **I1** (curl script) | ✓ | ✓ | ✓ | ✓ |
| **I2** (npm install) | ✓ | ✓ | ✓ | ✓ |
| **I3** (npm --pin) | ✓ | ✓ | ✓ | ✓ |
| **I4** (source link) | ✓ | ✓ | ✓ | ✓ |

That's 16 combinations per platform. Each runs the same lifecycle suite.

### Platform matrix
| Platform | Resolver binary works? | Notes |
|---|---|---|
| Ubuntu 22.04 | Yes | Primary target |
| Ubuntu 24.04 | Yes | Newer LTS |
| Debian 12 | Yes | Minimal / Pi |
| Alpine | No (no glibc) | S2/S4 fall back to inline with warning |
| macOS (GH Actions) | No (no Darwin binary) | S2/S4 fall back to inline with warning |

On Alpine/macOS, S2 and S4 still run — they test that `vault-setup.sh` fails gracefully and the system falls back to inline mode.

---

## Container Lifecycle

```
[Base image: OS + Node + OpenClaw pre-installed]
  → [Start container]
  → [Run install path (I1/I2/I3/I4)]
  → [Run setup path (S1/S2/S3/S4)]
  → [Run lifecycle test suite]
  → [Destroy container]
```

One container per matrix cell. No state carries over. No cleanup logic.

---

## Lifecycle Test Suite

This is the single test suite that runs on every matrix combination. It tests everything a user would do after install + setup.

### Phase 1: Verify installation
1. Plugin appears in `openclaw plugins list` as loaded
2. `openclaw vault` shows help
3. `openclaw vault list` returns empty list

### Phase 2: Add credentials
4. **Auto-detect format:** `vault add github --key "ghp_FAKETOKEN..."` → verify `.enc` created, rules auto-detected, `vault test` passes
5. **Custom env/command:** `vault add myapi --key "..." --env MY_API_KEY --command "myapp *"` → verify custom rules stored
6. **Browser password:** `vault add amazon --type browser-password --domain .amazon.com --key "p@ss!"` → verify domain pin
7. **Browser cookie:** `vault add example --type browser-cookie --domain .example.com` → verify cookie stored
8. **Special characters:** `vault add special --key 'p@$$w0rd!#%^&*()'` → verify preserved exactly

### Phase 3: Read operations
9. `vault list` → shows all 5 tools, correct status/injection/scrubbing columns, no credential values
10. `vault show github` → shows rules and metadata, no credential value
11. `vault test github` → decryption OK, injection rules OK, resolver mode matches setup path
12. `vault logs` → shows access events from adds and tests above

### Phase 4: Modify operations
13. `vault rotate github --key "ghp_NEWTOKEN..."` → timestamp updated, new value works, old value gone
14. `vault remove special` → `.enc` deleted, removed from list, `vault test` fails clearly
15. `vault remove myapi --purge` → same as above, system vault copy also deleted if binary mode

### Phase 5: Gateway injection & scrubbing
**(Requires running gateway with mock LLM provider)**

16. **Injection:** Gateway runs `gh api user` → `GH_TOKEN` present in subprocess env
17. **Scrubbing:** Gateway runs `echo $GH_TOKEN` → output contains `[VAULT:github]`, NOT the fake token
18. **Multi-credential:** Compound command using github + npm → both injected, both scrubbed
19. **Non-matching command:** `ls -la` → no injection, no scrubbing, normal output
20. **Compound commands:** `gh api user && echo done`, `echo start; gh api user`, multi-line, piped → all inject and scrub correctly
21. **Error commands:** `gh api /nonexistent` → credential injected, error output scrubbed, exit code preserved
22. **Hot-reload add:** `vault add newcred --key ...` → next tool call injects without restart, log shows "hot-reloaded"
23. **Hot-reload remove:** `vault remove newcred` → next tool call does NOT inject, no crash
24. **Binary resolver path** (S2/S4 only): credential resolved via setuid binary, non-root can't read `.enc` in system vault
25. **Inline fallback** (S1/S3, or when binary deleted): credential resolved inline, warning logged
26. **Protocol mismatch** (S2/S4 only): tampered binary → actionable error with fix instructions

### Phase 6: Error handling
27. **Empty key:** `vault add bad --key ""` → clear error, nothing created
28. **Nonexistent tool test:** `vault test doesnotexist` → clear error
29. **Corrupt .enc file:** corrupt one credential's file → that one errors, others still work
30. **No init:** fresh vault state, run `vault add` → clear error pointing to `vault init`
31. **Setup without sudo:** `bash vault-setup.sh` (no sudo) → clear permission error
32. **Long credential:** 4096-char string → stored, decrypted, injected, scrubbed correctly
33. **Rapid add/remove:** 10 adds then 10 removes → clean state, no orphaned files

---

## Fake Token Convention

Tokens look real (trigger auto-detection) but are obviously fake:
```
ghp_FAKETOKEN0123456789abcdefghijklmnop     # GitHub PAT format
npm_FAKETOKEN0123456789abcdefghijklmnopqrst  # npm format
```

Scrub markers are deliberately different: `[VAULT:github]`, `[VAULT:npm]`

Tests assert: fake token NOT in output, scrub marker IS in output. This distinguishes "leaked" from "scrubbed."

---

## Implementation

### Directory structure
```
tests/e2e/
├── run-e2e.sh                  # Orchestrator: builds images, iterates matrix, runs suite
├── Dockerfile.ubuntu22         # Base images with OpenClaw pre-installed
├── Dockerfile.ubuntu24
├── Dockerfile.debian12
├── Dockerfile.alpine
├── lib/
│   ├── assertions.sh           # Test helpers (assert_exit_code, assert_output_contains, etc.)
│   ├── install-paths.sh        # Functions: install_curl, install_npm, install_pin, install_link
│   ├── setup-paths.sh          # Functions: setup_machine_inline, setup_machine_binary, etc.
│   └── mock-provider.js        # Fake LLM: normal/error/multi tool calls + text responses
├── lifecycle-suite.sh          # THE test suite — runs identically on every combination
└── fixtures/
    └── fake-tokens.env         # Fake credential values
```

### How the orchestrator works
```bash
for platform in ubuntu22 ubuntu24 debian12 alpine; do
  for install in curl npm pin link; do
    for setup in machine-inline machine-binary passphrase-inline passphrase-binary; do
      echo "=== Testing: $platform / $install / $setup ==="
      docker run --rm \
        vault-e2e-$platform \
        bash -c "install_$install && setup_$setup && bash lifecycle-suite.sh"
    done
  done
done
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
      - run: bash tests/e2e/run-e2e.sh --platform ${{ matrix.platform }}
  e2e-macos:
    runs-on: macos-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with: { node-version: 22 }
      - run: bash tests/e2e/run-e2e.sh --platform macos
```

---

## Success Criteria

All 33 lifecycle tests must pass on every matrix cell. A single failure blocks release.

**Exceptions:**
- Alpine/macOS: binary resolver tests (24, 26) expected to gracefully fall back — that fallback IS the test
- Alpine: if Perl unavailable, scrubbing tests note degraded mode
