# E2E Test Design — Real User Experience Testing

## Philosophy

These tests simulate a real human typing commands in a terminal. No mocks, no stubs, no simulation. If these tests pass, the product works.

**Speed target: full 14-combo matrix on Debian 12 in <5 minutes.**

---

## Speed Architecture

### The principle
**Separate what we're testing from what we're not.**

We are NOT testing: npm's download speed, Node.js installation, OpenClaw's core installer.
We ARE testing: our plugin installs correctly, vault commands work, injection + scrubbing work.

### The solution: pre-built base image + local tarball

1. **One pre-built base image** (Debian 12) — built once, cached. Contains OS + Node 22 + OpenClaw + Perl + sudo + jq. Built locally or pulled from GHCR. Only rebuilt when OpenClaw releases a new version.

2. **Local tarball install** — `npm pack` creates a `.tgz` from the repo. All install paths use this local file instead of fetching from npm registry. Takes <2 seconds vs 5+ minutes.

3. **No network dependency** — tests run fully offline after the base image exists.

### Install path mapping (local tarball)

- **I1 (curl script):** `install.sh` pointed at local tarball instead of GitHub release
- **I2 (npm install):** `openclaw plugins install /e2e/plugin.tgz`
- **I3 (npm + pin):** `openclaw plugins install /e2e/plugin.tgz --pin`
- **I4 (source link):** `openclaw plugins install --link /workspace`

All complete in <5 seconds. npm still resolves the 2 runtime deps (argon2, yaml) from registry — seconds, not minutes.

### What was slow before
1. `npm install -g openclaw` in every container (~3-5 min) — now baked into base image, built once
2. `openclaw plugins install` from npm registry (~2-3 min) — now from local tarball (~2 sec)
3. The actual tests were always fast (~30 sec). 95% of time was package downloads.

### Staleness strategy
- **Base image** (Debian 12 + Node 22 + OpenClaw): rebuild manually when OpenClaw ships a new version
- **Plugin dependencies** (argon2, yaml): resolved fresh every test run from the tarball's `^` ranges — automatically catches dep breakage
- **Plugin code**: always fresh — `npm pack` runs from current working tree before every test

---

## The Matrix

### Install paths

- **I1** — Install script (`install.sh` → local tarball)
- **I2** — Local tarball (`openclaw plugins install <local.tgz>`)
- **I3** — Local tarball + pin (`openclaw plugins install <local.tgz> --pin`)
- **I4** — Source link (`openclaw plugins install --link /workspace`)

### Setup paths

- **S1** — Machine key + inline (no sudo, no binary resolver)
- **S2** — Machine key + binary (`vault init` + `sudo bash vault-setup.sh`)
- **S3** — Passphrase + inline (`OPENCLAW_VAULT_PASSPHRASE` env var, no binary)
- **S4** — Passphrase + binary (`vault init --passphrase` + `sudo bash vault-setup.sh`)

### Valid combinations (14 total)

- I1 pairs with S2 and S4 only (curl script always runs setup, requires binary)
- I2, I3, I4 pair with all four setup paths (S1-S4)

### Platform

**Debian 12** — the dev VM and a common deployment target. Binary resolver works. Additional platforms (Alpine, macOS, Ubuntu variants) can be added to CI later.

---

## Container Lifecycle

```
[Pre-built base image: Debian 12 + Node 22 + OpenClaw]
  → docker run --rm --memory=1g \
      -v plugin.tgz:/e2e/plugin.tgz \
      -v tests/e2e:/e2e \
      -v repo:/workspace \
      vault-e2e-debian12 \
      bash /e2e/run-combo.sh <install> <setup>
  → [Install path: <5 sec]
  → [Setup path: <5 sec]
  → [Lifecycle suite: ~30 sec]
  → [Container destroyed]
```

**Per combo: ~40 seconds. All 14 combos sequential: ~10 minutes.**

### Resource constraints (karan-claw: 2 vCPU, 3.8 GB RAM, no swap)

- **Sequential only** — one container at a time
- **`--memory=1g`** — prevent OOM, leaves headroom for host + gateway
- **Never build images on this VM** — build once locally or pull from GHCR
- Report results after the full run completes

---

## Lifecycle Test Suite (33 tests)

Single suite (`lifecycle-suite.sh`), runs identically on every matrix cell.

### Phase 1: Verify installation (3 tests)
1. Plugin appears in `openclaw plugins list`
2. `openclaw vault` shows help text
3. `openclaw vault list` returns empty (clean state)

### Phase 2: Add credentials (5 tests)
4. Auto-detect: `vault add github --key "ghp_FAKETOKEN..."` → `.enc` created, rules auto-detected
5. Custom: `vault add myapi --key "..." --env MY_API_KEY --command "myapp *"` → custom rules stored
6. Browser password: `vault add amazon --type browser-password --domain .amazon.com --key "p@ss!"`
7. Browser cookie: `vault add example --type browser-cookie --domain .example.com`
8. Special chars: `vault add special --key 'p@$$w0rd!#%^&*()'` → preserved exactly

### Phase 3: Read operations (4 tests)
9. `vault list` → all 5 tools, correct columns, no credential values
10. `vault show github` → rules + metadata, no value
11. `vault test github` → decryption OK, resolver mode matches setup path
12. `vault logs` → access events from above operations

### Phase 4: Modify operations (3 tests)
13. `vault rotate github --key "ghp_NEWTOKEN..."` → timestamp updated, new value works
14. `vault remove special` → `.enc` deleted, removed from list
15. `vault remove myapi --purge` → system vault copy also deleted if binary mode

### Phase 5: Gateway injection & scrubbing (11 tests)
Uses mock LLM provider (zero-dep Node HTTP server, started in container).

16. Injection: `gh api user` → `GH_TOKEN` present in subprocess env
17. Scrubbing: `echo $GH_TOKEN` → output shows `[VAULT:github]`, NOT the fake token
18. Multi-credential: compound command → both injected, both scrubbed
19. Non-matching: `ls -la` → no injection, no scrubbing
20. Compound commands: `gh api user && echo done`, pipes, semicolons → all work
21. Error commands: `gh api /nonexistent` → injected, error scrubbed, exit code preserved
22. Hot-reload add: `vault add newcred` → immediate injection without restart
23. Hot-reload remove: `vault remove newcred` → immediate de-injection, no crash
24. Binary resolver (S2/S4 only): credential resolved via setuid binary
25. Inline fallback (S1/S3 only): credential inline, warning logged
26. Protocol mismatch (S2/S4 only): tampered binary → actionable error

### Phase 6: Error handling (7 tests)
27. Empty key: `vault add bad --key ""` → clear error
28. Nonexistent tool: `vault test doesnotexist` → clear error
29. Corrupt `.enc`: corrupt one file → that one errors, others still work
30. No init: `vault add` without init → clear error
31. Setup without sudo: `bash vault-setup.sh` → permission error
32. Long credential: 4096 chars → works end-to-end
33. Rapid cycle: 10 adds + 10 removes → clean state, no leaks

---

## Fake Token Convention

```
ghp_FAKETOKEN0123456789abcdefghijklmnop     # GitHub PAT (triggers auto-detect)
npm_FAKETOKEN0123456789abcdefghijklmnopqrst  # npm token
sk_test_FAKETOKEN0123456789abcdefghijklmnop  # Stripe test key
```

Scrub markers: `[VAULT:github]`, `[VAULT:npm]` — deliberately different from fake tokens so tests can distinguish leaked credentials from properly scrubbed output.

---

## Directory Structure

```
tests/e2e/
├── run-e2e.sh              # Orchestrator: npm pack + iterate 14 combos
├── run-combo.sh            # Single combo: install + setup + lifecycle
├── lifecycle-suite.sh      # 33 tests (TAP output)
├── lib/
│   ├── assertions.sh       # TAP helpers (assert_exit_code, assert_output_contains, etc.)
│   ├── install-paths.sh    # I1-I4 functions (all use local tarball)
│   ├── setup-paths.sh      # S1-S4 functions
│   └── mock-provider.js    # Fake LLM server (Node http module, zero deps)
├── fixtures/
│   └── fake-tokens.env     # Fake credential values
├── images/
│   └── Dockerfile.debian12 # Base image definition
└── RESULTS.md              # Generated by test run
```

---

## CI Pipeline

```yaml
name: E2E Tests
on: [push, pull_request]
jobs:
  e2e-debian12:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: npm pack
      - run: docker build -t vault-e2e-debian12 -f tests/e2e/images/Dockerfile.debian12 .
      - run: bash tests/e2e/run-e2e.sh --platform debian12
```

Additional platforms (Alpine, macOS, Ubuntu variants) added as separate jobs when needed.

---

## Success Criteria

All 33 tests pass on all 14 combos on Debian 12. One failure blocks merge.

Setup-conditional tests (24-26) adapt to the setup path:
- S2/S4 (binary): tests 24, 26 run normally
- S1/S3 (inline): tests 24, 26 verify inline fallback — that IS the pass condition
