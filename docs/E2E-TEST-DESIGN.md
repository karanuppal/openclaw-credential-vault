# E2E Test Design — Real User Experience Testing

## Philosophy

These tests simulate a real human typing commands in a terminal. No mocks, no stubs, no simulation. Every command runs exactly as a user would run it. Every output is captured and validated against expected behavior.

If these tests pass, the product works. If they fail, something is broken that a real user would hit.

## Test Environment

### Docker-based isolation
- Each test run starts from a **clean container** — no prior state
- Container has: Node.js, npm, bash, perl, sudo, standard Linux tools
- OpenClaw is installed fresh inside the container (not pre-baked)
- Tests run as a non-root user with sudo access (mimics real server setup)

### Platform matrix
| Image | Purpose | Resolver mode |
|---|---|---|
| `ubuntu:22.04` | Primary target (most OpenClaw users) | Binary (setuid) |
| `ubuntu:24.04` | Newer LTS | Binary (setuid) |
| `debian:12` | Raspberry Pi / minimal | Binary (setuid) |
| `node:22-alpine` | Container deployments | Inline (no glibc) |

### macOS
- GitHub Actions `macos-latest` runner
- Tests inline mode only (no setuid binary for Darwin yet)
- Validates install path + all CLI commands

---

## Test Suites

### Suite 1: Installation Paths

Tests that the plugin can be installed through every documented method.

#### 1A: Install script (curl one-liner)
```
curl -fsSL https://raw.githubusercontent.com/karanuppal/openclaw-credential-vault/main/install.sh | bash
```
**Validates:**
- Script downloads and runs without error
- Plugin appears in `openclaw plugins list` as "loaded"
- `openclaw vault` command is available
- Setup script ran (prompted for sudo)

#### 1B: npm install (manual)
```
openclaw plugins install openclaw-credential-vault
```
**Validates:**
- Package downloads from npm registry
- Plugin appears in `openclaw plugins list`
- `openclaw vault` command is available
- No setup script ran yet (user must run manually)

#### 1C: npm install with pin
```
openclaw plugins install openclaw-credential-vault --pin
```
**Validates:**
- Installs exact version (not range)
- `openclaw plugins list` shows pinned version

#### 1D: Source link (developer mode)
```
git clone https://github.com/karanuppal/openclaw-credential-vault.git
cd openclaw-credential-vault && npm install && npm run build
openclaw plugins install --link .
```
**Validates:**
- Plugin loads from source path
- Changes to src/ + rebuild are reflected after gateway restart

---

### Suite 2: Setup Variations

Tests every path through the setup flow.

#### 2A: Machine key mode (default, no passphrase)
```
openclaw vault init
```
**Validates:**
- Creates `~/.openclaw/vault/` directory
- Creates `tools.yaml` with `masterKeyMode: machine`
- No passphrase prompt
- `openclaw vault list` works (empty)

#### 2B: Passphrase mode
```
OPENCLAW_VAULT_PASSPHRASE="test-phrase-123" openclaw vault init --passphrase
```
**Validates:**
- Creates vault with `masterKeyMode: passphrase`
- Credentials encrypted with passphrase-derived key
- Without env var set, vault operations fail with clear error

#### 2C: Binary resolver setup (sudo required)
```
sudo bash vault-setup.sh
```
**Validates:**
- Creates `openclaw-vault` system user
- Copies resolver binary to `/usr/local/bin/openclaw-vault-resolver`
- Sets setuid bit
- Creates `/var/lib/openclaw-vault/` with restricted permissions
- Copies `.enc` files to system vault
- `openclaw vault test <tool>` shows "Binary resolver: OK"

#### 2D: Inline-only mode (no sudo)
```
openclaw vault init
# Skip vault-setup.sh entirely
```
**Validates:**
- Vault works without binary resolver
- `openclaw vault test <tool>` shows inline decryption works
- Warning about reduced security (no OS-level isolation)

#### 2E: Setup on system without Perl
**Validates:**
- Vault init succeeds
- Warning about stdout scrubber being unavailable
- Injection still works, but output scrubbing is degraded

---

### Suite 3: Credential Lifecycle

Tests the full lifecycle of credentials through every CLI command.

#### 3A: Add credential (auto-detect format)
```
openclaw vault add github --key "[VAULT:github]wx"
```
**Validates:**
- Success message displayed
- `~/.openclaw/vault/github.enc` created
- `tools.yaml` updated with injection rules for `gh *|git *|curl*api.github.com*`
- Scrubbing pattern auto-detected: `ghp_[a-zA-Z0-9]{36}`

#### 3B: Add credential (custom env var + command match)
```
openclaw vault add myapi --key "sk_custom_token_value" --env MY_API_KEY --command "myapp *|curl*myapi.com*"
```
**Validates:**
- Custom env var name used (not auto-guessed)
- Custom command match stored
- `openclaw vault show myapi` displays correct rules

#### 3C: Add credential (browser password)
```
openclaw vault add amazon --type browser-password --domain .amazon.com --key "p@ssw0rd"
```
**Validates:**
- Stored with browser injection rules
- Domain pin recorded
- `openclaw vault show amazon` shows browser-password type

#### 3D: Add credential (browser cookie)
```
openclaw vault add example --type browser-cookie --domain .example.com
# Then paste cookie JSON
```
**Validates:**
- Interactive paste mode works
- Cookie JSON stored and encrypted
- Domain pin recorded

#### 3E: List credentials
```
openclaw vault list
```
**Validates:**
- Table shows all added tools
- Status column: "active" for valid, "missing" for deleted .enc
- Injection and Scrubbing columns accurate
- No credential values displayed

#### 3F: Show credential details
```
openclaw vault show github
```
**Validates:**
- Displays injection rules (env var, command match)
- Displays scrubbing patterns
- Displays rotation info
- Does NOT display the actual credential value

#### 3G: Test credential
```
openclaw vault test github
```
**Validates:**
- Decryption: OK (with masked preview)
- Injection rules displayed
- Scrubbing test runs
- Binary resolver status (if setup ran)

#### 3H: Rotate credential
```
openclaw vault add github --key "ghp_new_token_abcdefghijklmnopqrstuvwxyz12"
```
**Validates:**
- Overwrites existing credential
- `lastRotated` timestamp updated
- Old credential no longer decryptable
- New credential works in `vault test`

#### 3I: Remove credential
```
openclaw vault remove github
```
**Validates:**
- `.enc` file deleted
- `tools.yaml` entry removed
- `openclaw vault list` no longer shows it
- Subsequent `vault test github` fails with clear error

#### 3J: Audit log
```
openclaw vault logs
```
**Validates:**
- Shows access events with timestamps
- Command strings recorded
- No credential values in log output

---

### Suite 4: Injection & Scrubbing (Gateway Integration)

Tests that credentials are actually injected into commands and scrubbed from output. **Requires a running OpenClaw gateway.**

#### Gateway setup for testing
- Install OpenClaw in the container
- Configure with a mock LLM provider (simple HTTP server returning canned tool-call responses)
- Load the vault plugin
- Add test credentials

#### 4A: Environment variable injection
**Setup:** Add `github` credential, gateway running
**Action:** Gateway processes a model response containing `exec: gh api user`
**Validates:**
- `GH_TOKEN` is set in the subprocess environment
- `GITHUB_TOKEN` is set in the subprocess environment
- `process.env` is NOT contaminated (checked after tool call)

#### 4B: Stdout scrubbing (Perl)
**Setup:** Add `github` credential with known test value
**Action:** Run command that echoes the credential value to stdout
**Validates:**
- Output contains `[VAULT:github]` replacement marker
- Actual credential value does NOT appear in output
- Exit code is preserved

#### 4C: Multi-credential injection
**Setup:** Add `github` and `npm` credentials
**Action:** Run compound command that uses both
**Validates:**
- Both env vars injected
- Both credentials scrubbed from output

#### 4D: Non-matching command (negative test)
**Setup:** Add `github` credential (matches `gh *`)
**Action:** Run `ls -la` (doesn't match any pattern)
**Validates:**
- No injection occurs
- No scrubbing occurs
- Command runs normally

#### 4E: Hot-reload after vault add
**Setup:** Gateway running, no credentials
**Action:** `vault add github --key ...` then immediately run matched command
**Validates:**
- Credential injected WITHOUT gateway restart
- Journal/log shows "Config hot-reloaded"

#### 4F: Hot-reload after vault remove
**Setup:** Gateway running with `github` credential
**Action:** `vault remove github` then run `gh` command
**Validates:**
- Credential NOT injected after removal
- No crash or error

#### 4G: Binary resolver injection
**Setup:** Binary mode (`vault-setup.sh` ran), credential in system vault
**Action:** Run matched command
**Validates:**
- Credential resolved via setuid binary
- Audit log shows resolver access
- Non-root user cannot read `.enc` files directly

#### 4H: Inline fallback
**Setup:** Binary resolver not installed (or binary deleted)
**Action:** Run matched command
**Validates:**
- Falls back to inline decryption with warning
- Credential still injected correctly

#### 4I: Protocol version mismatch
**Setup:** Tamper with resolver binary version
**Action:** Run matched command
**Validates:**
- Actionable error message with fix instructions
- Follows `onResolverFailure` policy (block or warn-and-inline)

---

### Suite 5: Error Handling & Edge Cases

#### 5A: Add duplicate tool name
**Validates:** Overwrites cleanly, no orphaned files

#### 5B: Add with empty key
**Validates:** Clear error, no file created

#### 5C: Test nonexistent tool
**Validates:** Clear error message

#### 5D: Vault operations without init
**Validates:** Clear error directing user to run `vault init`

#### 5E: Binary resolver without sudo
**Validates:** Clear error about permissions

#### 5F: Corrupt .enc file
**Validates:** Clear error, other credentials still work

#### 5G: Special characters in credential
**Validates:** Credentials with `$`, `"`, `'`, `\`, newlines stored and injected correctly

---

## Implementation

### Test runner
- Bash script (`run-e2e.sh`) that orchestrates Docker builds + test execution
- Each suite is a separate script (`suite-1-install.sh`, `suite-2-setup.sh`, etc.)
- Each test case is a function with:
  - **Setup**: preconditions
  - **Action**: the actual command(s)
  - **Assert**: output validation (grep, exit code, file existence)
- TAP-compatible output for CI integration

### Test assertion helpers
```bash
assert_exit_code() {
  local expected=$1; shift
  "$@"; local actual=$?
  [[ $actual -eq $expected ]] || fail "Expected exit $expected, got $actual"
}

assert_output_contains() {
  local pattern=$1; shift
  local output=$("$@" 2>&1)
  echo "$output" | grep -q "$pattern" || fail "Output missing: $pattern"
}

assert_output_not_contains() {
  local pattern=$1; shift
  local output=$("$@" 2>&1)
  echo "$output" | grep -q "$pattern" && fail "Output contains forbidden: $pattern"
}

assert_file_exists() {
  [[ -f "$1" ]] || fail "File missing: $1"
}

assert_file_not_exists() {
  [[ ! -f "$1" ]] || fail "File should not exist: $1"
}
```

### Directory structure
```
tests/e2e/
├── run-e2e.sh              # Main orchestrator
├── Dockerfile.ubuntu22     # Ubuntu 22.04 base image
├── Dockerfile.ubuntu24     # Ubuntu 24.04 base image
├── Dockerfile.debian12     # Debian 12 base image
├── Dockerfile.alpine       # Alpine base image
├── lib/
│   ├── assertions.sh       # Test assertion helpers
│   ├── setup.sh            # Common setup (install OpenClaw, etc.)
│   └── mock-provider.js    # Fake LLM for gateway integration
├── suites/
│   ├── 01-install.sh       # Suite 1: Installation paths
│   ├── 02-setup.sh         # Suite 2: Setup variations
│   ├── 03-lifecycle.sh     # Suite 3: Credential lifecycle
│   ├── 04-integration.sh   # Suite 4: Gateway integration
│   └── 05-errors.sh        # Suite 5: Error handling
└── fixtures/
    ├── test-tokens.env     # Fake tokens for testing
    └── mock-responses/     # Canned LLM responses with tool calls
```

### CI pipeline (`.github/workflows/e2e.yml`)
```yaml
name: E2E Tests
on:
  push:
    branches: [main]
  pull_request:

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

### Mock LLM Provider
Minimal Express server that returns canned responses:
- Request 1: Returns a tool call `{exec: {command: "gh api user"}}`
- Request 2: Returns a tool call `{exec: {command: "echo $GH_TOKEN"}}`
- Request 3: Returns a text response (no tool call)

This lets us test injection + scrubbing without real API keys.

---

## Success Criteria

**All tests must pass on all platforms before any release.**

A single failing test blocks the release — these tests represent real user experiences. If a test fails, a user would hit that same failure.

### Coverage targets
- Suite 1-3: Must pass on ALL platforms (install, setup, CLI)
- Suite 4: Must pass on Ubuntu 22.04 + 24.04 (gateway integration)
- Suite 5: Must pass on ALL platforms (error handling)

---

## Open Questions

1. **OpenClaw install in Docker**: Do we install via the official install script, or `npm install -g openclaw`? The install script is the real user path but adds complexity.

2. **Mock provider fidelity**: How accurately must the mock mimic a real LLM API? Minimum: return valid tool_call JSON that OpenClaw's message parser accepts.

3. **Test credential values**: Use obviously-fake tokens that match real patterns (e.g., `[VAULT:github]`). These should trigger auto-detection but never be confused with real credentials.

4. **Timing sensitivity**: Hot-reload tests (4E, 4F) depend on mtime changes. Should we add a small sleep between write + test to avoid same-second mtime issues?

5. **Binary resolver on CI**: GitHub Actions runners allow sudo. Alpine won't have glibc. Do we test the "binary not compatible" fallback explicitly?

6. **macOS binary**: We don't ship a Darwin binary yet. Should we cross-compile one for the beta, or is inline-only acceptable for macOS users?
