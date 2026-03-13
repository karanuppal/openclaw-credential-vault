# E2E Test Design — Real User Experience Testing

## Philosophy

These tests simulate a real human typing commands in a terminal. No mocks, no stubs, no simulation. Every command runs exactly as a user would run it. Every output is captured and validated against expected behavior.

If these tests pass, the product works. If they fail, something is broken that a real user would hit.

## Test Environment

### Docker-based isolation
- **Base images have OpenClaw pre-installed** (baked in) — we're not testing OpenClaw's installer, we're testing our plugin
- Each test suite starts from a **fresh container** — no state carries over between suites
- Container is destroyed after each suite — no cleanup logic needed
- Container has: Node.js, npm, bash, perl, sudo, standard Linux tools
- Tests run as a non-root user with sudo access (mimics real server setup)

### Platform matrix
| Image | Purpose | Resolver mode |
|---|---|---|
| `ubuntu:22.04` | Primary target (most OpenClaw users) | Binary (setuid) |
| `ubuntu:24.04` | Newer LTS | Binary (setuid) |
| `debian:12` | Raspberry Pi / minimal | Binary (setuid) |
| `node:22-alpine` | Container deployments | Inline (no glibc — binary incompatible, explicit fallback test) |

### macOS
- GitHub Actions `macos-latest` runner
- Inline mode only (no Darwin binary yet — acceptable for beta)
- Validates install path + all CLI commands

### Running tests
- **Locally:** `bash tests/e2e/run-e2e.sh` — builds Docker images, runs all suites
- **CI:** GitHub Actions on every push to main + PRs — same Docker images, same suites
- Both paths run identical tests — CI is not a separate thing

---

## Container Lifecycle

Each suite gets a **fresh container** from the base image (OpenClaw pre-installed, no vault state):

```
[Base image: OpenClaw installed] → [Start container] → [Run suite] → [Destroy container]
```

No suite depends on another. No cleanup needed. If a test fails mid-suite, the container is still destroyed. This ensures complete isolation.

---

## Test Suites

### Suite 1: Installation Paths

Tests that the plugin can be installed through every documented method. **Each installation path runs the full validation checklist** — not just "did it install" but "does everything work after."

#### Validation checklist (run after EVERY install method)
After installing the plugin via any method, validate ALL of the following:
1. Plugin appears in `openclaw plugins list` as "loaded"
2. `openclaw vault` command is available and shows help
3. `openclaw vault init` succeeds (machine key mode)
4. `openclaw vault list` works (shows empty list)
5. **Inline mode test:** Add a test credential, run `vault test` — decryption works
6. **Setup script test:** Run `sudo bash vault-setup.sh` — binary resolver installs
7. **Binary mode test:** Run `vault test` again — shows "Binary resolver: OK"
8. **Post-setup vault operations:** `vault list`, `vault show`, `vault logs` all work

#### 1A: Install script (curl one-liner)
```
curl -fsSL https://raw.githubusercontent.com/karanuppal/openclaw-credential-vault/main/install.sh | bash
```
**Additional checks:**
- Script downloads and runs without error
- Script invokes `vault-setup.sh` with sudo prompt
- Output contains expected progress messages
- → Run full validation checklist

#### 1B: npm install (manual)
```
openclaw plugins install openclaw-credential-vault
```
**Additional checks:**
- Package downloads from npm registry
- Setup script NOT automatically run (user must run manually)
- `vault-setup.sh` path is communicated to user in output
- → Run `sudo bash vault-setup.sh` separately
- → Run full validation checklist

#### 1C: npm install with pin
```
openclaw plugins install openclaw-credential-vault --pin
```
**Additional checks:**
- `openclaw plugins list` shows exact pinned version (not range)
- → Run `sudo bash vault-setup.sh` separately
- → Run full validation checklist

#### 1D: Source link (developer mode)
```
git clone https://github.com/karanuppal/openclaw-credential-vault.git
cd openclaw-credential-vault && npm install && npm run build
openclaw plugins install --link .
```
**Additional checks:**
- Plugin loads from local source path
- → Run `sudo bash vault-setup.sh` separately
- → Run full validation checklist

---

### Suite 2: Setup Variations

Tests every path through the setup flow. Each runs in a fresh container with the plugin already installed (via npm install, since Suite 1 validated all install methods).

#### 2A: Machine key mode (default, no passphrase)
```
openclaw vault init
```
**Validates:**
- Creates `~/.openclaw/vault/` directory
- Creates `tools.yaml` with `masterKeyMode: machine`
- No passphrase prompt
- `openclaw vault list` works (empty list)
- Adding and testing a credential works (inline mode)

#### 2B: Passphrase mode
```
OPENCLAW_VAULT_PASSPHRASE="test-phrase-123" openclaw vault init --passphrase
```
**Validates:**
- Creates vault with `masterKeyMode: passphrase`
- Adding a credential works with passphrase set
- Without env var set, vault operations fail with clear error message
- With env var set, all operations work

#### 2C: Binary resolver setup
```
sudo bash vault-setup.sh
```
**Validates:**
- Creates `openclaw-vault` system user
- Copies resolver binary to `/usr/local/bin/openclaw-vault-resolver`
- Sets setuid bit (`-rwsr-xr-x`)
- Creates `/var/lib/openclaw-vault/` with restricted permissions
- Copies existing `.enc` files to system vault
- `openclaw vault test <tool>` shows "Binary resolver: OK"
- Non-root user CANNOT read `.enc` files in `/var/lib/openclaw-vault/`

#### 2D: Inline-only mode (no sudo, no setup script)
```
openclaw vault init
# Intentionally skip vault-setup.sh
```
**Validates:**
- All vault operations work without binary resolver
- `openclaw vault test <tool>` shows inline decryption works
- Warning about reduced security displayed
- Injection still works correctly

#### 2E: Setup on system without Perl
**(Alpine container, or Ubuntu with perl removed)**
**Validates:**
- `vault init` succeeds
- `vault add` and `vault test` succeed
- Warning about stdout scrubber being unavailable
- Injection works, scrubbing is degraded (noted in test output)

---

### Suite 3: Credential Lifecycle

Tests the full lifecycle of credentials through every CLI command. Fresh container, plugin installed + initialized.

#### 3A: Add credential (auto-detect format — GitHub token)
```
openclaw vault add github --key "[VAULT:github]r"
```
**Validates:**
- Success message displayed
- `~/.openclaw/vault/github.enc` file created
- `tools.yaml` updated with injection rules for `gh *|git *|curl*api.github.com*`
- Scrubbing pattern auto-detected: `ghp_[a-zA-Z0-9]{36}`
- `vault test github` passes

#### 3B: Add credential (custom env var + command match)
```
openclaw vault add myapi --key "sk_custom_FAKETOKEN_abcdefghij" --env MY_API_KEY --command "myapp *|curl*myapi.com*"
```
**Validates:**
- Custom env var name `MY_API_KEY` used (not auto-guessed)
- Custom command match `myapp *|curl*myapi.com*` stored
- `openclaw vault show myapi` displays correct rules

#### 3C: Add credential (browser password)
```
openclaw vault add amazon --type browser-password --domain .amazon.com --key "p@ssw0rd!#$%"
```
**Validates:**
- Stored with browser injection rules
- Domain pin `.amazon.com` recorded
- `openclaw vault show amazon` shows browser-password type
- Special characters in password preserved

#### 3D: Add credential (browser cookie)
```
openclaw vault add example --type browser-cookie --domain .example.com
# Pipe cookie JSON via stdin
```
**Validates:**
- Cookie JSON stored and encrypted
- Domain pin recorded
- `openclaw vault show example` shows browser-cookie type

#### 3E: List credentials
```
openclaw vault list
```
**Validates:**
- Table shows all 4 added tools (github, myapi, amazon, example)
- Status column: "active" for all
- Injection column: "exec" for github/myapi, "browser" for amazon/example
- Scrubbing column accurate
- No credential VALUES displayed anywhere

#### 3F: Show credential details
```
openclaw vault show github
```
**Validates:**
- Displays injection rules (env var names, command match patterns)
- Displays scrubbing patterns
- Displays add date and rotation info
- Does NOT display the actual credential value

#### 3G: Test credential
```
openclaw vault test github
```
**Validates:**
- "Decryption: OK" with masked preview (e.g., `ghp_****...opqr`)
- Injection rules displayed and marked ✓
- Scrubbing test shows pattern matching
- Binary resolver status (OK or "not installed" depending on setup)

#### 3H: Rotate credential
```
openclaw vault rotate github --key "[VAULT:github]"
```
**Validates:**
- `lastRotated` timestamp updated (newer than `addedAt`)
- Old credential value no longer returned by `vault test`
- New credential value works in `vault test`
- Injection rules unchanged

#### 3I: Remove credential
```
openclaw vault remove github
```
**Validates:**
- `.enc` file deleted from `~/.openclaw/vault/`
- Tool entry removed from `tools.yaml`
- `openclaw vault list` no longer shows `github`
- `openclaw vault test github` fails with clear error

#### 3J: Remove credential with purge
```
openclaw vault remove myapi --purge
```
**Validates:**
- `.enc` file deleted
- Tool entry removed from `tools.yaml`
- System vault copy also deleted (if binary mode)
- Audit log entries for this tool preserved (purge removes credential, not history)

#### 3K: Audit log
```
openclaw vault logs
```
**Validates:**
- Shows access events with timestamps
- Command strings recorded (truncated appropriately)
- Credential names shown, credential VALUES never shown
- Events from add, test, rotate, remove all logged

---

### Suite 4: Injection & Scrubbing (Gateway Integration)

Tests that credentials are actually injected into commands and scrubbed from output. **Requires a running OpenClaw gateway.**

#### Gateway setup
- OpenClaw gateway running in the container
- Mock LLM provider: simple HTTP server returning canned responses
  - Response variations: normal tool calls, error tool calls, multi-tool calls, text-only responses
- Vault plugin loaded, test credentials added

#### Test token convention
- **Fake tokens look real but are obviously fake:** `[VAULT:github]r`
- **Scrub replacement markers:** `[VAULT:github]`
- These are deliberately different so tests can distinguish between "token leaked" (fake token visible) and "token scrubbed" (replacement marker visible)

#### 4A: Environment variable injection
**Setup:** Add `github` credential
**Action:** Gateway processes model response containing `exec: gh api user`
**Validates:**
- `GH_TOKEN` is set in the subprocess environment
- `GITHUB_TOKEN` is set in the subprocess environment
- `process.env` of the gateway is NOT contaminated after the tool call

#### 4B: Stdout scrubbing (Perl)
**Setup:** Add `github` credential with known fake token value
**Action:** Run command that echoes the credential value to stdout (e.g., `echo $GH_TOKEN`)
**Validates:**
- Output contains `[VAULT:github]` replacement marker
- Fake token string does NOT appear in output
- Exit code of original command is preserved

#### 4C: Multi-credential injection
**Setup:** Add `github` and `npm` credentials
**Action:** Run compound command that uses both
**Validates:**
- Both `GH_TOKEN` and `NPM_TOKEN` env vars injected
- Both credentials scrubbed from output independently
- No cross-contamination between credentials

#### 4D: Non-matching command (negative test)
**Setup:** Add `github` credential (matches `gh *`)
**Action:** Run `ls -la` (doesn't match any pattern)
**Validates:**
- No env vars injected
- No scrubbing occurs
- Command runs normally, output unmodified

#### 4E: Compound and multi-line commands
**Setup:** Add `github` credential
**Action:** Run commands with various structures:
- `gh api user && echo "done"`
- `echo "start"; gh api user; echo "end"`
- Multi-line command with `gh` on line 2
- Command with pipes: `gh api user | jq .login`
**Validates:**
- Injection triggers for all compound formats containing a matching command
- Scrubbing works across all output regardless of command structure
- Exit codes preserved correctly through pipes and chains

#### 4F: Error command responses
**Setup:** Add credential, mock provider returns an error-producing tool call
**Action:** Gateway processes tool call that will fail (e.g., `gh api /nonexistent`)
**Validates:**
- Credential still injected (even for failing commands)
- Error output is scrubbed (credentials don't leak in error messages)
- Error exit code preserved and reported to model

#### 4G: Hot-reload after vault add
**Setup:** Gateway running, no credentials configured
**Action:** `vault add github --key ...` then immediately run matched command
**Wait:** 2 seconds between add and test (allow mtime to propagate)
**Validates:**
- Credential injected WITHOUT gateway restart
- Gateway log shows "Config hot-reloaded"
- Full injection + scrubbing works

#### 4H: Hot-reload after vault remove
**Setup:** Gateway running with `github` credential active
**Action:** `vault remove github` then run `gh` command
**Wait:** 2 seconds
**Validates:**
- Credential NOT injected after removal
- No crash or error in gateway
- Command runs without injection (may fail due to missing auth — that's expected)

#### 4I: Binary resolver injection
**Setup:** Binary mode (`vault-setup.sh` ran), credential in system vault
**Action:** Run matched command through gateway
**Validates:**
- Credential resolved via setuid binary (not inline)
- Audit log shows resolver access event
- Non-root user cannot read `.enc` files directly (permission check)

#### 4J: Inline fallback when binary unavailable
**Setup:** Binary resolver not installed (or binary deleted after setup)
**Action:** Run matched command through gateway
**Validates:**
- Falls back to inline decryption
- Warning logged about degraded security
- Credential still injected correctly
- Follows `onResolverFailure` policy

#### 4K: Protocol version mismatch
**Setup:** Tamper with resolver binary version (rename real binary, place fake)
**Action:** Run matched command through gateway
**Validates:**
- Actionable error message displayed with fix instructions (mentions `vault-setup.sh`)
- Follows `onResolverFailure` config: "block" stops injection, "warn-and-inline" falls back
- No crash

#### 4L: Binary resolver incompatible (Alpine — explicit test)
**Setup:** Alpine container (no glibc), binary resolver present but can't execute
**Action:** Run matched command
**Validates:**
- Clear error/warning about binary incompatibility
- Falls back to inline mode gracefully
- Credential still works via inline decryption

---

### Suite 5: Error Handling & Edge Cases

#### 5A: Add duplicate tool name
```
openclaw vault add github --key "token1"
openclaw vault add github --key "token2"
```
**Validates:** Second add overwrites cleanly, `vault test` returns token2, no orphaned files

#### 5B: Add with empty key
```
openclaw vault add test --key ""
```
**Validates:** Clear error message, no `.enc` file created, no entry in `tools.yaml`

#### 5C: Test nonexistent tool
```
openclaw vault test nonexistent
```
**Validates:** Clear error message, non-zero exit code

#### 5D: Vault operations without init
**(Fresh container, never ran `vault init`)**
```
openclaw vault add github --key "token"
openclaw vault list
openclaw vault test github
```
**Validates:** Clear error directing user to run `vault init`

#### 5E: Binary resolver setup without sudo
```
bash vault-setup.sh  # no sudo
```
**Validates:** Clear error about needing root/sudo permissions

#### 5F: Corrupt .enc file
**Setup:** Add two credentials, then corrupt one `.enc` file (write garbage bytes)
**Validates:**
- Corrupted credential: clear error on `vault test`
- Other credential: still works perfectly
- `vault list` shows corrupted one as error state
- No crash or cascading failure

#### 5G: Special characters in credential
```
openclaw vault add special --key 'p@$$w0rd!#%^&*()_+-={}[]|\\:\";<>?,./'
```
**Validates:**
- Credential stored and decrypted correctly
- Special characters preserved exactly
- Injection works (env var contains exact value)
- Scrubbing catches the literal value in output

#### 5H: Very long credential
```
openclaw vault add longcred --key "<4096 character string>"
```
**Validates:** Stored, decrypted, injected, scrubbed correctly

#### 5I: Rapid add/remove cycle
```
for i in {1..10}; do
  openclaw vault add test-$i --key "token-$i"
done
for i in {1..10}; do
  openclaw vault remove test-$i
done
openclaw vault list
```
**Validates:** Clean state after all operations, no orphaned files, empty list

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
  [[ $actual -eq $expected ]] || fail "Expected exit $expected, got $actual: $*"
}

assert_output_contains() {
  local pattern=$1; shift
  local output=$("$@" 2>&1)
  echo "$output" | grep -q "$pattern" || fail "Output missing: $pattern\nGot: $output"
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

assert_file_not_readable() {
  # Verify current user can't read a file (for permission tests)
  cat "$1" 2>/dev/null && fail "File should not be readable: $1"
}
```

### Directory structure
```
tests/e2e/
├── run-e2e.sh                  # Main orchestrator
├── Dockerfile.base             # Base image with OpenClaw pre-installed
├── Dockerfile.ubuntu22         # Ubuntu 22.04 FROM base
├── Dockerfile.ubuntu24         # Ubuntu 24.04 FROM base
├── Dockerfile.debian12         # Debian 12 FROM base
├── Dockerfile.alpine           # Alpine FROM base (no glibc)
├── lib/
│   ├── assertions.sh           # Test assertion helpers
│   ├── setup.sh                # Per-suite setup (install plugin, init vault)
│   └── mock-provider.js        # Fake LLM returning canned tool calls + errors
├── suites/
│   ├── 01-install.sh           # Suite 1: Installation paths + full validation
│   ├── 02-setup.sh             # Suite 2: Setup variations
│   ├── 03-lifecycle.sh         # Suite 3: Credential lifecycle (every CLI command)
│   ├── 04-integration.sh       # Suite 4: Gateway injection + scrubbing
│   └── 05-errors.sh            # Suite 5: Error handling + edge cases
└── fixtures/
    ├── fake-tokens.env         # Fake tokens (look real, obviously fake)
    └── mock-responses/         # Canned LLM responses: tool calls, errors, text
```

### Fake token convention
Tokens must look like real credentials (trigger auto-detection) but be obviously fake:
```
[VAULT:github]r    # GitHub PAT format
npm_FAKETOKEN1234567890abcdefghijklmnopqrstu  # npm token format
sk_test_FAKE1234567890abcdef                   # Stripe test-mode format
```
These are deliberately different from scrub markers (`[VAULT:github]`) so tests can distinguish "leaked" from "scrubbed."

### Mock LLM Provider
Minimal Express server returning canned responses:
- **Normal tool call:** `{tool_call: {name: "exec", arguments: {command: "gh api user"}}}`
- **Error-producing tool call:** `{tool_call: {name: "exec", arguments: {command: "gh api /nonexistent"}}}`
- **Multi-tool call:** Two tool calls in one response
- **Exfiltration attempt:** `{tool_call: {name: "exec", arguments: {command: "echo $GH_TOKEN"}}}`
- **Text-only response:** No tool call (baseline, verify no injection on plain text)

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

---

## Success Criteria

**All tests must pass on all platforms before any release.**

A single failing test blocks the release — these tests represent real user experiences.

### Coverage requirements
- **Suite 1-3:** Must pass on ALL platforms (install, setup, CLI)
- **Suite 4:** Must pass on Ubuntu 22.04 + 24.04 (gateway integration); best-effort on others
- **Suite 5:** Must pass on ALL platforms (error handling)
- **Alpine:** Binary resolver tests expected to fail gracefully (inline fallback); all other tests must pass
- **macOS:** Inline mode only; all non-binary tests must pass
