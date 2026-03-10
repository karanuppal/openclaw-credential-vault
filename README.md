# @openclaw/credential-vault

> OpenClaw plugin for encrypted credential management — encrypts, injects, and scrubs external tool credentials at runtime.

Your AI agent needs API keys, tokens, and cookies to interact with external services. This plugin ensures those credentials are encrypted at rest, injected only when needed, and scrubbed from all outputs and transcripts.

## Features

- **AES-256-GCM encryption** with Argon2id key derivation
- **Automatic injection** into exec commands via environment variables
- **Browser credential support** — cookies and passwords with domain pinning
- **Output scrubbing** — secrets removed from tool results, transcripts, and messages
- **Rotation tracking** — creation dates, expiry alerts, documented rotation procedures
- **Audit logging** — every credential access logged with timestamps
- **Rust resolver binary** — optional OS-level isolation via setuid + seccomp sandboxing

## Requirements

- Node.js ≥ 20
- OpenClaw gateway (plugin host)
- Linux (see [Platform Support](docs/platform-support.md) for future OS plans)
- Rust toolchain (only if building the resolver binary from source)

## Installation

```bash
# Install the plugin
npm install @openclaw/credential-vault

# Or load from a local path in your OpenClaw config:
# plugins.load.paths: ["~/Projects/openclaw-credential-vault"]
```

## Quick Start

### 1. Initialize the vault

```bash
openclaw vault init
```

This creates `~/.openclaw/vault/` with:
- `tools.yaml` — credential metadata and injection rules
- `meta.json` — vault configuration (key mode, install timestamp)

Two key modes are available:
- **machine** (default) — derives the master key from machine characteristics (hostname, user, install timestamp). Zero-config, tied to the machine.
- **passphrase** — uses a user-provided passphrase via `OPENCLAW_VAULT_PASSPHRASE` env var. Portable across machines.

### 2. Add a credential

```bash
openclaw vault add <tool-name>
```

For known tools (e.g., `gumroad`, `github`, `brave`), the plugin auto-configures injection rules, scrub patterns, and rotation metadata. For unknown tools, you'll be guided through manual setup.

Example — adding a Gumroad API token:

```bash
openclaw vault add gumroad
# Paste your access token when prompted
# → Encrypted file created at ~/.openclaw/vault/gumroad.enc
# → Injection rules added to tools.yaml
```

### 3. List credentials

```bash
openclaw vault list
```

Shows all stored credentials with:
- Tool name and credential type
- Creation date and age
- Rotation status (overdue / OK)
- Scrub pattern count

### 4. Rotate a credential

```bash
openclaw vault rotate <tool-name>
```

Prompts for the new credential value, re-encrypts it, updates the creation timestamp, and signals the gateway to reload via SIGUSR2.

### 5. Test injection

```bash
openclaw vault test <tool-name>
```

Decrypts the credential and displays a redacted preview to confirm it's stored correctly.

### 6. Audit credentials

```bash
openclaw vault audit
```

Reports:
- Credentials overdue for rotation
- Access statistics from the audit log
- Security recommendations

## How It Works

### Credential Injection

When the agent calls a tool (e.g., `exec`), the plugin's `before_tool_call` hook intercepts the request:

1. Matches the tool call against injection rules in `tools.yaml` (command glob patterns, URL patterns)
2. Decrypts the credential from `~/.openclaw/vault/<tool>.enc`
3. Injects the credential as environment variables into the tool call
4. The credential never appears in the agent's prompt or transcript

### Output Scrubbing

The plugin scrubs credentials from outputs at multiple layers:

- **after_tool_call** — scrubs tool results before the agent sees them
- **tool_result_persist** — scrubs before transcript storage
- **message_sending** — final safety net before any message leaves the gateway

Scrubbing uses regex patterns (configurable per tool) plus literal hash-based matching for format-agnostic detection.

### Browser Credentials

#### Cookies

Store browser cookies for authenticated sessions:

```bash
openclaw vault add <tool-name>
# Choose format: playwright-json or netscape
# Paste or pipe your cookie data
```

Cookies are stored encrypted with domain pinning — they're only injected when the browser navigates to matching domains.

#### Passwords

Store site credentials for automated login:

```bash
openclaw vault add <tool-name>
# Configure as browser-password type
# Set domain pin and field hints
```

The plugin injects credentials into browser fill actions, pinned to specific domains to prevent prompt-injection redirects.

### Rust Resolver (Phase 2 — Binary Mode)

For enhanced isolation, the plugin can delegate decryption to a Rust binary (`openclaw-vault-resolver`). This binary:

- Runs as a separate process (optionally setuid to a dedicated vault user)
- Uses seccomp to restrict syscalls to the minimum required
- Communicates via stdin/stdout JSON protocol
- Ensures the Node.js process never sees the raw master key

Build from source:

```bash
cd resolver
cargo build --release --target x86_64-unknown-linux-musl
```

The resulting static binary is at `resolver/target/x86_64-unknown-linux-musl/release/openclaw-vault-resolver`.

## Security Model

### Encryption

- **Algorithm:** AES-256-GCM (authenticated encryption)
- **Key derivation:** Argon2id with configurable parameters
- **Per-credential salt:** Each `.enc` file has a unique random salt
- **At rest:** Credentials stored as encrypted binary blobs in `~/.openclaw/vault/`

### Isolation Layers

| Layer | Protection |
|-------|-----------|
| File permissions | Vault directory restricted to owner (0700) |
| Encryption at rest | AES-256-GCM — compromise of disk doesn't expose secrets |
| Injection scoping | Credentials only injected into matching tool calls |
| Domain pinning | Browser credentials locked to specific domains |
| Output scrubbing | Multi-layer scrubbing prevents leaks in transcripts |
| Rust resolver | Optional OS-level process isolation + seccomp |
| Audit logging | All credential access logged for review |

### Threat Model

The vault protects against:
- **Transcript leakage** — credentials scrubbed from all persisted content
- **Prompt injection** — domain pinning prevents credential exfiltration via redirects
- **Disk access** — encrypted at rest; machine-key mode ties decryption to the host
- **Plugin compromise** — Rust resolver ensures decryption happens in a sandboxed process

It does **not** protect against:
- Root access on the host machine
- Memory inspection of the running Node.js process (mitigated by Rust resolver)
- Compromise of the OpenClaw gateway process itself

## Configuration

### tools.yaml

The vault config lives at `~/.openclaw/vault/tools.yaml`:

```yaml
tools:
  gumroad:
    credentialType: api-token
    inject:
      - tool: exec
        commandMatch: "curl *api.gumroad.com*"
        env:
          GUMROAD_TOKEN: "$vault:gumroad"
    scrub:
      patterns:
        - "[a-zA-Z0-9_-]{20,}"
    rotation:
      intervalDays: 90
      support: manual
      procedure: "Generate new token at https://app.gumroad.com/settings/advanced"
    createdAt: "2026-03-08T12:00:00Z"
```

### Plugin Config (openclaw.plugin.json)

```json
{
  "vaultDir": "~/.openclaw/vault",
  "masterKeyMode": "machine"
}
```

## Troubleshooting

### "Vault not initialized"

Run `openclaw vault init` to create the vault directory and config files.

### "Decryption failed"

- **Machine mode:** The machine characteristics (hostname, username) may have changed. If you've moved machines, you'll need to re-add credentials.
- **Passphrase mode:** Ensure `OPENCLAW_VAULT_PASSPHRASE` is set correctly.

### "Resolver binary not found"

The Rust resolver is optional. If not present, the plugin falls back to inline decryption (Node.js process). To build:

```bash
cd resolver
# Install Rust: https://rustup.rs
rustup target add x86_64-unknown-linux-musl
sudo apt-get install musl-tools  # Ubuntu/Debian
cargo build --release --target x86_64-unknown-linux-musl
```

### Credential not injecting

1. Check `openclaw vault list` — verify the credential exists
2. Check `openclaw vault test <tool>` — verify decryption works
3. Verify the `commandMatch` glob pattern matches your tool call
4. Check audit log: `openclaw vault audit` → look for access entries

### Scrubbing not working

1. Verify scrub patterns in `tools.yaml` are correct regex
2. Test manually: the scrubber removes any text matching the patterns
3. Check for false positives: overly broad patterns may scrub legitimate content

## Performance Note

Argon2id key derivation is intentionally slow (~200ms per derivation) as a security measure against brute-force attacks. Credentials are cached in memory after first decryption, so this cost is paid once per gateway restart. The Rust resolver adds ~50ms of process spawn overhead but provides stronger isolation.

Benchmark tests exist in the test suite (`performance.test.ts`) but may show variance depending on system load and available CPU. CI runs may exhibit different timings than local development.

## Development

```bash
# Install dependencies
npm ci

# Build TypeScript
npm run build

# Run unit tests
npm test

# Run Rust tests
cd resolver && cargo test

# Run cross-language compatibility tests
npm run test:cross

# Build Rust resolver
npm run build:resolver

# Package check
npm pack --dry-run
```

## License

MIT

## ⚠️ Security: Migration from Plaintext

**CRITICAL:** Never migrate existing plaintext credentials through an AI agent (e.g., `vault add --key "your-secret"`). The agent sees the plaintext in its context window — the credential is effectively leaked.

### Correct migration flow:

1. **Generate a new credential** (in your browser/dashboard — not through the agent)
2. **Add it to the vault directly in your terminal:**
   ```bash
   openclaw vault add <name> --key "<new-credential>" --yes
   ```
3. **Revoke the old credential** in the service's dashboard
4. **Delete any plaintext files** that had the old credential

### Why?

When an AI agent reads a credential (via `cat`, `echo`, file reads, etc.), that plaintext enters the LLM context. Even if you immediately encrypt it into the vault, the plaintext was processed by the model. Treat any credential that has passed through an AI agent as compromised.

### For existing users migrating to the vault:

```bash
# ❌ WRONG — agent sees the credential
cat ~/.my-api-token | openclaw vault add myservice --key "$(cat ~/.my-api-token)"

# ✅ RIGHT — rotate first, add new token in terminal
# 1. Generate new token in service dashboard
# 2. In YOUR terminal (not the agent):
openclaw vault add myservice --key "new-token-from-dashboard" --yes
# 3. Revoke old token in service dashboard
# 4. Delete plaintext file
```
