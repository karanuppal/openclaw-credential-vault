# OpenClaw Credential Vault

Encrypted credential management for [OpenClaw](https://openclaw.ai). Keeps API keys, tokens, and passwords out of the AI agent's context window — where they could be exfiltrated, leaked into transcripts, or exposed through tool output.

## Install

```bash
curl -fsSL https://raw.githubusercontent.com/karanuppal/openclaw-credential-vault/main/install.sh | bash
```

This installs the plugin, creates a dedicated system user for credential isolation, and configures everything. You'll be prompted for sudo.

**Can't use sudo?** Run `openclaw vault init` for inline-only mode — credentials are still encrypted at rest, just without OS-level user separation.

## Quick Start

```bash
# Add a credential (auto-detects format)
openclaw vault add github --key "ghp_your_token_here"

# Verify it works
openclaw vault test github

# Add more
openclaw vault add stripe --key "sk_live_..."
openclaw vault add amazon --type browser-password --domain .amazon.com --key "p@ssw0rd"
```

That's it. The agent can now use `gh`, call Stripe APIs, and log into Amazon — without ever seeing the credentials.

## How It Works

```
Agent runs "gh pr list"
    ↓
before_tool_call hook matches "gh" → decrypts credential → injects GH_TOKEN into subprocess
    ↓
gh runs with the token, returns PR listings
    ↓
Subprocess exits — credential dies with it
    ↓
Output scrubbed for credential patterns (3 layers: regex + literal + env-var)
    ↓
Agent sees clean PR listings — no credential anywhere in context
```

**Encryption:** AES-256-GCM with Argon2id key derivation (64 MiB memory, 3 iterations). Each credential is a separate `.enc` file.

**Isolation:** The Rust resolver binary runs as a dedicated `openclaw-vault` system user via setuid. The agent process can't read the credential files — it gets "Permission denied."

**Scrubbing:** Three redundant layers catch credentials in tool output, file writes, outbound messages, and session transcripts. Patterns for GitHub, Stripe, Gumroad, OpenAI, and Anthropic tokens ship built-in.

## Commands

| Command | Description |
|---------|-------------|
| `vault init` | Initialize vault (creates directory, shows setup instructions) |
| `vault add <tool> --key <cred>` | Add a credential (auto-detects format) |
| `vault add <tool> --type browser-password --domain <d> --key <p>` | Add a domain-pinned browser password |
| `vault add <tool> --type browser-cookie --domain <d>` | Add browser cookies (paste JSON or Netscape format) |
| `vault list` | Show all stored credentials and status |
| `vault show <tool>` | Show credential details and config |
| `vault test <tool>` | Verify injection and scrubbing work |
| `vault rotate <tool> --key <new>` | Rotate a credential |
| `vault rotate --check` | Show overdue rotations |
| `vault rotate --all` | Emergency mass rotation walkthrough |
| `vault remove <tool>` | Remove credential (keeps scrub patterns) |
| `vault remove <tool> --purge` | Fully remove credential + config |
| `vault audit` | Security audit (permissions, rotation, config) |
| `vault logs` | View audit log (credential access + scrubbing) |
| `vault logs --stats` | Aggregate access/scrub statistics |
| `vault logs --tool <name> --last <duration>` | Filter by tool and time |
| `vault logs --json` | Raw JSONL output |

## Platform Support

| Platform | Status |
|----------|--------|
| Linux x64 | Full support (inline + resolver) |
| Linux arm64 | Inline mode only (resolver binary coming soon) |
| macOS | Inline mode only |

**Sandbox mode:** Not yet tested with OpenClaw's Docker sandbox. The vault hooks run in the gateway process (not inside the sandbox container), so they should work in theory, but no end-to-end verification has been done. See [Specification](docs/SPEC.md#sandbox-compatibility) for details.

## Learn More

- **[Architecture](docs/ARCHITECTURE.md)** — Component map, Mermaid diagrams, hook pipeline, Rust resolver deep dive
- **[Threat Model](docs/THREAT-MODEL.md)** — What we defend against, what we don't, and design trade-offs
- **[Specification](docs/SPEC.md)** — Encryption scheme, hook behavior, CLI reference, config schemas
- **[Testing](docs/TESTING.md)** — 540 tests across 27 files: unit, integration, adversarial, performance
- **[Security Audit](docs/SECURITY-AUDIT.md)** — Validation methodology, results, bugs found and fixed

## License

MIT
