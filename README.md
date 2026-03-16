# OpenClaw Credential Vault

Encrypted credential management for [OpenClaw](https://openclaw.ai). Keeps API keys, tokens, and passwords out of the AI agent's context window — where they could be exfiltrated, leaked into transcripts, or exposed through tool output.

## What You Get

- **Your credentials never enter the AI's context.** They're decrypted, injected into a short-lived subprocess, and scrubbed from output before the agent sees it.
- **Encryption at rest.** Each credential is individually encrypted with AES-256-GCM. Even if someone reads your vault directory, they get ciphertext.
- **OS-level isolation.** A dedicated system user owns the credential files. The agent process can't read them — decryption happens in a separate, sandboxed Rust binary.
- **Automatic output scrubbing.** Credentials are caught and redacted in tool output, outbound messages, and session transcripts through multiple independent layers.
- **Thoroughly tested.** 658 tests across 34 files covering crypto, injection, scrubbing, adversarial attacks, false positives, and clean-machine install verification.

## Install

```bash
curl -fsSL https://raw.githubusercontent.com/karanuppal/openclaw-credential-vault/main/install.sh | bash
```

This installs the plugin, creates the dedicated system user, and configures file permissions. You'll be prompted for sudo.

**Can't use sudo?** Run `openclaw vault init` for inline-only mode — credentials are still encrypted at rest, just without OS-level user separation.

## Quick Start

```bash
# Add a credential (auto-detects format)
openclaw vault add github --key "ghp_your_token_here"

# Verify it works
openclaw vault test github

# Add more
openclaw vault add stripe --key "sk_live_..."
```

That's it. The agent can now use `gh` and call Stripe APIs without ever seeing the credentials.

## How It Works

```
Agent runs "gh pr list"
    ↓
Vault matches "gh" → decrypts credential → injects into subprocess environment
    ↓
gh runs with the token, returns results
    ↓
Subprocess exits — credential dies with it
    ↓
Output scrubbed for credential patterns before the agent sees it
    ↓
Agent gets clean PR listings — no credential anywhere in context
```

After adding a credential, changes take effect immediately — no gateway restart needed.

If the plugin and resolver binary get out of sync after an update, you'll get a clear warning with the exact command to fix it.

## Commands

| Command | Description |
|---------|-------------|
| `vault init` | Initialize vault |
| `vault add <tool> --key <cred>` | Add a credential (interactive usage selection: API, CLI, browser login, browser session) |
| `vault add <tool> --key <cred> --use api --url <pattern> [--header <name>] [--no-bearer]` | Non-interactive API header injection |
| `vault add <tool> --key <cred> --use cli --command <name> --env <var>` | Non-interactive CLI env injection |
| `vault add <tool> --key <cred> --use browser-login --domain <domain>` | Domain-pinned browser password flow |
| `vault add <tool> --key '<cookie-json>' --use browser-session --domain <domain>` | Browser session with inline cookie JSON |
| `vault add <tool> --key /path/to/cookies.json --use browser-session --domain <domain>` | Browser session with cookie file |
| `vault list` | Show all stored credentials and status |
| `vault show <tool>` | Show credential details and injection config |
| `vault test <tool>` | Verify injection and scrubbing work end-to-end |
| `vault rotate <tool> --key <new>` | Rotate a credential |
| `vault rotate --check` | Show credentials overdue for rotation |
| `vault rotate --all` | Interactive mass rotation walkthrough |
| `vault remove <tool>` | Remove credential (keeps scrub patterns as safety net) |
| `vault remove <tool> --purge` | Fully remove credential + all config |
| `vault audit` | Security audit (permissions, rotation, resolver status) |
| `vault logs` | View audit log (`--tool`, `--type`, `--last`, `--stats`, `--json`) |

### `vault add` flags

- `--use <types>`: comma-separated `api`, `cli`, `browser-login`, `browser-session`
- API flags: `--url`, `--header`, `--no-bearer`
- CLI flags: `--command`, `--env`
- Browser flags: `--domain`
- Scrubbing: `--scrub-pattern <regex>`
- Automation: `--yes` (strict: requires known format/template, or `--use` + required flags)

## Platform Support

| Platform | Status |
|----------|--------|
| Debian 12+ / Ubuntu 22.04+ (x64) | ✅ Full support (inline + binary resolver) |
| Other Linux x64 | Should work — untested |
| Linux arm64 | Inline mode only |
| macOS | Inline mode only |
| Alpine Linux | Not supported |

## Documentation

- **[Architecture](docs/ARCHITECTURE.md)** — Component map, hook pipeline, Rust resolver deep dive
- **[Specification](docs/SPEC.md)** — Encryption scheme, hook behavior, CLI reference, config schemas
- **[Threat Model](docs/THREAT-MODEL.md)** — What we defend against, what we don't, and design trade-offs
- **[Testing](docs/TESTING.md)** — 656 tests: unit, integration, adversarial, performance, install verification
- **[Security Audit](docs/SECURITY-AUDIT.md)** — Validation methodology, results, findings
- **[Install Verification](docs/INSTALL-VERIFICATION.md)** — Clean-machine Docker testing on Debian 12 and Ubuntu 24.04

## License

MIT
