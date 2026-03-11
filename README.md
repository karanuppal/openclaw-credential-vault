# OpenClaw Credential Vault

Encrypted credential management for OpenClaw. Keeps API keys, tokens, and passwords out of the AI agent's context window.

## Install

```bash
curl -fsSL https://raw.githubusercontent.com/opscontrol711/openclaw-credential-vault/main/install.sh | bash
```

This installs the plugin, creates a dedicated system user for credential isolation, and configures everything. You'll be prompted for sudo.

## Add Credentials

```bash
openclaw vault add github --key "ghp_your_token_here"
openclaw vault add stripe --key "sk_live_..."

# Verify it works
openclaw vault test github
```

The vault auto-detects credential formats and configures injection rules, environment variables, and scrubbing patterns automatically.

## How It Works

1. Credentials are encrypted at rest (AES-256-GCM + Argon2id)
2. When the agent runs a matching command (e.g. `gh pr list`), the vault decrypts and injects the credential into the subprocess environment
3. The subprocess exits — the credential dies with it
4. All output is scrubbed for credential patterns before reaching the agent

Decryption happens in a separate setuid binary running as the `openclaw-vault` system user. The agent process never touches the credential files or the decryption key.

## Why `sudo`?

The installer creates a `openclaw-vault` system user and installs a setuid binary — the same pattern used by Docker, PostgreSQL, and other software that needs process isolation. This is a one-time operation. After setup, everything runs without elevated privileges.

If you can't use sudo, run `openclaw vault init` for inline-only mode. Credentials are still encrypted at rest, but without OS-level user separation.

## Commands

| Command | Description |
|---------|-------------|
| `vault init` | Initialize vault (inline mode, no sudo needed) |
| `vault add <tool> --key <cred>` | Add a credential |
| `vault add <tool> --type browser-password --domain <d> --key <p>` | Add a browser password (auto-filled on domain) |
| `vault add <tool> --type browser-cookie --domain <d>` | Add browser cookies (paste JSON or Netscape format) |
| `vault list` | Show all stored credentials |
| `vault show <tool>` | Show credential details |
| `vault test <tool>` | Verify injection and scrubbing |
| `vault rotate <tool> --key <new>` | Rotate a credential |
| `vault rotate --check` | Show overdue rotations |
| `vault rotate --all` | Emergency mass rotation walkthrough |
| `vault remove <tool>` | Remove credential (keeps scrub patterns) |
| `vault remove <tool> --purge` | Fully remove credential + config |
| `vault audit` | Check permissions, rotation age, security |
| `vault logs` | View audit log (credential access + scrubbing events) |
| `vault logs --stats` | Aggregate access/scrub statistics |
| `vault logs --tool <name>` | Filter log by tool |
| `vault logs --last <duration>` | Filter by time window (e.g. `24h`, `7d`, `30m`) |
| `vault logs --json` | Raw JSONL output |

## Platform Support

| Platform | Status |
|----------|--------|
| Linux x64 | ✅ Fully supported |
| Linux arm64 | Inline mode only (resolver coming soon) |
| macOS | Inline mode only (resolver coming soon) |

## License

MIT
