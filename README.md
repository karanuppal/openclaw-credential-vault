# OpenClaw Credential Vault

Encrypted credential management for OpenClaw. Keeps API keys, tokens, and passwords out of the AI agent's context window.

## Install

```bash
openclaw plugins install @openclaw/credential-vault
```

## Setup

After installation, the plugin prints one command. Run it:

```bash
sudo bash /path/to/vault-setup.sh    # ← printed after install, copy-paste it
```

That's it. The setup script handles everything — vault initialization, encryption setup, system user creation, binary installation, and config updates. The gateway restarts automatically.

**Why sudo?** The script creates a dedicated `openclaw-vault` system user (like `postgres` or `docker`) so the AI agent physically cannot read your credential files. This is a one-time operation. After setup, everything runs without elevated privileges.

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

With OS-level isolation enabled, decryption happens in a separate setuid binary running as the `openclaw-vault` user. The agent process never touches the credential files or the decryption key.

## Why `sudo`?

The setup script needs root to:
- Create a `openclaw-vault` system user (like `postgres` or `docker`)
- Install a setuid binary in `/usr/local/bin/`
- Set file ownership so only that user can read credentials

This is a one-time operation. After setup, everything runs without elevated privileges. This is the same pattern used by Docker, PostgreSQL, and other software that needs process isolation.

## Commands

| Command | Description |
|---------|-------------|
| `vault init` | Initialize the vault + show setup instructions |
| `vault add <tool> --key <cred>` | Add a credential |
| `vault list` | Show all stored credentials |
| `vault show <tool>` | Show credential details |
| `vault rotate <tool> --key <new>` | Rotate a credential |
| `vault remove <tool>` | Remove a credential |
| `vault test <tool>` | Verify injection and scrubbing |
| `vault audit` | Check permissions, rotation age, security |

## Platform Support

| Platform | Status |
|----------|--------|
| Linux x64 | ✅ Fully supported |
| Linux arm64 | Inline mode only (resolver binary coming soon) |
| macOS | Inline mode only (resolver binary coming soon) |

## License

MIT
