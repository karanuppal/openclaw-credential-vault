# OpenClaw Credential Vault

Encrypted credential management for OpenClaw. Keeps API keys, tokens, and passwords out of the AI agent's context window.

## Quick Start

```bash
# Initialize the vault
openclaw vault init

# Add a credential
openclaw vault add github --key "ghp_your_token_here"

# Verify it works
openclaw vault test github
```

That's it. Your agent can now run `gh` commands with automatic credential injection. The token never appears in the agent's context.

## How It Works

1. Credentials are encrypted at rest (AES-256-GCM + Argon2id)
2. When the agent runs a matching command (e.g. `gh pr list`), the vault injects the credential into the subprocess environment
3. The subprocess exits — the credential dies with it
4. All output is scrubbed for credential patterns before reaching the agent

## Security Modes

### Inline Mode (default — no sudo required)

```bash
openclaw vault init
```

- Credentials encrypted at rest with AES-256-GCM
- Machine-specific key derivation (hostname + uid + install timestamp)
- Agent sees ciphertext if it reads `.enc` files — useless without the key
- Credentials injected only into short-lived subprocesses
- All output scrubbed before reaching the agent context

**Threat coverage:** Protects against accidental credential leakage into the AI context window, prompt injection attacks that try to exfiltrate secrets, and credential exposure through session transcripts or message history.

**Limitation:** The agent runs as the same OS user. A sophisticated attack could theoretically derive the machine key and decrypt credentials. For most deployments, this is an acceptable risk — the primary threat is accidental leakage, not a targeted attack against the encryption.

### Binary Resolver Mode (recommended — requires sudo)

```bash
# Step 1: Initialize the vault (as your normal user)
openclaw vault init

# Step 2: Run the setup script (as root)
sudo bash $(openclaw vault init 2>&1 | grep "sudo bash" | awk '{print $3}')

# Or find the script directly:
sudo bash ~/.openclaw/vault/../../../Projects/openclaw-credential-vault/bin/vault-setup.sh

# Step 3: Restart the gateway
openclaw doctor fix
```

Everything in inline mode, **plus:**

- Credentials owned by a dedicated `openclaw-vault` system user
- Agent gets "Permission denied" if it tries to read credential files
- Decryption happens in a separate setuid binary with seccomp sandboxing
- Hard OS-level boundary — not bypassable from the agent process

**Why sudo?** The setup script creates a system user (`openclaw-vault`) and installs a setuid binary. These are kernel-level operations that require root. This is a one-time setup — after that, everything runs without elevated privileges.

## Adding Credentials

```bash
# API keys and tokens
openclaw vault add github --key "ghp_..."
openclaw vault add stripe --key "sk_live_..."
openclaw vault add gumroad --key "gum_..."

# The vault auto-detects the credential format and configures:
# - Which commands trigger injection (e.g., gh, stripe, curl)
# - Which environment variables to set (e.g., GH_TOKEN, STRIPE_API_KEY)
# - Which patterns to scrub from output
```

## Commands

| Command | Description |
|---------|-------------|
| `vault init` | Initialize the vault |
| `vault add <tool> --key <cred>` | Add a credential |
| `vault list` | Show all stored credentials |
| `vault show <tool>` | Show credential details |
| `vault rotate <tool> --key <new>` | Rotate a credential |
| `vault remove <tool>` | Remove a credential |
| `vault test <tool>` | Verify injection and scrubbing |
| `vault audit` | Check permissions, rotation age, security |

## Supported Platforms

| Platform | Inline Mode | Binary Resolver |
|----------|-------------|-----------------|
| Linux x64 | ✅ | ✅ |
| Linux arm64 | ✅ | Coming soon |
| macOS x64 | ✅ | Coming soon |
| macOS arm64 | ✅ | Coming soon |

## License

MIT
