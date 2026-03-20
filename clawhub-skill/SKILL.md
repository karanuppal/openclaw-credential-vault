---
name: openclaw-credential-vault
description: Encrypted credential management for OpenClaw — keeps API keys, tokens, and passwords out of the AI agent's context window. AES-256-GCM encryption, subprocess-scoped injection, automatic output scrubbing.
version: 1.0.0-beta.5
metadata:
  openclaw:
    emoji: "🔐"
    homepage: https://github.com/karanuppal/openclaw-credential-vault
    requires:
      bins:
        - openclaw
      config:
        - ~/.openclaw/vault/tools.yaml
        - ~/.openclaw/vault/*.enc
    install:
      - id: openclaw-credential-vault
        kind: node
        package: openclaw-credential-vault
        bins: [openclaw-credential-vault]
        label: Install Credential Vault plugin (npm)
---

# OpenClaw Credential Vault

Encrypted credential management for OpenClaw. Keeps API keys, tokens, and passwords out of the AI agent's context window — where they could be exfiltrated, leaked into transcripts, or exposed through tool output.

**Full TypeScript source and tests are included in this skill bundle for verification.** See `src/` and `tests/` directories.

## What You Get

- **Credentials never enter the AI's context.** Decrypted and injected only into the specific subprocess that needs them, then scrubbed from output before the agent sees it.
- **Encryption at rest.** Each credential individually encrypted with AES-256-GCM, Argon2id key derivation.
- **Automatic output scrubbing.** Multiple independent scrubbing layers catch credentials in tool output, outbound messages, and session transcripts.
- **~700 tests** across 36 files covering crypto, injection, scrubbing, adversarial attacks, and end-to-end scenarios. Representative test files included in this bundle under `tests/`.
- **Open source.** Full source at [GitHub](https://github.com/karanuppal/openclaw-credential-vault).

## Source Code Included

This skill bundle includes the complete TypeScript source code for verification:

- `src/crypto.ts` — AES-256-GCM encryption/decryption, Argon2id key derivation
- `src/scrubber.ts` — Credential pattern matching and output scrubbing
- `src/index.ts` — Plugin hook registration (before_tool_call, after_tool_call, before_message_write, message_sending)
- `src/browser.ts` — Browser credential domain-pinning logic
- `src/audit.ts` — Credential access audit logging
- `src/cli.ts` — CLI commands (vault add, list, test, rotate, remove)
- `src/resolver.ts` — Credential resolution and injection rule matching
- `src/config.ts` — tools.yaml configuration management
- `src/guesser.ts` — Credential format auto-detection
- `src/types.ts` — TypeScript type definitions
- `tests/` — Representative test files (crypto, scrubber, hooks, e2e, false-positives, browser, audit)

## Storage and File Access

All data stored under `~/.openclaw/vault/`:

- `*.enc` — Individual encrypted credential files (AES-256-GCM). File permissions 600.
- `tools.yaml` — Injection rules: which command patterns trigger which credential injection, which URL patterns get auth headers.
- `.vault-meta.json` — Vault metadata (initialization timestamp, version).
- `audit.log` — Credential access audit log.

## Key Derivation (Exact Details)

Encryption keys are derived using Argon2id with these parameters (see `src/crypto.ts` lines 15-20):

- **Algorithm:** Argon2id (hybrid — resistant to both side-channel and GPU attacks)
- **Memory cost:** 65,536 KiB (64 MiB)
- **Time cost:** 3 iterations
- **Parallelism:** 1
- **Output length:** 32 bytes (256-bit key for AES-256)
- **Salt:** 16 random bytes per credential (stored in the `.enc` file header)

**Key source:** When the user provides a passphrase during `vault init`, that passphrase is used. When no passphrase is provided (machine key mode), the key is derived from `hostname + uid + install-timestamp` (see `getMachinePassphrase()` in `src/crypto.ts` line 44).

**File format:** Each `.enc` file is `[16-byte salt][12-byte nonce][ciphertext][16-byte auth tag]`.

## Scrubbing Heuristics (Exact Details)

Three-layer scrubbing pipeline (see `src/scrubber.ts`):

1. **Regex pattern matching** — Per-credential patterns generated from the credential format. Known prefixes like `ghp_`, `sk_live_`, `npm_`, `xoxb-` are matched by format-specific regexes. Catches any credential of a given format, not just the stored one.

2. **Hash-based literal matching** — The exact credential value (populated at injection time) is matched as a literal string. Catches the specific stored credential regardless of format. Prevents false negatives when a credential doesn't match any known regex pattern.

3. **Environment variable name matching** — Regex `\b([A-Z_]*(?:KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|API_KEY|APIKEY)[A-Z_]*)=([^\s\n]+)` catches credentials exposed as `KEY=[VAULT:env-redacted] in output.

**Global patterns** (always active): Telegram bot tokens (`\d{10}:[A-Za-z0-9_-]{35}`), Slack bot tokens (`xoxb-[A-Za-z0-9-]+`).

**Replacement format:** Matched credentials are replaced with `[VAULT:toolname]`.

## Plugin Hooks

The plugin registers these OpenClaw hooks (see `src/index.ts`):

- **`before_tool_call`** (priority 10, runs last) — Injects credent[VAULT:gmail-app] parameters. Matches the command against `tools.yaml` injection rules, decrypts the matching `.enc` file, and sets environment variables on the subprocess.
- **`after_tool_call`** (priority 1, runs first) — Audit logging for credential access events.
- **`before_message_write`** (priority 1, runs first) — Scrubs credentials from all messages before transcript write.
- **`message_sending`** (priority 1, runs first) — Scrubs credentials from outbound messages before delivery.

All hooks are **fail-open**: if scrubbing/injection errors occur, the operation proceeds rather than crashing the gateway.

## Install

Install the plugin via npm:

```bash
npm install -g openclaw-credential-vault
```

Then restart the gateway to load the plugin. The npm package contains the compiled JavaScript, native Argon2 bindings, and the Rust resolver binary. The TypeScript source included in this skill bundle is the pre-compilation version of the same code.

## Quick Start

```bash
# Initialize the vault
openclaw vault init

# Add a credential (interactive — picks the right injection type)
openclaw vault add github --key "ghp_your_token_here"

# Verify it works end-to-end (injection + scrubbing)
openclaw vault test github

# Add more
openclaw vault add stripe --key "sk_live_..."
openclaw vault add npm --key "npm_..."
```

## Commands

- `vault init` — Initialize vault and create `~/.openclaw/vault/` directory
- `vault add <tool> --key <cred>` — Add a credential (interactive usage selection: API, CLI)
- `vault list` — Show all stored credentials and status
- `vault show <tool>` — Show credential details and injection config
- `vault test <tool>` — Verify injection and scrubbing work end-to-end
- `vault rotate <tool> --key <new>` — Rotate a credential (re-encrypts in place)
- `vault rotate --check` — Show credentials overdue for rotation
- `vault remove <tool>` — Remove credential file and injection rules

### Non-Interactive Mode

```bash
# API header injection
openclaw vault add stripe --key "sk_live_..." --use api --url "api.stripe.com/*" --yes

# CLI env injection
openclaw vault add github --key "ghp_..." --use cli --command gh --env GITHUB_TOKEN --yes
```

## Links

- GitHub: https://github.com/karanuppal/openclaw-credential-vault
- npm: https://www.npmjs.com/package/openclaw-credential-vault
- Issues: https://github.com/karanuppal/openclaw-credential-vault/issues
