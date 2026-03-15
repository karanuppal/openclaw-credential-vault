# Release Notes — 1.0.0-beta.2

The first public beta of the OpenClaw Credential Vault.

---

## What this gives you

**Your AI agent can use GitHub, Stripe, and other services — without ever seeing your credentials.**

The vault encrypts credentials at rest, injects them into short-lived subprocesses at tool-call time, and scrubs them from all output before the agent sees anything. If a prompt injection tries to exfiltrate your tokens, multiple independent layers catch it.

## Key features

**Zero-config credential detection.** Run `vault add github --key ghp_...` and the vault auto-detects the format, sets up injection rules for `gh` commands, and configures scrub patterns — all from the key prefix alone. Works out of the box for GitHub, Stripe, OpenAI, Anthropic, and Gumroad.

**Two security tiers.** Inline mode (no sudo required) gives you encryption at rest + full scrubbing. Binary mode (run the setup script with sudo) adds OS-level user separation — your credentials live in a directory the agent literally cannot read, decrypted by a sandboxed Rust binary.

**Browser credential support.** Domain-pinned passwords (`$vault:amazon-login` only resolves on `*.amazon.com`) and cookie jar injection for authenticated browsing. A prompt injection directing your password to `evil-site.com` gets blocked, not silently skipped.

**Hot-reload.** After `vault add` or `vault rotate`, changes take effect immediately. No gateway restart.

**Credential rotation tracking.** Every credential records when it was added and last rotated. `vault rotate --check` shows what's overdue. `vault rotate --all` walks you through everything interactively.

**Audit log.** Every credential access and every scrubbing event is logged. `vault logs --stats` gives you aggregate telemetry. `vault logs --tool github --last 7d` shows exactly when your GitHub token was used.

**Version-safe updates.** The plugin and resolver binary communicate via a versioned protocol. If they get out of sync after an update, you get a clear warning with the exact command to fix it — not a silent failure.

## Testing confidence

**610 tests across 30 files, all passing.** This isn't a "works on my machine" beta:

- **Adversarial test suite** — 54 tests simulating real attacks: prompt injection, domain spoofing, format evasion, credential writes to files, environment variable exfiltration
- **False positive corpus** — 37 tests ensuring UUIDs, git hashes, CSS colors, and other common patterns are NOT incorrectly scrubbed
- **Cross-language verification** — TypeScript and Rust produce byte-identical encryption output, verified by 8 compatibility tests
- **Install verification** — Docker-based clean-machine tests on Debian 12 and Ubuntu 24.04 prove the packaged artifact installs and works, not just the source tree
- **CI pipeline** — 6 jobs run on every push: Rust resolver tests, TypeScript tests on Node 20 + 22, install verification on two platforms, cross-language compatibility

## Platform support

| Platform | Status |
|----------|--------|
| Debian 12+ / Ubuntu 22.04+ (x64) | ✅ Full support |
| Other Linux x64 | Should work — untested |
| Linux arm64 | Inline mode only |
| macOS | Inline mode only |
| Alpine Linux | Not supported |

## Known limitations

- **Machine-key derivation** uses hostname + UID + install timestamp. This is defense-in-depth, not a strong secret. Binary mode with OS-user separation is the real protection.
- **Scrubbing is best-effort.** Credentials in unusual encodings (base64-wrapped, URL-encoded, split across lines) may not be caught by regex. Literal matching covers exact values.
- **Browser credentials are tested but not production-hardened.** Cookie injection and password filling work in integration tests; real-world browser automation may have edge cases.
- **Sandbox mode is untested.** The hooks run in the gateway process (not inside Docker), so it should work — but no end-to-end verification has been done yet.

## Getting started

```bash
curl -fsSL https://raw.githubusercontent.com/karanuppal/openclaw-credential-vault/main/install.sh | bash
openclaw vault add github --key "ghp_your_token_here"
openclaw vault test github
```

Full documentation: [README](README.md) · [Architecture](docs/ARCHITECTURE.md) · [Threat Model](docs/THREAT-MODEL.md) · [Specification](docs/SPEC.md)
