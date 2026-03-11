# Specification

> Living spec derived from the current source code. This documents what **is** built — not what was planned.

---

## Principles

1. **Every secret gets the same treatment.** No exceptions — all credentials go through the same encrypt → inject → scrub → audit pipeline.
2. **Hard boundaries over soft mitigations.** OS-level user separation via the Rust resolver is the production target.
3. **Rotation is first-class.** Creation tracking, overdue alerts, emergency mass-rotation, documented procedures.
4. **Ship as a plugin.** Any OpenClaw user can install it. No core changes required.
5. **Build it, don't wait for upstream.** The plugin implements everything it needs without depending on features not yet in OpenClaw core.

---

## Encryption Scheme

### Cipher

- **Algorithm:** AES-256-GCM (authenticated encryption — provides both confidentiality and integrity)
- **Key derivation:** Argon2id (memory-hard, resistant to GPU/ASIC attacks)

### Argon2id Parameters

| Parameter | Value |
|-----------|-------|
| Algorithm | Argon2id (v0x13) |
| Memory cost | 64 MiB (65536 KiB) |
| Iterations | 3 |
| Parallelism | 1 |
| Output length | 32 bytes (256 bits) |
| Salt | 16 bytes, randomly generated per credential |

### Master Key Derivation

The master passphrase for Argon2id is derived from machine characteristics:

```
passphrase = SHA-256(hostname + ":" + uid + ":" + installTimestamp).hex()
```

Where:
- `hostname` — OS hostname
- `uid` — numeric user ID
- `installTimestamp` — ISO timestamp from `.vault-meta.json`, captured at `vault init`

This produces a deterministic 64-character hex string. The Rust resolver computes this identically using the same formula.

> **Note:** Passphrase mode (`OPENCLAW_VAULT_PASSPHRASE` env var) is implemented but not exposed in the CLI. Machine mode is the only user-facing option in v1.

### Encrypted File Format

Each credential is stored as a single binary file: `<tool-name>.enc`

```
[16-byte salt][12-byte nonce][variable ciphertext][16-byte auth tag]
```

| Segment | Length | Purpose |
|---------|--------|---------|
| Salt | 16 bytes | Random, unique per file — input to Argon2id |
| Nonce | 12 bytes | Random, unique per encryption — input to AES-256-GCM |
| Ciphertext | Variable | Encrypted credential value |
| Auth tag | 16 bytes | GCM authentication tag — integrity verification |

File permissions: `0600` (owner read/write only).

### Secure Delete

When a credential is removed or rotated, the old `.enc` file is overwritten with random bytes before unlinking:

```typescript
// Overwrite with random data before unlink
writeFileSync(filePath, randomBytes(existingSize));
unlinkSync(filePath);
```

---

## Hook Registration

The plugin registers 7 hooks on the OpenClaw plugin API:

### Hook Table

| Hook | Priority | Behavior | Error Handling |
|------|----------|----------|----------------|
| `before_tool_call` | 10 (last) | Injects credentials; scrubs write/edit content | Returns void (no injection) |
| `after_tool_call` | 1 (first) | Audit logging; env var cleanup | Swallows error |
| `tool_result_persist` | 1 (first) | Scrubs tool results before transcript | Returns void (fail-open) |
| `before_message_write` | 1 (first) | Scrubs all messages before transcript | Returns void (fail-open) |
| `message_sending` | 1 (first) | Scrubs outbound messages | Returns void (fail-open) |
| `after_compaction` | default | Logs compaction event | — |
| `gateway_start` | default | Validates vault, checks rotations, warms cache | — |

### Priority Rationale

- **Priority 10 (injection):** Runs last among plugins, minimizing the window where other plugins can see decrypted credentials in params.
- **Priority 1 (scrubbing):** Runs first among plugins, ensuring credentials are scrubbed before any downstream plugin processes the result.

### Error Handling Philosophy

All hook handlers are wrapped in try-catch blocks. On error:
1. The error is logged to `~/.openclaw/vault/error.log` (only when `OPENCLAW_VAULT_DEBUG` is set)
2. The hook returns void — allowing the operation to proceed without the vault's intervention
3. This is a deliberate **fail-open** design: blocking all agent output on a scrubbing bug would be worse than a potential credential exposure

---

## Credential Injection

### Injection Types

| Type | Tool | How It Works |
|------|------|-------------|
| `exec-env` | exec | Credential injected as environment variable in subprocess. Export commands prepended to the command string so the subprocess inherits them. |
| `http-header` | web_fetch | Credential injected as HTTP header (typically `Authorization: Bearer`). |
| `browser-password` | browser | `$vault:name` placeholder in fill text resolved after domain-pin validation. |
| `browser-cookie` | browser | Cookies injected via `_vaultCookies` param on navigate actions matching domain pins. |

### Injection Flow (exec-env)

1. Agent generates: `exec({ command: "gh pr list" })`
2. `before_tool_call` fires — `findMatchingRules()` matches "gh" against `commandMatch: "gh *|git *|curl*api.github.com*"`
3. Credential decrypted (from cache or via Argon2id)
4. Env var injected: `params.env.GH_TOKEN = "<credential>"`
5. Export prepended: `params.command = "export GH_TOKEN=[VAULT:env-redacted] && gh pr list"`
6. Subprocess runs with credential in environment
7. Subprocess exits — credential dies with it
8. `after_tool_call` cleans up `process.env.GH_TOKEN`

### Pattern Matching

Commands and URLs are matched using glob patterns converted to regex:

```typescript
// Glob: "gh *|git *|curl*api.github.com*"
// Becomes regex tested against each segment of the command
```

For multi-line commands (common when the gateway prepends shell comments):
1. The full command string is tested first (fast path)
2. If no match, the command is split on newlines
3. Comment lines (`#` prefix) are discarded
4. Each remaining line is split on `;`, `&&`, `||`
5. Each segment is tested independently
6. A match on any segment triggers injection

### Domain Pinning (Browser Credentials)

Browser credentials use domain pins to prevent injection on wrong sites:

- **Leading dot** (e.g., `.amazon.com`): Matches the domain itself AND all subdomains (`www.amazon.com`, `smile.amazon.com`)
- **Exact match** (e.g., `login.amazon.com`): Matches only that specific hostname
- **No wildcards**: `*.com` is rejected by validation

If the browser URL doesn't match the domain pin, the action is **blocked** with an error message — not silently skipped.

---

## Scrubbing Pipeline

### Three Layers

1. **Regex patterns** — Compiled from `scrub.patterns` in tool configs. Catch any credential matching a known format, even credentials not in the vault.
2. **Literal matching** — After decrypting a credential for injection, the exact plaintext is added to an in-memory match list. `indexOf`-based search catches it regardless of format.
3. **Env-variable names** — Pattern matching for `KEY=[VAULT:env-redacted] `TOKEN=[VAULT:env-redacted] `SECRET=[VAULT:env-redacted] `PASSWORD=[VAULT:env-redacted] values in output. Redacts the value portion.

### Replacement Format

Scrubbed credentials are replaced with: `[VAULT:<toolname>]`

### Hooks Where Scrubbing Runs

| Hook | What Gets Scrubbed |
|------|-------------------|
| `before_tool_call` | Write/edit tool content (content, newText, new_string params) |
| `tool_result_persist` | Tool result messages before session transcript write |
| `before_message_write` | All messages before transcript write |
| `message_sending` | Outbound messages to user |

### Built-In Scrub Patterns

From the known tools registry:

| Service | Patterns |
|---------|----------|
| Stripe | `sk_live_[a-zA-Z0-9]{24,}`, `sk_test_[a-zA-Z0-9]{24,}`, `rk_live_[a-zA-Z0-9]{24,}` |
| GitHub | `ghp_[a-zA-Z0-9]{36}`, `github_pat_[a-zA-Z0-9_]{82}` |
| Gumroad | `gum_[a-zA-Z0-9]{16,}` |
| OpenAI | `sk-[a-zA-Z0-9]{20,}` |
| Anthropic | `sk-ant-[a-zA-Z0-9-]{20,}` |

Users can add custom patterns via `vault add` or by editing `tools.yaml`.

---

## Credential Resolution Modes

### Inline Mode (Phase 1)

TypeScript decrypts `.enc` files directly from `~/.openclaw/vault/`:

- Same OS user as the agent process
- Encrypted at rest — agent sees ciphertext if it reads the file
- No permission barrier beyond encryption

### Binary Mode (Phase 2)

TypeScript spawns the Rust resolver (`openclaw-vault-resolver`) as a setuid subprocess:

- Resolver runs as `openclaw-vault` system user
- Reads `.enc` files from `/var/lib/openclaw-vault/` (mode 700, owned by `openclaw-vault`)
- Agent process cannot read credential files — gets `Permission denied`
- Resolver applies seccomp filter after decryption (restricts to read/write/exit/brk/mmap/munmap/close/fstat/futex/getrandom)
- Resolver drops all Linux capabilities after writing to stdout

### Mode Selection

The mode is set in `tools.yaml`:

```yaml
resolverMode: binary  # or "inline" (default)
resolverPath: /usr/local/bin/openclaw-vault-resolver  # optional custom path
```

Running `sudo bash vault-setup.sh` switches the mode to `binary` and migrates credential files.

---

## CLI Command Reference

All commands are subcommands of `openclaw vault`:

### vault init

Initialize the credential vault. Creates `~/.openclaw/vault/` with `tools.yaml` and `.vault-meta.json`.

```bash
openclaw vault init
```

- Idempotent — safe to run multiple times
- Shows sudo setup instructions for binary mode
- If binary mode is already configured, reports status

### vault add \<tool\>

Add a credential to the vault.

```bash
openclaw vault add <tool> --key <credential> [--yes]
openclaw vault add <tool> --type browser-cookie --domain <domain>
openclaw vault add <tool> --type browser-password --domain <domain> --key <password>
```

**Options:**
| Flag | Description |
|------|-------------|
| `--key <credential>` | The credential value to store |
| `--type <type>` | Credential type: `browser-cookie` or `browser-password` |
| `--domain <domain>` | Domain pin (required for browser types, e.g., `.amazon.com`) |
| `--yes` | Skip confirmation prompts, accept defaults |

**Behavior:**
1. Validates tool name (rejects path traversal, slashes, control chars, max 64 chars)
2. Detects credential format using prefix rules and heuristics
3. Shows detected format and suggested config
4. Prompts for confirmation (`[Y/n/edit]`) unless `--yes`
5. Encrypts credential with AES-256-GCM + Argon2id
6. Writes `.enc` file and updates `tools.yaml`
7. Signals gateway hot-reload via SIGUSR2

**Format detection:** Recognizes Stripe (sk_live_, sk_test_, rk_live_), GitHub (ghp_, github_pat_), Gumroad (gum_), Anthropic (sk-ant-), OpenAI (sk-), JWTs, JSON blobs, short passwords, and generic API keys.

### vault list

Show all registered tools and their status.

```bash
openclaw vault list
```

Displays a table with: tool name, status (active/missing), last rotation date, injection tool types, and scrubbing status.

### vault show \<tool\>

Show detailed configuration for a specific tool.

```bash
openclaw vault show <tool>
```

Shows: status, timestamps, rotation metadata (label, interval, scopes, procedure, revoke URL), injection rules with env vars and URL matches, and scrub patterns.

### vault test \<tool\>

Simulate injection and scrubbing for a tool — verifies the complete pipeline.

```bash
openclaw vault test <tool>
```

Tests: credential decryption, injection rule display, scrubbing pattern application against sample text.

### vault rotate

Rotate one or more credentials.

```bash
openclaw vault rotate <tool> --key <new-credential>
openclaw vault rotate --check
openclaw vault rotate --all
```

| Form | Description |
|------|-------------|
| `rotate <tool> --key <new>` | Replace credential for a single tool. Updates encryption, timestamp, and scrub patterns. Shows post-rotation security checklist. |
| `rotate --check` | List all credentials overdue for rotation (based on `rotationIntervalDays`, default 90). |
| `rotate --all` | Interactive mass rotation walkthrough — prompts for each credential, skip with Enter. |

### vault remove \<tool\>

Remove a credential.

```bash
openclaw vault remove <tool>
openclaw vault remove <tool> --purge
```

- Without `--purge`: Removes the `.enc` file and clears injection rules, but **keeps scrub patterns active** (recommended — continues protecting against that credential format in output)
- With `--purge`: Fully removes the tool entry from `tools.yaml`

### vault audit

Run a security audit of the vault.

```bash
openclaw vault audit
```

Checks:
- Vault directory permissions (should be 700)
- Credential file permissions (should be 600)
- Missing `.enc` files for configured tools
- Missing scrub patterns
- Rotation age (warns if >90 days since last rotation)
- Vault metadata presence

### vault logs

View the audit log.

```bash
openclaw vault logs [options]
```

| Flag | Description |
|------|-------------|
| `--tool <name>` | Filter by tool name |
| `--type <type>` | Filter by event type (`credential_access`, `scrub`, `compaction`) |
| `--last <duration>` | Time filter: `24h`, `7d`, `30m`, etc. |
| `--json` | Raw JSONL output |
| `--stats` | Aggregate statistics: access frequency, scrub counts, by-tool breakdown |

---

## Configuration Schema

### tools.yaml

```yaml
version: 1
masterKeyMode: machine           # "machine" or "passphrase"
resolverMode: inline             # "inline" or "binary"
resolverPath: /usr/local/bin/... # optional custom resolver binary path
tools:
  github:
    name: github
    addedAt: "2026-03-08T00:00:00.000Z"
    lastRotated: "2026-03-08T00:00:00.000Z"
    inject:
      - tool: exec
        commandMatch: "gh *|git *|curl*api.github.com*"
        env:
          GH_TOKEN: "$vault:github"
          GITHUB_TOKEN: "$vault:github"
    scrub:
      patterns:
        - "ghp_[a-zA-Z0-9]{36}"
        - "github_pat_[a-zA-Z0-9_]{82}"
    rotation:
      label: "GitHub Personal Access Token"
      rotationIntervalDays: 90
      rotationSupport: manual
      scopes:
        - repo
        - workflow
      rotationProcedure: "GitHub Settings → Developer settings → revoke old → generate new"
      revokeUrl: "https://github.com/settings/tokens"
```

### .vault-meta.json

```json
{
  "createdAt": "2026-03-08T00:00:00.000Z",
  "installTimestamp": "2026-03-08T00:00:00.000Z",
  "masterKeyMode": "machine"
}
```

### InjectionRule Schema

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `tool` | string | Yes | Tool to match: `exec`, `web_fetch`, `browser` |
| `commandMatch` | string | No | Glob pattern for exec commands |
| `urlMatch` | string | No | Glob pattern for web_fetch/browser URLs |
| `env` | Record<string, string> | No | Env vars to inject (values contain `$vault:name`) |
| `headers` | Record<string, string> | No | HTTP headers to inject |
| `type` | string | No | `browser-password` or `browser-cookie` |
| `domainPin` | string[] | No | Domain pins for browser credentials |
| `method` | string | No | `fill` or `cookie-jar` |

### ToolConfig Schema

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | Yes | Tool identifier (alphanumeric, hyphens, underscores, dots; max 64 chars) |
| `addedAt` | string | Yes | ISO timestamp of when the credential was first added |
| `lastRotated` | string | Yes | ISO timestamp of last rotation |
| `inject` | InjectionRule[] | Yes | Array of injection rules |
| `scrub` | ScrubConfig | Yes | Scrub configuration with regex patterns array |
| `rotation` | RotationMetadata | No | Extended rotation metadata |

### RotationMetadata Schema

| Field | Type | Description |
|-------|------|-------------|
| `label` | string | Human-readable label |
| `rotationIntervalDays` | number | Days between expected rotations (default: 90) |
| `rotationSupport` | string | `manual`, `cli`, or `api` |
| `scopes` | string[] | Credential scopes/permissions |
| `rotationProcedure` | string | Human-readable rotation instructions |
| `revokeUrl` | string | URL to revoke the old credential |

---

## Known Tools Registry

The plugin ships with built-in detection and configuration for these services:

| Service | Prefix | Detection Confidence | Injection Type |
|---------|--------|---------------------|----------------|
| Stripe | `sk_live_`, `sk_test_`, `rk_live_` | High | exec-env + http-header |
| GitHub | `ghp_`, `github_pat_` | High | exec-env |
| Gumroad | `gum_` | High | exec-env + http-header |
| Anthropic | `sk-ant-` | High | exec-env + http-header |
| OpenAI | `sk-` (not `sk-ant-`) | High | exec-env + http-header |
| Amazon | — | Manual | browser-password + browser-cookie |
| Netflix | — | Manual | browser-password |

For credentials with unknown prefixes, the guesser applies heuristics:
- Three dot-separated base64 segments → JWT (medium confidence)
- JSON blob → session cookies or OAuth token (medium confidence)
- Short string (<32 chars) → password (medium confidence)
- Long random alphanumeric (≥32 chars) → generic API key (low confidence)

---

## Agent Tool: vault_status

An optional agent-facing tool that lets the AI query vault health without accessing credential values:

```
vault_status → {
  totalCredentials: 4,
  overdueCount: 1,
  credentials: [
    { name: "github", isOverdue: false, lastRotated: "2026-03-08T..." },
    { name: "stripe", isOverdue: true, daysOverdue: 15, ... }
  ]
}
```

Registered via `api.registerTool()` with `optional: true`. The agent can check rotation health and last access times without ever seeing credential values.

---

## Audit Logging

### Event Types

**Credential access:** Logged in `after_tool_call` for every successful injection.
```json
{
  "type": "credential_access",
  "timestamp": "2026-03-09T18:30:00Z",
  "tool": "exec",
  "credential": "github",
  "injectionType": "exec-env",
  "command": "gh pr list --repo openclaw/openclaw",
  "durationMs": 1200,
  "success": true
}
```

**Scrubbing event:** Logged when a scrubber fires and replaces content.
```json
{
  "type": "scrub",
  "timestamp": "2026-03-09T18:30:01Z",
  "hook": "after_tool_call",
  "credential": "github",
  "pattern": "ghp_[a-zA-Z0-9]{36}",
  "replacements": 1
}
```

**Compaction event:** Logged when session compaction occurs.
```json
{
  "type": "compaction",
  "timestamp": "2026-03-09T19:00:00Z",
  "scrubbingActive": true
}
```

### Storage

- **Location:** `~/.openclaw/vault/audit.log` (JSONL, one event per line)
- **Permissions:** 0600 (inline mode) or owned by `openclaw-vault` (binary mode)
- **Rotation:** Automatic at 5MB — current log rotated to `audit.log.1`, fresh log started

---

## Hot-Reload

When any `vault` CLI command modifies config:

1. `tools.yaml` is written atomically (tmp + rename)
2. SIGUSR2 is sent to the gateway process (via PID file at `~/.openclaw/gateway.pid`)
3. The plugin's signal handler re-reads config and recompiles scrub rules
4. Credential cache is preserved if the passphrase hasn't changed
5. No gateway restart needed

---

## Platform Support

| Platform | Inline Mode | Binary Mode (Rust Resolver) |
|----------|------------|---------------------------|
| Linux x64 | ✅ | ✅ |
| Linux arm64 | ✅ | Resolver binary not yet cross-compiled |
| macOS | ✅ | setuid model not applicable (use inline) |

---

## Known Limitations

1. **Machine-key derivation material is low-entropy.** The passphrase is derived from hostname, UID, and install timestamp — values an attacker with shell access could guess. Binary mode with OS-user separation is the primary defense; encryption is defense-in-depth.

2. **Scrubbing is best-effort.** Credentials in unusual encodings (base64-wrapped, URL-encoded, split across lines) may not be caught by regex patterns. Literal matching covers exact values but not transforms.

3. **No passphrase mode CLI.** Passphrase-based encryption is implemented in both TypeScript and Rust but not exposed in the CLI. Machine mode is the only user-facing option.

4. **Browser credential support is experimental.** Cookie injection and password filling work in tests but haven't been exercised through the full gateway pipeline in production.

5. **Single-user system vault.** The `vault-setup.sh` script migrates credentials to a shared `/var/lib/openclaw-vault/` directory. Multiple OS users running setup would overwrite each other's credentials.

6. **Plugin install requires gateway restart.** SIGUSR2 handles config changes, but installing or updating the plugin code requires a full gateway restart (`openclaw doctor fix`).

7. **Concurrent access is safe but untested at scale.** The credential cache uses a synchronous `Map` — Node.js single-threaded model prevents races. No stress testing has been done beyond 5 concurrent resolutions.

---

## Future Work

- **Passphrase mode CLI** — expose `OPENCLAW_VAULT_PASSPHRASE` mode for environments where machine-key derivation is insufficient
- **Assisted cookie capture** — open browser, user logs in, cookies auto-captured (requires display)
- **Gateway log scanning** — periodic scan for credentials that leaked into gateway logs
- **CI pipeline** — GitHub Actions for automated testing on push
- **Cross-platform resolver builds** — arm64, macOS (inline-only fallback for non-Linux)
- **SecretBackend interface** — abstract credential storage for future macOS Keychain / Windows Credential Manager support
