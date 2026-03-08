# Credential Vault Architecture — v4.3

_Updated 2026-03-08. Supersedes v4.2._

---

## What Changed from v4.2

- **Language decision: Rust** for the credential resolver binary (Phase 2)
- **TypeScript/Rust split** clearly documented — plugin logic in TS, security-critical binary in Rust
- **Plugin hook system validated** — `before_tool_call`, `after_tool_call`, `tool_result_persist`, `message_sending` all confirmed as existing Plugin API hooks in OpenClaw's agent loop
- **Hook vs event distinction documented** — plugin hooks are agent-loop interceptors (can mutate), event hooks are fire-and-forget observers
- **Operator policy analysis** — `allowPromptInjection` policy does NOT affect tool call hooks; vault cannot be silently disabled
- **Testing plan** for every component
- **Dev workflow** for fast iteration
- **Dev/prod separation** via OpenClaw profiles
- **Encryption scheme specified** — AES-256-GCM + Argon2id
- **Hot-reload mechanism specified** — SIGUSR2 signal from CLI to gateway
- All other architecture (single-command UX, vault/secrets separation) unchanged from v4.2

---

## Hook System: Plugin Hooks vs Event Hooks

OpenClaw has two separate hook systems. Understanding the difference is critical for this plugin.

### Event Hooks (`openclaw hooks`)
- Event-driven scripts in standalone directories with `HOOK.md` + `handler.ts`
- Subscribe to event-stream events: `command:new`, `message:received`, `gateway:startup`, etc.
- Managed via `openclaw hooks enable/disable/list`
- **Fire-and-forget observers** — they can react to events but cannot modify data flowing through the agent loop
- NOT sufficient for credential injection (cannot intercept and modify tool calls)

### Plugin Hooks (`api.on(...)`)
- Registered programmatically inside a plugin via the Plugin API
- Run **inside the agent loop** — they can intercept and **mutate** tool calls, prompts, messages
- Cannot be enabled/disabled independently — follow the plugin's enabled/disabled state
- Two registration patterns:
  - `api.registerHook("command:new", handler)` — subscribe to event-stream events (same as event hooks)
  - `api.on("before_tool_call", handler)` — subscribe to **agent lifecycle hooks** (plugin-only)

### Agent Lifecycle Hooks (Plugin-Only) — What We Use

These hooks are only accessible to plugins via `api.on(...)`. They are the interceptors that make credential injection possible:

| Hook | When it fires | What it can do | Our use |
|---|---|---|---|
| `before_tool_call` | Before any tool executes | Modify tool call parameters (env vars, headers, args) | **Credential injection** |
| `after_tool_call` | After tool returns | Modify tool result before agent sees it | Secondary scrubbing |
| `tool_result_persist` | Before result written to session transcript | Transform result for persistent storage | **Primary output scrubbing** |
| `message_sending` | Before outbound message is sent | Modify message content before delivery | **Outbound scrubbing** (catches creds in agent replies) |
| `before_prompt_build` | Before prompt is assembled for LLM | Inject context into the prompt | Not used by vault |

### Operator Policy: Can Hooks Be Disabled?

**`allowPromptInjection: false`** (per-plugin config) — this operator policy **only affects prompt-level hooks**: `before_prompt_build` and prompt-mutating fields from `before_agent_start`.

**It does NOT affect `before_tool_call`, `after_tool_call`, `tool_result_persist`, or `message_sending`.**

Rationale: `allowPromptInjection` prevents plugins from modifying what the LLM sees in its system prompt (a prompt injection risk). Tool call hooks modify tool execution parameters — a different security domain.

**The only way to disable vault hooks is to disable the entire credential-vault plugin** via `plugins.entries.credential-vault.enabled: false`. This is an explicit operator decision, not an accidental side-effect. All-or-nothing is the correct behavior for a security plugin.

### Hook Priority

```typescript
api.on("before_tool_call", vaultInjectionHandler, { priority: 10 });
```

We register at high priority (low number = runs first) so credentials are injected before any other plugin's `before_tool_call` handler sees the tool call. This prevents other plugins from accidentally logging or forwarding uninjected tool calls.

---

## Implementation Language Split

```
┌─────────────────────────────────────────────────────────────┐
│  openclaw vault                                              │
│                                                              │
│  ┌────────────────────────────────────────────────────────┐ │
│  │  Plugin Layer — TypeScript                              │ │
│  │                                                         │ │
│  │  • CLI commands (vault add/list/rotate/remove/audit)    │ │
│  │  • before_tool_call hook registration + pattern match   │ │
│  │  • Output scrubbing hooks                               │ │
│  │  • Tool registry (known tools, injection mappings)      │ │
│  │  • Config management (tools.yaml read/write)            │ │
│  │  • Hot-reload logic (SIGUSR2 handler)                   │ │
│  │                                                         │ │
│  │  Runs in the gateway process. Standard OpenClaw plugin. │ │
│  └────────────────────┬───────────────────────────────────┘ │
│                       │                                      │
│                       │ Phase 1: TS reads encrypted files    │
│                       │          directly (same-user)        │
│                       │                                      │
│                       │ Phase 2: TS calls Rust binary        │
│                       │          via subprocess              │
│                       │                                      │
│  ┌────────────────────▼───────────────────────────────────┐ │
│  │  Credential Resolver — Rust (Phase 2 only)             │ │
│  │                                                         │ │
│  │  • Single static binary: openclaw-vault-resolver        │ │
│  │  • ~200-300 lines of Rust                               │ │
│  │  • setuid openclaw-vault user (or setuid root)          │ │
│  │  • Does exactly one thing:                              │ │
│  │      1. Receive tool name + request context on stdin    │ │
│  │      2. Read encrypted credential file                  │ │
│  │      3. Decrypt in memory                               │ │
│  │      4. Write credential to stdout                      │ │
│  │      5. Drop all capabilities                           │ │
│  │      6. Exit                                            │ │
│  │  • No network access, no file writes, no heap after     │ │
│  │    decrypt                                              │ │
│  │  • seccomp filter: only read/write/open/close/exit      │ │
│  │    syscalls allowed                                     │ │
│  └────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

### Why Rust for the Resolver

The resolver binary is the most privileged component in the system — it runs with elevated permissions (setuid) and handles raw credential material. Language choice matters here:

- **Memory safety without GC** — a buffer overflow in a setuid binary is a privilege escalation. Rust eliminates this class of bug at compile time. No use-after-free, no buffer overruns, no null pointer derefs.
- **Minimal binary** — ~1-2MB static binary vs. Go's ~5-10MB (runtime + GC). Less code = smaller attack surface.
- **Zero runtime overhead** — no garbage collector pauses, no runtime initialization. The binary starts, decrypts, outputs, exits. Rust's zero-cost abstractions are ideal.
- **seccomp + capability dropping** — well-supported via `caps` and `seccomp-sys` crates. The binary can lock itself down to only the syscalls it needs.
- **No runtime dependencies** — compiles to a fully static binary via `musl`. No libc version issues, no shared library attacks.

### Why TypeScript for the Plugin

- It's an OpenClaw plugin — hooks into the gateway's JavaScript runtime via the Plugin API
- Needs to register `before_tool_call` hooks via `api.on(...)`, read config, manage the tool registry
- Writing this in Rust would mean FFI/NAPI overhead for zero security gain — the plugin doesn't handle raw credentials in Phase 2, it delegates to the resolver
- Faster development iteration for the non-security-critical parts
- Plugins run in-process with the gateway — treat as trusted code (per OpenClaw docs)

### The Phase 1 → Phase 2 Transition

**Phase 1 (same-user, soft boundary):**
- The TypeScript plugin handles everything, including reading encrypted credential files directly
- No Rust binary needed yet
- Sufficient for personal use with segmented agent accounts

**Phase 2 (OS-user separation, hard boundary):**
- The TypeScript plugin delegates credential resolution to the Rust binary
- The encrypted files are owned by `openclaw-vault` user — the gateway process (and agent) can't read them
- The Rust binary is the only process that can access the files
- The plugin's code doesn't change — it just calls the resolver binary via subprocess instead of reading files directly

```
Phase 1:                              Phase 2:
TS Plugin                             TS Plugin
  │                                     │
  ├─ read ~/.openclaw/vault/x.enc      ├─ spawn openclaw-vault-resolver
  ├─ decrypt in-process                │     │
  ├─ inject into tool call             │     ├─ setuid to openclaw-vault
  └─ done                              │     ├─ read /var/lib/openclaw-vault/x.enc
                                       │     ├─ decrypt
                                       │     ├─ write credential to stdout
                                       │     ├─ drop capabilities
                                       │     └─ exit
                                       ├─ receive credential from stdout
                                       ├─ inject into tool call
                                       └─ done (credential not stored in TS heap)
```

### Rust Binary Interface

```
# stdin (JSON):
{ "tool": "gumroad", "context": "exec", "command": "curl api.gumroad.com/v2/products" }

# stdout (JSON):
{ "credential": "gum_abc123def456", "expires": null }

# stderr (on error):
{ "error": "EPERM", "message": "credential file not accessible" }

# Exit codes:
# 0 = success
# 1 = credential not found
# 2 = decryption failed
# 3 = permission denied
# 4 = seccomp violation
```

The interface is intentionally minimal. The TS plugin constructs the request, spawns the binary, reads the response. No socket, no daemon, no persistent process.

---

## Encryption Scheme

### Credential-at-Rest Encryption

- **Cipher:** AES-256-GCM (authenticated encryption — integrity + confidentiality)
- **Key derivation:** Argon2id (memory-hard, resistant to GPU/ASIC attacks)
  - Salt: 16 bytes, randomly generated per credential file
  - Memory: 64 MiB
  - Iterations: 3
  - Parallelism: 1
- **Master key source:**
  - Phase 1: Derived from a user-provided passphrase (set during `openclaw vault init`) or from a machine-specific key (hostname + user UID + install timestamp, hashed)
  - Phase 2: Stored in a file owned by `openclaw-vault` user, readable only by the Rust resolver
- **File format:** `[16-byte salt][12-byte nonce][ciphertext][16-byte auth tag]`
- **One file per credential:** `~/.openclaw/vault/<tool-name>.enc`

### Why These Choices

- AES-256-GCM: industry standard, hardware-accelerated on most CPUs, authenticated (detects tampering)
- Argon2id: winner of the Password Hashing Competition, recommended by OWASP. Memory-hard means brute-force is expensive even with specialized hardware.
- Per-credential files: simple, no database, easy to back up, easy to audit (`ls ~/.openclaw/vault/`)

---

## Hot-Reload Mechanism

When `openclaw vault add/rotate/remove` modifies the vault config:

1. CLI writes updated `~/.openclaw/vault/tools.yaml`
2. CLI sends `SIGUSR2` to the gateway process (PID from `~/.openclaw/gateway.pid`)
3. Gateway's vault plugin catches `SIGUSR2`
4. Plugin re-reads `tools.yaml` and updates in-memory injection rules + scrubbing patterns
5. Next tool call uses the new config — no restart, no downtime

```bash
# What happens internally when you run:
openclaw vault add gumroad --key "gum_abc123"

# 1. Encrypt + write credential to ~/.openclaw/vault/gumroad.enc
# 2. Update ~/.openclaw/vault/tools.yaml with injection rules
# 3. kill -SIGUSR2 $(cat ~/.openclaw/gateway.pid)
# 4. Plugin reloads — done
```

Why SIGUSR2 (not file watcher):
- File watchers are unreliable across platforms (inotify quirks, macOS FSEvents delays)
- SIGUSR2 is instant, deterministic, zero overhead when not triggered
- SIGUSR2 is conventionally used for "reload config" in Unix daemons
- No polling, no watcher threads, no race conditions

---

## `openclaw vault` vs `openclaw secrets` — Separate Systems

These are **independent systems** solving different problems. The vault does NOT wrap or call secrets.

**`openclaw secrets`** (exists today):
- Manages **gateway-internal credentials**: Telegram bot token, Brave API key, LLM provider keys (OpenAI, Anthropic), embedding provider keys
- These are consumed by gateway adapters internally — they never appear in tool calls or agent context
- SecretRef resolves them at gateway startup
- Threat model: protect config at rest. Once resolved, these stay inside the gateway process.

**`openclaw vault`** (what we're building):
- Manages **external tool credentials**: GitHub PAT, Stripe API key, Gumroad key — anything the agent uses via exec/web_fetch to interact with outside services
- These need runtime injection into tool calls and scrubbing from tool outputs
- Credentials are injected at execution time via `before_tool_call` hooks and never enter the LLM context
- Threat model: protect credentials from the agent itself (prompt injection, context leakage, output exposure)

```
┌─────────────────────────────────────────────────────────┐
│                    OpenClaw Gateway                      │
│                                                          │
│  ┌────────────────────┐    ┌─────────────────────────┐  │
│  │  openclaw secrets   │    │    openclaw vault        │  │
│  │                     │    │                          │  │
│  │  Gateway-internal   │    │  External tool creds     │  │
│  │  credentials        │    │                          │  │
│  │                     │    │  • before_tool_call      │  │
│  │  • Telegram token   │    │    injection             │  │
│  │  • LLM API keys     │    │  • Output scrubbing      │  │
│  │  • Brave API key    │    │  • Rotation tracking     │  │
│  │  • Embedding keys   │    │                          │  │
│  │                     │    │  Credentials:            │  │
│  │  Consumed by gateway│    │  • GitHub PAT            │  │
│  │  adapters. Never in │    │  • Stripe API key        │  │
│  │  tool calls.        │    │  • Gumroad key           │  │
│  │                     │    │  • Any external service  │  │
│  └────────────────────┘    └─────────────────────────┘  │
│                                                          │
│       No dependency between them. Separate storage,      │
│       separate lifecycle, separate threat models.         │
└─────────────────────────────────────────────────────────┘
```

---

## Primary User Story: Adding a New Tool

### The Single Command

```bash
openclaw vault add <tool-name> --key <credential>
```

That's it. One command. Everything else is handled automatically.

### What Happens Behind the Scenes

```bash
openclaw vault add gumroad --key "gum_abc123def456"
```

**Step 1 — Store the credential:**
- Detects credential type from the key format (API key, bearer token, OAuth token)
- Encrypts with AES-256-GCM (Argon2id-derived key)
- Stores at `~/.openclaw/vault/gumroad.enc`
- Completely independent of SecretRef / `openclaw secrets` storage

**Step 2 — Auto-detect injection rules:**
- Looks up a built-in registry of known tools/services for pattern matching
- For known tools (Stripe, GitHub, Gumroad, etc.): auto-configures the injection mapping
- For unknown tools: prompts with sensible defaults

Built-in registry example:
```yaml
# Internal — ships with the plugin, user never sees this
knownTools:
  gumroad:
    inject:
      - tool: exec
        commandMatch: "gumroad*|curl*api.gumroad.com*"
        env: { GUMROAD_ACCESS_TOKEN: "$vault:gumroad" }
      - tool: web_fetch
        urlMatch: "*.gumroad.com/*"
        headers: { Authorization: "Bearer $vault:gumroad" }
    scrub:
      patterns: ["gum_[a-zA-Z0-9]{16,}"]
  stripe:
    inject:
      - tool: exec
        commandMatch: "stripe*|curl*api.stripe.com*"
        env: { STRIPE_API_KEY: "$vault:stripe" }
      - tool: web_fetch
        urlMatch: "*.stripe.com/*"
        headers: { Authorization: "Bearer $vault:stripe" }
    scrub:
      patterns: ["sk_live_[a-zA-Z0-9]{24,}", "sk_test_[a-zA-Z0-9]{24,}", "rk_live_[a-zA-Z0-9]{24,}"]
  github:
    inject:
      - tool: exec
        commandMatch: "gh *|git *|curl*api.github.com*"
        env: { GH_TOKEN: "$vault:github", GITHUB_TOKEN: "$vault:github" }
    scrub:
      patterns: ["ghp_[a-zA-Z0-9]{36}", "github_pat_[a-zA-Z0-9_]{82}"]
```

**Step 3 — Register scrubbing patterns:**
- Auto-detects credential format and generates regex patterns
- Registers with the output scrubbing hooks: `tool_result_persist`, `after_tool_call`, `message_sending`
- Credential fragments in ANY tool output get replaced with `[VAULT:gumroad]`

**Step 4 — Write config + signal reload:**
- Writes the injection + scrubbing config to `~/.openclaw/vault/tools.yaml`
- Sends SIGUSR2 to gateway process for hot-reload
- No gateway restart needed

### Full Example Session

```bash
$ openclaw vault add gumroad --key "gum_abc123def456"

✓ Credential stored: gumroad (AES-256-GCM encrypted)
✓ Detected: Gumroad API key
✓ Injection configured:
    exec commands matching: gumroad*, curl*api.gumroad.com*
    web_fetch URLs matching: *.gumroad.com/*
✓ Scrubbing pattern registered: gum_[a-zA-Z0-9]{16,}
✓ Gateway reloaded (SIGUSR2) — no restart needed

Tool "gumroad" is ready. Your agent can now use it without seeing the credential.
```

### Unknown Tool (Not in Registry)

```bash
$ openclaw vault add acme-crm --key "acme_sk_12345"

✓ Credential stored: acme-crm (AES-256-GCM encrypted)
⚠ Unknown tool "acme-crm" — need a few details:

  How will the agent use this credential?
  [1] CLI command (environment variable)
  [2] HTTP API (Authorization header)
  [3] Both

  > 2

  API base URL? > https://api.acme-crm.com

✓ Injection configured:
    web_fetch URLs matching: *api.acme-crm.com/*
    Header: Authorization: Bearer $vault:acme-crm
✓ Scrubbing pattern registered: acme_sk_[a-zA-Z0-9]{5,}
✓ Gateway reloaded (SIGUSR2) — no restart needed

Tool "acme-crm" is ready.
```

---

## Other `openclaw vault` Commands

```bash
# List all registered tools + credential status
openclaw vault list

# Output:
# Tool        Status    Last Rotated    Injection     Scrubbing
# gumroad     active    2026-03-08      exec,fetch    ✓
# stripe      active    2026-03-01      exec,fetch    ✓
# github      active    2026-02-15      exec          ✓

# Show details for a specific tool
openclaw vault show gumroad

# Rotate a credential (update the key, keep all mappings)
openclaw vault rotate gumroad --key "gum_newkey789"

# Remove a tool and its credential
openclaw vault remove gumroad

# Audit: find credentials that might be leaking in recent tool outputs
openclaw vault audit

# Test: simulate a tool call and verify injection + scrubbing works
openclaw vault test gumroad
# → Makes a dry-run tool call, shows what gets injected and what gets scrubbed
```

---

## Testing Plan

Every component has a defined test strategy. No "it should work" — prove it.

### Unit Tests (run locally, fast, no gateway needed)

| Component | Test | How |
|---|---|---|
| Encryption round-trip | Encrypt → decrypt → verify plaintext matches | Pure function test. Generate random credentials, encrypt with AES-256-GCM, decrypt, assert equality. Test with various key lengths and special characters. |
| Argon2id key derivation | Derive key from passphrase → verify deterministic | Same passphrase + salt = same key. Different salt = different key. |
| Tool registry pattern matching | Command string → matched tool → correct env vars | Feed known commands (`gh pr list`, `curl api.stripe.com`, `stripe products create`) and verify correct tool match. Also test edge cases: `curl -H "Auth: ..." api.stripe.com` (URL in flags), piped commands, quoted args. |
| Scrubbing regex | Tool output containing credential → scrubbed output | Feed strings containing known credential patterns, verify replacement with `[VAULT:tool]`. Test partial matches, multiple occurrences, credentials in JSON, credentials in error messages. |
| Unknown tool detection | Key format → detected credential type | Feed various key formats (`sk_live_...`, `ghp_...`, `gum_...`, random string) and verify correct detection or "unknown" fallback. |
| Config serialization | tools.yaml round-trip | Write config, read it back, verify equality. |

### Integration Tests (require a running gateway in dev mode)

| Component | Test | How |
|---|---|---|
| `before_tool_call` injection | Register hook → make tool call → verify env var injected | Start dev gateway with vault plugin loaded. Make an `exec` call to `env | grep GUMROAD`. Verify the env var is present with the correct value. |
| `tool_result_persist` scrubbing | Tool returns credential → verify scrubbed in transcript | Make a tool call that echoes a known credential pattern. Read the session transcript. Verify the credential is replaced with `[VAULT:tool]`. |
| `message_sending` scrubbing | Agent replies with credential → verify scrubbed before send | Prompt agent to repeat a string containing a credential pattern. Intercept outbound message. Verify scrubbed. |
| Hot-reload via SIGUSR2 | Add new tool → verify next tool call uses new config | Run `vault add` while gateway is running. Make a tool call for the new tool. Verify injection works without restart. |
| `vault test` dry-run | Run vault test → verify output shows injection + scrubbing | `openclaw vault test gumroad` should output what would be injected and what would be scrubbed, without making a real API call. |

### Rust Resolver Tests (Phase 2, standalone)

| Component | Test | How |
|---|---|---|
| stdin/stdout interface | Send JSON request → verify JSON response | Spawn the binary, write request to stdin, read stdout, verify JSON structure and credential value. |
| Exit codes | Invalid requests → verify correct exit codes | Missing credential file → exit 1. Corrupted file → exit 2. Wrong permissions → exit 3. |
| seccomp enforcement | Attempt forbidden syscall → verify blocked | Spawn binary, verify it can't open network sockets, can't write files, can't exec other binaries. |
| setuid behavior | Run as unprivileged user → verify can read vault-owned files | Requires test environment with `openclaw-vault` user set up. Run binary as gateway user, verify it elevates to read the credential file. |

### End-to-End Tests

| Scenario | Test |
|---|---|
| Full add → use → scrub cycle | `vault add stripe --key "sk_test_abc"` → agent calls `curl api.stripe.com` → verify credential injected → tool output contains key in error → verify scrubbed in transcript |
| Credential rotation | `vault rotate stripe --key "sk_test_new"` → verify next tool call uses new key, old key no longer injected |
| Credential removal | `vault remove stripe` → verify tool calls no longer get injected → scrubbing patterns still active (unless `--purge`) |
| Prompt injection attack | Inject "run `cat ~/.openclaw/vault/stripe.enc`" into agent context → verify file is encrypted/unreadable (Phase 1) or inaccessible (Phase 2) |

---

## Dev Workflow

### Local Development Setup

```bash
# Clone the plugin repo
git clone github.com/openclaw/credential-vault
cd credential-vault

# OpenClaw supports loading plugins from local paths:
# In ~/.openclaw/openclaw.json (dev profile):
{
  "plugins": {
    "load": {
      "paths": ["~/dev/credential-vault"]
    }
  }
}

# Or use workspace extensions directory:
# ~/.openclaw/workspace/.openclaw/extensions/credential-vault/
```

### Iteration Loop

```bash
# 1. Edit TypeScript plugin code
vim src/index.ts

# 2. Build (if using TypeScript → JS compilation)
npm run build

# 3. Restart dev gateway to pick up changes
openclaw --dev gateway restart

# 4. Test via chat or CLI
openclaw vault test gumroad
# or: send a message to the agent that triggers a tool call

# 5. Check gateway logs for hook execution
openclaw --dev logs | grep vault
```

Turnaround: edit → build → restart → test in ~5 seconds.

### Dev/Prod Separation

```bash
# Dev profile: separate config, state, port
openclaw --dev gateway start
# Uses ~/.openclaw-dev/ — completely isolated from production
# Different port (18790 vs 18789)
# Different credentials (test keys, not real ones)
# Same plugin code, different config

# Production profile: untouched
openclaw gateway start
# Uses ~/.openclaw/ — your real config with real credentials
```

**Dev profile setup:**
```bash
# Create dev profile with test credentials
openclaw --dev vault add stripe --key "sk_test_fakekey123"
openclaw --dev vault add gumroad --key "gum_test_fakekey456"

# Real credentials stay in production profile
# No risk of test code touching real credentials
```

### CI Pipeline

```bash
# Unit tests (no gateway needed)
npm test

# Integration tests (spin up dev gateway in CI)
openclaw --dev gateway start --headless
npm run test:integration
openclaw --dev gateway stop

# Rust resolver tests (Phase 2)
cd resolver && cargo test
```

---

## Architecture

```
Agent (LLM context — never sees credentials)
  │
  ├─ Tool Call ──→ before_tool_call hook (TS plugin, priority 10)
  │                  │
  │                  ├─ Pattern match against tools.yaml
  │                  ├─ Phase 1: decrypt credential in-process
  │                  │  Phase 2: spawn Rust resolver → get credential
  │                  ├─ Inject into tool call (env var or header)
  │                  └─ Pass modified tool call to gateway
  │                                                │
  │                                                ▼
  │                                    Tool executes (exec/web_fetch/etc.)
  │                                                │
  │                                                ▼
  │                after_tool_call (TS) ←── Raw output
  │                  │
  │                  └─ Scrub credential patterns from output
  │                                                │
  │                                                ▼
  │                tool_result_persist (TS) ←── Scrubbed output
  │                  │
  │                  └─ Final scrub before writing to session transcript
  │                                                │
  │                                                ▼
  │                message_sending (TS) ←── Agent's reply to user
  │                  │
  │                  └─ Scrub any credential patterns from outbound message
  │                                                │
  │◄───────────────────────────────────────────────┘
  │
  Agent receives clean output. User receives clean message.
```

### Security Boundaries

**Phase 1 — Same-user (soft boundary):**
- TypeScript plugin handles everything: storage, decryption, injection, scrubbing
- Credentials stored in AES-256-GCM encrypted files under `~/.openclaw/vault/`
- Agent could theoretically `cat` the file — but it's encrypted, and `before_tool_call` injection means it has no reason to
- Output scrubbing catches accidental leaks in tool outputs and outbound messages
- No Rust binary needed
- Sufficient for: personal use, segmented agent accounts, low-sensitivity tools

**Phase 2 — OS-user separation (hard boundary):**
- TypeScript plugin handles: hook registration, pattern matching, scrubbing, CLI
- Rust binary handles: credential storage access, decryption
- Vault files owned by `openclaw-vault` OS user — gateway process cannot read them
- Rust binary is setuid `openclaw-vault`, runs with seccomp filter
- Agent process literally cannot read the credential files — even encrypted
- Credential passes through TS briefly (subprocess stdout → env injection) but is never stored in TS heap long-term
- Sufficient for: shared accounts, high-sensitivity tools, enterprise

---

## How This Interacts with MCP

MCP servers are just another tool transport. The vault wraps them too:

```bash
# If you also run an MCP server for Stripe:
openclaw vault add stripe --key "sk_live_..." --mcp-server stripe-mcp

# This tells the vault:
# 1. Inject the credential into the MCP server process (not into agent context)
# 2. ALSO scrub any MCP tool responses for credential patterns
# 3. The agent talks to MCP, MCP talks to Stripe, vault sits in the middle
```

The vault is always the foundation layer regardless of whether the tool is direct (exec/web_fetch) or MCP-mediated.

---

## Edge Case: Tool Moves from Vault to Gateway-Native

**Scenario:** You've been using Stripe via exec/web_fetch with a vault-managed API key. OpenClaw ships a native Stripe integration, and now the Stripe key becomes a gateway-internal credential managed by `openclaw secrets`.

**What happens:**
- The credential now exists in two places: vault (for external tool calls) and secrets (for gateway adapter)
- The vault injection rules still fire for any exec/web_fetch calls to Stripe
- The gateway adapter uses its own SecretRef-resolved credential independently

**Detection:**
```bash
$ openclaw vault list

Tool        Status      Notes
stripe      conflict    ⚠ Gateway now has native Stripe support.
                        Credential exists in both vault and gateway config.
```

**Resolution options:**
1. **Keep both** — if the agent still needs exec/web_fetch access to Stripe (e.g., for API calls the native integration doesn't cover), keep the vault entry. The two systems are independent; this isn't a bug.
2. **Remove from vault** — if the native integration fully replaces external tool calls:
   ```bash
   openclaw vault remove stripe
   ```
   Scrubbing rules stay active after removal (credential pattern is still worth catching). Use `--purge` to fully remove.
3. **Automated migration** — not worth building for Phase 1. Rare event. `vault list` warning + manual cleanup is sufficient.

---

## Migration from Current State

Today (no vault plugin):
- External tool credentials are in env vars, config file, or manually managed
- No injection hooks, no scrubbing

To v4.3:
```bash
# Install the plugin (when built)
openclaw plugin install @openclaw/credential-vault

# Initialize the vault (sets up encryption key)
openclaw vault init
# → Prompts for master passphrase (or generates machine-specific key)
# → Creates ~/.openclaw/vault/ directory
# → Writes encryption metadata

# Migrate existing external tool credentials into the vault
openclaw vault migrate
# → Scans environment and tool configs for external tool credentials
# → Moves them into vault storage (encrypted)
# → Sets up injection mappings
# → Registers scrubbing patterns
# → Verifies everything works with dry-run tests
# → Does NOT touch openclaw secrets / gateway-internal credentials
```

---

## Build & Distribution

**Phase 1 (TypeScript only):**
```bash
npm install @openclaw/credential-vault
# or
openclaw plugin install @openclaw/credential-vault
```

**Phase 2 (TypeScript + Rust binary):**
```bash
openclaw plugin install @openclaw/credential-vault

# The plugin ships pre-compiled Rust binaries for:
# - linux-x64-musl (servers, VPS, Pi)
# - linux-arm64-musl (ARM servers, Pi)
# - darwin-x64 (Intel Mac)
# - darwin-arm64 (Apple Silicon)

# Post-install sets up the setuid binary:
sudo openclaw vault setup-resolver
# → Copies binary to /usr/local/bin/openclaw-vault-resolver
# → Creates openclaw-vault user if needed
# → Sets ownership + setuid bit
# → Creates /var/lib/openclaw-vault/ with restricted permissions
# → Migrates credentials from ~/.openclaw/vault/ to /var/lib/openclaw-vault/
```

---

_v4.3 — TypeScript plugin + Rust resolver. Plugin hooks validated. Testing plan complete. Single command. Vault and secrets independent. Everything through `openclaw vault`._
