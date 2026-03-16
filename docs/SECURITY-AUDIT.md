# Security Audit

> Comprehensive security audit of the OpenClaw Credential Vault plugin.
> Last updated: 2026-03-16 (post vault-add UX overhaul + browser credential support)
> Auditor: Automated security engineering review (agentic)
> Scope: Full source code, injection path, scrubbing pipeline, browser credential flow, CLI add UX, tests, dependencies, Rust resolver
> Branch: fix/vault-add-ux-overhaul (24 commits since main)

---

## Executive Summary

The OpenClaw Credential Vault implements a defense-in-depth architecture for managing AI agent credentials. The codebase demonstrates strong cryptographic foundations (AES-256-GCM + Argon2id), comprehensive 4-hook scrubbing pipeline, and a well-designed browser credential injection system with domain pinning.

**Overall Risk Rating: LOW**

The vault is suitable for its stated purpose (credential management in AI agent frameworks). The UX overhaul and browser credential support introduce no critical vulnerabilities. Key findings:

1. **Tab URL cache poisoning via `content[0].text` JSON parsing** — an attacker-controlled tool result could inject a malicious URL into the cache (MEDIUM)
2. **Debug logging leaks credential metadata to stderr** — `[vault-debug]` lines include cache keys, target IDs, URLs, and cache sizes unconditionally (MEDIUM)
3. **`--yes` flag skips cookie file secure delete** — plaintext cookie files left on disk in non-interactive mode (MEDIUM)
4. **Shell history exposure for `--key` inline credentials** — documented with warnings but no mitigation (LOW, accepted)
5. **Cookie domain filtering is not bidirectional** — cookies with broader domains than the pin could be injected (LOW)
6. **`browserTabUrls` cache has no size limit or TTL** — grows without bound (LOW)

No CRITICAL findings. All previously resolved findings (F-1, F-2, F-8, F-10) remain fixed. Test suite comprehensive at 695 tests across 36 files.

---

## 1. Credential Flow Analysis

### Flow 1: Exec/Web_Fetch Injection (Existing)

```
vault.enc → Argon2id KDF → AES-256-GCM decrypt → credentialCache (15min TTL)
  → params.env (exec) or params.headers (web_fetch)
  → Perl stdout scrubber (base64-encoded replacement)
  → after_tool_call (audit only) → tool_result_persist (scrub) → before_message_write (scrub) → message_sending (scrub)
```

**Finding: No leakage paths identified.** Credentials never touch `process.env`. The Perl scrubber catches stdout/stderr before the gateway captures output. All 4 post-execution hooks scrub independently.

### Flow 2: Browser Password Injection (New)

```
vault.enc → decrypt → credentialCache
  → LLM sends browser action with $vault:name placeholder
  → before_tool_call: extract vaultName from params.text
  → domain pin check against current URL (params.url || params.targetUrl || browserTabUrls cache)
  → if match: replace $vault:name with actual credential in params.text
  → browser tool executes (types credential into field)
  → after_tool_call: cache tab URL from result
  → tool_result_persist + before_message_write + message_sending: scrub credential from any output
```

**Finding: Flow is sound.** The `$vault:` placeholder mechanism means the LLM never sees the actual credential value — it only knows the placeholder. The credential is injected at priority 10 (last) and scrubbed at priority 1 (first).

**Risk: The credential IS passed to the browser tool as plaintext in `params.text`.** If any other plugin hooks `before_tool_call` at priority < 10, it would see the pre-injection placeholder (safe). If a plugin hooks at priority > 10, it would see the injected credential. This is documented behavior and the priority split is tested.

### Flow 3: Browser Cookie Injection (New)

```
vault.enc → decrypt → credentialCache → JSON.parse → PlaywrightCookie[]
  → before_tool_call: on navigate action, check URL against all cookie rule domainPins
  → if match: filter cookies by domain, remove expired → params._vaultCookies
  → browser tool injects via addCookies()
  → Cookies are HTTP-only, not visible in page JS
```

**Finding: Flow is sound.** Cookies are domain-filtered before injection. The `_vaultCookies` param is a private convention between the vault plugin and the browser tool.

### Flow 4: Write/Edit Scrubbing

```
before_tool_call: intercept write/edit tools → scrub content/newText/new_string
  → regex patterns + literal cached credentials
```

**Finding: Complete.** Both array and string content paths are handled.

---

## 2. Browser Credential Security

### 2A. Domain Pin Enforcement

**Implementation** (`src/browser.ts` lines 32-55): Two modes — leading dot for subdomain wildcard (`.amazon.com` matches `amazon.com` and `*.amazon.com`), exact match otherwise.

**Bypass Attempts Reviewed:**
- **IDN homograph**: `new URL()` normalizes punycode, so `аmazon.com` (Cyrillic а) becomes `xn--mazon-wfb.com` — does NOT match `.amazon.com` ✅
- **Port injection**: `evil.com:443@amazon.com` → `URL.hostname` returns `evil.com` ✅
- **Path confusion**: `amazon.com.evil.com` → does NOT match `.amazon.com` because `endsWith(".amazon.com")` fails ✅
- **data:/javascript: URLs**: `extractHostname()` returns null for these (no hostname) → resolution fails → credential blocked ✅
- **Empty URL**: Returns null → "Cannot resolve domain from URL" error → blocked ✅
- **Case sensitivity**: Both hostname and pin are lowercased before comparison ✅

**Verdict: Domain pinning is robust.** No bypass found.

### 2B. Tab URL Cache Poisoning — MEDIUM (F-NEW-1)

**Severity: MEDIUM**
**Location:** `src/index.ts` lines 636-662 (`handleAfterToolCall`)

The `browserTabUrls` cache is populated from two sources:
1. `navigate`/`open` actions in `before_tool_call` (line 482) — uses `params.url`, which is the URL the agent requested → **trusted**
2. `after_tool_call` result parsing (lines 636-662) — parses from `event.result` → **partially trusted**

The `after_tool_call` handler attempts to extract URLs from the tool result:
```typescript
// Also try parsing from content[0].text as fallback
if (!details.url && Array.isArray(res.content)) {
  const firstContent = res.content[0] as Record<string, unknown> | undefined;
  if (firstContent && typeof firstContent.text === "string") {
    try { parsed = JSON.parse(firstContent.text as string); } catch { /* ignore */ }
  }
}
```

**Attack scenario:**
1. A malicious tool result (e.g., from a compromised browser page or injected content) returns JSON in `content[0].text` with `{"url": "https://evil.com", "targetId": "existing-tab-id"}`
2. This overwrites the cached URL for an existing tab
3. On the next `$vault:` password fill, the domain pin checks against `evil.com` — correctly blocks the credential

**Mitigating factor:** Even if the cache is poisoned with a wrong URL, the domain pin check STILL runs. The worst case is:
- A legitimate tab's cached URL is overwritten with a wrong domain → credential injection is incorrectly blocked (denial of service, not credential leak)
- The cache is overwritten with an attacker's domain → the pin check blocks because the attacker's domain doesn't match

**The cache cannot WEAKEN the pin check — it can only provide an alternative URL when `params.url` is absent.** The pin always validates the URL regardless of source.

**Residual risk:** If an attacker can both (a) poison the cache with a domain that matches the pin AND (b) control the page the browser navigates to, they could cause the credential to be typed into a lookalike page. This requires the attacker to control a subdomain of the pinned domain, which is an edge case.

**Recommendation:**
- Only cache URLs from `navigate`/`open` actions (trusted user-initiated navigation), not from result parsing
- Alternatively, validate that `result.url` matches the originally requested `params.url` before caching

### 2C. Cookie Injection Scope — LOW (F-NEW-2)

**Severity: LOW**
**Location:** `src/browser.ts` `filterCookiesByDomain()` (lines 140-154)

The domain filtering checks that the cookie's domain is a match or subdomain of the pin domain. However, the check is unidirectional:

```typescript
return (
  cookieDomain === pinDomain || cookieDomain.endsWith("." + pinDomain)
);
```

This means a cookie with domain `.com` would NOT match a pin of `.amazon.com` (correct). But a cookie with domain `.amazon.com` WOULD match a pin of `.amazon.com` (correct). A cookie with domain `.sub.amazon.com` WOULD also match (correct).

**Finding:** The filtering is correct. Cookies can only be injected to domains that are equal to or subdomains of the pin domain. The browser itself enforces cookie domain scoping independently as a second layer.

**Minor concern:** If the stored cookie JSON contains cookies for unrelated domains (e.g., tracking cookies from a browser export), `filterCookiesByDomain` correctly excludes them. The `filterTrackingCookies` function exists but is not called in the injection path — only available for CLI use during import.

**Recommendation:** Consider calling `filterTrackingCookies` in the injection path as defense-in-depth.

### 2D. Result Parsing in after_tool_call — LOW (F-NEW-3)

**Severity: LOW**
**Location:** `src/index.ts` lines 646-651

Parsing `content[0].text` as JSON has minimal direct risk:
- The parsed data is only used to extract `url` and `targetId` strings
- No code execution or eval occurs
- Failed JSON parsing is silently caught
- The extracted values are only stored in `browserTabUrls` (a `Map<string, string>`)

**Finding:** No injection risk from JSON parsing itself. The risk is cache poisoning (covered in F-NEW-1).

---

## 3. Scrubbing Completeness

### Hook Coverage

| Hook | Location | Priority | Scrubs | Modifies |
|------|----------|----------|--------|----------|
| `after_tool_call` | index.ts:622 | 1 | ❌ (audit only + URL caching) | No |
| `tool_result_persist` | index.ts:546 | 1 | ✅ regex + literal + array content | Returns `{message}` |
| `before_message_write` | index.ts:590 | 1 | ✅ regex + literal + tracking + array content | Returns `{message}` |
| `message_sending` | index.ts:632 | 1 | ✅ regex + literal (string only) | Returns `{content}` |

**Finding: `after_tool_call` does NOT scrub.** This is by design — it's observe-only in the OpenClaw API. The Perl stdout scrubber catches credentials before they reach the result.

### Scrubbing Pipeline (3 layers)

1. **Regex patterns** — compiled from `tools.yaml` + global patterns (Telegram, Slack)
2. **Literal indexOf** — exact credential value match from `literalCredentials` Map
3. **Env-var name** — `KEY=[VAULT:env-redacted] patterns with selective scrubbing (skips already-scrubbed values)

### Potential Scrubbing Gaps

**Browser password in `params.text`**: When a `$vault:` placeholder is resolved to the actual credential, the credential is placed in `params.text` (or `request.text`). After the browser tool executes, the result typically does NOT contain the credential (it was typed into a password field, not echoed). However, if the browser tool returns an error containing the params, the credential would appear in the error message. The `tool_result_persist` hook would catch this via literal scrubbing.

**Browser cookies in `params._vaultCookies`**: Cookie values are placed in a custom params field. The browser tool is expected to inject these via `addCookies()` and not echo them. If the params themselves leak (e.g., via debug logging in the gateway), the cookie values could be exposed. The scrubbing hooks operate on the result/message content, not on the original params.

**Verdict:** Scrubbing is comprehensive for all output paths. The one gap is params-level credential exposure to the browser tool itself, which is an inherent requirement of the injection model.

---

## 4. CLI Add Flow Security

### 4A. `--yes` Flag Behavior — MEDIUM (F-NEW-4)

**Severity: MEDIUM**
**Location:** `src/cli.ts` lines 386-398

When `--yes` is used with a cookie file path:
```typescript
if (options.yes) {
  // --yes skips the delete prompt; warn that plaintext file still exists
  console.log(`  ⚠ Source file still exists at ${cookieSourcePath}`);
}
```

**Finding:** The `--yes` flag skips the secure delete prompt and leaves the plaintext cookie file on disk. The warning is printed to stdout but may be lost in automated/scripted usage.

**Recommendation:**
- In `--yes` mode, default to secure delete (inverse of current behavior — safer default)
- Add `--keep-source` flag for cases where the file should be preserved
- At minimum, write an audit event when `--yes` leaves a plaintext file on disk

### 4B. Cookie File Secure Delete — INFO

**Severity: INFO (Positive Finding)**
**Location:** `src/cli.ts` `secureDeleteFile()` (lines 197-215)

The implementation overwrites with zeros before unlinking. This is effective against casual file recovery but not against:
- Journaling filesystem recovery (ext4 journal may contain original data)
- SSD wear-leveling (original blocks may persist in spare area)
- Copy-on-write filesystems (btrfs, ZFS — original snapshot may exist)

**Recommendation:** Document the limitations. For truly sensitive cookie files, recommend using an encrypted filesystem or tmpfs mount.

### 4C. Inline Credential via `--key` — LOW (Accepted)

**Severity: LOW (Accepted Risk)**
**Location:** `src/cli.ts` lines 399, 877

Both interactive and non-interactive paths warn about shell history:
```
⚠ Cookie JSON was passed via --key — it may be visible in shell history.
```

The credential value appears in:
- Shell history file (`~/.bash_history`, `~/.zsh_history`)
- `/proc/PID/cmdline` while the process is running
- System audit logs (auditd, if configured)

**Mitigations available to the user:**
- Prefix command with a space (in zsh/bash with `HISTCONTROL=ignorespace`)
- Use stdin piping: `echo "secret" | openclaw vault add tool --key -`
- Use env var: `VAULT_KEY=[VAULT:env-redacted] secret.txt) openclaw vault add tool --key "$VAULT_KEY"`

**Note:** Stdin piping (`--key -`) is NOT currently implemented. The `--key` flag only accepts a direct value or file path.

**Recommendation:** Add `--key -` support to read from stdin, documented as the secure alternative.

### 4D. `--yes` Validation Strictness — INFO (Positive Finding)

**Severity: INFO**

The `--yes` flag correctly requires all necessary flags for each usage type:
- `api` requires `--url`
- `cli` requires `--command` and `--env`
- `browser-login` requires `--domain`
- `browser-session` requires `--domain` and valid cookie data in `--key`

Unknown format credentials cannot use `--yes` without `--use` flags. This prevents accidental [VAULT:gmail-app].

---

## 5. New Attack Surfaces

### 5A. Debug Logging to stderr — MEDIUM (F-NEW-5)

**Severity: MEDIUM**
**Location:** `src/index.ts` lines 413, 636, 658, 661

Four `console.error` calls with `[vault-debug]` prefix are **unconditional** — they run in production, not just when `OPENCLAW_VAULT_DEBUG` is set:

```typescript
console.error(`[vault-debug] browser-password resolve: targetId="${targetId}" cachedUrl="${cachedUrl}" params.url="${params.url}" cacheSize=${state.browserTabUrls.size} cacheKeys=[${[...state.browserTabUrls.keys()].join(",")}]`);
console.error(`[vault-debug] after_tool_call browser: action=${event.params.action} result=${JSON.stringify(event.result).slice(0, 200)} error=${event.error}`);
```

These log:
- All browser tab target IDs and their cached URLs
- Partial browser tool results (first 200 chars, which could contain page content)
- Cache size and all cache keys
- Browser action parameters

**Impact:** Credentials are NOT logged (good), but operational metadata about which sites the agent visits and which tabs it uses IS logged. In a multi-user/shared system, this metadata could be sensitive.

**Recommendation:** Gate these behind `OPENCLAW_VAULT_DEBUG` like other debug logging. Replace with `logVaultError()` or remove entirely.

### 5B. `browserTabUrls` Cache Unbounded Growth — LOW (F-NEW-6)

**Severity: LOW**
**Location:** `src/index.ts` line 85, `browserTabUrls: Map<string, string>`

The tab URL cache grows without bound. Every `navigate`/`open` action and every browser result adds an entry. There is no eviction, no TTL, and no size limit.

**Impact:** Me[VAULT:gmail-app]-running sessions. Each entry is small (~100 bytes), so 10,000 entries ≈ 1MB. Not a security vulnerability per se, but in a session with thousands of browser actions, it could accumulate.

**Recommendation:** Add a max size (e.g., 1000 entries) with LRU eviction, or clear on SIGUSR2 reload.

### 5C. Raw Cookie String Parsing — LOW (F-NEW-7)

**Severity: LOW**
**Location:** `src/browser.ts` `parseRawCookieString()` (lines 182-204), `src/cli.ts` multiple call sites

The `--key` flag now accepts raw cookie strings like `session_id=abc123`. The detection heuristic is:
```typescript
if (options.key && !fs.existsSync(options.key) && options.key.includes("=")) {
  // Treat as raw cookie string
}
```

**Edge case:** If a credential value happens to contain `=` (e.g., a base64-encoded API key like `dGVzdA==`) and is NOT a file path, it would be incorrectly parsed as a raw cookie string in the `browser-session` path. However, this only applies when `--use browser-session` is explicitly specified, so the user's intent is clear.

**Recommendation:** Document that `--key` with `--use browser-session` interprets `=` as cookie separator. For base64 credentials, use `--use api` or `--use cli` instead.

### 5D. Interactive Flow Cookie Re-encryption — INFO

**Severity: INFO**
**Location:** `src/cli.ts` line 862

In the interactive flow, if the user selects option 4 (browser session), the credential is re-encrypted as a cookie JSON payload, overwriting the previously encrypted `--key` value:

```typescript
// Encrypt cookie data (may overwrite key encrypted above)
await writeCredentialFile(vaultDir, tool, credentialPayload, passphrase);
```

The comment acknowledges this. The original `--key` value (which was already encrypted at line 696) is overwritten with the parsed cookie structure. This is correct behavior but means the original key format is lost.

---

## 6. Findings Summary

### New Findings (This Audit)

| ID | Finding | Severity | Status |
|----|---------|----------|--------|
| F-NEW-1 | Tab URL cache can be populated from parsed `content[0].text` in tool results — cache poisoning possible but domain pin still validates | MEDIUM | Open |
| F-NEW-2 | Cookie domain filtering is correct but `filterTrackingCookies` not called in injection path | LOW | Open |
| F-NEW-3 | `content[0].text` JSON parsing has no direct injection risk | LOW | Informational |
| F-NEW-4 | `--yes` flag skips cookie file secure delete, leaving plaintext on disk | MEDIUM | Open |
| F-NEW-5 | Debug logging to stderr is unconditional — leaks operational metadata in production | MEDIUM | Open |
| F-NEW-6 | `browserTabUrls` cache has no size limit or TTL | LOW | Open |
| F-NEW-7 | Raw cookie string parsing heuristic may misinterpret `=` in non-cookie credentials | LOW | Open |

### Prior Findings Status

| ID | Finding | Original Severity | Current Status |
|----|---------|-------------------|----------------|
| F-1 | process.env contamination | Medium | ✅ RESOLVED (params.env only) |
| F-2 | Rust resolver path traversal | Medium | ✅ RESOLVED (tool name validation) |
| F-3 | Credential cache no max size | Low | Open (unchanged) |
| F-4 | Concurrent tests mocked | Low | Open (unchanged) |
| F-5 | Fail-open error handling silent | Low | Open (unchanged) |
| F-6 | SIGUSR2 preserves stale literals | Low | Open (security-positive) |
| F-7 | Global scrub patterns missing providers | Info | Open (unchanged) |
| F-8 | Multi-command shell escaping | Info | ✅ RESOLVED (params.env only) |
| F-9 | LLM receives unscrubbed tool output | High | ✅ MITIGATED (Perl scrubber) |
| F-10 | System vault sync/remove | Medium | ✅ RESOLVED (setuid resolver) |

---

## 7. Recommendations (Priority Order)

### Must Fix (Before GA)

1. **Gate debug logging behind `OPENCLAW_VAULT_DEBUG`** (F-NEW-5) — Wrap all `[vault-debug]` `console.error` calls in a debug check. These should never run in production.

2. **Change `--yes` default for cookie files** (F-NEW-4) — Either auto-delete the source file in `--yes` mode (with `--keep-source` opt-out), or write an audit event when plaintext is left on disk.

### Should Fix

3. **Restrict tab URL cache population source** (F-NEW-1) — Only cache URLs from `navigate`/`open` params (user-initiated). Remove or restrict the `content[0].text` JSON parsing fallback, or validate against the original requested URL.

4. **Add `--key -` stdin support** (F-NEW-7-related) — Read credential from stdin to avoid shell history exposure. Document as the recommended secure path.

5. **Cap `browserTabUrls` cache size** (F-NEW-6) — Add LRU eviction at 500-1000 entries.

### Nice to Have

6. Call `filterTrackingCookies` in the cookie injection path (F-NEW-2)
7. Add process.env cleanliness regression test (from prior audit G-3)
8. Add concur[VAULT:gmail-app] crypto (from prior audit G-5)
9. Add global scrub patterns for AWS, GCP (from prior audit F-7)

---

## 8. Positive Findings Worth Preserving

- **Domain pinning is robust** — Handles IDN homograph, port injection, path confusion, data:/javascript: URLs, case sensitivity
- **`$vault:` placeholder model** — LLM never sees actual credentials; only the placeholder name
- **Split-priority hooks** — Injection at priority 10 (last), scrubbing at priority 1 (first)
- **Perl stdout scrubber with base64 encoding** — No credential appears in plaintext in command strings
- **Cookie domain filtering** — Cookies filtered to match pin domain before injection
- **Expired cookie removal** — `removeExpiredCookies()` called before injection
- **Cookie file secure delete** — Zero-overwrite before unlink (when user confirms)
- **`--yes` validation strictness** — Requires all flags for the specified usage type
- **Tool name validation** — Comprehensive validation prevents path traversal
- **695 tests across 36 files** — Including adversarial, false-positive, browser E2E, interactive flow tests

---

## 9. Test Coverage Assessment (Updated)

### New Test Files (This Branch)

| Test File | Tests | Coverage |
|-----------|-------|----------|
| `tests/browser-password-e2e.test.ts` | ~15 | Tab URL cache → domain pin → credential injection E2E |
| `tests/browser-session-e2e.test.ts` | ~15 | Cookie file → parse → encrypt → inject E2E |
| `tests/cli-use-flag.test.ts` | ~20 | `--use` flag combinations with `--yes` |
| `tests/interactive-flow.test.ts` | ~18 | Interac[VAULT:gmail-app] mocked stdin |
| `tests/usage-config.test.ts` | ~25 | `buildToolConfig()` from `UsageSelection` |

### Missing Test Cases (New)

1. **Tab URL cache poisoning** — No test verifies that a malicious `content[0].text` result cannot cause credential injection to an unintended domain
2. **`--yes` with cookie file path** — No test verifies the plaintext file warning behavior
3. **Raw cookie string `=` ambiguity** — No test verifies behavior when a non-cookie credential containing `=` is used with `--use browser-session`
4. **Debug logging gating** — No test verifies `[vault-debug]` messages are gated behind env var (they currently aren't)
5. **`browserTabUrls` cache size** — No test for memory growth under many navigations

---

## 10. Dependency Analysis (Updated)

No new production dependencies added in this branch. Same 2 production deps (argon2, yaml), same 3 dev deps (typescript, vitest, @types/node).

**npm audit: 0 vulnerabilities** (verified 2026-03-16).

---

## 11. Overall Risk Rating

**LOW**

The UX overhaul is well-executed. The browser credential support adds meaningful new functionality with appropriate security controls (domain pinning, cookie filtering, placeholder model). The three MEDIUM findings are:
- F-NEW-1 (cache poisoning): Mitigated by domain pin validation — worst case is denial of service
- F-NEW-4 (`--yes` skips delete): Operational risk, not a credential leak vector
- F-NEW-5 (debug logging): Information disclosure of operational metadata, not credentials

No path was found where a credential could leak to an unintended recipient through the new code. The defense-in-depth model (domain pinning → scrubbing pipeline → literal matching) provides multiple layers of protection.

---

## Changes from Prior Audit (2026-03-12)

### What's New

- **Browser password injection flow** — Full E2E review of `$vault:` placeholder → domain pin → credential resolution
- **Browser cookie injection flow** — Cookie parsing, domain filtering, expired cookie removal, `_vaultCookies` injection
- **Tab URL cache analysis** — Cache poisoning vectors, `content[0].text` parsing risk
- **CLI `vault add` UX overhaul** — `--use` flags, `--yes` non-interactive mode, raw cookie string support, cookie file secure delete
- **Debug logging audit** — Identified unconditional `[vault-debug]` stderr output
- **7 new findings** (3 MEDIUM, 4 LOW/INFO)

### What Regressed

- **Debug logging** — 4 unconditional `console.error` calls added in browser credential support that should be gated behind `OPENCLAW_VAULT_DEBUG`

### What Improved

- **695 tests** (up from 610) across 36 files (up from 30)
- **5 new test files** covering browser E2E, CLI use-flag, interactive flow, usage config
- **Cookie domain filtering** — Correct bidirectional pin matching
- **`--yes` validation** — Strict flag requirements prevent [VAULT:gmail-app]
- **Secure delete** — Cookie file overwrite-before-unlink
