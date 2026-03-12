# Security Audit

> Comprehensive security audit of the OpenClaw Credential Vault plugin.
> Audit date: 2026-03-12
> Auditor: Automated security engineering review (agentic)
> Scope: Full source code, tests, dependencies, Rust resolver, CI pipeline

---

## Executive Summary

The OpenClaw Credential Vault implements a well-designed defense-in-depth architecture for managing AI agent credentials. The codebase demonstrates strong cryptographic foundations (AES-256-GCM + Argon2id), comprehensive scrubbing across 5 hook points, and thoughtful handling of the unique threat surface created by LLM agents with tool access.

**Overall Risk Rating: LOW-MEDIUM**

The vault is suitable for its stated purpose (beta release for credential management in AI agent frameworks). The primary residual risks are:

1. **process.env contamination during injection** — credentials briefly exist in the gateway process environment (Medium severity)
2. **Machine-key derivation uses low-entropy inputs** (hostname, uid, timestamp) — encryption alone is insufficient against a local attacker. Binary mode mitigates by adding OS-user file isolation, making encrypted files inaccessible regardless of key strength (Medium severity)
3. **Fail-open scrubbing** — design choice with acceptable trade-offs but creates a real exposure window on scrubber bugs (Medium severity)
4. **No path traversal validation in Rust resolver** — setuid binary accepts arbitrary tool names from stdin (Medium severity)
5. **Mocked concurrent test coverage** — concurrent resolution tests don't exercise real crypto/IO paths (Low severity)

No critical vulnerabilities were found. All previously identified bugs (12 from the prior audit) remain fixed. The test suite is comprehensive at 576 tests across 29 files with dedicated adversarial, false-positive, sub-agent isolation, and resolver versioning coverage.

---

## Threat Coverage Matrix

Assessment of each threat vector from THREAT-MODEL.md against actual code defenses and test coverage.

### Threat 1: Agent Context Exfiltration

**Threat:** Prompt injection instructs agent to send credentials to an attacker-controlled endpoint.

**Code Defenses:**
- `src/index.ts` `handleBeforeToolCall()` (lines 178-443): Credentials injected into subprocess `params.env`, not returned as visible text to the agent
- `src/scrubber.ts` `scrubText()`: 3-layer scrubbing pipeline (regex → literal → env-var) catches credentials in all output
- `src/browser.ts` `resolveBrowserPassword()`: Domain pinning blocks credential resolution on non-matching domains
- `src/index.ts`: Scrubbing hooks at priority 1 across `after_tool_call`, `tool_result_persist`, `before_message_write`, `message_sending`

**Test Coverage:**
- `tests/adversarial.test.ts`: 56 tests covering 7 attack vectors including domain spoofing, encoded leakage, split credentials
- `tests/e2e.test.ts`: Full injection → scrubbing round-trip tests
- `tests/browser.test.ts`: Domain pinning bypass attempts (IDN homograph, subdomain spoof, data: URLs, javascript: URLs)

**Rating: ✅ Well Covered**

Specific strengths: Multi-hook redundancy (same credential caught at up to 4 separate points), domain pinning for browser credentials, priority-based hook ordering.

---

### Threat 2: Transcript Leakage

**Threat:** Credentials persist in session transcript files on disk.

**Code Defenses:**
- `src/index.ts` `handleToolResultPersist()` (lines 494-532): Scrubs tool results before transcript write
- `src/index.ts` `handleBeforeMessageWrite()` (lines 546-588): Scrubs all messages before transcript write
- Priority 1 ensures scrubbing runs before any other plugin writes to transcript
- `src/index.ts` `handleMessageSending()` (lines 596-618): Final scrub before outbound delivery

**Test Coverage:**
- `tests/hooks.test.ts`: Verifies scrubbing at before_message_write and tool_result_persist hooks
- `tests/compaction-scrub.test.ts`: 12 tests verifying compacted content is scrubbed before re-entry to transcript
- `tests/e2e.test.ts`: E2E verification of scrubbing pipeline

**Rating: ✅ Well Covered**

---

### Threat 3: Plugin-to-Plugin Leaks

**Threat:** Another plugin sees credentials in params or results via shared hooks.

**Code Defenses:**
- `src/index.ts` line 668: Injection at priority 10 (runs last — other plugins see pre-injection params)
- `src/index.ts` lines 671-674: Scrubbing at priority 1 (runs first — other plugins see scrubbed results)
- Split-priority design documented in `register()` function

**Test Coverage:**
- `tests/hooks.test.ts` "Hook priority validation": Contract test verifying SCRUB_PRIORITY < INJECT_PRIORITY
- No integration test with actual mock plugins to verify priority isolation end-to-end

**Rating: ⚠️ Partially Covered**

Gap: Priority-based isolation is verified as a design contract but never tested with actual concurrent plugins. The test validates `1 < 10` arithmetically but doesn't exercise the OpenClaw hook dispatch order with competing plugins.

---

### Threat 4: Sub-Agent Isolation

**Threat:** Sub-agents spawned by the main agent bypass scrubbing.

**Code Defenses:**
- Hooks fire at gateway level for all sessions, including sub-agents (architectural property of OpenClaw, not vault-specific code)
- Scrubbing uses the same `scrubText()` pipeline regardless of session type

**Test Coverage:**
- `tests/subagent-isolation.test.ts`: 8 tests verifying identical scrubbing behavior for main and sub-agent sessions
- Tests simulate concurrent sub-agent sessions with different credentials

**Rating: ⚠️ Partially Covered**

Gap: Tests simulate the hook dispatch behavior but don't actually exercise the OpenClaw gateway's session routing. The tests call `scrubText()` directly and assert identical results, which is correct but doesn't prove that the gateway actually routes sub-agent tool calls through the same hooks. This is an architectural assumption that should be integration-tested with the actual gateway.

---

### Threat 5: Credential Persistence in Memory Files

**Threat:** Agent writes credentials to workspace files via write/edit tools.

**Code Defenses:**
- `src/index.ts` `handleBeforeToolCall()` (lines 229-239): Intercepts `write` and `edit` tool calls, scrubs `content`, `newText`, `new_string` params
- `src/index.ts` `scrubWriteEditContent()` (lines 205-226): Dedicated function for write/edit scrubbing
- Both regex patterns and literal cached credentials are scrubbed from file content

**Test Coverage:**
- `tests/write-edit-scrub.test.ts`: 13 tests for write content, edit newText, edit new_string, JSON content, YAML content, edge cases
- `tests/adversarial.test.ts` "Attack Vector 5": Write/edit bypass attempts including heredoc, JSON escapes, base64

**Rating: ✅ Well Covered**

---

### Threat 6: Environment Variable Exposure

**Threat:** Credentials injected as env vars persist in gateway's process.env.

**Code Defenses:**
- `src/index.ts` line 393: `process.env[envKey] = resolved` — credentials ARE set on process.env during injection
- `src/index.ts` lines 478-484: `handleAfterToolCall()` cleans up injected env vars via `delete process.env[envKey]`
- `src/scrubber.ts` `scrubEnvVars()`: ENV_VAR_PATTERN catches `KEY=[VAULT:env-redacted] patterns in output

**Test Coverage:**
- `tests/adversarial.test.ts` "Attack Vector 4": Env variable scrubbing bypass tests
- No test verifying the process.env injection/cleanup lifecycle

**Rating: ⚠️ Partially Covered**

**NEW FINDING — process.env contamination (see New Findings F-1 below)**

---

### Threat 7: Output Pattern Leakage

**Threat:** Tool output contains credential-like strings (e.g., `set -x` echo, API responses with auth tokens).

**Code Defenses:**
- `src/scrubber.ts`: 3-layer pipeline — regex patterns, literal indexOf matching, env-var name matching
- `src/scrubber.ts` `GLOBAL_SCRUB_PATTERNS`: Telegram bot tokens and Slack bot tokens scrubbed regardless of vault registration
- `src/registry.ts`: 7 known tool patterns (Stripe, GitHub, Gumroad, OpenAI, Anthropic, Amazon, Netflix)

**Test Coverage:**
- `tests/adversarial.test.ts`: Encoded leakage (base64, URL-encode, hex, ROT13, reversed — all documented as known gaps)
- `tests/false-positives.test.ts`: 11 tests ensuring UUIDs, git hashes, CSS colors, base64 data URIs are NOT over-scrubbed
- `tests/adversarial.test.ts`: Concurrent scrubbing, massive output, pathological regex input

**Rating: ✅ Well Covered**

Known gaps (all documented in adversarial tests): base64-encoded, URL-encoded, hex-encoded, ROT13, reversed, split-across-calls, zero-width-character-injected credentials bypass scrubbing. These are acknowledged limitations of pattern-based scrubbing.

---

### Threat 8 (Implicit): Credential File Direct Read

**Threat:** Agent reads encrypted files directly via `cat ~/.openclaw/vault/*.enc`.

**Code Defenses:**
- `src/crypto.ts`: AES-256-GCM encryption — files are binary ciphertext, not usable without key derivation
- `bin/vault-setup.sh`: In binary mode, files owned by `openclaw-vault` user with mode 600 — agent gets `Permission denied`
- `src/crypto.ts` `writeCredentialFile()`: Atomic write with 0o600 permissions

**Test Coverage:**
- `tests/crypto.test.ts`: 19 tests for encryption round-trip, wrong passphrase, tampered ciphertext, file permissions

**Rating: ✅ Well Covered**

---

## New Findings

### F-1: process.env Contamination During Injection (Medium) — RESOLVED

**Severity: Medium → RESOLVED (commit 630c7a5)**
**Location:** `src/index.ts`, env injection block

**Original issue:** During credential injection, the vault set credentials on `process.env` and prepended `export KEY=[VAULT:env-redacted] && command` to the command string. This contaminated the gateway process environment and exposed credentials in the command string.

**Resolution:** Credentials are now injected ONLY via `params.env` (passed directly to the subprocess spawn). No `process.env` mutation, no command string prepend. A Perl stdout scrubber pipes subprocess output through credential value replacement before exec captures it. Credentials are base64-encoded in the perl command, never appearing in plaintext in the command string.

**Recommendation:**
- Remove `process.env[envKey] = resolved` (line 393) — it's redundant with the `params.env` injection on line 391 and the command prepend on line 399
- If process.env injection is necessary for some tools, document the race window in THREAT-MODEL.md

**Test Gap:** No test verifies that `process.env` is clean during/after injection.

---

### F-2: No Path Traversal Validation in Rust Resolver (Medium)

**Severity: Medium**
**Location:** `resolver/src/main.rs`, `find_vault_paths()` function, line using `format!("{}.enc", tool_name)`

The Rust resolver binary accepts a tool name from stdin JSON and constructs a file path:
```rust
let enc_path = dir.join(format!("{}.enc", tool_name));
```

The tool name is not validated for path traversal characters (`../`, `/`, etc.). While the TypeScript CLI validates tool names via `validateToolName()` in `src/cli.ts`, the Rust binary is invoked independently and runs with setuid permissions.

**Attack scenario:** If an attacker can invoke the setuid resolver binary directly (bypassing the TypeScript layer), they could request:
```json
{"tool": "../../etc/shadow", "context": "exec", "command": "test"}
```
This would attempt to read `/var/lib/openclaw-vault/../../etc/shadow.enc` = `/etc/shadow.enc` — which likely doesn't exist, and if it did, decryption would fail. However, the existence check itself leaks information (file existence oracle). On systems where `.enc` files exist outside the vault, this could be exploited.

**Recommendation:**
- Add tool name validation in `main.rs` before path construction: reject names containing `/`, `\`, `..`, or starting with `.`
- This is defense-in-depth — the setuid binary should not trust its input

---

### F-3: Credential Cache Has No Maximum Size (Low)

**Severity: Low**
**Location:** `src/index.ts`, `VaultState.credentialCache` (line 69)

The `credentialCache` Map grows without bound. Entries are evicted only when accessed after TTL expiry. There is no maximum cache size, no periodic sweep, and no cache clearing on SIGUSR2 reload (the cache is intentionally preserved across reloads if the passphrase hasn't changed — line 685).

**Impact:** All decrypted credential values persist in process memory for 15 minutes. In a system with many tools, this increases the attack surface for memory-based credential extraction.

**Recommendation:**
- Add a maximum cache size (e.g., 100 entries)
- Consider a periodic sweep (e.g., every 5 minutes) to evict expired entries proactively
- On `vault remove`, evict the corresponding cache entry (currently not done)

---

### F-4: Concurrent Resolution Tests Are Mocked (Low)

**Severity: Low**
**Location:** `tests/concurrent.test.ts`

All 5 concurrent resolution tests use `simulateCredentialResolution()` — a mock function that returns hardcoded credentials after a `setTimeout`. These tests verify that `Promise.all()` works correctly (which is a JavaScript runtime guarantee, not a vault property).

The tests do NOT exercise:
- Real Argon2id derivation under concurrent load
- File I/O contention when multiple resolutions read the same `.enc` file simultaneously
- Credential cache behavior under concurrent access (Map operations are synchronous in V8, so this is actually safe, but it's not tested)

**Recommendation:**
- Add at least one concurrent test that uses real `readCredentialFile()` with actual encrypted files
- The existing mocked tests can remain as documentation of the concurrency contract

---

### F-5: Fail-Open Error Handling Lacks Alerting (Low)

**Severity: Low**
**Location:** `src/index.ts`, all hook handlers (lines 442, 486, 530, 586, 616)

All hook handlers catch errors and return void (fail-open). The `logVaultError()` function only writes to `error.log` when `OPENCLAW_VAULT_DEBUG` is set. In production, a scrubbing failure would be completely silent — no console output, no audit log entry, no notification.

**Impact:** If a scrubbing bug causes an error, credentials could leak through unscrubbed content with no indication to the operator.

**Recommendation:**
- Always log scrubbing errors to the audit log (not just when debug mode is enabled)
- Consider a `console.warn` for scrubbing failures in production — these are security events that warrant visibility
- The `logVaultError` function already exists; it should be augmented to always write to the audit log regardless of debug mode

---

### F-6: SIGUSR2 Hot-Reload Preserves Stale Literal Credentials (Low)

**Severity: Low**
**Location:** `src/index.ts`, SIGUSR2 handler (lines 677-686); `src/scrubber.ts`, module-level `literalCredentials` Map

When the vault config is reloaded via SIGUSR2, the credential cache is preserved (line 685: `newState.credentialCache = state.credentialCache`), but the module-level `literalCredentials` Map in `scrubber.ts` is never cleared. This means:
- Credentials that were removed from the vault remain in the literal scrub set
- This is actually a *positive* security property (over-scrubbing is safer than under-scrubbing)
- However, it means the literal match set grows monotonically and is never pruned

**Recommendation:** This is informational. The behavior is security-positive (scrubs more, not less). Document it.

---

### F-7: Global Scrub Patterns Missing Common Providers (Informational)

**Severity: Informational**
**Location:** `src/scrubber.ts`, `GLOBAL_SCRUB_PATTERNS` (lines 18-22)

Only Telegram bot tokens and Slack bot tokens have global scrub patterns. Other common credential formats that could appear in agent output are not covered globally:
- AWS access keys (`AKIA[0-9A-Z]{16}`)
- Google Cloud service account JSON
- Database connection strings with embedded passwords
- Bearer tokens in HTTP headers

**Recommendation:** Consider adding global patterns for AWS, GCP, and common JWT bearer patterns. These would provide defense-in-depth even for credentials not registered in the vault.

---

### F-8: Multi-Command Injection May Interact with Shell Metacharacters (Informational)

**Severity: Informational**
**Location:** `src/index.ts`, lines 396-399

The command prepend logic constructs:
```typescript
params.command = `${envExports.join(" && ")} && ${params.command}`;
```

The credential value is escaped with single-quote shell escaping (line 397):
```typescript
const escaped = resolved.replace(/'/g, "'\\''");
envExports.push(`export ${envKey}='${escaped}'`);
```

This escaping handles single quotes correctly for bash. However:
- If the exec tool uses a different shell (e.g., sh, zsh, fish), the escaping may behave differently
- If the credential contains null bytes, backslashes, or other special characters, edge cases may arise
- The `envKey` is not escaped — a malicious injection rule with a crafted env var name could break the shell syntax

**Recommendation:** The current escaping is adequate for standard bash usage. Consider documenting the shell assumption.

### F-9: LLM Receives Unscrubbed Tool Output (High)

**Severity: High**
**Location:** OpenClaw gateway architecture (not vault-specific code)

**Finding:** The vault scrubs credentials at `tool_result_persist`, `before_message_write`, and `message_sending` hooks. However, the LLM receives the raw tool result **before** `tool_result_persist` runs. The persist hook only scrubs what gets written to the session transcript — not what the LLM sees in real-time during inference.

**Attack path:**
1. Agent calls `exec` with a command matching an injection rule (e.g., `gws auth status`)
2. Vault injects credentials via env vars / command prepend
3. Tool executes and returns output — **Perl stdout scrubber replaces credential values before exec captures stdout**
4. LLM receives the scrubbed output with `[VAULT:name]` replacement markers
5. `tool_result_persist` scrubs the transcript for persistence
6. `message_sending` scrubs outbound messages as a final defense layer

**Status: MITIGATED (commit 630c7a5)**

The Perl stdout scrubber (implemented via `before_tool_call` hook) wraps exec commands in `{ command ; } 2>&1 | perl -pe 's/\Qcredential\E/[VAULT:name]/g'`. Credentials are base64-encoded in the perl command, decoded at runtime via MIME::Base64. This catches the primary exfiltration vectors: `printenv`, `env.VAR` in jq, `echo $VAR`.

**Known limitations:**
- File redirect bypass: `echo $SECRET > /tmp/file` writes to disk before the pipe sees it
- Shell injection: sophisticated command construction could bypass the pipe (e.g., subshells, heredocs)
- Both require deliberate multi-step attacks by a malicious LLM

**Original vulnerability (2026-03-12):** The LLM saw the raw GWS client ID in tool output and posted a partial form to Telegram that didn't match the full regex pattern. This is now mitigated by the Perl scrubber catching the value at the subprocess output level.

**Remaining recommendation:** Request OpenClaw `transform_tool_result` hook for defense-in-depth — this would provide a second scrubbing layer between tool execution and LLM inference, independent of the Perl pipe approach.

---

## Gaps & Recommendations

### Security Gaps

| # | Gap | Severity | Recommendation |
|---|-----|----------|---------------|
| G-1 | ~~process.env contamination during injection~~ | ~~Medium~~ | **RESOLVED** — params.env only, no process.env mutation |
| G-2 | Rust resolver lacks tool name validation | Medium | Add path traversal validation before file path construction |
| G-3 | No test for process.env cleanup lifecycle | Medium | Add test verifying env vars are cleaned after tool call completes |
| G-4 | No integration test for plugin priority isolation | Low | Add mock-plugin test verifying injection/scrubbing priority ordering |
| G-5 | Concurrent tests are fully mocked | Low | Add at least one real concurrent crypto test |
| G-6 | Scrubbing errors silent in production | Low | Always log scrubbing errors to audit log |
| G-7 | No gateway log scanning for leaked credentials | Low | Planned but not built (acknowledged in prior audit) |
| G-8 | vault_status tool doesn't verify credential file integrity | Informational | Add optional integrity check (attempt decrypt, report failures) |

### Positive Findings Worth Preserving

- **Atomic writes everywhere** — both `writeCredentialFile()` and `writeConfig()` use tmp+rename pattern
- **Secure delete on remove** — `removeCredentialFile()` overwrites with random data before unlinking
- **Config backup and recovery** — `readConfig()` auto-recovers from corrupted tools.yaml using `.bak` file
- **Tool name validation** — comprehensive validation in `cli.ts` prevents path traversal via the CLI path
- **Audit log rotation** — 5MB cap prevents unbounded growth
- **Setuid + seccomp + capability dropping** — Rust resolver has defense-in-depth OS isolation
- **False positive test corpus** — dedicated tests prevent over-scrubbing of UUIDs, git hashes, CSS colors

---

## Dependency Analysis

### Production Dependencies (2)

| Package | Version | Risk | Notes |
|---------|---------|------|-------|
| `argon2` | ^0.41.1 | **Low** | Native module (N-API). Well-maintained binding to the reference C implementation. No known vulnerabilities. Handles the most security-critical operation (key derivation). |
| `yaml` | ^2.7.0 | **Low** | Pure JavaScript YAML parser. Used only for config file read/write. No known vulnerabilities. |

### Dev Dependencies (3)

| Package | Version | Risk | Notes |
|---------|---------|------|-------|
| `typescript` | ^5.7.0 | **Negligible** | Build-time only |
| `vitest` | ^3.0.0 | **Negligible** | Test-time only |
| `@types/node` | ^22.0.0 | **Negligible** | Build-time only |

### Rust Dependencies (Resolver)

| Crate | Version | Risk | Notes |
|-------|---------|------|-------|
| `aes-gcm` | 0.10 | **Low** | RustCrypto project, well-audited |
| `argon2` | 0.5 | **Low** | Pure Rust Argon2id implementation |
| `serde`/`serde_json` | 1.x | **Low** | De facto standard serialization |
| `sha2` | 0.10 | **Low** | RustCrypto SHA-256 |
| `seccompiler` | 0.4 | **Low** | AWS Firecracker project, well-maintained |
| `caps` | 0.5 | **Low** | Linux capabilities management |
| `libc` | 0.2 | **Low** | Standard FFI bindings |
| `hostname` | 0.4 | **Low** | OS hostname retrieval |
| `hex` | 0.4 | **Low** | Hex encoding/decoding |

### npm Audit Results

**0 vulnerabilities** across 6 production and 103 dev dependencies (as of 2026-03-12).

### Supply Chain Assessment

- **Minimal dependency surface:** Only 2 production dependencies (argon2 + yaml). The attack surface for supply-chain compromise is very small.
- **No transitive production dependencies beyond argon2's N-API bindings.** The yaml package is pure JavaScript with zero dependencies.
- **Rust resolver uses well-established crates** from RustCrypto and AWS Firecracker ecosystems.
- **CI pipeline** uses `npm ci` (locked dependencies) and caches Cargo registry.
- **`package.json` uses caret ranges** (`^0.41.1`) — `npm ci` with lockfile mitigates this, but without a lockfile, minor version bumps could introduce changes.

---

## Test Coverage Assessment

### Coverage by Component

| Component | Source File | Test File(s) | Tests | Coverage Notes |
|-----------|-----------|------------|-------|----------------|
| Encryption | `src/crypto.ts` | `tests/crypto.test.ts` | 19 | Excellent — round-trip, wrong passphrase, tampered data, file perms, secure delete |
| Scrubbing | `src/scrubber.ts` | `tests/adversarial.test.ts`, `tests/hooks.test.ts`, `tests/write-edit-scrub.test.ts`, `tests/compaction-scrub.test.ts`, `tests/false-positives.test.ts` | ~150+ | Excellent — 3-layer pipeline, adversarial bypass attempts, false positive corpus |
| Registry | `src/registry.ts` | (inline in other test files) | ~22 | Good — glob matching, command matching, URL matching |
| Config | `src/config.ts` | (inline in e2e tests) | ~10 | Adequate — read/write/atomic, meta file |
| Browser | `src/browser.ts` | `tests/browser.test.ts` | 94 | Excellent — domain pinning, cookies, tracking filters, password resolution |
| Audit | `src/audit.ts` | (inline in hook tests) | ~29 | Good — JSONL append, rotation, filtered queries |
| CLI | `src/cli.ts` | (manual testing per prior audit) | Manual | Adequate — tested via manual simulation, tool name validation unit tested |
| Resolver | `resolver/src/main.rs` | Inline Rust tests + `tests/e2e.test.ts`, `tests/cross-compat.test.ts` | ~23 | Good — round-trip, cross-language compat, error handling |
| Hooks | `src/index.ts` | `tests/hooks.test.ts`, `tests/e2e.test.ts` | ~27 | Adequate — hook registration tested indirectly, scrubbing pipeline tested directly |
| Guesser | `src/guesser.ts` | (separate guesser test file) | ~61 | Good — prefix detection, JWT, JSON, password, generic API key |
| Vault Status | `src/vault-status.ts` | (tested via CLI manual) | Minimal | Gap — no dedicated unit tests for `computeVaultStatus()` |

### Missing Test Cases

1. **process.env injection/cleanup lifecycle** — no test verifies env vars are set and then cleaned
2. **Concurrent resolution with real crypto** — all concurrent tests use mocks
3. **Credential cache TTL enforcement** — no test verifies that expired cache entries are actually re-derived
4. **SIGUSR2 hot-reload** — no test verifies config reload behavior
5. **Vault status tool** — no unit test for `computeVaultStatus()` or `createVaultStatusTool().execute()`
6. **Error path in hooks** — no test verifies fail-open behavior when scrubbing throws
7. **Audit log rotation** — no test for the 5MB rotation logic in `writeAuditEvent()`
8. **Tool name validation in Rust resolver** — (doesn't exist in code, should be added and tested)

---

## Overall Risk Rating

**LOW-MEDIUM**

The vault provides strong security for its intended threat model. The cryptographic primitives are correctly implemented, the scrubbing pipeline is comprehensive with redundant layers, and the test suite is thorough with dedicated adversarial coverage.

The residual risks are:
- **Medium:** process.env contamination and Rust resolver path validation gaps are actionable findings that should be addressed before v1.0 stable
- **Low:** Mocked concurrent tests, silent scrubbing errors, and missing vault_status tests are quality gaps, not security vulnerabilities
- **Informational:** The documented scrubbing blind spots (base64, URL-encoding, split credentials) are inherent limitations of pattern-based scrubbing and are clearly acknowledged

The codebase shows evidence of security-conscious development: atomic writes, secure delete, fail-open with explicit rationale, priority-based hook isolation, and comprehensive adversarial testing. The threat model is honest about limitations and does not overstate the vault's protections.

---

## Changes from Prior Audit

Comparison with the prior audit dated 2026-03-11.

### What's New in This Audit

- **F-1: process.env contamination finding** — Not identified in the prior audit. The prior audit did not examine the race window between credential injection into `process.env` and cleanup in `after_tool_call`. This is the most significant new finding.
- **F-2: Rust resolver path traversal** — Not identified in the prior audit. The resolver binary's input validation was not assessed.
- **F-3: Credential cache sizing** — New finding, informational.
- **F-5: Fail-open error handling alerting gap** — Prior audit noted fail-open as a design choice. This audit adds that production failures are completely silent (no audit log entry without debug mode).
- **F-7: Global scrub patterns coverage** — New informational finding.
- **F-8: Multi-command shell escaping** — New informational finding.
- **Comprehensive dependency analysis** — Prior audit did not include npm audit results or Rust crate assessment.
- **Rust resolver source review** — This audit includes line-by-line review of `resolver/src/main.rs` including seccomp filter, capability dropping, and path resolution.

### Post-Audit Changes (2026-03-12, same day)

The following changes were implemented during the doc review session after the audit was completed:

- **Protocol versioning added to resolver** — Both TS plugin and Rust resolver now include `protocol_version` in their JSON communication. On mismatch, the resolver rejects with a structured `EPROTO` error. This addresses the version drift risk identified in the v4.5.5 spec (Pitfall #17).
- **Configurable resolver failure policy** — New `onResolverFailure` config option: `"block"` (default, credential not injected) or `"warn-and-inline"` (falls back to inline decryption with security downgrade audit event).
- **Actionable warnings on resolver failure** — Warnings injected into tool output include direction-specific fix instructions (which side to update). Prominent console warning on first mismatch per session.
- **New audit event types** — `resolver_failure` and `security_downgrade` events written to audit log on resolver failures.
- **Pre-built binary rebuilt** — `bin/linux-x64/openclaw-vault-resolver` updated with protocol versioning support.
- **THREAT-MODEL.md accuracy pass** — Threat 1 reframed (honest about prompt injection limits), Threat 6 corrected (process.env is briefly set during injection), Path 4 fixed, overview tightened.
- **Sandbox compatibility documented** — SPEC.md and README.md now honestly state sandbox mode is untested with real gateway Docker sandbox.

### What Improved Since Prior Audit

- All 12 bugs identified in the prior audit remain fixed (verified by code inspection):
  - Bug #1: Tool name validation (confirmed in `cli.ts` `validateToolName()`)
  - Bug #3: SIGUSR2 pgrep fallback removed (confirmed in `config.ts` `signalGatewayReload()`)
  - Bug #5: Debug logging gated behind OPENCLAW_VAULT_DEBUG (confirmed in `index.ts` `logVaultError()`)
  - Bug #7: Multi-line command matching (confirmed in `registry.ts` `matchesCommand()`)
  - Bug #8: Try-catch on all hooks (confirmed in `index.ts` — 5 handler functions wrapped)
  - Bug #9: Atomic config writes (confirmed in `config.ts` `writeConfig()`)
  - Bug #10: Cache TTL (confirmed in `index.ts` `CACHE_TTL_MS = 15 * 60 * 1000`)
  - Bug #11: Error log path (confirmed in `index.ts` `logVaultError()` — uses `~/.openclaw/vault/error.log`)
  - Bug #12: Audit log rotation (confirmed in `audit.ts` `MAX_AUDIT_LOG_BYTES = 5 * 1024 * 1024`)

### What Regressed

- Nothing regressed. All prior fixes are intact.

### What Was Removed

- The prior audit's "Gap Analysis" section listed 7 gaps all marked "Closed". This audit replaces that section with a new gap analysis reflecting current findings.
- The prior audit's manual testing section (58 test cases) is not reproduced here as it represents a point-in-time validation. The automated test suite (576 tests) provides ongoing coverage.

### Status of Prior Known Limitations

| Prior Limitation | Current Status |
|-----------------|----------------|
| Machine-key entropy | Unchanged — low-entropy inputs (hostname, uid, timestamp); encryption alone insufficient against local attacker. Binary mode sidesteps via OS-user file isolation. |
| Fail-open scrubbing | Unchanged — this audit adds alerting gap (F-5) |
| Scrubbing blind spots (base64, URL-encode, split) | Unchanged — all documented in adversarial tests |
| No gateway log scanning | Unchanged — still not built |
| Browser credentials not production-tested | Unchanged — still unit/integration tested only |
| Single-user system vault | Unchanged — needs per-user separation |
| Plugin install requires restart | Unchanged — SIGUSR2 handles config only |
