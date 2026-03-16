# Hook-Level E2E Test Gap Analysis

Generated: 2026-03-16

## Summary

**Critical gap identified and fixed:** The only tests that exercised ACTUAL hook handlers
(`handleBeforeToolCall`, `handleAfterToolCall`) were NONE — zero tests called the real handlers
with realistic OpenClaw-sh[VAULT:gmail-app]ts. This allowed a bug to go undetected where
`after_tool_call` couldn't parse OpenClaw's wrapped result format `{content: [...], details: {...}}`.

## New Test File: `tests/hook-e2e.test.ts` (29 tests)

### What's Covered

| Suite | Tests | Coverage Added |
|-------|-------|----------------|
| Browser Password Full Flow | 5 | navigate→act flow, cold-cache block, domain-pin reject, nested request path |
| Browser Cookie Full Flow | 4 | Cookie injection, non-matching domain, expired filter, tracking cookie passthrough |
| Exec Injection Full Flow | 3 | Matching command, non-matching, multi-credential |
| Web Fetch Full Flow | 2 | Header injection, non-matching URL |
| Scrubbing Full Flow | 4 | tool_result_persist, before_message_write, write/edit interception, array content |
| Result Parsing Regression | 8 | details path (the fix), content fallback, graceful no-ops, null/empty |
| Edge Cases | 3 | Non-browser passthrough, edit scrub, hot-reload |

### Key Regression Tests for the Bug Fix (after_tool_call result parsing)

1. **`Result with details containing url/targetId (the fix)`** — Tests that `result.details.url` and `result.details.targetId` are used to populate the tab URL cache. This is the primary regression test for the bug.

2. **`Re[VAULT:gmail-app]ent[0].text (fallback path)`** — Tests that when `details` is absent, the handler falls back to parsing `content[0].text` as JSON to extract url/targetId.

3. **`Result with neither details nor parseable content (graceful no-op)`** — Tests that non-JSON content doesn't crash the handler and leaves the cache empty.

4. **`Result with details but targetId only in params`** — Tests that `params.targetId` is used when `details` doesn't contain it (common navigate scenario).

5. **`Result for snapshot action`** — snapshot returns url in details, should update cache.

6. **`Result for start action`** — start has no url/targetId, should not throw.

7. **`Result with empty object`** / **`Result with null`** — defensive edge cases.

## Gap Analysis by Credential Type

### API Key (e.g., Stripe, OpenAI)

| Coverage Area | Before | After |
|--------------|--------|-------|
| Add flow (crypto + config) | ✅ e2e.test.ts | ✅ unchanged |
| Pattern scrubbing | ✅ scrubber.test.ts | ✅ unchanged |
| **Hook-level injection** | ❌ MISSING | ✅ hook-e2e.test.ts |
| **Hook-level scrubbing** | ❌ MISSING | ✅ hook-e2e.test.ts |
| Removal | N/A (file delete) | N/A |

### CLI Token (e.g., GitHub, Gumroad)

| Coverage Area | Before | After |
|--------------|--------|-------|
| Add flow | ✅ e2e.test.ts | ✅ unchanged |
| Pattern matching | ✅ registry.test.ts | ✅ unchanged |
| **Hook-level injection** | ❌ MISSING | ✅ hook-e2e.test.ts (exec inject) |
| **Hook-level scrubbing** | ❌ MISSING | ✅ hook-e2e.test.ts |

### Browser Password

| Coverage Area | Before | After |
|--------------|--------|-------|
| Add flow | ✅ browser-password.test.ts | ✅ unchanged |
| Domain pin logic | ✅ browser.test.ts | ✅ unchanged |
| Tab URL cache (function-level) | ✅ browser-password-e2e.test.ts | ✅ unchanged |
| **Hook-level full flow** | ❌ MISSING | ✅ hook-e2e.test.ts (navigate→act) |
| **after_tool_call URL caching** | ❌ MISSING | ✅ hook-e2e.test.ts (regression tests) |
| Cold cache block | ✅ browser-password-e2e.test.ts | ✅ hook-e2e.test.ts |
| Domain pin rejection | ✅ browser-password-e2e.test.ts | ✅ hook-e2e.test.ts |

### Browser Cookie

| Coverage Area | Before | After |
|--------------|--------|-------|
| Add flow | ✅ browser-cookie.test.ts | ✅ unchanged |
| Domain match logic | ✅ browser.test.ts | ✅ unchanged |
| Cookie parsing | ✅ browser.test.ts | ✅ unchanged |
| Expiry detection | ✅ browser-cookie.test.ts | ✅ unchanged |
| **Hook-level navigate injection** | ❌ MISSING | ✅ hook-e2e.test.ts |
| **Expired cookie filtering** | ❌ MISSING | ✅ hook-e2e.test.ts |
| Tracking cookie passthrough | Noted in docs | ✅ hook-e2e.test.ts (confirmed behavior) |

## Root Cause of Test Coverage Gap

The existing test architecture was **function-level only** — it tested individual functions like
`resolveBrowserPassword()`, `shouldInjectCookies()`, `filterCookiesByDomain()` in isolation.

This is correct and valuable, but it missed the **integration layer**: the `handleBeforeToolCall`
and `handleAfterToolCall` handlers that GLUE these functions together with:
- Module-level state management (browserTabUrls cache)
- Credential decryption and caching
- Result parsing (the bug!)
- Config hot-reload detection
- Multi-step flows (navigate → act)

## Conclusion

The new `tests/hook-e2e.test.ts` file fills this gap by:
1. Calling `register()` with a mock PluginApi against a temp vault dir
2. Calling the actual exported handlers with realistic OpenClaw-shaped events
3. Verifying the end-to-end behavior including state side-effects

**Total tests added: 29**
**Total test suite: 695 (was 666)**
