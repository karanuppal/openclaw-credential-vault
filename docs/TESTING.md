# Testing

Current baseline (latest full run):

- **36 test files**
- **~695 tests** (includes parameterized expansions via `it.each`)
- **0 failures**

Run everything:

```bash
npm run build
npx vitest run
```

## Quick commands

```bash
# all tests
npx vitest run

# single file
npx vitest run tests/cli-use-flag.test.ts

# filter by test name
npx vitest run -t "browser-session"

# watch mode
npm run test:watch

# Rust resolver tests
npm run test:resolver

# TS <-> Rust compatibility tests
npm run test:cross
```

## Test file list and counts

- `tests/adversarial.test.ts` — 54
- `tests/audit-log.test.ts` — 9
- `tests/audit.test.ts` — 18
- `tests/browser-cookie.test.ts` — 20
- `tests/browser-password-e2e.test.ts` — 8 *(new: full flow navigate→act/type with domain-pin validation via browserTabUrls cache)*
- `tests/browser-password.test.ts` — 18
- `tests/browser-session-e2e.test.ts` — 6
- `tests/browser.test.ts` — 56
- `tests/cli-browser.test.ts` — 2
- `tests/cli-logs-display.test.ts` — 5
- `tests/cli-use-flag.test.ts` — 20
- `tests/compaction-scrub.test.ts` — 12
- `tests/concurrent.test.ts` — 5
- `tests/config.test.ts` — 10
- `tests/cross-compat.test.ts` — 8
- `tests/crypto.test.ts` — 19
- `tests/e2e.test.ts` — 15
- `tests/env-scrub.test.ts` — 18
- `tests/false-positives.test.ts` — 11
- `tests/format-guessing.test.ts` — 17
- `tests/guesser.test.ts` — 45
- `tests/hook-e2e.test.ts` — 29 *(new: tests actual hook handlers with realistic OpenClaw-shaped inputs including wrapped {content, details} format)*
- `tests/hooks.test.ts` — 12
- `tests/interactive-flow.test.ts` — 8
- `tests/literal-scrub.test.ts` — 12
- `tests/performance.test.ts` — 6
- `tests/perl-scrubber.test.ts` — 30
- `tests/registry.test.ts` — 22
- `tests/resolver-versioning.test.ts` — 33
- `tests/rotation.test.ts` — 19
- `tests/sandbox-e2e.test.ts` — 9
- `tests/scrubber-advanced.test.ts` — 26
- `tests/scrubber.test.ts` — 18
- `tests/subagent-isolation.test.ts` — 8
- `tests/usage-config.test.ts` — 23
- `tests/write-edit-scrub.test.ts` — 13

Total (static `it`/`test` calls): **644** — parameterized tests expand to ~695 at runtime.

## Coverage map (high level)

- **Core crypto + config:** `crypto.test.ts`, `config.test.ts`, `cross-compat.test.ts`
- **Credential format + vault add UX:** `guesser.test.ts`, `format-guessing.test.ts`, `usage-config.test.ts`, `interactive-flow.test.ts`, `cli-use-flag.test.ts`, `browser-session-e2e.test.ts`
- **Injection + hooks:** `registry.test.ts`, `hooks.test.ts`, `e2e.test.ts`, `sandbox-e2e.test.ts`, `hook-e2e.test.ts`
- **Scrubbing:** `scrubber.test.ts`, `scrubber-advanced.test.ts`, `literal-scrub.test.ts`, `env-scrub.test.ts`, `perl-scrubber.test.ts`
- **Browser credentials:** `browser.test.ts`, `browser-password.test.ts`, `browser-password-e2e.test.ts`, `browser-cookie.test.ts`, `browser-session-e2e.test.ts`, `cli-browser.test.ts`
- **Adversarial/security:** `adversarial.test.ts`, `false-positives.test.ts`, `write-edit-scrub.test.ts`, `compaction-scrub.test.ts`, `subagent-isolation.test.ts`, `concurrent.test.ts`
- **Operations/audit:** `audit.test.ts`, `audit-log.test.ts`, `rotation.test.ts`, `cli-logs-display.test.ts`, `resolver-versioning.test.ts`
- **Performance:** `performance.test.ts`

## New test files in this release

### `tests/hook-e2e.test.ts` (29 tests)

Tests the **actual exported hook handlers** (`handleBeforeToolCall`, `handleAfterToolCall`, `handleToolResultPersist`, `handleBeforeMessageWrite`) with realistic OpenClaw-shaped inputs. Calls `register()` with a mock `PluginApi` pointing at a temp vault directory to initialize module-level state, then invokes captured handlers directly.

Key scenarios:
- `after_tool_call` parsing of OpenClaw's wrapped result format `{content: [{type: "text", text: "..."}], details: {url, targetId}}`
- Tab URL caching from navigate results → domain-pin validation on subsequent act/type calls
- `tool_result_persist` scrubbing credentials from structured message content
- `before_message_write` scrubbing outbound text
- Full inject→audit→scrub cycle through the real hook pipeline

This test file caught the bug where `after_tool_call` expected flat `{url, targetId}` at the result top level but OpenClaw wraps results in `{content: [...], details: {...}}`.

### `tests/browser-password-e2e.test.ts` (8 tests)

Tests the complete browser password flow: navigate (populates URL cache) → act/type with `$vault:name` placeholder → domain-pin check → credential injection. Validates the `browserTabUrls` workaround for missing URL in `act`/`type` params.

## Notes

- `vault add` coverage reflects the current `--use` flow (`api`, `cli`, `browser-login`, `browser-session`) and strict `--yes` validation.
- Browser-session coverage includes:
  - inline cookie JSON via `--key`
  - file path via `--key`
  - raw cookie strings (`name=value`) via `--key`
  - re-prompt behavior for invalid/empty interactive input
  - plaintext source warning behavior
  - prompt for cookie name when `--key` is a plain value (no `=` sign)
- Scrub pattern detection: auto-detection with Y/n confirm, manual regex prompt when auto-detection is declined or skipped
