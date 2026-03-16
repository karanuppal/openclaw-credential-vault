# Testing

Current baseline (latest full run):

- **34 test files**
- **658 tests**
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
- `tests/env-scrub.test.ts` — 26
- `tests/false-positives.test.ts` — 37
- `tests/format-guessing.test.ts` — 17
- `tests/guesser.test.ts` — 45
- `tests/hooks.test.ts` — 12
- `tests/interactive-flow.test.ts` — 8
- `tests/literal-scrub.test.ts` — 12
- `tests/performance.test.ts` — 21
- `tests/perl-scrubber.test.ts` — 30
- `tests/registry.test.ts` — 22
- `tests/resolver-versioning.test.ts` — 35
- `tests/rotation.test.ts` — 19
- `tests/sandbox-e2e.test.ts` — 9
- `tests/scrubber-advanced.test.ts` — 26
- `tests/scrubber.test.ts` — 18
- `tests/subagent-isolation.test.ts` — 8
- `tests/usage-config.test.ts` — 23
- `tests/write-edit-scrub.test.ts` — 13

Total: **658** tests.

## Coverage map (high level)

- **Core crypto + config:** `crypto.test.ts`, `config.test.ts`, `cross-compat.test.ts`
- **Credential format + vault add UX:** `guesser.test.ts`, `format-guessing.test.ts`, `usage-config.test.ts`, `interactive-flow.test.ts`, `cli-use-flag.test.ts`, `browser-session-e2e.test.ts`
- **Injection + hooks:** `registry.test.ts`, `hooks.test.ts`, `e2e.test.ts`, `sandbox-e2e.test.ts`
- **Scrubbing:** `scrubber.test.ts`, `scrubber-advanced.test.ts`, `literal-scrub.test.ts`, `env-scrub.test.ts`, `perl-scrubber.test.ts`
- **Browser credentials:** `browser.test.ts`, `browser-password.test.ts`, `browser-cookie.test.ts`, `browser-session-e2e.test.ts`, `cli-browser.test.ts`
- **Adversarial/security:** `adversarial.test.ts`, `false-positives.test.ts`, `write-edit-scrub.test.ts`, `compaction-scrub.test.ts`, `subagent-isolation.test.ts`, `concurrent.test.ts`
- **Operations/audit:** `audit.test.ts`, `audit-log.test.ts`, `rotation.test.ts`, `cli-logs-display.test.ts`, `resolver-versioning.test.ts`
- **Performance:** `performance.test.ts`

## Notes

- `vault add` coverage reflects the current `--use` flow (`api`, `cli`, `browser-login`, `browser-session`) and strict `--yes` validation.
- Browser-session coverage includes:
  - inline cookie JSON via `--key`
  - file path via `--key`
  - re-prompt behavior for invalid/empty interactive input
  - plaintext source warning beha[VAULT:gmail-app]tion is declined or skipped
