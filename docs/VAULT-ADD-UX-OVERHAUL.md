# `vault add` UX Overhaul — Design Spec (Phases 2–5)

_Branch: `fix/vault-add-ux-overhaul`_
_Status: Addressing PR #2 review comments_
_Phase 1 (bug fix) shipped in 1.0.0-beta.4_

---

## What Phase 1 Fixed (shipped)

`buildToolConfigFromGuess` silently dropped user answers when `suggestedInject` was empty (passwords, unknown formats). Fixed: overrides now create exec rules from scratch. 6 regression tests added. This makes the existing flow *functional* but doesn't fix the UX problems.

## What's Still Wrong

### 1. Questions don't match how users think

Users think: *"I have a Gumroad password. I want my agent to log into Gumroad."*
The flow asks: *"CLI tool name? Command pattern? Environment variable name?"*

### 2. Password defaults to exec-env — wrong for browser logins

Most passwords are for website login, not CLI tools. But the flow doesn't offer browser-password as an option — it defaults to exec injection, which doesn't help with browser-based login at all.

### 3. Browser types exist but are hidden

`--type browser-password` and `--type browser-cookie` work fully (domain pinning, `$vault:` resolution, cookie injection). But they're only accessible via explicit flags. The interactive flow never mentions them.

### 4. No scrub pattern configuration or explanation

The flow never mentions scrubbing. Users don't know if their credential will be caught in output. Literal scrubbing happens automatically (in-memory, at injection time — never stored in tools.yaml), but the user isn't told.

### 5. Format ≠ Usage

JWT → assumes Bearer. But JWTs are used as custom headers, cookies, env vars. The guesser should suggest, the user should decide.

---

## How Each Injection Type Actually Works

Important context for the design — each usage type has a different injection mechanism:

| Usage Type | Injection Mechanism | How It Works |
|-----------|---------------------|--------------|
| API calls | `params.headers` | HTTP headers added to web_fetch requests |
| CLI tool | `params.env` | Environment variables passed to subprocess spawn + Perl stdout scrubber |
| Browser login | `$vault:` in `params.text` | Placeholder resolved to real password; domain-pinned; blocked if wrong domain |
| Browser session | `params._vaultCookies` | Cookie array injected on browser navigate actions |

These are all separate code paths in `before_tool_call`. The new [VAULT:gmail-app]ces to the correct mechanism automatically.

**Critical: Literal scrubbing architecture.** The actual credential value is NEVER stored in tools.yaml or any config file. tools.yaml only stores regex patterns (like `ghp_[a-zA-Z0-9]{36}`). Literal scrubbing works from an in-memory cache: when a credential is decrypted for injection, the value is cached in `credentialCache` and used for literal string matching in `after_tool_call`. The Perl scrubber uses the value base64-encoded. No plaintext credential in any stored config.

---

## New Flow Design

### Step 1: Encrypt and detect

```
$ openclaw vault add gumroad --key "my-secret-password"

✓ Credential encrypted and stored (AES-256-GCM)
  Detected: password (short string)
```

Always encrypt first. Detection is informational.

### Step 2: Usage selection

```
How will your agent use this credential?

  1. API calls      — HTTP requests to a web service
  2. CLI tool       — command-line programs (gh, aws, curl)
  3. Browser login  — fill a password on a website
  4. Browser session — use cookies from a logged-in session

Choose one or more (comma-separated) [3]: 
```

Default pre-selected based on format:
- Password → default 3 (browser login)
- JWT → default 1 (API calls)
- JSON blob → default 4 (browser session)
- Generic API key → default 1 (API calls)
- Known prefix → skip entirely (auto-configured from template)
- Known tool name → skip if template exists (e.g., `vault add resy` matches `resy` template)
- Unknown → no default

### Step 3: Usage-specific follow-ups

**API calls (1):**
```
  API domain or URL: api.gumroad.com
  Header name [Authorization]: 
  Value format [Bearer <token>]: 
```
Defaults to `Authorization: Bearer`. User overrides for custom headers.

**CLI tool (2):**
```
  CLI command name (or Enter for general scripts): gumroad-cli
  Environment variable [GUMROAD_API_KEY]: GUMROAD_TOKEN
```
If no command name, asks for a command pattern.

**Browser login (3):**
```
  Website domain: .gumroad.com
```
One question. Domain pinning configured automatically. Agent uses `$vault:gumroad` in bro[VAULT:gmail-app]ms.

**Browser session (4):**
```
  Cookie domain: .gumroad.com
  Path to cookies file (JSON or Netscape format): /path/to/cookies.json
```
Accepts a file path instead of pasting. Simpler and doesn't require users to know Ctrl+D.

### Step 4: Scrubbing

```
Output scrubbing (protects against credential leakage):
  ✓ Literal match: always active — your exact credential value will be
    redacted from all agent output, messages, and transcripts.
    (Stored in memory only — never written to config files.)
  
  Add a regex pattern to also catch similar credentials? [N/y]:
```

Literal scrubbing is always on and the user is told. The parenthetical clarifies that the actual value never touches tools.yaml. Regex is optional.

### Step 5: Summary + confirm

```
Summary for "gumroad":
  ✓ Encrypted:  AES-256-GCM
  ✓ Injection:  browser login on .gumroad.com
  ✓ Scrubbing:  literal match (always active)

Save? [Y/n]:
```

---

## Implementation Details

### New `buildToolConfig` function

Replaces `buildToolConfigFromGuess` entirely (no backward compat needed — early beta, clean break). Takes structured `UsageSelection` input, creates rules from scratch.

```typescript
interface UsageSelection {
  apiCalls?: {
    urlPattern: string;      // e.g., "*api.gumroad.com/*"
    headerName: string;      // e.g., "Authorization" or "x-resy-auth-token"
    headerFormat: string;    // e.g., "Bearer $token" or "$token"
  };
  cliTool?: {
    commandName?: string;    // e.g., "gh" — optional
    commandMatch?: string;   // e.g., "*gumroad*" — fallback when no command name
    envVar: string;          // e.g., "GUMROAD_TOKEN"
  };
  browserLogin?: {
    domain: string;          // e.g., ".gumroad.com"
  };
  browserSession?: {
    domain: string;
    cookieFilePath: string;  // path to JSON/Netscape cookie file
  };
  scrubPatterns: string[];   // user-provided regex patterns (can be empty)
}

function buildToolConfig(
  toolName: string,
  usage: UsageSelection
): { inject: InjectionRule[]; scrub: ScrubConfig }
```

Each usage type maps to exactly one `InjectionRule`. No find-and-modify. No empty-array bugs.

### Guesser changes

For non-known-prefix formats, the guesser stops generating `suggestedInject`. It only:
1. Detects the format (JWT, password, API key, etc.)
2. Suggests a default usage type number
3. Generates suggested scrub patterns (for known formats)

Known-prefix and known-name-template matches still auto-configure everything.

### CLI flow refactor

The current tangle of `if (confirmLower === "edit")` / `if (guess.needsPrompt)` branches is replaced with one linear flow:

1. Detect format
2. Show detection result
3. Show usage menu
4. Collect usage-specific answers
5. Ask about scrub patterns
6. Show summary
7. Confirm and write

One path. Predictable. No branching.

### Old code removed

- `buildToolConfigFromGuess` — deleted, replaced by `buildToolConfig`
- `--type browser-password` / `--type browser-cookie` flags — removed, replaced by `--use browser-login` / `--use browser-session`
- Edit/Y/needsPrompt branching — removed, replaced by linear flow
- All prompt hint logic in guesser — simplified to just `suggestedUsage`

---

## Non-Interactive Mode (CLI Flags)

```bash
# API calls with custom header
openclaw vault add resy --key "eyJ..." \
  --use api --header x-resy-auth-token --no-bearer --url "*api.resy.com/*" --yes

# CLI tool
openclaw vault add github --key "ghp_..." \
  --use cli --command gh --env GH_TOKEN --yes

# Browser login
openclaw vault add amazon --key "p@ssw0rd" \
  --use browser-login --domain .amazon.com --yes

# Multiple usages
openclaw vault add myservice --key "abc123" \
  --use api,cli --url "*api.myservice.com/*" --command myctl --env MYSERVICE_TOKEN --yes

# Auto-detect (known prefix — only case where --yes works alone)
openclaw vault add stripe --key "sk_live_..." --yes
```

| Flag | Usage type | Description |
|------|-----------|-------------|
| `--use <types>` | All | Comma-separated: `api`, `cli`, `browser-login`, `browser-session` |
| `--url <pattern>` | api | URL match pattern for header injection |
| `--header <name>` | api | Custom header name (default: `Authorization`) |
| `--no-bearer` | api | Don't prepend "Bearer " to value |
| `--command <name>` | cli | CLI command name for command matching |
| `--env <name>` | cli | Environment variable name |
| `--domain <domain>` | browser-login, browser-session | Domain for login or cookie pinning |
| `--cookie-file <path>` | browser-session | Path to cookie file (JSON or Netscape) |
| `--scrub-pattern <regex>` | All | Add a regex scrub pattern |

**`--yes` rules:**
- Known-prefix credential → works alone (auto-configured)
- Known-name template match → works alone (auto-configured)
- Everything else → requires `--use` with all required flags for that usage type
- If `--yes` used without sufficient info: `Error: --yes requires either a known credential format or --use with all required flags.`

No guessing. No defaults. `--yes` is strictly a convenience for script automation where all info is explicitly provided.

---

## Implementation Plan

### Phase 2: New interactive flow (with unit tests)
1. New `UsageSelection` type and `buildToolConfig` function + unit tests
2. Usage-[VAULT:gmail-app]at-based defaults + unit tests for default selection
3. Usage-specific follow-up prompts (API, CLI, browser-login, browser-session)
4. Custom header support (header name + format) + unit tests
5. Scrub pattern prompt with literal match explanation
6. Summary display before confirmation
7. Wire into `cli.ts`, remove old prompt branches and `buildToolConfigFromGuess`

### Phase 3: CLI flags (with unit tests)
8. `--use` flag parsing and validation + unit tests
9. Per-usage-type flags + unit tests for flag validation
10. Flag combinations for multi-usage (`--use api,cli`) + unit tests
11. `--yes` strict validation + unit tests
12. Known-name template matching (e.g., `vault add resy` auto-configures from registry)

### Phase 4: Integration tests + docs
13. Integration tests: interactive flow simulation (mock stdin)
14. Integration tests: non-interactive flag mode
15. Edge case tests: missing flags, invalid combinations
16. Update README commands table
17. Update SPEC CLI reference
18. Update TESTING.md with new test counts

### Phase 5: Security audit
19. Verify credential value never appears in tools.yaml or any config file
20. Verify domain pinning works for browser-login and browser-session
21. Verify scrubbing covers all injection paths (exec, web_fetch, browser)
22. Verify `$vault:` placeholder resolution is domain-pinned
23. Run full adversarial test suite against new flow
24. Regression check: all 616+ existing tests still pass
