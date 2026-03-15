# `vault add` UX Overhaul — Design Spec (Phases 2–4)

_Branch: `fix/vault-add-ux-overhaul`_
_Status: DRAFT — awaiting review_
_Phase 1 (bug fix) shipped in 1.0.0-beta.4_

---

## What Phase 1 Fixed (shipped)

`buildToolConfigFromGuess` silently dropped user answers when `suggestedInject` was empty (passwords, unknown formats). Fixed: overrides now create exec rules from scratch. 6 regression tests added. This makes the existing flow *functional* but doesn't fix the UX problems.

## What's Still Wrong

### 1. Questions don't match how users think

The flow asks:
- *"CLI tool name?"* — irrelevant for browser-based services
- *"Command pattern to match?"* — implementation detail the user doesn't understand
- *"Environment variable name?"* — another implementation detail

Users think: *"I have a Gumroad password. I want my agent to use it."* They don't think in env vars and glob patterns.

### 2. No scrub pattern configuration

The flow never mentions scrubbing. Known-prefix credentials get auto-scrub patterns from templates. Everything else gets nothing — the user doesn't know their password could leak into agent output.

### 3. Format ≠ Usage

The guesser detects *what the credential looks like* (JWT, password, API key) and uses that to decide *how it's injected*. But:
- A JWT can be a Bearer token, a custom header (`x-resy-auth-token`), a cookie, or an env var
- A password can be for browser login, CLI auth, or an API secret
- A "generic API key" can be a header, env var, or query parameter

Format detection should inform the *default suggestion*, not the *final decision*.

### 4. Three different question paths

Depending on Y/edit/needsPrompt, you get different questions. Some paths create rules, some don't. Unpredictable.

### 5. No final summary

The user never sees a confirmation of exactly what was configured before it's written. If something is wrong, the only way to know is `vault show` after the fact.

---

## How Users Think About Adding Credentials

1. *"I have a credential"* — they know what it is
2. *"I want my agent to use it for service X"* — they know the service
3. *"Make it work"* — they don't care about injection mechanics

The new flow follows this mental model.

---

## New Flow Design

### Step 1: Encrypt and detect

```
$ openclaw vault add gumroad --key "my-secret-password"

✓ Credential encrypted and stored (AES-256-GCM)
  Detected: password (short string)
```

Always encrypt first. Detection is informational — tells the user what we see, doesn't drive the flow.

### Step 2: Usage selection

```
How will your agent use this credential?

  1. API calls     — HTTP requests to a web service
  2. CLI tool      — command-line programs (gh, aws, curl)
  3. Browser login — fill a password on a website
  4. Browser session — use cookies from a logged-in session

Choose one or more (comma-separated) [3]: 
```

The default is pre-selected based on format detection:
- Password → default 3 (browser login)
- JWT → default 1 (API calls)
- JSON blob → default 4 (browser session)
- Generic API key → default 2 (CLI tool)
- Known prefix → skip entirely (auto-configured)
- Unknown → no default

Note: "Script/automation" is merged into "CLI tool" — both create exec rules, just with different follow-up questions. If the user picks CLI and doesn't have a specific command name, the flow falls back to a general env var + pattern.

### Step 3: Usage-specific follow-ups

Each selection has 2-3 targeted questions:

**API calls (1):**
```
  API domain or URL: api.gumroad.com
  Header name [Authorization]: 
  Value format [Bearer <token>]: 
```

Defaults: `Authorization` header, `Bearer <token>` format. User overrides for custom headers.

**CLI tool (2):**
```
  CLI command name (or press Enter for general scripts): gumroad-cli
  Environment variable [GUMROAD_API_KEY]: GUMROAD_TOKEN
```

If no command name given, asks for a general command pattern (`*gumroad*`).

**Browser login (3):**
```
  Website domain: .gumroad.com
```

One question. Domain pinning configured automatically.

**Browser session (4):**
```
  Cookie domain: .gumroad.com
  Paste cookies (JSON or Netscape format, Ctrl+D when done):
```

Existing cookie flow, integrated into the new menu.

### Step 4: Scrubbing

```
Output scrubbing (protects against credential leakage):
  ✓ Literal match: always active — your exact credential value will be
    redacted from all agent output, messages, and transcripts.
  
  Add a regex pattern to also catch similar credentials? [N/y]:
```

Literal scrubbing is always on and the user is told. Regex is optional and explained.

### Step 5: Summary + confirm

```
Summary for "gumroad":
  ✓ Encrypted:  AES-256-GCM
  ✓ Injection:  browser login on .gumroad.com
  ✓ Scrubbing:  literal match (always active)

Save? [Y/n]:
```

User sees exactly what was configured. If wrong, they can say no and redo.

---

## Implementation Details

### New `buildToolConfig` function

Replaces `buildToolConfigFromGuess`. Takes structured `UsageSelection` input, creates rules from scratch. No "find and modify" pattern.

```typescript
interface UsageSelection {
  apiCalls?: {
    urlPattern: string;      // e.g., "*api.gumroad.com/*"
    headerName: string;      // e.g., "Authorization" or "x-resy-auth-token"
    headerFormat: string;    // e.g., "Bearer $token" or "$token"
  };
  cliTool?: {
    commandName?: string;    // e.g., "gh" — optional
    commandMatch?: string;   // e.g., "*gumroad*" — used when no specific command
    envVar: string;          // e.g., "GUMROAD_TOKEN"
  };
  browserLogin?: {
    domain: string;          // e.g., ".gumroad.com"
  };
  browserSession?: {
    domain: string;
    cookies: PlaywrightCookie[];
  };
  scrubPatterns: string[];   // user-provided regex patterns (can be empty)
}
```

Each usage type maps to exactly one `InjectionRule`. The function always produces correct, complete output.

### Guesser changes

The guesser's return type gets a new field:

```typescript
interface GuessResult {
  // ... existing fields ...
  suggestedUsage: number[];  // which usage types to pre-select (1-4)
}
```

The guesser no longer generates `suggestedInject` for non-known-prefix formats. It just says "this looks like a JWT, suggest API calls" and the new flow takes it from there.

Known-prefix formats still generate full `suggestedInject` + `suggestedScrub` and skip the flow entirely — that path is not changing.

### CLI prompt refactor

The current tangle of `if (confirmLower === "edit")` / `if (guess.needsPrompt)` / `if (guess.confidence === "low")` branches is replaced with a single linear flow:

1. Detect format
2. Show detection result
3. Show usage menu with pre-selected default
4. Collect usage-specific answers
5. Ask about scrub patterns
6. Show summary
7. Confirm and write

One path. Same questions every time (except the follow-ups vary by usage type). Predictable.

---

## Non-Interactive Mode (CLI Flags)

```bash
# API calls with custom header
openclaw vault add resy --key "eyJ..." \
  --use api --header x-resy-auth-token --no-bearer --url "*api.resy.com/*"

# CLI tool
openclaw vault add github --key "ghp_..." \
  --use cli --command gh --env GH_TOKEN

# Browser login
openclaw vault add amazon --key "p@ssw0rd" \
  --use browser-login --domain .amazon.com

# Multiple usages
openclaw vault add myservice --key "abc123" \
  --use api,cli --url "*api.myservice.com/*" --command myctl --env MYSERVICE_TOKEN

# Auto-detect (known prefix)
openclaw vault add stripe --key "sk_live_..." --yes
```

| Flag | Usage type | Description |
|------|-----------|-------------|
| `--use <types>` | All | Comma-separated: `api`, `cli`, `browser-login`, `browser-session` |
| `--url <pattern>` | API | URL match pattern for header injection |
| `--header <name>` | API | Custom header name (default: `Authorization`) |
| `--no-bearer` | API | Don't prepend "Bearer " to value |
| `--command <name>` | CLI | CLI command name for command matching |
| `--env <name>` | CLI | Environment variable name |
| `--domain <domain>` | Browser | Domain for login or cookie pinning |
| `--scrub-pattern <regex>` | All | Add a regex scrub pattern |

When `--use` is provided, all required flags for that usage type must also be provided. Missing required flags → error with clear message.

---

## Backward Compatibility

- `--type browser-password` and `--type browser-cookie` still work — they bypass the new flow
- `--yes` still auto-accepts for known-prefix credentials
- `tools.yaml` format unchanged — same `InjectionRule` structures
- Old `buildToolConfigFromGuess` kept as internal fallback for `--yes` mode with non-known formats
- Existing stored credentials are not affected

---

## Implementation Plan

### Phase 2: New interactive flow
1. New `UsageSelection` type and `buildToolConfig` function
2. Usage-type menu with format-based defaults
3. Usage-specific follow-up prompts (API, CLI, browser-login, browser-session)
4. Custom header support (header name + format)
5. Scrub pattern prompt with literal match explanation
6. Summary display before confirmation
7. Wire into `cli.ts`, replacing the current prompt branches

### Phase 3: CLI flags
8. `--use` flag parsing and validation
9. Per-usage-type flags (`--header`, `--url`, `--command`, `--env`, `--domain`, `--no-bearer`, `--scrub-pattern`)
10. Flag validation: required flags per usage type, error messages
11. Flag combinations for multi-usage (`--use api,cli`)

### Phase 4: Tests + docs
12. Unit tests for `buildToolConfig` — one test per usage type, one per combination
13. Integration tests: interactive flow simulation (mock stdin)
14. Integration tests: non-interactive flag mode
15. Edge case tests: missing flags, invalid combinations, backward compat
16. Update README commands table
17. Update SPEC CLI reference
18. Update TESTING.md with new test counts

---

## Open Questions

1. **Should `--yes` with non-known-prefix credentials use the guesser's suggested default?** Today `--yes` accepts whatever the guesser suggests (which may be wrong). With the new flow, `--yes` would accept the format-based default usage type and use auto-generated values for follow-up questions. This is better than today but still potentially wrong. Alternative: require `--use` when `--yes` is used with non-known formats.

2. **Should the guesser try to match templates by tool name?** `vault add resy --key "eyJ..."` could auto-configure if a "resy" template exists in the registry. This is the browser credential UX spec's proposal — it layers on top of this overhaul.
