# `vault add` UX Overhaul — Design Spec

_Branch: `fix/vault-add-ux-overhaul`_
_Status: DRAFT — awaiting review_

---

## The Problem

`vault add` is the first thing every user does. If it doesn't work, nothing works. Today it's broken in several ways:

### Bug: Password credentials get no injection or scrub rules

When you add a password, the guesser returns `suggestedInject: []` and `suggestedScrub: []`. The user answers all the prompts (service name, env var, command match), but `buildToolConfigFromGuess` only *modifies* existing rules — it can't *create* rules from scratch. All user-provided answers are silently dropped. The credential is stored encrypted but completely inert — no injection, no scrubbing.

### UX: Questions don't match the user's mental model

The flow asks developer-facing questions that don't map to how users think about credentials:

- **"CLI tool name?"** — Most password credentials are for browser-based services. The user doesn't have a CLI tool. They skip this, and the flow loses the only path that creates an exec rule.
- **"Command pattern to match?"** — The user has no idea what this means. They typed a password for Gumroad. What command pattern?
- **"Environment variable name?"** — Again, the user is thinking "I want my agent to log into Gumroad." They don't know what env var to use.

The questions are implementation details of the injection system, not user-facing concepts.

### UX: No opportunity to configure scrubbing

The flow never asks about scrub patterns. For known-prefix credentials (GitHub, Stripe), scrub patterns come from the template. For everything else, there's no mechanism to add them. The user has no idea that their password won't be scrubbed from output.

### UX: The guessing is backwards

The guesser detects the credential *format* (JWT, password, API key) and uses it to predict *how it's used*. But format ≠ usage:

- A JWT might be a Bearer token, a custom header, or a cookie value
- A password might be for browser login, CLI auth, or an API key that happens to look short
- A "generic API key" might be used as a header, env var, or query parameter

The guesser should tell the user what it detected, then ask **how they plan to use it** — not assume.

### UX: Three different question paths (Y/edit/needsPrompt)

Depending on whether you hit "Y", "edit", or the automatic `needsPrompt` path, you get different questions. Some paths create rules, some don't. The user can't predict which path they're on or what questions to expect.

---

## How Users Actually Think About Adding Credentials

When a user runs `vault add`, they're thinking:

1. **"I have a credential"** — they know what it is (a password, an API key, a token)
2. **"I want my agent to use it for X"** — they know the service (Gumroad, Resy, GitHub)
3. **"Make it work"** — they don't care about env vars, command patterns, or injection types

The questions should follow this mental model, not the vault's internal architecture.

---

## Current Flow Analysis

### What the guesser detects and what happens for each format:

| Format | suggestedInject | suggestedScrub | Questions Asked | Result |
|--------|----------------|----------------|-----------------|--------|
| Known prefix (ghp_, sk-...) | ✅ Full from template | ✅ From template | None (auto) | ✅ Works |
| JWT | ⚠️ `[web_fetch Bearer]` | ✅ Pattern | Service name, API URL, CLI tool | ⚠️ Only works if Bearer is correct |
| JSON blob | ❌ Empty | ❌ Empty | Service name, API URL, CLI tool, injection type | ❌ Broken (same as password) |
| Password | ❌ Empty | ❌ Empty | Service name, injection type; env var + match | ❌ Broken (overrides have nothing to modify) |
| Generic API key | ✅ `[exec with env]` | ✅ Pattern | Service name, API URL, CLI tool; env var + match | ⚠️ Works but questions are confusing |
| Unknown | ❌ Empty | ❌ Empty | Service, API URL, CLI tool, injection type; env var + match | ❌ Broken (same as password) |

**3 out of 6 paths are completely broken.** They store the credential but create no injection or scrub rules.

---

## New Design

### Principle: Ask about usage, not implementation

Instead of asking "What env var name?" and "What command pattern?", ask **"How will your agent use this credential?"** and derive the implementation details automatically.

### The New Flow

```
$ openclaw vault add gumroad --key "my-secret-password"

✓ Credential encrypted and stored.

How will your agent use this credential?

  1. API calls (HTTP requests to a web service)
  2. CLI tool (command-line program like gh, aws, gcloud)
  3. Browser login (fill username/password on a website)
  4. Browser session (use cookies from a logged-in session)
  5. Script/automation (env variable for custom scripts)

Choose one or more (comma-separated) [1]: 
```

Then follow-up questions are **specific to each usage type**:

#### If user picks 1 (API calls):

```
API calls:
  API domain or URL pattern: api.gumroad.com
  Header name [Authorization]: 
  Include "Bearer" prefix? [Y/n]: y

✓ HTTP injection: Authorization: Bearer on *api.gumroad.com/*
```

Generated rule:
```yaml
- tool: web_fetch
  urlMatch: "*api.gumroad.com/*"
  headers:
    Authorization: "Bearer $vault:gumroad"
```

#### If user picks 2 (CLI tool):

```
CLI tool:
  Command name: gumroad-cli
  Environment variable [GUMROAD_API_KEY]: GUMROAD_TOKEN

✓ CLI injection: GUMROAD_TOKEN for gumroad-cli* commands
```

Generated rule:
```yaml
- tool: exec
  commandMatch: "gumroad-cli*"
  env:
    GUMROAD_TOKEN: "$vault:gumroad"
```

#### If user picks 3 (Browser login):

```
Browser login:
  Website domain: .gumroad.com

✓ Browser password configured for *.gumroad.com
  Agent will use $vault:gumroad in browser tool text params
```

Generated rule:
```yaml
- tool: browser
  type: browser-password
  domainPin: [".gumroad.com"]
  method: fill
```

#### If user picks 4 (Browser session):

```
Browser session:
  Cookie domain: .gumroad.com
  Paste cookies (JSON or Netscape format, Ctrl+D when done):
```

(This is the existing browser-cookie flow, just better integrated.)

#### If user picks 5 (Script/automation):

```
Script/automation:
  Environment variable [GUMROAD_PASSWORD]: GUMROAD_PASSWORD
  Command pattern to inject on [*gumroad*]: *gumroad*

✓ Script injection: GUMROAD_PASSWORD for *gumroad* commands
```

Generated rule:
```yaml
- tool: exec
  commandMatch: "*gumroad*"
  env:
    GUMROAD_PASSWORD: "$vault:gumroad"
```

#### After usage selection — Scrub patterns:

```
Scrub patterns protect against credential leakage in agent output.
Auto-detected scrub pattern: (none — literal value match will be used)

Add a custom regex pattern? (e.g., gum_[a-zA-Z0-9]{32}) [N/y]: 
```

**Literal scrubbing is ALWAYS enabled** — the exact credential value is always added to the literal scrub set, regardless of what the user answers here. The regex question is for additional pattern-based scrubbing (catching similar-looking credentials).

#### Final summary:

```
Summary for "gumroad":
  ✓ Credential: encrypted (AES-256-GCM)
  ✓ Injection: API calls → Authorization: Bearer on *api.gumroad.com/*
  ✓ Injection: CLI → GUMROAD_TOKEN for gumroad-cli* commands
  ✓ Scrubbing: literal match (always on)
  ✓ Scrubbing: 1 custom regex pattern

Confirm? [Y/n]: 
```

### What the Guesser Now Does

The guesser's role changes from "predict how the credential is used" to **"detect the format and suggest a default usage type"**:

| Format | Default Usage Suggestion | Default Selection |
|--------|------------------------|-------------------|
| Known prefix (ghp_, sk-) | Auto-configured, skip the flow | No questions |
| JWT | "This is a JWT. Commonly used for API calls." | Pre-select option 1 |
| JSON blob | "This looks like session data." | Pre-select option 4 |
| Password | "This looks like a password." | Pre-select option 3 |
| Generic API key | "This looks like an API key." | Pre-select option 1 |
| Unknown | "Couldn't auto-detect format." | No pre-selection |

The guesser **suggests** but the user **decides**. If the guesser says "API calls" and the user changes to "Browser login", that works. Today, the guesser decides and the user can't override without manually editing tools.yaml.

### What `buildToolConfigFromGuess` Becomes

Rename to `buildToolConfig`. It takes the usage selections and answers directly, not a `GuessResult` + overrides. No more "find existing rule and modify" logic — it builds rules from scratch based on what the user chose.

```typescript
interface UsageSelection {
  apiCalls?: {
    urlPattern: string;
    headerName: string;       // default: "Authorization"
    headerFormat: string;     // default: "Bearer $token"
  };
  cliTool?: {
    commandName: string;
    envVar: string;
  };
  browserLogin?: {
    domain: string;
  };
  browserSession?: {
    domain: string;
    cookies: PlaywrightCookie[];
  };
  scriptEnv?: {
    envVar: string;
    commandMatch: string;
  };
  scrubPatterns?: string[];   // user-provided regex patterns
}

function buildToolConfig(
  toolName: string,
  usage: UsageSelection
): { inject: InjectionRule[]; scrub: ScrubConfig }
```

This function always produces correct output because it creates rules directly from structured input — no empty-array modification bugs possible.

### Literal Scrubbing: Always On

Today, literal scrubbing (matching the exact credential value in output) happens only if the credential was decrypted during injection. This is correct — but the user should know about it.

For regex-based scrubbing, the guesser can still suggest patterns for known formats (e.g., `ghp_[a-zA-Z0-9]{36}` for GitHub PATs). For unknown formats, the user gets a chance to add custom patterns. If they don't, literal scrubbing is the fallback — which is honestly fine for most credentials.

### Non-Interactive Mode

```bash
# API calls with custom header
openclaw vault add resy --key "eyJ..." \
  --use api \
  --header x-resy-auth-token \
  --no-bearer \
  --url "*api.resy.com/*"

# CLI tool
openclaw vault add github --key "ghp_..." \
  --use cli \
  --cli-command gh \
  --env GH_TOKEN

# Browser login
openclaw vault add amazon --key "p@ssw0rd" \
  --use browser-login \
  --domain .amazon.com

# Multiple usages
openclaw vault add myservice --key "abc123" \
  --use api,cli \
  --url "*api.myservice.com/*" \
  --cli-command myctl \
  --env MYSERVICE_TOKEN

# Skip all prompts with auto-detection
openclaw vault add stripe --key "sk_live_..." --yes
```

The `--use` flag maps directly to the usage types. Multiple values are comma-separated. Each usage type's flags are only required when that usage is selected.

### Known Prefix (Auto-Config) — No Change

For credentials with recognized prefixes (ghp_, sk-, sk-ant-, etc.), the flow works perfectly today. No questions, full auto-config. This stays exactly the same.

---

## Backward Compatibility

- `--type browser-password` and `--type browser-cookie` continue to work as before (they bypass the new flow)
- `--yes` auto-accepts the guesser's suggestion without prompts (same as today, but the guesser now suggests a usage type, not implementation details)
- `tools.yaml` format is unchanged — the new flow produces the same `InjectionRule` structures
- Existing credentials are not affected

---

## Implementation Plan

### Phase 1: Fix the bug (can ship immediately)

1. `buildToolConfigFromGuess`: When overrides provide `envVarName`/`commandMatch` but no exec rule exists, **create one** instead of silently dropping
2. Password/unknown guesser: Always generate a literal scrub entry (the credential value is always scrubbed)
3. Post-add validation: If `inject.length === 0` after building, warn explicitly

### Phase 2: New interactive flow

4. Replace the prompt logic in `cli.ts` with the usage-type selection flow
5. New `buildToolConfig` function that creates rules from `UsageSelection` (not overrides on empty arrays)
6. Custom header support (header name + format prompts)
7. Scrub pattern prompt (always show, explain literal vs regex)
8. Summary display before confirmation

### Phase 3: CLI flags

9. `--use` flag with usage types
10. `--header`, `--no-bearer`, `--url`, `--cli-command`, `--env`, `--domain` flags
11. Multiple `--use` values for multi-injection

### Phase 4: Tests + docs

12. Test every usage type path
13. Test multi-usage combinations
14. Test non-interactive mode
15. Update README, SPEC

---

## Open Questions

1. **Should "Script/automation" (option 5) be separate from "CLI tool" (option 2)?** They both create exec injection rules. The difference: CLI tool asks for a command name (e.g., `gh`), script asks for a pattern (e.g., `*deploy*`). Could merge them into one option with a follow-up question.

2. **Should the guesser still try to auto-detect known services by name?** E.g., `vault add resy --key "eyJ..."` could match a "resy" template even though `eyJ` isn't a known prefix. Today this doesn't happen. The browser credential UX spec proposes adding named templates — that work would layer on top of this.

3. **Should Phase 1 (bug fix) ship on `main` before the overhaul?** It's a one-line fix that unblocks password/unknown credentials immediately. The overhaul is bigger and will take longer.
