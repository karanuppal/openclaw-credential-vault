# Changelog

## 1.0.0-beta.5

### Much simpler way to add credentials

`vault add` now asks one question: **how will you use this credential?**

```
$ openclaw vault add my-service --key sk_...
How will this credential be used?
  1) API calls (HTTP headers)
  2) CLI tool (environment variable)
  3) Browser login (password fill)
  4) Browser session (cookies)
```

Pick a number and answer 1-2 follow-up questions. That's it — injection rules, scrubbing patterns, and domain pins are all configured automatically.

**Non-interactive mode** works too:
```
vault add github --key ghp_... --use cli --command "gh *" --env GH_TOKEN --yes
vault add resy --key sk-... --use api --url "*.resy.com*" --yes
vault add my-site --key hunter2 --use browser-login --domain .example.com --yes
```

### Browser credential support

Two new credential types:

- **Browser login** — Store a password, and the vault fills it in automatic[VAULT:gmail-app]t visits the right domain. Domain-pinned: credentials only inject on allowed sites.
- **Browser session** — Import cookies (from a JSON file, inline, or raw `name=value` strings) and the vault injects them when the agent navigates to matching domains. Source cookie files are securely deleted after import.

### Security hardening

- Debug logging gated behind `OPENCLAW_VAULT_DEBUG` env var (no longer leaks tab IDs/URLs to stderr)
- Browser tab URL cache only trusts structured data from OpenClaw, not parseable tool output text (prevents cache poisoning)
- `--yes` mode now auto-deletes plaintext cookie files after encryption (previously left them on disk)

### Under the hood

- Fixed browser credential injection failing after gateway restart (tab URL cache wasn't populated from OpenClaw's wrapped result format)
- Known tool names (e.g., `resy`, `gumroad`) auto-configure with correct injection rules
- 700 tests across 36 files (was 616 / 34)

---

## 1.0.0-beta.4

- Fixed `vault add` for password/unknown credential formats — now correctly creates exec injection rules

## 1.0.0-beta.3

- Documentation refresh: README, ARCHITECTURE, TESTING, SECURITY-AUDIT, platform-support
- Install verification job added to CI

## 1.0.0-beta.2

- Multi-hook scrubbing pipeline (after_tool_call, tool_result_persist, before_message_write, message_sending)
- Write/edit tool interception — credentials scrubbed before the agent can save them to files
- Audit logging for all credential access events
- Performance: <25ms scrubbing for 1MB output

## 1.0.0-beta.1

- Initial release: AES-256-GCM encryption, Argon2id key derivation
- Exec and web_fetch credential injection
- Pattern-based output scrubbing
- CLI: vault add, remove, list, show, rotate, logs
