# AGENTS.md — Build Instructions

## What to build
Read SPEC.md — it's the v4.3 architecture spec. Build Phase 1 (TypeScript only, same-user mode).

## Architecture Reference
- SPEC.md is the TDD (Technical Design Document) — follow it exactly
- If you run into issues or design questions, document them in ISSUES.md — do NOT change the design
- Plugin hooks to use: `before_tool_call`, `after_tool_call`, `tool_result_persist`, `message_sending` via `api.on(...)`
- Plugin manifest: `openclaw.plugin.json` with `id` and `configSchema`
- Plugin entry: export a function `(api) => { ... }` or object with `register(api)`
- SDK import: `openclaw/plugin-sdk/core` for plugin APIs
- CLI registration: `api.registerCli(({ program }) => { ... }, { commands: [...] })`

## Build Order (Phase 1 only)
1. **Scaffold**: package.json, tsconfig.json, openclaw.plugin.json, directory structure
2. **Encryption layer**: AES-256-GCM + Argon2id, encrypt/decrypt functions, file format [salt][nonce][ciphertext][tag]
3. **Tool registry**: known tools config (Stripe/GitHub/Gumroad), pattern matching, tools.yaml read/write
4. **CLI commands**: vault init, vault add, vault list, vault show, vault rotate, vault remove, vault test, vault audit
5. **Plugin hooks**: before_tool_call (credential injection), after_tool_call + tool_result_persist (output scrubbing), message_sending (outbound scrubbing)
6. **Hot-reload**: SIGUSR2 handler in plugin, CLI sends signal after config changes
7. **Tests**: Unit tests for encryption, pattern matching, scrubbing. Use vitest or jest.

## Key Design Decisions
- Vault storage: `~/.openclaw/vault/<tool>.enc` (encrypted files, one per credential)
- Config: `~/.openclaw/vault/tools.yaml` (injection rules + scrubbing patterns)
- Master key: derived from passphrase via Argon2id OR machine-specific key
- Hook priority: 10 (high priority = runs first)
- Scrub replacement text: `[VAULT:<tool-name>]`
- Gateway PID file: `~/.openclaw/gateway.pid` for SIGUSR2

## File Structure Target
```
openclaw-credential-vault/
├── openclaw.plugin.json
├── package.json
├── tsconfig.json
├── src/
│   ├── index.ts              # Plugin entry point, hook registration
│   ├── crypto.ts             # AES-256-GCM encrypt/decrypt + Argon2id
│   ├── registry.ts           # Known tools registry + pattern matching
│   ├── scrubber.ts           # Output scrubbing logic
│   ├── config.ts             # tools.yaml read/write + hot-reload
│   ├── cli.ts                # CLI command registration (vault add/list/etc)
│   └── types.ts              # TypeScript interfaces
├── tests/
│   ├── crypto.test.ts
│   ├── registry.test.ts
│   ├── scrubber.test.ts
│   └── config.test.ts
└── SPEC.md                   # Architecture reference (do not modify)
```

## Rules
- Do NOT modify SPEC.md
- If something in the spec is unclear or seems wrong, note it in ISSUES.md
- Write tests for every module
- Use Node.js crypto module for AES-256-GCM
- Use the `argon2` npm package for Argon2id
- Use `yaml` npm package for tools.yaml
- TypeScript strict mode
- No external dependencies beyond what's needed (keep it minimal)

## Completion
When done, run all tests and report results. Run `openclaw system event --text "Done: credential-vault Phase 1 build complete. Tests: [pass/fail count]" --mode now` to notify.
