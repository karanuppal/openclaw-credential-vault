# Release Notes — 1.0.0-beta.4

## Bug fix: `vault add` for passwords and unknown credential formats

`vault add` with a password or unrecognized credential format was storing the credential correctly (encrypted) but silently creating **zero injection rules and zero scrub patterns**. The credential was inert — stored but never used.

**What was happening:** When the guesser couldn't auto-detect the format (passwords, short strings, unknown formats), it returned an empty set of suggested injection rules. The user would answer all the prompts — env var name, command match pattern — but `buildToolConfigFromGuess` could only *modify* existing rules, not create new ones. With nothing to modify, the user's answers were silently dropped.

**What's fixed:** When user-provided overrides (env var name, command match) are given and no injection rule exists, one is now created from the override values. 6 regression tests added to prevent this from recurring.

**Affected users:** Anyone who added a credential that wasn't auto-detected by prefix (ghp_, sk-, etc.) and answered the interactive prompts. If you previously added credentials that aren't working, remove and re-add them:

```bash
openclaw vault remove <tool> --purge
openclaw vault add <tool> --key "<credential>"
```

---

Full test suite: 616 tests across 30 files, all passing.
