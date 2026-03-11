# Future Work — UX Improvements & Nice-to-Haves

Items collected from real-world usage testing. Prioritized by user impact.

---

## UX Improvements

### 1. Fuzzy match on tool name not found
**Trigger:** `openclaw vault remove gumroad-password` → "not found"
**Current behavior:** Hard fail with no help.
**Desired behavior:** Show fuzzy matches — "Did you mean one of these?"
```
Tool "gumroad-password" not found. Similar tools in vault:
  - gumroad-login
  - gumroad-api
  - gumroad-session
```
**Applies to:** All commands that take a tool name (`show`, `remove`, `rotate`, `test`, `logs --tool`)

### 2. `vault logs --last N` should accept a count
**Trigger:** `openclaw vault logs --last 5` to see last 5 entries
**Current behavior:** `--last` only accepts a duration string (e.g. `24h`, `7d`, `30m`).
**Desired behavior:** Also accept a plain number — `--last 10` shows the 10 most recent log entries regardless of time.

### 3. Audit log display truncates commands
**Trigger:** `openclaw vault logs` — commands cut off mid-word
**Current behavior:** Command field is truncated at a fixed width. `git push origin main` shows as `gi`.
**Raw log has full data** — this is display-only, not a storage issue.
**Desired behavior:** Either:
  - Wrap long commands (preferred)
  - Truncate with `...` at a word boundary so it's at least obvious it's truncated
  - Add `--wide` or `--full` flag to disable truncation

---

*More items will be added as testing continues.*
