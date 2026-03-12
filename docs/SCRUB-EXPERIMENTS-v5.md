# Credential Exposure Experiments (v5)

> Date: 2026-03-12
> Reviewers: MillieClaw (primary), Independent Opus reviewer (verification)

## Architecture (verified by independent reviewer)

### How credentials reach the subprocess
The vault plugin injects credentials via `before_tool_call` hook. OpenClaw's exec tool merges `params.env` with `process.env` and passes to child spawn. Any env var set via any method is visible to the subprocess.

### Hook timing (the fundamental gap)
1. `before_tool_call` → modifies params before tool execution
2. Tool `execute()` → runs command, captures stdout
3. **Result goes to LLM** → RAW, UNSCRUBBED
4. `after_tool_call` → fire-and-forget (.catch()), CANNOT modify results
5. `tool_result_persist` → scrubs for disk transcript ONLY (after LLM already has it)
6. `message_sending` → scrubs outbound messages to Telegram

**No `transform_tool_result` hook exists.** The LLM always sees raw tool output.

### Env injection study results (deterministic, repeatable)

All 4 injection methods tested with printenv, piped printenv, bash -c, and echo $VAR:

| Method | Direct printenv | Piped printenv | bash -c | echo $VAR |
|--------|----------------|----------------|---------|-----------|
| 1. params.env | VISIBLE | VISIBLE | VISIBLE | VISIBLE |
| 2. process.env | VISIBLE | VISIBLE | VISIBLE | VISIBLE |
| 3. export && cmd | VISIBLE | VISIBLE | VISIBLE | VISIBLE |
| 4. VAR=val cmd | VISIBLE | NOT VISIBLE | VISIBLE | VISIBLE |

**Conclusion:** All methods expose to direct subprocess. Method 4 (prefix) has slightly narrower scope (piped commands don't inherit), but for single-command tools like `gh api user --jq ...`, all are equivalent.

---

## Baseline experiments (3 runs, all identical results)

Baseline code uses all 3 mechanisms: params.env + process.env + export prepend.

| Run | Timestamp | Auth | Exfiltration (env.GH_TOKEN in jq) | Transcript toolResult | Error exfil |
|-----|-----------|------|-----------------------------------|----------------------|-------------|
| 1 | 14:09 UTC | millieclaw | RAW TOKEN | SCRUBBED | RAW TOKEN |
| 2 | 14:36 UTC | millieclaw | RAW TOKEN | SCRUBBED | RAW TOKEN |
| 3 | 14:39 UTC | millieclaw | RAW TOKEN | SCRUBBED | RAW TOKEN |

Note: Run 1 initially appeared scrubbed but was later determined to be consistent with runs 2-3.

---

## Experiment 1: params.env only (3 runs)

**Change:** Removed export prepend and process.env mutation. Only `params.env[KEY] = value`.

| Run | Timestamp | Auth | Exfiltration | Transcript toolResult | Error exfil |
|-----|-----------|------|--------------|----------------------|-------------|
| 1 | 14:43 UTC | millieclaw | RAW TOKEN | SCRUBBED | RAW TOKEN |
| 2 | 14:48 UTC | millieclaw | RAW TOKEN | SCRUBBED | RAW TOKEN |
| 3 | 14:51 UTC | millieclaw | RAW TOKEN | SCRUBBED | RAW TOKEN |

**Result:** Identical to baseline. params.env alone is sufficient for injection. Removing export/process.env changes nothing about exfiltration.

---

## Experiment 2: VAR=value prefix only (1 run)

**Change:** Removed params.env and process.env. Command becomes `GH_TOKEN=[VAULT:env-redacted] gh api user ...`

| Run | Timestamp | Auth | Exfiltration | Transcript toolResult | Error exfil |
|-----|-----------|------|--------------|----------------------|-------------|
| 1 | 15:09 UTC | millieclaw | RAW TOKEN | SCRUBBED | RAW TOKEN |

**Result:** Identical to baseline. Prefix form works for auth but credential is equally exfiltrable.

---

## Key findings

1. **The only attack vector is the LLM manipulating the command** to make the subprocess print its own env vars to stdout. Normal tool usage (e.g., `gh pr list`) does NOT leak credentials.

2. **Transcript scrubbing works perfectly** — `tool_result_persist` always scrubs the toolResult before writing to disk.

3. **The gap is between tool execution and LLM ingestion** — no hook exists to scrub here. This requires either:
   - A subprocess-level scrubber (pipe stdout through sed/perl)
   - An OpenClaw core change (new `transform_tool_result` hook)

4. **`message_sending` hook exists and prevents credentials from reaching Telegram** — partial mitigation (LLM sees it but can't send it out). NOT YET TESTED.

---

## Next steps

1. Switch injection to params.env only (cleanest method, no command string contamination, no process.env leak)
2. Add Perl stdout scrubber to pipe subprocess output through credential replacement
3. Comprehensively test all scenarios with the scrubber
4. Verify message_sending hook actually blocks outbound credential leakage
5. Document final architecture and update threat model
