# Credential Exposure Experiments (v5.1)

> Date: 2026-03-12
> Reviewers: MillieClaw (primary), Independent Opus reviewer (verification)

## Architecture (verified by independent reviewer)

### How credentials reach the subprocess
The vault plugin injects credentials via `before_tool_call` hook. OpenClaw's exec tool merges `params.env` with `process.env` and passes to child spawn. Any env var set via any method is visible to the subprocess.

### Hook timing
1. `before_tool_call` → modifies params before tool execution (injects credentials into subprocess env)
2. Tool `execute()` → runs command, captures stdout → **stdout is what the LLM sees**
3. `after_tool_call` → fire-and-forget (.catch()), CANNOT modify results
4. `tool_result_persist` → scrubs for disk transcript ONLY (after LLM already has it)
5. `message_sending` → scrubs outbound messages to Telegram

**No `transform_tool_result` hook exists** between tool execution and LLM ingestion.

### Critical distinction: credentials live in subprocess env, NOT in tool output

Credentials are injected into the subprocess environment variables. They do NOT appear in tool output by default. Normal command usage (e.g., `gh pr list`, `gh api user --jq .login`) never exposes credentials — the tool authenticates silently using the env var and returns only the command's normal output.

**Credentials only appear in tool output when the LLM deliberately constructs a command that extracts env vars** — e.g., `env.GH_TOKEN` in jq, `printenv GH_TOKEN`, `echo $GH_TOKEN`. This is intentional exfiltration by the LLM, not accidental leakage.

The threat is: the LLM crafts a command to read its own subprocess env → credential appears in stdout → stdout is the tool result → LLM sees it.

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

1. **Credentials do NOT leak during normal tool usage.** Commands like `gh pr list`, `gh api user --jq .login` authenticate silently — the credential stays in subprocess env and never appears in stdout.

2. **The only exposure path is intentional LLM exfiltration.** The LLM must deliberately construct a command that reads env vars (e.g., `env.GH_TOKEN` in jq, `printenv`, `echo $VAR`). Only then does the credential appear in stdout → tool result → LLM context.

3. **Transcript scrubbing works perfectly** — `tool_result_persist` always scrubs the toolResult before writing to disk. Credentials never persist in session transcripts.

4. **`message_sending` hook exists and should prevent credentials from reaching Telegram** — even if the LLM sees a credential, this hook scrubs outbound messages. NOT YET TESTED.

5. **No hook exists between tool execution and LLM ingestion** — if the LLM does exfiltrate, there is no way to scrub the tool result before the LLM sees it. Mitigation options:
   - Subprocess-level scrubber (pipe stdout through sed/perl before exec captures it)
   - OpenClaw core change (new `transform_tool_result` hook)

---

## Next steps

1. Switch injection to params.env only (cleanest method, no command string contamination, no process.env leak)
2. Add Perl stdout scrubber to pipe subprocess output through credential replacement
3. Comprehensively test all scenarios with the scrubber
4. Verify message_sending hook actually blocks outbound credential leakage
5. Document final architecture and update threat model
