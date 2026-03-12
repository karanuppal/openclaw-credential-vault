# Credential Exposure Experiments (v4)

> Date: 2026-03-12
> Goal: Isolate exactly how credentials reach the LLM context and which injection paths leak
> Method: One change per experiment, test injection + exfiltration, revert before next

## Baseline (current code — commit 11f0175)

The vault injects credentials via THREE mechanisms simultaneously:
1. `params.env[KEY] = value` — exec tool passes to subprocess as env vars
2. `process.env[KEY] = value` — sets on gateway process (cleaned up in after_tool_call)
3. `params.command = "export KEY=[VAULT:env-redacted] && " + original_command` — prepends literal credential to command string

OpenClaw's exec tool merges `params.env` into subprocess env:
```
const mergedEnv = params.env ? { ...inheritedBaseEnv, ...params.env } : inheritedBaseEnv
```

---

## Experiment 1: params.env only

**Change:** Remove `export` command prepend AND `process.env` contamination. Keep ONLY `params.env[KEY] = value`.

**Thesis:** `params.env` is the correct injection mechanism. The `export` prepend and `process.env` are redundant. Removing the export prepend removes the credential from the command string.

---

## Experiment 2: Command prefix form only

**Change:** Remove `params.env` and `process.env`. Use bash prefix: `KEY=[VAULT:env-redacted] command` (no export keyword, no params.env).

**Thesis:** The prefix form sets the env var only for the immediate command. Tests if this alone is sufficient for auth and what the LLM can see.

---

## Tests (same 5 tests for baseline, experiment 1, and experiment 2)

| # | Test | Command | Purpose |
|---|------|---------|---------|
| 1 | Auth works | `gh api user --jq .login` | Does the credential injection actually work? |
| 2 | Exfiltration | `gh api user --jq '.login + " " + env.GH_TOKEN'` | Can the LLM see the raw token in tool output? |
| 3 | Transcript check | `grep 'ghp_' <last 10 lines of session jsonl>` | Is the raw token written to disk after test 2? |
| 4 | Error exfiltration | `gh api user --jq 'env.GH_TOKEN + " " + .nonexistent_field'` | When the command errors, does the error output expose the raw token? |
| 5 | Error transcript check | `grep 'ghp_' <last 5 lines of session jsonl>` | Is the raw token written to disk after test 4? |

---

## Execution Protocol

For each config (baseline, exp 1, exp 2):
1. Apply the code change (or clean baseline)
2. `npm run build`
3. Karan does stop/start
4. Run ALL 5 tests in order
5. Record EXACT raw output — no interpretation
6. `git checkout -- src/` to revert
7. Move to next

## Results

### Baseline Results

(to be filled)

### Experiment 1 Results

(to be filled)

### Experiment 2 Results

(to be filled)

### Analysis

(to be filled after ALL experiments complete — compare side by side)
