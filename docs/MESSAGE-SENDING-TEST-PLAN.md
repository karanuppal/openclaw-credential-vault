# message_sending Hook Scrubbing — Test Plan

**Date:** 2026-03-12
**Context:** OAuth client ID `[VAULT:gws-client-id]` leaked to Telegram despite vault scrubber being active.

---

## Architecture Summary

The `message_sending` hook is the **last line of defense** before text reaches Telegram. The scrubbing pipeline has 4 layers:

1. **`tool_result_persist`** — scrubs tool output before writing to session transcript
2. **`before_message_write`** — scrubs assistant messages before transcript write
3. **`message_sending`** — scrubs outbound text right before channel delivery
4. **Literal credential scrubbing** — matches exact decrypted credential values from `credentialCache`

The hook receives `{to, content, metadata}` where `content` is a **string** (the final text). It applies:
- `scrubText()` — regex-based pattern matching from `tools.yaml` scrub patterns
- `scrubLiteralCredential()` — exact string match against cached decrypted credential values

### Key Vulnerability: credentialCache dependency

The `message_sending` handler iterates `state.credentialCache` for literal scrubbing. If the credential was **never injected** (never decrypted via `getCredential()`), the literal won't be in the cache, and scrubbing depends solely on regex patterns.

For `gws-client-id`, the regex pattern is:
```
859385208636-igvdh0067s50holelfgne4jdlg1roftt\.apps\.googleusercontent\.com
```
This is a **literal regex** (escaped dots), so it should match the exact string. The regex approach is independent of the credential cache.

---

## Test Matrix

### Test 1: Verify hook registration

**Purpose:** Confirm `message_sending` hook is registered and recognized by OpenClaw.

**Command:**
```bash
journalctl --user -u openclaw-gateway --since today | grep -i "message_sending\|hasMessageSendingHooks"
```

**Expected:** Evidence that `hasMessageSendingHooks` evaluates to `true` (the delivery code checks this before calling the hook).

**What it proves:** The plugin successfully registered the hook at gateway startup.

---

### Test 2: Regex pattern compilation verification

**Purpose:** Confirm the `gws-client-id` scrub pattern compiles and matches correctly.

**Command:**
```bash
node -e "
const re = new RegExp('859385208636-igvdh0067s50holelfgne4jdlg1roftt\\.apps\\.googleusercontent\\.com', 'g');
const input = 'Client ID is [VAULT:gws-client-id] here';
console.log('Match:', re.test(input));
re.lastIndex = 0;
console.log('Replaced:', input.replace(re, '[VAULT:gws-client-id]'));
"
```

**Expected:**
```
Match: true
Replaced: Client ID is [VAULT:gws-client-id] here
```

**What it proves:** The regex pattern itself is correct and matches the leaked value.

---

### Test 3: Regex lastIndex bug check

**Purpose:** The `scrubText` function uses `scrubTextWithTracking` which calls `rule.regex.test()` then `text.replace(rule.regex)`. With the `g` flag, `test()` advances `lastIndex`, which can cause `replace()` to miss the first match.

**Command:**
```bash
node -e "
const re = new RegExp('859385208636-igvdh0067s50holelfgne4jdlg1roftt\\.apps\\.googleusercontent\\.com', 'g');
const text = 'ID: [VAULT:gws-client-id]';

// Simulate what scrubTextWithTracking does
console.log('--- Simulating scrubTextWithTracking ---');
const testResult = re.test(text);
console.log('test() returned:', testResult, '| lastIndex after test:', re.lastIndex);
const replaced = text.replace(re, '[VAULT:gws-client-id]');
console.log('replace() result:', replaced);
console.log('Still contains credential:', replaced.includes('859385208636'));
"
```

**Expected:** If there's a `lastIndex` bug, `replace()` might fail to replace the match because `lastIndex` is past the match position after `test()`.

**What it proves:** Whether the `g` flag + `test()` before `replace()` causes a missed replacement — a known JavaScript regex pitfall.

---

### Test 4: scrubTextWithTracking code path audit

**Purpose:** Read the actual `scrubTextWithTracking` implementation and check if it resets `lastIndex` before `replace()`.

**Command:**
```bash
# Read the compiled JS to see if lastIndex is reset
grep -A30 "scrubTextWithTracking" /home/karanuppal/Projects/openclaw-credential-vault/dist/scrubber.js | head -40
```

**Expected:** Look for `regex.lastIndex = 0` between `test()` and `replace()` calls. If missing, this is likely the root cause.

**What it proves:** Whether there's a regex `lastIndex` bug in the scrubbing hot path.

---

### Test 5: Live message_sending hook invocation with debug logging

**Purpose:** Confirm the hook fires and scrubs content on an actual outbound message.

**Setup:**
```bash
# Enable vault debug logging
export OPENCLAW_VAULT_DEBUG=1
sudo systemctl --user restart openclaw-gateway  # or use openclaw gateway restart
```

**Trigger:** Send a message from the agent that would contain a credential pattern. The simplest way:

```bash
# In the Telegram conversation, ask the agent to echo a string containing the pattern
# e.g., "Please repeat this exact text: The client ID is [VAULT:gws-client-id]"
```

**Check:**
```bash
# Check if the hook was called and what it did
tail -50 ~/.openclaw/vault/error.log
journalctl --user -u openclaw-gateway --since "5 minutes ago" | grep -i "vault\|scrub\|message_sending"
```

**Expected:** The message should arrive in Telegram with `[VAULT:gws-client-id]` replacing the client ID.

**What it proves:** End-to-end hook invocation and scrubbing on the Telegram delivery path.

---

### Test 6: Empty credentialCache scenario

**Purpose:** Test scrubbing when the credential was never injected (cache is empty).

**Rationale:** If the gateway restarted recently and no `gws-client-id` injection happened, `credentialCache` won't contain the literal value. Scrubbing depends entirely on regex patterns.

**Command:**
```bash
# Check when gws-client-id was last used for injection
journalctl --user -u openclaw-gateway --since today | grep "gws-client-id" | head -10
```

**Expected:** If `gws-client-id` was never injected since last restart, `scrubLiteralCredential` is a no-op for this credential. Only regex patterns protect against leakage.

**What it proves:** Whether regex-only scrubbing (without literal cache) is sufficient.

---

### Test 7: Multi-payload message splitting

**Purpose:** Test if message splitting (for long messages) happens before or after the hook.

**Context:** OpenClaw splits long messages into chunks via `sendTextChunks`. The `applyMessageSendingHook` runs on the full `payloadSummary.text` before chunking.

**Command:**
```bash
grep -n "sendTextChunks\|applyMessageSendingHook\|normalizePayloads" /home/karanuppal/.npm-global/lib/node_modules/openclaw/dist/deliver-DCtqEVTU.js | head -20
```

**Expected:** `applyMessageSendingHook` runs first on the full payload, then `sendTextChunks` splits for delivery. Scrubbing should catch everything.

**What it proves:** Message splitting doesn't bypass the hook.

---

### Test 8: Hook return value edge case

**Purpose:** The `handleMessageSending` function only returns `{content}` when scrubbing changed the text. If scrubbing fails silently (regex doesn't match), it returns `void` and the original text goes through.

**Code path:**
```typescript
// In handleMessageSending:
if (content !== event.content) {
  return { content };  // Only returned when something changed
}
// Falls through to return void — original content sent as-is
```

**Test:** Verify this logic is correct — returning `void` should mean "no modification" per the OpenClaw hook contract, not "cancel the hook."

**Command:**
```bash
# Check OpenClaw's handling of void return from message_sending
grep -A5 "sendingResult?.content == null" /home/karanuppal/.npm-global/lib/node_modules/openclaw/dist/deliver-DCtqEVTU.js
```

**Expected:** `void` return means no change — original payload passes through. This is correct behavior.

**What it proves:** The hook correctly passes through when no scrubbing needed.

---

### Test 9: gateway_start cache warming

**Purpose:** Verify that `handleGatewayStart` successfully warms the credential cache for all tools, including `gws-client-id`.

**Command:**
```bash
journalctl --user -u openclaw-gateway | grep -A2 "Vault ready\|cache\|warm\|gws-client-id" | tail -20
```

**Expected:** On gateway start, all credentials are decrypted and cached. This means `addLiteralCredential` is called for each, populating the literal match set.

**What it proves:** After gateway restart, literal scrubbing should work for all tools immediately — not just after first injection.

---

### Test 10: Concurrent delivery race condition

**Purpose:** Test if a race condition between credential injection (which populates `credentialCache`) and message delivery (which reads it) could cause a miss.

**Scenario:** Agent runs a tool that injects `gws-client-id`, tool output contains the credential, but the response message is delivered before `addLiteralCredential` completes.

**Analysis:** This is unlikely because:
1. `getCredential` is `async` and `addLiteralCredential` runs synchronously after decryption
2. `before_tool_call` (injection) runs before tool execution, which runs before result delivery
3. `gateway_start` pre-warms the cache

**Command:**
```bash
# Check tool execution timeline
journalctl --user -u openclaw-gateway --since today | grep -E "before_tool_call|after_tool_call|message_sending" | tail -20
```

**What it proves:** Whether hook ordering guarantees credential cache is populated before `message_sending` fires.

---

### Test 11: Direct message tool bypass

**Purpose:** Test if messages sent via the `message` tool (agent explicitly calling `message(action="send")`) go through `message_sending` hook.

**Command:**
```bash
# Search for how the message tool's send action routes through delivery
grep -rn "message.*send\|deliverOutbound" /home/karanuppal/.npm-global/lib/node_modules/openclaw/dist/ --include="*.js" | grep -i "tool\|message_tool\|action.*send" | head -10
```

**Expected:** All outbound messages, regardless of source (agent response or explicit `message` tool call), should route through `deliverOutboundPayloads` which calls `applyMessageSendingHook`.

**What it proves:** Whether the `message` tool bypasses the scrubbing pipeline.

---

### Test 12: Sub-agent message delivery path

**Purpose:** Test if sub-agent messages (spawned agents posting to Telegram) go through the parent's `message_sending` hook.

**Rationale:** The credential leak happened during a session where sub-agents were active. Sub-agents have their own delivery context.

**Command:**
```bash
# Check if sub-agent delivery uses the same hook runner
grep -rn "subagent\|sub.agent\|spawn" /home/karanuppal/.npm-global/lib/node_modules/openclaw/dist/deliver-DCtqEVTU.js | head -10
```

**Expected:** Sub-agents should share the same `hookRunner` singleton, so the same `message_sending` hook fires.

**What it proves:** Whether sub-agent messages bypass scrubbing.

---

## Preliminary Analysis (from transcript review)

**Key finding from session transcript:** The credential appearances in the transcript fall into two categories:

1. **Tools.yaml pattern display** — The agent read `tools.yaml` and the *regex pattern* (with escaped dots: `859385208636-igvdh0067s50holelfgne4jdlg1roftt\.apps\.googleusercontent\.com`) appeared in tool output. The scrub regex matches literal dots, NOT backslash-escaped dots, so the pattern string itself is not scrubbed.

2. **Agent discussing the credential** — The assistant wrote messages like `` `859385208636-...` `` when explaining the issue. This is a *partial* form — the regex requires the full `.apps.googleusercontent.com` suffix to match, so a truncated reference like `859385208636-...` or `859385208636-igvdh0067s50holelfgne4jdlg1roftt` won't be caught.

3. **tool_result_persist DID work** — Journal logs confirm: the actual credential in exec output was scrubbed to `[VAULT:gws-client-id]` before persistence.

**Verified:** `scrubTextWithTracking` correctly resets `lastIndex = 0` before `replace()`. No regex lastIndex bug.

## Root Cause Hypotheses (Ranked by Likelihood)

### H1: Agent paraphrasing/quoting credentials in natural language (HIGH)
The agent saw the credential in tool output (before `tool_result_persist` scrubbed the transcript copy), then **referenced it in its own words** in the response. The assistant's text `859385208636-...` is a partial quote that doesn't match the full regex pattern. The `message_sending` hook can't scrub what doesn't match any pattern. **This is most likely what happened.**

### H2: Partial credential patterns not covered by scrub rules (HIGH)
The scrub pattern requires the FULL string including `.apps.googleusercontent.com`. Any partial form (just the numeric prefix `859385208636-igvdh0067s50holelfgne4jdlg1roftt`) won't be caught. **Fix: add a scrub pattern for the numeric prefix alone.**

### H3: Regex pattern string itself leaking (MEDIUM)
When the agent reads `tools.yaml`, the escaped pattern `859385208636-igvdh0067s50holelfgne4jdlg1roftt\.apps\.googleusercontent\.com` appears in output. The backslash-dots don't match the regex (which expects literal dots). **Fix: add a second pattern without escapes, or scrub the pattern display.**

### H4: Credential not in cache at send time (LOW)
If the gateway restarted between credential injection and message delivery, `credentialCache` would be empty. But regex scrubbing still runs — and we confirmed the regex itself works for the full credential. This only matters for forms not covered by regex.

### H5: Sub-agent or message tool delivery bypass (LOW)
If sub-agents or the `message` tool use a different delivery path that doesn't call `applyMessageSendingHook`, scrubbing is skipped entirely. **Test 11 and Test 12 will confirm.**

---

## Execution Order

1. **Tests 1-2:** Quick verification (< 1 min each)
2. **Tests 3-4:** Regex lastIndex investigation (likely root cause)
3. **Test 5:** Live end-to-end with debug logging
4. **Tests 6, 9:** Cache state investigation
5. **Tests 7-8, 10-12:** Edge case and architecture validation

## Success Criteria

The test plan is complete when:
- Root cause of the `gws-client-id` leak is identified
- A fix is proposed with specific code changes
- The fix is verified with Test 5 (live end-to-end)
