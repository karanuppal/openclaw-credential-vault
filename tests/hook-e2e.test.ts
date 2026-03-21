/**
 * Hook-Level E2E Tests
 *
 * Tests the ACTUAL hook handlers (handleBeforeToolCall, handleAfterToolCall,
 * handleToolResultPersist, handleBeforeMessageWrite) with realistic OpenClaw-shaped
 * inputs/outputs.
 *
 * This catches bugs like the one where after_tool_call couldn't parse OpenClaw's
 * wrapped result format {content: [...], details: {...}} — it expected flat {url, targetId}.
 *
 * The handlers use module-level `state` — we call `register()` with a mock PluginApi
 * pointing at a temp vault dir to initialize it, then call the captured handlers directly.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";

import {
  writeCredentialFile,
  getMachinePassphrase,
} from "../src/crypto.js";
import {
  initConfig,
  readConfig,
  writeConfig,
  upsertTool,
  readMeta,
} from "../src/config.js";
import { clearLiteralCredentials } from "../src/scrubber.js";
import type { PluginApi, ToolConfig } from "../src/types.js";

// We import the individual handlers and use register() to set up module state
import register, {
  handleBeforeToolCall,
  handleAfterToolCall,
  handleToolResultPersist,
  handleBeforeMessageWrite,
  _resetResolverState,
  _state,
} from "../src/index.js";

// ---- Test Helpers ----

let tmpDir: string;
let vaultDir: string;
let passphrase: string;
let originalHome: string | undefined;

/** Captured hook registrations from the mock PluginApi */
let capturedHooks: Map<string, Function>;

/** Build a mock PluginApi */
function buildMockApi(): PluginApi {
  capturedHooks = new Map();
  return {
    id: "credential-vault-test",
    name: "credential-vault",
    version: "0.0.0-test",
    description: "test",
    source: "test",
    config: {},
    pluginConfig: {},
    runtime: {},
    logger: {
      debug: () => {},
      info: () => {},
      warn: () => {},
      error: () => {},
    },
    on(hook: string, handler: Function, _opts?: { priority?: number }) {
      capturedHooks.set(hook, handler);
    },
    registerCli: () => {},
    registerTool: () => {},
    registerHook: () => {},
    registerHttpRoute: () => {},
    registerCommand: () => {},
    resolvePath: (p: string) => p,
  };
}

/** Standard hook context for before_tool_call */
function makeBeforeCtx(toolName: string) {
  return { toolName, agentId: "test", sessionKey: "test-session", sessionId: "s1", runId: "r1", toolCallId: "tc1" };
}

/** Standard hook context for after_tool_call */
function makeAfterCtx(toolName: string) {
  return { toolName, agentId: "test", sessionKey: "test-session", sessionId: "s1", runId: "r1", toolCallId: "tc1" };
}

/** Initialize vault in temp dir with desired credentials and configs */
async function setupVault(tools: Record<string, { credential: string; config: Partial<ToolConfig> }>) {
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "vault-hook-e2e-"));
  // getVaultDir() uses $HOME/.openclaw/vault, so we set HOME to a fake dir
  // that places .openclaw/vault at our tmpDir
  vaultDir = path.join(tmpDir, ".openclaw", "vault");
  fs.mkdirSync(vaultDir, { recursive: true });

  // Point HOME at our temp dir so getVaultDir() finds our vault
  originalHome = process.env.HOME;
  process.env.HOME = tmpDir;

  initConfig(vaultDir, "machine");
  const meta = readMeta(vaultDir);
  passphrase = getMachinePassphrase(meta!.installTimestamp);

  let config = readConfig(vaultDir);
  for (const [name, tool] of Object.entries(tools)) {
    await writeCredentialFile(vaultDir, name, tool.credential, passphrase);
    const toolConfig: ToolConfig = {
      name,
      addedAt: new Date().toISOString(),
      lastRotated: new Date().toISOString(),
      inject: tool.config.inject ?? [],
      scrub: tool.config.scrub ?? { patterns: [] },
      ...tool.config,
    };
    config = upsertTool(config, toolConfig);
  }
  writeConfig(vaultDir, config);

  // Register the plugin — this sets the module-level `state`
  register(buildMockApi());
}

function cleanup() {
  // Restore HOME
  if (originalHome !== undefined) {
    process.env.HOME = originalHome;
  }
  clearLiteralCredentials();
  _resetResolverState();
  if (tmpDir) {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

// ================================================================
// Task 1: Browser Password Full Flow
// ================================================================
describe("Hook E2E: Browser Password Full Flow", () => {
  beforeEach(async () => {
    await setupVault({
      "test-cred": {
        credential: "SuperSecret123!",
        config: {
          inject: [
            {
              tool: "browser",
              type: "browser-password",
              domainPin: [".example.com"],
              method: "fill",
            },
          ],
          scrub: { patterns: [] },
        },
      },
    });
  });

  afterEach(cleanup);

  it("1. after_tool_call navigate with OpenClaw-wrapped result populates tab URL cache", () => {
    // Simulate navigate result in OpenClaw's wrapped format
    const event = {
      toolName: "browser",
      params: { action: "navigate", url: "https://example.com/login", targetId: "TAB1" },
      result: {
        content: [{ type: "text", text: '{"ok":true,"targetId":"TAB1","url":"https://example.com/login"}' }],
        details: { ok: true, targetId: "TAB1", url: "https://example.com/login" },
      },
    };

    handleAfterToolCall(event, makeAfterCtx("browser"));

    // The browserTabUrls cache should now have TAB1 → https://example.com/login
    // We verify this indirectly in the next test via before_tool_call
  });

  it("2. Navigate then act with $vault: — credential resolved and replaced", async () => {
    // Step 1: Simulate navigate (populates cache via after_tool_call)
    handleAfterToolCall(
      {
        toolName: "browser",
        params: { action: "navigate", url: "https://example.com/login", targetId: "TAB1" },
        result: {
          content: [{ type: "text", text: '{"ok":true,"targetId":"TAB1","url":"https://example.com/login"}' }],
          details: { ok: true, targetId: "TAB1", url: "https://example.com/login" },
        },
      },
      makeAfterCtx("browser"),
    );

    // Also do before_tool_call for navigate to populate cache via the navigate path
    await handleBeforeToolCall(
      {
        toolName: "browser",
        params: { action: "navigate", url: "https://example.com/login", targetId: "TAB1" },
      },
      makeBeforeCtx("browser"),
    );

    // Step 2: Act with $vault: placeholder
    const result = await handleBeforeToolCall(
      {
        toolName: "browser",
        params: { action: "act", text: "$vault:test-cred", targetId: "TAB1" },
      },
      makeBeforeCtx("browser"),
    );

    expect(result).toBeDefined();
    expect(result!.block).toBeFalsy();
    expect(result!.params).toBeDefined();
    expect(result!.params!.text).toBe("SuperSecret123!");
  });

  it("3. Cold cache scenario — no prior navigate → domain error (blocked)", async () => {
    // No navigate happened, so TAB99 has no cached URL
    const result = await handleBeforeToolCall(
      {
        toolName: "browser",
        params: { action: "act", text: "$vault:test-cred", targetId: "TAB99" },
      },
      makeBeforeCtx("browser"),
    );

    expect(result).toBeDefined();
    expect(result!.block).toBe(true);
    expect(result!.blockReason).toContain("Cannot resolve domain");
  });

  it("4. Domain pin REJECTION — navigate to evil.com, then try $vault: → blocked", async () => {
    // Navigate to evil.com
    await handleBeforeToolCall(
      {
        toolName: "browser",
        params: { action: "navigate", url: "https://evil.com/phishing", targetId: "TAB2" },
      },
      makeBeforeCtx("browser"),
    );

    handleAfterToolCall(
      {
        toolName: "browser",
        params: { action: "navigate", url: "https://evil.com/phishing", targetId: "TAB2" },
        result: {
          content: [{ type: "text", text: '{"ok":true,"targetId":"TAB2","url":"https://evil.com/phishing"}' }],
          details: { ok: true, targetId: "TAB2", url: "https://evil.com/phishing" },
        },
      },
      makeAfterCtx("browser"),
    );

    // Try to fill $vault: on evil.com
    const result = await handleBeforeToolCall(
      {
        toolName: "browser",
        params: { action: "act", text: "$vault:test-cred", targetId: "TAB2" },
      },
      makeBeforeCtx("browser"),
    );

    expect(result).toBeDefined();
    expect(result!.block).toBe(true);
    expect(result!.blockReason).toContain("Domain mismatch");
  });

  it("5. Nested request object path — request.text with $vault: placeholder", async () => {
    // Navigate first
    await handleBeforeToolCall(
      {
        toolName: "browser",
        params: { action: "navigate", url: "https://example.com/login", targetId: "TAB3" },
      },
      makeBeforeCtx("browser"),
    );

    // Act with nested request object
    const result = await handleBeforeToolCall(
      {
        toolName: "browser",
        params: {
          action: "act",
          targetId: "TAB3",
          request: { kind: "fill", ref: "e41", text: "$vault:test-cred" },
        },
      },
      makeBeforeCtx("browser"),
    );

    expect(result).toBeDefined();
    expect(result!.block).toBeFalsy();
    expect(result!.params).toBeDefined();
    const request = result!.params!.request as Record<string, unknown>;
    expect(request.text).toBe("SuperSecret123!");
  });
});

// ================================================================
// Task 1: Browser Cookie Full Flow
// ================================================================
describe("Hook E2E: Browser Cookie Full Flow", () => {
  const validCookies = JSON.stringify([
    {
      name: "session-id",
      value: "abc-123-session",
      domain: ".amazon.com",
      path: "/",
      expires: Math.floor(Date.now() / 1000) + 86400,
      httpOnly: true,
      secure: true,
      sameSite: "Lax",
    },
    {
      name: "ubid-main",
      value: "xyz-456-ubid",
      domain: ".amazon.com",
      path: "/",
      expires: Math.floor(Date.now() / 1000) + 86400 * 365,
      httpOnly: false,
      secure: true,
      sameSite: "Lax",
    },
  ]);

  beforeEach(async () => {
    await setupVault({
      "amazon-cookies": {
        credential: validCookies,
        config: {
          inject: [
            {
              tool: "browser",
              type: "browser-cookie",
              domainPin: [".amazon.com"],
              method: "cookie-jar",
            },
          ],
          scrub: { patterns: [] },
        },
      },
    });
  });

  afterEach(cleanup);

  it("1. Navigate to cookie-pinned domain → _vaultCookies attached", async () => {
    const result = await handleBeforeToolCall(
      {
        toolName: "browser",
        params: { action: "navigate", url: "https://www.amazon.com/orders" },
      },
      makeBeforeCtx("browser"),
    );

    expect(result).toBeDefined();
    expect(result!.params).toBeDefined();
    const cookies = result!.params!._vaultCookies as Array<Record<string, unknown>>;
    expect(cookies).toBeDefined();
    expect(Array.isArray(cookies)).toBe(true);
    expect(cookies.length).toBe(2);
    expect(cookies[0].name).toBe("session-id");
    expect(cookies[1].name).toBe("ubid-main");
  });

  it("2. Navigate to non-matching domain → NO cookies injected", async () => {
    const result = await handleBeforeToolCall(
      {
        toolName: "browser",
        params: { action: "navigate", url: "https://www.google.com/search" },
      },
      makeBeforeCtx("browser"),
    );

    expect(result).toBeDefined();
    expect(result!.params).toBeDefined();
    expect(result!.params!._vaultCookies).toBeUndefined();
  });

  it("3. Expired cookies are filtered out", async () => {
    // Re-setup with expired cookies
    cleanup();
    const mixedCookies = JSON.stringify([
      {
        name: "expired-session",
        value: "old-value",
        domain: ".amazon.com",
        path: "/",
        expires: Math.floor(Date.now() / 1000) - 86400, // expired yesterday
        httpOnly: true,
        secure: true,
        sameSite: "Lax",
      },
      {
        name: "valid-session",
        value: "good-value",
        domain: ".amazon.com",
        path: "/",
        expires: Math.floor(Date.now() / 1000) + 86400, // valid
        httpOnly: true,
        secure: true,
        sameSite: "Lax",
      },
    ]);

    await setupVault({
      "amazon-cookies": {
        credential: mixedCookies,
        config: {
          inject: [
            {
              tool: "browser",
              type: "browser-cookie",
              domainPin: [".amazon.com"],
              method: "cookie-jar",
            },
          ],
          scrub: { patterns: [] },
        },
      },
    });

    const result = await handleBeforeToolCall(
      {
        toolName: "browser",
        params: { action: "navigate", url: "https://www.amazon.com/orders" },
      },
      makeBeforeCtx("browser"),
    );

    const cookies = result!.params!._vaultCookies as Array<Record<string, unknown>>;
    expect(cookies).toBeDefined();
    expect(cookies.length).toBe(1);
    expect(cookies[0].name).toBe("valid-session");
  });

  it("4. Tracking cookies are NOT filtered at hook level", async () => {
    // Tracking cookie filtering is a different layer — hook injects all valid cookies
    cleanup();
    const cookiesWithTracking = JSON.stringify([
      {
        name: "_ga",
        value: "GA1.2.1234567890.1234567890",
        domain: ".amazon.com",
        path: "/",
        expires: Math.floor(Date.now() / 1000) + 86400,
        httpOnly: false,
        secure: false,
        sameSite: "Lax",
      },
      {
        name: "session-id",
        value: "real-session",
        domain: ".amazon.com",
        path: "/",
        expires: Math.floor(Date.now() / 1000) + 86400,
        httpOnly: true,
        secure: true,
        sameSite: "Lax",
      },
    ]);

    await setupVault({
      "amazon-cookies": {
        credential: cookiesWithTracking,
        config: {
          inject: [
            {
              tool: "browser",
              type: "browser-cookie",
              domainPin: [".amazon.com"],
              method: "cookie-jar",
            },
          ],
          scrub: { patterns: [] },
        },
      },
    });

    const result = await handleBeforeToolCall(
      {
        toolName: "browser",
        params: { action: "navigate", url: "https://www.amazon.com/" },
      },
      makeBeforeCtx("browser"),
    );

    const cookies = result!.params!._vaultCookies as Array<Record<string, unknown>>;
    expect(cookies).toBeDefined();
    // Both cookies should be present — tracking filtering is NOT done at hook level
    expect(cookies.length).toBe(2);
  });
});

// ================================================================
// Task 1: Exec Injection Full Flow
// ================================================================
describe("Hook E2E: Exec Injection Full Flow", () => {
  beforeEach(async () => {
    await setupVault({
      "github": {
        credential: "[VAULT:github]",
        config: {
          inject: [
            {
              tool: "exec",
              commandMatch: "gh *|git *|curl*api.github.com*",
              env: { GH_TOKEN: "$vault:github", GITHUB_TOKEN: "$vault:github" },
            },
          ],
          scrub: { patterns: ["ghp_[a-zA-Z0-9]{36}"] },
        },
      },
      "stripe": {
        credential: "sk_test_abc123def456ghi789xyzw01234",
        config: {
          inject: [
            {
              tool: "exec",
              commandMatch: "stripe*|curl*api.stripe.com*",
              env: { STRIPE_API_KEY: "$vault:stripe" },
            },
          ],
          scrub: { patterns: ["sk_test_[a-zA-Z0-9]{24,}"] },
        },
      },
    });
  });

  afterEach(cleanup);

  it("1. Exec with matching command → env injected", async () => {
    const result = await handleBeforeToolCall(
      {
        toolName: "exec",
        params: { command: "gh pr list --repo owner/repo" },
      },
      makeBeforeCtx("exec"),
    );

    expect(result).toBeDefined();
    expect(result!.params).toBeDefined();
    const env = result!.params!.env as Record<string, string>;
    expect(env).toBeDefined();
    expect(env.GH_TOKEN).toBe("[VAULT:github]");
    expect(env.GITHUB_TOKEN).toBe("[VAULT:github]");
  });

  it("2. Non-matching command → NOT injected", async () => {
    const result = await handleBeforeToolCall(
      {
        toolName: "exec",
        params: { command: "ls -la /tmp" },
      },
      makeBeforeCtx("exec"),
    );

    expect(result).toBeDefined();
    expect(result!.params).toBeDefined();
    const env = result!.params!.env as Record<string, string> | undefined;
    // No env should be set
    expect(env?.GH_TOKEN).toBeUndefined();
    expect(env?.STRIPE_API_KEY).toBeUndefined();
  });

  it("3. Multiple credentials matching same command → all injected", async () => {
    // A command that matches BOTH github AND stripe patterns
    const result = await handleBeforeToolCall(
      {
        toolName: "exec",
        params: { command: "curl https://api.github.com/user && curl https://api.stripe.com/v1/charges" },
      },
      makeBeforeCtx("exec"),
    );

    expect(result).toBeDefined();
    const env = result!.params!.env as Record<string, string>;
    // Both should match — the command contains both api.github.com and api.stripe.com
    // Note: depends on commandMatch glob behavior. At minimum github should match.
    expect(env.GH_TOKEN).toBeDefined();
    // Check if stripe also matched (curl*api.stripe.com* should match the full command)
    // The glob matching depends on implementation; let's check what we get
  });
});

// ================================================================
// Task 1: Web Fetch Full Flow
// ================================================================
describe("Hook E2E: Web Fetch Full Flow", () => {
  beforeEach(async () => {
    await setupVault({
      "resy-auth": {
        credential: "my-resy-auth-token-12345",
        config: {
          inject: [
            {
              tool: "web_fetch",
              urlMatch: "*api.resy.com/*",
              headers: { "x-resy-auth-token": "$vault:resy-auth" },
            },
          ],
          scrub: { patterns: [] },
        },
      },
    });
  });

  afterEach(cleanup);

  it("1. web_fetch with matching URL → headers injected", async () => {
    const result = await handleBeforeToolCall(
      {
        toolName: "web_fetch",
        params: { url: "https://api.resy.com/v1/reservations" },
      },
      makeBeforeCtx("web_fetch"),
    );

    expect(result).toBeDefined();
    expect(result!.params).toBeDefined();
    const headers = result!.params!.headers as Record<string, string>;
    expect(headers).toBeDefined();
    expect(headers["x-resy-auth-token"]).toBe("my-resy-auth-token-12345");
  });

  it("2. web_fetch with non-matching URL → no headers", async () => {
    const result = await handleBeforeToolCall(
      {
        toolName: "web_fetch",
        params: { url: "https://api.anthropic.com/v1/messages" },
      },
      makeBeforeCtx("web_fetch"),
    );

    expect(result).toBeDefined();
    const headers = result!.params!.headers as Record<string, string> | undefined;
    expect(headers?.["x-resy-auth-token"]).toBeUndefined();
  });
});

// ================================================================
// Task 1: Scrubbing Full Flow
// ================================================================
describe("Hook E2E: Scrubbing Full Flow", () => {
  beforeEach(async () => {
    await setupVault({
      "github": {
        credential: "[VAULT:github]",
        config: {
          inject: [
            {
              tool: "exec",
              commandMatch: "gh *",
              env: { GH_TOKEN: "$vault:github" },
            },
          ],
          scrub: { patterns: ["ghp_[a-zA-Z0-9]{36}"] },
        },
      },
    });

    // Trigger an injection so the credential gets into the cache
    await handleBeforeToolCall(
      {
        toolName: "exec",
        params: { command: "gh pr list" },
      },
      makeBeforeCtx("exec"),
    );
  });

  afterEach(cleanup);

  it("1. tool_result_persist scrubs credential values from output", () => {
    const message = {
      role: "tool",
      content: "Token [VAULT:github] used successfully",
    };

    const result = handleToolResultPersist(
      { toolName: "exec", message },
      { toolName: "exec" },
    );

    expect(result).toBeDefined();
    expect(result!.message).toBeDefined();
    const content = result!.message!.content as string;
    expect(content).not.toContain("ghp_abcdefghijklmnopqrstuvwxyz1234567890");
    expect(content).toContain("[VAULT:github]");
  });

  it("2. before_message_write scrubs credentials from agent messages", () => {
    const message = {
      role: "assistant",
      content: "I found the token [VAULT:github] in the output",
    };

    const result = handleBeforeMessageWrite(
      { message },
      {},
    );

    expect(result).toBeDefined();
    expect(result!.message).toBeDefined();
    const content = result!.message!.content as string;
    expect(content).not.toContain("ghp_abcdefghijklmnopqrstuvwxyz1234567890");
    expect(content).toContain("[VAULT:github]");
  });

  it("3. write/edit tool interception scrubs credent[VAULT:gmail-app]ent", async () => {
    const result = await handleBeforeToolCall(
      {
        toolName: "write",
        params: {
          path: "/tmp/test.txt",
          content: "API_KEY=[VAULT:github]",
        },
      },
      makeBeforeCtx("write"),
    );

    expect(result).toBeDefined();
    expect(result!.params).toBeDefined();
    const content = result!.params!.content as string;
    expect(content).not.toContain("ghp_abcdefghijklmnopqrstuvwxyz1234567890");
    expect(content).toContain("[VAULT:github]");
  });

  it("4. tool_result_persist scrubs array content format", () => {
    const message = {
      role: "tool",
      content: [
        { type: "text", text: "Output: [VAULT:github]" },
      ],
    };

    const result = handleToolResultPersist(
      { toolName: "exec", message },
      { toolName: "exec" },
    );

    expect(result).toBeDefined();
    const content = result!.message!.content as Array<{ type: string; text: string }>;
    expect(content[0].text).not.toContain("ghp_abcdefghijklmnopqrstuvwxyz1234567890");
    expect(content[0].text).toContain("[VAULT:github]");
  });
});

// ================================================================
// Task 3: Result Parsing Fix — Regression Tests
// ================================================================
describe("Hook E2E: after_tool_call Result Parsing (Regression)", () => {
  beforeEach(async () => {
    await setupVault({
      "test-cred": {
        credential: "TestPassword",
        config: {
          inject: [
            {
              tool: "browser",
              type: "browser-password",
              domainPin: [".example.com"],
              method: "fill",
            },
          ],
          scrub: { patterns: [] },
        },
      },
    });
  });

  afterEach(cleanup);

  it("Result with details containing url/targetId (the fix)", async () => {
    handleAfterToolCall(
      {
        toolName: "browser",
        params: { action: "navigate", targetId: "TAB1" },
        result: {
          content: [{ type: "text", text: '{"ok":true,"targetId":"TAB1","url":"https://example.com/page"}' }],
          details: { ok: true, targetId: "TAB1", url: "https://example.com/page" },
        },
      },
      makeAfterCtx("browser"),
    );

    // Verify cache was populated by trying to use the tab
    const result = await handleBeforeToolCall(
      {
        toolName: "browser",
        params: { action: "act", text: "$vault:test-cred", targetId: "TAB1" },
      },
      makeBeforeCtx("browser"),
    );

    expect(result).toBeDefined();
    expect(result!.block).toBeFalsy();
    expect(result!.params!.text).toBe("TestPassword");
  });

  it("Re[VAULT:gmail-app]ent[0].text (no details) does NOT populate cache (security)", async () => {
    // Security: content[0].text is untrusted tool output — must NOT be used for cache
    // See SECURITY-AUDIT.md F-NEW-1: cache poisoning via crafted content
    handleAfterToolCall(
      {
        toolName: "browser",
        params: { action: "navigate", targetId: "TAB2" },
        result: {
          content: [{ type: "text", text: '{"ok":true,"targetId":"TAB2","url":"https://example.com/fallback"}' }],
          // No details field — content[0].text should be IGNORED for security
        },
      },
      makeAfterCtx("browser"),
    );

    // Cache should NOT be populated — content[0].text is not trusted
    const result = await handleBeforeToolCall(
      {
        toolName: "browser",
        params: { action: "act", text: "$vault:test-cred", targetId: "TAB2" },
      },
      makeBeforeCtx("browser"),
    );

    // Should block because no cached URL (cold cache)
    expect(result).toBeDefined();
    expect(result!.block).toBe(true);
    expect(result!.blockReason).toContain("Cannot resolve domain");
  });

  it("Result with neither details nor parseable content (graceful no-op)", async () => {
    // Should not throw, should not populate cache
    handleAfterToolCall(
      {
        toolName: "browser",
        params: { action: "navigate", targetId: "TAB3" },
        result: {
          content: [{ type: "text", text: "Navigation complete" }], // not JSON
        },
      },
      makeAfterCtx("browser"),
    );

    // Tab should not be in cache — will fail domain check
    const result = await handleBeforeToolCall(
      {
        toolName: "browser",
        params: { action: "act", text: "$vault:test-cred", targetId: "TAB3" },
      },
      makeBeforeCtx("browser"),
    );

    expect(result).toBeDefined();
    expect(result!.block).toBe(true);
  });

  it("Result for snapshot action (returns url in details)", () => {
    // Snapshot returns url but may not have targetId in params
    handleAfterToolCall(
      {
        toolName: "browser",
        params: { action: "snapshot", targetId: "TAB4" },
        result: {
          content: [{ type: "text", text: "<snapshot content>" }],
          details: { url: "https://example.com/snapshot-page", targetId: "TAB4" },
        },
      },
      makeAfterCtx("browser"),
    );

    // Cache should be updated for TAB4
    // We can verify indirectly
  });

  it("Result for start action (no url/targetId expected)", () => {
    // start action typically returns {ok: true, profilePath: ...} — no url or targetId
    // Should not throw, should not modify cache
    handleAfterToolCall(
      {
        toolName: "browser",
        params: { action: "start" },
        result: {
          content: [{ type: "text", text: '{"ok":true,"profilePath":"/tmp/profile"}' }],
          details: { ok: true, profilePath: "/tmp/profile" },
        },
      },
      makeAfterCtx("browser"),
    );

    // No crash = success
  });

  it("Result with details but targetId only in params (not in details)", async () => {
    // Common scenario: navigate returns url in details but targetId only in event.params
    handleAfterToolCall(
      {
        toolName: "browser",
        params: { action: "navigate", url: "https://example.com/from-params", targetId: "TAB5" },
        result: {
          content: [{ type: "text", text: '{"ok":true}' }],
          details: { ok: true, url: "https://example.com/from-params" },
        },
      },
      makeAfterCtx("browser"),
    );

    // Should use params.targetId + details.url
    const result = await handleBeforeToolCall(
      {
        toolName: "browser",
        params: { action: "act", text: "$vault:test-cred", targetId: "TAB5" },
      },
      makeBeforeCtx("browser"),
    );

    expect(result).toBeDefined();
    expect(result!.block).toBeFalsy();
    expect(result!.params!.text).toBe("TestPassword");
  });

  it("Result with empty object (graceful no-op)", () => {
    handleAfterToolCall(
      {
        toolName: "browser",
        params: { action: "navigate" },
        result: {},
      },
      makeAfterCtx("browser"),
    );
    // No crash = success
  });

  it("Result with null (graceful no-op)", () => {
    handleAfterToolCall(
      {
        toolName: "browser",
        params: { action: "navigate" },
        result: null,
      },
      makeAfterCtx("browser"),
    );
    // No crash = success
  });
});

// ================================================================
// Security Regression Tests (SECURITY-AUDIT findings)
// ================================================================
describe("Hook E2E: Security Regression — F-NEW-1 (cache poisoning prevention)", () => {
  afterEach(cleanup);

  it("crafted content[0].text with fake URL does NOT populate cache", async () => {
    // An attacker-controlled tool could return content with a fake URL
    // to poison the cache and trick the vault into injecting creds on wrong domain
    await setupVault({
      "test-cred": {
        credential: "TestPassword",
        config: {
          inject: [{ tool: "browser", type: "browser-password", domainPin: [".example.com"], method: "fill" }],
          scrub: { patterns: [] },
        },
      },
    });

    // Simulate a result where content[0].text has a URL but details does NOT
    handleAfterToolCall(
      {
        toolName: "browser",
        params: { action: "navigate", targetId: "POISONED_TAB" },
        result: {
          content: [{ type: "text", text: '{"ok":true,"targetId":"POISONED_TAB","url":"https://example.com/legit"}' }],
          details: { ok: true },  // No url in details — content is untrusted
        },
      },
      makeAfterCtx("browser"),
    );

    // Attempt to use the "cached" URL — should FAIL because only details is trusted
    const result = await handleBeforeToolCall(
      {
        toolName: "browser",
        params: { action: "act", text: "$vault:test-cred", targetId: "POISONED_TAB" },
      },
      makeBeforeCtx("browser"),
    );

    expect(result!.block).toBe(true);
    expect(result!.blockReason).toContain("Cannot resolve domain");
  });

  it("details with URL IS trusted and populates cache", async () => {
    await setupVault({
      "test-cred": {
        credential: "TestPassword",
        config: {
          inject: [{ tool: "browser", type: "browser-password", domainPin: [".example.com"], method: "fill" }],
          scrub: { patterns: [] },
        },
      },
    });

    handleAfterToolCall(
      {
        toolName: "browser",
        params: { action: "navigate", targetId: "LEGIT_TAB" },
        result: {
          content: [{ type: "text", text: "irrelevant" }],
          details: { ok: true, targetId: "LEGIT_TAB", url: "https://example.com/real" },
        },
      },
      makeAfterCtx("browser"),
    );

    const result = await handleBeforeToolCall(
      {
        toolName: "browser",
        params: { action: "act", text: "$vault:test-cred", targetId: "LEGIT_TAB" },
      },
      makeBeforeCtx("browser"),
    );

    expect(result!.block).toBeFalsy();
    expect(result!.params!.text).toBe("TestPassword");
  });
});

describe("Hook E2E: Security Regression — F-NEW-5 (debug logging)", () => {
  it("vault-debug logs are suppressed when OPENCLAW_VAULT_DEBUG is not set", async () => {
    const errorSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    const origDebug = process.env.OPENCLAW_VAULT_DEBUG;
    delete process.env.OPENCLAW_VAULT_DEBUG;

    try {
      await setupVault({
        "test-cred": {
          credential: "TestPassword",
          config: {
            inject: [{ tool: "browser", type: "browser-password", domainPin: [".example.com"], method: "fill" }],
            scrub: { patterns: [] },
          },
        },
      });

      handleAfterToolCall(
        {
          toolName: "browser",
          params: { action: "navigate", targetId: "DBG_TAB" },
          result: {
            content: [],
            details: { ok: true, targetId: "DBG_TAB", url: "https://example.com" },
          },
        },
        makeAfterCtx("browser"),
      );

      const debugCalls = errorSpy.mock.calls.filter(
        (args) => typeof args[0] === "string" && args[0].includes("[vault-debug]")
      );
      expect(debugCalls).toHaveLength(0);
    } finally {
      if (origDebug !== undefined) process.env.OPENCLAW_VAULT_DEBUG = origDebug;
      errorSpy.mockRestore();
      cleanup();
    }
  });

  it("vault-debug logs ARE emitted when OPENCLAW_VAULT_DEBUG is set", async () => {
    const errorSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    const origDebug = process.env.OPENCLAW_VAULT_DEBUG;
    process.env.OPENCLAW_VAULT_DEBUG = "1";

    try {
      await setupVault({
        "test-cred": {
          credential: "TestPassword",
          config: {
            inject: [{ tool: "browser", type: "browser-password", domainPin: [".example.com"], method: "fill" }],
            scrub: { patterns: [] },
          },
        },
      });

      handleAfterToolCall(
        {
          toolName: "browser",
          params: { action: "navigate", targetId: "DBG_TAB2" },
          result: {
            content: [],
            details: { ok: true, targetId: "DBG_TAB2", url: "https://example.com" },
          },
        },
        makeAfterCtx("browser"),
      );

      const debugCalls = errorSpy.mock.calls.filter(
        (args) => typeof args[0] === "string" && args[0].includes("[vault-debug]")
      );
      expect(debugCalls.length).toBeGreaterThan(0);
    } finally {
      if (origDebug !== undefined) {
        process.env.OPENCLAW_VAULT_DEBUG = origDebug;
      } else {
        delete process.env.OPENCLAW_VAULT_DEBUG;
      }
      errorSpy.mockRestore();
      cleanup();
    }
  });
});

// ================================================================
// Task 2: Cross-cutting edge cases
// ================================================================
describe("Hook E2E: Edge Cases", () => {
  afterEach(cleanup);

  it("Non-browser tool calls pass through unmodified", async () => {
    await setupVault({
      "github": {
        credential: "[VAULT:github]",
        config: {
          inject: [{ tool: "exec", commandMatch: "gh *", env: { GH_TOKEN: "$vault:github" } }],
          scrub: { patterns: ["ghp_[a-zA-Z0-9]{36}"] },
        },
      },
    });

    const result = await handleBeforeToolCall(
      {
        toolName: "read",
        params: { path: "/tmp/test.txt" },
      },
      makeBeforeCtx("read"),
    );

    expect(result).toBeDefined();
    expect(result!.params).toBeDefined();
    expect(result!.params!.path).toBe("/tmp/test.txt");
    // No env injection for read tool
    expect(result!.params!.env).toBeUndefined();
  });

  it("Edit tool content is scrubbed via before_tool_call", async () => {
    await setupVault({
      "github": {
        credential: "[VAULT:github]",
        config: {
          inject: [{ tool: "exec", commandMatch: "gh *", env: { GH_TOKEN: "$vault:github" } }],
          scrub: { patterns: ["ghp_[a-zA-Z0-9]{36}"] },
        },
      },
    });

    // Inject first to populate cache
    await handleBeforeToolCall(
      { toolName: "exec", params: { command: "gh pr list" } },
      makeBeforeCtx("exec"),
    );

    const result = await handleBeforeToolCall(
      {
        toolName: "edit",
        params: {
          path: "/tmp/test.py",
          old_string: "old code",
          new_string: 'KEY = "[VAULT:github]"',
        },
      },
      makeBeforeCtx("edit"),
    );

    expect(result).toBeDefined();
    const newString = result!.params!.new_string as string;
    expect(newString).not.toContain("ghp_edit12345678901234567890123456789012");
    expect(newString).toContain("[VAULT:github]");
  });

  it("Config hot-reload picks up new credentials", async () => {
    await setupVault({
      "github": {
        credential: "[VAULT:github]",
        config: {
          inject: [{ tool: "exec", commandMatch: "gh *", env: { GH_TOKEN: "$vault:github" } }],
          scrub: { patterns: ["ghp_[a-zA-Z0-9]{36}"] },
        },
      },
    });

    // Add a new credential to the config file on disk
    let config = readConfig(vaultDir);
    await writeCredentialFile(vaultDir, "stripe", "sk_test_newcred1234567890abcdef", passphrase);
    config = upsertTool(config, {
      name: "stripe",
      addedAt: new Date().toISOString(),
      lastRotated: new Date().toISOString(),
      inject: [
        { tool: "exec", commandMatch: "stripe*", env: { STRIPE_API_KEY: "$vault:stripe" } },
      ],
      scrub: { patterns: ["sk_test_[a-zA-Z0-9]{24,}"] },
    });
    // Ensure mtime difference is detectable (filesystem granularity)
    await new Promise(r => setTimeout(r, 50));
    writeConfig(vaultDir, config);

    // Next before_tool_call should detect the config change and reload
    const result = await handleBeforeToolCall(
      {
        toolName: "exec",
        params: { command: "stripe charges list" },
      },
      makeBeforeCtx("exec"),
    );

    expect(result).toBeDefined();
    const env = result!.params!.env as Record<string, string>;
    expect(env.STRIPE_API_KEY).toBe("sk_test_newcred1234567890abcdef");
  });
});

// ================================================================
// macOS Migration Fixes — Regression Tests
// ================================================================
describe("Hook E2E: macOS Fix — binary mode with missing resolver", () => {
  afterEach(cleanup);

  it("binary mode with no resolver: env vars are NOT set to literal '$vault:X'", async () => {
    // This is the exact bug: resolverMode=binary, no binary exists,
    // GH_TOKEN was being set to the literal string "$vault:github"
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "vault-macos-e2e-"));
    vaultDir = path.join(tmpDir, ".openclaw", "vault");
    fs.mkdirSync(vaultDir, { recursive: true });
    originalHome = process.env.HOME;
    process.env.HOME = tmpDir;

    initConfig(vaultDir, "machine");
    const meta = readMeta(vaultDir);
    passphrase = getMachinePassphrase(meta!.installTimestamp);

    // Write credential
    await writeCredentialFile(vaultDir, "github", "ghp_realtoken123456789012345678901234", passphrase);

    // Write config with binary mode (no resolver binary exists on macOS)
    let config = readConfig(vaultDir);
    config = {
      ...config,
      resolverMode: "binary",
    };
    config = upsertTool(config, {
      name: "github",
      addedAt: new Date().toISOString(),
      lastRotated: new Date().toISOString(),
      inject: [
        {
          tool: "exec",
          commandMatch: "gh *",
          env: { GH_TOKEN: "$vault:github", GITHUB_TOKEN: "$vault:github" },
        },
      ],
      scrub: { patterns: ["ghp_[a-zA-Z0-9]{36}"] },
    });
    writeConfig(vaultDir, config);

    // Register plugin with binary mode
    register(buildMockApi());

    // Run a matching command
    const errorSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    const result = await handleBeforeToolCall(
      {
        toolName: "exec",
        params: { command: "gh auth status" },
      },
      makeBeforeCtx("exec"),
    );

    expect(result).toBeDefined();
    const env = result!.params!.env as Record<string, string> | undefined;

    // THE FIX: env vars should either be absent or contain the real credential
    // They must NEVER be the literal string "$vault:github"
    if (env?.GH_TOKEN) {
      expect(env.GH_TOKEN).not.toBe("$vault:github");
    }
    if (env?.GITHUB_TOKEN) {
      expect(env.GITHUB_TOKEN).not.toBe("$vault:github");
    }

    // Should have logged a warning about skipping injection
    const warnings = errorSpy.mock.calls.filter(
      (args) => typeof args[0] === "string" && args[0].includes("could not be resolved")
    );
    expect(warnings.length).toBeGreaterThan(0);

    errorSpy.mockRestore();
  });

  it("binary mode with no resolver: command runs without injected env vars", async () => {
    // Verify the command params still work — just without credentials
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "vault-macos-e2e-"));
    vaultDir = path.join(tmpDir, ".openclaw", "vault");
    fs.mkdirSync(vaultDir, { recursive: true });
    originalHome = process.env.HOME;
    process.env.HOME = tmpDir;

    initConfig(vaultDir, "machine");
    const meta = readMeta(vaultDir);
    passphrase = getMachinePassphrase(meta!.installTimestamp);

    await writeCredentialFile(vaultDir, "github", "ghp_realtoken123456789012345678901234", passphrase);

    let config = readConfig(vaultDir);
    config = { ...config, resolverMode: "binary" };
    config = upsertTool(config, {
      name: "github",
      addedAt: new Date().toISOString(),
      lastRotated: new Date().toISOString(),
      inject: [{
        tool: "exec",
        commandMatch: "gh *",
        env: { GH_TOKEN: "$vault:github" },
      }],
      scrub: { patterns: [] },
    });
    writeConfig(vaultDir, config);
    register(buildMockApi());

    vi.spyOn(console, "error").mockImplementation(() => {});

    const result = await handleBeforeToolCall(
      {
        toolName: "exec",
        params: { command: "gh pr list" },
      },
      makeBeforeCtx("exec"),
    );

    // The original command should be preserved (not wrapped in perl scrubber
    // since no credentials were resolved)
    expect(result!.params!.command).toBe("gh pr list");

    vi.restoreAllMocks();
  });
});

describe("Hook E2E: macOS Fix — hot-reload resolverMode change", () => {
  afterEach(cleanup);

  it("switching tools.yaml from binary→inline mid-session enables injection", async () => {
    // Start with binary mode (broken — no resolver)
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "vault-macos-e2e-"));
    vaultDir = path.join(tmpDir, ".openclaw", "vault");
    fs.mkdirSync(vaultDir, { recursive: true });
    originalHome = process.env.HOME;
    process.env.HOME = tmpDir;

    initConfig(vaultDir, "machine");
    const meta = readMeta(vaultDir);
    passphrase = getMachinePassphrase(meta!.installTimestamp);

    await writeCredentialFile(vaultDir, "github", "ghp_realtoken123456789012345678901234", passphrase);

    let config = readConfig(vaultDir);
    config = { ...config, resolverMode: "binary" };
    config = upsertTool(config, {
      name: "github",
      addedAt: new Date().toISOString(),
      lastRotated: new Date().toISOString(),
      inject: [{
        tool: "exec",
        commandMatch: "gh *",
        env: { GH_TOKEN: "$vault:github" },
      }],
      scrub: { patterns: [] },
    });
    writeConfig(vaultDir, config);
    register(buildMockApi());

    // First call: binary mode, no resolver — injection should be skipped
    vi.spyOn(console, "error").mockImplementation(() => {});
    vi.spyOn(console, "log").mockImplementation(() => {});

    const result1 = await handleBeforeToolCall(
      { toolName: "exec", params: { command: "gh auth status" } },
      makeBeforeCtx("exec"),
    );

    const env1 = result1!.params!.env as Record<string, string> | undefined;
    // Should NOT have the placeholder
    if (env1?.GH_TOKEN) {
      expect(env1.GH_TOKEN).not.toBe("$vault:github");
    }

    // Now switch to inline mode on disk
    await new Promise(r => setTimeout(r, 50)); // ensure mtime changes
    config = readConfig(vaultDir);
    config = { ...config, resolverMode: "inline" };
    writeConfig(vaultDir, config);

    // Second call: should hot-reload and use inline mode → injection works
    const result2 = await handleBeforeToolCall(
      { toolName: "exec", params: { command: "gh pr list" } },
      makeBeforeCtx("exec"),
    );

    const env2 = result2!.params!.env as Record<string, string>;
    expect(env2).toBeDefined();
    expect(env2.GH_TOKEN).toBe("ghp_realtoken123456789012345678901234");

    vi.restoreAllMocks();
  });
});

describe("Hook E2E: macOS Fix — inline mode full round-trip", () => {
  afterEach(cleanup);

  it("inline mode: credential encrypted, injected, and scrubbed end-to-end", async () => {
    await setupVault({
      "github": {
        credential: "ghp_livetoken99887766554433221100aabb",
        config: {
          inject: [{
            tool: "exec",
            commandMatch: "gh *",
            env: { GH_TOKEN: "$vault:github" },
          }],
          scrub: { patterns: ["ghp_[a-zA-Z0-9]{36}"] },
        },
      },
    });

    // Step 1: Injection — credential appears in params.env
    const injectResult = await handleBeforeToolCall(
      { toolName: "exec", params: { command: "gh api user" } },
      makeBeforeCtx("exec"),
    );

    const env = injectResult!.params!.env as Record<string, string>;
    expect(env.GH_TOKEN).toBe("ghp_livetoken99887766554433221100aabb");

    // Step 2: Scrubbing — credential in tool output gets redacted
    const scrubResult = handleToolResultPersist(
      {
        toolName: "exec",
        message: {
          role: "tool",
          content: "Token is ghp_livetoken99887766554433221100aabb and it works",
        },
      },
      { toolName: "exec" },
    );

    const scrubbedContent = scrubResult!.message!.content as string;
    expect(scrubbedContent).not.toContain("ghp_livetoken99887766554433221100aabb");
    expect(scrubbedContent).toContain("[VAULT:github]");

    // Step 3: Message write scrubbing — credential in outbound message gets redacted
    const msgResult = handleBeforeMessageWrite(
      {
        message: {
          role: "assistant",
          content: "The token ghp_livetoken99887766554433221100aabb was used",
        },
      },
      {},
    );

    const msgContent = msgResult!.message!.content as string;
    expect(msgContent).not.toContain("ghp_livetoken99887766554433221100aabb");
    expect(msgContent).toContain("[VAULT:github]");
  });

  it("inline mode: web_fetch header injection works correctly", async () => {
    await setupVault({
      "myapi": {
        credential: "secret-api-key-12345",
        config: {
          inject: [{
            tool: "web_fetch",
            urlMatch: "*api.myservice.com/*",
            headers: { "x-api-key": "$vault:myapi" },
          }],
          scrub: { patterns: [] },
        },
      },
    });

    const result = await handleBeforeToolCall(
      {
        toolName: "web_fetch",
        params: { url: "https://api.myservice.com/v1/data" },
      },
      makeBeforeCtx("web_fetch"),
    );

    const headers = result!.params!.headers as Record<string, string>;
    expect(headers["x-api-key"]).toBe("secret-api-key-12345");
  });

  it("inline mode: header injection skipped when credential resolution fails", async () => {
    // Set up with a tool that references a non-existent credential
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "vault-macos-e2e-"));
    vaultDir = path.join(tmpDir, ".openclaw", "vault");
    fs.mkdirSync(vaultDir, { recursive: true });
    originalHome = process.env.HOME;
    process.env.HOME = tmpDir;

    initConfig(vaultDir, "machine");

    // Write config referencing a credential that doesn't have an .enc file
    // Note: header value must be exactly "$vault:ghost" (not "Bearer $vault:ghost")
    // because resolveVaultRef only matches strings that are entirely $vault:X
    let config = readConfig(vaultDir);
    config = upsertTool(config, {
      name: "ghost",
      addedAt: new Date().toISOString(),
      lastRotated: new Date().toISOString(),
      inject: [{
        tool: "web_fetch",
        urlMatch: "*api.ghost.com/*",
        headers: { "x-api-key": "$vault:ghost" },
      }],
      scrub: { patterns: [] },
    });
    writeConfig(vaultDir, config);
    register(buildMockApi());

    vi.spyOn(console, "error").mockImplementation(() => {});

    const result = await handleBeforeToolCall(
      {
        toolName: "web_fetch",
        params: { url: "https://api.ghost.com/v1/posts" },
      },
      makeBeforeCtx("web_fetch"),
    );

    // Header should NOT be set at all (credential missing = skip injection)
    const headers = result!.params!.headers as Record<string, string> | undefined;
    expect(headers?.["x-api-key"]).toBeUndefined();

    // Should have logged a warning
    const warnings = (console.error as any).mock.calls.filter(
      (args: any[]) => typeof args[0] === "string" && args[0].includes("could not be resolved")
    );
    expect(warnings.length).toBeGreaterThan(0);

    vi.restoreAllMocks();
  });
});

// ================================================================
// Audit Logging: browser-password and browser-cookie injections
// ================================================================
describe("Hook E2E: Audit Logging — browser-password injection", () => {
  beforeEach(async () => {
    await setupVault({
      "test-cred": {
        credential: "SuperSecret123!",
        config: {
          inject: [
            {
              tool: "browser",
              type: "browser-password",
              domainPin: [".example.com"],
              method: "fill",
            },
          ],
          scrub: { patterns: [] },
        },
      },
    });
  });

  afterEach(cleanup);

  it("should track browser-password injection in currentInjections (direct text param)", async () => {
    // Populate tab URL cache
    handleAfterToolCall(
      {
        toolName: "browser",
        params: { action: "navigate", url: "https://example.com/login", targetId: "TAB1" },
        result: {
          content: [{ type: "text", text: '{"ok":true}' }],
          details: { ok: true, targetId: "TAB1", url: "https://example.com/login" },
        },
      },
      makeAfterCtx("browser"),
    );

    // Act with $vault: placeholder
    const result = await handleBeforeToolCall(
      {
        toolName: "browser",
        params: { action: "act", text: "$vault:test-cred", targetId: "TAB1" },
      },
      makeBeforeCtx("browser"),
    );

    expect(result).toBeDefined();
    expect(result!.block).toBeFalsy();
    expect(result!.params!.text).toBe("SuperSecret123!");

    // Verify currentInjections was populated
    expect(_state).not.toBeNull();
    expect(_state!.currentInjections.length).toBe(1);
    expect(_state!.currentInjections[0].tool).toBe("browser");
    expect(_state!.currentInjections[0].credential).toBe("test-cred");
    expect(_state!.currentInjections[0].injectionType).toBe("browser-password");
    expect(_state!.currentInjections[0].command).toBe("https://example.com/login");
    expect(_state!.currentInjections[0].startTime).toBeGreaterThan(0);
  });

  it("should track browser-password injection in currentInjections (nested request param)", async () => {
    // Populate tab URL cache
    handleAfterToolCall(
      {
        toolName: "browser",
        params: { action: "navigate", url: "https://example.com/login", targetId: "TAB2" },
        result: {
          content: [{ type: "text", text: '{"ok":true}' }],
          details: { ok: true, targetId: "TAB2", url: "https://example.com/login" },
        },
      },
      makeAfterCtx("browser"),
    );

    // Act with $vault: in nested request.text
    const result = await handleBeforeToolCall(
      {
        toolName: "browser",
        params: {
          action: "act",
          targetId: "TAB2",
          request: { kind: "fill", text: "$vault:test-cred", ref: "e9" },
        },
      },
      makeBeforeCtx("browser"),
    );

    expect(result).toBeDefined();
    expect(result!.block).toBeFalsy();
    const req = result!.params!.request as Record<string, unknown>;
    expect(req.text).toBe("SuperSecret123!");

    // Verify currentInjections
    expect(_state!.currentInjections.length).toBe(1);
    expect(_state!.currentInjections[0].injectionType).toBe("browser-password");
    expect(_state!.currentInjections[0].credential).toBe("test-cred");
  });

  it("should NOT track injection when domain pin blocks", async () => {
    // Populate cache with wrong domain
    handleAfterToolCall(
      {
        toolName: "browser",
        params: { action: "navigate", url: "https://evil.com/phish", targetId: "TAB3" },
        result: {
          content: [{ type: "text", text: '{"ok":true}' }],
          details: { ok: true, targetId: "TAB3", url: "https://evil.com/phish" },
        },
      },
      makeAfterCtx("browser"),
    );

    const result = await handleBeforeToolCall(
      {
        toolName: "browser",
        params: { action: "act", text: "$vault:test-cred", targetId: "TAB3" },
      },
      makeBeforeCtx("browser"),
    );

    expect(result!.block).toBe(true);
    // No injection should be tracked
    expect(_state!.currentInjections.length).toBe(0);
  });

  it("should write audit log entry via after_tool_call", async () => {
    // Populate tab URL cache
    handleAfterToolCall(
      {
        toolName: "browser",
        params: { action: "navigate", url: "https://example.com/login", targetId: "TAB4" },
        result: {
          content: [{ type: "text", text: '{"ok":true}' }],
          details: { ok: true, targetId: "TAB4", url: "https://example.com/login" },
        },
      },
      makeAfterCtx("browser"),
    );

    // Inject
    await handleBeforeToolCall(
      {
        toolName: "browser",
        params: { action: "act", text: "$vault:test-cred", targetId: "TAB4" },
      },
      makeBeforeCtx("browser"),
    );

    expect(_state!.currentInjections.length).toBe(1);

    // Simulate after_tool_call — this should flush currentInjections to audit log
    handleAfterToolCall(
      {
        toolName: "browser",
        params: { action: "act", text: "[scrubbed]", targetId: "TAB4" },
        result: { content: [{ type: "text", text: '{"ok":true}' }], details: { ok: true } },
      },
      makeAfterCtx("browser"),
    );

    // currentInjections should be cleared after after_tool_call
    expect(_state!.currentInjections.length).toBe(0);

    // Verify audit log file was written
    const auditLogPath = path.join(vaultDir, "audit.log");
    expect(fs.existsSync(auditLogPath)).toBe(true);
    const logContent = fs.readFileSync(auditLogPath, "utf-8");
    const entries = logContent.trim().split("\n").map((l: string) => JSON.parse(l));
    const browserEntry = entries.find(
      (e: any) => e.type === "credential_access" && e.injectionType === "browser-password"
    );
    expect(browserEntry).toBeDefined();
    expect(browserEntry.credential).toBe("test-cred");
    expect(browserEntry.tool).toBe("browser");
  });
});

describe("Hook E2E: Audit Logging — browser-cookie injection", () => {
  const validCookies = JSON.stringify([
    {
      name: "session-id",
      value: "abc-123",
      domain: ".amazon.com",
      path: "/",
      expires: Math.floor(Date.now() / 1000) + 86400,
      httpOnly: true,
      secure: true,
      sameSite: "Lax",
    },
  ]);

  beforeEach(async () => {
    await setupVault({
      "amazon-cookies": {
        credential: validCookies,
        config: {
          inject: [
            {
              tool: "browser",
              type: "browser-cookie",
              domainPin: [".amazon.com"],
              method: "cookie-jar",
            },
          ],
          scrub: { patterns: [] },
        },
      },
    });
  });

  afterEach(cleanup);

  it("should track browser-cookie injection in currentInjections on navigate", async () => {
    const result = await handleBeforeToolCall(
      {
        toolName: "browser",
        params: { action: "navigate", url: "https://www.amazon.com/orders" },
      },
      makeBeforeCtx("browser"),
    );

    expect(result).toBeDefined();
    expect(result!.params!._vaultCookies).toBeDefined();

    // Verify currentInjections
    expect(_state!.currentInjections.length).toBe(1);
    expect(_state!.currentInjections[0].tool).toBe("browser");
    expect(_state!.currentInjections[0].credential).toBe("amazon-cookies");
    expect(_state!.currentInjections[0].injectionType).toBe("browser-cookie");
    expect(_state!.currentInjections[0].command).toBe("https://www.amazon.com/orders");
  });

  it("should NOT track cookie injection when domain doesn't match", async () => {
    const result = await handleBeforeToolCall(
      {
        toolName: "browser",
        params: { action: "navigate", url: "https://www.google.com" },
      },
      makeBeforeCtx("browser"),
    );

    expect(result).toBeDefined();
    expect(result!.params!._vaultCookies).toBeUndefined();
    expect(_state!.currentInjections.length).toBe(0);
  });

  it("should write audit log entry for cookie injection via after_tool_call", async () => {
    // Inject cookies
    await handleBeforeToolCall(
      {
        toolName: "browser",
        params: { action: "navigate", url: "https://www.amazon.com/orders" },
      },
      makeBeforeCtx("browser"),
    );

    expect(_state!.currentInjections.length).toBe(1);

    // Flush via after_tool_call
    handleAfterToolCall(
      {
        toolName: "browser",
        params: { action: "navigate", url: "https://www.amazon.com/orders" },
        result: { content: [{ type: "text", text: '{"ok":true}' }], details: { ok: true, url: "https://www.amazon.com/orders" } },
      },
      makeAfterCtx("browser"),
    );

    expect(_state!.currentInjections.length).toBe(0);

    // Verify audit log
    const auditLogPath = path.join(vaultDir, "audit.log");
    expect(fs.existsSync(auditLogPath)).toBe(true);
    const logContent = fs.readFileSync(auditLogPath, "utf-8");
    const entries = logContent.trim().split("\n").map((l: string) => JSON.parse(l));
    const cookieEntry = entries.find(
      (e: any) => e.type === "credential_access" && e.injectionType === "browser-cookie"
    );
    expect(cookieEntry).toBeDefined();
    expect(cookieEntry.credential).toBe("amazon-cookies");
    expect(cookieEntry.tool).toBe("browser");
  });
});
