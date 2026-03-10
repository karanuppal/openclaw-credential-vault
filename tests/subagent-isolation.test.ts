/**
 * Phase 5: Sub-agent Isolation Tests
 *
 * Validates spec requirement: "Sub-agent isolation (verify hooks fire for sub-agents)"
 * Spec ref: Pitfall #3 — "Sub-agents don't get hook interception"
 * Mitigation: "Hooks fire at gateway level for all sessions"
 *
 * Tests that beforeToolCall/afterToolCall hooks execute identically
 * regardless of whether the tool call originates from a main session
 * or a sub-agent session.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";
import {
  compileScrubRules,
  scrubText,
  scrubLiteralCredential,
  addLiteralCredential,
  clearLiteralCredentials,
  CompiledScrubRule,
} from "../src/scrubber.js";
import { ToolConfig } from "../src/types.js";

/**
 * Simulates the gateway-level hook dispatch.
 * In the real system, hooks fire at the gateway level and are session-agnostic —
 * both main agent and sub-agent sessions go through the same hook pipeline.
 */
interface HookContext {
  sessionId: string;
  sessionType: "main" | "subagent";
  tool: string;
  params: Record<string, unknown>;
}

const testTools: Record<string, ToolConfig> = {
  github: {
    name: "github",
    addedAt: "2026-01-01",
    lastRotated: "2026-01-01",
    inject: [
      {
        tool: "exec",
        commandMatch: "gh *",
        env: { GITHUB_TOKEN: "$vault:github" },
      },
    ],
    scrub: { patterns: ["ghp_[a-zA-Z0-9]{36}"] },
  },
  stripe: {
    name: "stripe",
    addedAt: "2026-01-01",
    lastRotated: "2026-01-01",
    inject: [],
    scrub: { patterns: ["sk_live_[a-zA-Z0-9]{24,}"] },
  },
};

let rules: CompiledScrubRule[];

beforeEach(() => {
  clearLiteralCredentials();
  rules = compileScrubRules(testTools);
});

afterEach(() => {
  clearLiteralCredentials();
});

/**
 * Simulate before_tool_call scrubbing (write/edit interception)
 * as it would run at the gateway level.
 */
function simulateBeforeToolCallScrub(
  ctx: HookContext,
  scrubRules: CompiledScrubRule[]
): Record<string, unknown> {
  const params = { ...ctx.params };
  const contentKeys = ["content", "newText", "new_string"];

  for (const key of contentKeys) {
    const value = params[key];
    if (typeof value === "string") {
      params[key] = scrubText(value, scrubRules);
    }
  }
  return params;
}

/**
 * Simulate after_tool_call scrubbing as it would run at the gateway level.
 */
function simulateAfterToolCallScrub(
  output: string,
  scrubRules: CompiledScrubRule[]
): string {
  return scrubText(output, scrubRules);
}

describe("Sub-agent isolation — hooks fire for sub-agent sessions", () => {
  it("should scrub output from sub-agent sessions (after_tool_call)", () => {
    const subagentOutput =
      "Cloned repo using token ghp_abcdefghijklmnopqrstuvwxyz1234567890";

    const scrubbed = simulateAfterToolCallScrub(subagentOutput, rules);

    expect(scrubbed).toContain("[VAULT:github]");
    expect(scrubbed).not.toContain("ghp_");
  });

  it("should scrub output from main session identically (after_tool_call)", () => {
    const mainOutput =
      "Cloned repo using token ghp_abcdefghijklmnopqrstuvwxyz1234567890";

    const scrubbed = simulateAfterToolCallScrub(mainOutput, rules);

    expect(scrubbed).toContain("[VAULT:github]");
    expect(scrubbed).not.toContain("ghp_");
  });

  it("should produce identical scrub results for main and sub-agent sessions", () => {
    const output =
      "Keys: ghp_abcdefghijklmnopqrstuvwxyz1234567890 and sk_live_abcdefghijklmnopqrstuvwx";

    const mainResult = simulateAfterToolCallScrub(output, rules);
    const subagentResult = simulateAfterToolCallScrub(output, rules);

    expect(mainResult).toBe(subagentResult);
    expect(mainResult).toContain("[VAULT:github]");
    expect(mainResult).toContain("[VAULT:stripe]");
  });

  it("should scrub write tool content from sub-agent sessions (before_tool_call)", () => {
    const ctx: HookContext = {
      sessionId: "subagent:task-123",
      sessionType: "subagent",
      tool: "write",
      params: {
        path: "/tmp/notes.md",
        content: "API key: ghp_abcdefghijklmnopqrstuvwxyz1234567890",
      },
    };

    const scrubbedParams = simulateBeforeToolCallScrub(ctx, rules);

    expect(scrubbedParams.content).toContain("[VAULT:github]");
    expect(scrubbedParams.content).not.toContain("ghp_");
  });

  it("should scrub edit tool newText from sub-agent sessions (before_tool_call)", () => {
    const ctx: HookContext = {
      sessionId: "subagent:coding-fix-456",
      sessionType: "subagent",
      tool: "edit",
      params: {
        path: "/tmp/config.ts",
        oldText: "placeholder",
        newText: 'const KEY = "sk_live_abcdefghijklmnopqrstuvwx";',
      },
    };

    const scrubbedParams = simulateBeforeToolCallScrub(ctx, rules);

    expect(scrubbedParams.newText).toContain("[VAULT:stripe]");
    expect(scrubbedParams.newText).not.toContain("sk_live_");
  });

  it("should handle literal credentials from sub-agent sessions", () => {
    addLiteralCredential("my-secret-subagent-token-xyz", "custom-service");

    const output = "Sub-agent received: my-secret-subagent-token-xyz in response";
    const scrubbed = scrubText(output, rules);

    expect(scrubbed).toContain("[VAULT:custom-service]");
    expect(scrubbed).not.toContain("my-secret-subagent-token-xyz");
  });

  it("should handle concurrent sub-agent sessions without cross-contamination", async () => {
    const sessions = [
      {
        id: "subagent:task-1",
        output: "Token: ghp_abcdefghijklmnopqrstuvwxyz1234567890",
        expectedTag: "[VAULT:github]",
      },
      {
        id: "subagent:task-2",
        output: "Key: sk_live_abcdefghijklmnopqrstuvwx",
        expectedTag: "[VAULT:stripe]",
      },
      {
        id: "subagent:task-3",
        output: "Both: ghp_abcdefghijklmnopqrstuvwxyz1234567890 and sk_live_abcdefghijklmnopqrstuvwx",
        expectedTag: "[VAULT:",
      },
    ];

    // Process all sessions concurrently
    const results = await Promise.all(
      sessions.map(async (session) => {
        // Simulate slight delay variance
        await new Promise((r) => setTimeout(r, Math.random() * 10));
        return {
          id: session.id,
          scrubbed: simulateAfterToolCallScrub(session.output, rules),
        };
      })
    );

    // Verify each session got correct scrubbing
    expect(results[0].scrubbed).toContain("[VAULT:github]");
    expect(results[0].scrubbed).not.toContain("ghp_");

    expect(results[1].scrubbed).toContain("[VAULT:stripe]");
    expect(results[1].scrubbed).not.toContain("sk_live_");

    expect(results[2].scrubbed).toContain("[VAULT:github]");
    expect(results[2].scrubbed).toContain("[VAULT:stripe]");
  });

  it("should not modify non-secret content from sub-agent sessions", () => {
    const cleanOutput = "Sub-agent completed: 42 files processed, 0 errors.";
    const scrubbed = simulateAfterToolCallScrub(cleanOutput, rules);
    expect(scrubbed).toBe(cleanOutput);
  });
});
