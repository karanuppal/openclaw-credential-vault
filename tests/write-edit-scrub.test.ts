/**
 * Phase 5: Write/Edit Tool Scrubbing Tests
 *
 * Validates spec section "Write/Edit Tool Scrubbing" (Phase 3D):
 * - before_tool_call intercepts write/edit tools
 * - Scrubs credential patterns from content/newText/new_string params
 * - Prevents credential leakage into memory files, workspace docs, etc.
 *
 * Spec ref: "the agent can leak secrets by writing them to memory files"
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import {
  compileScrubRules,
  scrubText,
  CompiledScrubRule,
} from "../src/scrubber.js";
import { ToolConfig } from "../src/types.js";

// --- Test fixtures ---

const testTools: Record<string, ToolConfig> = {
  stripe: {
    name: "stripe",
    addedAt: "2026-01-01",
    lastRotated: "2026-01-01",
    inject: [],
    scrub: { patterns: ["sk_live_[a-zA-Z0-9]{24,}", "sk_test_[a-zA-Z0-9]{24,}"] },
  },
  github: {
    name: "github",
    addedAt: "2026-01-01",
    lastRotated: "2026-01-01",
    inject: [],
    scrub: { patterns: ["ghp_[a-zA-Z0-9]{36}"] },
  },
  gumroad: {
    name: "gumroad",
    addedAt: "2026-01-01",
    lastRotated: "2026-01-01",
    inject: [],
    scrub: { patterns: ["gum_[a-zA-Z0-9]{16,}"] },
  },
};

/**
 * Simulates the before_tool_call write/edit scrubbing logic from spec.
 * TODO: Replace with actual import once src/index.ts implements this path.
 *
 * Spec pseudocode:
 *   if (toolName === "write" || toolName === "edit") {
 *     const content = params.content || params.newText || params.new_string;
 *     if (content) { scrub and return modified params }
 *   }
 */
function scrubWriteEditParams(
  toolName: string,
  params: Record<string, unknown>,
  rules: CompiledScrubRule[]
): Record<string, unknown> {
  if (toolName !== "write" && toolName !== "edit") return params;

  const contentKeys = ["content", "newText", "new_string"];
  for (const key of contentKeys) {
    const value = params[key];
    if (typeof value === "string") {
      const scrubbed = scrubText(value, rules);
      if (scrubbed !== value) {
        return { ...params, [key]: scrubbed };
      }
    }
  }
  return params;
}

describe("Write/Edit Tool Scrubbing — before_tool_call intercept", () => {
  let rules: CompiledScrubRule[];

  beforeEach(() => {
    rules = compileScrubRules(testTools);
  });

  describe("write tool — content param", () => {
    it("should scrub Stripe key from write content", () => {
      const params = {
        file_path: "/workspace/memory/2026-03-10.md",
        content: "Used Stripe key sk_live_abcdefghijklmnopqrstuvwx for payment",
      };
      const result = scrubWriteEditParams("write", params, rules);
      expect(result.content).toBe("Used Stripe key [VAULT:stripe] for payment");
      expect(result.file_path).toBe(params.file_path); // path unchanged
    });

    it("should scrub GitHub PAT from write content", () => {
      const params = {
        content: "export GH_TOKEN=ghp_abcdefghijklmnopqrstuvwxyz1234567890",
      };
      const result = scrubWriteEditParams("write", params, rules);
      expect(result.content).toBe("export GH_TOKEN=[VAULT:github]");
    });

    it("should scrub multiple credentials from write content", () => {
      const params = {
        content: "stripe: sk_live_abcdefghijklmnopqrstuvwx\ngithub: ghp_abcdefghijklmnopqrstuvwxyz1234567890",
      };
      const result = scrubWriteEditParams("write", params, rules);
      expect(result.content).toContain("[VAULT:stripe]");
      expect(result.content).toContain("[VAULT:github]");
      expect(result.content).not.toContain("sk_live_");
      expect(result.content).not.toContain("ghp_");
    });

    it("should not modify content without credentials", () => {
      const params = {
        content: "Just a normal memory note about today's work",
      };
      const result = scrubWriteEditParams("write", params, rules);
      expect(result.content).toBe(params.content);
    });
  });

  describe("edit tool — newText param", () => {
    it("should scrub credentials from newText", () => {
      const params = {
        file_path: "/workspace/config.yaml",
        oldText: "api_key: placeholder",
        newText: "api_key: sk_live_abcdefghijklmnopqrstuvwx",
      };
      const result = scrubWriteEditParams("edit", params, rules);
      expect(result.newText).toBe("api_key: [VAULT:stripe]");
      expect(result.oldText).toBe("api_key: placeholder"); // oldText untouched
    });
  });

  describe("edit tool — new_string param", () => {
    it("should scrub credentials from new_string", () => {
      const params = {
        old_string: "token: xxx",
        new_string: "token: gum_abcdefghijklmnop",
      };
      const result = scrubWriteEditParams("edit", params, rules);
      expect(result.new_string).toBe("token: [VAULT:gumroad]");
      expect(result.old_string).toBe("token: xxx"); // old_string untouched
    });
  });

  describe("non-write/edit tools are not intercepted", () => {
    it("should not scrub exec params", () => {
      const params = {
        command: "echo sk_live_abcdefghijklmnopqrstuvwx",
      };
      const result = scrubWriteEditParams("exec", params, rules);
      expect(result.command).toBe(params.command); // untouched
    });

    it("should not scrub browser params", () => {
      const params = {
        text: "sk_live_abcdefghijklmnopqrstuvwx",
      };
      const result = scrubWriteEditParams("browser", params, rules);
      expect(result.text).toBe(params.text);
    });
  });

  describe("edge cases", () => {
    it("should handle empty content", () => {
      const params = { content: "" };
      const result = scrubWriteEditParams("write", params, rules);
      expect(result.content).toBe("");
    });

    it("should handle params without any content key", () => {
      const params = { file_path: "/some/path" };
      const result = scrubWriteEditParams("write", params, rules);
      expect(result).toEqual(params);
    });

    it("should prioritize content over newText over new_string", () => {
      // If 'content' exists and has a credential, it gets scrubbed first
      const params = {
        content: "sk_live_abcdefghijklmnopqrstuvwx",
        newText: "ghp_abcdefghijklmnopqrstuvwxyz1234567890",
      };
      const result = scrubWriteEditParams("write", params, rules);
      expect(result.content).toBe("[VAULT:stripe]");
    });

    it("should scrub credential embedded in JSON content", () => {
      const params = {
        content: '{"api_key": "sk_live_abcdefghijklmnopqrstuvwx", "env": "prod"}',
      };
      const result = scrubWriteEditParams("write", params, rules);
      expect(result.content).toContain("[VAULT:stripe]");
      expect(result.content).not.toContain("sk_live_");
    });

    it("should scrub credential in YAML content", () => {
      const params = {
        content: "stripe:\n  key: sk_test_abcdefghijklmnopqrstuvwx\n  env: test",
      };
      const result = scrubWriteEditParams("write", params, rules);
      expect(result.content).toContain("[VAULT:stripe]");
      expect(result.content).not.toContain("sk_test_");
    });
  });
});
