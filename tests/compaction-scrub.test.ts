/**
 * Phase 5: Compaction Scrub Verification Tests
 *
 * Validates spec requirement: "Compaction scrub verification"
 * Spec ref: Pitfall #6 — "Compaction preserves leaked secrets"
 * Mitigation: "before_message_write scrubs compacted output"
 *
 * Tests that when the context compaction pipeline produces output
 * (summarized/compacted conversation), it passes through the scrubbing
 * pipeline before being written to the transcript.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";
import {
  compileScrubRules,
  scrubText,
  scrubLiteralCredential,
  scrubTextWithTracking,
  addLiteralCredential,
  clearLiteralCredentials,
  CompiledScrubRule,
} from "../src/scrubber.js";
import { logCompactionEvent, readAuditLog } from "../src/audit.js";
import { ToolConfig } from "../src/types.js";

const testTools: Record<string, ToolConfig> = {
  github: {
    name: "github",
    addedAt: "2026-01-01",
    lastRotated: "2026-01-01",
    inject: [],
    scrub: { patterns: ["ghp_[a-zA-Z0-9]{36}"] },
  },
  stripe: {
    name: "stripe",
    addedAt: "2026-01-01",
    lastRotated: "2026-01-01",
    inject: [],
    scrub: { patterns: ["sk_live_[a-zA-Z0-9]{24,}"] },
  },
  openai: {
    name: "openai",
    addedAt: "2026-01-01",
    lastRotated: "2026-01-01",
    inject: [],
    scrub: { patterns: ["sk-[a-zA-Z0-9]{48,}"] },
  },
};

let rules: CompiledScrubRule[];
let tmpDir: string;

beforeEach(() => {
  clearLiteralCredentials();
  rules = compileScrubRules(testTools);
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "vault-compaction-test-"));
});

afterEach(() => {
  clearLiteralCredentials();
  fs.rmSync(tmpDir, { recursive: true, force: true });
});

/**
 * Simulate the before_message_write hook processing compacted content.
 * This mirrors handleBeforeMessageWrite from index.ts.
 */
function simulateBeforeMessageWrite(
  message: string,
  scrubRules: CompiledScrubRule[],
  cachedCredentials: Map<string, string>
): string {
  const { text } = scrubTextWithTracking(message, scrubRules);
  let result = text;
  for (const [toolName, cred] of cachedCredentials.entries()) {
    result = scrubLiteralCredential(result, cred, toolName);
  }
  return result;
}

describe("Compaction scrub — before_message_write scrubs compacted output", () => {
  it("should scrub regex-matched credentials from compacted summaries", () => {
    const compactedContent = `[Compacted conversation summary]
The agent cloned the repository using GitHub PAT ghp_abcdefghijklmnopqrstuvwxyz1234567890
and configured the Stripe integration with key sk_live_abcdefghijklmnopqrstuvwx.
All tests passed successfully.`;

    const scrubbed = simulateBeforeMessageWrite(
      compactedContent,
      rules,
      new Map()
    );

    expect(scrubbed).toContain("[VAULT:github]");
    expect(scrubbed).toContain("[VAULT:stripe]");
    expect(scrubbed).not.toContain("ghp_");
    expect(scrubbed).not.toContain("sk_live_");
    expect(scrubbed).toContain("All tests passed successfully.");
  });

  it("should scrub literal credentials from compacted output", () => {
    const cachedCredentials = new Map([
      ["acme-api", "super-secret-acme-key-do-not-leak"],
      ["internal-db", "db-password-hunter2-production"],
    ]);
    addLiteralCredential("super-secret-acme-key-do-not-leak", "acme-api");
    addLiteralCredential("db-password-hunter2-production", "internal-db");

    const compactedContent = `[Summary of tool calls]
Agent called ACME API with key super-secret-acme-key-do-not-leak.
Database connection used password db-password-hunter2-production.
Operations completed.`;

    const scrubbed = simulateBeforeMessageWrite(
      compactedContent,
      rules,
      cachedCredentials
    );

    expect(scrubbed).not.toContain("super-secret-acme-key-do-not-leak");
    expect(scrubbed).not.toContain("db-password-hunter2-production");
    expect(scrubbed).toContain("[VAULT:acme-api]");
    expect(scrubbed).toContain("[VAULT:internal-db]");
    expect(scrubbed).toContain("Operations completed.");
  });

  it("should scrub both regex and literal credentials in same compacted output", () => {
    addLiteralCredential("opaque-token-for-custom-service-xyz", "custom");

    const compactedContent = `[Compacted]
GitHub: ghp_abcdefghijklmnopqrstuvwxyz1234567890
Custom: opaque-token-for-custom-service-xyz
Done.`;

    const scrubbed = simulateBeforeMessageWrite(
      compactedContent,
      rules,
      new Map([["custom", "opaque-token-for-custom-service-xyz"]])
    );

    expect(scrubbed).not.toContain("ghp_");
    expect(scrubbed).not.toContain("opaque-token-for-custom-service-xyz");
    expect(scrubbed).toContain("[VAULT:github]");
    expect(scrubbed).toContain("[VAULT:custom]");
  });

  it("should handle compacted output with multiple occurrences of same credential", () => {
    const compactedContent = `[Summary]
Step 1: Used ghp_abcdefghijklmnopqrstuvwxyz1234567890 to clone.
Step 2: Pushed with ghp_abcdefghijklmnopqrstuvwxyz1234567890.
Step 3: Created PR with ghp_abcdefghijklmnopqrstuvwxyz1234567890.`;

    const scrubbed = simulateBeforeMessageWrite(
      compactedContent,
      rules,
      new Map()
    );

    expect(scrubbed).not.toContain("ghp_");
    // All three occurrences should be replaced
    const matches = scrubbed.match(/\[VAULT:github\]/g);
    expect(matches).toHaveLength(3);
  });

  it("should leave clean compacted output unmodified", () => {
    const cleanContent = `[Compacted conversation]
Agent helped user set up a Node.js project.
Dependencies installed: express, typescript, vitest.
Project structure created with src/ and tests/ directories.`;

    const scrubbed = simulateBeforeMessageWrite(
      cleanContent,
      rules,
      new Map()
    );

    expect(scrubbed).toBe(cleanContent);
  });
});

describe("Compaction scrub — audit logging", () => {
  it("should log compaction event with scrubbing active", () => {
    logCompactionEvent(
      { scrubbingActive: true, sessionKey: "test-session" },
      tmpDir
    );

    const events = readAuditLog({}, tmpDir);
    expect(events.length).toBe(1);
    expect(events[0].type).toBe("compaction");
    if (events[0].type === "compaction") {
      expect(events[0].scrubbingActive).toBe(true);
    }
  });

  it("should log compaction event with scrubbing inactive", () => {
    logCompactionEvent(
      { scrubbingActive: false, sessionKey: "empty-vault" },
      tmpDir
    );

    const events = readAuditLog({}, tmpDir);
    expect(events.length).toBe(1);
    expect(events[0].type).toBe("compaction");
    if (events[0].type === "compaction") {
      expect(events[0].scrubbingActive).toBe(false);
    }
  });

  it("should track scrub replacements in compacted content for audit", () => {
    const compactedContent =
      "Used ghp_abcdefghijklmnopqrstuvwxyz1234567890 and sk_live_abcdefghijklmnopqrstuvwx";

    const { text, replacements } = scrubTextWithTracking(
      compactedContent,
      rules
    );

    expect(text).toContain("[VAULT:github]");
    expect(text).toContain("[VAULT:stripe]");
    expect(replacements.length).toBeGreaterThanOrEqual(2);

    const githubReplacement = replacements.find((r) => r.toolName === "github");
    expect(githubReplacement).toBeTruthy();
    expect(githubReplacement!.count).toBe(1);

    const stripeReplacement = replacements.find((r) => r.toolName === "stripe");
    expect(stripeReplacement).toBeTruthy();
    expect(stripeReplacement!.count).toBe(1);
  });
});

describe("Compaction scrub — edge cases", () => {
  it("should handle empty compacted output", () => {
    const scrubbed = simulateBeforeMessageWrite("", rules, new Map());
    expect(scrubbed).toBe("");
  });

  it("should handle compacted output that is only a credential", () => {
    const scrubbed = simulateBeforeMessageWrite(
      "ghp_abcdefghijklmnopqrstuvwxyz1234567890",
      rules,
      new Map()
    );
    expect(scrubbed).toBe("[VAULT:github]");
  });

  it("should handle very long compacted output with embedded credentials", () => {
    // Simulate a large compacted summary
    const padding = "Normal conversation content. ".repeat(500);
    const compactedContent = `${padding}Secret: ghp_abcdefghijklmnopqrstuvwxyz1234567890${padding}`;

    const scrubbed = simulateBeforeMessageWrite(
      compactedContent,
      rules,
      new Map()
    );

    expect(scrubbed).not.toContain("ghp_");
    expect(scrubbed).toContain("[VAULT:github]");
  });

  it("should handle credentials split across compaction boundary (adjacent tokens)", () => {
    // Test that partial credential patterns don't cause false negatives
    // A full credential should always be caught even in compacted text
    const compactedContent = `Token:ghp_abcdefghijklmnopqrstuvwxyz1234567890.`;

    const scrubbed = simulateBeforeMessageWrite(
      compactedContent,
      rules,
      new Map()
    );

    expect(scrubbed).not.toContain("ghp_");
    expect(scrubbed).toContain("[VAULT:github]");
  });
});
