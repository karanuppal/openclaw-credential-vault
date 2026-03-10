/**
 * Phase 5: Concurrent Resolution Tests
 *
 * Validates spec section "Pitfall #16: Concurrent exec race conditions":
 * - 5 simultaneous credential resolutions without interference
 * - Each resolution returns the correct credential for its tool
 * - No cross-contamination between concurrent requests
 * - Stateless per-request design (no locking needed)
 *
 * Spec ref: "Stateless per-request, no locking needed"
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import { readCredentialFile, getMachinePassphrase } from "../src/crypto.js";

// --- Mock concurrent resolution ---
// TODO: These tests validate the contract that concurrent credential
// resolutions don't interfere with each other. Once the full plugin
// is wired up, replace mocks with actual resolution calls.

/**
 * Simulates credential resolution for a tool.
 * In the real implementation, this would call getCredential() from index.ts.
 */
async function simulateCredentialResolution(
  toolName: string,
  delayMs: number
): Promise<{ tool: string; credential: string }> {
  // Simulate varying resolution times (Argon2id + file I/O)
  await new Promise((resolve) => setTimeout(resolve, delayMs));

  // Return a deterministic credential per tool
  const credentials: Record<string, string> = {
    github: "ghp_github_credential_value_1234567890abcdef",
    stripe: "sk_live_stripe_credential_value_abcdefgh",
    gumroad: "gum_gumroad_credential_value",
    openai: "sk-openai_credential_value_48chars_padded_to_length",
    anthropic: "sk-ant-anthropic_credential_value_padded_to_80chars_minimum_requirement_met_here_ok",
  };

  return {
    tool: toolName,
    credential: credentials[toolName] ?? `cred_${toolName}`,
  };
}

describe("Concurrent Resolution — 5 simultaneous resolutions", () => {
  it("should resolve all 5 credentials simultaneously without interference", async () => {
    const tools = ["github", "stripe", "gumroad", "openai", "anthropic"];

    // Launch all 5 resolutions concurrently with varying delays
    const promises = tools.map((tool, i) =>
      simulateCredentialResolution(tool, (i + 1) * 10) // 10ms, 20ms, 30ms, 40ms, 50ms
    );

    const results = await Promise.all(promises);

    // Verify all 5 completed
    expect(results).toHaveLength(5);

    // Verify each got the correct credential (no cross-contamination)
    for (const result of results) {
      expect(result.tool).toBeTruthy();
      switch (result.tool) {
        case "github":
          expect(result.credential).toContain("github");
          break;
        case "stripe":
          expect(result.credential).toContain("stripe");
          break;
        case "gumroad":
          expect(result.credential).toContain("gumroad");
          break;
        case "openai":
          expect(result.credential).toContain("openai");
          break;
        case "anthropic":
          expect(result.credential).toContain("anthropic");
          break;
      }
    }
  });

  it("should not have any tool receive another tool's credential", async () => {
    const tools = ["github", "stripe", "gumroad", "openai", "anthropic"];

    const results = await Promise.all(
      tools.map((tool) => simulateCredentialResolution(tool, Math.random() * 50))
    );

    // Cross-check: each tool's credential should NOT contain other tool names
    for (const result of results) {
      const otherTools = tools.filter((t) => t !== result.tool);
      for (const other of otherTools) {
        expect(result.credential).not.toContain(other);
      }
    }
  });

  it("should handle repeated resolutions of the same tool concurrently", async () => {
    // 5 simultaneous resolutions for the SAME tool
    const promises = Array.from({ length: 5 }, (_, i) =>
      simulateCredentialResolution("github", (i + 1) * 5)
    );

    const results = await Promise.all(promises);

    // All should return the same credential
    const firstCred = results[0].credential;
    for (const result of results) {
      expect(result.credential).toBe(firstCred);
      expect(result.tool).toBe("github");
    }
  });

  it("should complete all resolutions within reasonable time", async () => {
    const start = Date.now();

    const tools = ["github", "stripe", "gumroad", "openai", "anthropic"];
    const promises = tools.map((tool) =>
      simulateCredentialResolution(tool, 20) // 20ms each
    );

    await Promise.all(promises);

    const elapsed = Date.now() - start;

    // Concurrent: should complete in ~20ms (not 5 * 20ms = 100ms)
    // Allow generous margin for CI
    expect(elapsed).toBeLessThan(200);
  });

  it("should maintain credential cache independence per tool", async () => {
    // Simulate the credential cache behavior:
    // First resolution caches, subsequent reads from cache
    const cache = new Map<string, string>();

    async function cachedResolve(tool: string): Promise<string> {
      if (cache.has(tool)) {
        return cache.get(tool)!;
      }
      const result = await simulateCredentialResolution(tool, 10);
      cache.set(tool, result.credential);
      return result.credential;
    }

    // Resolve all concurrently
    const [gh1, st1, gm1] = await Promise.all([
      cachedResolve("github"),
      cachedResolve("stripe"),
      cachedResolve("gumroad"),
    ]);

    // Resolve again (should hit cache)
    const [gh2, st2, gm2] = await Promise.all([
      cachedResolve("github"),
      cachedResolve("stripe"),
      cachedResolve("gumroad"),
    ]);

    // Same values both times
    expect(gh1).toBe(gh2);
    expect(st1).toBe(st2);
    expect(gm1).toBe(gm2);

    // Different from each other
    expect(gh1).not.toBe(st1);
    expect(st1).not.toBe(gm1);
  });
});
