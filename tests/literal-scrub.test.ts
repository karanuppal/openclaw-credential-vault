/**
 * Phase 5: Hash-Based Literal Scrubbing Tests
 *
 * Validates spec section "Hash-Based Literal Scrubbing" (Phase 3E):
 * - After credential injection, plaintext value added to in-memory literal match list
 * - SHA-256 hash stored on disk as reference (never plaintext)
 * - Every output scrubbing pass runs indexOf/string search for literal value
 * - Catches credentials that have no recognizable prefix or pattern
 *
 * Spec ref: "Both strategies are required. Regex alone misses format-agnostic secrets."
 */

import { describe, it, expect } from "vitest";
import { scrubLiteralCredential } from "../src/scrubber.js";
import * as crypto from "crypto";

// --- Mock literal scrub manager (NOT BUILT yet) ---
// TODO: Replace with actual implementation from src/scrubber.ts or src/index.ts

/**
 * Simulates the in-memory literal match list that tracks
 * credentials after they've been injected.
 */
class LiteralScrubManager {
  private literals: Map<string, string> = new Map(); // toolName -> plaintext
  private hashes: Map<string, string> = new Map(); // SHA-256 hash -> toolName

  /**
   * Register a credential for literal scrubbing after injection.
   */
  registerLiteral(toolName: string, credential: string): void {
    this.literals.set(toolName, credential);
    const hash = crypto.createHash("sha256").update(credential).digest("hex");
    this.hashes.set(hash, toolName);
  }

  /**
   * Scrub all registered literal credentials from text.
   */
  scrubAll(text: string): string {
    let result = text;
    for (const [toolName, cred] of this.literals) {
      result = scrubLiteralCredential(result, cred, toolName);
    }
    return result;
  }

  /**
   * Check if a SHA-256 hash corresponds to a registered credential.
   */
  isKnownHash(hash: string): boolean {
    return this.hashes.has(hash);
  }

  /**
   * Get tool name for a SHA-256 hash.
   */
  getToolForHash(hash: string): string | undefined {
    return this.hashes.get(hash);
  }

  /**
   * Get SHA-256 hash for a credential value.
   */
  static hashCredential(credential: string): string {
    return crypto.createHash("sha256").update(credential).digest("hex");
  }
}

describe("Literal Scrubbing — no-prefix credentials after injection", () => {
  it("should scrub a random API key with no known prefix", () => {
    const manager = new LiteralScrubManager();
    const credential = "a7b9c3d8e5f2g1h4i6j0k9l8m7n2o5p4";
    manager.registerLiteral("acme", credential);

    const output = `API response: key=${credential}, status=ok`;
    const scrubbed = manager.scrubAll(output);

    expect(scrubbed).not.toContain(credential);
    expect(scrubbed).toContain("[VAULT:acme]");
  });

  it("should scrub a password with special characters", () => {
    const manager = new LiteralScrubManager();
    const credential = "P@ssw0rd!2026#$%^";
    manager.registerLiteral("myservice", credential);

    const output = `Login with password: ${credential}`;
    const scrubbed = manager.scrubAll(output);

    expect(scrubbed).not.toContain(credential);
    expect(scrubbed).toContain("[VAULT:myservice]");
  });

  it("should scrub credentials appearing multiple times", () => {
    const manager = new LiteralScrubManager();
    const credential = "secret_token_12345678";
    manager.registerLiteral("service", credential);

    const output = `Token1: ${credential}, Token2: ${credential}`;
    const scrubbed = manager.scrubAll(output);

    const occurrences = (scrubbed.match(/\[VAULT:service\]/g) || []).length;
    expect(occurrences).toBe(2);
    expect(scrubbed).not.toContain(credential);
  });

  it("should scrub multiple different credentials", () => {
    const manager = new LiteralScrubManager();
    manager.registerLiteral("github", "my_github_token_abc123");
    manager.registerLiteral("stripe", "my_stripe_secret_xyz789");

    const output = "Keys: my_github_token_abc123 and my_stripe_secret_xyz789";
    const scrubbed = manager.scrubAll(output);

    expect(scrubbed).not.toContain("my_github_token_abc123");
    expect(scrubbed).not.toContain("my_stripe_secret_xyz789");
    expect(scrubbed).toContain("[VAULT:github]");
    expect(scrubbed).toContain("[VAULT:stripe]");
  });

  it("should not scrub very short credentials (< 4 chars)", () => {
    const manager = new LiteralScrubManager();
    manager.registerLiteral("test", "abc");

    const output = "Short: abc in context";
    const scrubbed = manager.scrubAll(output);

    // scrubLiteralCredential skips credentials < 4 chars
    expect(scrubbed).toBe(output);
  });
});

describe("Literal Scrubbing — SHA-256 hash reference", () => {
  it("should store SHA-256 hash of credential", () => {
    const manager = new LiteralScrubManager();
    const credential = "secret_api_key_12345";
    const expectedHash = crypto.createHash("sha256").update(credential).digest("hex");

    manager.registerLiteral("myservice", credential);

    expect(manager.isKnownHash(expectedHash)).toBe(true);
    expect(manager.getToolForHash(expectedHash)).toBe("myservice");
  });

  it("should produce correct SHA-256 hash for known credential", () => {
    const credential = "ghp_abcdefghijklmnopqrstuvwxyz1234567890";
    const hash = LiteralScrubManager.hashCredential(credential);

    // SHA-256 produces 64 hex chars
    expect(hash).toHaveLength(64);
    expect(hash).toMatch(/^[0-9a-f]{64}$/);
  });

  it("should not match unrelated hashes", () => {
    const manager = new LiteralScrubManager();
    manager.registerLiteral("test", "my_credential");

    const wrongHash = crypto.createHash("sha256").update("different_credential").digest("hex");
    expect(manager.isKnownHash(wrongHash)).toBe(false);
  });

  it("should track multiple credentials with unique hashes", () => {
    const manager = new LiteralScrubManager();
    const creds = [
      { tool: "github", value: "github_cred_123" },
      { tool: "stripe", value: "stripe_cred_456" },
      { tool: "gumroad", value: "gumroad_cred_789" },
    ];

    for (const cred of creds) {
      manager.registerLiteral(cred.tool, cred.value);
    }

    for (const cred of creds) {
      const hash = LiteralScrubManager.hashCredential(cred.value);
      expect(manager.isKnownHash(hash)).toBe(true);
      expect(manager.getToolForHash(hash)).toBe(cred.tool);
    }
  });
});

describe("Literal Scrubbing — combined with regex scrubbing", () => {
  it("should catch credentials that regex misses", () => {
    const manager = new LiteralScrubManager();
    // A credential with no recognizable format prefix
    const opaqueToken = "xyzzy12345678_no_prefix_at_all_random_chars";
    manager.registerLiteral("custom-service", opaqueToken);

    const output = `Authenticated with token: ${opaqueToken}`;
    const scrubbed = manager.scrubAll(output);

    expect(scrubbed).not.toContain(opaqueToken);
    expect(scrubbed).toContain("[VAULT:custom-service]");
  });

  it("should scrub credential embedded in JSON output", () => {
    const manager = new LiteralScrubManager();
    const credential = "opaque_api_key_that_has_no_pattern";
    manager.registerLiteral("acme", credential);

    const output = JSON.stringify({ token: credential, status: "ok" });
    const scrubbed = manager.scrubAll(output);

    expect(scrubbed).not.toContain(credential);
    expect(scrubbed).toContain("[VAULT:acme]");
  });

  it("should scrub credential in multi-line output", () => {
    const manager = new LiteralScrubManager();
    const credential = "long_random_credential_value_123456789";
    manager.registerLiteral("svc", credential);

    const output = [
      "Line 1: normal text",
      `Line 2: secret=${credential}`,
      "Line 3: more text",
    ].join("\n");
    const scrubbed = manager.scrubAll(output);

    expect(scrubbed).not.toContain(credential);
    expect(scrubbed).toContain("[VAULT:svc]");
    expect(scrubbed).toContain("Line 1: normal text");
    expect(scrubbed).toContain("Line 3: more text");
  });
});
