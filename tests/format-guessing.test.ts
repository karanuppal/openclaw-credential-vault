/**
 * Phase 5: Credential Format Guessing Tests
 *
 * Validates spec section "Credential Format Guessing" (Phase 3A):
 * - Known prefix detection for Stripe, GitHub, Gumroad, Anthropic, OpenAI
 * - Heuristic rules for JWT, short strings, JSON blobs, long random strings
 * - Correct tool name + display name returned for each detection
 *
 * Spec ref: "Heuristic rules (built into registry)" and "Credential Format Guessing"
 */

import { describe, it, expect } from "vitest";
import { detectCredentialType } from "../src/registry.js";

// --- Mock for heuristic detection (NOT BUILT yet) ---
// TODO: Replace with actual import once format guessing is fully implemented
// The existing detectCredentialType handles known prefixes; these tests also
// cover the heuristic detection that needs to be built.

/**
 * Extended format guesser that adds heuristic detection on top of
 * the existing prefix-based detectCredentialType.
 * TODO: Merge into registry.ts when implemented.
 */
interface FormatGuess {
  toolName?: string;
  displayName: string;
  suggestedType?: "exec-env" | "http-header" | "browser-password" | "browser-cookie";
  confidence: "high" | "medium" | "low";
}

function guessCredentialFormat(key: string): FormatGuess | null {
  // 1. Try known prefix detection first (already built)
  const known = detectCredentialType(key);
  if (known) {
    return {
      toolName: known.toolName,
      displayName: known.displayName,
      confidence: "high",
    };
  }

  // 2. JWT detection: three dot-separated base64 segments
  const jwtParts = key.split(".");
  if (jwtParts.length === 3) {
    const isBase64 = (s: string) => /^[A-Za-z0-9_-]+=*$/.test(s) && s.length > 10;
    if (jwtParts.every(isBase64)) {
      return {
        displayName: "JWT token (three dot-separated base64 segments)",
        suggestedType: "http-header",
        confidence: "high",
      };
    }
  }

  // 3. JSON blob: likely session cookies or OAuth token
  if (key.startsWith("{") || key.startsWith("[")) {
    try {
      JSON.parse(key);
      return {
        displayName: "JSON blob (likely session cookies or OAuth token)",
        confidence: "medium",
      };
    } catch {
      // Not valid JSON
    }
  }

  // 4. Short alphanumeric (< 32 chars): likely password
  if (key.length < 32 && /^[a-zA-Z0-9!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]+$/.test(key)) {
    return {
      displayName: "Short string (likely password)",
      suggestedType: "browser-password",
      confidence: "low",
    };
  }

  // 5. Long random string, no prefix: generic API key
  if (key.length >= 32 && /^[a-zA-Z0-9_-]+$/.test(key)) {
    return {
      displayName: "Long random string (likely API key)",
      suggestedType: "http-header",
      confidence: "low",
    };
  }

  return null;
}

describe("Format Guessing — known prefix detection", () => {
  describe("Stripe", () => {
    it("should detect sk_live_ as Stripe live key", () => {
      const result = detectCredentialType("sk_live_4eC39HqLyjWDarjtT1zdp7dc");
      expect(result).not.toBeNull();
      expect(result!.toolName).toBe("stripe");
      expect(result!.displayName).toContain("Stripe");
      expect(result!.displayName).toContain("live");
    });

    it("should detect sk_test_ as Stripe test key", () => {
      const result = detectCredentialType("sk_test_4eC39HqLyjWDarjtT1zdp7dc");
      expect(result).not.toBeNull();
      expect(result!.toolName).toBe("stripe");
      expect(result!.displayName).toContain("test");
    });

    it("should detect rk_live_ as Stripe restricted key", () => {
      const result = detectCredentialType("rk_live_4eC39HqLyjWDarjtT1zdp7dc");
      expect(result).not.toBeNull();
      expect(result!.toolName).toBe("stripe");
      expect(result!.displayName).toContain("restricted");
    });
  });

  describe("GitHub", () => {
    it("should detect ghp_ as GitHub personal access token", () => {
      const result = detectCredentialType("ghp_abcdefghijklmnopqrstuvwxyz1234567890");
      expect(result).not.toBeNull();
      expect(result!.toolName).toBe("github");
      expect(result!.displayName).toContain("GitHub");
    });

    it("should detect github_pat_ as fine-grained PAT", () => {
      const result = detectCredentialType(
        "github_pat_" + "a".repeat(82)
      );
      expect(result).not.toBeNull();
      expect(result!.toolName).toBe("github");
      expect(result!.displayName).toContain("fine-grained");
    });
  });

  describe("Gumroad", () => {
    it("should detect gum_ as Gumroad API key", () => {
      const result = detectCredentialType("gum_abc123def456789x");
      expect(result).not.toBeNull();
      expect(result!.toolName).toBe("gumroad");
      expect(result!.displayName).toContain("Gumroad");
    });
  });

  describe("Anthropic", () => {
    it("should detect sk-ant- as Anthropic API key", () => {
      const result = detectCredentialType("sk-ant-" + "a".repeat(80));
      expect(result).not.toBeNull();
      expect(result!.toolName).toBe("anthropic");
      expect(result!.displayName).toContain("Anthropic");
    });
  });

  describe("OpenAI", () => {
    it("should detect sk- (not sk-ant-) as OpenAI API key", () => {
      const result = detectCredentialType("sk-" + "a".repeat(48));
      expect(result).not.toBeNull();
      expect(result!.toolName).toBe("openai");
      expect(result!.displayName).toContain("OpenAI");
    });

    it("should not confuse sk-ant- with OpenAI", () => {
      const result = detectCredentialType("sk-ant-" + "a".repeat(80));
      expect(result).not.toBeNull();
      expect(result!.toolName).toBe("anthropic"); // NOT openai
    });
  });
});

describe("Format Guessing — heuristic detection", () => {
  describe("JWT tokens", () => {
    it("should detect JWT format (three dot-separated base64 segments)", () => {
      const jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
      const result = guessCredentialFormat(jwt);
      expect(result).not.toBeNull();
      expect(result!.displayName).toContain("JWT");
      expect(result!.suggestedType).toBe("http-header");
      expect(result!.confidence).toBe("high");
    });

    it("should not detect non-JWT dot-separated strings", () => {
      const notJwt = "foo.bar.baz";
      const result = guessCredentialFormat(notJwt);
      // Should not be detected as JWT (parts are too short)
      if (result) {
        expect(result.displayName).not.toContain("JWT");
      }
    });
  });

  describe("Short strings (passwords)", () => {
    it("should detect short alphanumeric as likely password", () => {
      const result = guessCredentialFormat("MyP@ssw0rd!");
      expect(result).not.toBeNull();
      expect(result!.displayName).toContain("Short string");
      expect(result!.confidence).toBe("low");
    });
  });

  describe("JSON blobs", () => {
    it("should detect JSON object as likely session cookies/OAuth", () => {
      const json = '{"access_token":"abc123","token_type":"bearer"}';
      const result = guessCredentialFormat(json);
      expect(result).not.toBeNull();
      expect(result!.displayName).toContain("JSON");
      expect(result!.confidence).toBe("medium");
    });

    it("should detect JSON array as likely cookies", () => {
      const json = '[{"name":"sid","value":"abc123"}]';
      const result = guessCredentialFormat(json);
      expect(result).not.toBeNull();
      expect(result!.displayName).toContain("JSON");
    });
  });

  describe("Long random strings (API keys)", () => {
    it("should detect long random string as likely API key", () => {
      const longKey = "a".repeat(64);
      const result = guessCredentialFormat(longKey);
      expect(result).not.toBeNull();
      expect(result!.displayName).toContain("API key");
      expect(result!.suggestedType).toBe("http-header");
      expect(result!.confidence).toBe("low");
    });
  });

  describe("Known prefixes take priority over heuristics", () => {
    it("should detect Stripe before generic long string", () => {
      const result = guessCredentialFormat("sk_live_4eC39HqLyjWDarjtT1zdp7dc");
      expect(result).not.toBeNull();
      expect(result!.toolName).toBe("stripe");
      expect(result!.confidence).toBe("high");
    });

    it("should detect GitHub before generic long string", () => {
      const result = guessCredentialFormat("ghp_abcdefghijklmnopqrstuvwxyz1234567890");
      expect(result).not.toBeNull();
      expect(result!.toolName).toBe("github");
      expect(result!.confidence).toBe("high");
    });
  });
});
