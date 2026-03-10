/**
 * Phase 5: False Positive Corpus Tests
 *
 * Validates spec section "Pitfall #13: Scrubber false positives":
 * - UUIDs must NOT be scrubbed
 * - Git commit hashes must NOT be scrubbed
 * - Base64 data URIs must NOT be scrubbed
 * - CSS hex colors must NOT be scrubbed
 * - Common identifiers that look like credentials but aren't
 *
 * Spec ref: "Conservative patterns + false positive corpus testing"
 */

import { describe, it, expect } from "vitest";
import {
  compileScrubRules,
  scrubText,
  CompiledScrubRule,
} from "../src/scrubber.js";
import { ToolConfig } from "../src/types.js";

// Use the full set of known tool scrub patterns
const allTools: Record<string, ToolConfig> = {
  stripe: {
    name: "stripe",
    addedAt: "2026-01-01",
    lastRotated: "2026-01-01",
    inject: [],
    scrub: {
      patterns: [
        "sk_live_[a-zA-Z0-9]{24,}",
        "sk_test_[a-zA-Z0-9]{24,}",
        "rk_live_[a-zA-Z0-9]{24,}",
      ],
    },
  },
  github: {
    name: "github",
    addedAt: "2026-01-01",
    lastRotated: "2026-01-01",
    inject: [],
    scrub: {
      patterns: [
        "ghp_[a-zA-Z0-9]{36}",
        "github_pat_[a-zA-Z0-9_]{82}",
      ],
    },
  },
  gumroad: {
    name: "gumroad",
    addedAt: "2026-01-01",
    lastRotated: "2026-01-01",
    inject: [],
    scrub: { patterns: ["gum_[a-zA-Z0-9]{16,}"] },
  },
  openai: {
    name: "openai",
    addedAt: "2026-01-01",
    lastRotated: "2026-01-01",
    inject: [],
    scrub: { patterns: ["sk-[a-zA-Z0-9]{48}"] },
  },
  anthropic: {
    name: "anthropic",
    addedAt: "2026-01-01",
    lastRotated: "2026-01-01",
    inject: [],
    scrub: { patterns: ["sk-ant-[a-zA-Z0-9-]{80,}"] },
  },
};

let rules: CompiledScrubRule[];

// Compile rules once
rules = compileScrubRules(allTools);

describe("False Positives — UUIDs must NOT be scrubbed", () => {
  const uuids = [
    "550e8400-e29b-41d4-a716-446655440000",
    "6ba7b810-9dad-11d1-80b4-00c04fd430c8",
    "f47ac10b-58cc-4372-a567-0e02b2c3d479",
    "123e4567-e89b-12d3-a456-426614174000",
  ];

  for (const uuid of uuids) {
    it(`should not scrub UUID: ${uuid}`, () => {
      const input = `Resource ID: ${uuid}`;
      const result = scrubText(input, rules);
      expect(result).toBe(input);
    });
  }

  it("should not scrub UUID in JSON context", () => {
    const input = '{"id": "550e8400-e29b-41d4-a716-446655440000", "status": "active"}';
    const result = scrubText(input, rules);
    expect(result).toBe(input);
  });
});

describe("False Positives — git commit hashes must NOT be scrubbed", () => {
  const gitHashes = [
    "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0", // full SHA-1 (40 chars)
    "abc1234", // short hash (7 chars)
    "deadbeef", // common short hash
    "cafebabe12345678", // 16-char abbreviated
  ];

  for (const hash of gitHashes) {
    it(`should not scrub git hash: ${hash}`, () => {
      const input = `commit ${hash}`;
      const result = scrubText(input, rules);
      expect(result).toBe(input);
    });
  }

  it("should not scrub hashes in git log output", () => {
    const input = `commit a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0
Author: Dev <dev@example.com>
Date: Mon Mar 10 2026

    Fix bug #42`;
    const result = scrubText(input, rules);
    expect(result).toBe(input);
  });
});

describe("False Positives — base64 data URIs must NOT be scrubbed", () => {
  const dataUris = [
    "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk",
    "data:text/plain;base64,SGVsbG8gV29ybGQ=",
    "data:application/json;base64,eyJrZXkiOiJ2YWx1ZSJ9",
  ];

  for (const uri of dataUris) {
    it(`should not scrub data URI: ${uri.slice(0, 40)}...`, () => {
      const input = `Image: ${uri}`;
      const result = scrubText(input, rules);
      expect(result).toBe(input);
    });
  }
});

describe("False Positives — CSS hex colors must NOT be scrubbed", () => {
  const cssColors = [
    "#ff0000",
    "#00ff00",
    "#0000ff",
    "#ffffff",
    "#000000",
    "#f0f0f0",
    "#abc123",
    "#FF5733",
    "#333",
    "#fff",
  ];

  for (const color of cssColors) {
    it(`should not scrub CSS color: ${color}`, () => {
      const input = `background-color: ${color};`;
      const result = scrubText(input, rules);
      expect(result).toBe(input);
    });
  }

  it("should not scrub hex colors in style attributes", () => {
    const input = 'style="color: #ff5733; background: #333333; border: 1px solid #abc123"';
    const result = scrubText(input, rules);
    expect(result).toBe(input);
  });
});

describe("False Positives — common non-credential strings", () => {
  const falsePositives = [
    // npm package versions
    "package@1.2.3",
    // Docker image hashes
    "sha256:abc1234567890def",
    // URL query parameters
    "?token=page_navigation_token",
    // Environment variable names (without values)
    "STRIPE_API_KEY",
    "GH_TOKEN",
    // File paths
    "/home/user/.ssh/known_hosts",
    // Short identifiers
    "sk_prod", // only 7 chars, too short for sk- pattern
    // Version strings
    "v4.5.5",
    // Session IDs (non-credential format)
    "sess_abc123",
    // Kubernetes resource names
    "pod-abc123-def456",
  ];

  for (const fp of falsePositives) {
    it(`should not scrub: "${fp}"`, () => {
      const input = `Value: ${fp}`;
      const result = scrubText(input, rules);
      expect(result).toBe(input);
    });
  }
});

describe("False Positives — things that SHOULD still be caught", () => {
  it("should still catch real Stripe key", () => {
    const input = "sk_live_4eC39HqLyjWDarjtT1zdp7dc";
    const result = scrubText(input, rules);
    expect(result).toContain("[VAULT:stripe]");
  });

  it("should still catch real GitHub PAT", () => {
    const input = "ghp_abcdefghijklmnopqrstuvwxyz1234567890";
    const result = scrubText(input, rules);
    expect(result).toContain("[VAULT:github]");
  });

  it("should still catch real Gumroad key", () => {
    const input = "gum_abcdefghijklmnop";
    const result = scrubText(input, rules);
    expect(result).toContain("[VAULT:gumroad]");
  });
});
