import { describe, it, expect } from "vitest";
import {
  globToRegex,
  matchesCommand,
  matchesUrl,
  findMatchingRules,
  detectCredentialType,
  getKnownTool,
  generateScrubPattern,
  KNOWN_TOOLS,
} from "../src/registry.js";
import { InjectionRule } from "../src/types.js";

describe("globToRegex", () => {
  it("should convert simple glob with wildcard", () => {
    const re = globToRegex("stripe*");
    expect(re.test("stripe")).toBe(true);
    expect(re.test("stripe products list")).toBe(true);
    expect(re.test("notstripe")).toBe(false);
  });

  it("should handle alternation with |", () => {
    const re = globToRegex("gh *|git *");
    expect(re.test("gh pr list")).toBe(true);
    expect(re.test("git push")).toBe(true);
    expect(re.test("curl something")).toBe(false);
  });

  it("should handle dots in URLs", () => {
    const re = globToRegex("*.stripe.com/*");
    expect(re.test("api.stripe.com/v1/charges")).toBe(true);
    expect(re.test("dashboard.stripe.com/test")).toBe(true);
    expect(re.test("notstripe.com/path")).toBe(false);
  });
});

describe("matchesCommand", () => {
  it("should match exact command", () => {
    expect(matchesCommand("stripe products list", "stripe*")).toBe(true);
  });

  it("should match curl with API domain", () => {
    expect(
      matchesCommand(
        "curl https://api.stripe.com/v1/charges",
        "curl*api.stripe.com*"
      )
    ).toBe(true);
  });

  it("should match alternation patterns", () => {
    expect(matchesCommand("gh pr list", "gh *|git *|curl*api.github.com*")).toBe(true);
    expect(matchesCommand("git push origin main", "gh *|git *|curl*api.github.com*")).toBe(true);
  });

  it("should not match unrelated commands", () => {
    expect(matchesCommand("ls -la", "stripe*")).toBe(false);
    expect(matchesCommand("npm install", "gh *|git *")).toBe(false);
  });
});

describe("matchesUrl", () => {
  it("should match URLs with wildcard subdomains", () => {
    expect(matchesUrl("https://api.gumroad.com/v2/products", "*.gumroad.com/*")).toBe(true);
  });

  it("should not match unrelated URLs", () => {
    expect(matchesUrl("https://example.com/api", "*.stripe.com/*")).toBe(false);
  });
});

describe("findMatchingRules", () => {
  const rules: InjectionRule[] = [
    {
      tool: "exec",
      commandMatch: "stripe*|curl*api.stripe.com*",
      env: { STRIPE_API_KEY: "$vault:stripe" },
    },
    {
      tool: "web_fetch",
      urlMatch: "*.stripe.com/*",
      headers: { Authorization: "Bearer $vault:stripe" },
    },
    {
      tool: "exec",
      commandMatch: "gh *|git *",
      env: { GH_TOKEN: "$vault:github" },
    },
  ];

  it("should find matching exec rules", () => {
    const matches = findMatchingRules("exec", { command: "stripe charges list" }, rules);
    expect(matches).toHaveLength(1);
    expect(matches[0].env).toEqual({ STRIPE_API_KEY: "$vault:stripe" });
  });

  it("should find matching web_fetch rules", () => {
    const matches = findMatchingRules(
      "web_fetch",
      { url: "https://api.stripe.com/v1/charges" },
      rules
    );
    expect(matches).toHaveLength(1);
    expect(matches[0].headers).toEqual({ Authorization: "Bearer $vault:stripe" });
  });

  it("should return empty for non-matching calls", () => {
    const matches = findMatchingRules("exec", { command: "ls -la" }, rules);
    expect(matches).toHaveLength(0);
  });

  it("should match github rules", () => {
    const matches = findMatchingRules("exec", { command: "gh pr list" }, rules);
    expect(matches).toHaveLength(1);
    expect(matches[0].env).toEqual({ GH_TOKEN: "$vault:github" });
  });
});

describe("detectCredentialType", () => {
  it("should detect Gumroad keys", () => {
    const result = detectCredentialType("gum_abc123def456789x");
    expect(result?.toolName).toBe("gumroad");
  });

  it("should detect Stripe live keys", () => {
    const result = detectCredentialType("sk_live_abcdefghijklmnopqrstuvwx");
    expect(result?.toolName).toBe("stripe");
  });

  it("should detect Stripe test keys", () => {
    const result = detectCredentialType("sk_test_abcdefghijklmnopqrstuvwx");
    expect(result?.toolName).toBe("stripe");
  });

  it("should detect GitHub PATs", () => {
    const result = detectCredentialType("ghp_abcdefghijklmnopqrstuvwxyz1234567890");
    expect(result?.toolName).toBe("github");
  });

  it("should return null for unknown formats", () => {
    expect(detectCredentialType("random_key_12345")).toBeNull();
  });
});

describe("getKnownTool", () => {
  it("should return definition for known tools", () => {
    const tool = getKnownTool("stripe");
    expect(tool).not.toBeNull();
    expect(tool!.inject.length).toBeGreaterThan(0);
    expect(tool!.scrub.patterns.length).toBeGreaterThan(0);
  });

  it("should return null for unknown tools", () => {
    expect(getKnownTool("unknown-service")).toBeNull();
  });
});

describe("generateScrubPattern", () => {
  it("should generate pattern from prefixed key", () => {
    const pattern = generateScrubPattern("gum_abc123def456");
    const regex = new RegExp(pattern);
    expect(regex.test("gum_abc123def456")).toBe(true);
    expect(regex.test("gum_abcdefghijkl")).toBe(true); // Same length, different chars
  });

  it("should generate a matching pattern for keys with dots", () => {
    // "key" is the alpha prefix, rest ".with.dots_abc123" becomes a char class range
    const pattern = generateScrubPattern("key.with.dots_abc123");
    const regex = new RegExp(pattern);
    // Should match other keys with the same "key" prefix and sufficient length
    expect(regex.test("key_abcdefghijklmno")).toBe(true);
  });
});
