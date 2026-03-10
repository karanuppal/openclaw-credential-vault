import { describe, it, expect } from "vitest";
import {
  compileScrubRules,
  scrubText,
  scrubObject,
  containsCredentials,
  scrubLiteralCredential,
  GLOBAL_SCRUB_PATTERNS,
} from "../src/scrubber.js";
import { ToolConfig } from "../src/types.js";

const testTools: Record<string, ToolConfig> = {
  stripe: {
    name: "stripe",
    addedAt: "2026-01-01",
    lastRotated: "2026-01-01",
    inject: [],
    scrub: {
      patterns: [
        "sk_live_[a-zA-Z0-9]{24,}",
        "sk_test_[a-zA-Z0-9]{24,}",
      ],
    },
  },
  github: {
    name: "github",
    addedAt: "2026-01-01",
    lastRotated: "2026-01-01",
    inject: [],
    scrub: {
      patterns: ["ghp_[a-zA-Z0-9]{36}"],
    },
  },
  gumroad: {
    name: "gumroad",
    addedAt: "2026-01-01",
    lastRotated: "2026-01-01",
    inject: [],
    scrub: {
      patterns: ["gum_[a-zA-Z0-9]{16,}"],
    },
  },
};

describe("compileScrubRules", () => {
  it("should compile rules for all tools", () => {
    const rules = compileScrubRules(testTools);
    // 2 stripe + 1 github + 1 gumroad + global patterns (telegram, slack) = 6 rules
    expect(rules.length).toBe(4 + GLOBAL_SCRUB_PATTERNS.length);
  });

  it("should set correct replacement text", () => {
    const rules = compileScrubRules(testTools);
    const stripeRule = rules.find((r) => r.toolName === "stripe");
    expect(stripeRule?.replacement).toBe("[VAULT:stripe]");
  });
});

describe("scrubText", () => {
  const rules = compileScrubRules(testTools);

  it("should scrub Stripe live keys", () => {
    const input = "Error: Invalid key sk_live_abcdefghijklmnopqrstuvwx";
    const result = scrubText(input, rules);
    expect(result).toBe("Error: Invalid key [VAULT:stripe]");
  });

  it("should scrub Stripe test keys", () => {
    const input = "Using key sk_test_abcdefghijklmnopqrstuvwx for testing";
    const result = scrubText(input, rules);
    expect(result).toBe("Using key [VAULT:stripe] for testing");
  });

  it("should scrub GitHub PATs", () => {
    const input = "Token: ghp_abcdefghijklmnopqrstuvwxyz1234567890";
    const result = scrubText(input, rules);
    expect(result).toBe("Token: [VAULT:github]");
  });

  it("should scrub Gumroad keys", () => {
    const input = "GUMROAD_ACCESS_TOKEN=gum_abcdefghijklmnop";
    const result = scrubText(input, rules);
    expect(result).toBe("GUMROAD_ACCESS_TOKEN=[VAULT:gumroad]");
  });

  it("should scrub multiple credentials in one string", () => {
    const input =
      "Keys: sk_live_abcdefghijklmnopqrstuvwx and ghp_abcdefghijklmnopqrstuvwxyz1234567890";
    const result = scrubText(input, rules);
    expect(result).toBe("Keys: [VAULT:stripe] and [VAULT:github]");
  });

  it("should not modify strings without credentials", () => {
    const input = "This is a normal output with no secrets";
    const result = scrubText(input, rules);
    expect(result).toBe(input);
  });

  it("should handle credentials in JSON output", () => {
    const input = '{"api_key": "sk_live_abcdefghijklmnopqrstuvwx", "status": "ok"}';
    const result = scrubText(input, rules);
    expect(result).toBe('{"api_key": "[VAULT:stripe]", "status": "ok"}');
  });
});

describe("scrubObject", () => {
  const rules = compileScrubRules(testTools);

  it("should scrub string values in objects", () => {
    const input = {
      output: "Key is sk_live_abcdefghijklmnopqrstuvwx",
      status: "ok",
    };
    const result = scrubObject(input, rules) as Record<string, string>;
    expect(result.output).toBe("Key is [VAULT:stripe]");
    expect(result.status).toBe("ok");
  });

  it("should scrub nested objects", () => {
    const input = {
      data: {
        nested: {
          key: "ghp_abcdefghijklmnopqrstuvwxyz1234567890",
        },
      },
    };
    const result = scrubObject(input, rules) as any;
    expect(result.data.nested.key).toBe("[VAULT:github]");
  });

  it("should scrub arrays", () => {
    const input = [
      "sk_live_abcdefghijklmnopqrstuvwx",
      "normal text",
      "ghp_abcdefghijklmnopqrstuvwxyz1234567890",
    ];
    const result = scrubObject(input, rules) as string[];
    expect(result[0]).toBe("[VAULT:stripe]");
    expect(result[1]).toBe("normal text");
    expect(result[2]).toBe("[VAULT:github]");
  });

  it("should handle null and non-object values", () => {
    expect(scrubObject(null, rules)).toBeNull();
    expect(scrubObject(42, rules)).toBe(42);
    expect(scrubObject(true, rules)).toBe(true);
  });
});

describe("containsCredentials", () => {
  const rules = compileScrubRules(testTools);

  it("should detect credentials", () => {
    expect(
      containsCredentials("Has sk_live_abcdefghijklmnopqrstuvwx", rules)
    ).toBe(true);
  });

  it("should return false for clean text", () => {
    expect(containsCredentials("No credentials here", rules)).toBe(false);
  });
});

describe("scrubLiteralCredential", () => {
  it("should scrub exact credential matches", () => {
    const result = scrubLiteralCredential(
      "Output: my-custom-key-12345",
      "my-custom-key-12345",
      "acme"
    );
    expect(result).toBe("Output: [VAULT:acme]");
  });

  it("should handle special regex characters in credential", () => {
    const result = scrubLiteralCredential(
      "Key: abc+def.ghi",
      "abc+def.ghi",
      "test"
    );
    expect(result).toBe("Key: [VAULT:test]");
  });

  it("should not scrub very short credentials", () => {
    const result = scrubLiteralCredential("Key: abc", "abc", "test");
    expect(result).toBe("Key: abc"); // Too short (< 4 chars)
  });
});
