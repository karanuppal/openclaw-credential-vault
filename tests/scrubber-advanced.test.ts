/**
 * Tests for Phase 3E: Advanced scrubbing — global patterns, literal matching,
 * env-variable-name matching, hash-based tracking.
 */
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import {
  compileScrubRules,
  scrubText,
  scrubTextWithTracking,
  scrubEnvVars,
  addLiteralCredential,
  removeLiteralCredential,
  clearLiteralCredentials,
  hashCredential,
  getCredentialHashes,
  getLiteralCredentials,
  containsCredentials,
  GLOBAL_SCRUB_PATTERNS,
} from "../src/scrubber.js";
import { ToolConfig } from "../src/types.js";

const testTools: Record<string, ToolConfig> = {
  github: {
    name: "github",
    addedAt: "2026-01-01",
    lastRotated: "2026-01-01",
    inject: [],
    scrub: { patterns: ["ghp_[a-zA-Z0-9]{36}"] },
  },
};

beforeEach(() => {
  clearLiteralCredentials();
});

afterEach(() => {
  clearLiteralCredentials();
});

describe("Telegram bot token pattern (Phase 3E)", () => {
  it("should scrub Telegram bot tokens", () => {
    const rules = compileScrubRules(testTools);
    const input = "Bot token: 1234567890:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghi";
    const result = scrubText(input, rules);
    expect(result).toBe("Bot token: [VAULT:telegram-bot-token]");
  });

  it("should not match short numeric prefixes", () => {
    const rules = compileScrubRules(testTools);
    const input = "ID: 12345:somethingshort";
    const result = scrubText(input, rules);
    // Should NOT match — prefix is only 5 digits, not 10
    expect(result).toBe(input);
  });

  it("should match Telegram token in env output", () => {
    const rules = compileScrubRules(testTools);
    const input = "TELEGRAM_BOT_TOKEN=1234567890:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghi";
    const result = scrubText(input, rules);
    expect(result).not.toContain("1234567890:ABCDEFGHIJKLMNOPQRSTUVWXYZ");
  });
});

describe("Slack bot token pattern (Phase 3E)", () => {
  it("should scrub Slack bot tokens", () => {
    const rules = compileScrubRules(testTools);
    const input = "SLACK_TOKEN=xoxb-1234567890-abcdefghijklmn";
    const result = scrubText(input, rules);
    expect(result).toContain("[VAULT:slack-bot-token]");
    expect(result).not.toContain("xoxb-");
  });

  it("should match various Slack token formats", () => {
    const rules = compileScrubRules(testTools);
    const input = "xoxb-12345-67890-abcdef";
    const result = scrubText(input, rules);
    expect(result).toBe("[VAULT:slack-bot-token]");
  });
});

describe("Hash-based literal scrubbing (Phase 3E)", () => {
  it("should add credential to literal match set on addLiteralCredential", () => {
    addLiteralCredential("my-opaque-secret-12345", "myservice");
    const literals = getLiteralCredentials();
    expect(literals.has("my-opaque-secret-12345")).toBe(true);
    expect(literals.get("my-opaque-secret-12345")).toBe("myservice");
  });

  it("should track SHA-256 hash of credential", () => {
    addLiteralCredential("my-opaque-secret-12345", "myservice");
    const hashes = getCredentialHashes();
    const expectedHash = hashCredential("my-opaque-secret-12345");
    expect(hashes.has(expectedHash)).toBe(true);
    expect(hashes.get(expectedHash)).toBe("myservice");
  });

  it("should scrub literal credentials via indexOf matching", () => {
    const rules = compileScrubRules(testTools);
    addLiteralCredential("opaque-api-key-no-pattern", "custom");

    const text = "Output: opaque-api-key-no-pattern was used";
    const result = scrubText(text, rules);
    expect(result).toBe("Output: [VAULT:custom] was used");
  });

  it("should scrub multiple occurrences of the same literal", () => {
    const rules = compileScrubRules(testTools);
    addLiteralCredential("secret-value-abc123", "svc");

    const text = "First: secret-value-abc123, Second: secret-value-abc123";
    const result = scrubText(text, rules);
    expect(result).toBe("First: [VAULT:svc], Second: [VAULT:svc]");
  });

  it("should not add very short credentials (< 4 chars)", () => {
    addLiteralCredential("ab", "short");
    const literals = getLiteralCredentials();
    expect(literals.has("ab")).toBe(false);
  });

  it("should remove credential from literal set", () => {
    addLiteralCredential("removable-secret-123", "temp");
    expect(getLiteralCredentials().has("removable-secret-123")).toBe(true);

    removeLiteralCredential("removable-secret-123");
    expect(getLiteralCredentials().has("removable-secret-123")).toBe(false);
  });

  it("should also remove hash when removing credential", () => {
    addLiteralCredential("removable-secret-123", "temp");
    const hash = hashCredential("removable-secret-123");
    expect(getCredentialHashes().has(hash)).toBe(true);

    removeLiteralCredential("removable-secret-123");
    expect(getCredentialHashes().has(hash)).toBe(false);
  });

  it("should clear all literal credentials", () => {
    addLiteralCredential("cred-1", "svc1");
    addLiteralCredential("cred-2-longer", "svc2");
    // cred-1 is 6 chars, cred-2-longer is 14 chars — both above min length
    expect(getLiteralCredentials().size).toBe(2);

    clearLiteralCredentials();
    expect(getLiteralCredentials().size).toBe(0);
    expect(getCredentialHashes().size).toBe(0);
  });

  it("should detect literal credentials via containsCredentials", () => {
    const rules = compileScrubRules(testTools);
    addLiteralCredential("detectable-secret-99", "svc");

    expect(containsCredentials("has detectable-secret-99 here", rules)).toBe(true);
    expect(containsCredentials("no secrets here", rules)).toBe(false);
  });
});

describe("Env-variable-name matching (Phase 3E)", () => {
  it("should redact KEY= values", () => {
    const result = scrubEnvVars("SOME_API_KEY=abc123secretvalue");
    expect(result).toBe("SOME_API_KEY=[VAULT:env-redacted]");
  });

  it("should redact TOKEN= values", () => {
    const result = scrubEnvVars("AUTH_TOKEN=xyz789");
    expect(result).toBe("AUTH_TOKEN=[VAULT:env-redacted]");
  });

  it("should redact SECRET= values", () => {
    const result = scrubEnvVars("CLIENT_SECRET=mysecretvalue123");
    expect(result).toBe("CLIENT_SECRET=[VAULT:env-redacted]");
  });

  it("should redact PASSWORD= values", () => {
    const result = scrubEnvVars("DB_PASSWORD=hunter2");
    expect(result).toBe("DB_PASSWORD=[VAULT:env-redacted]");
  });

  it("should redact multiple env vars in one string", () => {
    const input = "API_KEY=abc123\nAUTH_TOKEN=xyz789\nNORMAL_VAR=hello";
    const result = scrubEnvVars(input);
    expect(result).toContain("API_KEY=[VAULT:env-redacted]");
    expect(result).toContain("AUTH_TOKEN=[VAULT:env-redacted]");
    expect(result).toContain("NORMAL_VAR=hello"); // No match
  });

  it("should not match variable names that don't contain KEY/TOKEN/SECRET/PASSWORD", () => {
    const result = scrubEnvVars("HOME=/home/user\nPATH=/usr/bin\nSHELL=/bin/bash");
    expect(result).toBe("HOME=/home/user\nPATH=/usr/bin\nSHELL=/bin/bash");
  });

  it("should match APIKEY (no underscore) pattern", () => {
    const result = scrubEnvVars("MYAPIKEY=value123");
    expect(result).toBe("MYAPIKEY=[VAULT:env-redacted]");
  });

  it("should integrate with main scrubText pipeline", () => {
    const rules = compileScrubRules(testTools);
    const text = "env output:\nMY_SECRET=very-secret-value\nNORMAL=fine";
    const result = scrubText(text, rules);
    expect(result).toContain("[VAULT:env-redacted]");
    expect(result).toContain("NORMAL=fine");
  });

  it("should not re-scrub already-scrubbed values in pipeline", () => {
    const rules = compileScrubRules(testTools);
    // This mimics the case where regex scrubbing already replaced the value
    // and env-var matching should not double-scrub
    const text = "GITHUB_TOKEN=ghp_abcdefghijklmnopqrstuvwxyz1234567890";
    const result = scrubText(text, rules);
    // The regex pattern should scrub the ghp_ token first
    // Then env-var matching should see [VAULT:github] and skip it
    expect(result).toBe("GITHUB_TOKEN=[VAULT:github]");
  });
});

describe("Global scrub patterns registration", () => {
  it("should include Telegram and Slack patterns", () => {
    const names = GLOBAL_SCRUB_PATTERNS.map(p => p.name);
    expect(names).toContain("telegram-bot-token");
    expect(names).toContain("slack-bot-token");
  });

  it("should compile global patterns into scrub rules", () => {
    const rules = compileScrubRules({});
    expect(rules.length).toBe(GLOBAL_SCRUB_PATTERNS.length);
    const names = rules.map(r => r.toolName);
    expect(names).toContain("telegram-bot-token");
    expect(names).toContain("slack-bot-token");
  });
});

describe("Combined scrubbing pipeline ordering", () => {
  it("should apply regex patterns before literal matching before env-var matching", () => {
    const rules = compileScrubRules(testTools);
    addLiteralCredential("custom-opaque-token-123", "acme");

    const text = `GITHUB_TOKEN=ghp_abcdefghijklmnopqrstuvwxyz1234567890
ACME_API_KEY=custom-opaque-token-123
MY_SECRET=some-unknown-value`;

    const result = scrubText(text, rules);
    // Regex: ghp_ pattern
    expect(result).toContain("GITHUB_TOKEN=[VAULT:github]");
    // Literal: custom-opaque-token-123
    expect(result).toContain("[VAULT:acme]");
    // Env-var: MY_SECRET
    expect(result).toContain("MY_SECRET=[VAULT:env-redacted]");
  });
});
