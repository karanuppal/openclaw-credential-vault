import { describe, it, expect } from "vitest";
import {
  guessCredentialFormat,
  isJwt,
  isJsonBlob,
  isShortPassword,
  isGenericApiKey,
  formatGuessDisplay,
  buildToolConfigFromGuess,
  GuessResult,
} from "../src/guesser.js";

// ─── Known Prefix Detection ─────────────────────────────────────────────────

describe("Known Prefix Detection", () => {
  it("detects Stripe live key (sk_live_)", () => {
    const result = guessCredentialFormat("sk_live_4eC39HqLyjWDarjtT1zdp7dc");
    expect(result.format).toBe("stripe-live");
    expect(result.displayName).toBe("Stripe live API key");
    expect(result.confidence).toBe("high");
    expect(result.knownToolName).toBe("stripe");
    expect(result.needsPrompt).toBe(false);
    expect(result.suggestedInject.length).toBeGreaterThan(0);
    expect(result.suggestedScrub.patterns.length).toBeGreaterThan(0);
  });

  it("detects Stripe test key (sk_test_)", () => {
    const result = guessCredentialFormat("sk_test_51HG9abc123def456ghi789jkl");
    expect(result.format).toBe("stripe-test");
    expect(result.displayName).toBe("Stripe test API key");
    expect(result.confidence).toBe("high");
    expect(result.knownToolName).toBe("stripe");
  });

  it("detects Stripe restricted key (rk_live_)", () => {
    const result = guessCredentialFormat("rk_live_abc123def456ghi789jkl012mno");
    expect(result.format).toBe("stripe-restricted");
    expect(result.knownToolName).toBe("stripe");
  });

  it("detects GitHub PAT (ghp_)", () => {
    const result = guessCredentialFormat("ghp_ABCDEFghijklmnopqrstuvwxyz0123456789");
    expect(result.format).toBe("github-pat");
    expect(result.displayName).toBe("GitHub personal access token");
    expect(result.confidence).toBe("high");
    expect(result.knownToolName).toBe("github");
    expect(result.needsPrompt).toBe(false);
  });

  it("detects GitHub fine-grained PAT (github_pat_)", () => {
    const token = "github_pat_" + "A".repeat(82);
    const result = guessCredentialFormat(token);
    expect(result.format).toBe("github-fine-grained");
    expect(result.displayName).toBe("GitHub fine-grained PAT");
    expect(result.knownToolName).toBe("github");
  });

  it("detects Gumroad API key (gum_)", () => {
    const result = guessCredentialFormat("gum_abc123def456ghij");
    expect(result.format).toBe("gumroad");
    expect(result.displayName).toBe("Gumroad API key");
    expect(result.knownToolName).toBe("gumroad");
  });

  it("detects Anthropic API key (sk-ant-)", () => {
    const key = "sk-ant-" + "a".repeat(80);
    const result = guessCredentialFormat(key);
    expect(result.format).toBe("anthropic");
    expect(result.displayName).toBe("Anthropic API key");
    expect(result.confidence).toBe("high");
    expect(result.knownToolName).toBe("anthropic");
  });

  it("detects OpenAI API key (sk- but not sk-ant-)", () => {
    const key = "sk-" + "a".repeat(48);
    const result = guessCredentialFormat(key);
    expect(result.format).toBe("openai");
    expect(result.displayName).toBe("OpenAI API key");
    expect(result.confidence).toBe("high");
    expect(result.knownToolName).toBe("openai");
  });

  it("does NOT classify sk-ant- as OpenAI", () => {
    const key = "sk-ant-" + "a".repeat(80);
    const result = guessCredentialFormat(key);
    expect(result.format).toBe("anthropic");
    expect(result.knownToolName).not.toBe("openai");
  });

  it("provides injection rules from known tool registry for known prefixes", () => {
    const result = guessCredentialFormat("ghp_ABCDEFghijklmnopqrstuvwxyz0123456789");
    // GitHub should have exec injection for gh/git commands
    const execRule = result.suggestedInject.find((r) => r.tool === "exec");
    expect(execRule).toBeDefined();
    expect(execRule!.commandMatch).toContain("gh ");
    expect(execRule!.env).toHaveProperty("GH_TOKEN");
  });
});

// ─── Heuristic Detection ────────────────────────────────────────────────────

describe("Heuristic Detection", () => {
  describe("isJwt", () => {
    it("returns true for valid JWT format", () => {
      // A real JWT structure: header.payload.signature
      const jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
      expect(isJwt(jwt)).toBe(true);
    });

    it("returns false for non-JWT strings", () => {
      expect(isJwt("not-a-jwt")).toBe(false);
      expect(isJwt("only.two.")).toBe(false);
      expect(isJwt("")).toBe(false);
    });

    it("returns false for strings with wrong number of parts", () => {
      expect(isJwt("one")).toBe(false);
      expect(isJwt("one.two")).toBe(false);
      expect(isJwt("one.two.three.four")).toBe(false);
    });
  });

  describe("isJsonBlob", () => {
    it("returns true for JSON object", () => {
      expect(isJsonBlob('{"access_token":"abc123","token_type":"bearer"}')).toBe(true);
    });

    it("returns true for JSON array", () => {
      expect(isJsonBlob('[{"name":"session","value":"xyz"}]')).toBe(true);
    });

    it("returns false for invalid JSON", () => {
      expect(isJsonBlob("{not json}")).toBe(false);
    });

    it("returns false for non-JSON strings", () => {
      expect(isJsonBlob("sk_live_abc123")).toBe(false);
      expect(isJsonBlob("just a string")).toBe(false);
    });
  });

  describe("isShortPassword", () => {
    it("returns true for short strings", () => {
      expect(isShortPassword("MyP@ssw0rd!")).toBe(true);
      expect(isShortPassword("hunter2")).toBe(true);
    });

    it("returns false for long strings", () => {
      expect(isShortPassword("a".repeat(32))).toBe(false);
    });

    it("returns false for strings with dots (could be JWT)", () => {
      expect(isShortPassword("a.b.c")).toBe(false);
    });

    it("returns false for JSON-looking strings", () => {
      expect(isShortPassword('{"a":1}')).toBe(false);
      expect(isShortPassword("[1,2,3]")).toBe(false);
    });
  });

  describe("isGenericApiKey", () => {
    it("returns true for long alphanumeric strings", () => {
      expect(isGenericApiKey("a".repeat(40))).toBe(true);
      expect(isGenericApiKey("ABCdef123_-" + "x".repeat(25))).toBe(true);
    });

    it("returns false for short strings", () => {
      expect(isGenericApiKey("short")).toBe(false);
    });

    it("returns false for strings with spaces", () => {
      expect(isGenericApiKey("has spaces " + "x".repeat(30))).toBe(false);
    });

    it("returns false for strings with special chars", () => {
      expect(isGenericApiKey("has@special#chars" + "x".repeat(30))).toBe(false);
    });
  });
});

// ─── guessCredentialFormat with Heuristics ───────────────────────────────────

describe("guessCredentialFormat — Heuristic paths", () => {
  it("detects JWT token", () => {
    const jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
    const result = guessCredentialFormat(jwt, "acme");
    expect(result.format).toBe("jwt");
    expect(result.confidence).toBe("medium");
    expect(result.needsPrompt).toBe(true);
    expect(result.promptHints.askApiUrl).toBe(true);
    // Should suggest Bearer header injection
    const webFetch = result.suggestedInject.find((r) => r.tool === "web_fetch");
    expect(webFetch).toBeDefined();
    expect(webFetch!.headers).toHaveProperty("Authorization");
    expect(webFetch!.headers!.Authorization).toContain("Bearer");
  });

  it("detects JWT and asks for service name when no toolName provided", () => {
    const jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
    const result = guessCredentialFormat(jwt);
    expect(result.promptHints.askServiceName).toBe(true);
  });

  it("detects short password", () => {
    const result = guessCredentialFormat("MyP@ssw0rd!");
    expect(result.format).toBe("password");
    expect(result.confidence).toBe("medium");
    expect(result.needsPrompt).toBe(true);
    expect(result.promptHints.askServiceName).toBe(true);
    expect(result.promptHints.askInjectionType).toBe(true);
  });

  it("detects JSON blob as cookies/OAuth", () => {
    const json = '{"access_token":"abc123","token_type":"bearer","expires_in":3600}';
    const result = guessCredentialFormat(json);
    expect(result.format).toBe("json-blob");
    expect(result.confidence).toBe("medium");
    expect(result.needsPrompt).toBe(true);
    expect(result.promptHints.askInjectionType).toBe(true);
  });

  it("detects JSON array (cookies) as json-blob", () => {
    const json = '[{"name":"session-id","value":"xyz","domain":".amazon.com"}]';
    const result = guessCredentialFormat(json);
    expect(result.format).toBe("json-blob");
  });

  it("detects long random string as generic API key", () => {
    const key = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEF";
    const result = guessCredentialFormat(key, "acme-service");
    expect(result.format).toBe("generic-api-key");
    expect(result.confidence).toBe("low");
    expect(result.needsPrompt).toBe(true);
    expect(result.promptHints.askApiUrl).toBe(true);
    // Should suggest exec-env injection with tool name in env var
    const execRule = result.suggestedInject.find((r) => r.tool === "exec");
    expect(execRule).toBeDefined();
    expect(execRule!.env).toHaveProperty("ACME_SERVICE_API_KEY");
  });

  it("falls back to unknown for unrecognizable formats", () => {
    const result = guessCredentialFormat("🔑 weird credential with spaces and emojis that's pretty long too");
    expect(result.format).toBe("unknown");
    expect(result.confidence).toBe("low");
    expect(result.needsPrompt).toBe(true);
  });
});

// ─── Prefix Ordering ────────────────────────────────────────────────────────

describe("Prefix Ordering", () => {
  it("sk-ant- is detected as Anthropic, not OpenAI", () => {
    const key = "sk-ant-api03-" + "x".repeat(80);
    const result = guessCredentialFormat(key);
    expect(result.format).toBe("anthropic");
    expect(result.knownToolName).toBe("anthropic");
  });

  it("sk- without ant is detected as OpenAI", () => {
    const key = "sk-proj-" + "A".repeat(44);
    const result = guessCredentialFormat(key);
    expect(result.format).toBe("openai");
    expect(result.knownToolName).toBe("openai");
  });
});

// ─── formatGuessDisplay ─────────────────────────────────────────────────────

describe("formatGuessDisplay", () => {
  it("formats high-confidence known tool with injection details", () => {
    const guess = guessCredentialFormat("sk_live_4eC39HqLyjWDarjtT1zdp7dc");
    const display = formatGuessDisplay(guess, "mystripe");
    expect(display).toContain("✓ Detected: Stripe live API key");
    expect(display).toContain("Suggested config:");
    expect(display).toContain("exec-env");
    expect(display).toContain("Scrub pattern:");
  });

  it("formats JWT detection", () => {
    const jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
    const guess = guessCredentialFormat(jwt, "acme");
    const display = formatGuessDisplay(guess, "acme");
    expect(display).toContain("JWT token");
    expect(display).toContain("http-header");
    expect(display).toContain("Authorization: Bearer");
  });

  it("formats password detection", () => {
    const guess = guessCredentialFormat("MyP@ssw0rd!");
    const display = formatGuessDisplay(guess, "myservice");
    expect(display).toContain("password");
  });

  it("formats JSON blob detection", () => {
    const guess = guessCredentialFormat('{"token":"abc"}');
    const display = formatGuessDisplay(guess, "myservice");
    expect(display).toContain("session cookies or an OAuth token");
  });

  it("formats generic API key", () => {
    const guess = guessCredentialFormat("a".repeat(40), "myservice");
    const display = formatGuessDisplay(guess, "myservice");
    expect(display).toContain("exec-env");
  });
});

// ─── buildToolConfigFromGuess ───────────────────────────────────────────────

describe("buildToolConfigFromGuess", () => {
  it("returns suggested config for known tools unchanged", () => {
    const guess = guessCredentialFormat("ghp_ABCDEFghijklmnopqrstuvwxyz0123456789");
    const config = buildToolConfigFromGuess("github", guess);
    expect(config.inject).toEqual(guess.suggestedInject);
    expect(config.scrub).toEqual(guess.suggestedScrub);
  });

  it("applies apiUrl override — adds web_fetch rule", () => {
    const guess = guessCredentialFormat("a".repeat(40), "acme");
    const config = buildToolConfigFromGuess("acme", guess, {
      apiUrl: "https://api.acme-crm.com/v1",
    });
    const webFetch = config.inject.find((r) => r.tool === "web_fetch");
    expect(webFetch).toBeDefined();
    expect(webFetch!.urlMatch).toContain("api.acme-crm.com");
  });

  it("applies cliTool override — adds/updates exec rule", () => {
    const guess = guessCredentialFormat("a".repeat(40), "acme");
    const config = buildToolConfigFromGuess("acme", guess, {
      cliTool: "acme-cli",
    });
    const execRule = config.inject.find((r) => r.tool === "exec");
    expect(execRule).toBeDefined();
    expect(execRule!.commandMatch).toContain("acme-cli");
  });

  it("applies both apiUrl and cliTool overrides", () => {
    const jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
    const guess = guessCredentialFormat(jwt, "acme");
    const config = buildToolConfigFromGuess("acme", guess, {
      apiUrl: "https://api.acme.io",
      cliTool: "acme",
    });
    const webFetch = config.inject.find((r) => r.tool === "web_fetch");
    expect(webFetch).toBeDefined();
    expect(webFetch!.urlMatch).toContain("api.acme.io");
    const execRule = config.inject.find((r) => r.tool === "exec");
    expect(execRule).toBeDefined();
    expect(execRule!.commandMatch).toContain("acme");
  });
});
