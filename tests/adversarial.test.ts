/**
 * 🛡️ Adversarial Security Tests for OpenClaw Credential Vault
 *
 * These tests attempt to break the security model through creative attack vectors.
 * Tests PASS if the security model holds (credential is scrubbed/blocked).
 * Tests FAIL if an attack vector succeeds (credential leaks).
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import {
  compileScrubRules,
  scrubText,
  scrubObject,
  scrubTextWithTracking,
  addLiteralCredential,
  clearLiteralCredentials,
  scrubLiteralCredential,
  scrubEnvVars,
  containsCredentials,
  CompiledScrubRule,
} from "../src/scrubber.js";
import {
  matchesDomainPin,
  matchesAnyDomainPin,
  extractHostname,
  resolveBrowserPassword,
  isVaultPlaceholder,
} from "../src/browser.js";
import { ToolConfig } from "../src/types.js";

// ---- Test Fixtures ----

const STRIPE_KEY = "sk_live_abcdef1234567890abcdef12";
const GITHUB_TOKEN = "ghp_abcdefghijklmnopqrstuvwxyz1234567890";
const CUSTOM_SECRET = "my_super_secret_credential_value_2026";
const SHORT_SECRET = "s3cr3t";
const WORD_SECRET = "password"; // common English word

const testTools: Record<string, ToolConfig> = {
  stripe: {
    name: "stripe",
    addedAt: "2026-01-01",
    lastRotated: "2026-01-01",
    inject: [],
    scrub: {
      patterns: ["sk_live_[a-zA-Z0-9]{24,}", "sk_test_[a-zA-Z0-9]{24,}"],
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
  "custom-api": {
    name: "custom-api",
    addedAt: "2026-01-01",
    lastRotated: "2026-01-01",
    inject: [],
    scrub: {
      patterns: [],
    },
  },
};

let rules: CompiledScrubRule[];

beforeEach(() => {
  clearLiteralCredentials();
  rules = compileScrubRules(testTools);
  // Register literal credentials for hash-based matching
  addLiteralCredential(STRIPE_KEY, "stripe");
  addLiteralCredential(GITHUB_TOKEN, "github");
  addLiteralCredential(CUSTOM_SECRET, "custom-api");
});

afterEach(() => {
  clearLiteralCredentials();
});

// =====================================================================
// ATTACK VECTOR 1: Prompt Injection via Domain Pinning
// =====================================================================
describe("Attack Vector 1: Domain Pinning Bypass", () => {
  /**
   * Attack: Subdomain spoof — amazon.com.evil.com
   * Expected defense: matchesDomainPin should NOT match because the actual
   * domain is evil.com, not amazon.com
   */
  it("should reject subdomain spoof: amazon.com.evil.com", () => {
    const spoofedHostname = "amazon.com.evil.com";
    const pins = [".amazon.com"];
    // The spoof hostname ends with ".amazon.com" — this is the critical test
    // "amazon.com.evil.com".endsWith(".amazon.com") → FALSE ✓
    expect(matchesDomainPin(spoofedHostname, ".amazon.com")).toBe(false);
  });

  /**
   * Attack: More subtle subdomain spoof with proper structure
   * www.amazon.com.evil.com should not match .amazon.com
   */
  it("should reject www.amazon.com.evil.com", () => {
    expect(matchesDomainPin("www.amazon.com.evil.com", ".amazon.com")).toBe(false);
  });

  /**
   * Attack: IDN homograph — Cyrillic 'а' looks like Latin 'a'
   * аmazon.com (first char is Cyrillic а, U+0430) vs amazon.com
   * Expected defense: string comparison should fail since bytes differ
   */
  it("should reject IDN homograph: Cyrillic а vs Latin a", () => {
    // Cyrillic а (U+0430) followed by "mazon.com"
    const homograph = "\u0430mazon.com";
    const pins = [".amazon.com"];
    expect(matchesDomainPin(homograph, ".amazon.com")).toBe(false);
    expect(matchesAnyDomainPin(homograph, pins)).toBe(false);
  });

  /**
   * Attack: Use Punycode-encoded IDN domain in URL
   * Browser URL might show xn-- encoded version
   */
  it("should reject punycode IDN domain", () => {
    const punycodeHostname = "xn--mazon-dsa.com"; // hypothetical punycode for fake amazon
    expect(matchesDomainPin(punycodeHostname, ".amazon.com")).toBe(false);
  });

  /**
   * Attack: Redirect chain — page at evil.com requests $vault:amazon-login
   * The URL passed to resolveBrowserPassword should be the CURRENT page URL
   * not the original navigation target
   */
  it("should block credential on wrong domain after redirect", () => {
    const result = resolveBrowserPassword(
      "$vault:amazon-login",
      "https://evil.com/phishing",
      "my_amazon_password",
      [".amazon.com"]
    );
    expect(result.allowed).toBe(false);
    expect(result.error).toContain("Domain mismatch");
  });

  /**
   * Attack: Use data: URL to bypass domain check
   */
  it("should block credential for data: URLs", () => {
    const result = resolveBrowserPassword(
      "$vault:amazon-login",
      "data:text/html,<script>steal()</script>",
      "my_amazon_password",
      [".amazon.com"]
    );
    expect(result.allowed).toBe(false);
  });

  /**
   * Attack: Use javascript: URL to bypass domain check
   */
  it("should block credential for javascript: URLs", () => {
    const result = resolveBrowserPassword(
      "$vault:amazon-login",
      "javascript:void(0)",
      "my_amazon_password",
      [".amazon.com"]
    );
    expect(result.allowed).toBe(false);
  });

  /**
   * Attack: Empty URL — should not resolve
   */
  it("should block credential for empty URL", () => {
    const result = resolveBrowserPassword(
      "$vault:amazon-login",
      "",
      "my_amazon_password",
      [".amazon.com"]
    );
    expect(result.allowed).toBe(false);
  });

  /**
   * Attack: URL with user info containing domain name
   * https://amazon.com@evil.com/path
   */
  it("should block credential when domain is in user info", () => {
    const result = resolveBrowserPassword(
      "$vault:amazon-login",
      "https://amazon.com@evil.com/path",
      "my_amazon_password",
      [".amazon.com"]
    );
    // URL parser should extract "evil.com" as hostname, not "amazon.com"
    expect(result.allowed).toBe(false);
  });

  /**
   * Positive test: Valid Amazon domain should work
   */
  it("should allow credential on valid pinned domain", () => {
    const result = resolveBrowserPassword(
      "$vault:amazon-login",
      "https://www.amazon.com/ap/signin",
      "my_amazon_password",
      [".amazon.com"]
    );
    expect(result.allowed).toBe(true);
    expect(result.resolvedValue).toBe("my_amazon_password");
  });
});

// =====================================================================
// ATTACK VECTOR 2: Encoded Credential Leakage
// =====================================================================
describe("Attack Vector 2: Encoded Credential Leakage", () => {
  /**
   * Attack: Base64-encode the credential to bypass literal matching
   * echo "sk_live_abcdef1234567890abcdef12" | base64
   * → "c2tfbGl2ZV9hYmNkZWYxMjM0NTY3ODkwYWJjZGVmMTI="
   *
   * KNOWN GAP: The scrubber does NOT decode base64 output to check for credentials.
   * This is documented as a limitation — scrubbing base64 would require decoding
   * all base64 strings, which is expensive and has false positives.
   */
  it("GAP: base64-encoded credential is NOT caught by literal scrubber", () => {
    const base64Encoded = Buffer.from(STRIPE_KEY).toString("base64");
    const output = `Command output:\n${base64Encoded}\n`;
    const scrubbed = scrubText(output, rules);
    // This test documents the gap — the base64 encoded form is NOT scrubbed
    // If the scrubber ever adds base64 decoding, this test should be updated
    expect(scrubbed).toContain(base64Encoded);
  });

  /**
   * Attack: URL-encode the credential
   * sk_live_abc → sk_live_abc%31%32%33...
   *
   * KNOWN GAP: URL-encoded credentials bypass literal matching
   */
  it("GAP: URL-encoded credential is NOT caught by literal scrubber", () => {
    // Partially URL-encode the credential
    const urlEncoded = STRIPE_KEY.replace(/[0-9]/g, (c) => `%3${c}`);
    const output = `Encoded: ${urlEncoded}`;
    const scrubbed = scrubText(output, rules);
    // URL encoding breaks the literal match AND the regex pattern
    expect(scrubbed).toContain(urlEncoded);
  });

  /**
   * Attack: Hex-encode the credential
   */
  it("GAP: hex-encoded credential is NOT caught", () => {
    const hexEncoded = Buffer.from(STRIPE_KEY).toString("hex");
    const output = `Hex: ${hexEncoded}`;
    const scrubbed = scrubText(output, rules);
    expect(scrubbed).toContain(hexEncoded);
  });

  /**
   * Attack: Reverse the credential string
   */
  it("GAP: reversed credential string is NOT caught", () => {
    const reversed = STRIPE_KEY.split("").reverse().join("");
    const output = `Reversed: ${reversed}`;
    const scrubbed = scrubText(output, rules);
    // Reversed form won't match the regex or literal
    expect(scrubbed).toContain(reversed);
  });

  /**
   * Attack: ROT13 encoding
   */
  it("GAP: ROT13-encoded credential is NOT caught", () => {
    const rot13 = STRIPE_KEY.replace(/[a-zA-Z]/g, (c) => {
      const base = c <= "Z" ? 65 : 97;
      return String.fromCharCode(((c.charCodeAt(0) - base + 13) % 26) + base);
    });
    const output = `ROT13: ${rot13}`;
    const scrubbed = scrubText(output, rules);
    expect(scrubbed).toContain(rot13);
  });

  /**
   * Defense: The REGEX pattern should still catch the raw credential even
   * in unusual contexts
   */
  it("should catch raw credential in JSON output", () => {
    const output = `{"apiKey": "${STRIPE_KEY}"}`;
    const scrubbed = scrubText(output, rules);
    expect(scrubbed).not.toContain(STRIPE_KEY);
    expect(scrubbed).toContain("[VAULT:stripe]");
  });

  /**
   * Defense: Credential in multi-line output should be caught
   */
  it("should catch credential in multi-line output", () => {
    const output = `Line 1: some text\nLine 2: ${STRIPE_KEY}\nLine 3: more text`;
    const scrubbed = scrubText(output, rules);
    expect(scrubbed).not.toContain(STRIPE_KEY);
  });
});

// =====================================================================
// ATTACK VECTOR 3: Split Credential Attacks
// =====================================================================
describe("Attack Vector 3: Split Credential Attacks", () => {
  /**
   * Attack: Split credential across two separate tool calls
   * Call 1 output: "sk_live_"
   * Call 2 output: "abcdef1234567890abcdef12"
   *
   * KNOWN GAP: Each tool call output is scrubbed independently.
   * Split credentials across calls won't be caught.
   */
  it("GAP: split credential across two calls is NOT caught individually", () => {
    const part1 = "sk_live_";
    const part2 = "abcdef1234567890abcdef12";
    // Each part independently doesn't match the regex pattern
    const scrubbed1 = scrubText(part1, rules);
    const scrubbed2 = scrubText(part2, rules);
    // Part 1 is just a prefix — too short to be a credential match
    expect(scrubbed1).toBe("sk_live_");
    // Part 2 is just random chars — no pattern match
    expect(scrubbed2).toBe("abcdef1234567890abcdef12");
  });

  /**
   * Attack: Describe credential in natural language
   * "My key starts with sk_live_ and ends with ef12"
   */
  it("GAP: natural language description leaks partial credential", () => {
    const description = "My key starts with sk_live_ and ends with ef12";
    const scrubbed = scrubText(description, rules);
    // The regex won't match this because it's not a complete credential format
    // BUT the description still leaks partial info
    // The literal scrubber won't match because the full string isn't present
    expect(scrubbed).toBe(description);
  });

  /**
   * Defense: Full credential split with newline should still be caught by literal match
   */
  it("should catch credential even when split across lines but present in full", () => {
    // If the full credential appears in a single scrubText call, it should be caught
    const output = `Key:\n${STRIPE_KEY}\nDone`;
    const scrubbed = scrubText(output, rules);
    expect(scrubbed).not.toContain(STRIPE_KEY);
  });

  /**
   * Attack: Credential with spaces inserted
   */
  it("GAP: credential with spaces inserted is NOT caught", () => {
    const spaced = STRIPE_KEY.split("").join(" ");
    const scrubbed = scrubText(spaced, rules);
    expect(scrubbed).toContain(spaced);
  });
});

// =====================================================================
// ATTACK VECTOR 4: Env Variable Scrubbing Bypasses
// =====================================================================
describe("Attack Vector 4: Env Variable Scrubbing Bypasses", () => {
  /**
   * Attack: lowercase env var name
   * api_token=secretvalue — does ENV_VAR_PATTERN catch this?
   * Pattern: [A-Z_]*(KEY|TOKEN|SECRET|PASSWORD|...)= — requires UPPERCASE
   */
  it("GAP: lowercase env var names are NOT scrubbed", () => {
    const output = "api_token=mysecretvalue123";
    const scrubbed = scrubEnvVars(output);
    // ENV_VAR_PATTERN only matches [A-Z_]* prefix — lowercase won't match
    expect(scrubbed).toBe(output);
  });

  /**
   * Attack: Mixed case env var name
   */
  it("GAP: mixed case env var names are NOT scrubbed", () => {
    const output = "Api_Token=mysecretvalue123";
    const scrubbed = scrubEnvVars(output);
    expect(scrubbed).toBe(output);
  });

  /**
   * Defense: Standard uppercase env var IS scrubbed
   */
  it("should scrub standard uppercase env var", () => {
    const output = "API_TOKEN=mysecretvalue123";
    const scrubbed = scrubEnvVars(output);
    expect(scrubbed).toBe("API_TOKEN=[VAULT:env-redacted]");
  });

  /**
   * Attack: Colon separator instead of =
   * API_TOKEN:secretvalue
   */
  it("GAP: colon separator is NOT caught by env scrubber", () => {
    const output = "API_TOKEN:mysecretvalue123";
    const scrubbed = scrubEnvVars(output);
    // Pattern requires = sign
    expect(scrubbed).toBe(output);
  });

  /**
   * Attack: Arrow separator
   * API_TOKEN → secretvalue
   */
  it("GAP: arrow separator is NOT caught by env scrubber", () => {
    const output = "API_TOKEN → mysecretvalue123";
    const scrubbed = scrubEnvVars(output);
    expect(scrubbed).toBe(output);
  });

  /**
   * Attack: Env var with spaces around =
   * API_TOKEN = secretvalue (space before and after =)
   */
  it("GAP: env var with spaces around = is NOT caught", () => {
    const output = "API_TOKEN = mysecretvalue123";
    const scrubbed = scrubEnvVars(output);
    // Pattern requires KEY=value with no spaces around =
    expect(scrubbed).toBe(output);
  });

  /**
   * Defense: Multiple env vars on separate lines
   */
  it("should scrub multiple env vars", () => {
    const output = "STRIPE_SECRET_KEY=sk_live_xxx\nGH_TOKEN=ghp_xxx";
    const scrubbed = scrubEnvVars(output);
    expect(scrubbed).toContain("[VAULT:env-redacted]");
    expect(scrubbed).not.toContain("sk_live_xxx");
    expect(scrubbed).not.toContain("ghp_xxx");
  });

  /**
   * Attack: export prefix
   * export API_SECRET=value
   */
  it("should scrub env var with export prefix", () => {
    const output = "export API_SECRET=mysecretvalue123";
    const scrubbed = scrubEnvVars(output);
    expect(scrubbed).toContain("[VAULT:env-redacted]");
  });
});

// =====================================================================
// ATTACK VECTOR 5: Write/Edit Scrubbing Bypasses
// =====================================================================
describe("Attack Vector 5: Write/Edit Scrubbing Bypasses", () => {
  /**
   * Attack: Write credential split across multiple lines in file content
   * The full credential exists in the content but spans lines via concatenation
   */
  it("should catch credential in multi-line file content", () => {
    const content = `const key = "${STRIPE_KEY}";\nconsole.log(key);`;
    const scrubbed = scrubText(content, rules);
    expect(scrubbed).not.toContain(STRIPE_KEY);
  });

  /**
   * Attack: Credential in JSON with escape characters
   * "key": "sk_live_abc\"123" — the \" doesn't break the credential
   */
  it("should catch credential in JSON with escapes around it", () => {
    // The credential itself doesn't contain escape chars, but is surrounded by them
    const content = `{"key": "${STRIPE_KEY}", "note": "test\\"value"}`;
    const scrubbed = scrubText(content, rules);
    expect(scrubbed).not.toContain(STRIPE_KEY);
  });

  /**
   * Attack: Credential embedded in a heredoc
   */
  it("should catch credential in heredoc content", () => {
    const content = `cat << 'EOF'\nSTRIPE_KEY=${STRIPE_KEY}\nEOF`;
    const scrubbed = scrubText(content, rules);
    expect(scrubbed).not.toContain(STRIPE_KEY);
  });

  /**
   * Attack: Credential in base64-encoded file content that the agent writes
   * Agent constructs: btoa("sk_live_...") and writes the result
   */
  it("GAP: base64 of credential written to file is NOT caught", () => {
    const b64Content = Buffer.from(STRIPE_KEY).toString("base64");
    const scrubbed = scrubText(b64Content, rules);
    // Neither regex nor literal match will catch the base64 form
    expect(scrubbed).toBe(b64Content);
  });

  /**
   * Attack: Write custom secret (no regex pattern) that's been registered as literal
   */
  it("should catch literal-registered credential in write content", () => {
    const content = `API_KEY=${CUSTOM_SECRET}`;
    const scrubbed = scrubText(content, rules);
    expect(scrubbed).not.toContain(CUSTOM_SECRET);
  });

  /**
   * Attack: Credential in YAML format
   */
  it("should catch credential in YAML content", () => {
    const content = `apiKey: ${STRIPE_KEY}\nother: value`;
    const scrubbed = scrubText(content, rules);
    expect(scrubbed).not.toContain(STRIPE_KEY);
  });

  /**
   * Attack: Credential in XML/HTML attribute
   */
  it("should catch credential in HTML attribute", () => {
    const content = `<input value="${STRIPE_KEY}" type="hidden"/>`;
    const scrubbed = scrubText(content, rules);
    expect(scrubbed).not.toContain(STRIPE_KEY);
  });
});

// =====================================================================
// ATTACK VECTOR 6: Literal Scrubbing Gaps
// =====================================================================
describe("Attack Vector 6: Literal Scrubbing Gaps", () => {
  /**
   * Attack: Very short credential (<4 chars) — addLiteralCredential rejects these
   * to avoid over-matching common strings
   */
  it("should NOT register credentials shorter than 4 chars", () => {
    clearLiteralCredentials();
    addLiteralCredential("abc", "short-tool");
    const output = "The value is abc and more text";
    const scrubbed = scrubText(output, rules);
    // "abc" should NOT be scrubbed because it's too short (<4 chars)
    expect(scrubbed).toContain("abc");
  });

  /**
   * Test: Credential exactly 4 chars — should be registered
   */
  it("should register credentials of exactly 4 chars", () => {
    clearLiteralCredentials();
    addLiteralCredential("ab12", "four-char-tool");
    const output = "Token: ab12 end";
    const scrubbed = scrubText(output, rules);
    expect(scrubbed).not.toContain("ab12");
    expect(scrubbed).toContain("[VAULT:four-char-tool]");
  });

  /**
   * Attack: Credential that's a common English word
   * If someone stores "password" as a credential, will it over-scrub?
   */
  it("should scrub common word credential but risks false positives", () => {
    clearLiteralCredentials();
    addLiteralCredential("password", "word-tool");
    const text = "Enter your password in the password field";
    const scrubbed = scrubText(text, rules);
    // This will replace ALL occurrences of "password" — including descriptive text
    // This is technically correct (it scrubs) but causes false positives
    expect(scrubbed).not.toContain("password");
    expect(scrubbed).toContain("[VAULT:word-tool]");
  });

  /**
   * Attack: Credential that's a substring of other words
   * Credential "test" appears in "testing", "greatest", etc.
   */
  it("RISK: credential substring matches inside other words", () => {
    clearLiteralCredentials();
    addLiteralCredential("test", "substr-tool");
    const text = "Testing the greatest feature";
    const scrubbed = scrubText(text, rules);
    // indexOf-based matching will match "test" inside "Testing" and "greatest"
    // This is aggressive but safe (over-scrubs rather than under-scrubs)
    expect(scrubbed).toContain("[VAULT:substr-tool]");
  });

  /**
   * Defense: Long, unique credentials should scrub cleanly
   */
  it("should cleanly scrub long unique credentials", () => {
    clearLiteralCredentials();
    const longCred = "xq7k2m9p4r1t8w3y6v0a5c_unique_credential_2026";
    addLiteralCredential(longCred, "long-tool");
    const text = `The credential is ${longCred} and it's secret`;
    const scrubbed = scrubText(text, rules);
    expect(scrubbed).not.toContain(longCred);
    expect(scrubbed).toContain("[VAULT:long-tool]");
  });

  /**
   * Attack: Credential that looks like a common format prefix
   * e.g., "Bearer " — if stored as a credential, would wreck all Bearer tokens
   */
  it("RISK: 'Bearer ' as credential would over-scrub", () => {
    clearLiteralCredentials();
    addLiteralCredential("Bearer ", "bearer-tool");
    const text = "Authorization: Bearer some_normal_token";
    const scrubbed = scrubText(text, rules);
    // "Bearer " would be replaced, mangling the output
    expect(scrubbed).toContain("[VAULT:bearer-tool]");
  });
});

// =====================================================================
// ATTACK VECTOR 7: Race Conditions
// =====================================================================
describe("Attack Vector 7: Race Conditions / Concurrent Scrubbing", () => {
  /**
   * Attack: Multiple concurrent scrub calls — ensure thread safety
   * In JS/Node single-threaded model, true races are unlikely,
   * but async operations with shared state could still cause issues.
   */
  it("should handle concurrent scrub calls safely", async () => {
    const promises = Array.from({ length: 100 }, (_, i) => {
      return new Promise<string>((resolve) => {
        const text = `Call ${i}: ${STRIPE_KEY} and ${GITHUB_TOKEN}`;
        const scrubbed = scrubText(text, rules);
        resolve(scrubbed);
      });
    });

    const results = await Promise.all(promises);
    for (const result of results) {
      expect(result).not.toContain(STRIPE_KEY);
      expect(result).not.toContain(GITHUB_TOKEN);
      expect(result).toContain("[VAULT:stripe]");
      expect(result).toContain("[VAULT:github]");
    }
  });

  /**
   * Attack: Add/remove literals while scrubbing is in progress
   * Modify the literal credential set between scrub operations
   */
  it("should handle credential set modification between calls", () => {
    const NEW_CRED = "new_credential_added_during_operation";
    // First call — NEW_CRED not registered
    const before = scrubText(`Value: ${NEW_CRED}`, rules);
    expect(before).toContain(NEW_CRED);

    // Register new credential
    addLiteralCredential(NEW_CRED, "new-tool");

    // Second call — should now be scrubbed
    const after = scrubText(`Value: ${NEW_CRED}`, rules);
    expect(after).not.toContain(NEW_CRED);
    expect(after).toContain("[VAULT:new-tool]");
  });

  /**
   * Attack: Regex with catastrophic backtracking
   * Input designed to cause exponential regex processing time
   */
  it("should not hang on pathological regex input", () => {
    // Create a string that looks like a credential prefix but is very long
    const pathological = "sk_live_" + "a".repeat(10000);
    const start = Date.now();
    const scrubbed = scrubText(pathological, rules);
    const elapsed = Date.now() - start;
    // Should complete in under 1 second
    expect(elapsed).toBeLessThan(1000);
    // The regex should match this (it's a valid credential format)
    expect(scrubbed).toContain("[VAULT:stripe]");
  });

  /**
   * Attack: Massive output with many credential instances
   */
  it("should handle massive output efficiently", () => {
    const bigOutput = Array.from({ length: 1000 }, (_, i) =>
      `Line ${i}: key=${STRIPE_KEY} token=${GITHUB_TOKEN}`
    ).join("\n");
    const start = Date.now();
    const scrubbed = scrubText(bigOutput, rules);
    const elapsed = Date.now() - start;
    expect(elapsed).toBeLessThan(5000);
    expect(scrubbed).not.toContain(STRIPE_KEY);
    expect(scrubbed).not.toContain(GITHUB_TOKEN);
  });
});

// =====================================================================
// ADDITIONAL ATTACK VECTORS
// =====================================================================
describe("Additional Attack Vectors", () => {
  /**
   * Attack: Credential in a URL query parameter
   */
  it("should catch credential in URL query parameter", () => {
    const url = `https://api.example.com/data?key=${STRIPE_KEY}&format=json`;
    const scrubbed = scrubText(url, rules);
    expect(scrubbed).not.toContain(STRIPE_KEY);
  });

  /**
   * Attack: Credential with surrounding Unicode zero-width characters
   * These invisible chars might break literal matching
   */
  it("GAP: zero-width chars around credential break literal match", () => {
    const zwsp = "\u200B"; // zero-width space
    const obfuscated = `${zwsp}${CUSTOM_SECRET.slice(0, 10)}${zwsp}${CUSTOM_SECRET.slice(10)}`;
    const scrubbed = scrubText(obfuscated, rules);
    // The zero-width space breaks the literal indexOf match
    // This is a documented gap — invisible unicode insertion
    expect(scrubbed).toContain(zwsp);
  });

  /**
   * Attack: Credential in nested object scrubbing
   */
  it("should scrub credentials in deeply nested objects", () => {
    const obj = {
      level1: {
        level2: {
          level3: {
            secret: STRIPE_KEY,
            array: [GITHUB_TOKEN, "safe"],
          },
        },
      },
    };
    const scrubbed = scrubObject(obj, rules) as any;
    expect(scrubbed.level1.level2.level3.secret).not.toContain(STRIPE_KEY);
    expect(scrubbed.level1.level2.level3.array[0]).not.toContain(GITHUB_TOKEN);
    expect(scrubbed.level1.level2.level3.array[1]).toBe("safe");
  });

  /**
   * Attack: containsCredentials check consistency with scrubText
   */
  it("containsCredentials should agree with scrubText", () => {
    const texts = [
      STRIPE_KEY,
      `key=${STRIPE_KEY}`,
      "API_TOKEN=secretvalue",
      "no credentials here",
    ];
    for (const text of texts) {
      const detected = containsCredentials(text, rules);
      const scrubbed = scrubText(text, rules);
      const wasScrubbed = scrubbed !== text;
      expect(detected).toBe(wasScrubbed);
    }
  });

  /**
   * Attack: Null bytes in credential
   */
  it("should handle null bytes in output", () => {
    const output = `Before\0${STRIPE_KEY}\0After`;
    const scrubbed = scrubText(output, rules);
    expect(scrubbed).not.toContain(STRIPE_KEY);
  });

  /**
   * Attack: Very long line with credential at the end
   */
  it("should catch credential at end of very long line", () => {
    const longPrefix = "x".repeat(100000);
    const output = `${longPrefix}${STRIPE_KEY}`;
    const scrubbed = scrubText(output, rules);
    expect(scrubbed).not.toContain(STRIPE_KEY);
  });

  /**
   * Attack: Multiple different credentials on the same line
   */
  it("should scrub multiple different credentials on same line", () => {
    const output = `stripe=${STRIPE_KEY} github=${GITHUB_TOKEN} custom=${CUSTOM_SECRET}`;
    const scrubbed = scrubText(output, rules);
    expect(scrubbed).not.toContain(STRIPE_KEY);
    expect(scrubbed).not.toContain(GITHUB_TOKEN);
    expect(scrubbed).not.toContain(CUSTOM_SECRET);
  });

  /**
   * Attack: Credential followed by itself (overlapping matches)
   */
  it("should handle credential repeated consecutively", () => {
    const output = `${STRIPE_KEY}${STRIPE_KEY}`;
    const scrubbed = scrubText(output, rules);
    expect(scrubbed).not.toContain(STRIPE_KEY);
  });
});
