/**
 * Phase 5: Browser Password Injection Tests
 *
 * Validates spec section "browser-password" (Phase 3B):
 * - $vault: placeholder resolution in browser fill actions
 * - Domain pinning: credential only resolves when browser URL matches pinned domain(s)
 * - Domain mismatch blocks the action with descriptive error
 * - Leading dot means "this domain and all subdomains"
 * - Exact match (no leading dot) means only that specific hostname
 * - No wildcards beyond subdomain matching (*.com is not valid)
 *
 * Spec ref: "browser-password: domain-pinned fill injection"
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import { ToolConfig, InjectionRule } from "../src/types.js";

// --- Mock types for browser-password injection (NOT BUILT yet) ---
// TODO: Replace with actual imports once browser-password injection is implemented

interface DomainPinConfig {
  type: "browser-password";
  domainPin: string[];
  inject: {
    tool: "browser";
    method: "fill";
    fieldHint?: string;
  };
  scrub: boolean;
}

interface BrowserPasswordResult {
  allowed: boolean;
  resolvedText?: string;
  error?: string;
}

/**
 * Simulates domain matching logic per spec:
 * - Leading dot: matches domain + all subdomains
 * - No leading dot: exact hostname match only
 */
function matchesDomainPin(currentUrl: string, domainPins: string[]): boolean {
  let hostname: string;
  try {
    hostname = new URL(currentUrl).hostname;
  } catch {
    return false;
  }

  for (const pin of domainPins) {
    if (pin.startsWith(".")) {
      // Leading dot: match domain and all subdomains
      const domain = pin.slice(1); // remove leading dot
      if (hostname === domain || hostname.endsWith("." + domain)) {
        return true;
      }
    } else {
      // Exact match
      if (hostname === pin) {
        return true;
      }
    }
  }
  return false;
}

/**
 * Simulates the before_tool_call browser-password resolution logic.
 * TODO: Replace with actual implementation from src/index.ts
 */
function resolveBrowserPassword(
  params: Record<string, unknown>,
  currentUrl: string,
  config: DomainPinConfig,
  credentialValue: string
): BrowserPasswordResult {
  const text = params.text as string | undefined;
  if (!text || !text.startsWith("$vault:")) {
    return { allowed: true, resolvedText: text };
  }

  if (!matchesDomainPin(currentUrl, config.domainPin)) {
    const hostname = new URL(currentUrl).hostname;
    return {
      allowed: false,
      error: `Domain mismatch — credential pinned to ${config.domainPin.join(", ")}, current page is ${hostname}`,
    };
  }

  return {
    allowed: true,
    resolvedText: credentialValue,
  };
}

describe("Browser Password — $vault: placeholder resolution", () => {
  const amazonConfig: DomainPinConfig = {
    type: "browser-password",
    domainPin: [".amazon.com", ".amazon.co.uk", ".amazon.de"],
    inject: { tool: "browser", method: "fill", fieldHint: "password" },
    scrub: true,
  };
  const realPassword = "SuperSecret123!";

  it("should resolve $vault: placeholder to real credential on correct domain", () => {
    const params = { action: "act", kind: "fill", ref: "password-field", text: "$vault:amazon-login" };
    const result = resolveBrowserPassword(params, "https://www.amazon.com/ap/signin", amazonConfig, realPassword);
    expect(result.allowed).toBe(true);
    expect(result.resolvedText).toBe(realPassword);
  });

  it("should resolve on subdomain of pinned domain", () => {
    const params = { text: "$vault:amazon-login" };
    const result = resolveBrowserPassword(params, "https://smile.amazon.com/login", amazonConfig, realPassword);
    expect(result.allowed).toBe(true);
    expect(result.resolvedText).toBe(realPassword);
  });

  it("should resolve on bare domain (no subdomain)", () => {
    const params = { text: "$vault:amazon-login" };
    const result = resolveBrowserPassword(params, "https://amazon.com/ap/signin", amazonConfig, realPassword);
    expect(result.allowed).toBe(true);
    expect(result.resolvedText).toBe(realPassword);
  });

  it("should resolve on regional domain (.co.uk)", () => {
    const params = { text: "$vault:amazon-login" };
    const result = resolveBrowserPassword(params, "https://www.amazon.co.uk/ap/signin", amazonConfig, realPassword);
    expect(result.allowed).toBe(true);
    expect(result.resolvedText).toBe(realPassword);
  });

  it("should resolve on regional domain (.de)", () => {
    const params = { text: "$vault:amazon-login" };
    const result = resolveBrowserPassword(params, "https://www.amazon.de/ap/signin", amazonConfig, realPassword);
    expect(result.allowed).toBe(true);
    expect(result.resolvedText).toBe(realPassword);
  });
});

describe("Browser Password — domain pinning blocks wrong domain", () => {
  const amazonConfig: DomainPinConfig = {
    type: "browser-password",
    domainPin: [".amazon.com", ".amazon.co.uk", ".amazon.de"],
    inject: { tool: "browser", method: "fill", fieldHint: "password" },
    scrub: true,
  };
  const realPassword = "SuperSecret123!";

  it("should block credential on unrelated domain", () => {
    const params = { text: "$vault:amazon-login" };
    const result = resolveBrowserPassword(params, "https://evil-site.com/fake-amazon", amazonConfig, realPassword);
    expect(result.allowed).toBe(false);
    expect(result.error).toContain("Domain mismatch");
    expect(result.error).toContain("evil-site.com");
    expect(result.resolvedText).toBeUndefined();
  });

  it("should block credential on similar-looking domain (typosquatting)", () => {
    const params = { text: "$vault:amazon-login" };
    const result = resolveBrowserPassword(params, "https://amaz0n.com/signin", amazonConfig, realPassword);
    expect(result.allowed).toBe(false);
    expect(result.error).toContain("Domain mismatch");
  });

  it("should block credential on domain containing 'amazon' as substring", () => {
    const params = { text: "$vault:amazon-login" };
    const result = resolveBrowserPassword(params, "https://not-amazon.com/login", amazonConfig, realPassword);
    expect(result.allowed).toBe(false);
  });

  it("should block credential on phishing subdomain of wrong domain", () => {
    const params = { text: "$vault:amazon-login" };
    const result = resolveBrowserPassword(params, "https://amazon.com.evil.org/login", amazonConfig, realPassword);
    expect(result.allowed).toBe(false);
    expect(result.error).toContain("Domain mismatch");
  });

  it("should include pinned domains in error message", () => {
    const params = { text: "$vault:amazon-login" };
    const result = resolveBrowserPassword(params, "https://google.com", amazonConfig, realPassword);
    expect(result.allowed).toBe(false);
    expect(result.error).toContain(".amazon.com");
  });
});

describe("Browser Password — domain matching rules", () => {
  it("leading dot matches domain and all subdomains", () => {
    expect(matchesDomainPin("https://amazon.com/path", [".amazon.com"])).toBe(true);
    expect(matchesDomainPin("https://www.amazon.com/path", [".amazon.com"])).toBe(true);
    expect(matchesDomainPin("https://sub.deep.amazon.com/path", [".amazon.com"])).toBe(true);
  });

  it("exact match (no leading dot) matches only that hostname", () => {
    expect(matchesDomainPin("https://example.com/path", ["example.com"])).toBe(true);
    expect(matchesDomainPin("https://www.example.com/path", ["example.com"])).toBe(false);
    expect(matchesDomainPin("https://sub.example.com/path", ["example.com"])).toBe(false);
  });

  it("invalid URL returns false", () => {
    expect(matchesDomainPin("not-a-url", [".amazon.com"])).toBe(false);
  });

  it("multiple domain pins: any match is sufficient", () => {
    const pins = [".amazon.com", ".amazon.co.uk", ".amazon.de"];
    expect(matchesDomainPin("https://www.amazon.de/login", pins)).toBe(true);
    expect(matchesDomainPin("https://www.amazon.fr/login", pins)).toBe(false);
  });
});

describe("Browser Password — passthrough for non-vault text", () => {
  const config: DomainPinConfig = {
    type: "browser-password",
    domainPin: [".example.com"],
    inject: { tool: "browser", method: "fill" },
    scrub: true,
  };

  it("should pass through text that doesn't start with $vault:", () => {
    const params = { text: "regular-password-text" };
    const result = resolveBrowserPassword(params, "https://example.com", config, "secret");
    expect(result.allowed).toBe(true);
    expect(result.resolvedText).toBe("regular-password-text");
  });

  it("should pass through when no text param exists", () => {
    const params = { ref: "some-ref", kind: "click" };
    const result = resolveBrowserPassword(params, "https://example.com", config, "secret");
    expect(result.allowed).toBe(true);
    expect(result.resolvedText).toBeUndefined();
  });
});

describe("Browser Password — Netflix single-domain config", () => {
  const netflixConfig: DomainPinConfig = {
    type: "browser-password",
    domainPin: [".netflix.com"],
    inject: { tool: "browser", method: "fill", fieldHint: "password" },
    scrub: true,
  };
  const netflixPassword = "NetflixPass456!";

  it("should allow on netflix.com", () => {
    const params = { text: "$vault:netflix" };
    const result = resolveBrowserPassword(params, "https://www.netflix.com/login", netflixConfig, netflixPassword);
    expect(result.allowed).toBe(true);
    expect(result.resolvedText).toBe(netflixPassword);
  });

  it("should block on hulu.com", () => {
    const params = { text: "$vault:netflix" };
    const result = resolveBrowserPassword(params, "https://www.hulu.com/login", netflixConfig, netflixPassword);
    expect(result.allowed).toBe(false);
  });
});
