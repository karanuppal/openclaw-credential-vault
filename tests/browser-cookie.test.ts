/**
 * Phase 5: Browser Cookie Injection Tests
 *
 * Validates spec section "browser-cookie" (Phase 3B):
 * - Cookie injection via Playwright context.addCookies() before navigation
 * - Cookie values scrubbed from output (afterToolCall)
 * - Cookie expiry tracking + audit warnings
 * - Domain pinning for cookie injection
 *
 * Spec ref: "browser-cookie: domain-pinned cookie jar inject"
 */

import { describe, it, expect, vi, beforeEach } from "vitest";

// --- Mock types for browser-cookie injection (NOT BUILT yet) ---
// TODO: Replace with actual imports once browser-cookie is implemented

interface PlaywrightCookie {
  name: string;
  value: string;
  domain: string;
  path: string;
  expires: number; // Unix timestamp, -1 for session
  httpOnly: boolean;
  secure: boolean;
  sameSite: "Strict" | "Lax" | "None";
}

interface CookieConfig {
  type: "browser-cookie";
  domainPin: string[];
  inject: {
    tool: "browser";
    method: "cookie-jar";
    urlMatch: string;
  };
  scrub: boolean;
  expires?: string; // ISO timestamp of earliest cookie expiry
}

interface CookieInjectionResult {
  injected: boolean;
  cookieCount: number;
  error?: string;
}

/**
 * Simulates cookie URL matching for injection trigger.
 * Cookies are injected before navigation to matching URLs.
 */
function shouldInjectCookies(url: string, config: CookieConfig): boolean {
  // Check domain pin
  let hostname: string;
  try {
    hostname = new URL(url).hostname;
  } catch {
    return false;
  }

  for (const pin of config.domainPin) {
    if (pin.startsWith(".")) {
      const domain = pin.slice(1);
      if (hostname === domain || hostname.endsWith("." + domain)) {
        return true;
      }
    } else {
      if (hostname === pin) return true;
    }
  }
  return false;
}

/**
 * Simulates cookie expiry checking.
 */
function getEarliestExpiry(cookies: PlaywrightCookie[]): Date | null {
  const withExpiry = cookies.filter((c) => c.expires > 0);
  if (withExpiry.length === 0) return null;
  const earliest = Math.min(...withExpiry.map((c) => c.expires));
  return new Date(earliest * 1000);
}

function isCookieExpired(cookies: PlaywrightCookie[]): boolean {
  const earliest = getEarliestExpiry(cookies);
  if (!earliest) return false; // session cookies don't expire
  return earliest.getTime() < Date.now();
}

/**
 * Simulates scrubbing cookie values from tool output.
 */
function scrubCookieValues(text: string, cookies: PlaywrightCookie[]): string {
  let result = text;
  for (const cookie of cookies) {
    if (cookie.value.length >= 4) {
      result = result.replaceAll(cookie.value, "[VAULT:cookie]");
    }
  }
  return result;
}

// --- Test data ---

const amazonCookies: PlaywrightCookie[] = [
  {
    name: "session-id",
    value: "139-4827659-3847265",
    domain: ".amazon.com",
    path: "/",
    expires: Math.floor(Date.now() / 1000) + 86400, // expires tomorrow
    httpOnly: true,
    secure: true,
    sameSite: "Lax",
  },
  {
    name: "session-token",
    value: "abcdef1234567890abcdef1234567890abcdef",
    domain: ".amazon.com",
    path: "/",
    expires: Math.floor(Date.now() / 1000) + 86400,
    httpOnly: true,
    secure: true,
    sameSite: "Lax",
  },
  {
    name: "ubid-main",
    value: "131-2849572-9384756",
    domain: ".amazon.com",
    path: "/",
    expires: Math.floor(Date.now() / 1000) + 86400 * 365,
    httpOnly: false,
    secure: true,
    sameSite: "Lax",
  },
];

const amazonCookieConfig: CookieConfig = {
  type: "browser-cookie",
  domainPin: [".amazon.com"],
  inject: {
    tool: "browser",
    method: "cookie-jar",
    urlMatch: "*.amazon.com/*",
  },
  scrub: true,
  expires: new Date(Date.now() + 86400 * 1000).toISOString(),
};

describe("Browser Cookie — injection before navigation", () => {
  it("should inject cookies when URL matches pinned domain", () => {
    const url = "https://www.amazon.com/orders";
    expect(shouldInjectCookies(url, amazonCookieConfig)).toBe(true);
  });

  it("should inject on bare domain", () => {
    const url = "https://amazon.com/gp/css/homepage.html";
    expect(shouldInjectCookies(url, amazonCookieConfig)).toBe(true);
  });

  it("should inject on subdomain", () => {
    const url = "https://smile.amazon.com/";
    expect(shouldInjectCookies(url, amazonCookieConfig)).toBe(true);
  });

  it("should NOT inject on wrong domain", () => {
    const url = "https://evil-site.com/fake-amazon";
    expect(shouldInjectCookies(url, amazonCookieConfig)).toBe(false);
  });

  it("should NOT inject on domain containing amazon as substring", () => {
    const url = "https://not-amazon.com/orders";
    expect(shouldInjectCookies(url, amazonCookieConfig)).toBe(false);
  });

  it("should NOT inject on phishing domain", () => {
    const url = "https://amazon.com.evil.org/orders";
    expect(shouldInjectCookies(url, amazonCookieConfig)).toBe(false);
  });

  it("should handle invalid URL gracefully", () => {
    expect(shouldInjectCookies("not-a-url", amazonCookieConfig)).toBe(false);
  });
});

describe("Browser Cookie — output scrubbing", () => {
  it("should scrub session-id from page content", () => {
    const output = `Order #123 placed. Session: 139-4827659-3847265`;
    const scrubbed = scrubCookieValues(output, amazonCookies);
    expect(scrubbed).not.toContain("139-4827659-3847265");
    expect(scrubbed).toContain("[VAULT:cookie]");
  });

  it("should scrub session-token from page content", () => {
    const output = `Token: abcdef1234567890abcdef1234567890abcdef`;
    const scrubbed = scrubCookieValues(output, amazonCookies);
    expect(scrubbed).not.toContain("abcdef1234567890abcdef1234567890abcdef");
    expect(scrubbed).toContain("[VAULT:cookie]");
  });

  it("should scrub multiple cookie values in one output", () => {
    const output = `session-id=139-4827659-3847265; ubid-main=131-2849572-9384756`;
    const scrubbed = scrubCookieValues(output, amazonCookies);
    expect(scrubbed).not.toContain("139-4827659-3847265");
    expect(scrubbed).not.toContain("131-2849572-9384756");
  });

  it("should not modify output without cookie values", () => {
    const output = "Your order has been shipped!";
    const scrubbed = scrubCookieValues(output, amazonCookies);
    expect(scrubbed).toBe(output);
  });

  it("should scrub cookie values from JSON responses", () => {
    const output = JSON.stringify({
      cookies: [{ name: "session-id", value: "139-4827659-3847265" }],
    });
    const scrubbed = scrubCookieValues(output, amazonCookies);
    expect(scrubbed).not.toContain("139-4827659-3847265");
  });
});

describe("Browser Cookie — expiry tracking", () => {
  it("should detect earliest expiry from cookies", () => {
    const earliest = getEarliestExpiry(amazonCookies);
    expect(earliest).not.toBeNull();
    expect(earliest!.getTime()).toBeGreaterThan(Date.now());
  });

  it("should return null for session-only cookies (no expiry)", () => {
    const sessionCookies: PlaywrightCookie[] = [
      {
        name: "sid",
        value: "abc123",
        domain: ".example.com",
        path: "/",
        expires: -1, // session cookie
        httpOnly: true,
        secure: true,
        sameSite: "Lax",
      },
    ];
    const earliest = getEarliestExpiry(sessionCookies);
    expect(earliest).toBeNull();
  });

  it("should detect expired cookies", () => {
    const expiredCookies: PlaywrightCookie[] = [
      {
        name: "old-session",
        value: "expired-value-123",
        domain: ".example.com",
        path: "/",
        expires: Math.floor(Date.now() / 1000) - 86400, // expired yesterday
        httpOnly: true,
        secure: true,
        sameSite: "Lax",
      },
    ];
    expect(isCookieExpired(expiredCookies)).toBe(true);
  });

  it("should not flag valid (non-expired) cookies", () => {
    expect(isCookieExpired(amazonCookies)).toBe(false);
  });

  it("should pick the earliest expiry among multiple cookies", () => {
    const mixedCookies: PlaywrightCookie[] = [
      { ...amazonCookies[0], expires: Math.floor(Date.now() / 1000) + 3600 }, // 1 hour
      { ...amazonCookies[1], expires: Math.floor(Date.now() / 1000) + 86400 }, // 1 day
      { ...amazonCookies[2], expires: Math.floor(Date.now() / 1000) + 86400 * 365 }, // 1 year
    ];
    const earliest = getEarliestExpiry(mixedCookies);
    expect(earliest).not.toBeNull();
    // Should be ~1 hour from now (the shortest)
    const diffMs = earliest!.getTime() - Date.now();
    expect(diffMs).toBeLessThan(3600 * 1000 + 5000);
    expect(diffMs).toBeGreaterThan(3500 * 1000);
  });
});

describe("Browser Cookie — multi-domain config", () => {
  const multiConfig: CookieConfig = {
    type: "browser-cookie",
    domainPin: [".example.com", ".example.co.uk"],
    inject: { tool: "browser", method: "cookie-jar", urlMatch: "*.example.com/*" },
    scrub: true,
  };

  it("should match primary domain", () => {
    expect(shouldInjectCookies("https://www.example.com/page", multiConfig)).toBe(true);
  });

  it("should match regional domain", () => {
    expect(shouldInjectCookies("https://www.example.co.uk/page", multiConfig)).toBe(true);
  });

  it("should not match other regions not in config", () => {
    expect(shouldInjectCookies("https://www.example.fr/page", multiConfig)).toBe(false);
  });
});
