/**
 * Tests for browser credential support (Phase 3B):
 * - Domain pinning
 * - $vault: placeholder resolution
 * - Cookie parsing (JSON + Netscape)
 * - Cookie filtering & expiry
 * - Tracking cookie detection
 */

import { describe, it, expect } from "vitest";
import {
  extractHostname,
  matchesDomainPin,
  matchesAnyDomainPin,
  validateDomainPins,
  isVaultPlaceholder,
  extractVaultName,
  resolveBrowserPassword,
  shouldInjectCookies,
  filterCookiesByDomain,
  getEarliestExpiry,
  hasExpiredCookies,
  removeExpiredCookies,
  isTrackingCookie,
  filterTrackingCookies,
  parseCookieJson,
  parseNetscapeCookies,
  parseCookies,
  findBrowserPasswordRule,
  findBrowserCookieRule,
  findAllBrowserCookieRules,
} from "../src/browser.js";
import type { PlaywrightCookie, InjectionRule } from "../src/types.js";

// ===== Domain Pinning =====

describe("Domain Pinning", () => {
  describe("extractHostname", () => {
    it("extracts hostname from HTTPS URL", () => {
      expect(extractHostname("https://www.amazon.com/orders")).toBe("www.amazon.com");
    });

    it("extracts hostname from HTTP URL", () => {
      expect(extractHostname("http://login.amazon.co.uk/signin")).toBe("login.amazon.co.uk");
    });

    it("returns null for invalid URL", () => {
      expect(extractHostname("not-a-url")).toBeNull();
    });

    it("lowercases hostname", () => {
      expect(extractHostname("https://WWW.Amazon.COM/path")).toBe("www.amazon.com");
    });
  });

  describe("matchesDomainPin", () => {
    // Leading dot = subdomain match
    it("leading dot matches exact base domain", () => {
      expect(matchesDomainPin("amazon.com", ".amazon.com")).toBe(true);
    });

    it("leading dot matches www subdomain", () => {
      expect(matchesDomainPin("www.amazon.com", ".amazon.com")).toBe(true);
    });

    it("leading dot matches deep subdomain", () => {
      expect(matchesDomainPin("smile.www.amazon.com", ".amazon.com")).toBe(true);
    });

    it("leading dot does NOT match unrelated domain", () => {
      expect(matchesDomainPin("evil-amazon.com", ".amazon.com")).toBe(false);
    });

    it("leading dot does NOT match partial suffix", () => {
      expect(matchesDomainPin("notamazon.com", ".amazon.com")).toBe(false);
    });

    // Exact match (no leading dot)
    it("exact match succeeds for same hostname", () => {
      expect(matchesDomainPin("login.amazon.com", "login.amazon.com")).toBe(true);
    });

    it("exact match fails for subdomain", () => {
      expect(matchesDomainPin("www.login.amazon.com", "login.amazon.com")).toBe(false);
    });

    it("exact match fails for different hostname", () => {
      expect(matchesDomainPin("amazon.com", "login.amazon.com")).toBe(false);
    });

    // Case insensitivity
    it("matching is case-insensitive", () => {
      expect(matchesDomainPin("WWW.Amazon.COM", ".amazon.com")).toBe(true);
    });
  });

  describe("matchesAnyDomainPin", () => {
    const pins = [".amazon.com", ".amazon.co.uk", ".amazon.de"];

    it("matches any of multiple pins", () => {
      expect(matchesAnyDomainPin("www.amazon.co.uk", pins)).toBe(true);
    });

    it("fails if none match", () => {
      expect(matchesAnyDomainPin("evil-site.com", pins)).toBe(false);
    });
  });

  describe("validateDomainPins", () => {
    it("accepts valid pins", () => {
      expect(validateDomainPins([".amazon.com", "login.netflix.com"])).toEqual([]);
    });

    it("rejects wildcard pins", () => {
      const errors = validateDomainPins(["*.com"]);
      expect(errors.length).toBe(1);
      expect(errors[0]).toContain("wildcards");
    });

    it("rejects bare TLD", () => {
      const errors = validateDomainPins([".com"]);
      expect(errors.length).toBe(1);
      expect(errors[0]).toContain("bare TLDs");
    });
  });
});

// ===== Browser Password Placeholder =====

describe("Browser Password", () => {
  describe("isVaultPlaceholder / extractVaultName", () => {
    it("detects $vault: prefix", () => {
      expect(isVaultPlaceholder("$vault:amazon-login")).toBe(true);
    });

    it("rejects non-vault strings", () => {
      expect(isVaultPlaceholder("my-password")).toBe(false);
    });

    it("extracts vault name", () => {
      expect(extractVaultName("$vault:amazon-login")).toBe("amazon-login");
    });

    it("returns null for non-vault", () => {
      expect(extractVaultName("plain-text")).toBeNull();
    });
  });

  describe("resolveBrowserPassword", () => {
    const pins = [".amazon.com"];
    const cred = "s3cretP@ss";

    it("resolves when domain matches", () => {
      const result = resolveBrowserPassword(
        "$vault:amazon-login",
        "https://www.amazon.com/ap/signin",
        cred,
        pins
      );
      expect(result.allowed).toBe(true);
      expect(result.resolvedValue).toBe(cred);
    });

    it("blocks when domain does NOT match", () => {
      const result = resolveBrowserPassword(
        "$vault:amazon-login",
        "https://evil-site.com/phishing",
        cred,
        pins
      );
      expect(result.allowed).toBe(false);
      expect(result.error).toContain("Domain mismatch");
      expect(result.error).toContain("evil-site.com");
    });

    it("passes through non-vault text unchanged", () => {
      const result = resolveBrowserPassword("plain text", "https://anything.com", cred, pins);
      expect(result.allowed).toBe(true);
      expect(result.resolvedValue).toBe("plain text");
    });

    it("errors on unparseable URL", () => {
      const result = resolveBrowserPassword(
        "$vault:test",
        "not-a-url",
        cred,
        pins
      );
      expect(result.allowed).toBe(false);
      expect(result.error).toContain("Cannot resolve domain");
    });

    it("matches subdomain correctly", () => {
      const result = resolveBrowserPassword(
        "$vault:amazon-login",
        "https://smile.amazon.com/login",
        cred,
        pins
      );
      expect(result.allowed).toBe(true);
    });
  });
});

// ===== Cookie Operations =====

const makeCookie = (overrides: Partial<PlaywrightCookie> = {}): PlaywrightCookie => ({
  name: "session-id",
  value: "abc123",
  domain: ".amazon.com",
  path: "/",
  expires: Math.floor(Date.now() / 1000) + 86400, // 24h from now
  httpOnly: true,
  secure: true,
  sameSite: "Lax",
  ...overrides,
});

describe("Cookie Operations", () => {
  describe("shouldInjectCookies", () => {
    it("matches URL against domain pins", () => {
      expect(shouldInjectCookies("https://www.amazon.com/orders", [".amazon.com"])).toBe(true);
    });

    it("does not match unrelated URL", () => {
      expect(shouldInjectCookies("https://evil.com", [".amazon.com"])).toBe(false);
    });

    it("returns false for invalid URL", () => {
      expect(shouldInjectCookies("not-a-url", [".amazon.com"])).toBe(false);
    });
  });

  describe("filterCookiesByDomain", () => {
    it("keeps cookies matching domain pin", () => {
      const cookies = [
        makeCookie({ domain: ".amazon.com" }),
        makeCookie({ domain: ".other.com", name: "other" }),
      ];
      const filtered = filterCookiesByDomain(cookies, [".amazon.com"]);
      expect(filtered).toHaveLength(1);
      expect(filtered[0].domain).toBe(".amazon.com");
    });

    it("handles cookies without leading dot", () => {
      const cookies = [makeCookie({ domain: "amazon.com" })];
      const filtered = filterCookiesByDomain(cookies, [".amazon.com"]);
      expect(filtered).toHaveLength(1);
    });
  });

  describe("getEarliestExpiry", () => {
    it("finds earliest expiring cookie", () => {
      const cookies = [
        makeCookie({ expires: 1000 }),
        makeCookie({ expires: 500 }),
        makeCookie({ expires: 2000 }),
      ];
      const earliest = getEarliestExpiry(cookies);
      expect(earliest).toBe(new Date(500 * 1000).toISOString());
    });

    it("returns null for session-only cookies", () => {
      const cookies = [makeCookie({ expires: -1 })];
      expect(getEarliestExpiry(cookies)).toBeNull();
    });
  });

  describe("hasExpiredCookies / removeExpiredCookies", () => {
    it("detects expired cookies", () => {
      const cookies = [makeCookie({ expires: 1 })]; // epoch second 1 = long ago
      expect(hasExpiredCookies(cookies)).toBe(true);
    });

    it("does not flag valid cookies", () => {
      const cookies = [makeCookie()]; // 24h from now
      expect(hasExpiredCookies(cookies)).toBe(false);
    });

    it("removes expired cookies", () => {
      const cookies = [
        makeCookie({ expires: 1, name: "old" }),
        makeCookie({ name: "valid" }),
      ];
      const valid = removeExpiredCookies(cookies);
      expect(valid).toHaveLength(1);
      expect(valid[0].name).toBe("valid");
    });

    it("keeps session cookies (expires = -1)", () => {
      const cookies = [makeCookie({ expires: -1, name: "session" })];
      const valid = removeExpiredCookies(cookies);
      expect(valid).toHaveLength(1);
    });
  });
});

// ===== Cookie Parsing =====

describe("Cookie Parsing", () => {
  describe("parseCookieJson", () => {
    it("parses Playwright-format JSON array", () => {
      const json = JSON.stringify([
        {
          name: "session-id",
          value: "abc123",
          domain: ".amazon.com",
          path: "/",
          expires: 1710072000,
          httpOnly: true,
          secure: true,
          sameSite: "Lax",
        },
      ]);
      const cookies = parseCookieJson(json);
      expect(cookies).toHaveLength(1);
      expect(cookies[0].name).toBe("session-id");
      expect(cookies[0].value).toBe("abc123");
      expect(cookies[0].httpOnly).toBe(true);
    });

    it("fills defaults for missing fields", () => {
      const json = JSON.stringify([{ name: "x", value: "y", domain: ".test.com" }]);
      const cookies = parseCookieJson(json);
      expect(cookies[0].path).toBe("/");
      expect(cookies[0].expires).toBe(-1);
      expect(cookies[0].sameSite).toBe("Lax");
    });

    it("throws on non-array input", () => {
      expect(() => parseCookieJson('{"name":"x"}')).toThrow("must be an array");
    });
  });

  describe("parseNetscapeCookies", () => {
    it("parses tab-separated Netscape format", () => {
      const text = `.amazon.com\tTRUE\t/\tTRUE\t1710072000\tsession-id\tabc123`;
      const cookies = parseNetscapeCookies(text);
      expect(cookies).toHaveLength(1);
      expect(cookies[0].name).toBe("session-id");
      expect(cookies[0].value).toBe("abc123");
      expect(cookies[0].domain).toBe(".amazon.com");
      expect(cookies[0].secure).toBe(true);
    });

    it("skips comment lines", () => {
      const text = `# Netscape HTTP Cookie File\n.amazon.com\tTRUE\t/\tFALSE\t0\ttest\tval`;
      const cookies = parseNetscapeCookies(text);
      expect(cookies).toHaveLength(1);
    });

    it("skips malformed lines", () => {
      const text = `incomplete\tline`;
      const cookies = parseNetscapeCookies(text);
      expect(cookies).toHaveLength(0);
    });
  });

  describe("parseCookies (auto-detect)", () => {
    it("detects JSON format", () => {
      const json = JSON.stringify([{ name: "a", value: "b", domain: ".x.com" }]);
      const cookies = parseCookies(json);
      expect(cookies).toHaveLength(1);
    });

    it("detects Netscape format", () => {
      const text = `.x.com\tTRUE\t/\tFALSE\t0\ta\tb`;
      const cookies = parseCookies(text);
      expect(cookies).toHaveLength(1);
    });
  });
});

// ===== Tracking Cookie Detection =====

describe("Tracking Cookie Detection", () => {
  it("identifies Google Analytics cookies", () => {
    expect(isTrackingCookie("_ga")).toBe(true);
    expect(isTrackingCookie("_gid")).toBe(true);
    expect(isTrackingCookie("_gat_gtag")).toBe(true);
  });

  it("identifies Facebook pixel cookie", () => {
    expect(isTrackingCookie("_fbp")).toBe(true);
  });

  it("identifies UTM cookies", () => {
    expect(isTrackingCookie("__utma")).toBe(true);
    expect(isTrackingCookie("__utmz")).toBe(true);
  });

  it("identifies Google Click ID cookies", () => {
    expect(isTrackingCookie("_gcl_au")).toBe(true);
  });

  it("does NOT flag session cookies", () => {
    expect(isTrackingCookie("session-id")).toBe(false);
    expect(isTrackingCookie("JSESSIONID")).toBe(false);
  });

  it("filters tracking cookies from a list", () => {
    const cookies = [
      makeCookie({ name: "session-id" }),
      makeCookie({ name: "_ga" }),
      makeCookie({ name: "_fbp" }),
      makeCookie({ name: "csrftoken" }),
    ];
    const filtered = filterTrackingCookies(cookies);
    expect(filtered).toHaveLength(2);
    expect(filtered.map((c) => c.name)).toEqual(["session-id", "csrftoken"]);
  });
});

// ===== Rule Finders =====

describe("Rule Finders", () => {
  const rules: InjectionRule[] = [
    {
      tool: "browser",
      type: "browser-password",
      domainPin: [".amazon.com"],
      method: "fill",
      fieldHint: "password",
    },
    {
      tool: "browser",
      type: "browser-cookie",
      domainPin: [".amazon.com"],
      method: "cookie-jar",
      urlMatch: "*.amazon.com/*",
    },
    {
      tool: "exec",
      commandMatch: "gh *",
      env: { GH_TOKEN: "$vault:github" },
    },
  ];

  it("finds browser-password rule", () => {
    const rule = findBrowserPasswordRule("amazon", rules);
    expect(rule).not.toBeNull();
    expect(rule!.type).toBe("browser-password");
  });

  it("finds browser-cookie rule", () => {
    const rule = findBrowserCookieRule("amazon", rules);
    expect(rule).not.toBeNull();
    expect(rule!.type).toBe("browser-cookie");
  });

  it("returns null when no browser rules exist", () => {
    const execOnly: InjectionRule[] = [
      { tool: "exec", commandMatch: "gh *", env: { GH_TOKEN: "$vault:github" } },
    ];
    expect(findBrowserPasswordRule("github", execOnly)).toBeNull();
    expect(findBrowserCookieRule("github", execOnly)).toBeNull();
  });

  it("findAllBrowserCookieRules collects across tools", () => {
    const configs = {
      amazon: { inject: rules },
      netflix: {
        inject: [
          {
            tool: "browser",
            type: "browser-cookie" as const,
            domainPin: [".netflix.com"],
            method: "cookie-jar" as const,
          },
        ],
      },
    };
    const all = findAllBrowserCookieRules(configs);
    expect(all).toHaveLength(2);
    expect(all.map((r) => r.vaultToolName)).toEqual(["amazon", "netflix"]);
  });
});
