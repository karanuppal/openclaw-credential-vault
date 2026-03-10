/**
 * Browser credential support: domain-pinned password injection and cookie jar management.
 *
 * - browser-password: resolves $vault: placeholders in browser fill actions after domain pin check
 * - browser-cookie: injects cookies via addCookies() on navigate when URL matches cookie domains
 */

import { InjectionRule, PlaywrightCookie, BrowserCookieCredential } from "./types.js";

// ----- Domain Pinning -----

/**
 * Extract hostname from a URL string.
 * Returns null if URL is unparseable.
 */
export function extractHostname(url: string): string | null {
  try {
    const parsed = new URL(url);
    return parsed.hostname.toLowerCase();
  } catch {
    return null;
  }
}

/**
 * Check if a hostname matches a domain pin.
 *
 * Domain pin rules:
 * - Leading dot (e.g. ".amazon.com"): matches the domain itself AND all subdomains
 *   ".amazon.com" matches "amazon.com", "www.amazon.com", "smile.amazon.com"
 * - Exact match (no leading dot, e.g. "login.amazon.com"): matches only that exact hostname
 * - NO wildcards beyond subdomain matching — "*.com" is NOT valid
 */
export function matchesDomainPin(hostname: string, pin: string): boolean {
  const h = hostname.toLowerCase();
  const p = pin.toLowerCase();

  if (p.startsWith(".")) {
    // Subdomain match: ".amazon.com" matches "amazon.com" and "*.amazon.com"
    const baseDomain = p.slice(1); // remove leading dot
    return h === baseDomain || h.endsWith("." + baseDomain);
  }

  // Exact hostname match
  return h === p;
}

/**
 * Check if a hostname matches ANY of the domain pins.
 */
export function matchesAnyDomainPin(hostname: string, pins: string[]): boolean {
  return pins.some((pin) => matchesDomainPin(hostname, pin));
}

/**
 * Validate domain pin entries. Returns array of error messages (empty = valid).
 * Rejects wildcards like "*.com" or bare TLDs.
 */
export function validateDomainPins(pins: string[]): string[] {
  const errors: string[] = [];
  for (const pin of pins) {
    const cleaned = pin.startsWith(".") ? pin.slice(1) : pin;
    if (cleaned.includes("*")) {
      errors.push(`Invalid domain pin "${pin}": wildcards (*) are not allowed`);
    }
    if (!cleaned.includes(".")) {
      errors.push(`Invalid domain pin "${pin}": must contain at least one dot (no bare TLDs)`);
    }
  }
  return errors;
}

// ----- Browser Password -----

/** Vault placeholder pattern: $vault:name */
const VAULT_PLACEHOLDER_RE = /^\$vault:(.+)$/;

/**
 * Check if a string is a $vault: placeholder.
 */
export function isVaultPlaceholder(value: string): boolean {
  return VAULT_PLACEHOLDER_RE.test(value);
}

/**
 * Extract the credential name from a $vault: placeholder.
 * Returns null if not a placeholder.
 */
export function extractVaultName(value: string): string | null {
  const m = value.match(VAULT_PLACEHOLDER_RE);
  return m ? m[1] : null;
}

/**
 * Result of attempting to resolve a browser-password placeholder.
 */
export interface BrowserPasswordResult {
  allowed: boolean;
  resolvedValue?: string;
  error?: string;
}

/**
 * Attempt to resolve a $vault: placeholder for a browser fill action.
 *
 * 1. Checks that the text param contains a $vault: placeholder
 * 2. Finds the matching browser-password injection rule
 * 3. Validates the current browser URL against the domain pin
 * 4. Returns the resolved credential or an error
 */
export function resolveBrowserPassword(
  text: string,
  currentUrl: string,
  credentialValue: string,
  domainPins: string[]
): BrowserPasswordResult {
  if (!isVaultPlaceholder(text)) {
    return { allowed: true, resolvedValue: text };
  }

  const hostname = extractHostname(currentUrl);
  if (!hostname) {
    return {
      allowed: false,
      error: `Cannot resolve domain from URL: ${currentUrl}`,
    };
  }

  if (!matchesAnyDomainPin(hostname, domainPins)) {
    return {
      allowed: false,
      error: `Domain mismatch — credential pinned to ${domainPins.join(", ")}, current page is ${hostname}`,
    };
  }

  return { allowed: true, resolvedValue: credentialValue };
}

// ----- Browser Cookies -----

/**
 * Check if a URL matches any of the cookie domain pins.
 * Used to determine whether to inject cookies before navigation.
 */
export function shouldInjectCookies(url: string, domainPins: string[]): boolean {
  const hostname = extractHostname(url);
  if (!hostname) return false;
  return matchesAnyDomainPin(hostname, domainPins);
}

/**
 * Filter cookies to only include those matching the target domain pins.
 * Cookies have their own domain field; we filter to avoid injecting
 * cookies from other domains.
 */
export function filterCookiesByDomain(
  cookies: PlaywrightCookie[],
  domainPins: string[]
): PlaywrightCookie[] {
  return cookies.filter((cookie) => {
    // Cookie domain may have a leading dot (e.g. ".amazon.com")
    const cookieDomain = cookie.domain.startsWith(".")
      ? cookie.domain.slice(1)
      : cookie.domain;
    return domainPins.some((pin) => {
      const pinDomain = pin.startsWith(".") ? pin.slice(1) : pin;
      return (
        cookieDomain === pinDomain || cookieDomain.endsWith("." + pinDomain)
      );
    });
  });
}

/**
 * Get the earliest expiry timestamp from a set of cookies.
 * Returns null if all cookies are session cookies (expires = -1).
 * Returns the ISO string of the earliest expiry.
 */
export function getEarliestExpiry(cookies: PlaywrightCookie[]): string | null {
  let earliest: number | null = null;
  for (const cookie of cookies) {
    if (cookie.expires > 0) {
      if (earliest === null || cookie.expires < earliest) {
        earliest = cookie.expires;
      }
    }
  }
  if (earliest === null) return null;
  return new Date(earliest * 1000).toISOString();
}

/**
 * Check if any cookies in the set are expired.
 */
export function hasExpiredCookies(cookies: PlaywrightCookie[]): boolean {
  const now = Date.now() / 1000;
  return cookies.some((c) => c.expires > 0 && c.expires < now);
}

/**
 * Remove expired cookies from the set.
 */
export function removeExpiredCookies(
  cookies: PlaywrightCookie[]
): PlaywrightCookie[] {
  const now = Date.now() / 1000;
  return cookies.filter((c) => c.expires <= 0 || c.expires >= now);
}

// ----- Cookie Parsing -----

/** Known tracking/analytics cookie prefixes to filter out */
const TRACKING_COOKIE_PATTERNS = [
  /^_ga/,
  /^_gid$/,
  /^_gat/,
  /^_fbp$/,
  /^_fbc$/,
  /^__utm/,
  /^_gcl_/,
  /^_hjid$/,
  /^_hjAbsoluteSessionInProgress$/,
  /^mp_/,
  /^__hssc$/,
  /^__hssrc$/,
  /^__hstc$/,
  /^hubspotutk$/,
  /^intercom-/,
  /^ajs_/,
  /^optimizelyEndUserId$/,
  /^_mkto_trk$/,
];

/**
 * Check if a cookie name matches known tracking/analytics patterns.
 */
export function isTrackingCookie(name: string): boolean {
  return TRACKING_COOKIE_PATTERNS.some((pat) => pat.test(name));
}

/**
 * Filter out tracking/analytics cookies from a list.
 */
export function filterTrackingCookies(
  cookies: PlaywrightCookie[]
): PlaywrightCookie[] {
  return cookies.filter((c) => !isTrackingCookie(c.name));
}

/**
 * Parse a JSON array of cookies into PlaywrightCookie format.
 * Accepts Playwright-format JSON (array of objects with name, value, domain, etc).
 */
export function parseCookieJson(json: string): PlaywrightCookie[] {
  const parsed = JSON.parse(json);
  if (!Array.isArray(parsed)) {
    throw new Error("Cookie JSON must be an array");
  }
  return parsed.map(normalizeCookie);
}

/**
 * Parse Netscape/curl cookie format (tab-separated) into PlaywrightCookie format.
 *
 * Format: domain\tflag\tpath\tsecure\texpires\tname\tvalue
 * Lines starting with # are comments.
 */
export function parseNetscapeCookies(text: string): PlaywrightCookie[] {
  const cookies: PlaywrightCookie[] = [];
  const lines = text.split("\n");

  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;

    const parts = trimmed.split("\t");
    if (parts.length < 7) continue;

    const [domain, , path, secure, expires, name, value] = parts;
    cookies.push({
      name,
      value,
      domain,
      path: path || "/",
      expires: parseInt(expires, 10) || -1,
      httpOnly: false, // Not encoded in Netscape format
      secure: secure.toUpperCase() === "TRUE",
      sameSite: "Lax",
    });
  }

  return cookies;
}

/**
 * Normalize a cookie object to PlaywrightCookie format, filling in defaults.
 */
function normalizeCookie(raw: Record<string, unknown>): PlaywrightCookie {
  return {
    name: String(raw.name ?? ""),
    value: String(raw.value ?? ""),
    domain: String(raw.domain ?? ""),
    path: String(raw.path ?? "/"),
    expires: typeof raw.expires === "number" ? raw.expires : -1,
    httpOnly: Boolean(raw.httpOnly ?? false),
    secure: Boolean(raw.secure ?? false),
    sameSite: normalizeSameSite(raw.sameSite),
  };
}

function normalizeSameSite(
  val: unknown
): "Strict" | "Lax" | "None" {
  const s = String(val ?? "Lax");
  if (s === "Strict") return "Strict";
  if (s === "None") return "None";
  return "Lax";
}

/**
 * Auto-detect cookie format (JSON or Netscape) and parse.
 */
export function parseCookies(input: string): PlaywrightCookie[] {
  const trimmed = input.trim();
  if (trimmed.startsWith("[")) {
    return parseCookieJson(trimmed);
  }
  return parseNetscapeCookies(trimmed);
}

// ----- Hook Integration Helpers -----

/**
 * Find browser-password injection rules for a given vault tool name.
 */
export function findBrowserPasswordRule(
  vaultToolName: string,
  rules: InjectionRule[]
): InjectionRule | null {
  return (
    rules.find(
      (r) => r.tool === "browser" && r.type === "browser-password"
    ) ?? null
  );
}

/**
 * Find browser-cookie injection rules for a given vault tool name.
 */
export function findBrowserCookieRule(
  vaultToolName: string,
  rules: InjectionRule[]
): InjectionRule | null {
  return (
    rules.find(
      (r) => r.tool === "browser" && r.type === "browser-cookie"
    ) ?? null
  );
}

/**
 * Find ALL browser-cookie rules across all configured tools.
 * Returns pairs of [vaultToolName, rule].
 */
export function findAllBrowserCookieRules(
  toolConfigs: Record<string, { inject: InjectionRule[] }>
): Array<{ vaultToolName: string; rule: InjectionRule }> {
  const results: Array<{ vaultToolName: string; rule: InjectionRule }> = [];
  for (const [name, config] of Object.entries(toolConfigs)) {
    for (const rule of config.inject) {
      if (rule.tool === "browser" && rule.type === "browser-cookie") {
        results.push({ vaultToolName: name, rule });
      }
    }
  }
  return results;
}
