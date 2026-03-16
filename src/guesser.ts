/**
 * Credential Format Guessing — Phase 3A
 *
 * Analyzes a credential value and guesses:
 * 1. What service it belongs to (known prefix detection)
 * 2. What type of credential it is (JWT, password, API key, cookies/OAuth)
 * 3. Suggested injection config (type, command/URL match, scrub pattern)
 */

import { InjectionRule, ScrubConfig, KnownToolDef, UsageSelection } from "./types.js";
import { KNOWN_TOOLS, generateScrubPattern } from "./registry.js";

// ─── Types ──────────────────────────────────────────────────────────────────

export type CredentialFormat =
  | "stripe-live"
  | "stripe-test"
  | "stripe-restricted"
  | "github-pat"
  | "github-fine-grained"
  | "gumroad"
  | "anthropic"
  | "openai"
  | "jwt"
  | "password"
  | "json-blob"
  | "generic-api-key"
  | "unknown";

export interface GuessResult {
  /** Detected format */
  format: CredentialFormat;
  /** Human-readable description */
  displayName: string;
  /** Confidence: "high" (known prefix), "medium" (heuristic), "low" (fallback) */
  confidence: "high" | "medium" | "low";
  /** Known tool name if matched to registry (e.g. "stripe", "github") */
  knownToolName: string | null;
  /** Suggested injection rules — only populated for high-confidence known-prefix matches */
  suggestedInject: InjectionRule[];
  /** Suggested scrub config */
  suggestedScrub: ScrubConfig;
  /** Whether interactive prompting is recommended */
  needsPrompt: boolean;
  /**
   * Suggested usage type numbers for the new interactive flow menu:
   *   1 = API calls, 2 = CLI tool, 3 = Browser login, 4 = Browser session
   * Empty array means no default suggestion.
   */
  suggestedUsage: number[];
}

// ─── Known Prefix Definitions ───────────────────────────────────────────────

interface PrefixRule {
  prefix: string;
  format: CredentialFormat;
  displayName: string;
  knownToolName: string;
}

/**
 * Ordered list of known prefixes. More specific prefixes first
 * (e.g. sk-ant- before sk- to avoid false matches).
 */
const PREFIX_RULES: PrefixRule[] = [
  { prefix: "sk_live_", format: "stripe-live", displayName: "Stripe live API key", knownToolName: "stripe" },
  { prefix: "sk_test_", format: "stripe-test", displayName: "Stripe test API key", knownToolName: "stripe" },
  { prefix: "rk_live_", format: "stripe-restricted", displayName: "Stripe restricted key", knownToolName: "stripe" },
  { prefix: "github_pat_", format: "github-fine-grained", displayName: "GitHub fine-grained PAT", knownToolName: "github" },
  { prefix: "ghp_", format: "github-pat", displayName: "GitHub personal access token", knownToolName: "github" },
  { prefix: "gum_", format: "gumroad", displayName: "Gumroad API key", knownToolName: "gumroad" },
  { prefix: "sk-ant-", format: "anthropic", displayName: "Anthropic API key", knownToolName: "anthropic" },
  // sk- must come AFTER sk-ant- to avoid matching Anthropic keys as OpenAI
  { prefix: "sk-", format: "openai", displayName: "OpenAI API key", knownToolName: "openai" },
];

// ─── Heuristic Helpers ──────────────────────────────────────────────────────

/**
 * Check if a string is valid base64 (standard or URL-safe).
 */
function isBase64Like(s: string): boolean {
  // Allow standard base64 chars + URL-safe variants + padding
  return /^[A-Za-z0-9+/=_-]+$/.test(s) && s.length >= 4;
}

/**
 * Detect JWT: three dot-separated base64url segments.
 */
export function isJwt(value: string): boolean {
  const parts = value.split(".");
  if (parts.length !== 3) return false;
  // Each part should be non-empty and base64url-like
  return parts.every((p) => p.length > 0 && isBase64Like(p));
}

/**
 * Detect JSON blob (cookies, OAuth tokens, etc.)
 */
export function isJsonBlob(value: string): boolean {
  const trimmed = value.trim();
  if (
    (trimmed.startsWith("{") && trimmed.endsWith("}")) ||
    (trimmed.startsWith("[") && trimmed.endsWith("]"))
  ) {
    try {
      JSON.parse(trimmed);
      return true;
    } catch {
      return false;
    }
  }
  return false;
}

/**
 * Detect short string (likely a password).
 */
export function isShortPassword(value: string): boolean {
  return value.length < 32 && !value.includes(".") && !value.startsWith("{") && !value.startsWith("[");
}

/**
 * Detect long random string (generic API key).
 * Must be alphanumeric (possibly with dashes/underscores), 32+ chars, no spaces.
 */
export function isGenericApiKey(value: string): boolean {
  if (value.length < 32) return false;
  if (value.includes(" ")) return false;
  // Must be mostly alphanumeric with optional dashes/underscores
  return /^[A-Za-z0-9_-]+$/.test(value);
}

// ─── Main Guess Function ────────────────────────────────────────────────────

/**
 * Analyze a credential value and return a guess about its format,
 * suggested injection config, and scrub patterns.
 */
export function guessCredentialFormat(value: string, toolName?: string): GuessResult {
  // 1. Known prefix detection (high confidence)
  for (const rule of PREFIX_RULES) {
    if (value.startsWith(rule.prefix)) {
      const knownTool = KNOWN_TOOLS[rule.knownToolName];
      return {
        format: rule.format,
        displayName: rule.displayName,
        confidence: "high",
        knownToolName: rule.knownToolName,
        suggestedInject: knownTool ? [...knownTool.inject] : [],
        suggestedScrub: knownTool ? { ...knownTool.scrub } : { patterns: [generateScrubPattern(value)] },
        needsPrompt: false,
        suggestedUsage: [], // auto-configured from known template
      };
    }
  }

  // 2. JWT detection (medium confidence)
  if (isJwt(value)) {
    const scrubPattern = generateScrubPattern(value);
    return {
      format: "jwt",
      displayName: "JWT token (three dot-separated base64 segments)",
      confidence: "medium",
      knownToolName: null,
      suggestedInject: [], // user selects usage via menu
      suggestedScrub: { patterns: [scrubPattern] },
      needsPrompt: true,
      suggestedUsage: [1], // API calls (Bearer header)
    };
  }

  // 3. JSON blob detection (medium confidence — cookies or OAuth)
  if (isJsonBlob(value)) {
    return {
      format: "json-blob",
      displayName: "JSON blob (likely session cookies or OAuth token)",
      confidence: "medium",
      knownToolName: null,
      suggestedInject: [],
      suggestedScrub: { patterns: [] },
      needsPrompt: true,
      suggestedUsage: [4], // Browser session (cookie jar)
    };
  }

  // 4. Short string detection (medium confidence — password)
  if (isShortPassword(value)) {
    return {
      format: "password",
      displayName: "Short string (likely a password)",
      confidence: "medium",
      knownToolName: null,
      suggestedInject: [],
      suggestedScrub: { patterns: [] },
      needsPrompt: true,
      suggestedUsage: [3], // Browser login (password fill)
    };
  }

  // 5. Long random string (low confidence — generic API key)
  if (isGenericApiKey(value)) {
    const scrubPattern = generateScrubPattern(value);
    return {
      format: "generic-api-key",
      displayName: "Long random string (likely an API key)",
      confidence: "low",
      knownToolName: null,
      suggestedInject: [], // user selects usage via menu
      suggestedScrub: { patterns: [scrubPattern] },
      needsPrompt: true,
      suggestedUsage: [1], // API calls
    };
  }

  // 6. Unknown format (low confidence)
  return {
    format: "unknown",
    displayName: "Unknown credential format",
    confidence: "low",
    knownToolName: null,
    suggestedInject: [],
    suggestedScrub: { patterns: [generateScrubPattern(value)] },
    needsPrompt: true,
    suggestedUsage: [], // no default suggestion
  };
}

// ─── Display Helpers ────────────────────────────────────────────────────────

/**
 * Format a GuessResult into a human-readable display for CLI output.
 */
export function formatGuessDisplay(guess: GuessResult, toolName: string): string {
  const lines: string[] = [];

  lines.push(`✓ Detected: ${guess.displayName}`);

  if (guess.confidence === "high" && guess.knownToolName) {
    lines.push(`  Suggested config:`);
    for (const rule of guess.suggestedInject) {
      if (rule.tool === "exec" && rule.commandMatch) {
        const envKeys = rule.env ? Object.keys(rule.env).join(", ") : "";
        lines.push(`    Type: exec-env`);
        lines.push(`    Injection: env ${envKeys}`);
        lines.push(`    Command match: ${rule.commandMatch}`);
      }
      if (rule.tool === "web_fetch" && rule.urlMatch) {
        lines.push(`    Type: http-header`);
        const headerType = rule.headers
          ? Object.entries(rule.headers).map(([k, v]) => `${k}: ${v}`).join(", ")
          : "Authorization: Bearer";
        lines.push(`    HTTP header: ${headerType}`);
        lines.push(`    URL match: ${rule.urlMatch}`);
      }
    }
    if (guess.suggestedScrub.patterns.length > 0) {
      lines.push(`    Scrub pattern: ${guess.suggestedScrub.patterns.join(", ")}`);
    }
  } else if (guess.format === "jwt") {
    lines.push(`  Suggested config:`);
    lines.push(`    Type: http-header`);
    lines.push(`    Injection: HTTP Authorization: Bearer`);
  } else if (guess.format === "json-blob") {
    lines.push(`  This looks like session cookies or an OAuth token.`);
    lines.push(`  Additional context is needed to configure injection.`);
  } else if (guess.format === "password") {
    lines.push(`  This looks like a password.`);
    lines.push(`  Additional context is needed to configure injection.`);
  } else if (guess.format === "generic-api-key") {
    lines.push(`  Suggested config:`);
    lines.push(`    Type: exec-env`);
    if (guess.suggestedInject[0]?.env) {
      const envKeys = Object.keys(guess.suggestedInject[0].env).join(", ");
      lines.push(`    Injection: env ${envKeys}`);
    }
    if (guess.suggestedInject[0]?.commandMatch) {
      lines.push(`    Command match: ${guess.suggestedInject[0].commandMatch}`);
    }
  }

  return lines.join("\n");
}

// ─── New buildToolConfig ─────────────────────────────────────────────────────

/**
 * Build a ToolConfig from a structured UsageSelection.
 * Replaces buildToolConfigFromGuess for the new interactive/non-interactive flow.
 *
 * Each usage type maps to exactly one InjectionRule — no find-and-modify logic.
 * The credential VALUE is never stored here; only $vault: placeholders.
 */
export function buildToolConfig(
  toolName: string,
  usage: UsageSelection
): { inject: InjectionRule[]; scrub: ScrubConfig } {
  const inject: InjectionRule[] = [];

  // API calls → web_fetch header injection
  if (usage.apiCalls) {
    const headerValue = usage.apiCalls.headerFormat.replace("$token", `$vault:${toolName}`);
    inject.push({
      tool: "web_fetch",
      urlMatch: usage.apiCalls.urlPattern,
      headers: { [usage.apiCalls.headerName]: headerValue },
    });
  }

  // CLI tool → exec env injection
  if (usage.cliTool) {
    inject.push({
      tool: "exec",
      commandMatch: usage.cliTool.commandMatch,
      env: { [usage.cliTool.envVar]: `$vault:${toolName}` },
    });
  }

  // Browser login → browser-password with domain pinning
  if (usage.browserLogin) {
    inject.push({
      tool: "browser",
      type: "browser-password",
      domainPin: [usage.browserLogin.domain],
      method: "fill",
    });
  }

  // Browser session → browser-cookie with domain pinning
  if (usage.browserSession) {
    inject.push({
      tool: "browser",
      type: "browser-cookie",
      domainPin: [usage.browserSession.domain],
      method: "cookie-jar",
    });
  }

  return {
    inject,
    scrub: { patterns: usage.scrubPatterns },
  };
}

/**
 * Extract domain from a URL string.
 */
function extractDomain(url: string): string {
  try {
    const u = new URL(url);
    return u.hostname;
  } catch {
    // Fallback: strip protocol and path
    return url.replace(/^https?:\/\//, "").split("/")[0];
  }
}
