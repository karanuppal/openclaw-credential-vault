/**
 * Output scrubbing: replaces credential patterns in text with [VAULT:toolname].
 *
 * Scrubbing pipeline (per spec):
 * 1. Regex pattern matching (catches any credential of a given FORMAT)
 * 2. Hash-based literal matching (catches THIS SPECIFIC credential regardless of format)
 * 3. Env-variable-name matching (catches KEY=, TOKEN=, SECRET=, PASSWORD= values)
 */

import * as crypto from "node:crypto";
import { ToolConfig } from "./types.js";

/** A compiled scrubbing rule ready for fast matching */
export interface CompiledScrubRule {
  toolName: string;
  regex: RegExp;
  replacement: string;
}

/**
 * Global scrubbing patterns — not tied to any specific tool.
 * These catch common credential formats regardless of vault registration.
 */
export const GLOBAL_SCRUB_PATTERNS: Array<{ name: string; pattern: string }> = [
  // Telegram bot token: \b\d{10}:[A-Za-z0-9_-]{35}\b
  { name: "telegram-bot-token", pattern: "\\b\\d{10}:[A-Za-z0-9_-]{35}\\b" },
  // Slack bot token: xoxb-[A-Za-z0-9-]+
  { name: "slack-bot-token", pattern: "xoxb-[A-Za-z0-9-]+" },
];

/**
 * Env variable name patterns — variable names that suggest the value is a secret.
 * Matches lines like KEY=value, TOKEN=value, etc. and redacts the value.
 */
const ENV_VAR_PATTERN = /\b([A-Z_]*(?:KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|API_KEY|APIKEY)[A-Z_]*)=([^\s\n]+)/gi;

/**
 * In-memory set of literal credential values for hash-based scrubbing.
 * Populated when credentials are decrypted for injection.
 */
const literalCredentials: Map<string, string> = new Map(); // credential value -> tool name

/**
 * On-disk hashes: SHA-256 hash -> tool name.
 * Used to persist which credentials we're tracking without storing plaintext.
 */
const credentialHashes: Map<string, string> = new Map(); // SHA-256 hex -> tool name

/**
 * Add a decrypted credential to the in-memory literal match set.
 * Called after decrypting a credential for injection.
 */
export function addLiteralCredential(credential: string, toolName: string): void {
  if (!credential || credential.length < 4) return;
  literalCredentials.set(credential, toolName);
  // Also store hash
  const hash = crypto.createHash("sha256").update(credential).digest("hex");
  credentialHashes.set(hash, toolName);
}

/**
 * Remove a literal credential from the in-memory set.
 */
export function removeLiteralCredential(credential: string): void {
  literalCredentials.delete(credential);
  const hash = crypto.createHash("sha256").update(credential).digest("hex");
  credentialHashes.delete(hash);
}

/**
 * Get the SHA-256 hash of a credential value.
 */
export function hashCredential(credential: string): string {
  return crypto.createHash("sha256").update(credential).digest("hex");
}

/**
 * Get all tracked credential hashes (for on-disk persistence).
 */
export function getCredentialHashes(): Map<string, string> {
  return new Map(credentialHashes);
}

/**
 * Get the current literal credentials map (for testing).
 */
export function getLiteralCredentials(): Map<string, string> {
  return new Map(literalCredentials);
}

/**
 * Clear all literal credentials (for testing).
 */
export function clearLiteralCredentials(): void {
  literalCredentials.clear();
  credentialHashes.clear();
}

/**
 * Compile scrubbing patterns from tool configs into ready-to-use regexes.
 */
export function compileScrubRules(
  tools: Record<string, ToolConfig>
): CompiledScrubRule[] {
  const rules: CompiledScrubRule[] = [];

  // Tool-specific patterns
  for (const [name, tool] of Object.entries(tools)) {
    for (const pattern of tool.scrub.patterns) {
      try {
        rules.push({
          toolName: name,
          regex: new RegExp(pattern, "g"),
          replacement: `[VAULT:${name}]`,
        });
      } catch {
        // Skip invalid patterns silently
      }
    }
  }

  // Global patterns (not tied to a specific tool)
  for (const gp of GLOBAL_SCRUB_PATTERNS) {
    try {
      rules.push({
        toolName: gp.name,
        regex: new RegExp(gp.pattern, "g"),
        replacement: `[VAULT:${gp.name}]`,
      });
    } catch {
      // Skip invalid patterns
    }
  }

  return rules;
}

/**
 * Track scrub replacements: returns {scrubbed text, list of (toolName, pattern, count)}.
 */
export interface ScrubResult {
  text: string;
  replacements: Array<{ toolName: string; pattern: string; count: number }>;
}

/**
 * Scrub all credential patterns from a string, tracking replacements.
 */
export function scrubTextWithTracking(
  text: string,
  rules: CompiledScrubRule[]
): ScrubResult {
  let result = text;
  const replacements: ScrubResult["replacements"] = [];

  // 1. Regex pattern matching
  for (const rule of rules) {
    rule.regex.lastIndex = 0;
    const before = result;
    result = result.replace(rule.regex, rule.replacement);
    if (result !== before) {
      // Count replacements
      rule.regex.lastIndex = 0;
      const matches = before.match(rule.regex);
      replacements.push({
        toolName: rule.toolName,
        pattern: rule.regex.source,
        count: matches?.length ?? 1,
      });
    }
  }

  // 2. Literal credential matching (indexOf-based)
  for (const [credential, toolName] of literalCredentials.entries()) {
    let idx = result.indexOf(credential);
    let count = 0;
    while (idx !== -1) {
      result = result.substring(0, idx) + `[VAULT:${toolName}]` + result.substring(idx + credential.length);
      count++;
      idx = result.indexOf(credential, idx + `[VAULT:${toolName}]`.length);
    }
    if (count > 0) {
      replacements.push({
        toolName,
        pattern: "literal",
        count,
      });
    }
  }

  // 3. Env-variable-name matching — only redact values that weren't already scrubbed
  const envBefore = result;
  result = scrubEnvVarsSelective(result);
  if (result !== envBefore) {
    replacements.push({
      toolName: "env-var",
      pattern: "env-variable-name",
      count: 1,
    });
  }

  return { text: result, replacements };
}

/**
 * Scrub all credential patterns from a string.
 * Returns the scrubbed string.
 */
export function scrubText(
  text: string,
  rules: CompiledScrubRule[]
): string {
  return scrubTextWithTracking(text, rules).text;
}

/**
 * Scrub env variable values that look like secrets.
 * Matches KEY=value, TOKEN=value, SECRET=value, PASSWORD=value patterns.
 */
export function scrubEnvVars(text: string): string {
  return text.replace(ENV_VAR_PATTERN, (match, varName) => {
    return `${varName}=[VAULT:env-redacted]`;
  });
}

/**
 * Selective env var scrubbing: only redact values that haven't already been
 * scrubbed by regex/literal passes (i.e., skip values that contain [VAULT:]).
 */
function scrubEnvVarsSelective(text: string): string {
  return text.replace(ENV_VAR_PATTERN, (match, varName, value) => {
    // If the value was already scrubbed by regex/literal pass, don't re-scrub
    if (value.includes("[VAULT:")) return match;
    return `${varName}=[VAULT:env-redacted]`;
  });
}

/**
 * Scrub credential patterns from an object recursively.
 * Handles strings, arrays, and nested objects.
 */
export function scrubObject(
  obj: unknown,
  rules: CompiledScrubRule[]
): unknown {
  if (typeof obj === "string") {
    return scrubText(obj, rules);
  }
  if (Array.isArray(obj)) {
    return obj.map((item) => scrubObject(item, rules));
  }
  if (obj !== null && typeof obj === "object") {
    const result: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(obj as Record<string, unknown>)) {
      result[key] = scrubObject(value, rules);
    }
    return result;
  }
  return obj;
}

/**
 * Check if a string contains any credential patterns.
 */
export function containsCredentials(
  text: string,
  rules: CompiledScrubRule[]
): boolean {
  // Check regex rules
  for (const rule of rules) {
    rule.regex.lastIndex = 0;
    if (rule.regex.test(text)) {
      return true;
    }
  }

  // Check literal credentials
  for (const credential of literalCredentials.keys()) {
    if (text.indexOf(credential) !== -1) {
      return true;
    }
  }

  // Check env var patterns
  const envPatternCopy = new RegExp(ENV_VAR_PATTERN.source, ENV_VAR_PATTERN.flags);
  if (envPatternCopy.test(text)) {
    return true;
  }

  return false;
}

/**
 * Also scrub the raw credential value itself (exact match).
 * This catches cases where the credential doesn't match known patterns
 * but is still the literal stored value.
 */
export function scrubLiteralCredential(
  text: string,
  credential: string,
  toolName: string
): string {
  if (!credential || credential.length < 4) return text;
  // Use indexOf for fast literal matching
  let result = text;
  let idx = result.indexOf(credential);
  while (idx !== -1) {
    result = result.substring(0, idx) + `[VAULT:${toolName}]` + result.substring(idx + credential.length);
    idx = result.indexOf(credential, idx + `[VAULT:${toolName}]`.length);
  }
  return result;
}
