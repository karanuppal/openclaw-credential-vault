/**
 * Output scrubbing: replaces credential patterns in text with [VAULT:toolname].
 */

import { ToolConfig } from "./types.js";

/** A compiled scrubbing rule ready for fast matching */
export interface CompiledScrubRule {
  toolName: string;
  regex: RegExp;
  replacement: string;
}

/**
 * Compile scrubbing patterns from tool configs into ready-to-use regexes.
 */
export function compileScrubRules(
  tools: Record<string, ToolConfig>
): CompiledScrubRule[] {
  const rules: CompiledScrubRule[] = [];
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
  return rules;
}

/**
 * Scrub all credential patterns from a string.
 * Returns the scrubbed string.
 */
export function scrubText(
  text: string,
  rules: CompiledScrubRule[]
): string {
  let result = text;
  for (const rule of rules) {
    // Reset lastIndex for global regexes
    rule.regex.lastIndex = 0;
    result = result.replace(rule.regex, rule.replacement);
  }
  return result;
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
  for (const rule of rules) {
    rule.regex.lastIndex = 0;
    if (rule.regex.test(text)) {
      return true;
    }
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
  // Escape for regex
  const escaped = credential.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  return text.replace(new RegExp(escaped, "g"), `[VAULT:${toolName}]`);
}
