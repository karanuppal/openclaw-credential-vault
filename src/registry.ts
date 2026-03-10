/**
 * Tool registry: known tools configuration and pattern matching.
 *
 * Ships with built-in knowledge of common tools (Stripe, GitHub, Gumroad).
 * Pattern matching determines which tool call gets which credential injected.
 */

import { KnownToolDef, InjectionRule } from "./types.js";

/**
 * Built-in registry of known tools with their injection and scrubbing rules.
 */
export const KNOWN_TOOLS: Record<string, KnownToolDef> = {
  gumroad: {
    inject: [
      {
        tool: "exec",
        commandMatch: "gumroad*|curl*api.gumroad.com*",
        env: { GUMROAD_ACCESS_TOKEN: "$vault:gumroad" },
      },
      {
        tool: "web_fetch",
        urlMatch: "*.gumroad.com/*",
        headers: { Authorization: "Bearer $vault:gumroad" },
      },
    ],
    scrub: {
      patterns: ["gum_[a-zA-Z0-9]{16,}"],
    },
  },
  stripe: {
    inject: [
      {
        tool: "exec",
        commandMatch: "stripe*|curl*api.stripe.com*",
        env: { STRIPE_API_KEY: "$vault:stripe" },
      },
      {
        tool: "web_fetch",
        urlMatch: "*.stripe.com/*",
        headers: { Authorization: "Bearer $vault:stripe" },
      },
    ],
    scrub: {
      patterns: [
        "sk_live_[a-zA-Z0-9]{24,}",
        "sk_test_[a-zA-Z0-9]{24,}",
        "rk_live_[a-zA-Z0-9]{24,}",
      ],
    },
  },
  github: {
    inject: [
      {
        tool: "exec",
        commandMatch: "gh *|git *|curl*api.github.com*",
        env: { GH_TOKEN: "$vault:github", GITHUB_TOKEN: "$vault:github" },
      },
    ],
    scrub: {
      patterns: [
        "ghp_[a-zA-Z0-9]{36}",
        "github_pat_[a-zA-Z0-9_]{82}",
      ],
    },
  },
  openai: {
    inject: [
      {
        tool: "exec",
        commandMatch: "curl*api.openai.com*",
        env: { OPENAI_API_KEY: "$vault:openai" },
      },
      {
        tool: "web_fetch",
        urlMatch: "*.openai.com/*",
        headers: { Authorization: "Bearer $vault:openai" },
      },
    ],
    scrub: {
      patterns: ["sk-[a-zA-Z0-9]{48}"],
    },
  },
  anthropic: {
    inject: [
      {
        tool: "exec",
        commandMatch: "curl*api.anthropic.com*",
        env: { ANTHROPIC_API_KEY: "$vault:anthropic" },
      },
      {
        tool: "web_fetch",
        urlMatch: "*.anthropic.com/*",
        headers: { "x-api-key": "$vault:anthropic" },
      },
    ],
    scrub: {
      patterns: ["sk-ant-[a-zA-Z0-9-]{80,}"],
    },
  },
};

/**
 * Convert a glob-like pattern to a regex.
 * Supports * (any chars) and | (alternation at top level).
 */
export function globToRegex(pattern: string): RegExp {
  // Split on | for alternation
  const alternatives = pattern.split("|").map((alt) => {
    // Escape regex special chars except *
    let escaped = alt.replace(/[.+?^${}()|[\]\\]/g, "\\$&");
    // Convert * to .* (glob wildcard)
    escaped = escaped.replace(/\*/g, ".*");
    return escaped;
  });
  return new RegExp(`^(?:${alternatives.join("|")})$`, "i");
}

/**
 * Check if a command string matches a commandMatch pattern.
 */
export function matchesCommand(
  command: string,
  commandMatch: string
): boolean {
  const regex = globToRegex(commandMatch);
  return regex.test(command);
}

/**
 * Check if a URL matches a urlMatch pattern.
 */
export function matchesUrl(url: string, urlMatch: string): boolean {
  const regex = globToRegex(urlMatch);
  return regex.test(url);
}

/**
 * Find matching injection rules for a tool call.
 * Returns all rules that match the given tool and parameters.
 */
export function findMatchingRules(
  toolName: string,
  params: Record<string, unknown>,
  allRules: InjectionRule[]
): InjectionRule[] {
  return allRules.filter((rule) => {
    if (rule.tool !== toolName) return false;

    if (rule.commandMatch && toolName === "exec") {
      const command = String(params.command ?? "");
      return matchesCommand(command, rule.commandMatch);
    }

    if (rule.urlMatch && toolName === "web_fetch") {
      const url = String(params.url ?? "");
      return matchesUrl(url, rule.urlMatch);
    }

    // If no specific match pattern, match all calls to this tool type
    return !rule.commandMatch && !rule.urlMatch;
  });
}

/**
 * Detect credential type from the key format.
 * Returns the tool name if recognized, null otherwise.
 */
export function detectCredentialType(
  key: string
): { toolName: string; displayName: string } | null {
  const patterns: Array<{
    regex: RegExp;
    toolName: string;
    displayName: string;
  }> = [
    { regex: /^gum_/, toolName: "gumroad", displayName: "Gumroad API key" },
    {
      regex: /^sk_live_/,
      toolName: "stripe",
      displayName: "Stripe live API key",
    },
    {
      regex: /^sk_test_/,
      toolName: "stripe",
      displayName: "Stripe test API key",
    },
    {
      regex: /^rk_live_/,
      toolName: "stripe",
      displayName: "Stripe restricted key",
    },
    {
      regex: /^ghp_/,
      toolName: "github",
      displayName: "GitHub personal access token",
    },
    {
      regex: /^github_pat_/,
      toolName: "github",
      displayName: "GitHub fine-grained PAT",
    },
    {
      regex: /^sk-[a-zA-Z0-9]{48}/,
      toolName: "openai",
      displayName: "OpenAI API key",
    },
    {
      regex: /^sk-ant-/,
      toolName: "anthropic",
      displayName: "Anthropic API key",
    },
  ];

  for (const p of patterns) {
    if (p.regex.test(key)) {
      return { toolName: p.toolName, displayName: p.displayName };
    }
  }
  return null;
}

/**
 * Get the known tool definition for a tool name, if it exists.
 */
export function getKnownTool(toolName: string): KnownToolDef | null {
  return KNOWN_TOOLS[toolName] ?? null;
}

/**
 * Generate a basic scrub pattern from a credential key.
 * Extracts the prefix pattern and creates a regex that matches similar keys.
 */
export function generateScrubPattern(key: string): string {
  // Find the prefix (non-alphanumeric boundary)
  const prefixMatch = key.match(/^([a-zA-Z_-]+)/);
  if (prefixMatch) {
    const prefix = prefixMatch[1].replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const rest = key.slice(prefixMatch[1].length);
    // Determine character class of the rest
    const hasUnderscore = rest.includes("_");
    const hasDash = rest.includes("-");
    let charClass = "[a-zA-Z0-9";
    if (hasUnderscore) charClass += "_";
    if (hasDash) charClass += "\\-";
    charClass += "]";
    const minLen = Math.max(rest.length - 4, 4);
    return `${prefix}${charClass}{${minLen},}`;
  }
  // Fallback: escape the whole key as a literal
  return key.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
