/**
 * Phase 5: Environment Variable Scrubbing Tests
 *
 * Validates spec section "Env Dump Detection" (reinstated in v4.5.4):
 * - Lightweight env-variable-name pattern matching in the scrubber
 * - Matches KEY=, TOKEN=, SECRET=, PASSWORD= in tool output
 * - Redacts the values (not the variable names)
 * - Covers pre-vault env vars and forgotten credentials
 *
 * Spec ref: "The scrubber matches variable names containing KEY=, TOKEN=,
 * SECRET=, PASSWORD= in tool output and redacts the values."
 */

import { describe, it, expect } from "vitest";

// --- Mock env scrubbing (NOT BUILT yet) ---
// TODO: Replace with actual import from src/scrubber.ts once env scrubbing patterns
// are added to the existing scrubbing pipeline.

/**
 * Simulates env-variable-name pattern matching.
 * Matches: any_KEY=value, any_TOKEN=value, any_SECRET=value, any_PASSWORD=value
 * Redacts the value portion, preserving the variable name.
 */
function scrubEnvVariables(text: string): string {
  // Match lines like VAR_NAME=value where VAR_NAME contains KEY, TOKEN, SECRET, or PASSWORD
  // Pattern: word chars containing the trigger word, followed by =, then value until newline or end
  const patterns = [
    /(\b\w*KEY\w*=)([^\s\n]+)/gi,
    /(\b\w*TOKEN\w*=)([^\s\n]+)/gi,
    /(\b\w*SECRET\w*=)([^\s\n]+)/gi,
    /(\b\w*PASSWORD\w*=)([^\s\n]+)/gi,
  ];

  let result = text;
  for (const pattern of patterns) {
    result = result.replace(pattern, "$1[REDACTED]");
  }
  return result;
}

describe("Env Scrubbing — KEY= pattern", () => {
  it("should redact STRIPE_API_KEY=value", () => {
    const input = "STRIPE_API_KEY=sk_live_abc123def456";
    const result = scrubEnvVariables(input);
    expect(result).toBe("STRIPE_API_KEY=[REDACTED]");
  });

  it("should redact API_KEY=value", () => {
    const input = "API_KEY=some_secret_value";
    const result = scrubEnvVariables(input);
    expect(result).toBe("API_KEY=[REDACTED]");
  });

  it("should redact OPENAI_API_KEY=value", () => {
    const input = "OPENAI_API_KEY=sk-proj-abc123";
    const result = scrubEnvVariables(input);
    expect(result).toBe("OPENAI_API_KEY=[REDACTED]");
  });

  it("should redact SSH_KEY=value", () => {
    const input = "SSH_KEY=/home/user/.ssh/id_rsa";
    const result = scrubEnvVariables(input);
    expect(result).toBe("SSH_KEY=[REDACTED]");
  });
});

describe("Env Scrubbing — TOKEN= pattern", () => {
  it("should redact GH_TOKEN=value", () => {
    const input = "GH_TOKEN=ghp_abcdefghijklmnop";
    const result = scrubEnvVariables(input);
    expect(result).toBe("GH_TOKEN=[REDACTED]");
  });

  it("should redact GITHUB_TOKEN=value", () => {
    const input = "GITHUB_TOKEN=ghp_xyz123";
    const result = scrubEnvVariables(input);
    expect(result).toBe("GITHUB_TOKEN=[REDACTED]");
  });

  it("should redact SLACK_TOKEN=value", () => {
    const input = "SLACK_TOKEN=xoxb-123-456-abc";
    const result = scrubEnvVariables(input);
    expect(result).toBe("SLACK_TOKEN=[REDACTED]");
  });

  it("should redact BOT_TOKEN=value", () => {
    const input = "BOT_TOKEN=1234567890:ABCdefGHIjklMNOpqrSTUvwxYZ";
    const result = scrubEnvVariables(input);
    expect(result).toBe("BOT_TOKEN=[REDACTED]");
  });
});

describe("Env Scrubbing — SECRET= pattern", () => {
  it("should redact AWS_SECRET_ACCESS_KEY=value", () => {
    const input = "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYzEXAMPLEKEY";
    const result = scrubEnvVariables(input);
    expect(result).toBe("AWS_SECRET_ACCESS_KEY=[REDACTED]");
  });

  it("should redact CLIENT_SECRET=value", () => {
    const input = "CLIENT_SECRET=my_oauth_client_secret";
    const result = scrubEnvVariables(input);
    expect(result).toBe("CLIENT_SECRET=[REDACTED]");
  });

  it("should redact APP_SECRET=value", () => {
    const input = "APP_SECRET=hex1234abcdef";
    const result = scrubEnvVariables(input);
    expect(result).toBe("APP_SECRET=[REDACTED]");
  });
});

describe("Env Scrubbing — PASSWORD= pattern", () => {
  it("should redact DATABASE_PASSWORD=value", () => {
    const input = "DATABASE_PASSWORD=super_secret_db_pass";
    const result = scrubEnvVariables(input);
    expect(result).toBe("DATABASE_PASSWORD=[REDACTED]");
  });

  it("should redact REDIS_PASSWORD=value", () => {
    const input = "REDIS_PASSWORD=r3d1s_p@ss";
    const result = scrubEnvVariables(input);
    expect(result).toBe("REDIS_PASSWORD=[REDACTED]");
  });

  it("should redact DB_PASSWORD=value", () => {
    const input = "DB_PASSWORD=postgres123";
    const result = scrubEnvVariables(input);
    expect(result).toBe("DB_PASSWORD=[REDACTED]");
  });
});

describe("Env Scrubbing — multi-line env dump", () => {
  it("should redact multiple env vars in env output", () => {
    const input = [
      "HOME=/home/user",
      "PATH=/usr/bin:/usr/local/bin",
      "GH_TOKEN=ghp_secret_token_value",
      "NODE_ENV=production",
      "STRIPE_API_KEY=sk_live_secret123",
      "DATABASE_PASSWORD=mydbpass",
      "LANG=en_US.UTF-8",
    ].join("\n");

    const result = scrubEnvVariables(input);

    // Non-sensitive vars should be untouched
    expect(result).toContain("HOME=/home/user");
    expect(result).toContain("PATH=/usr/bin:/usr/local/bin");
    expect(result).toContain("NODE_ENV=production");
    expect(result).toContain("LANG=en_US.UTF-8");

    // Sensitive vars should be redacted
    expect(result).toContain("GH_TOKEN=[REDACTED]");
    expect(result).toContain("STRIPE_API_KEY=[REDACTED]");
    expect(result).toContain("DATABASE_PASSWORD=[REDACTED]");

    // Raw values should NOT appear
    expect(result).not.toContain("ghp_secret_token_value");
    expect(result).not.toContain("sk_live_secret123");
    expect(result).not.toContain("mydbpass");
  });
});

describe("Env Scrubbing — should NOT redact non-sensitive vars", () => {
  const safeVars = [
    "HOME=/home/user",
    "PATH=/usr/bin:/usr/local/bin",
    "NODE_ENV=production",
    "LANG=en_US.UTF-8",
    "SHELL=/bin/bash",
    "USER=karanuppal",
    "PWD=/tmp/vault-tests",
    "EDITOR=vim",
    "TERM=xterm-256color",
  ];

  for (const v of safeVars) {
    it(`should not redact: ${v}`, () => {
      const result = scrubEnvVariables(v);
      expect(result).toBe(v);
    });
  }
});

describe("Env Scrubbing — case insensitivity", () => {
  it("should handle lowercase key=value", () => {
    const input = "api_key=secret_val";
    const result = scrubEnvVariables(input);
    expect(result).toBe("api_key=[REDACTED]");
  });

  it("should handle mixed case Token=value", () => {
    const input = "Auth_Token=bearer_xyz";
    const result = scrubEnvVariables(input);
    expect(result).toBe("Auth_Token=[REDACTED]");
  });
});
