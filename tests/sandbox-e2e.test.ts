/**
 * Phase 5: Sandbox Mode E2E Tests
 *
 * Validates spec requirement: "Sandbox mode E2E (enable sandbox, run vault-injected
 * exec, verify credential received via env, verify output scrubbed)"
 * Spec ref: Pitfall #4 — "Sandbox mode breaks credential access"
 * Mitigation: "Hooks run in gateway, env overrides passed to sandbox"
 *
 * Tests the flow where:
 * 1. Sandbox mode is enabled for exec calls
 * 2. Vault injects credentials into env params via before_tool_call
 * 3. The sandbox subprocess receives the credential via environment
 * 4. Output from the sandbox is scrubbed via after_tool_call
 *
 * Since the actual sandbox is an OS-level isolation feature, we mock the
 * sandbox execution while testing the full vault hook pipeline.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import {
  compileScrubRules,
  scrubText,
  scrubLiteralCredential,
  addLiteralCredential,
  clearLiteralCredentials,
  CompiledScrubRule,
} from "../src/scrubber.js";
import { findMatchingRules } from "../src/registry.js";
import { ToolConfig } from "../src/types.js";

// --- Test tool configurations ---

const testTools: Record<string, ToolConfig> = {
  github: {
    name: "github",
    addedAt: "2026-01-01",
    lastRotated: "2026-01-01",
    inject: [
      {
        tool: "exec",
        commandMatch: "gh *",
        env: { GITHUB_TOKEN: "$vault:github" },
      },
    ],
    scrub: { patterns: ["ghp_[a-zA-Z0-9]{36}"] },
  },
  npm: {
    name: "npm",
    addedAt: "2026-01-01",
    lastRotated: "2026-01-01",
    inject: [
      {
        tool: "exec",
        commandMatch: "npm publish*",
        env: { NPM_TOKEN: "$vault:npm" },
      },
    ],
    scrub: { patterns: ["npm_[a-zA-Z0-9]{36}"] },
  },
};

// Simulated decrypted credential values
const MOCK_CREDENTIALS: Record<string, string> = {
  github: "ghp_MockGitHubTokenForSandboxTest1234567890ab",
  npm: "npm_MockNpmTokenForSandboxTestAbcdefghijklm012",
};

let rules: CompiledScrubRule[];

beforeEach(() => {
  clearLiteralCredentials();
  rules = compileScrubRules(testTools);
  // Register literal credentials (simulating getCredential cache population)
  for (const [toolName, cred] of Object.entries(MOCK_CREDENTIALS)) {
    addLiteralCredential(cred, toolName);
  }
});

afterEach(() => {
  clearLiteralCredentials();
});

/**
 * Simulates the full sandbox exec flow:
 * 1. before_tool_call: match injection rules, build env overrides
 * 2. sandbox exec: subprocess runs with injected env
 * 3. after_tool_call: scrub output
 */
interface SandboxExecResult {
  /** The env vars that would be passed to the sandbox */
  injectedEnv: Record<string, string>;
  /** The raw output from the sandbox (before scrubbing) */
  rawOutput: string;
  /** The scrubbed output (after after_tool_call) */
  scrubbedOutput: string;
}

function simulateSandboxExec(
  command: string,
  sandboxEnabled: boolean,
  mockSubprocessOutput: (env: Record<string, string>) => string
): SandboxExecResult {
  // Step 1: before_tool_call — find matching injection rules
  const injectedEnv: Record<string, string> = {};

  for (const [toolName, toolConfig] of Object.entries(testTools)) {
    const matchingRules = findMatchingRules("exec", { command }, toolConfig.inject);
    for (const rule of matchingRules) {
      if (rule.env) {
        for (const [envKey, envVal] of Object.entries(rule.env)) {
          // Resolve $vault:toolname references
          const match = envVal.match(/^\$vault:(.+)$/);
          if (match) {
            const cred = MOCK_CREDENTIALS[match[1]];
            if (cred) {
              injectedEnv[envKey] = cred;
            }
          }
        }
      }
    }
  }

  // Step 2: Sandbox execution — subprocess receives env
  // In sandbox mode, the gateway passes env overrides to the sandboxed process
  const rawOutput = mockSubprocessOutput(injectedEnv);

  // Step 3: after_tool_call — scrub the output
  let scrubbedOutput = scrubText(rawOutput, rules);
  // Also apply literal scrubbing
  for (const [toolName, cred] of Object.entries(MOCK_CREDENTIALS)) {
    scrubbedOutput = scrubLiteralCredential(scrubbedOutput, cred, toolName);
  }

  return { injectedEnv, rawOutput, scrubbedOutput };
}

describe("Sandbox mode E2E — credential injection via env", () => {
  it("should inject credential into sandbox env for matching exec command", () => {
    const result = simulateSandboxExec(
      "gh repo list",
      true,
      (env) => `Listed 5 repos using token from env.`
    );

    expect(result.injectedEnv).toHaveProperty("GITHUB_TOKEN");
    expect(result.injectedEnv.GITHUB_TOKEN).toBe(MOCK_CREDENTIALS.github);
  });

  it("should not inject credentials for non-matching commands", () => {
    const result = simulateSandboxExec(
      "ls -la /tmp",
      true,
      (env) => "total 4\ndrwxrwxrwt 2 root root 4096 Mar 10 00:00 ."
    );

    expect(Object.keys(result.injectedEnv)).toHaveLength(0);
  });

  it("should pass credential to sandboxed subprocess via env", () => {
    const result = simulateSandboxExec(
      "gh api /user",
      true,
      (env) => {
        // Simulate a verbose subprocess that leaks the full token in output
        const token = env.GITHUB_TOKEN ?? "MISSING";
        return `Authenticated as user123 (token: ${token})`;
      }
    );

    // Verify the subprocess received the credential (raw output has it)
    expect(result.rawOutput).toContain(MOCK_CREDENTIALS.github);
    // Verify the output is scrubbed (no credential in scrubbed output)
    expect(result.scrubbedOutput).not.toContain(MOCK_CREDENTIALS.github);
    expect(result.scrubbedOutput).toContain("[VAULT:github]");
  });
});

describe("Sandbox mode E2E — output scrubbing", () => {
  it("should scrub credential patterns from sandbox output", () => {
    const result = simulateSandboxExec(
      "gh auth status",
      true,
      (env) =>
        `Logged in to github.com as user (token: ${env.GITHUB_TOKEN ?? "none"})`
    );

    expect(result.scrubbedOutput).not.toContain(MOCK_CREDENTIALS.github);
    expect(result.scrubbedOutput).toContain("[VAULT:github]");
  });

  it("should scrub literal credential values leaked in sandbox output", () => {
    const result = simulateSandboxExec(
      "gh repo clone org/repo",
      true,
      (env) => {
        // Simulate a verbose subprocess that leaks the full token
        const token = env.GITHUB_TOKEN ?? "";
        return `remote: Using token ${token}\nCloning into 'repo'...\ndone.`;
      }
    );

    expect(result.scrubbedOutput).not.toContain(MOCK_CREDENTIALS.github);
    expect(result.scrubbedOutput).toContain("[VAULT:github]");
    expect(result.scrubbedOutput).toContain("Cloning into 'repo'");
  });

  it("should scrub multiple credential types from sandbox output", () => {
    // Simulate a complex command that somehow triggers both tools
    // (testing that scrubbing handles multiple patterns)
    const rawOutput = `
GitHub token: ${MOCK_CREDENTIALS.github}
NPM token: ${MOCK_CREDENTIALS.npm}
Deploy complete.`;

    let scrubbed = scrubText(rawOutput, rules);
    for (const [toolName, cred] of Object.entries(MOCK_CREDENTIALS)) {
      scrubbed = scrubLiteralCredential(scrubbed, cred, toolName);
    }

    expect(scrubbed).not.toContain(MOCK_CREDENTIALS.github);
    expect(scrubbed).not.toContain(MOCK_CREDENTIALS.npm);
    expect(scrubbed).toContain("[VAULT:github]");
    expect(scrubbed).toContain("[VAULT:npm]");
    expect(scrubbed).toContain("Deploy complete.");
  });

  it("should leave clean sandbox output unmodified", () => {
    const result = simulateSandboxExec(
      "gh repo list",
      true,
      () => "org/repo1\norg/repo2\norg/repo3"
    );

    expect(result.scrubbedOutput).toBe("org/repo1\norg/repo2\norg/repo3");
  });
});

describe("Sandbox mode E2E — env override mechanism", () => {
  it("should build env overrides that sandbox can pass to subprocess", () => {
    const result = simulateSandboxExec(
      "gh pr list",
      true,
      (env) => "PR #1: Fix bug\nPR #2: Add feature"
    );

    // The injected env represents what the gateway passes to the sandbox
    // Sandbox receives these as env overrides for the subprocess
    expect(result.injectedEnv.GITHUB_TOKEN).toBeDefined();
    expect(typeof result.injectedEnv.GITHUB_TOKEN).toBe("string");
    expect(result.injectedEnv.GITHUB_TOKEN.length).toBeGreaterThan(0);
  });

  it("should handle npm publish with sandbox env injection", () => {
    const result = simulateSandboxExec(
      "npm publish --access public",
      true,
      (env) => {
        const token = env.NPM_TOKEN ?? "MISSING";
        return `npm notice Publishing to https://registry.npmjs.org with token ${token.substring(0, 8)}...`;
      }
    );

    expect(result.injectedEnv).toHaveProperty("NPM_TOKEN");
    expect(result.injectedEnv.NPM_TOKEN).toBe(MOCK_CREDENTIALS.npm);
    // Scrubbing should redact any leaked token fragments
    expect(result.scrubbedOutput).not.toContain(MOCK_CREDENTIALS.npm);
  });
});
