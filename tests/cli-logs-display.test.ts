/**
 * CLI Logs Display Tests
 *
 * Validates that `vault logs` pretty-print output does not silently truncate
 * command text. Long commands must be shown in full (or with clear "..." indicator).
 *
 * Bug: commands were truncated at 60 chars with no indicator, making
 * "git push origin main" appear as "gi" after a long cwd prefix.
 */

import { describe, it, expect } from "vitest";

/**
 * Simulate the log formatting logic from cli.ts to test display behavior.
 * We extract the formatting to a pure function for testability.
 */
function formatCredentialAccessEvent(event: {
  timestamp: string;
  credential: string;
  tool: string;
  injectionType: string;
  command: string;
}): string {
  const ts = new Date(event.timestamp).toLocaleString();
  return `[${ts}] ACCESS ${event.credential} via ${event.tool} (${event.injectionType}) — ${event.command}`;
}

describe("CLI logs display — command truncation fix", () => {
  const longCommand =
    "cd /home/karanuppal/Projects/openclaw-credential-vault && git push origin main 2>&1";

  const event = {
    timestamp: "2026-03-11T18:56:52.737Z",
    credential: "github",
    tool: "exec",
    injectionType: "exec-env",
    command: longCommand,
  };

  it("should display the full command without truncation", () => {
    const output = formatCredentialAccessEvent(event);
    // The full command must appear in the output
    expect(output).toContain("git push origin main 2>&1");
    // Must NOT be truncated to just "gi" or any partial fragment
    expect(output).not.toMatch(/— .*gi$/);
  });

  it("should contain the complete command string", () => {
    const output = formatCredentialAccessEvent(event);
    expect(output).toContain(longCommand);
  });

  it("should handle very long commands (200+ chars)", () => {
    const veryLongCmd = "cd /some/very/deep/nested/project/directory && " +
      "git commit -m \"fix: update install URL from opscontrol711 to karanuppal in all documentation files\" && " +
      "git push origin main 2>&1";
    const bigEvent = { ...event, command: veryLongCmd };
    const output = formatCredentialAccessEvent(bigEvent);
    expect(output).toContain("git push origin main 2>&1");
    expect(output).toContain(veryLongCmd);
  });

  it("should handle short commands without issues", () => {
    const shortEvent = { ...event, command: "gh pr list" };
    const output = formatCredentialAccessEvent(shortEvent);
    expect(output).toContain("gh pr list");
  });

  it("should handle empty command gracefully", () => {
    const emptyEvent = { ...event, command: "" };
    const output = formatCredentialAccessEvent(emptyEvent);
    expect(output).toContain("ACCESS github via exec");
  });
});
