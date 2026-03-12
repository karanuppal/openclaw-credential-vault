import { describe, it, expect } from "vitest";
import { execSync } from "child_process";

/**
 * Tests for the Perl stdout scrubber that pipes subprocess output
 * through credential replacement before exec captures it.
 *
 * These are unit-level tests that simulate the exact command transformation
 * our before_tool_call hook performs, without needing the full gateway.
 */

const SECRET = "ghp_TESTSECRET1234567890abcdefghijklmn";
const REPLACEMENT = "[VAULT:github]";
const B64 = Buffer.from(SECRET).toString("base64");

// Build the perl script the same way production code does
const perlBegin = `use MIME::Base64; $s0=decode_base64("${B64}"); $r0="${REPLACEMENT}";`;
const perlSubs = `s/\\Q$s0\\E/$r0/g`;
const perlScript = `BEGIN { ${perlBegin} } ${perlSubs}`;

function wrapCommand(cmd: string): string {
  return `set -o pipefail; { ${cmd} ; } 2>&1 | perl -pe '${perlScript}'`;
}

function run(cmd: string, env?: Record<string, string>): { stdout: string; exitCode: number } {
  const mergedEnv = { ...process.env, ...(env ?? {}) };
  try {
    const stdout = execSync(cmd, {
      encoding: "utf-8",
      shell: "/bin/bash",
      env: mergedEnv,
      timeout: 5000,
    }).trim();
    return { stdout, exitCode: 0 };
  } catch (e: any) {
    return {
      stdout: (e.stdout ?? e.stderr ?? e.message ?? "").trim(),
      exitCode: e.status ?? 1,
    };
  }
}

describe("Perl stdout scrubber", () => {
  describe("basic scrubbing", () => {
    it("should scrub credential from echo output", () => {
      const env = { GH_TOKEN: SECRET };
      const result = run(wrapCommand(`echo $GH_TOKEN`), env);
      expect(result.stdout).toBe(REPLACEMENT);
      expect(result.stdout).not.toContain(SECRET);
    });

    it("should scrub credential from printenv", () => {
      const env = { GH_TOKEN: SECRET };
      const result = run(wrapCommand(`printenv GH_TOKEN`), env);
      expect(result.stdout).toBe(REPLACEMENT);
      expect(result.stdout).not.toContain(SECRET);
    });

    it("should scrub multiple occurrences on same line", () => {
      const env = { GH_TOKEN: SECRET };
      const result = run(wrapCommand(`echo "$GH_TOKEN and $GH_TOKEN"`), env);
      expect(result.stdout).toBe(`${REPLACEMENT} and ${REPLACEMENT}`);
      expect(result.stdout).not.toContain(SECRET);
    });

    it("should scrub credential in multi-line output", () => {
      const env = { GH_TOKEN: SECRET };
      const result = run(wrapCommand(`echo "line1"; echo $GH_TOKEN; echo "line3"`), env);
      expect(result.stdout).toContain("line1");
      expect(result.stdout).toContain(REPLACEMENT);
      expect(result.stdout).toContain("line3");
      expect(result.stdout).not.toContain(SECRET);
    });

    it("should pass through output without credentials unchanged", () => {
      const result = run(wrapCommand(`echo "hello world"`));
      expect(result.stdout).toBe("hello world");
    });
  });

  describe("exfiltration scenarios", () => {
    it("should scrub jq env access (simulated)", () => {
      const env = { GH_TOKEN: SECRET };
      // Simulate: jq reads env var and outputs it
      const result = run(wrapCommand(`echo '{"user":"test"}' | GH_TOKEN=[VAULT:env-redacted] jq -r --arg t "$GH_TOKEN" '$t'`), env);
      expect(result.stdout).not.toContain(SECRET);
    });

    it("should scrub stderr output containing credential", () => {
      const env = { GH_TOKEN: SECRET };
      const result = run(wrapCommand(`echo $GH_TOKEN >&2`), env);
      // 2>&1 captures stderr, perl scrubs it
      expect(result.stdout).not.toContain(SECRET);
    });

    it("should scrub semicolon-separated commands", () => {
      const env = { GH_TOKEN: SECRET };
      const result = run(wrapCommand(`echo "safe"; echo $GH_TOKEN`), env);
      expect(result.stdout).toContain("safe");
      expect(result.stdout).not.toContain(SECRET);
    });
  });

  describe("exit code preservation", () => {
    it("should preserve exit code 0 on success", () => {
      const result = run(wrapCommand(`echo "ok"`));
      expect(result.exitCode).toBe(0);
    });

    it("should preserve non-zero exit code on failure", () => {
      const result = run(wrapCommand(`false`));
      expect(result.exitCode).not.toBe(0);
    });

    it("should preserve exit code from command, not perl", () => {
      const result = run(wrapCommand(`exit 42`));
      expect(result.exitCode).toBe(42);
    });
  });

  describe("security edge cases", () => {
    it("should NOT prevent file redirect bypass (known limitation)", () => {
      const env = { GH_TOKEN: SECRET };
      const tmpFile = "/tmp/vault-test-redirect-" + Date.now();
      run(wrapCommand(`echo $GH_TOKEN > ${tmpFile}`), env);
      const fileContent = run(`cat ${tmpFile}`);
      // Known limitation: redirect bypasses the pipe
      expect(fileContent.stdout).toContain(SECRET);
      run(`rm -f ${tmpFile}`);
    });

    it("should handle empty output", () => {
      const result = run(wrapCommand(`true`));
      expect(result.stdout).toBe("");
      expect(result.exitCode).toBe(0);
    });

    it("should handle large output without timeout", () => {
      const result = run(wrapCommand(`seq 1 10000`));
      const lines = result.stdout.split("\n");
      expect(lines.length).toBe(10000);
      expect(result.exitCode).toBe(0);
    });

    it("should handle credentials with special characters via base64", () => {
      const specialSecret = "sk_live_abc$def'ghi\"jkl\\mno|pqr";
      const specialB64 = Buffer.from(specialSecret).toString("base64");
      const specialReplacement = "[VAULT:special]";
      const specialPerlBegin = `use MIME::Base64; $s0=decode_base64("${specialB64}"); $r0="${specialReplacement}";`;
      const specialPerlSubs = `s/\\Q$s0\\E/$r0/g`;
      const specialPerlScript = `BEGIN { ${specialPerlBegin} } ${specialPerlSubs}`;
      const cmd = `set -o pipefail; { echo '${specialSecret.replace(/'/g, "'\\''")}' ; } 2>&1 | perl -pe '${specialPerlScript}'`;
      const result = run(cmd);
      expect(result.stdout).toBe(specialReplacement);
      expect(result.stdout).not.toContain(specialSecret);
    });
  });

  describe("command wrapping", () => {
    it("should wrap simple command correctly", () => {
      const wrapped = wrapCommand("gh api user --jq .login");
      expect(wrapped).toContain("set -o pipefail");
      expect(wrapped).toContain("{ gh api user --jq .login ; }");
      expect(wrapped).toContain("perl -pe");
      expect(wrapped).toContain("MIME::Base64");
    });

    it("should not contain raw credential in wrapped command", () => {
      const wrapped = wrapCommand("gh api user");
      expect(wrapped).not.toContain(SECRET);
      expect(wrapped).toContain(B64); // base64-encoded only
    });
  });
});
