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

// Multi-credential test values
const SECRET2 = "GOCSPX--vuTESTSECRET9876543210xyz";
const REPLACEMENT2 = "[VAULT:gws-client-secret]";
const B64_2 = Buffer.from(SECRET2).toString("base64");

const SECRET3 = "[VAULT:slack-bot-token]";
const REPLACEMENT3 = "[VAULT:slack-bot]";
const B64_3 = Buffer.from(SECRET3).toString("base64");

// Build perl script for N credentials — mirrors production code exactly
function buildPerlScript(creds: Array<{secret: string; replacement: string}>): string {
  const pairs = creds.map((c, i) => {
    const b64 = Buffer.from(c.secret).toString("base64");
    return { b64, replacement: c.replacement, index: i };
  });
  const perlBegin = pairs
    .map(p => `use MIME::Base64; $s${p.index}=decode_base64("${p.b64}"); $r${p.index}="${p.replacement}";`)
    .join(" ");
  const perlSubs = pairs
    .map(p => `s/\\Q$s${p.index}\\E/$r${p.index}/g`)
    .join("; ");
  return `BEGIN { ${perlBegin} } ${perlSubs}`;
}

// Single-credential script (used by most tests)
const perlScript = buildPerlScript([{ secret: SECRET, replacement: REPLACEMENT }]);

// Multi-credential script
const multiPerlScript = buildPerlScript([
  { secret: SECRET, replacement: REPLACEMENT },
  { secret: SECRET2, replacement: REPLACEMENT2 },
  { secret: SECRET3, replacement: REPLACEMENT3 },
]);

function wrapCommand(cmd: string, script?: string): string {
  return `set -o pipefail; { ${cmd} ; } 2>&1 | perl -pe '${script ?? perlScript}'`;
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

  describe("multi-credential scrubbing", () => {
    it("should scrub 2 different credentials on the same line", () => {
      const env = { GH_TOKEN: SECRET, GWS_SECRET: SECRET2 };
      const result = run(
        wrapCommand(`echo "$GH_TOKEN $GWS_SECRET"`, multiPerlScript),
        env
      );
      expect(result.stdout).toBe(`${REPLACEMENT} ${REPLACEMENT2}`);
      expect(result.stdout).not.toContain(SECRET);
      expect(result.stdout).not.toContain(SECRET2);
    });

    it("should scrub 3 different credentials across multiple lines", () => {
      const env = { CRED1: SECRET, CRED2: SECRET2, CRED3: SECRET3 };
      const result = run(
        wrapCommand(`echo "$CRED1"; echo "$CRED2"; echo "$CRED3"`, multiPerlScript),
        env
      );
      expect(result.stdout).toContain(REPLACEMENT);
      expect(result.stdout).toContain(REPLACEMENT2);
      expect(result.stdout).toContain(REPLACEMENT3);
      expect(result.stdout).not.toContain(SECRET);
      expect(result.stdout).not.toContain(SECRET2);
      expect(result.stdout).not.toContain(SECRET3);
    });

    it("should scrub only the matching credential and leave others untouched", () => {
      const env = { GH_TOKEN: SECRET };
      const result = run(
        wrapCommand(`echo "$GH_TOKEN and some_other_text"`, multiPerlScript),
        env
      );
      expect(result.stdout).toBe(`${REPLACEMENT} and some_other_text`);
      expect(result.stdout).not.toContain(SECRET);
    });

    it("should scrub repeated occurrences of different credentials", () => {
      const env = { CRED1: SECRET, CRED2: SECRET2 };
      const result = run(
        wrapCommand(`echo "$CRED1 $CRED2 $CRED1 $CRED2"`, multiPerlScript),
        env
      );
      expect(result.stdout).toBe(`${REPLACEMENT} ${REPLACEMENT2} ${REPLACEMENT} ${REPLACEMENT2}`);
    });

    it("should handle multi-credential with one containing special chars", () => {
      const specialSecret = "sk_live_abc$def'ghi";
      const creds = [
        { secret: SECRET, replacement: REPLACEMENT },
        { secret: specialSecret, replacement: "[VAULT:stripe]" },
      ];
      const script = buildPerlScript(creds);
      const env = { GH_TOKEN: SECRET, STRIPE_KEY: specialSecret };
      const result = run(
        wrapCommand(`echo "$GH_TOKEN"; echo '${specialSecret.replace(/'/g, "'\\''")}'`, script),
        env
      );
      expect(result.stdout).not.toContain(SECRET);
      expect(result.stdout).not.toContain(specialSecret);
      expect(result.stdout).toContain(REPLACEMENT);
      expect(result.stdout).toContain("[VAULT:stripe]");
    });

    it("should not contain any raw credentials in the wrapped command string", () => {
      const wrapped = wrapCommand("some command", multiPerlScript);
      expect(wrapped).not.toContain(SECRET);
      expect(wrapped).not.toContain(SECRET2);
      expect(wrapped).not.toContain(SECRET3);
      // Should contain base64 versions
      expect(wrapped).toContain(B64);
      expect(wrapped).toContain(B64_2);
      expect(wrapped).toContain(B64_3);
    });

    it("should preserve exit code with multi-credential scrubbing", () => {
      const result = run(wrapCommand(`exit 7`, multiPerlScript));
      expect(result.exitCode).toBe(7);
    });

    it("should handle empty output with multi-credential script", () => {
      const result = run(wrapCommand(`true`, multiPerlScript));
      expect(result.stdout).toBe("");
      expect(result.exitCode).toBe(0);
    });
  });

  describe("system compatibility", () => {
    it("should verify perl is available", () => {
      const result = run("perl -v | head -2");
      expect(result.exitCode).toBe(0);
      expect(result.stdout.toLowerCase()).toContain("perl");
    });

    it("should verify MIME::Base64 module is available", () => {
      const result = run("perl -e 'use MIME::Base64; print \"ok\"'");
      expect(result.stdout).toBe("ok");
    });
  });

  describe("PTY mode behavior", () => {
    // PTY mode (pty:true) allocates a pseudo-terminal. The concern is that
    // our pipe-based scrubber may not work when the subprocess has a PTY,
    // since PTY output handling differs from plain pipe stdout.

    it("should scrub credential when command runs inside script (PTY emulation)", () => {
      // `script -qc` allocates a real PTY for the command, similar to exec pty:true
      const innerCmd = `echo "${SECRET}"`;
      const cmd = wrapCommand(`script -qc '${innerCmd}' /dev/null`);
      const result = run(cmd, {});
      // script output may include carriage returns from PTY
      const cleaned = result.stdout.replace(/\r/g, "");
      expect(cleaned).toContain(REPLACEMENT);
      expect(cleaned).not.toContain(SECRET);
    });

    it("should scrub credential from PTY env var exfiltration", () => {
      const env = { GH_TOKEN: SECRET };
      const innerCmd = `printenv GH_TOKEN`;
      const cmd = wrapCommand(`script -qc '${innerCmd}' /dev/null`);
      const result = run(cmd, env);
      const cleaned = result.stdout.replace(/\r/g, "");
      expect(cleaned).toContain(REPLACEMENT);
      expect(cleaned).not.toContain(SECRET);
    });

    it("should scrub multiple credentials through PTY", () => {
      const env = { CRED1: SECRET, CRED2: SECRET2 };
      const innerCmd = `echo "$CRED1 $CRED2"`;
      const cmd = wrapCommand(`script -qc '${innerCmd}' /dev/null`, multiPerlScript);
      const result = run(cmd, env);
      const cleaned = result.stdout.replace(/\r/g, "");
      expect(cleaned).not.toContain(SECRET);
      expect(cleaned).not.toContain(SECRET2);
      expect(cleaned).toContain(REPLACEMENT);
      expect(cleaned).toContain(REPLACEMENT2);
    });
  });
});
