/**
 * Tests for CLI browser-cookie and browser-password --type/--domain flags.
 * Spec ref: Phase 3B — Cookie Capture CLI (Option A — manual paste)
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";

import {
  writeCredentialFile,
  readCredentialFile,
  getMachinePassphrase,
} from "../src/crypto.js";
import {
  initConfig,
  readConfig,
  writeConfig,
  upsertTool,
} from "../src/config.js";
import * as configModule from "../src/config.js";
import { registerCliCommands, setStdinReader, resetStdinReader, setPromptUser, resetPromptUser } from "../src/cli.js";
import { PlaywrightCookie, BrowserCookieCredential } from "../src/types.js";

// ── Helpers ──

/** Create a temp vault dir and initialize it */
function setupTempVault(): string {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "vault-cli-browser-"));
  initConfig(tmpDir, "machine");
  return tmpDir;
}

/** Build a minimal mock Commander program that captures registered commands */
interface CapturedCommand {
  name: string;
  options: Map<string, any>;
  action: ((...args: any[]) => Promise<void>) | null;
  subcommands: Map<string, CapturedCommand>;
}

function createMockProgram() {
  const commands = new Map<string, CapturedCommand>();

  function makeCommand(name: string): any {
    const cmd: CapturedCommand = {
      name,
      options: new Map(),
      action: null,
      subcommands: new Map(),
    };

    const builder: any = {
      description: () => builder,
      argument: () => builder,
      option: (flags: string) => {
        // Extract option name from flags like "--key <credential>"
        const match = flags.match(/--(\w+)/);
        if (match) cmd.options.set(match[1], flags);
        return builder;
      },
      action: (fn: any) => {
        cmd.action = fn;
        return builder;
      },
      command: (subName: string) => {
        const sub = makeCommand(subName);
        cmd.subcommands.set(subName, sub._cmd);
        return sub;
      },
      _cmd: cmd,
    };

    return builder;
  }

  return {
    command: (name: string) => {
      const builder = makeCommand(name);
      commands.set(name, builder._cmd);
      return builder;
    },
    commands,
  };
}

/** Get the 'add' command action from the mock program */
function getAddAction(program: ReturnType<typeof createMockProgram>) {
  const vault = program.commands.get("vault")!;
  const add = vault.subcommands.get("add")!;
  return add.action!;
}

/** Get the 'add' command from the mock program */
function getAddCommand(program: ReturnType<typeof createMockProgram>) {
  const vault = program.commands.get("vault")!;
  return vault.subcommands.get("add")!;
}

// ── Sample cookie data ──

const SAMPLE_COOKIES_JSON = JSON.stringify([
  {
    name: "session-id",
    value: "abc-123-def",
    domain: ".amazon.com",
    path: "/",
    expires: Math.floor(Date.now() / 1000) + 86400 * 30, // 30 days from now
    httpOnly: true,
    secure: true,
    sameSite: "Lax",
  },
  {
    name: "session-token",
    value: "xyz-789-uvw",
    domain: ".amazon.com",
    path: "/",
    expires: Math.floor(Date.now() / 1000) + 86400 * 7, // 7 days from now (earliest)
    httpOnly: true,
    secure: true,
    sameSite: "Lax",
  },
]);

const SAMPLE_COOKIES_NETSCAPE = [
  "# Netscape HTTP Cookie File",
  ".amazon.com\tTRUE\t/\tTRUE\t" + (Math.floor(Date.now() / 1000) + 86400 * 30) + "\tsession-id\tabc-123-def",
  ".amazon.com\tTRUE\t/\tTRUE\t" + (Math.floor(Date.now() / 1000) + 86400 * 7) + "\tsession-token\txyz-789-uvw",
].join("\n");

// ── Tests ──

describe("CLI vault add --type/--domain flags", () => {
  let tmpDir: string;
  let consoleOutput: string[];
  let consoleErrors: string[];
  let getVaultDirSpy: any;

  beforeEach(() => {
    tmpDir = setupTempVault();
    // Mock getVaultDir to return our temp dir
    getVaultDirSpy = vi.spyOn(configModule, "getVaultDir").mockReturnValue(tmpDir);
    consoleOutput = [];
    consoleErrors = [];
    vi.spyOn(console, "log").mockImplementation((...args) => {
      consoleOutput.push(args.join(" "));
    });
    vi.spyOn(console, "error").mockImplementation((...args) => {
      consoleErrors.push(args.join(" "));
    });
  });

  afterEach(() => {
    vi.restoreAllMocks();
    resetStdinReader();
    // Cleanup temp dir
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  describe("command registration", () => {
    it("should register --type and --domain options on vault add", () => {
      const program = createMockProgram();
      registerCliCommands(program as any);

      const addCmd = getAddCommand(program);
      expect(addCmd.options.has("type")).toBe(true);
      expect(addCmd.options.has("domain")).toBe(true);
    });
  });

  describe("--type browser-cookie", () => {
    it("should error when --domain is missing", async () => {
      const program = createMockProgram();
      registerCliCommands(program as any);
      const action = getAddAction(program);

      await action("amazon-session", { type: "browser-cookie" });

      expect(consoleErrors.some((e) => e.includes("--domain is required"))).toBe(true);
    });

    it("should store JSON cookies and configure injection rule", async () => {
      setStdinReader(async () => SAMPLE_COOKIES_JSON);

      const program = createMockProgram();
      registerCliCommands(program as any);
      const action = getAddAction(program);

      await action("amazon-session", {
        type: "browser-cookie",
        domain: ".amazon.com",
      });

      // Verify output messages
      const output = consoleOutput.join("\n");
      expect(output).toContain("Stored 2 cookies for .amazon.com");
      expect(output).toContain("AES-256-GCM encrypted");
      expect(output).toContain("Expires:");

      // Verify config was written
      const config = readConfig(tmpDir);
      const toolConfig = config.tools["amazon-session"];
      expect(toolConfig).toBeDefined();
      expect(toolConfig.inject).toHaveLength(1);
      expect(toolConfig.inject[0].type).toBe("browser-cookie");
      expect(toolConfig.inject[0].method).toBe("cookie-jar");
      expect(toolConfig.inject[0].domainPin).toEqual([".amazon.com"]);
      expect(toolConfig.inject[0].tool).toBe("browser");

      // Verify encrypted credential can be decrypted
      const meta = configModule.readMeta(tmpDir);
      const passphrase = getMachinePassphrase(meta?.installTimestamp);
      const stored = await readCredentialFile(tmpDir, "amazon-session", passphrase);
      const parsed: BrowserCookieCredential = JSON.parse(stored);
      expect(parsed.cookies).toHaveLength(2);
      expect(parsed.domain).toBe(".amazon.com");
      expect(parsed.capturedAt).toBeTruthy();
    });

    it("should store Netscape format cookies", async () => {
      setStdinReader(async () => SAMPLE_COOKIES_NETSCAPE);

      const program = createMockProgram();
      registerCliCommands(program as any);
      const action = getAddAction(program);

      await action("amazon-session", {
        type: "browser-cookie",
        domain: ".amazon.com",
      });

      const output = consoleOutput.join("\n");
      expect(output).toContain("Stored 2 cookies for .amazon.com");

      // Verify stored cookies
      const meta = configModule.readMeta(tmpDir);
      const passphrase = getMachinePassphrase(meta?.installTimestamp);
      const stored = await readCredentialFile(tmpDir, "amazon-session", passphrase);
      const parsed: BrowserCookieCredential = JSON.parse(stored);
      expect(parsed.cookies).toHaveLength(2);
      expect(parsed.cookies[0].name).toBe("session-id");
      expect(parsed.cookies[1].name).toBe("session-token");
    });

    it("should error on empty input", async () => {
      setStdinReader(async () => "");

      const program = createMockProgram();
      registerCliCommands(program as any);
      const action = getAddAction(program);

      await action("amazon-session", {
        type: "browser-cookie",
        domain: ".amazon.com",
      });

      expect(consoleErrors.some((e) => e.includes("No cookie data provided"))).toBe(true);
    });

    it("should error on invalid JSON", async () => {
      setStdinReader(async () => "[not valid json");

      const program = createMockProgram();
      registerCliCommands(program as any);
      const action = getAddAction(program);

      await action("amazon-session", {
        type: "browser-cookie",
        domain: ".amazon.com",
      });

      expect(consoleErrors.some((e) => e.includes("Error parsing cookies"))).toBe(true);
    });

    it("should show earliest expiry from cookies", async () => {
      setStdinReader(async () => SAMPLE_COOKIES_JSON);

      const program = createMockProgram();
      registerCliCommands(program as any);
      const action = getAddAction(program);

      await action("amazon-session", {
        type: "browser-cookie",
        domain: ".amazon.com",
      });

      const output = consoleOutput.join("\n");
      expect(output).toContain("Expires:");
      // The 7-day cookie should be earliest
      const cookies = JSON.parse(SAMPLE_COOKIES_JSON);
      const earliestTs = Math.min(...cookies.map((c: any) => c.expires));
      const expectedDate = new Date(earliestTs * 1000).toISOString();
      expect(output).toContain(expectedDate);
    });

    it("should skip --key flag for browser-cookie type", async () => {
      setStdinReader(async () => SAMPLE_COOKIES_JSON);

      const program = createMockProgram();
      registerCliCommands(program as any);
      const action = getAddAction(program);

      // Even if --key is passed, browser-cookie should ignore it and use paste
      await action("amazon-session", {
        type: "browser-cookie",
        domain: ".amazon.com",
        key: "this-should-be-ignored",
      });

      const output = consoleOutput.join("\n");
      expect(output).toContain("Stored 2 cookies");
    });
  });

  describe("--type browser-password", () => {
    it("should error when --domain is missing", async () => {
      const program = createMockProgram();
      registerCliCommands(program as any);
      const action = getAddAction(program);

      await action("github-login", { type: "browser-password", key: "mypassword" });

      expect(consoleErrors.some((e) => e.includes("--domain is required"))).toBe(true);
    });

    it("should error when --key is missing", async () => {
      const program = createMockProgram();
      registerCliCommands(program as any);
      const action = getAddAction(program);

      await action("github-login", { type: "browser-password", domain: ".github.com" });

      expect(consoleErrors.some((e) => e.includes("--key is required"))).toBe(true);
    });

    it("should store password and configure browser-password injection", async () => {
      const program = createMockProgram();
      registerCliCommands(program as any);
      const action = getAddAction(program);

      await action("github-login", {
        type: "browser-password",
        domain: ".github.com",
        key: "super-secret-password",
      });

      const output = consoleOutput.join("\n");
      expect(output).toContain("Credential stored: github-login");
      expect(output).toContain("AES-256-GCM encrypted");

      // Verify config
      const config = readConfig(tmpDir);
      const toolConfig = config.tools["github-login"];
      expect(toolConfig).toBeDefined();
      expect(toolConfig.inject).toHaveLength(1);
      expect(toolConfig.inject[0].type).toBe("browser-password");
      expect(toolConfig.inject[0].method).toBe("fill");
      expect(toolConfig.inject[0].domainPin).toEqual([".github.com"]);
      expect(toolConfig.inject[0].tool).toBe("browser");

      // Verify credential
      const meta = configModule.readMeta(tmpDir);
      const passphrase = getMachinePassphrase(meta?.installTimestamp);
      const stored = await readCredentialFile(tmpDir, "github-login", passphrase);
      expect(stored).toBe("super-secret-password");
    });
  });

  describe("default type (no --type flag)", () => {
    it("should still require --key when --type is omitted", async () => {
      const program = createMockProgram();
      registerCliCommands(program as any);
      const action = getAddAction(program);

      await action("stripe", {});

      expect(consoleErrors.some((e) => e.includes("--key is required"))).toBe(true);
    });

    it("should not route to browser handlers when --type is omitted", async () => {
      const program = createMockProgram();
      registerCliCommands(program as any);
      const action = getAddAction(program);

      // Mock promptUser to auto-confirm (standard flow now has interactive confirm prompt)
      setPromptUser(async () => "Y");

      // With key but no type, should use standard flow (not browser-cookie/password)
      await action("stripe", { key: "sk_live_abc123def456ghi789jkl012mno" });

      // Clean up
      resetPromptUser();

      const output = consoleOutput.join("\n");
      // Should NOT see browser-cookie/password messages
      expect(output).not.toContain("cookies for");
      expect(output).not.toContain("browser fill");
      // Should see standard credential stored message
      expect(output).toContain("Credential stored: stripe");
    });
  });
});
