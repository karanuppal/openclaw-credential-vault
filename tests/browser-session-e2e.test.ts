import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";

import { initConfig, readConfig } from "../src/config.js";
import * as configModule from "../src/config.js";
import { registerCliCommands, setPromptUser, resetPromptUser } from "../src/cli.js";
import { readCredentialFile, getMachinePassphrase } from "../src/crypto.js";

interface CapturedCommand {
  name: string;
  options: Map<string, string>;
  action: ((...args: any[]) => Promise<void>) | null;
  subcommands: Map<string, CapturedCommand>;
}

function createMockProgram() {
  const commands = new Map<string, CapturedCommand>();

  function makeCommand(name: string): any {
    const cmd: CapturedCommand = { name, options: new Map(), action: null, subcommands: new Map() };
    const builder: any = {
      description: () => builder,
      argument: () => builder,
      option: (flags: string) => {
        const match = flags.match(/--([\w-]+)/);
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

function getAddAction(program: ReturnType<typeof createMockProgram>) {
  const vault = program.commands.get("vault")!;
  const add = vault.subcommands.get("add")!;
  return add.action!;
}

describe("browser-session end-to-end", () => {
  let tmpDir: string;
  let logs: string[];

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "vault-browser-session-"));
    initConfig(tmpDir, "machine");
    vi.spyOn(configModule, "getVaultDir").mockReturnValue(tmpDir);
    logs = [];
    vi.spyOn(console, "log").mockImplementation((...args) => logs.push(args.join(" ")));
    vi.spyOn(console, "error").mockImplementation(() => {});
  });

  afterEach(() => {
    resetPromptUser();
    vi.restoreAllMocks();
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it("reads cookie file, encrypts payload, and writes browser-cookie inject rule", async () => {
    const cookieFile = path.join(tmpDir, "cookies.json");
    fs.writeFileSync(cookieFile, JSON.stringify([{ name: "sid", value: "cookie-secret", domain: ".gumroad.com", path: "/", expires: -1, httpOnly: true, secure: true, sameSite: "Lax" }]));

    const program = createMockProgram();
    registerCliCommands(program as any);
    await getAddAction(program)("gumroad-session", {
      use: "browser-session",
      domain: ".gumroad.com",
      key: cookieFile,
      yes: true,
    });

    const cfg = readConfig(tmpDir).tools["gumroad-session"];
    expect(cfg).toBeDefined();
    expect(cfg.inject[0].type).toBe("browser-cookie");
    expect(cfg.inject[0].method).toBe("cookie-jar");
    expect(cfg.inject[0].domainPin).toEqual([".gumroad.com"]);

    const meta = configModule.readMeta(tmpDir);
    const passphrase = getMachinePassphrase(meta?.installTimestamp, meta?.pinnedHostname);
    const decrypted = await readCredentialFile(tmpDir, "gumroad-session", passphrase);
    const parsed = JSON.parse(decrypted);
    expect(parsed.cookies).toHaveLength(1);
    expect(parsed.domain).toBe(".gumroad.com");
  });

  it("prompts secure delete and removes so[VAULT:gmail-app]irmed", async () => {
    const cookieFile = path.join(tmpDir, "cookies-delete.json");
    fs.writeFileSync(cookieFile, JSON.stringify([{ name: "sid", value: "cookie-secret", domain: ".gumroad.com", path: "/", expires: -1, httpOnly: true, secure: true, sameSite: "Lax" }]));

    setPromptUser(async () => "y");

    const program = createMockProgram();
    registerCliCommands(program as any);
    await getAddAction(program)("gumroad-delete", {
      use: "browser-session",
      domain: ".gumroad.com",
      key: cookieFile,
    });

    expect(fs.existsSync(cookieFile)).toBe(false);
    expect(logs.join("\n")).toContain("Source file securely deleted");
  });

  it("keeps source file and logs war[VAULT:gmail-app]ines delete prompt", async () => {
    const cookieFile = path.join(tmpDir, "cookies-keep.json");
    fs.writeFileSync(cookieFile, JSON.stringify([{ name: "sid", value: "cookie-secret", domain: ".gumroad.com", path: "/", expires: -1, httpOnly: true, secure: true, sameSite: "Lax" }]));

    setPromptUser(async () => "n");

    const program = createMockProgram();
    registerCliCommands(program as any);
    await getAddAction(program)("gumroad-keep", {
      use: "browser-session",
      domain: ".gumroad.com",
      key: cookieFile,
    });

    expect(fs.existsSync(cookieFile)).toBe(true);
    expect(logs.join("\n")).toContain("Source file still exists");
  });

  it("accepts inline cookie JSON via --key (starts with [)", async () => {
    const inlineCookies = JSON.stringify([{ name: "sid", value: "inline-secret", domain: ".gumroad.com", path: "/", expires: -1, httpOnly: true, secure: true, sameSite: "Lax" }]);

    const program = createMockProgram();
    registerCliCommands(program as any);
    await getAddAction(program)("gumroad-inline", {
      key: inlineCookies,
      use: "browser-session",
      domain: ".gumroad.com",
      yes: true,
    });

    const cfg = readConfig(tmpDir).tools["gumroad-inline"];
    expect(cfg).toBeDefined();
    expect(cfg.inject[0].type).toBe("browser-cookie");
    expect(cfg.inject[0].domainPin).toEqual([".gumroad.com"]);
    expect(logs.join("\n")).toContain("shell history");
  });

  it("accepts --key as file path when it points to an existing file", async () => {
    const cookieFile = path.join(tmpDir, "cookies-via-key.json");
    fs.writeFileSync(cookieFile, JSON.stringify([{ name: "sid", value: "file-secret", domain: ".gumroad.com", path: "/", expires: -1, httpOnly: true, secure: true, sameSite: "Lax" }]));

    const program = createMockProgram();
    registerCliCommands(program as any);
    await getAddAction(program)("gumroad-keyfile", {
      key: cookieFile,
      use: "browser-session",
      domain: ".gumroad.com",
      yes: true,
    });

    const cfg = readConfig(tmpDir).tools["gumroad-keyfile"];
    expect(cfg).toBeDefined();
    expect(cfg.inject[0].type).toBe("browser-cookie");
    // --yes path: auto-deletes source file for security
    expect(logs.join("\n")).toContain("securely deleted");
    expect(fs.existsSync(cookieFile)).toBe(false);
  });

  it("SECURITY: --yes does NOT leave plaintext cookie files on disk (F-NEW-4)", async () => {
    // Regression test: previously --yes left cookie files on disk.
    // Plaintext cookie files are a security risk — auto-delete is mandatory.
    const cookieFile = path.join(tmpDir, "cookies-security-check.json");
    fs.writeFileSync(cookieFile, JSON.stringify([{ name: "sid", value: "secret-cookie", domain: ".gumroad.com", path: "/", expires: -1, httpOnly: true, secure: true, sameSite: "Lax" }]));

    const program = createMockProgram();
    registerCliCommands(program as any);
    await getAddAction(program)("gumroad-security", {
      use: "browser-session",
      domain: ".gumroad.com",
      key: cookieFile,
      yes: true,
    });

    // The file MUST be gone — no plaintext credentials on disk
    expect(fs.existsSync(cookieFile)).toBe(false);
    // Credential must still be accessible from vault (encrypted)
    const cfg = readConfig(tmpDir).tools["gumroad-security"];
    expect(cfg).toBeDefined();
    expect(cfg.inject[0].type).toBe("browser-cookie");
  });

  it("non-interactive --yes with file auto-deletes source for security", async () => {
    const cookieFile = path.join(tmpDir, "cookies-yes-delete.json");
    fs.writeFileSync(cookieFile, JSON.stringify([{ name: "sid", value: "v1", domain: ".gumroad.com", path: "/", expires: -1, httpOnly: true, secure: true, sameSite: "Lax" }]));

    const program = createMockProgram();
    registerCliCommands(program as any);
    await getAddAction(program)("gumroad-yes-delete", {
      use: "browser-session",
      domain: ".gumroad.com",
      key: cookieFile,
      yes: true,
    });

    const cfg = readConfig(tmpDir).tools["gumroad-yes-delete"];
    expect(cfg).toBeDefined();
    // --yes now auto-deletes cookie source files (security default)
    expect(fs.existsSync(cookieFile)).toBe(false);
    expect(logs.join("\n")).toContain("securely deleted");
  });
});
