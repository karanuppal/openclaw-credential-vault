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
      cookieFile,
      yes: true,
    });

    const cfg = readConfig(tmpDir).tools["gumroad-session"];
    expect(cfg).toBeDefined();
    expect(cfg.inject[0].type).toBe("browser-cookie");
    expect(cfg.inject[0].method).toBe("cookie-jar");
    expect(cfg.inject[0].domainPin).toEqual([".gumroad.com"]);

    const meta = configModule.readMeta(tmpDir);
    const passphrase = getMachinePassphrase(meta?.installTimestamp);
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
      cookieFile,
    });

    expect(fs.existsSync(cookieFile)).toBe(false);
    expect(logs.join("\n")).toContain("Source file securely deleted");
  });

  it("keeps so[VAULT:gmail-app] declines delete prompt", async () => {
    const cookieFile = path.join(tmpDir, "cookies-keep.json");
    fs.writeFileSync(cookieFile, JSON.stringify([{ name: "sid", value: "cookie-secret", domain: ".gumroad.com", path: "/", expires: -1, httpOnly: true, secure: true, sameSite: "Lax" }]));

    setPromptUser(async () => "n");

    const program = createMockProgram();
    registerCliCommands(program as any);
    await getAddAction(program)("gumroad-keep", {
      use: "browser-session",
      domain: ".gumroad.com",
      cookieFile,
    });

    expect(fs.existsSync(cookieFile)).toBe(true);
  });
});
