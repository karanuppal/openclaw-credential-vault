import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";

import { initConfig, readConfig } from "../src/config.js";
import * as configModule from "../src/config.js";
import { registerCliCommands } from "../src/cli.js";

interface CapturedCommand {
  name: string;
  options: Map<string, string>;
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

function setupTempVault() {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "vault-cli-use-"));
  initConfig(tmpDir, "machine");
  return tmpDir;
}

function getAddAction(program: ReturnType<typeof createMockProgram>) {
  const vault = program.commands.get("vault")!;
  const add = vault.subcommands.get("add")!;
  return add.action!;
}

describe("vault add --use parsing", () => {
  let tmpDir: string;
  let errors: string[];

  beforeEach(() => {
    tmpDir = setupTempVault();
    vi.spyOn(configModule, "getVaultDir").mockReturnValue(tmpDir);
    errors = [];
    vi.spyOn(console, "error").mockImplementation((...args) => {
      errors.push(args.join(" "));
    });
    vi.spyOn(console, "log").mockImplementation(() => {});
  });

  afterEach(() => {
    vi.restoreAllMocks();
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it("parses single --use api", async () => {
    const program = createMockProgram();
    registerCliCommands(program as any);
    await getAddAction(program)("svc-api", { key: "A".repeat(40), use: "api", url: "*api.svc.com/*", yes: true });

    const cfg = readConfig(tmpDir).tools["svc-api"];
    expect(cfg.inject.some((r) => r.tool === "web_fetch")).toBe(true);
  });

  it("parses comma-separated --use api,cli", async () => {
    const program = createMockProgram();
    registerCliCommands(program as any);
    await getAddAction(program)("svc-apicli", { key: "A".repeat(40), use: "api,cli", url: "*svc.io/*", command: "svc", env: "SVC_KEY", yes: true });

    const inject = readConfig(tmpDir).tools["svc-apicli"].inject;
    expect(inject.some((r) => r.tool === "web_fetch")).toBe(true);
    expect(inject.some((r) => r.tool === "exec")).toBe(true);
  });

  it("parses --use browser-login", async () => {
    const program = createMockProgram();
    registerCliCommands(program as any);
    await getAddAction(program)("svc-login", { key: "pass123", use: "browser-login", domain: ".example.com", yes: true });

    const inject = readConfig(tmpDir).tools["svc-login"].inject;
    expect(inject[0].type).toBe("browser-password");
    expect(inject[0].domainPin).toEqual([".example.com"]);
  });

  it("parses --use browser-session", async () => {
    const cookiePath = path.join(tmpDir, "cookies.json");
    fs.writeFileSync(cookiePath, JSON.stringify([{ name: "sid", value: "abc123", domain: ".gumroad.com", path: "/", expires: -1, httpOnly: true, secure: true, sameSite: "Lax" }]));

    const program = createMockProgram();
    registerCliCommands(program as any);
    await getAddAction(program)("svc-session", { use: "browser-session", domain: ".gumroad.com", cookieFile: cookiePath, yes: true });

    const inject = readConfig(tmpDir).tools["svc-session"].inject;
    expect(inject[0].type).toBe("browser-cookie");
    expect(inject[0].domainPin).toEqual([".gumroad.com"]);
  });

  it("trims whitespace in --use api, cli", async () => {
    const program = createMockProgram();
    registerCliCommands(program as any);
    // --yes requires explicit --command AND --env for cli
    await getAddAction(program)("svc-trim", { key: "A".repeat(40), use: "api, cli", url: "*svc.io/*", command: "svc", env: "SVC_TOKEN", yes: true });

    const inject = readConfig(tmpDir).tools["svc-trim"].inject;
    expect(inject.some((r) => r.tool === "web_fetch")).toBe(true);
    expect(inject.some((r) => r.tool === "exec")).toBe(true);
  });

  it("supports all 4 usage types in one --use", async () => {
    const cookiePath = path.join(tmpDir, "cookies-all.json");
    fs.writeFileSync(cookiePath, JSON.stringify([{ name: "sid", value: "abc123", domain: ".gumroad.com", path: "/", expires: -1, httpOnly: true, secure: true, sameSite: "Lax" }]));

    const program = createMockProgram();
    registerCliCommands(program as any);
    await getAddAction(program)("svc-all", {
      key: "A".repeat(40),
      use: "api,cli,browser-login,browser-session",
      url: "*svc.io/*",
      command: "svc",
      env: "SVC_KEY",
      domain: ".gumroad.com",
      cookieFile: cookiePath,
      yes: true,
    });

    const inject = readConfig(tmpDir).tools["svc-all"].inject;
    expect(inject.some((r) => r.tool === "web_fetch")).toBe(true);
    expect(inject.some((r) => r.tool === "exec")).toBe(true);
    expect(inject.some((r) => r.type === "browser-password")).toBe(true);
    expect(inject.some((r) => r.type === "browser-cookie")).toBe(true);
  });

  describe("--yes validation edge cases", () => {
    it("--yes with known prefix (sk_live_) and no --use succeeds", async () => {
      const program = createMockProgram();
      registerCliCommands(program as any);
      await getAddAction(program)("stripe", { key: "sk_live_4eC39HqLyjWDarjtT1zdp7dc", yes: true });

      expect(readConfig(tmpDir).tools["stripe"]).toBeDefined();
      expect(errors.length).toBe(0);
    });

    it("--yes with --use api + --url succeeds", async () => {
      const program = createMockProgram();
      registerCliCommands(program as any);
      await getAddAction(program)("api-ok", { key: "A".repeat(40), use: "api", url: "*api.ok/*", yes: true });

      expect(readConfig(tmpDir).tools["api-ok"]).toBeDefined();
      expect(errors.length).toBe(0);
    });

    it("--yes with --use api but no --url errors", async () => {
      const program = createMockProgram();
      registerCliCommands(program as any);
      await getAddAction(program)("api-missing", { key: "A".repeat(40), use: "api", yes: true });

      expect(errors.some((e) => e.includes("--yes requires either a known credential format or --use with all required flags"))).toBe(true);
    });

    it("--yes with --use browser-login + --domain succeeds", async () => {
      const program = createMockProgram();
      registerCliCommands(program as any);
      await getAddAction(program)("login-ok", { key: "password123", use: "browser-login", domain: ".example.com", yes: true });

      expect(readConfig(tmpDir).tools["login-ok"]).toBeDefined();
      expect(errors.length).toBe(0);
    });

    it("--yes with --use browser-login but no --domain errors", async () => {
      const program = createMockProgram();
      registerCliCommands(program as any);
      await getAddAction(program)("login-missing", { key: "password123", use: "browser-login", yes: true });

      expect(errors.some((e) => e.includes("--yes requires either a known credential format or --use with all required flags"))).toBe(true);
    });

    it("--yes with --use browser-session + --domain + --cookie-file succeeds", async () => {
      const cookiePath = path.join(tmpDir, "cookies-yes.json");
      fs.writeFileSync(cookiePath, JSON.stringify([{ name: "sid", value: "v1", domain: ".gumroad.com", path: "/", expires: -1, httpOnly: true, secure: true, sameSite: "Lax" }]));

      const program = createMockProgram();
      registerCliCommands(program as any);
      await getAddAction(program)("session-ok", { use: "browser-session", domain: ".gumroad.com", cookieFile: cookiePath, yes: true });

      expect(readConfig(tmpDir).tools["session-ok"]).toBeDefined();
      expect(errors.length).toBe(0);
    });

    it("--yes with --use browser-session missing --cookie-file errors", async () => {
      const program = createMockProgram();
      registerCliCommands(program as any);
      await getAddAction(program)("session-missing", { use: "browser-session", domain: ".gumroad.com", yes: true });

      expect(errors.some((e) => e.includes("--yes requires either a known credential format or --use with all required flags"))).toBe(true);
    });

    it("--yes with unknown format and no --use errors", async () => {
      const program = createMockProgram();
      registerCliCommands(program as any);
      await getAddAction(program)("unknown", { key: "this is unknown format value", yes: true });

      expect(errors.some((e) => e.includes("--yes requires either a known credential format or --use with all required flags"))).toBe(true);
    });

    it("--yes with --use cli + --command + --env succeeds", async () => {
      const program = createMockProgram();
      registerCliCommands(program as any);
      await getAddAction(program)("cli-ok", { key: "A".repeat(40), use: "cli", command: "mycli", env: "MYCLI_TOKEN", yes: true });

      expect(readConfig(tmpDir).tools["cli-ok"]).toBeDefined();
      expect(errors.length).toBe(0);
    });

    it("--yes with --use cli but no --command errors", async () => {
      const program = createMockProgram();
      registerCliCommands(program as any);
      await getAddAction(program)("cli-no-cmd", { key: "A".repeat(40), use: "cli", env: "MYCLI_TOKEN", yes: true });

      expect(errors.some((e) => e.includes("--yes requires either a known credential format or --use with all required flags"))).toBe(true);
    });

    it("--yes with --use cli but no --env errors", async () => {
      const program = createMockProgram();
      registerCliCommands(program as any);
      await getAddAction(program)("cli-no-env", { key: "A".repeat(40), use: "cli", command: "mycli", yes: true });

      expect(errors.some((e) => e.includes("--yes requires either a known credential format or --use with all required flags"))).toBe(true);
    });

    it("--yes with --use cli but no --command and no --env errors", async () => {
      const program = createMockProgram();
      registerCliCommands(program as any);
      await getAddAction(program)("cli-no-flags", { key: "A".repeat(40), use: "cli", yes: true });

      expect(errors.some((e) => e.includes("--yes requires either a known credential format or --use with all required flags"))).toBe(true);
    });
  });
});
