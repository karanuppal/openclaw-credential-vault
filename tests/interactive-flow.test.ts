import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";

import { initConfig, readConfig } from "../src/config.js";
import * as configModule from "../src/config.js";
import { registerCliCommands, setPromptUser, resetPromptUser } from "../src/cli.js";

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
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "vault-interactive-"));
  initConfig(tmpDir, "machine");
  return tmpDir;
}

function getAddAction(program: ReturnType<typeof createMockProgram>) {
  const vault = program.commands.get("vault")!;
  const add = vault.subcommands.get("add")!;
  return add.action!;
}

function withPromptAnswers(answers: string[]) {
  let i = 0;
  setPromptUser(async () => answers[i++] ?? "");
}

describe("vault add interactive flow", () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = setupTempVault();
    vi.spyOn(configModule, "getVaultDir").mockReturnValue(tmpDir);
    vi.spyOn(console, "log").mockImplementation(() => {});
    vi.spyOn(console, "error").mockImplementation(() => {});
  });

  afterEach(() => {
    resetPromptUser();
    vi.restoreAllMocks();
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it("interactive flow: selects option 1 (api), provides URL, defaults header -> writes web_fetch rule", async () => {
    withPromptAnswers([
      "1",                 // choose usage
      "api.example.com",   // API domain
      "",                  // header -> default Authorization
      "",                  // format -> default Bearer $token
      "n",                 // include detected scrub pattern? (generic-api-key has one)
      "n",                 // add custom scrub regex?
      "y",                 // save
    ]);

    const program = createMockProgram();
    registerCliCommands(program as any);
    await getAddAction(program)("api-interactive", { key: "A".repeat(40) });

    const inject = readConfig(tmpDir).tools["api-interactive"].inject;
    const webFetch = inject.find((r) => r.tool === "web_fetch");
    expect(webFetch).toBeDefined();
    expect(webFetch!.urlMatch).toBe("*api.example.com/*");
    expect(webFetch!.headers?.Authorization).toBe("Bearer $vault:api-interactive");
  });

  it("interactive flow: selects option 3 (browser-login), provides domain -> writes browser rule", async () => {
    withPromptAnswers([
      "3",
      ".github.com",
      "n",
      "y",
    ]);

    const program = createMockProgram();
    registerCliCommands(program as any);
    await getAddAction(program)("browser-login-interactive", { key: "mypassword123" });

    const inject = readConfig(tmpDir).tools["browser-login-interactive"].inject;
    expect(inject[0].type).toBe("browser-password");
    expect(inject[0].domainPin).toEqual([".github.com"]);
  });

  it("interactive flow: selects option 2 (cli), provides command name and env var -> writes exec rule", async () => {
    withPromptAnswers([
      "2",
      "gh",
      "GITHUB_TOKEN",
      "n",                 // include detected scrub pattern? (generic-api-key has one)
      "n",                 // add custom scrub regex?
      "y",
    ]);

    const program = createMockProgram();
    registerCliCommands(program as any);
    await getAddAction(program)("cli-interactive", { key: "A".repeat(40) });

    const inject = readConfig(tmpDir).tools["cli-interactive"].inject;
    const execRule = inject.find((r) => r.tool === "exec");
    expect(execRule).toBeDefined();
    expect(execRule!.commandMatch).toBe("gh*");
    expect(execRule!.env?.GITHUB_TOKEN).toBe("$vault:cli-interactive");
  });

  it("interactive flow: selects multiple (1,2) -> writes both web_fetch and exec rules", async () => {
    withPromptAnswers([
      "1,2",
      "api.multi.com",
      "Authorization",
      "Bearer $token",
      "multi",
      "MULTI_TOKEN",
      "n",                 // include detected scrub pattern? (generic-api-key has one)
      "n",                 // add custom scrub regex?
      "y",
    ]);

    const program = createMockProgram();
    registerCliCommands(program as any);
    await getAddAction(program)("multi-interactive", { key: "A".repeat(40) });

    const inject = readConfig(tmpDir).tools["multi-interactive"].inject;
    expect(inject.some((r) => r.tool === "web_fetch")).toBe(true);
    expect(inject.some((r) => r.tool === "exec")).toBe(true);
  });

  it("interactive flow: accepts detected scrub pattern from guesser -> adds to scrub config", async () => {
    withPromptAnswers([
      "1",                 // choose usage
      "api.example.com",   // API domain
      "",                  // header -> default Authorization
      "",                  // format -> default Bearer $token
      "y",                 // include detected scrub pattern? (accept)
      "n",                 // add custom scrub regex?
      "y",                 // save
    ]);

    const program = createMockProgram();
    registerCliCommands(program as any);
    await getAddAction(program)("scrub-accepted", { key: "A".repeat(40) });

    const tool = readConfig(tmpDir).tools["scrub-accepted"];
    expect(tool).toBeDefined();
    // The guesser-suggested pattern should be included
    expect(tool.scrub.patterns.length).toBeGreaterThan(0);
  });

  it("interactive flow: answers N to save -> does not write config", async () => {
    withPromptAnswers([
      "1",
      "api.nosave.com",
      "",
      "",
      "n",                 // include detected scrub pattern? (generic-api-key has one)
      "n",                 // add custom scrub regex?
      "n",                 // save
    ]);

    const program = createMockProgram();
    registerCliCommands(program as any);
    await getAddAction(program)("no-save", { key: "A".repeat(40) });

    expect(readConfig(tmpDir).tools["no-save"]).toBeUndefined();
  });
});
