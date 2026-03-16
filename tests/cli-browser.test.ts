import { describe, it, expect } from "vitest";
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

function getAddCommand(program: ReturnType<typeof createMockProgram>) {
  const vault = program.commands.get("vault")!;
  return vault.subcommands.get("add")!;
}

describe("CLI vault add browser option registration", () => {
  it("registers --use and browser-related flags", () => {
    const program = createMockProgram();
    registerCliCommands(program as any);

    const addCmd = getAddCommand(program);
    expect(addCmd.options.has("use")).toBe(true);
    expect(addCmd.options.has("domain")).toBe(true);
  });

  it("does not register legacy --type on vault add", () => {
    const program = createMockProgram();
    registerCliCommands(program as any);

    const addCmd = getAddCommand(program);
    expect(addCmd.options.has("type")).toBe(false);
  });
});
