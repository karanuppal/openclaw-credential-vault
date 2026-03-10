import { describe, it, expect, beforeEach, afterEach } from "vitest";
import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";
import {
  readConfig,
  writeConfig,
  upsertTool,
  removeTool,
  initConfig,
  readMeta,
  getConfigPath,
} from "../src/config.js";
import { VaultConfig, ToolConfig } from "../src/types.js";

describe("Config serialization", () => {
  const tmpDir = path.join(os.tmpdir(), `vault-config-test-${Date.now()}`);

  beforeEach(() => {
    fs.mkdirSync(tmpDir, { recursive: true });
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it("should return default config when file doesn't exist", () => {
    const config = readConfig(tmpDir);
    expect(config.version).toBe(1);
    expect(config.masterKeyMode).toBe("machine");
    expect(Object.keys(config.tools)).toHaveLength(0);
  });

  it("should write and read config round-trip", () => {
    const config: VaultConfig = {
      version: 1,
      masterKeyMode: "machine",
      tools: {
        stripe: {
          name: "stripe",
          addedAt: "2026-01-01T00:00:00.000Z",
          lastRotated: "2026-01-01T00:00:00.000Z",
          inject: [
            {
              tool: "exec",
              commandMatch: "stripe*",
              env: { STRIPE_API_KEY: "$vault:stripe" },
            },
          ],
          scrub: {
            patterns: ["sk_live_[a-zA-Z0-9]{24,}"],
          },
        },
      },
    };

    writeConfig(tmpDir, config);

    // Verify file exists
    expect(fs.existsSync(getConfigPath(tmpDir))).toBe(true);

    // Read it back
    const loaded = readConfig(tmpDir);
    expect(loaded.version).toBe(1);
    expect(loaded.masterKeyMode).toBe("machine");
    expect(loaded.tools.stripe.name).toBe("stripe");
    expect(loaded.tools.stripe.inject).toHaveLength(1);
    expect(loaded.tools.stripe.inject[0].commandMatch).toBe("stripe*");
    expect(loaded.tools.stripe.scrub.patterns).toEqual(["sk_live_[a-zA-Z0-9]{24,}"]);
  });

  it("should set config file permissions to 0600", () => {
    const config: VaultConfig = { version: 1, masterKeyMode: "machine", tools: {} };
    writeConfig(tmpDir, config);
    const stat = fs.statSync(getConfigPath(tmpDir));
    expect((stat.mode & 0o777).toString(8)).toBe("600");
  });

  it("should handle malformed YAML gracefully", () => {
    fs.writeFileSync(getConfigPath(tmpDir), "just_a_string_value", "utf8");
    // Should not throw, returns defaults since parsed value is not an object with expected shape
    const config = readConfig(tmpDir);
    expect(config).toBeDefined();
    expect(config.version).toBe(1);
  });
});

describe("Config mutations", () => {
  it("should add a tool via upsertTool", () => {
    const config: VaultConfig = { version: 1, masterKeyMode: "machine", tools: {} };
    const tool: ToolConfig = {
      name: "github",
      addedAt: "2026-01-01",
      lastRotated: "2026-01-01",
      inject: [{ tool: "exec", commandMatch: "gh *", env: { GH_TOKEN: "$vault:github" } }],
      scrub: { patterns: ["ghp_[a-zA-Z0-9]{36}"] },
    };

    const updated = upsertTool(config, tool);
    expect(updated.tools.github).toBeDefined();
    expect(updated.tools.github.name).toBe("github");
    // Original should not be mutated
    expect(config.tools.github).toBeUndefined();
  });

  it("should update existing tool via upsertTool", () => {
    const config: VaultConfig = {
      version: 1,
      masterKeyMode: "machine",
      tools: {
        github: {
          name: "github",
          addedAt: "2026-01-01",
          lastRotated: "2026-01-01",
          inject: [],
          scrub: { patterns: [] },
        },
      },
    };
    const updated = upsertTool(config, {
      ...config.tools.github,
      lastRotated: "2026-03-08",
    });
    expect(updated.tools.github.lastRotated).toBe("2026-03-08");
  });

  it("should remove a tool via removeTool", () => {
    const config: VaultConfig = {
      version: 1,
      masterKeyMode: "machine",
      tools: {
        stripe: {
          name: "stripe",
          addedAt: "2026-01-01",
          lastRotated: "2026-01-01",
          inject: [],
          scrub: { patterns: [] },
        },
        github: {
          name: "github",
          addedAt: "2026-01-01",
          lastRotated: "2026-01-01",
          inject: [],
          scrub: { patterns: [] },
        },
      },
    };

    const updated = removeTool(config, "stripe");
    expect(updated.tools.stripe).toBeUndefined();
    expect(updated.tools.github).toBeDefined();
    // Original not mutated
    expect(config.tools.stripe).toBeDefined();
  });
});

describe("Vault initialization", () => {
  const tmpDir = path.join(os.tmpdir(), `vault-init-test-${Date.now()}`);

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it("should create vault directory and config", () => {
    const config = initConfig(tmpDir, "machine", "2026-01-01");
    expect(config.version).toBe(1);
    expect(config.masterKeyMode).toBe("machine");
    expect(fs.existsSync(getConfigPath(tmpDir))).toBe(true);
  });

  it("should write metadata file", () => {
    initConfig(tmpDir, "passphrase", "2026-03-08");
    const meta = readMeta(tmpDir);
    expect(meta).not.toBeNull();
    expect(meta!.masterKeyMode).toBe("passphrase");
    expect(meta!.installTimestamp).toBe("2026-03-08");
  });

  it("should set metadata file permissions to 0600", () => {
    initConfig(tmpDir, "machine");
    const metaPath = path.join(tmpDir, ".vault-meta.json");
    const stat = fs.statSync(metaPath);
    expect((stat.mode & 0o777).toString(8)).toBe("600");
  });
});
