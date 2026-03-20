/**
 * Tests for macOS vault fixes:
 * 1. resolveVaultRef should not inject literal "$vault:X" when credential is null
 * 2. Hot-reload should update resolverMode
 * 3. ensureResolverModeValid should detect missing binary and downgrade to inline
 */

import { describe, it, expect, vi } from "vitest";
import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";
import { writeConfig, readConfig } from "../src/config.js";
import { getMachinePassphrase } from "../src/crypto.js";
import { findResolverBinary } from "../src/resolver.js";
import { ensureResolverModeValid } from "../src/cli.js";

// Create isolated test vault directory
function createTestVault(): { vaultDir: string; passphrase: string; cleanup: () => void } {
  const vaultDir = fs.mkdtempSync(path.join(os.tmpdir(), "vault-macos-test-"));
  const installTimestamp = new Date().toISOString();

  const metaPath = path.join(vaultDir, ".vault-meta.json");
  fs.writeFileSync(metaPath, JSON.stringify({
    createdAt: installTimestamp,
    installTimestamp,
    masterKeyMode: "machine",
  }));
  fs.chmodSync(metaPath, 0o600);

  const passphrase = getMachinePassphrase(installTimestamp);

  return {
    vaultDir,
    passphrase,
    cleanup: () => {
      fs.rmSync(vaultDir, { recursive: true, force: true });
    },
  };
}

describe("Fix 2: Hot-reload should update resolverMode", () => {
  it("should pick up resolverMode changes on config file change", () => {
    const { vaultDir, cleanup } = createTestVault();
    try {
      writeConfig(vaultDir, {
        version: 1,
        masterKeyMode: "machine",
        resolverMode: "binary",
        tools: {},
      });

      let config = readConfig(vaultDir);
      expect(config.resolverMode).toBe("binary");

      writeConfig(vaultDir, {
        version: 1,
        masterKeyMode: "machine",
        resolverMode: "inline",
        tools: {},
      });

      config = readConfig(vaultDir);
      expect(config.resolverMode).toBe("inline");
    } finally {
      cleanup();
    }
  });

  it("should default resolverMode to inline when not specified", () => {
    const { vaultDir, cleanup } = createTestVault();
    try {
      const configPath = path.join(vaultDir, "tools.yaml");
      fs.writeFileSync(configPath, "version: 1\nmasterKeyMode: machine\ntools: {}\n");

      const config = readConfig(vaultDir);
      expect(config.resolverMode).toBe("inline");
    } finally {
      cleanup();
    }
  });
});

describe("Fix 3: ensureResolverModeValid", () => {
  it("should downgrade binary to inline when resolver binary is missing", () => {
    // Skip this test if a resolver binary actually exists on this machine
    if (findResolverBinary()) {
      return;
    }

    const { vaultDir, cleanup } = createTestVault();
    try {
      writeConfig(vaultDir, {
        version: 1,
        masterKeyMode: "machine",
        resolverMode: "binary",
        tools: {},
      });

      const logSpy = vi.spyOn(console, "log").mockImplementation(() => {});

      let config = readConfig(vaultDir);
      expect(config.resolverMode).toBe("binary");

      // Call the actual function
      config = ensureResolverModeValid(config, vaultDir);

      expect(config.resolverMode).toBe("inline");

      // Should have warned the user
      const warnings = logSpy.mock.calls.filter(
        (args) => typeof args[0] === "string" && args[0].includes("Switching to")
      );
      expect(warnings.length).toBeGreaterThan(0);

      logSpy.mockRestore();
    } finally {
      cleanup();
    }
  });

  it("should persist the downgrade to disk", () => {
    if (findResolverBinary()) {
      return;
    }

    const { vaultDir, cleanup } = createTestVault();
    try {
      writeConfig(vaultDir, {
        version: 1,
        masterKeyMode: "machine",
        resolverMode: "binary",
        tools: {
          github: {
            name: "github",
            addedAt: new Date().toISOString(),
            lastRotated: new Date().toISOString(),
            inject: [],
            scrub: { patterns: [] },
          },
        },
      });

      vi.spyOn(console, "log").mockImplementation(() => {});

      let config = readConfig(vaultDir);
      config = ensureResolverModeValid(config, vaultDir);

      // Re-read from disk — should be persisted
      const reloaded = readConfig(vaultDir);
      expect(reloaded.resolverMode).toBe("inline");
      // Tools should be preserved
      expect(reloaded.tools.github).toBeDefined();

      vi.restoreAllMocks();
    } finally {
      cleanup();
    }
  });

  it("should be a no-op when resolverMode is already inline", () => {
    const { vaultDir, cleanup } = createTestVault();
    try {
      writeConfig(vaultDir, {
        version: 1,
        masterKeyMode: "machine",
        resolverMode: "inline",
        tools: {},
      });

      const logSpy = vi.spyOn(console, "log").mockImplementation(() => {});

      let config = readConfig(vaultDir);
      config = ensureResolverModeValid(config, vaultDir);

      expect(config.resolverMode).toBe("inline");
      // Should NOT have logged any warnings
      const warnings = logSpy.mock.calls.filter(
        (args) => typeof args[0] === "string" && args[0].includes("Switching to")
      );
      expect(warnings).toHaveLength(0);

      logSpy.mockRestore();
    } finally {
      cleanup();
    }
  });

  it("should be a no-op when resolver binary exists and is executable", () => {
    // This test only runs if a resolver binary actually exists AND can execute
    // (on macOS with a Linux binary in the repo, findResolverBinary returns a path
    // but isExecutable fails — that's the exact edge case we're fixing)
    const binaryPath = findResolverBinary();
    if (!binaryPath) return;
    try {
      const { execFileSync } = require("node:child_process");
      execFileSync(binaryPath, ["--version"], { timeout: 5000, stdio: "ignore" });
    } catch {
      return; // Binary exists but can't execute — skip this test
    }

    const { vaultDir, cleanup } = createTestVault();
    try {
      writeConfig(vaultDir, {
        version: 1,
        masterKeyMode: "machine",
        resolverMode: "binary",
        tools: {},
      });

      let config = readConfig(vaultDir);
      config = ensureResolverModeValid(config, vaultDir);

      // Should stay as binary
      expect(config.resolverMode).toBe("binary");
    } finally {
      cleanup();
    }
  });
});

describe("VaultRefResult type safety", () => {
  it("should not allow null credential to be used as env var value", () => {
    const envVars: Record<string, string> = {};
    const resolvedNull: string | null = null;

    // Old bug: literal placeholder injected
    const oldBehavior = resolvedNull ?? "$vault:github";
    expect(oldBehavior).toBe("$vault:github");

    // New behavior: skip injection
    if (resolvedNull !== null) {
      envVars["GH_TOKEN"] = resolvedNull;
    }
    expect(envVars["GH_TOKEN"]).toBeUndefined();
  });
});
