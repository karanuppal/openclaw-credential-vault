/**
 * Phase 4: Rotation Infrastructure Tests
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";
import {
  readConfig,
  writeConfig,
  upsertTool,
  initConfig,
  getOverdueCredentials,
} from "../src/config.js";
import { computeVaultStatus, createVaultStatusTool } from "../src/vault-status.js";
import { writeAuditEvent } from "../src/audit.js";
import { ToolConfig, VaultConfig, RotationMetadata, AuditCredentialAccess } from "../src/types.js";

function makeTempVault(): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "vault-rotation-test-"));
  initConfig(dir, "machine");
  return dir;
}

function makeToolConfig(
  name: string,
  lastRotated: string,
  rotation?: RotationMetadata
): ToolConfig {
  return {
    name,
    addedAt: "2026-01-01T00:00:00Z",
    lastRotated,
    inject: [],
    scrub: { patterns: [] },
    rotation,
  };
}

function daysAgo(n: number): string {
  const d = new Date();
  d.setDate(d.getDate() - n);
  return d.toISOString();
}

describe("Rotation Metadata Schema", () => {
  let vaultDir: string;

  beforeEach(() => { vaultDir = makeTempVault(); });
  afterEach(() => { fs.rmSync(vaultDir, { recursive: true, force: true }); });

  it("should store and read rotation metadata fields", () => {
    const config = readConfig(vaultDir);
    const tool = makeToolConfig("github", "2026-02-02T00:00:00Z", {
      label: "GitHub Personal Access Token",
      rotationIntervalDays: 90,
      scopes: ["repo", "workflow", "read:org"],
      rotationProcedure:
        "GitHub Settings → Developer settings → revoke old → generate new → openclaw vault rotate github",
      revokeUrl: "https://github.com/settings/tokens",
      rotationSupport: "manual",
    });

    const updated = upsertTool(config, tool);
    writeConfig(vaultDir, updated);

    const reread = readConfig(vaultDir);
    const stored = reread.tools["github"];

    expect(stored.rotation).toBeDefined();
    expect(stored.rotation!.label).toBe("GitHub Personal Access Token");
    expect(stored.rotation!.rotationIntervalDays).toBe(90);
    expect(stored.rotation!.scopes).toEqual(["repo", "workflow", "read:org"]);
    expect(stored.rotation!.rotationProcedure).toContain("GitHub Settings");
    expect(stored.rotation!.revokeUrl).toBe("https://github.com/settings/tokens");
    expect(stored.rotation!.rotationSupport).toBe("manual");
  });

  it("should match the spec example JSON schema exactly", () => {
    const specExample = {
      label: "GitHub Personal Access Token",
      rotationIntervalDays: 90,
      scopes: ["repo", "workflow", "read:org"],
      rotationProcedure:
        "GitHub Settings → Developer settings → revoke old → generate new → openclaw vault rotate github",
      revokeUrl: "https://github.com/settings/tokens",
      rotationSupport: "manual" as const,
    };

    const config = readConfig(vaultDir);
    const tool: ToolConfig = {
      name: "github/pat",
      addedAt: "2026-02-02T00:00:00Z",
      lastRotated: "2026-02-02T00:00:00Z",
      inject: [],
      scrub: { patterns: [] },
      rotation: specExample,
    };

    const updated = upsertTool(config, tool);
    writeConfig(vaultDir, updated);
    const reread = readConfig(vaultDir);

    expect(reread.tools["github/pat"].rotation).toEqual(specExample);
  });

  it("should handle tools without rotation metadata", () => {
    const config = readConfig(vaultDir);
    const tool: ToolConfig = {
      name: "simple",
      addedAt: "2026-01-01T00:00:00Z",
      lastRotated: "2026-01-01T00:00:00Z",
      inject: [],
      scrub: { patterns: [] },
    };

    const updated = upsertTool(config, tool);
    writeConfig(vaultDir, updated);
    const reread = readConfig(vaultDir);
    expect(reread.tools["simple"]).toBeDefined();
    expect(reread.tools["simple"].name).toBe("simple");
  });

  it("should accept all rotation support types: manual, cli, api", () => {
    let config = readConfig(vaultDir);

    for (const support of ["manual", "cli", "api"] as const) {
      const tool = makeToolConfig(`tool-${support}`, "2026-01-01T00:00:00Z", {
        rotationSupport: support,
      });
      config = upsertTool(config, tool);
    }
    writeConfig(vaultDir, config);

    const reread = readConfig(vaultDir);
    expect(reread.tools["tool-manual"].rotation!.rotationSupport).toBe("manual");
    expect(reread.tools["tool-cli"].rotation!.rotationSupport).toBe("cli");
    expect(reread.tools["tool-api"].rotation!.rotationSupport).toBe("api");
  });
});

describe("getOverdueCredentials", () => {
  it("should return empty array when no tools exist", () => {
    const config: VaultConfig = { version: 1, masterKeyMode: "machine", tools: {} };
    expect(getOverdueCredentials(config)).toEqual([]);
  });

  it("should return empty when all within interval", () => {
    const config: VaultConfig = {
      version: 1,
      masterKeyMode: "machine",
      tools: {
        github: makeToolConfig("github", daysAgo(30), { rotationIntervalDays: 90 }),
      },
    };
    expect(getOverdueCredentials(config)).toEqual([]);
  });

  it("should detect overdue credentials using rotationIntervalDays", () => {
    const config: VaultConfig = {
      version: 1,
      masterKeyMode: "machine",
      tools: {
        github: makeToolConfig("github", daysAgo(100), {
          rotationIntervalDays: 90,
          label: "GitHub PAT",
        }),
      },
    };

    const overdue = getOverdueCredentials(config);
    expect(overdue).toHaveLength(1);
    expect(overdue[0].name).toBe("github");
    expect(overdue[0].label).toBe("GitHub PAT");
    expect(overdue[0].daysSinceRotation).toBeGreaterThanOrEqual(100);
    expect(overdue[0].daysOverdue).toBeGreaterThanOrEqual(10);
    expect(overdue[0].rotationIntervalDays).toBe(90);
  });

  it("should use default interval (90 days) when not set", () => {
    const config: VaultConfig = {
      version: 1,
      masterKeyMode: "machine",
      tools: {
        old: makeToolConfig("old", daysAgo(95)),
        recent: makeToolConfig("recent", daysAgo(30)),
      },
    };
    const overdue = getOverdueCredentials(config);
    expect(overdue).toHaveLength(1);
    expect(overdue[0].name).toBe("old");
  });

  it("should respect custom default interval", () => {
    const config: VaultConfig = {
      version: 1,
      masterKeyMode: "machine",
      tools: { tool1: makeToolConfig("tool1", daysAgo(40)) },
    };
    expect(getOverdueCredentials(config, 90)).toHaveLength(0);
    expect(getOverdueCredentials(config, 30)).toHaveLength(1);
  });

  it("should include rotation metadata in results", () => {
    const config: VaultConfig = {
      version: 1,
      masterKeyMode: "machine",
      tools: {
        stripe: makeToolConfig("stripe", daysAgo(100), {
          rotationIntervalDays: 60,
          rotationProcedure: "Go to Stripe dashboard",
          revokeUrl: "https://dashboard.stripe.com/apikeys",
          rotationSupport: "manual",
          scopes: ["read", "write"],
        }),
      },
    };
    const overdue = getOverdueCredentials(config);
    expect(overdue[0].rotationProcedure).toBe("Go to Stripe dashboard");
    expect(overdue[0].revokeUrl).toBe("https://dashboard.stripe.com/apikeys");
    expect(overdue[0].rotationSupport).toBe("manual");
    expect(overdue[0].scopes).toEqual(["read", "write"]);
  });

  it("should detect multiple overdue credentials", () => {
    const config: VaultConfig = {
      version: 1,
      masterKeyMode: "machine",
      tools: {
        github: makeToolConfig("github", daysAgo(100), { rotationIntervalDays: 90 }),
        stripe: makeToolConfig("stripe", daysAgo(70), { rotationIntervalDays: 60 }),
        fresh: makeToolConfig("fresh", daysAgo(5), { rotationIntervalDays: 30 }),
      },
    };
    const overdue = getOverdueCredentials(config);
    expect(overdue).toHaveLength(2);
    expect(overdue.map((c) => c.name).sort()).toEqual(["github", "stripe"]);
  });
});

describe("vault_status agent tool", () => {
  let vaultDir: string;

  beforeEach(() => { vaultDir = makeTempVault(); });
  afterEach(() => { fs.rmSync(vaultDir, { recursive: true, force: true }); });

  it("should return empty status for empty vault", () => {
    const status = computeVaultStatus(vaultDir);
    expect(status.totalCredentials).toBe(0);
    expect(status.overdueCount).toBe(0);
    expect(status.credentials).toEqual([]);
  });

  it("should list credential names without values", () => {
    const config = readConfig(vaultDir);
    const tool = makeToolConfig("github", daysAgo(10), {
      label: "GitHub PAT",
      rotationIntervalDays: 90,
    });
    writeConfig(vaultDir, upsertTool(config, tool));

    const status = computeVaultStatus(vaultDir);
    expect(status.totalCredentials).toBe(1);
    expect(status.credentials[0].name).toBe("github");
    expect(status.credentials[0].label).toBe("GitHub PAT");

    const json = JSON.stringify(status);
    expect(json).not.toContain("sk_live");
    expect(json).not.toContain("ghp_");
  });

  it("should report overdue credentials", () => {
    const config = readConfig(vaultDir);
    const fresh = makeToolConfig("fresh", daysAgo(10), { rotationIntervalDays: 90 });
    const overdue = makeToolConfig("overdue", daysAgo(100), { rotationIntervalDays: 90 });
    let updated = upsertTool(config, fresh);
    updated = upsertTool(updated, overdue);
    writeConfig(vaultDir, updated);

    const status = computeVaultStatus(vaultDir);
    expect(status.overdueCount).toBe(1);

    const freshCred = status.credentials.find((c) => c.name === "fresh")!;
    expect(freshCred.isOverdue).toBe(false);

    const overdueCred = status.credentials.find((c) => c.name === "overdue")!;
    expect(overdueCred.isOverdue).toBe(true);
    expect(overdueCred.daysOverdue).toBeGreaterThanOrEqual(10);
  });

  it("should include last access times from audit log", () => {
    const config = readConfig(vaultDir);
    writeConfig(vaultDir, upsertTool(config, makeToolConfig("github", daysAgo(10))));

    const accessEvent: AuditCredentialAccess = {
      type: "credential_access",
      timestamp: "2026-03-09T18:30:00Z",
      tool: "exec",
      credential: "github",
      injectionType: "exec-env",
      command: "gh pr list",
      sessionKey: "test",
      durationMs: 100,
      success: true,
    };
    writeAuditEvent(accessEvent, vaultDir);

    const status = computeVaultStatus(vaultDir);
    expect(status.credentials.find((c) => c.name === "github")!.lastAccess).toBe("2026-03-09T18:30:00Z");
  });

  it("should include rotation metadata in status", () => {
    const config = readConfig(vaultDir);
    const tool = makeToolConfig("stripe", daysAgo(50), {
      rotationIntervalDays: 60,
      rotationSupport: "manual",
      revokeUrl: "https://dashboard.stripe.com/apikeys",
      scopes: ["read_write"],
      rotationProcedure: "Go to Stripe dashboard",
    });
    writeConfig(vaultDir, upsertTool(config, tool));

    const status = computeVaultStatus(vaultDir);
    const cred = status.credentials[0];
    expect(cred.rotationIntervalDays).toBe(60);
    expect(cred.rotationSupport).toBe("manual");
    expect(cred.revokeUrl).toBe("https://dashboard.stripe.com/apikeys");
    expect(cred.scopes).toEqual(["read_write"]);
    expect(cred.rotationProcedure).toBe("Go to Stripe dashboard");
  });

  it("should create a valid agent tool definition", () => {
    const tool = createVaultStatusTool();
    expect(tool.name).toBe("vault_status");
    expect(tool.label).toBe("Vault Status");
    expect(tool.description).toBeTruthy();
    expect(typeof tool.execute).toBe("function");
  });

  it("should compute overdue status correctly", () => {
    const config = readConfig(vaultDir);
    writeConfig(vaultDir, upsertTool(config, makeToolConfig("github", daysAgo(100), {
      label: "GitHub PAT",
      rotationIntervalDays: 90,
    })));

    const status = computeVaultStatus(vaultDir);
    expect(status.credentials[0].isOverdue).toBe(true);
  });
});

describe("gateway_start rotation warnings", () => {
  let vaultDir: string;

  beforeEach(() => { vaultDir = makeTempVault(); });
  afterEach(() => { fs.rmSync(vaultDir, { recursive: true, force: true }); });

  it("should use per-credential rotation intervals", () => {
    const config = readConfig(vaultDir);
    const shortInterval = makeToolConfig("api-key", daysAgo(40), { rotationIntervalDays: 30 });
    const longInterval = makeToolConfig("cert", daysAgo(100), { rotationIntervalDays: 180 });

    let updated = upsertTool(config, shortInterval);
    updated = upsertTool(updated, longInterval);
    writeConfig(vaultDir, updated);

    const overdue = getOverdueCredentials(readConfig(vaultDir));
    expect(overdue).toHaveLength(1);
    expect(overdue[0].name).toBe("api-key");
  });
});
