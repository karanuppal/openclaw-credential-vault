/**
 * Configuration manager: tools.yaml read/write + hot-reload support.
 */

import * as fs from "node:fs";
import * as path from "node:path";
import YAML from "yaml";
import { VaultConfig, ToolConfig } from "./types.js";

const DEFAULT_CONFIG: VaultConfig = {
  version: 1,
  masterKeyMode: "machine",
  tools: {},
};

/**
 * Get the default vault directory path.
 */
export function getVaultDir(): string {
  const home = process.env.HOME ?? process.env.USERPROFILE ?? "~";
  return path.join(home, ".openclaw", "vault");
}

/**
 * Get the tools.yaml path for a vault directory.
 */
export function getConfigPath(vaultDir: string): string {
  return path.join(vaultDir, "tools.yaml");
}

/**
 * Read and parse tools.yaml. Returns default config if file doesn't exist.
 */
export function readConfig(vaultDir: string): VaultConfig {
  const configPath = getConfigPath(vaultDir);
  if (!fs.existsSync(configPath)) {
    return { ...DEFAULT_CONFIG, tools: {} };
  }
  const raw = fs.readFileSync(configPath, "utf8");
  let parsed: any;
  try {
    parsed = YAML.parse(raw);
  } catch (yamlErr: unknown) {
    // Corrupted YAML: try to recover from backup
    const backupPath = configPath + ".bak";
    if (fs.existsSync(backupPath)) {
      try {
        const backupRaw = fs.readFileSync(backupPath, "utf8");
        parsed = YAML.parse(backupRaw);
        // Restore from backup
        fs.writeFileSync(configPath, backupRaw, "utf8");
        console.error(`[vault] tools.yaml was corrupted — restored from backup`);
      } catch {
        throw yamlErr; // Backup also corrupted, throw original error
      }
    } else {
      throw yamlErr;
    }
  }
  if (!parsed || typeof parsed !== "object") {
    return { ...DEFAULT_CONFIG, tools: {} };
  }
  const tools = parsed.tools ?? {};
  for (const [, tool] of Object.entries(tools)) {
    const t = tool as any;
    if (t && typeof t === "object" && !t.rotation) {
      t.rotation = {};
    }
  }

  return {
    version: parsed.version ?? 1,
    masterKeyMode: parsed.masterKeyMode ?? "machine",
    resolverMode: parsed.resolverMode ?? "inline",
    resolverPath: parsed.resolverPath,
    tools,
  };
}

/**
 * Write the config to tools.yaml.
 */
export function writeConfig(vaultDir: string, config: VaultConfig): void {
  const configPath = getConfigPath(vaultDir);
  fs.mkdirSync(vaultDir, { recursive: true });
  // Keep a backup of the last known-good config for corruption recovery
  if (fs.existsSync(configPath)) {
    try { fs.copyFileSync(configPath, configPath + ".bak"); } catch { /* best-effort */ }
  }
  const yamlStr = YAML.stringify(config, { indent: 2 });
  // Atomic write: write to temp file, then rename. Prevents corruption
  // if the process crashes mid-write (rename is atomic on POSIX).
  const tmpPath = configPath + ".tmp";
  fs.writeFileSync(tmpPath, yamlStr, "utf8");
  fs.chmodSync(tmpPath, 0o600);
  fs.renameSync(tmpPath, configPath);
}

/**
 * Add or update a tool in the config.
 */
export function upsertTool(
  config: VaultConfig,
  tool: ToolConfig
): VaultConfig {
  return {
    ...config,
    tools: {
      ...config.tools,
      [tool.name]: tool,
    },
  };
}

/**
 * Remove a tool from the config.
 */
export function removeTool(
  config: VaultConfig,
  toolName: string
): VaultConfig {
  const { [toolName]: _removed, ...rest } = config.tools;
  return {
    ...config,
    tools: rest,
  };
}

/**
 * Initialize vault config with the specified key mode.
 */
export function initConfig(
  vaultDir: string,
  masterKeyMode: "passphrase" | "machine",
  installTimestamp?: string
): VaultConfig {
  const config: VaultConfig = {
    version: 1,
    masterKeyMode,
    tools: {},
  };

  // Write metadata file with install timestamp (for machine key derivation)
  const metaPath = path.join(vaultDir, ".vault-meta.json");
  const meta = {
    createdAt: new Date().toISOString(),
    installTimestamp: installTimestamp ?? new Date().toISOString(),
    masterKeyMode,
  };
  fs.mkdirSync(vaultDir, { recursive: true });
  fs.writeFileSync(metaPath, JSON.stringify(meta, null, 2), "utf8");
  fs.chmodSync(metaPath, 0o600);

  writeConfig(vaultDir, config);
  return config;
}

/**
 * Read the vault metadata (install timestamp, etc).
 */
export function readMeta(
  vaultDir: string
): { createdAt: string; installTimestamp: string; masterKeyMode: string } | null {
  const metaPath = path.join(vaultDir, ".vault-meta.json");
  if (!fs.existsSync(metaPath)) return null;
  try {
    return JSON.parse(fs.readFileSync(metaPath, "utf8"));
  } catch {
    return null;
  }
}

/**
 * Check which credentials are overdue for rotation.
 */
export function getOverdueCredentials(
  config: VaultConfig,
  defaultIntervalDays = 90
): Array<{
  name: string;
  label?: string;
  lastRotated: string;
  rotationIntervalDays: number;
  daysSinceRotation: number;
  daysOverdue: number;
  rotationProcedure?: string;
  revokeUrl?: string;
  rotationSupport?: string;
  scopes?: string[];
}> {
  const now = Date.now();
  const results: Array<{
    name: string;
    label?: string;
    lastRotated: string;
    rotationIntervalDays: number;
    daysSinceRotation: number;
    daysOverdue: number;
    rotationProcedure?: string;
    revokeUrl?: string;
    rotationSupport?: string;
    scopes?: string[];
  }> = [];

  for (const [name, tool] of Object.entries(config.tools)) {
    const intervalDays = tool.rotation?.rotationIntervalDays ?? defaultIntervalDays;
    if (!tool.lastRotated) continue;

    const lastRotatedMs = new Date(tool.lastRotated).getTime();
    const daysSince = Math.floor((now - lastRotatedMs) / (1000 * 60 * 60 * 24));

    if (daysSince > intervalDays) {
      results.push({
        name,
        label: tool.rotation?.label,
        lastRotated: tool.lastRotated,
        rotationIntervalDays: intervalDays,
        daysSinceRotation: daysSince,
        daysOverdue: daysSince - intervalDays,
        rotationProcedure: tool.rotation?.rotationProcedure,
        revokeUrl: tool.rotation?.revokeUrl,
        rotationSupport: tool.rotation?.rotationSupport,
        scopes: tool.rotation?.scopes,
      });
    }
  }

  return results;
}

/**
 * Send SIGUSR2 to the gateway process for hot-reload.
 */
export function signalGatewayReload(): boolean {
  try {
    // Only signal the gateway if it's running under our HOME.
    // When CLI runs with a different HOME (isolated testing), skip the signal
    // to avoid corrupting the real gateway's in-memory state with rapid reloads.
    const pidFile = path.join(
      process.env.HOME ?? "~",
      ".openclaw",
      "gateway.pid"
    );
    let pid: number | undefined;
    if (fs.existsSync(pidFile)) {
      pid = parseInt(fs.readFileSync(pidFile, "utf8").trim(), 10);
      if (isNaN(pid)) pid = undefined;
    }
    // Only use PID file — no pgrep fallback.
    // pgrep can find gateways belonging to other HOME dirs and signal them,
    // which corrupts their state when CLI is running in an isolated environment.
    if (!pid) return false;
    process.kill(pid, "SIGUSR2");
    return true;
  } catch {
    return false;
  }
}
