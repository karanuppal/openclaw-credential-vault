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
  const parsed = YAML.parse(raw);
  if (!parsed || typeof parsed !== "object") {
    return { ...DEFAULT_CONFIG, tools: {} };
  }
  return {
    version: parsed.version ?? 1,
    masterKeyMode: parsed.masterKeyMode ?? "machine",
    resolverMode: parsed.resolverMode ?? "inline",
    resolverPath: parsed.resolverPath,
    tools: parsed.tools ?? {},
  };
}

/**
 * Write the config to tools.yaml.
 */
export function writeConfig(vaultDir: string, config: VaultConfig): void {
  const configPath = getConfigPath(vaultDir);
  fs.mkdirSync(vaultDir, { recursive: true });
  const yamlStr = YAML.stringify(config, { indent: 2 });
  fs.writeFileSync(configPath, yamlStr, "utf8");
  fs.chmodSync(configPath, 0o600);
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
 * Send SIGUSR2 to the gateway process for hot-reload.
 */
export function signalGatewayReload(): boolean {
  try {
    const pidFile = path.join(
      process.env.HOME ?? "~",
      ".openclaw",
      "gateway.pid"
    );
    if (!fs.existsSync(pidFile)) return false;
    const pid = parseInt(fs.readFileSync(pidFile, "utf8").trim(), 10);
    if (isNaN(pid)) return false;
    process.kill(pid, "SIGUSR2");
    return true;
  } catch {
    return false;
  }
}
