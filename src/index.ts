/**
 * OpenClaw Credential Vault Plugin — Entry Point
 *
 * Registers plugin hooks for credential injection and output scrubbing,
 * plus CLI commands for vault management.
 */

import { readConfig, getVaultDir, readMeta } from "./config.js";
import { readCredentialFile, getMachinePassphrase } from "./crypto.js";
import { resolveViaRustBinary } from "./resolver.js";
import { findMatchingRules } from "./registry.js";
import {
  compileScrubRules,
  scrubText,
  scrubObject,
  scrubLiteralCredential,
  CompiledScrubRule,
} from "./scrubber.js";
import { registerCliCommands } from "./cli.js";
import { PluginApi, VaultConfig, ToolConfig } from "./types.js";

/** In-memory state for the running plugin */
interface VaultState {
  config: VaultConfig;
  scrubRules: CompiledScrubRule[];
  vaultDir: string;
  passphrase: string;
  /** Credential resolution mode: "inline" (Phase 1) or "binary" (Phase 2) */
  resolverMode: "inline" | "binary";
  /** Custom path to Rust resolver binary */
  resolverPath?: string;
  /** Cache of decrypted credentials to avoid repeated Argon2id derivation */
  credentialCache: Map<string, string>;
}

let state: VaultState | null = null;

/**
 * Load or reload vault state from disk.
 */
function loadState(): VaultState | null {
  const vaultDir = getVaultDir();
  const config = readConfig(vaultDir);
  const meta = readMeta(vaultDir);

  if (!meta) {
    // Vault not initialized
    return null;
  }

  let passphrase: string;
  if (meta.masterKeyMode === "passphrase") {
    const envPass = process.env.OPENCLAW_VAULT_PASSPHRASE;
    if (!envPass) return null; // Can't decrypt without passphrase
    passphrase = envPass;
  } else {
    passphrase = getMachinePassphrase(meta.installTimestamp);
  }

  const scrubRules = compileScrubRules(config.tools);

  return {
    config,
    scrubRules,
    vaultDir,
    passphrase,
    resolverMode: config.resolverMode ?? "inline",
    resolverPath: config.resolverPath,
    credentialCache: new Map(),
  };
}

/**
 * Get (or decrypt and cache) a credential for a tool.
 * In "inline" mode (Phase 1): decrypts directly in TypeScript.
 * In "binary" mode (Phase 2): delegates to the Rust resolver binary.
 */
async function getCredential(
  toolName: string,
  st: VaultState,
  context?: string,
  command?: string
): Promise<string | null> {
  if (st.credentialCache.has(toolName)) {
    return st.credentialCache.get(toolName)!;
  }
  try {
    let cred: string | null;

    if (st.resolverMode === "binary") {
      // Phase 2: delegate to Rust resolver binary
      const result = await resolveViaRustBinary(
        toolName,
        context ?? "unknown",
        command ?? "",
        st.resolverPath
      );
      cred = result?.credential ?? null;
    } else {
      // Phase 1: decrypt in-process
      cred = await readCredentialFile(st.vaultDir, toolName, st.passphrase);
    }

    if (cred) {
      st.credentialCache.set(toolName, cred);
    }
    return cred;
  } catch {
    return null;
  }
}

/**
 * Resolve a $vault:toolname reference to the actual credential.
 */
async function resolveVaultRef(
  value: string,
  st: VaultState,
  context?: string,
  command?: string
): Promise<string> {
  const match = value.match(/^\$vault:(.+)$/);
  if (!match) return value;
  const cred = await getCredential(match[1], st, context, command);
  return cred ?? value; // Return original if can't resolve
}

/**
 * before_tool_call handler: inject credentials into tool call parameters.
 */
async function handleBeforeToolCall(
  toolCall: Record<string, unknown>
): Promise<Record<string, unknown>> {
  if (!state) return toolCall;

  const toolName = String(toolCall.tool ?? "");
  const params = (toolCall.params ?? {}) as Record<string, unknown>;

  // Collect all injection rules from all configured tools
  for (const [vaultToolName, toolConfig] of Object.entries(
    state.config.tools
  )) {
    const matchingRules = findMatchingRules(
      toolName,
      params,
      toolConfig.inject
    );

    for (const rule of matchingRules) {
      // Build context info for binary resolver
      const cmdStr = String(params.command ?? params.url ?? "");

      // Inject environment variables
      if (rule.env) {
        const existingEnv = (params.env ?? {}) as Record<string, string>;
        for (const [envKey, envVal] of Object.entries(rule.env)) {
          const resolved = await resolveVaultRef(envVal, state, toolName, cmdStr);
          existingEnv[envKey] = resolved;
        }
        params.env = existingEnv;
      }

      // Inject headers
      if (rule.headers) {
        const existingHeaders = (params.headers ?? {}) as Record<
          string,
          string
        >;
        for (const [headerKey, headerVal] of Object.entries(rule.headers)) {
          const resolved = await resolveVaultRef(headerVal, state, toolName, cmdStr);
          existingHeaders[headerKey] = resolved;
        }
        params.headers = existingHeaders;
      }
    }
  }

  return { ...toolCall, params };
}

/**
 * after_tool_call handler: scrub credentials from tool output.
 */
function handleAfterToolCall(result: unknown): unknown {
  if (!state) return result;
  return scrubObject(result, state.scrubRules);
}

/**
 * tool_result_persist handler: final scrub before writing to session transcript.
 */
function handleToolResultPersist(result: unknown): unknown {
  if (!state) return result;

  let scrubbed = scrubObject(result, state.scrubRules);

  // Also scrub literal cached credentials
  if (typeof scrubbed === "string") {
    for (const [toolName, cred] of state.credentialCache.entries()) {
      scrubbed = scrubLiteralCredential(
        scrubbed as string,
        cred,
        toolName
      );
    }
  }

  return scrubbed;
}

/**
 * message_sending handler: scrub credentials from outbound messages.
 */
function handleMessageSending(message: unknown): unknown {
  if (!state) return message;

  if (typeof message === "string") {
    let result = scrubText(message, state.scrubRules);
    for (const [toolName, cred] of state.credentialCache.entries()) {
      result = scrubLiteralCredential(result, cred, toolName);
    }
    return result;
  }

  return scrubObject(message, state.scrubRules);
}

/**
 * Plugin registration function — the main entry point.
 */
export default function register(api: PluginApi): void {
  // Load initial state
  state = loadState();

  // Register agent lifecycle hooks at priority 10 (runs first)
  api.on("before_tool_call", handleBeforeToolCall, { priority: 10 });
  api.on("after_tool_call", handleAfterToolCall, { priority: 10 });
  api.on("tool_result_persist", handleToolResultPersist, { priority: 10 });
  api.on("message_sending", handleMessageSending, { priority: 10 });

  // Register CLI commands
  api.registerCli(
    ({ program }) => {
      registerCliCommands(program);
    },
    { commands: ["vault"] }
  );

  // Hot-reload: listen for SIGUSR2 to reload config
  process.on("SIGUSR2", () => {
    const newState = loadState();
    if (newState) {
      // Preserve credential cache from old state if passphrase unchanged
      if (state && state.passphrase === newState.passphrase) {
        newState.credentialCache = state.credentialCache;
      }
      state = newState;
      console.log("[vault] Config reloaded via SIGUSR2");
    }
  });
}
