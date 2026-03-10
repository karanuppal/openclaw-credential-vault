/**
 * OpenClaw Credential Vault Plugin — Entry Point
 *
 * Registers plugin hooks for credential injection and output scrubbing,
 * plus CLI commands for vault management.
 *
 * Hook priorities (per spec v4.5.4):
 * - Injection (before_tool_call): priority 10 — runs LAST (inject as late as possible)
 * - Scrubbing (after_tool_call, tool_result_persist, before_message_write, message_sending): priority 1 — runs FIRST (scrub before other plugins)
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
  scrubTextWithTracking,
  addLiteralCredential,
  CompiledScrubRule,
} from "./scrubber.js";
import { registerCliCommands } from "./cli.js";
import { logCredentialAccess, logScrubEvent, logCompactionEvent } from "./audit.js";
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
  /** Track which credentials were injected in the current tool call (for audit) */
  currentInjections: Array<{
    tool: string;
    credential: string;
    injectionType: string;
    command: string;
    startTime: number;
  }>;
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
    currentInjections: [],
  };
}

/**
 * Get (or decrypt and cache) a credential for a tool.
 * In "inline" mode (Phase 1): decrypts directly in TypeScript.
 * In "binary" mode (Phase 2): delegates to the Rust resolver binary.
 *
 * On successful decrypt, adds the credential to the literal match set.
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
      // Phase 3E: Add to literal match set for hash-based scrubbing
      addLiteralCredential(cred, toolName);
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
 * Scrub credential patterns from write/edit tool content (Phase 3D).
 */
function scrubWriteEditContent(
  params: Record<string, unknown>,
  st: VaultState
): { params: Record<string, unknown>; modified: boolean } {
  // Determine which parameter contains the content
  const contentKeys = ["content", "newText", "new_string"];
  let modified = false;

  for (const key of contentKeys) {
    const value = params[key];
    if (typeof value === "string") {
      let scrubbed = scrubText(value, st.scrubRules);
      // Also scrub literal cached credentials
      for (const [toolName, cred] of st.credentialCache.entries()) {
        scrubbed = scrubLiteralCredential(scrubbed, cred, toolName);
      }
      if (scrubbed !== value) {
        params = { ...params, [key]: scrubbed };
        modified = true;
      }
    }
  }

  return { params, modified };
}

/**
 * before_tool_call handler: inject credentials into tool call parameters
 * AND scrub write/edit tool content (Phase 3D).
 */
async function handleBeforeToolCall(
  toolCall: Record<string, unknown>
): Promise<Record<string, unknown>> {
  if (!state) return toolCall;

  const toolName = String(toolCall.tool ?? "");
  let params = (toolCall.params ?? {}) as Record<string, unknown>;

  // Phase 3D: Intercept write/edit tools — scrub credential patterns from content
  if (toolName === "write" || toolName === "edit") {
    const { params: scrubbedParams, modified } = scrubWriteEditContent(params, state);
    if (modified) {
      params = scrubbedParams;
    }
  }

  // Reset current injections tracking
  state.currentInjections = [];

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
      const startTime = Date.now();

      // Inject environment variables
      if (rule.env) {
        const existingEnv = (params.env ?? {}) as Record<string, string>;
        for (const [envKey, envVal] of Object.entries(rule.env)) {
          const resolved = await resolveVaultRef(envVal, state, toolName, cmdStr);
          existingEnv[envKey] = resolved;
        }
        params.env = existingEnv;

        // Track injection for audit
        state.currentInjections.push({
          tool: toolName,
          credential: vaultToolName,
          injectionType: "exec-env",
          command: cmdStr,
          startTime,
        });
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

        // Track injection for audit
        state.currentInjections.push({
          tool: toolName,
          credential: vaultToolName,
          injectionType: "http-header",
          command: cmdStr,
          startTime,
        });
      }
    }
  }

  return { ...toolCall, params };
}

/**
 * after_tool_call handler: scrub credentials from tool output + audit logging.
 */
function handleAfterToolCall(result: unknown): unknown {
  if (!state) return result;

  // Phase 3C: Audit logging for credential access events
  const now = Date.now();
  for (const injection of state.currentInjections) {
    logCredentialAccess({
      tool: injection.tool,
      credential: injection.credential,
      injectionType: injection.injectionType,
      command: injection.command,
      durationMs: now - injection.startTime,
      success: true,
    }, state.vaultDir);
  }
  state.currentInjections = [];

  // Scrub output with tracking for audit
  if (typeof result === "string") {
    const { text, replacements } = scrubTextWithTracking(result, state.scrubRules);
    // Log scrub events
    for (const r of replacements) {
      logScrubEvent({
        hook: "after_tool_call",
        credential: r.toolName,
        pattern: r.pattern,
        replacements: r.count,
      }, state.vaultDir);
    }
    return text;
  }

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
 * before_message_write handler (Phase 3C): scrub ALL messages before transcript write.
 * Priority 1 — runs FIRST before other plugins.
 */
function handleBeforeMessageWrite(message: unknown): unknown {
  if (!state) return message;

  if (typeof message === "string") {
    const { text, replacements } = scrubTextWithTracking(message, state.scrubRules);
    // Also scrub literal cached credentials
    let result = text;
    for (const [toolName, cred] of state.credentialCache.entries()) {
      result = scrubLiteralCredential(result, cred, toolName);
    }
    // Log scrub events
    for (const r of replacements) {
      logScrubEvent({
        hook: "before_message_write",
        credential: r.toolName,
        pattern: r.pattern,
        replacements: r.count,
      }, state.vaultDir);
    }
    return result;
  }

  return scrubObject(message, state.scrubRules);
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
 * after_compaction handler (Phase 3C): log that compaction occurred with scrubbing active.
 */
function handleAfterCompaction(event: unknown): void {
  if (!state) return;

  logCompactionEvent({
    scrubbingActive: state.scrubRules.length > 0,
  }, state.vaultDir);
}

/**
 * gateway_start handler (Phase 3C): validate vault accessibility + rotation check + cache warm.
 */
async function handleGatewayStart(): Promise<void> {
  if (!state) {
    console.log("[vault] Vault not initialized — skipping gateway_start checks");
    return;
  }

  console.log("[vault] Gateway start — validating vault...");

  // 1. Validate vault directory accessibility
  const { existsSync, statSync } = await import("node:fs");
  if (!existsSync(state.vaultDir)) {
    console.warn("[vault] ⚠ Vault directory not found:", state.vaultDir);
    return;
  }

  // 2. Check rotation status for all tools
  const now = Date.now();
  const ROTATION_WARN_DAYS = 90;
  for (const [name, tool] of Object.entries(state.config.tools)) {
    if (tool.lastRotated) {
      const age = now - new Date(tool.lastRotated).getTime();
      const days = Math.floor(age / (1000 * 60 * 60 * 24));
      if (days > ROTATION_WARN_DAYS) {
        console.warn(`[vault] ⚠ Tool "${name}" last rotated ${days} days ago (>${ROTATION_WARN_DAYS}d)`);
      }
    }
  }

  // 3. Cache warm: pre-decrypt all credentials
  for (const toolName of Object.keys(state.config.tools)) {
    try {
      await getCredential(toolName, state, "gateway_start", "");
    } catch {
      console.warn(`[vault] ⚠ Failed to warm cache for tool "${toolName}"`);
    }
  }

  console.log(`[vault] Vault ready — ${Object.keys(state.config.tools).length} tool(s) loaded`);
}

/**
 * Plugin registration function — the main entry point.
 */
export default function register(api: PluginApi): void {
  // Load initial state
  state = loadState();

  // Injection hooks: priority 10 (runs LAST — inject right before execution)
  api.on("before_tool_call", handleBeforeToolCall, { priority: 10 });

  // Scrubbing hooks: priority 1 (runs FIRST — scrub before other plugins)
  api.on("after_tool_call", handleAfterToolCall, { priority: 1 });
  api.on("tool_result_persist", handleToolResultPersist, { priority: 1 });
  api.on("before_message_write", handleBeforeMessageWrite, { priority: 1 });
  api.on("message_sending", handleMessageSending, { priority: 1 });

  // Observation hooks
  api.on("after_compaction", handleAfterCompaction);
  api.on("gateway_start", handleGatewayStart);

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

// Export for testing
export {
  loadState,
  handleBeforeToolCall,
  handleAfterToolCall,
  handleToolResultPersist,
  handleBeforeMessageWrite,
  handleMessageSending,
  handleAfterCompaction,
  handleGatewayStart,
  scrubWriteEditContent,
  state as _state,
};
