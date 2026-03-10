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

import { readConfig, getVaultDir, readMeta, getOverdueCredentials } from "./config.js";
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
import { createVaultStatusTool } from "./vault-status.js";
import { PluginApi, VaultConfig, ToolConfig, PlaywrightCookie } from "./types.js";
import {
  isVaultPlaceholder,
  extractVaultName,
  resolveBrowserPassword,
  findBrowserPasswordRule,
  findAllBrowserCookieRules,
  shouldInjectCookies,
  removeExpiredCookies,
  filterCookiesByDomain,
} from "./browser.js";

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
 *
 * OpenClaw API signature:
 *   (event: {toolName, params, runId?, toolCallId?}, ctx: {agentId?, sessionKey?, sessionId?, runId?, toolName, toolCallId?})
 *   => {params?, block?, blockReason?} | void
 */
async function handleBeforeToolCall(
  event: { toolName: string; params: Record<string, unknown>; runId?: string; toolCallId?: string },
  _ctx: { agentId?: string; sessionKey?: string; sessionId?: string; runId?: string; toolName: string; toolCallId?: string }
): Promise<{ params?: Record<string, unknown>; block?: boolean; blockReason?: string } | void> {
  if (!state) return;

  const toolName = event.toolName;
  let params = { ...event.params };

  // Phase 3D: Intercept write/edit tools — scrub credential patterns from content
  if (toolName === "write" || toolName === "edit") {
    const { params: scrubbedParams, modified } = scrubWriteEditContent(params, state);
    if (modified) {
      params = scrubbedParams;
    }
  }

  // Reset current injections tracking
  state.currentInjections = [];

  // --- Browser password: $vault: placeholder resolution ---
  if (toolName === "browser") {
    const action = String(params.action ?? "");
    const text = params.text as string | undefined;

    // Handle browser fill with $vault: placeholder
    if (
      (action === "act" || !action) &&
      text &&
      isVaultPlaceholder(text)
    ) {
      const vaultName = extractVaultName(text)!;
      // Find the browser-password rule for this credential
      const toolConfig = state.config.tools[vaultName];
      if (toolConfig) {
        const rule = findBrowserPasswordRule(vaultName, toolConfig.inject);
        if (rule && rule.domainPin) {
          // We need the current browser URL — it should be in params.url or
          // we check params.targetUrl for context
          const currentUrl = String(
            params.url ?? params.targetUrl ?? ""
          );
          const cred = await getCredential(vaultName, state, "browser", currentUrl);
          if (cred) {
            const result = resolveBrowserPassword(
              text,
              currentUrl,
              cred,
              rule.domainPin
            );
            if (result.allowed && result.resolvedValue) {
              params.text = result.resolvedValue;
            } else {
              // Block the action — return error instead of executing
              return {
                block: true,
                blockReason: result.error ?? "Domain pin check failed",
              };
            }
          }
        }
      }
    }

    // Handle nested request object (browser act with request param)
    const request = params.request as Record<string, unknown> | undefined;
    if (request && typeof request === "object") {
      const reqText = request.text as string | undefined;
      if (reqText && isVaultPlaceholder(reqText)) {
        const vaultName = extractVaultName(reqText)!;
        const toolConfig = state.config.tools[vaultName];
        if (toolConfig) {
          const rule = findBrowserPasswordRule(vaultName, toolConfig.inject);
          if (rule && rule.domainPin) {
            const currentUrl = String(
              request.url ?? params.url ?? params.targetUrl ?? ""
            );
            const cred = await getCredential(vaultName, state, "browser", currentUrl);
            if (cred) {
              const resolveResult = resolveBrowserPassword(
                reqText,
                currentUrl,
                cred,
                rule.domainPin
              );
              if (resolveResult.allowed && resolveResult.resolvedValue) {
                request.text = resolveResult.resolvedValue;
                params.request = request;
              } else {
                return {
                  block: true,
                  blockReason: resolveResult.error ?? "Domain pin check failed",
                };
              }
            }
          }
        }
      }
    }

    // --- Browser cookie injection on navigate ---
    if (action === "navigate") {
      const navUrl = String(params.url ?? "");
      if (navUrl) {
        const cookieRules = findAllBrowserCookieRules(state.config.tools);
        const cookiesToInject: PlaywrightCookie[] = [];

        for (const { vaultToolName, rule } of cookieRules) {
          if (rule.domainPin && shouldInjectCookies(navUrl, rule.domainPin)) {
            const cred = await getCredential(
              vaultToolName,
              state,
              "browser-cookie",
              navUrl
            );
            if (cred) {
              try {
                const cookieData = JSON.parse(cred);
                let cookies: PlaywrightCookie[];
                if (Array.isArray(cookieData)) {
                  cookies = cookieData;
                } else if (cookieData.cookies && Array.isArray(cookieData.cookies)) {
                  cookies = cookieData.cookies;
                } else {
                  continue;
                }
                // Remove expired, filter by domain
                const valid = filterCookiesByDomain(
                  removeExpiredCookies(cookies),
                  rule.domainPin
                );
                cookiesToInject.push(...valid);
              } catch {
                // Invalid cookie JSON — skip
              }
            }
          }
        }

        if (cookiesToInject.length > 0) {
          // Attach cookies to params for the browser tool to inject via addCookies()
          params._vaultCookies = cookiesToInject;
        }
      }
    }
  }

  // --- Standard exec/web_fetch injection (existing logic) ---
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

  return { params };
}

/**
 * after_tool_call handler: audit logging for credential access events.
 *
 * OpenClaw API signature:
 *   (event: {toolName, params, runId?, toolCallId?, result?, error?, durationMs?}, ctx: PluginHookToolContext)
 *   => void
 *
 * Note: after_tool_call cannot modify the result — it's observe-only.
 * Scrubbing of results happens in tool_result_persist instead.
 */
function handleAfterToolCall(
  event: { toolName: string; params: Record<string, unknown>; runId?: string; toolCallId?: string; result?: unknown; error?: string; durationMs?: number },
  _ctx: { agentId?: string; sessionKey?: string; sessionId?: string; runId?: string; toolName: string; toolCallId?: string }
): void {
  if (!state) return;

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
}

/**
 * tool_result_persist handler: final scrub before writing to session transcript.
 *
 * OpenClaw API signature:
 *   (event: {toolName?, toolCallId?, message: AgentMessage, isSynthetic?}, ctx: {agentId?, sessionKey?, toolName?, toolCallId?})
 *   => {message?: AgentMessage} | void
 */
function handleToolResultPersist(
  event: { toolName?: string; toolCallId?: string; message: Record<string, unknown>; isSynthetic?: boolean },
  _ctx: { agentId?: string; sessionKey?: string; toolName?: string; toolCallId?: string }
): { message?: Record<string, unknown> } | void {
  if (!state) return;

  // Deep-scrub the message object
  const scrubbed = scrubObject(event.message, state.scrubRules) as Record<string, unknown>;

  // Also scrub literal cached credentials from text content
  if (scrubbed && typeof scrubbed.content === "string") {
    let content = scrubbed.content as string;
    for (const [toolName, cred] of state.credentialCache.entries()) {
      content = scrubLiteralCredential(content, cred, toolName);
    }
    scrubbed.content = content;
  }
  // Handle array content (common in AgentMessage)
  if (scrubbed && Array.isArray(scrubbed.content)) {
    for (const part of scrubbed.content) {
      if (part && typeof part === "object" && typeof part.text === "string") {
        let text = part.text;
        for (const [toolName, cred] of state.credentialCache.entries()) {
          text = scrubLiteralCredential(text, cred, toolName);
        }
        part.text = text;
      }
    }
  }

  return { message: scrubbed };
}

/**
 * before_message_write handler (Phase 3C): scrub ALL messages before transcript write.
 * Priority 1 — runs FIRST before other plugins.
 *
 * OpenClaw API signature:
 *   (event: {message: AgentMessage, sessionKey?, agentId?}, ctx: {agentId?, sessionKey?})
 *   => {block?, message?: AgentMessage} | void
 */
function handleBeforeMessageWrite(
  event: { message: Record<string, unknown>; sessionKey?: string; agentId?: string },
  _ctx: { agentId?: string; sessionKey?: string }
): { block?: boolean; message?: Record<string, unknown> } | void {
  if (!state) return;

  const message = event.message;
  const scrubbed = scrubObject(message, state.scrubRules) as Record<string, unknown>;

  // Scrub literal cached credentials from text content fields
  if (scrubbed && typeof scrubbed.content === "string") {
    let content = scrubbed.content as string;
    const { text, replacements } = scrubTextWithTracking(content, state.scrubRules);
    content = text;
    for (const [toolName, cred] of state.credentialCache.entries()) {
      content = scrubLiteralCredential(content, cred, toolName);
    }
    for (const r of replacements) {
      logScrubEvent({
        hook: "before_message_write",
        credential: r.toolName,
        pattern: r.pattern,
        replacements: r.count,
      }, state.vaultDir);
    }
    scrubbed.content = content;
  }
  // Handle array content
  if (scrubbed && Array.isArray(scrubbed.content)) {
    for (const part of scrubbed.content) {
      if (part && typeof part === "object" && typeof part.text === "string") {
        let text = part.text;
        for (const [toolName, cred] of state.credentialCache.entries()) {
          text = scrubLiteralCredential(text, cred, toolName);
        }
        part.text = text;
      }
    }
  }

  return { message: scrubbed };
}

/**
 * message_sending handler: scrub credentials from outbound messages.
 *
 * OpenClaw API signature:
 *   (event: {to, content, metadata?}, ctx: {channelId, accountId?, conversationId?})
 *   => {content?, cancel?} | void
 */
function handleMessageSending(
  event: { to: string; content: string; metadata?: Record<string, unknown> },
  _ctx: { channelId: string; accountId?: string; conversationId?: string }
): { content?: string; cancel?: boolean } | void {
  if (!state) return;

  let content = event.content;
  if (typeof content === "string") {
    content = scrubText(content, state.scrubRules);
    for (const [_toolName, cred] of state.credentialCache.entries()) {
      content = scrubLiteralCredential(content, cred, _toolName);
    }
    if (content !== event.content) {
      return { content };
    }
  }
}

/**
 * after_compaction handler (Phase 3C): log that compaction occurred with scrubbing active.
 *
 * OpenClaw API signature:
 *   (event: {messageCount, tokenCount?, compactedCount, sessionFile?}, ctx: PluginHookAgentContext)
 *   => void
 */
function handleAfterCompaction(
  _event: { messageCount: number; tokenCount?: number; compactedCount: number; sessionFile?: string },
  _ctx: { agentId?: string; sessionKey?: string; sessionId?: string; workspaceDir?: string; messageProvider?: string; trigger?: string; channelId?: string }
): void {
  if (!state) return;

  logCompactionEvent({
    scrubbingActive: state.scrubRules.length > 0,
  }, state.vaultDir);
}

/**
 * gateway_start handler (Phase 3C): validate vault accessibility + rotation check + cache warm.
 *
 * OpenClaw API signature:
 *   (event: {port}, ctx: {port?})
 *   => void
 */
async function handleGatewayStart(
  _event: { port: number },
  _ctx: { port?: number }
): Promise<void> {
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

  // 2. Check rotation status for all tools using per-credential intervals
  const overdue = getOverdueCredentials(state.config);
  if (overdue.length > 0) {
    console.warn(`[vault] ⚠ ${overdue.length} credential(s) overdue for rotation:`);
    for (const cred of overdue) {
      const label = cred.label ? ` (${cred.label})` : "";
      console.warn(`[vault]   - ${cred.name}${label}: ${cred.daysSinceRotation} days since rotation (interval: ${cred.rotationIntervalDays}d, ${cred.daysOverdue}d overdue)`);
      if (cred.revokeUrl) {
        console.warn(`[vault]     Revoke: ${cred.revokeUrl}`);
      }
    }
    console.warn(`[vault] Run 'openclaw vault rotate --check' for details`);
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

  // Register vault_status agent tool
  api.registerTool(createVaultStatusTool(), {
    name: "vault_status",
    optional: true,
  });

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
