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

import { readConfig, getVaultDir, getConfigPath, readMeta, getOverdueCredentials } from "./config.js";
import { readCredentialFile, getMachinePassphrase } from "./crypto.js";
import { resolveViaRustBinary, PROTOCOL_VERSION } from "./resolver.js";
import type { ResolverResult } from "./resolver.js";
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
import { logCredentialAccess, logScrubEvent, logCompactionEvent, writeAuditEvent } from "./audit.js";
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

/**
 * Safely log vault errors when OPENCLAW_VAULT_DEBUG is set.
 * Writes to ~/.openclaw/vault/error.log (user-private) instead of /tmp.
 */
function logVaultError(hookName: string, err: unknown): void {
  if (process.env.OPENCLAW_VAULT_DEBUG) {
    try {
      const errFs = require("node:fs");
      const logPath = require("node:path").join(
        process.env.HOME ?? "/tmp", ".openclaw", "vault", "error.log"
      );
      errFs.appendFileSync(logPath,
        `[${new Date().toISOString()}] ${hookName} ERROR: ${(err as Error).message}\n${(err as Error).stack}\n\n`);
    } catch { /* ignore logging failures */ }
  }
}

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
  /** Failure policy for binary resolver: "block" (default) or "warn-and-inline" */
  onResolverFailure: "block" | "warn-and-inline";
  /** Cache of decrypted credentials to avoid repeated Argon2id derivation */
  credentialCache: Map<string, { value: string; cachedAt: number }>;
  /** Track which credentials were injected in the current tool call (for audit) */
  currentInjections: Array<{
    tool: string;
    credential: string;
    injectionType: string;
    command: string;
    startTime: number;
  }>;
  /** mtime of vault config file at last load — used for hot-reload detection */
  configMtimeMs: number;
  /** Track env vars injected into process.env for cleanup after tool call */
  injectedEnvVars: string[];
  /** Cache of browser tab URLs (targetId → last known URL) for domain-pin resolution */
  browserTabUrls: Map<string, string>;
}

let state: VaultState | null = null;

/**
 * Load or reload vault state from disk.
 */
function loadState(): VaultState | null {
  const vaultDir = getVaultDir();
  const config = readConfig(vaultDir);
  const meta = readMeta(vaultDir);
  const configPath = getConfigPath(vaultDir);
  let configMtimeMs = 0;
  try {
    const { statSync } = require("node:fs");
    configMtimeMs = statSync(configPath).mtimeMs;
  } catch { /* file may not exist yet */ }

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
    onResolverFailure: config.onResolverFailure ?? "block",
    credentialCache: new Map(),
    currentInjections: [],
    injectedEnvVars: [],
    browserTabUrls: new Map(),
    configMtimeMs,
  };
}

/**
 * Get (or decrypt and cache) a credential for a tool.
 * In "inline" mode (Phase 1): decrypts directly in TypeScript.
 * In "binary" mode (Phase 2): delegates to the Rust resolver binary.
 *
 * On successful decrypt, adds the credential to the literal match set.
 * On binary resolver failure, follows onResolverFailure policy.
 */
/** Credential cache TTL: 15 minutes. After this, credentials are re-decrypted. */
const CACHE_TTL_MS = 15 * 60 * 1000;

/** Track whether we've already shown the version mismatch warning this session */
let resolverMismatchWarned = false;

/**
 * Build a user-facing warning message for resolver failures.
 * Includes actionable fix instructions based on the error type.
 */
function buildResolverWarning(result: ResolverResult & { ok: false }, toolName: string): string {
  const lines: string[] = [];

  if (result.error === "PROTOCOL_MISMATCH") {
    lines.push(`⚠️ Vault resolver protocol mismatch for "${toolName}"`);
    lines.push(`   Plugin version: v${result.pluginVersion}, Resolver version: v${result.resolverVersion ?? "unknown"}`);

    if (result.resolverVersion !== null && result.pluginVersion > result.resolverVersion) {
      // Plugin is newer — user updated npm but not the binary
      lines.push(`   Fix: Rebuild the resolver binary to match the plugin:`);
      lines.push(`         sudo bash vault-setup.sh`);
    } else if (result.resolverVersion !== null && result.pluginVersion < result.resolverVersion) {
      // Resolver is newer — user rebuilt binary but not the plugin
      lines.push(`   Fix: Update the plugin to match the resolver:`);
      lines.push(`         npm update openclaw-credential-vault`);
    } else {
      lines.push(`   Fix: Ensure both plugin and resolver are the same version.`);
      lines.push(`         Plugin: npm update openclaw-credential-vault`);
      lines.push(`         Resolver: sudo bash vault-setup.sh`);
    }
  } else if (result.error === "NOT_FOUND") {
    lines.push(`⚠️ Vault resolver binary not found for "${toolName}"`);
    lines.push(`   Binary mode is configured but the resolver is not installed.`);
    lines.push(`   Fix: Install the resolver: sudo bash vault-setup.sh`);
    lines.push(`   Or switch to inline mode: set resolverMode: "inline" in tools.yaml`);
  } else {
    lines.push(`⚠️ Vault resolver failed for "${toolName}": ${result.message}`);
  }

  return lines.join("\n");
}

/** Result from getCredential — includes warning text if resolver failed with fallback */
interface CredentialResult {
  credential: string | null;
  /** Warning to inject into tool output (only set on resolver failure) */
  warning: string | null;
  /** Whether a security downgrade occurred (inline fallback in binary mode) */
  securityDowngrade: boolean;
}

async function getCredential(
  toolName: string,
  st: VaultState,
  context?: string,
  command?: string
): Promise<CredentialResult> {
  const cached = st.credentialCache.get(toolName);
  if (cached && (Date.now() - cached.cachedAt) < CACHE_TTL_MS) {
    return { credential: cached.value, warning: null, securityDowngrade: false };
  }
  // Evict expired entry
  if (cached) st.credentialCache.delete(toolName);

  try {
    let cred: string | null;
    let warning: string | null = null;
    let securityDowngrade = false;

    if (st.resolverMode === "binary") {
      // Phase 2: delegate to Rust resolver binary
      const result = await resolveViaRustBinary(
        toolName,
        context ?? "unknown",
        command ?? "",
        st.resolverPath
      );

      if (result.ok) {
        cred = result.credential;
      } else {
        // Resolver failed — build warning and decide on fallback
        warning = buildResolverWarning(result, toolName);
        console.error(`[vault] ${warning}`);

        // Log to audit
        writeAuditEvent({
          type: "resolver_failure",
          timestamp: new Date().toISOString(),
          tool: toolName,
          error: result.error,
          message: result.message,
          pluginVersion: result.pluginVersion,
          resolverVersion: result.resolverVersion,
          policy: st.onResolverFailure,
        }, st.vaultDir);

        // Log prominent warning on first mismatch
        if (result.error === "PROTOCOL_MISMATCH" && !resolverMismatchWarned) {
          resolverMismatchWarned = true;
          console.error(
            "\n" +
            "╔══════════════════════════════════════════════════════════════╗\n" +
            "║  VAULT: Protocol version mismatch detected!                ║\n" +
            `║  Plugin v${result.pluginVersion} ≠ Resolver v${String(result.resolverVersion ?? "?").padEnd(40)}║\n` +
            "║  Credentials will NOT be injected until this is fixed.     ║\n" +
            "║  Run: sudo bash vault-setup.sh (or npm update the plugin)  ║\n" +
            "╠══════════════════════════════════════════════════════════════╣\n" +
            `║  Policy: ${st.onResolverFailure.padEnd(50)}║\n` +
            "╚══════════════════════════════════════════════════════════════╝\n"
          );
        }

        if (st.onResolverFailure === "warn-and-inline") {
          // Fallback to inline decryption — security downgrade
          console.error(`[vault] Falling back to inline decryption for "${toolName}" (security downgrade)`);
          cred = await readCredentialFile(st.vaultDir, toolName, st.passphrase);
          securityDowngrade = true;
          warning += `\n   ⚠️ SECURITY DOWNGRADE: Fell back to inline decryption (bypasses OS-user isolation).`;

          writeAuditEvent({
            type: "security_downgrade",
            timestamp: new Date().toISOString(),
            tool: toolName,
            reason: "resolver_failure_inline_fallback",
            originalError: result.error,
          }, st.vaultDir);
        } else {
          // Block — credential not injected
          cred = null;
          warning += `\n   Credential NOT injected. The command will run without authentication.`;
        }
      }
    } else {
      // Phase 1: decrypt in-process (inline mode)
      cred = await readCredentialFile(st.vaultDir, toolName, st.passphrase);
    }

    if (cred) {
      st.credentialCache.set(toolName, { value: cred, cachedAt: Date.now() });
      // Phase 3E: Add to literal match set for hash-based scrubbing
      addLiteralCredential(cred, toolName);
    }
    return { credential: cred, warning, securityDowngrade };
  } catch {
    return { credential: null, warning: null, securityDowngrade: false };
  }
}

/**
 * Resolve a $vault:toolname reference to the actual credential.
 */
/** Accumulated resolver warnings for the current tool call */
let pendingResolverWarnings: string[] = [];

/** Reset resolver state — for testing only */
function _resetResolverState(): void {
  pendingResolverWarnings = [];
  resolverMismatchWarned = false;
}

async function resolveVaultRef(
  value: string,
  st: VaultState,
  context?: string,
  command?: string
): Promise<string> {
  const match = value.match(/^\$vault:(.+)$/);
  if (!match) return value;
  const result = await getCredential(match[1], st, context, command);
  if (result.warning) {
    pendingResolverWarnings.push(result.warning);
  }
  return result.credential ?? value; // Return original if can't resolve
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
        scrubbed = scrubLiteralCredential(scrubbed, cred.value, toolName);
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
  try {
  if (!state) return;

  // Hot-reload: re-read config if vault.json changed on disk (e.g. after `vault add`)
  try {
    const { statSync } = require("node:fs");
    const currentMtime = statSync(getConfigPath(state.vaultDir)).mtimeMs;
    if (currentMtime > state.configMtimeMs) {
      const newConfig = readConfig(state.vaultDir);
      state.config = newConfig;
      state.scrubRules = compileScrubRules(newConfig.tools);
      state.configMtimeMs = currentMtime;
      // Clear credential cache so new tools get decrypted fresh
      state.credentialCache.clear();
      console.log(`[vault] Config hot-reloaded — ${Object.keys(newConfig.tools).length} tool(s)`);
    }
  } catch { /* stat failure is non-fatal */ }

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
          // We need the current browser URL — check params first, then cached tab URL
          const targetId = String(params.targetId ?? "");
          const cachedUrl = targetId ? (state.browserTabUrls.get(targetId) ?? "") : "";
          if (process.env.OPENCLAW_VAULT_DEBUG) console.error(`[vault-debug] browser-password resolve: targetId="${targetId}" cachedUrl="${cachedUrl}" params.url="${params.url}" cacheSize=${state.browserTabUrls.size} cacheKeys=[${[...state.browserTabUrls.keys()].join(",")}]`);
          const currentUrl = String(
            params.url ?? params.targetUrl ?? cachedUrl
          );
          const credResult = await getCredential(vaultName, state, "browser", currentUrl);
          if (credResult.credential) {
            const result = resolveBrowserPassword(
              text,
              currentUrl,
              credResult.credential,
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
            const reqTargetId = String(params.targetId ?? "");
            const reqCachedUrl = reqTargetId ? (state.browserTabUrls.get(reqTargetId) ?? "") : "";
            const currentUrl = String(
              request.url ?? params.url ?? params.targetUrl ?? reqCachedUrl
            );
            const credResult2 = await getCredential(vaultName, state, "browser", currentUrl);
            if (credResult2.credential) {
              const resolveResult = resolveBrowserPassword(
                reqText,
                currentUrl,
                credResult2.credential,
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

    // --- Cache browser tab URL for domain-pin resolution ---
    if (action === "navigate" || action === "open") {
      const navUrlForCache = String(params.url ?? "");
      const tid = String(params.targetId ?? "");
      if (navUrlForCache && tid) {
        state.browserTabUrls.set(tid, navUrlForCache);
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
            const credResult3 = await getCredential(
              vaultToolName,
              state,
              "browser-cookie",
              navUrl
            );
            if (credResult3.credential) {
              try {
                const cookieData = JSON.parse(credResult3.credential);
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

      // Inject environment variables via params.env + Perl stdout scrubber
      if (rule.env) {
        const existingEnv = (params.env ?? {}) as Record<string, string>;
        const scrubPairs: Array<{b64Value: string; replacement: string}> = [];
        for (const [envKey, envVal] of Object.entries(rule.env)) {
          const resolved = await resolveVaultRef(envVal, state, toolName, cmdStr);
          existingEnv[envKey] = resolved;
          // Collect credential values for Perl scrubber (base64-encode to avoid
          // all shell/perl escaping issues with special characters in credentials)
          const b64Value = Buffer.from(resolved).toString("base64");
          scrubPairs.push({ b64Value, replacement: `[VAULT:${vaultToolName}]` });
        }
        params.env = existingEnv;

        // Append Perl stdout scrubber: decode base64 credential at runtime,
        // replace any occurrence in output. Uses pipefail to preserve exit code.
        if (scrubPairs.length > 0 && toolName === "exec" && params.command) {
          // Build perl BEGIN block that decodes credentials from base64
          const perlBegin = scrubPairs
            .map((p, i) => `use MIME::Base64; $s${i}=decode_base64("${p.b64Value}"); $r${i}="${p.replacement}";`)
            .join(" ");
          const perlSubs = scrubPairs
            .map((_, i) => `s/\\Q$s${i}\\E/$r${i}/g`)
            .join("; ");
          const perlScript = `BEGIN { ${perlBegin} } ${perlSubs}`;
          params.command = `set -o pipefail; { ${params.command} ; } 2>&1 | perl -pe '${perlScript}'`;
        }

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
  } catch (err: unknown) {
    logVaultError("handleBeforeToolCall", err);
    return;
  }
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
  try {
  if (!state) return;

  // Cache browser tab URL from results (navigate, snapshot, etc. return url)
  if (event.toolName === "browser") {
    if (process.env.OPENCLAW_VAULT_DEBUG) console.error(`[vault-debug] after_tool_call browser: action=${event.params.action} result=${JSON.stringify(event.result).slice(0, 200)} error=${event.error}`);
    if (event.result && typeof event.result === "object") {
      const res = event.result as Record<string, unknown>;

      // OpenClaw wraps tool results in {content: [...], details: {...}}
      // The actual structured data (url, targetId) lives in `details`
      const details = (res.details && typeof res.details === "object")
        ? res.details as Record<string, unknown>
        : res;

      // Security: only trust `details` (structured data from OpenClaw), not content[0].text
      // which could be manipulated by tool output. See SECURITY-AUDIT.md F-NEW-1.
      const source = details;
      const resultUrl = String(source.url ?? "");
      const tid = String(event.params.targetId ?? source.targetId ?? "");
      if (process.env.OPENCLAW_VAULT_DEBUG) console.error(`[vault-debug] after_tool_call: resultUrl="${resultUrl}" tid="${tid}" paramsTargetId="${event.params.targetId}" sourceTargetId="${source.targetId}" usedDetails=${source === details}`);
      if (resultUrl && tid) {
        state.browserTabUrls.set(tid, resultUrl);
        if (process.env.OPENCLAW_VAULT_DEBUG) console.error(`[vault-debug] cached tab URL: ${tid} → ${resultUrl} (cacheSize=${state.browserTabUrls.size})`);
      }
    }
  }

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

  // Note: process.env cleanup removed — we no longer set process.env during injection
  // (params.env only). The injectedEnvVars array is no longer populated.
  } catch (err: unknown) {
    logVaultError("handleAfterToolCall", err);
  }
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
  try {
  if (!state) return;

  // Inject any pending resolver warnings into the result content
  if (pendingResolverWarnings.length > 0) {
    const warningBlock = "\n\n" + pendingResolverWarnings.join("\n\n") + "\n";
    pendingResolverWarnings = [];

    // Append warning to message content so the agent/user sees it
    if (typeof event.message.content === "string") {
      event.message.content += warningBlock;
    } else if (Array.isArray(event.message.content)) {
      event.message.content.push({ type: "text", text: warningBlock });
    }
  }

  // Deep-scrub the message object
  const scrubbed = scrubObject(event.message, state.scrubRules) as Record<string, unknown>;

  // Also scrub literal cached credentials from text content
  if (scrubbed && typeof scrubbed.content === "string") {
    let content = scrubbed.content as string;
    for (const [toolName, cred] of state.credentialCache.entries()) {
      content = scrubLiteralCredential(content, cred.value, toolName);
    }
    scrubbed.content = content;
  }
  // Handle array content (common in AgentMessage)
  if (scrubbed && Array.isArray(scrubbed.content)) {
    for (const part of scrubbed.content) {
      if (part && typeof part === "object" && typeof part.text === "string") {
        let text = part.text;
        for (const [toolName, cred] of state.credentialCache.entries()) {
          text = scrubLiteralCredential(text, cred.value, toolName);
        }
        part.text = text;
      }
    }
  }

  return { message: scrubbed };
  } catch (err: unknown) {
    logVaultError("handleToolResultPersist", err);
    return; // fail-open: let unscrubbed message through rather than crash the hook
  }
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
  try {
  if (!state) return;

  const message = event.message;
  const scrubbed = scrubObject(message, state.scrubRules) as Record<string, unknown>;

  // Scrub literal cached credentials from text content fields
  if (scrubbed && typeof scrubbed.content === "string") {
    let content = scrubbed.content as string;
    const { text, replacements } = scrubTextWithTracking(content, state.scrubRules);
    content = text;
    for (const [toolName, cred] of state.credentialCache.entries()) {
      content = scrubLiteralCredential(content, cred.value, toolName);
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
          text = scrubLiteralCredential(text, cred.value, toolName);
        }
        part.text = text;
      }
    }
  }

  return { message: scrubbed };
  } catch (err: unknown) {
    logVaultError("handleBeforeMessageWrite", err);
    return; // fail-open: let message through rather than crash the hook
  }
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
  try {
  if (!state) return;

  let content = event.content;
  if (typeof content === "string") {
    content = scrubText(content, state.scrubRules);
    for (const [_toolName, cred] of state.credentialCache.entries()) {
      content = scrubLiteralCredential(content, cred.value, _toolName);
    }
    if (content !== event.content) {
      return { content };
    }
  }
  } catch (err: unknown) {
    logVaultError("handleMessageSending", err);
    return; // fail-open: let message through rather than crash the hook
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
  buildResolverWarning,
  _resetResolverState,
  state as _state,
};
