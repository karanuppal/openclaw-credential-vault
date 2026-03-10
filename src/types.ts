/**
 * Type definitions for the OpenClaw Credential Vault plugin.
 */

/** Injection rule for a specific tool call type */
export interface InjectionRule {
  tool: string; // "exec" | "web_fetch" | "browser" etc.
  commandMatch?: string; // glob pattern for exec commands
  urlMatch?: string; // glob pattern for web_fetch/browser URLs
  env?: Record<string, string>; // env vars to inject (value contains $vault:toolname)
  headers?: Record<string, string>; // headers to inject
  /** Browser credential injection type */
  type?: "browser-password" | "browser-cookie";
  /** Domain pinning — credential only resolves on matching domains */
  domainPin?: string[];
  /** Browser injection method: "fill" for password, "cookie-jar" for cookies */
  method?: "fill" | "cookie-jar";
  /** Hint for password field identification */
  fieldHint?: string;
}

/** A single Playwright-compatible cookie */
export interface PlaywrightCookie {
  name: string;
  value: string;
  domain: string;
  path: string;
  expires: number; // Unix epoch seconds, -1 for session
  httpOnly: boolean;
  secure: boolean;
  sameSite: "Strict" | "Lax" | "None";
}

/** Browser-cookie credential stored as JSON array of PlaywrightCookie */
export interface BrowserCookieCredential {
  cookies: PlaywrightCookie[];
  domain: string;
  capturedAt: string; // ISO timestamp
}

/** Scrub configuration for a tool */
export interface ScrubConfig {
  patterns: string[]; // regex patterns to match credential fragments
}

/** Known tool definition (ships with plugin) */
export interface KnownToolDef {
  inject: InjectionRule[];
  scrub: ScrubConfig;
}

/** Rotation support level for a credential */
export type RotationSupport = "manual" | "cli" | "api";

/** Extended rotation metadata for a credential */
export interface RotationMetadata {
  rotationIntervalDays?: number;
  scopes?: string[];
  rotationProcedure?: string;
  revokeUrl?: string;
  rotationSupport?: RotationSupport;
  label?: string;
}

/** Per-tool configuration stored in tools.yaml */
export interface ToolConfig {
  name: string;
  addedAt: string; // ISO timestamp
  lastRotated: string; // ISO timestamp
  inject: InjectionRule[];
  scrub: ScrubConfig;
  rotation?: RotationMetadata;
}

/** Rotation status for a single credential (used by vault_status) */
export interface CredentialRotationStatus {
  name: string;
  label?: string;
  lastRotated: string;
  rotationIntervalDays?: number;
  daysOverdue: number;
  isOverdue: boolean;
  rotationSupport?: RotationSupport;
  revokeUrl?: string;
  rotationProcedure?: string;
  scopes?: string[];
  lastAccess?: string;
}

/** vault_status tool result */
export interface VaultStatusResult {
  totalCredentials: number;
  overdueCount: number;
  credentials: CredentialRotationStatus[];
}

/** Full tools.yaml structure */
export interface VaultConfig {
  version: number;
  masterKeyMode: "passphrase" | "machine";
  /** Credential resolution mode: "inline" (Phase 1, TS decrypts) or "binary" (Phase 2, Rust resolver) */
  resolverMode?: "inline" | "binary";
  /** Custom path to the Rust resolver binary (optional, auto-detected if not set) */
  resolverPath?: string;
  tools: Record<string, ToolConfig>;
}

/** Encrypted file metadata (derived from the binary format) */
export interface EncryptedFileLayout {
  salt: Buffer; // 16 bytes
  nonce: Buffer; // 12 bytes
  ciphertext: Buffer; // variable length
  authTag: Buffer; // 16 bytes
}

/** Result of a tool call hook context */
export interface ToolCallContext {
  tool: string; // "exec" | "web_fetch" | etc.
  params: Record<string, unknown>;
}

/** Audit log event — credential access */
export interface AuditCredentialAccess {
  type: "credential_access";
  timestamp: string;
  tool: string;
  credential: string;
  injectionType: string;
  command: string;
  sessionKey: string;
  durationMs: number;
  success: boolean;
}

/** Audit log event — scrubbing */
export interface AuditScrubEvent {
  type: "scrub";
  timestamp: string;
  hook: string;
  credential: string;
  pattern: string;
  replacements: number;
  sessionKey: string;
}

/** Audit log event — compaction */
export interface AuditCompactionEvent {
  type: "compaction";
  timestamp: string;
  sessionKey: string;
  scrubbingActive: boolean;
}

/** Union of all audit event types */
export type AuditEvent = AuditCredentialAccess | AuditScrubEvent | AuditCompactionEvent;

/** Agent tool interface (subset we use for vault_status) */
export interface AgentToolDef {
  name: string;
  label: string;
  description: string;
  parameters: Record<string, unknown>;
  execute: (
    toolCallId: string,
    params: Record<string, unknown>,
    signal?: AbortSignal,
    onUpdate?: (partialResult: unknown) => void
  ) => Promise<{
    content: Array<{ type: "text"; text: string }>;
    details: unknown;
  }>;
}

/** Plugin API interface (subset we use) */
export interface PluginApi {
  on(
    hook: string,
    handler: (...args: any[]) => any,
    options?: { priority?: number }
  ): void;
  registerCli(
    fn: (ctx: { program: CliProgram }) => void,
    options?: { commands: string[] }
  ): void;
  registerTool(
    tool: AgentToolDef | ((ctx: unknown) => AgentToolDef | null),
    options?: { name?: string; names?: string[]; optional?: boolean }
  ): void;
}

/** CLI program interface (Commander-like) */
export interface CliProgram {
  command(name: string): CliCommand;
}

export interface CliCommand {
  description(desc: string): CliCommand;
  argument(arg: string, desc?: string): CliCommand;
  option(flags: string, desc?: string, defaultVal?: unknown): CliCommand;
  action(fn: (...args: any[]) => void | Promise<void>): CliCommand;
  command(name: string): CliCommand;
}
