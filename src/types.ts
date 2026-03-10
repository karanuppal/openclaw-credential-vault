/**
 * Type definitions for the OpenClaw Credential Vault plugin.
 */

/** Injection rule for a specific tool call type */
export interface InjectionRule {
  tool: string; // "exec" | "web_fetch" etc.
  commandMatch?: string; // glob pattern for exec commands
  urlMatch?: string; // glob pattern for web_fetch URLs
  env?: Record<string, string>; // env vars to inject (value contains $vault:toolname)
  headers?: Record<string, string>; // headers to inject
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

/** Per-tool configuration stored in tools.yaml */
export interface ToolConfig {
  name: string;
  addedAt: string; // ISO timestamp
  lastRotated: string; // ISO timestamp
  inject: InjectionRule[];
  scrub: ScrubConfig;
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
