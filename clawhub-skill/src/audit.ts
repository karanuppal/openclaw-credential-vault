/**
 * Audit logging: append-only JSONL audit log for credential access and scrubbing events.
 *
 * Storage: ~/.openclaw/vault/audit.log (JSONL, one event per line)
 * Permissions: 0600 (Phase 1), owned by openclaw-vault (Phase 2)
 */

import * as fs from "node:fs";
import * as path from "node:path";
import { AuditEvent } from "./types.js";
import { getVaultDir } from "./config.js";

/**
 * Get the audit log file path.
 */
export function getAuditLogPath(vaultDir?: string): string {
  const dir = vaultDir ?? getVaultDir();
  return path.join(dir, "audit.log");
}

/**
 * Append an audit event to the log file (JSONL, append-only).
 */
/** Max audit log size before rotation: 5 MB */
const MAX_AUDIT_LOG_BYTES = 5 * 1024 * 1024;

export function writeAuditEvent(event: AuditEvent, vaultDir?: string): void {
  const logPath = getAuditLogPath(vaultDir);
  const dir = path.dirname(logPath);

  // Ensure directory exists
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }

  // Rotate if log exceeds max size (keep one backup)
  try {
    if (fs.existsSync(logPath)) {
      const stat = fs.statSync(logPath);
      if (stat.size > MAX_AUDIT_LOG_BYTES) {
        const backupPath = logPath + ".1";
        try { fs.unlinkSync(backupPath); } catch { /* no old backup */ }
        fs.renameSync(logPath, backupPath);
      }
    }
  } catch { /* non-fatal: continue writing to current log */ }

  const line = JSON.stringify(event) + "\n";
  fs.appendFileSync(logPath, line, { mode: 0o600 });
}

/**
 * Log a credential access event.
 */
export function logCredentialAccess(params: {
  tool: string;
  credential: string;
  injectionType: string;
  command: string;
  sessionKey?: string;
  durationMs: number;
  success: boolean;
}, vaultDir?: string): void {
  writeAuditEvent({
    type: "credential_access",
    timestamp: new Date().toISOString(),
    tool: params.tool,
    credential: params.credential,
    injectionType: params.injectionType,
    command: params.command,
    sessionKey: params.sessionKey ?? "unknown",
    durationMs: params.durationMs,
    success: params.success,
  }, vaultDir);
}

/**
 * Log a scrubbing event.
 */
export function logScrubEvent(params: {
  hook: string;
  credential: string;
  pattern: string;
  replacements: number;
  sessionKey?: string;
}, vaultDir?: string): void {
  writeAuditEvent({
    type: "scrub",
    timestamp: new Date().toISOString(),
    hook: params.hook,
    credential: params.credential,
    pattern: params.pattern,
    replacements: params.replacements,
    sessionKey: params.sessionKey ?? "unknown",
  }, vaultDir);
}

/**
 * Log a compaction event.
 */
export function logCompactionEvent(params: {
  sessionKey?: string;
  scrubbingActive: boolean;
}, vaultDir?: string): void {
  writeAuditEvent({
    type: "compaction",
    timestamp: new Date().toISOString(),
    sessionKey: params.sessionKey ?? "unknown",
    scrubbingActive: params.scrubbingActive,
  }, vaultDir);
}

/** Filter options for reading audit log */
export interface AuditLogFilter {
  tool?: string;
  type?: string;
  last?: string; // e.g., "24h", "7d", "30m"
  limit?: number;
}

/**
 * Parse a duration string like "24h", "7d", "30m" into milliseconds.
 */
export function parseDuration(duration: string): number {
  const match = duration.match(/^(\d+)(m|h|d)$/);
  if (!match) throw new Error(`Invalid duration format: ${duration} (use e.g., 24h, 7d, 30m)`);

  const value = parseInt(match[1], 10);
  const unit = match[2];

  switch (unit) {
    case "m": return value * 60 * 1000;
    case "h": return value * 60 * 60 * 1000;
    case "d": return value * 24 * 60 * 60 * 1000;
    default: throw new Error(`Unknown duration unit: ${unit}`);
  }
}

/**
 * Read audit log events with optional filters.
 */
export function readAuditLog(filter: AuditLogFilter = {}, vaultDir?: string): AuditEvent[] {
  const logPath = getAuditLogPath(vaultDir);

  if (!fs.existsSync(logPath)) {
    return [];
  }

  const content = fs.readFileSync(logPath, "utf8");
  const lines = content.trim().split("\n").filter(Boolean);

  let events: AuditEvent[] = [];
  for (const line of lines) {
    try {
      events.push(JSON.parse(line) as AuditEvent);
    } catch {
      // Skip malformed lines
    }
  }

  // Apply type filter
  if (filter.type) {
    events = events.filter((e) => e.type === filter.type);
  }

  // Apply tool filter
  if (filter.tool) {
    events = events.filter((e) => {
      if (e.type === "credential_access") return e.tool === filter.tool || e.credential === filter.tool;
      if (e.type === "scrub") return e.credential === filter.tool;
      return false;
    });
  }

  // Apply time filter
  if (filter.last) {
    const ms = parseDuration(filter.last);
    const cutoff = Date.now() - ms;
    events = events.filter((e) => new Date(e.timestamp).getTime() >= cutoff);
  }

  // Apply limit (take last N)
  const limit = filter.limit ?? 50;
  if (events.length > limit) {
    events = events.slice(-limit);
  }

  return events;
}

/** Aggregate stats from the audit log */
export interface AuditStats {
  totalEvents: number;
  credentialAccesses: number;
  scrubEvents: number;
  compactionEvents: number;
  byTool: Record<string, { accesses: number; scrubs: number; lastAccess?: string }>;
  byHook: Record<string, number>;
}

/**
 * Compute aggregate stats from the audit log.
 */
export function computeAuditStats(vaultDir?: string): AuditStats {
  const events = readAuditLog({ limit: Infinity }, vaultDir);

  const stats: AuditStats = {
    totalEvents: events.length,
    credentialAccesses: 0,
    scrubEvents: 0,
    compactionEvents: 0,
    byTool: {},
    byHook: {},
  };

  for (const event of events) {
    switch (event.type) {
      case "credential_access": {
        stats.credentialAccesses++;
        const tool = event.credential;
        if (!stats.byTool[tool]) {
          stats.byTool[tool] = { accesses: 0, scrubs: 0 };
        }
        stats.byTool[tool].accesses++;
        stats.byTool[tool].lastAccess = event.timestamp;
        break;
      }
      case "scrub": {
        stats.scrubEvents++;
        const tool = event.credential;
        if (!stats.byTool[tool]) {
          stats.byTool[tool] = { accesses: 0, scrubs: 0 };
        }
        stats.byTool[tool].scrubs++;
        if (!stats.byHook[event.hook]) {
          stats.byHook[event.hook] = 0;
        }
        stats.byHook[event.hook]++;
        break;
      }
      case "compaction":
        stats.compactionEvents++;
        break;
    }
  }

  return stats;
}
