/**
 * vault_status agent tool: returns credential names (NEVER values),
 * rotation health, and last access times.
 */

import { readConfig, getVaultDir } from "./config.js";
import { readAuditLog } from "./audit.js";
import { VaultStatusResult, CredentialRotationStatus, AgentToolDef } from "./types.js";

/**
 * Compute the vault status: credential names, rotation health, last access times.
 * NEVER includes credential values.
 */
export function computeVaultStatus(vaultDir?: string): VaultStatusResult {
  const dir = vaultDir ?? getVaultDir();
  const config = readConfig(dir);
  const now = Date.now();

  // Get last access times from audit log
  const events = readAuditLog({ limit: 10000 }, dir);
  const lastAccessMap = new Map<string, string>();
  for (const event of events) {
    if (event.type === "credential_access") {
      lastAccessMap.set(event.credential, event.timestamp);
    }
  }

  const credentials: CredentialRotationStatus[] = [];
  let overdueCount = 0;

  for (const [name, tool] of Object.entries(config.tools)) {
    const rotation = tool.rotation ?? {};
    const intervalDays = rotation.rotationIntervalDays ?? 90;

    let daysOverdue = 0;
    let isOverdue = false;

    if (tool.lastRotated) {
      const lastRotatedMs = new Date(tool.lastRotated).getTime();
      const daysSince = Math.floor((now - lastRotatedMs) / (1000 * 60 * 60 * 24));
      if (daysSince > intervalDays) {
        daysOverdue = daysSince - intervalDays;
        isOverdue = true;
        overdueCount++;
      }
    }

    credentials.push({
      name,
      label: rotation.label,
      lastRotated: tool.lastRotated,
      rotationIntervalDays: rotation.rotationIntervalDays,
      daysOverdue,
      isOverdue,
      rotationSupport: rotation.rotationSupport,
      revokeUrl: rotation.revokeUrl,
      rotationProcedure: rotation.rotationProcedure,
      scopes: rotation.scopes,
      lastAccess: lastAccessMap.get(name),
    });
  }

  return {
    totalCredentials: credentials.length,
    overdueCount,
    credentials,
  };
}

/**
 * Create the vault_status agent tool definition.
 */
export function createVaultStatusTool(): AgentToolDef {
  return {
    name: "vault_status",
    label: "Vault Status",
    description:
      "Returns credential vault status: credential names (never values), rotation health, and last access times. Use this to check which credentials need rotation or to verify vault health.",
    parameters: {
      type: "object",
      properties: {},
      required: [],
    },
    execute: async (
      _toolCallId: string,
      _params: Record<string, unknown>,
      _signal?: AbortSignal
    ) => {
      const status = computeVaultStatus();

      const lines: string[] = [];
      lines.push(`Vault Status: ${status.totalCredentials} credential(s), ${status.overdueCount} overdue`);
      lines.push("");

      for (const cred of status.credentials) {
        const label = cred.label ? ` (${cred.label})` : "";
        const overdueStr = cred.isOverdue
          ? ` ⚠ OVERDUE by ${cred.daysOverdue} days`
          : " ✓ OK";
        lines.push(`${cred.name}${label}:${overdueStr}`);
        lines.push(`  Last rotated: ${cred.lastRotated ?? "never"}`);
        if (cred.rotationIntervalDays !== undefined) {
          lines.push(`  Rotation interval: ${cred.rotationIntervalDays} days`);
        }
        if (cred.lastAccess) {
          lines.push(`  Last access: ${cred.lastAccess}`);
        }
        if (cred.rotationSupport) {
          lines.push(`  Rotation support: ${cred.rotationSupport}`);
        }
        if (cred.scopes && cred.scopes.length > 0) {
          lines.push(`  Scopes: ${cred.scopes.join(", ")}`);
        }
        if (cred.revokeUrl) {
          lines.push(`  Revoke URL: ${cred.revokeUrl}`);
        }
        lines.push("");
      }

      return {
        content: [{ type: "text" as const, text: lines.join("\n") }],
        details: status,
      };
    },
  };
}
