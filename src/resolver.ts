/**
 * Rust resolver binary interface — Phase 2 credential resolution.
 *
 * Spawns the Rust openclaw-vault-resolver binary as a subprocess,
 * passes the tool request on stdin, reads the credential from stdout.
 */

import { execFile } from "node:child_process";
import * as fs from "node:fs";
import * as path from "node:path";

/** Default paths to check for the resolver binary (in priority order) */
const RESOLVER_PATHS = [
  "/usr/local/bin/openclaw-vault-resolver",
  // Dev fallback: relative to plugin directory
  path.join(__dirname, "..", "resolver", "target", "release", "openclaw-vault-resolver"),
  path.join(__dirname, "..", "resolver", "target", "x86_64-unknown-linux-musl", "release", "openclaw-vault-resolver"),
];

/**
 * Find the resolver binary path.
 * Checks custom path first, then default locations.
 */
export function findResolverBinary(customPath?: string): string | null {
  if (customPath && fs.existsSync(customPath)) {
    return customPath;
  }

  for (const p of RESOLVER_PATHS) {
    if (fs.existsSync(p)) {
      return p;
    }
  }

  return null;
}

/**
 * Spawn the Rust resolver binary and get a credential.
 *
 * @param toolName - The tool to resolve credentials for (e.g., "gumroad")
 * @param context - The calling context (e.g., "exec", "web_fetch")
 * @param command - The command or URL being executed
 * @param resolverPath - Optional custom path to the resolver binary
 * @returns The credential and expiry, or null if resolution failed
 */
export async function resolveViaRustBinary(
  toolName: string,
  context: string,
  command: string,
  resolverPath?: string
): Promise<{ credential: string; expires: string | null } | null> {
  const binaryPath = findResolverBinary(resolverPath);
  if (!binaryPath) {
    console.error(
      "[vault] Resolver binary not found. Install with: sudo openclaw vault setup-resolver"
    );
    return null;
  }

  const request = JSON.stringify({
    tool: toolName,
    context,
    command,
  });

  return new Promise((resolve) => {
    const child = execFile(
      binaryPath,
      [],
      {
        timeout: 30000, // 30s timeout (Argon2id can be slow)
        maxBuffer: 1024 * 1024, // 1MB max output
        env: {
          // Pass through only what the resolver needs
          HOME: process.env.HOME,
          OPENCLAW_VAULT_PASSPHRASE: process.env.OPENCLAW_VAULT_PASSPHRASE,
        },
      },
      (error, stdout, stderr) => {
        if (error) {
          const exitCode = (error as any).code ?? -1;
          let errorMsg = stderr.trim();

          // Try to parse structured error from stderr
          try {
            const errJson = JSON.parse(errorMsg);
            errorMsg = errJson.message ?? errorMsg;
          } catch {
            // stderr wasn't JSON, use as-is
          }

          switch (exitCode) {
            case 1:
              console.error(`[vault] Credential not found for tool: ${toolName}`);
              break;
            case 2:
              console.error(`[vault] Decryption failed for tool: ${toolName} — ${errorMsg}`);
              break;
            case 3:
              console.error(`[vault] Permission denied for tool: ${toolName} — ${errorMsg}`);
              break;
            case 4:
              console.error(`[vault] Seccomp violation in resolver for tool: ${toolName}`);
              break;
            default:
              console.error(`[vault] Resolver failed (exit ${exitCode}) for tool: ${toolName} — ${errorMsg}`);
          }
          resolve(null);
          return;
        }

        try {
          const result = JSON.parse(stdout.trim());
          if (typeof result.credential !== "string") {
            console.error("[vault] Resolver returned invalid response: missing credential field");
            resolve(null);
            return;
          }
          resolve({
            credential: result.credential,
            expires: result.expires ?? null,
          });
        } catch (parseErr) {
          console.error(`[vault] Failed to parse resolver output: ${(parseErr as Error).message}`);
          resolve(null);
        }
      }
    );

    // Write the request to stdin and close it
    child.stdin?.write(request);
    child.stdin?.end();
  });
}
