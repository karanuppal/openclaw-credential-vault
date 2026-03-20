/**
 * Rust resolver binary interface — Phase 2 credential resolution.
 *
 * Spawns the Rust openclaw-vault-resolver binary as a subprocess,
 * passes the tool request on stdin, reads the credential from stdout.
 */

import { execFile } from "node:child_process";
import * as fs from "node:fs";
import * as path from "node:path";

/**
 * Protocol version — must match the Rust resolver binary.
 * Increment when the stdin/stdout JSON schema changes.
 */
export const PROTOCOL_VERSION = 1;

/** Resolver error codes for structured failure handling */
export type ResolverErrorCode =
  | "NOT_FOUND"        // Binary not found on disk
  | "CREDENTIAL_MISSING" // Tool has no credential in vault
  | "DECRYPT_FAILED"   // Argon2id/AES decryption error
  | "PERMISSION_DENIED" // File permissions block access
  | "SECCOMP_VIOLATION" // Seccomp filter triggered
  | "PROTOCOL_MISMATCH" // Plugin/resolver version mismatch
  | "UNKNOWN";          // Unexpected failure

/** Structured result from resolver — success or typed error */
export type ResolverResult =
  | { ok: true; credential: string; expires: string | null; resolverVersion: number | null }
  | { ok: false; error: ResolverErrorCode; message: string; pluginVersion: number; resolverVersion: number | null };

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
 * Parse the resolver version from an error message like:
 * "Protocol version mismatch: plugin sent v2, resolver expects v1."
 */
function parseResolverVersionFromError(msg: string): number | null {
  const match = msg.match(/resolver expects v(\d+)/);
  return match ? parseInt(match[1], 10) : null;
}

/**
 * Spawn the Rust resolver binary and get a credential.
 * Returns a structured result with typed errors for the caller to handle.
 */
export async function resolveViaRustBinary(
  toolName: string,
  context: string,
  command: string,
  resolverPath?: string
): Promise<ResolverResult> {
  const binaryPath = findResolverBinary(resolverPath);
  if (!binaryPath) {
    return {
      ok: false,
      error: "NOT_FOUND",
      message: "Resolver binary not found. Install with: sudo bash vault-setup.sh",
      pluginVersion: PROTOCOL_VERSION,
      resolverVersion: null,
    };
  }

  const request = JSON.stringify({
    tool: toolName,
    context,
    command,
    protocol_version: PROTOCOL_VERSION,
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
          let errorCode = "EUNKNOWN";

          // Try to parse structured error from stderr
          try {
            const errJson = JSON.parse(errorMsg);
            errorMsg = errJson.message ?? errorMsg;
            errorCode = errJson.error ?? errorCode;
          } catch {
            // stderr wasn't JSON, use as-is
          }

          // Detect protocol mismatch from error code
          if (errorCode === "EPROTO" || errorMsg.includes("Protocol version mismatch")) {
            const resolverVersion = parseResolverVersionFromError(errorMsg);
            resolve({
              ok: false,
              error: "PROTOCOL_MISMATCH",
              message: errorMsg,
              pluginVersion: PROTOCOL_VERSION,
              resolverVersion,
            });
            return;
          }

          // Map exit codes to error types
          let mappedError: ResolverErrorCode;
          switch (exitCode) {
            case 1:
              mappedError = "CREDENTIAL_MISSING";
              break;
            case 2:
              mappedError = "DECRYPT_FAILED";
              break;
            case 3:
              mappedError = "PERMISSION_DENIED";
              break;
            case 4:
              mappedError = "SECCOMP_VIOLATION";
              break;
            default:
              mappedError = "UNKNOWN";
          }

          resolve({
            ok: false,
            error: mappedError,
            message: errorMsg || `Resolver exited with code ${exitCode}`,
            pluginVersion: PROTOCOL_VERSION,
            resolverVersion: null,
          });
          return;
        }

        try {
          const result = JSON.parse(stdout.trim());
          if (typeof result.credential !== "string") {
            resolve({
              ok: false,
              error: "UNKNOWN",
              message: "Resolver returned invalid response: missing credential field",
              pluginVersion: PROTOCOL_VERSION,
              resolverVersion: result.protocol_version ?? null,
            });
            return;
          }
          resolve({
            ok: true,
            credential: result.credential,
            expires: result.expires ?? null,
            resolverVersion: result.protocol_version ?? null,
          });
        } catch (parseErr) {
          resolve({
            ok: false,
            error: "UNKNOWN",
            message: `Failed to parse resolver output: ${(parseErr as Error).message}`,
            pluginVersion: PROTOCOL_VERSION,
            resolverVersion: null,
          });
        }
      }
    );

    // Write the request to stdin and close it
    child.stdin?.write(request);
    child.stdin?.end();
  });
}
