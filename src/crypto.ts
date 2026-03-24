/**
 * Encryption layer: AES-256-GCM + Argon2id key derivation.
 *
 * File format: [16-byte salt][12-byte nonce][ciphertext][16-byte auth tag]
 * One .enc file per credential in ~/.openclaw/vault/
 */

import * as crypto from "node:crypto";
import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";
import argon2 from "argon2";

// Argon2id parameters per spec
const ARGON2_MEMORY_COST = 65536; // 64 MiB in KiB
const ARGON2_TIME_COST = 3; // iterations
const ARGON2_PARALLELISM = 1;
const ARGON2_HASH_LENGTH = 32; // 256-bit key for AES-256

const SALT_LENGTH = 16;
const NONCE_LENGTH = 12;
const AUTH_TAG_LENGTH = 16;

/**
 * Derive a 256-bit encryption key from a passphrase using Argon2id.
 */
export async function deriveKey(
  passphrase: string,
  salt: Buffer
): Promise<Buffer> {
  const hash = await argon2.hash(passphrase, {
    type: argon2.argon2id,
    salt,
    memoryCost: ARGON2_MEMORY_COST,
    timeCost: ARGON2_TIME_COST,
    parallelism: ARGON2_PARALLELISM,
    hashLength: ARGON2_HASH_LENGTH,
    raw: true,
  });
  return Buffer.from(hash);
}

/**
 * Generate a machine-specific passphrase from hostname + uid + timestamp.
 * Used when no user passphrase is provided (machine key mode).
 */
export function getMachinePassphrase(installTimestamp?: string, pinnedHostname?: string): string {
  const hostname = pinnedHostname || os.hostname();
  const uid = process.getuid?.() ?? 0;
  const timestamp = installTimestamp ?? "default";
  const material = `${hostname}:${uid}:${timestamp}`;
  return crypto.createHash("sha256").update(material).digest("hex");
}

/**
 * Encrypt a credential string.
 * Returns the full binary payload: [salt][nonce][ciphertext][authTag]
 */
export async function encrypt(
  plaintext: string,
  passphrase: string
): Promise<Buffer> {
  const salt = crypto.randomBytes(SALT_LENGTH);
  const nonce = crypto.randomBytes(NONCE_LENGTH);
  const key = await deriveKey(passphrase, salt);

  const cipher = crypto.createCipheriv("aes-256-gcm", key, nonce);
  const encrypted = Buffer.concat([
    cipher.update(plaintext, "utf8"),
    cipher.final(),
  ]);
  const authTag = cipher.getAuthTag();

  // Format: [salt(16)][nonce(12)][ciphertext(var)][authTag(16)]
  return Buffer.concat([salt, nonce, encrypted, authTag]);
}

/**
 * Decrypt a credential from the binary payload.
 * Expects format: [salt(16)][nonce(12)][ciphertext(var)][authTag(16)]
 */
export async function decrypt(
  payload: Buffer,
  passphrase: string
): Promise<string> {
  if (payload.length < SALT_LENGTH + NONCE_LENGTH + AUTH_TAG_LENGTH) {
    throw new Error("Invalid encrypted payload: too short");
  }

  const salt = payload.subarray(0, SALT_LENGTH);
  const nonce = payload.subarray(SALT_LENGTH, SALT_LENGTH + NONCE_LENGTH);
  const authTag = payload.subarray(payload.length - AUTH_TAG_LENGTH);
  const ciphertext = payload.subarray(
    SALT_LENGTH + NONCE_LENGTH,
    payload.length - AUTH_TAG_LENGTH
  );

  const key = await deriveKey(passphrase, salt);

  const decipher = crypto.createDecipheriv("aes-256-gcm", key, nonce);
  decipher.setAuthTag(authTag);

  const decrypted = Buffer.concat([
    decipher.update(ciphertext),
    decipher.final(),
  ]);
  return decrypted.toString("utf8");
}

/**
 * Encrypt and write a credential to a .enc file.
 */
export async function writeCredentialFile(
  vaultDir: string,
  toolName: string,
  credential: string,
  passphrase: string
): Promise<string> {
  const filePath = path.join(vaultDir, `${toolName}.enc`);
  const payload = await encrypt(credential, passphrase);
  fs.mkdirSync(vaultDir, { recursive: true });
  // Atomic write: tmp + rename to prevent corruption on crash
  const tmpPath = filePath + ".tmp";
  fs.writeFileSync(tmpPath, payload);
  fs.chmodSync(tmpPath, 0o600);
  fs.renameSync(tmpPath, filePath);
  return filePath;
}

/**
 * Read and decrypt a credential from a .enc file.
 */
export async function readCredentialFile(
  vaultDir: string,
  toolName: string,
  passphrase: string
): Promise<string> {
  const filePath = path.join(vaultDir, `${toolName}.enc`);
  if (!fs.existsSync(filePath)) {
    throw new Error(`Credential file not found: ${filePath}`);
  }
  const payload = fs.readFileSync(filePath);
  return decrypt(payload, passphrase);
}

/**
 * Remove a credential file.
 */
export function removeCredentialFile(
  vaultDir: string,
  toolName: string
): void {
  const filePath = path.join(vaultDir, `${toolName}.enc`);
  if (fs.existsSync(filePath)) {
    // Overwrite with random data before unlinking (best-effort secure delete)
    const stat = fs.statSync(filePath);
    fs.writeFileSync(filePath, crypto.randomBytes(stat.size));
    fs.unlinkSync(filePath);
  }
}

/**
 * Check if a credential file exists.
 */
export function credentialFileExists(
  vaultDir: string,
  toolName: string
): boolean {
  return fs.existsSync(path.join(vaultDir, `${toolName}.enc`));
}

const SYSTEM_VAULT_DIR = "/var/lib/openclaw-vault";

/**
 * Sync a credential file to the system vault directory (/var/lib/openclaw-vault/).
 * Only needed in binary resolver mode — the setuid binary reads from the system dir.
 * Best-effort: logs warning on failure, never throws.
 */
export function syncToSystemVault(vaultDir: string, toolName: string): boolean {
  try {
    const srcPath = path.join(vaultDir, `${toolName}.enc`);
    if (!fs.existsSync(srcPath)) return false;

    // Try using the setuid resolver binary for sync (runs as openclaw-vault user)
    const resolverPath = findResolverBinary();
    if (resolverPath) {
      const data = fs.readFileSync(srcPath);
      const b64 = data.toString("base64");
      const input = JSON.stringify({ tool: toolName, action: "sync", data: b64, protocol_version: 1 });
      try {
        const { execSync } = require("child_process");
        execSync(`echo '${input.replace(/'/g, "'\\''")}' | "${resolverPath}"`, {
          encoding: "utf-8",
          timeout: 10000,
          stdio: ["pipe", "pipe", "pipe"],
        });
        // Also sync .vault-meta.json
        const metaSrc = path.join(vaultDir, ".vault-meta.json");
        if (fs.existsSync(metaSrc)) {
          const metaData = fs.readFileSync(metaSrc);
          const metaB64 = metaData.toString("base64");
          const metaInput = JSON.stringify({ tool: toolName, action: "sync-meta", data: metaB64, protocol_version: 1 });
          execSync(`echo '${metaInput.replace(/'/g, "'\\''")}' | "${resolverPath}"`, {
            encoding: "utf-8",
            timeout: 10000,
            stdio: ["pipe", "pipe", "pipe"],
          });
        }
        return true;
      } catch (resolverErr: unknown) {
        const msg = resolverErr instanceof Error ? resolverErr.message : String(resolverErr);
        console.error(`[vault] ⚠ Resolver sync failed, falling back to direct copy: ${msg}`);
      }
    }

    // Fallback: direct file copy (works if user has write access to system vault)
    if (!fs.existsSync(SYSTEM_VAULT_DIR)) {
      console.error(`[vault] ⚠ System vault dir ${SYSTEM_VAULT_DIR} not found. Run 'sudo bash vault-setup.sh' to fix.`);
      return false;
    }
    const destPath = path.join(SYSTEM_VAULT_DIR, `${toolName}.enc`);
    const tmpPath = destPath + ".tmp";
    fs.copyFileSync(srcPath, tmpPath);
    fs.renameSync(tmpPath, destPath);
    const metaSrc = path.join(vaultDir, ".vault-meta.json");
    const metaDest = path.join(SYSTEM_VAULT_DIR, ".vault-meta.json");
    if (fs.existsSync(metaSrc)) {
      const srcStat = fs.statSync(metaSrc);
      const destExists = fs.existsSync(metaDest);
      if (!destExists || fs.statSync(metaDest).mtimeMs < srcStat.mtimeMs) {
        const metaTmp = metaDest + ".tmp";
        fs.copyFileSync(metaSrc, metaTmp);
        fs.renameSync(metaTmp, metaDest);
      }
    }
    return true;
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    if (msg.includes("EACCES") || msg.includes("permission")) {
      console.error(`[vault] ⚠ SYNC FAILED: Cannot write to ${SYSTEM_VAULT_DIR} (permission denied).`);
      console.error(`[vault]   This credential will NOT work with the binary resolver until fixed.`);
      console.error(`[vault]   Fix: Run 'sudo bash vault-setup.sh' to re-sync all credentials.`);
    } else {
      console.error(`[vault] ⚠ Could not sync to system vault: ${msg}`);
    }
    return false;
  }
}

/** Find the installed setuid resolver binary */
function findResolverBinary(): string | null {
  const paths = [
    "/usr/local/bin/openclaw-vault-resolver",
    path.join(__dirname, "..", "bin", "linux-x64", "openclaw-vault-resolver"),
  ];
  for (const p of paths) {
    if (fs.existsSync(p)) return p;
  }
  return null;
}

/**
 * Remove a credential file from the system vault directory.
 * Best-effort: logs warning on failure, never throws.
 */
export function removeFromSystemVault(toolName: string): void {
  try {
    // Try using the setuid resolver binary (runs as openclaw-vault user)
    const resolverPath = findResolverBinary();
    if (resolverPath) {
      const input = JSON.stringify({ tool: toolName, action: "remove", protocol_version: 1 });
      try {
        const { execSync } = require("child_process");
        execSync(`echo '${input.replace(/'/g, "'\\''")}' | "${resolverPath}"`, {
          encoding: "utf-8",
          timeout: 10000,
          stdio: ["pipe", "pipe", "pipe"],
        });
        return;
      } catch (resolverErr: unknown) {
        const msg = resolverErr instanceof Error ? resolverErr.message : String(resolverErr);
        console.error(`[vault] ⚠ Resolver remove failed, falling back to direct delete: ${msg}`);
      }
    }

    // Fallback: direct delete (works if user has write access)
    const destPath = path.join(SYSTEM_VAULT_DIR, `${toolName}.enc`);
    if (fs.existsSync(destPath)) {
      fs.unlinkSync(destPath);
    }
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    console.error(`[vault] ⚠ Could not remove from system vault: ${msg}`);
  }
}
