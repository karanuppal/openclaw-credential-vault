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
export function getMachinePassphrase(installTimestamp?: string): string {
  const hostname = os.hostname();
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
  fs.writeFileSync(filePath, payload);
  fs.chmodSync(filePath, 0o600);
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
