import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";
import {
  encrypt,
  decrypt,
  deriveKey,
  writeCredentialFile,
  readCredentialFile,
  removeCredentialFile,
  credentialFileExists,
  getMachinePassphrase,
} from "../src/crypto.js";

describe("Argon2id key derivation", () => {
  it("should produce deterministic keys for same passphrase + salt", async () => {
    const salt = Buffer.alloc(16, 0x42);
    const key1 = await deriveKey("my-passphrase", salt);
    const key2 = await deriveKey("my-passphrase", salt);
    expect(key1).toEqual(key2);
    expect(key1.length).toBe(32); // 256-bit
  });

  it("should produce different keys for different salts", async () => {
    const salt1 = Buffer.alloc(16, 0x01);
    const salt2 = Buffer.alloc(16, 0x02);
    const key1 = await deriveKey("same-passphrase", salt1);
    const key2 = await deriveKey("same-passphrase", salt2);
    expect(key1).not.toEqual(key2);
  });

  it("should produce different keys for different passphrases", async () => {
    const salt = Buffer.alloc(16, 0x42);
    const key1 = await deriveKey("passphrase-a", salt);
    const key2 = await deriveKey("passphrase-b", salt);
    expect(key1).not.toEqual(key2);
  });
});

describe("AES-256-GCM encrypt/decrypt round-trip", () => {
  const passphrase = "test-vault-passphrase";

  it("should encrypt and decrypt a simple credential", async () => {
    const plaintext = "sk_live_abc123def456";
    const encrypted = await encrypt(plaintext, passphrase);
    const decrypted = await decrypt(encrypted, passphrase);
    expect(decrypted).toBe(plaintext);
  });

  it("should handle special characters", async () => {
    const plaintext = 'key-with-"special"&chars<>!@#$%^&*()';
    const encrypted = await encrypt(plaintext, passphrase);
    const decrypted = await decrypt(encrypted, passphrase);
    expect(decrypted).toBe(plaintext);
  });

  it("should handle empty string", async () => {
    const encrypted = await encrypt("", passphrase);
    const decrypted = await decrypt(encrypted, passphrase);
    expect(decrypted).toBe("");
  });

  it("should handle long credentials", async () => {
    const plaintext = "x".repeat(10000);
    const encrypted = await encrypt(plaintext, passphrase);
    const decrypted = await decrypt(encrypted, passphrase);
    expect(decrypted).toBe(plaintext);
  });

  it("should produce different ciphertexts for the same plaintext (random nonce)", async () => {
    const plaintext = "same-key";
    const enc1 = await encrypt(plaintext, passphrase);
    const enc2 = await encrypt(plaintext, passphrase);
    expect(enc1).not.toEqual(enc2); // Different salt + nonce
  });

  it("should fail to decrypt with wrong passphrase", async () => {
    const encrypted = await encrypt("secret", passphrase);
    await expect(decrypt(encrypted, "wrong-passphrase")).rejects.toThrow();
  });

  it("should fail on truncated payload", async () => {
    await expect(decrypt(Buffer.alloc(10), passphrase)).rejects.toThrow(
      "too short"
    );
  });

  it("should fail on tampered ciphertext", async () => {
    const encrypted = await encrypt("secret", passphrase);
    // Flip a byte in the ciphertext
    encrypted[30] ^= 0xff;
    await expect(decrypt(encrypted, passphrase)).rejects.toThrow();
  });

  it("should have correct binary format: [salt(16)][nonce(12)][ciphertext][tag(16)]", async () => {
    const plaintext = "hello";
    const encrypted = await encrypt(plaintext, passphrase);
    // Minimum size: 16 salt + 12 nonce + 5 ciphertext + 16 tag = 49
    expect(encrypted.length).toBeGreaterThanOrEqual(44 + plaintext.length);
  });
});

describe("Credential file operations", () => {
  const tmpDir = path.join(os.tmpdir(), `vault-test-${Date.now()}`);
  const passphrase = "file-test-passphrase";

  beforeEach(() => {
    fs.mkdirSync(tmpDir, { recursive: true });
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it("should write and read a credential file", async () => {
    await writeCredentialFile(tmpDir, "stripe", "sk_test_abc123", passphrase);
    expect(credentialFileExists(tmpDir, "stripe")).toBe(true);

    const cred = await readCredentialFile(tmpDir, "stripe", passphrase);
    expect(cred).toBe("sk_test_abc123");
  });

  it("should set file permissions to 0600", async () => {
    await writeCredentialFile(tmpDir, "github", "ghp_token", passphrase);
    const stat = fs.statSync(path.join(tmpDir, "github.enc"));
    expect((stat.mode & 0o777).toString(8)).toBe("600");
  });

  it("should remove a credential file securely", async () => {
    await writeCredentialFile(tmpDir, "test", "secret", passphrase);
    expect(credentialFileExists(tmpDir, "test")).toBe(true);

    removeCredentialFile(tmpDir, "test");
    expect(credentialFileExists(tmpDir, "test")).toBe(false);
  });

  it("should throw on reading non-existent file", async () => {
    await expect(
      readCredentialFile(tmpDir, "nonexistent", passphrase)
    ).rejects.toThrow("not found");
  });
});

describe("Machine passphrase generation", () => {
  it("should produce deterministic output for same inputs", () => {
    const p1 = getMachinePassphrase("2026-01-01");
    const p2 = getMachinePassphrase("2026-01-01");
    expect(p1).toBe(p2);
  });

  it("should produce different output for different timestamps", () => {
    const p1 = getMachinePassphrase("2026-01-01");
    const p2 = getMachinePassphrase("2026-01-02");
    expect(p1).not.toBe(p2);
  });

  it("should use pinnedHostname when provided", () => {
    const pinned1 = getMachinePassphrase("ts", "pinned-host");
    const pinned2 = getMachinePassphrase("ts", "pinned-host");
    const unpinned = getMachinePassphrase("ts");

    expect(pinned1).toBe(pinned2);
    expect(pinned1).not.toBe(unpinned);
  });

  it("should fall back to os.hostname() when pinnedHostname is undefined", () => {
    expect(getMachinePassphrase("ts")).toBe(
      getMachinePassphrase("ts", undefined)
    );
  });

  it("should produce different passphrase for different pinnedHostnames", () => {
    expect(getMachinePassphrase("ts", "pinned-host-a")).not.toBe(
      getMachinePassphrase("ts", "pinned-host-b")
    );
  });

  it("should produce consistent passphrase regardless of os.hostname() changes when pinned", async () => {
    vi.resetModules();
    vi.doMock("node:os", () => ({
      default: { hostname: () => "host-a" },
      hostname: () => "host-a",
    }));
    const { getMachinePassphrase: getWithHostA } = await import("../src/crypto.js");

    vi.resetModules();
    vi.doMock("node:os", () => ({
      default: { hostname: () => "host-b" },
      hostname: () => "host-b",
    }));
    const { getMachinePassphrase: getWithHostB } = await import("../src/crypto.js");

    const first = getWithHostA("ts", "pinned-host");
    const second = getWithHostB("ts", "pinned-host");

    expect(first).toBe(second);

    vi.doUnmock("node:os");
    vi.resetModules();
  });

  it("should fall back to os.hostname() when pinnedHostname is empty string", () => {
    expect(getMachinePassphrase("ts", "")).toBe(
      getMachinePassphrase("ts")
    );
  });

  it("should be a 64-char hex string (sha256)", () => {
    const p = getMachinePassphrase("test");
    expect(p).toMatch(/^[0-9a-f]{64}$/);
  });
});
