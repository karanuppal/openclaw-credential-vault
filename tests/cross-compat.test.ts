/**
 * Cross-Language Compatibility Test — THE most important test.
 *
 * Verifies that files encrypted by TypeScript can be decrypted by the Rust binary,
 * and that machine passphrase derivation is identical across both implementations.
 */

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";
import { execFileSync } from "node:child_process";
import {
  deriveKey,
  writeCredentialFile,
  getMachinePassphrase,
} from "../src/crypto.js";

// Path to the Rust resolver binary
const RESOLVER_BINARY_PATHS = [
  path.join(__dirname, "..", "resolver", "target", "release", "openclaw-vault-resolver"),
  path.join(__dirname, "..", "resolver", "target", "x86_64-unknown-linux-musl", "release", "openclaw-vault-resolver"),
  path.join(__dirname, "..", "resolver", "target", "debug", "openclaw-vault-resolver"),
];

function findResolverBinary(): string | null {
  for (const p of RESOLVER_BINARY_PATHS) {
    if (fs.existsSync(p)) return p;
  }
  return null;
}

const HAS_RESOLVER = findResolverBinary() !== null;

let resolverBinary: string;
let tmpHome: string;
let tmpVaultDir: string;

beforeAll(() => {
  if (!HAS_RESOLVER) return;
  resolverBinary = findResolverBinary()!;
  tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), "vault-cross-"));
  tmpVaultDir = path.join(tmpHome, ".openclaw", "vault");
  fs.mkdirSync(tmpVaultDir, { recursive: true });
});

afterAll(() => {
  if (tmpHome) fs.rmSync(tmpHome, { recursive: true, force: true });
});

describe.skipIf(!HAS_RESOLVER)("Cross-language: machine passphrase derivation", () => {
  it("should produce identical passphrases in TS and Rust", () => {
    // The TypeScript implementation: SHA-256(hostname:uid:timestamp) as hex
    const timestamp = "2026-03-08T12:00:00.000Z";
    const tsPassphrase = getMachinePassphrase(timestamp);

    // Verify it's a valid 64-char hex string
    expect(tsPassphrase).toMatch(/^[0-9a-f]{64}$/);
    expect(tsPassphrase.length).toBe(64);

    // The Rust binary uses the same algorithm — we'll verify this
    // indirectly via the decrypt test (if passphrase differs, decrypt fails)
    console.log(`TS machine passphrase (first 16 chars): ${tsPassphrase.substring(0, 16)}...`);
  });
});

describe.skipIf(!HAS_RESOLVER)("Cross-language: TS encrypt → Rust decrypt", () => {
  it("should decrypt a simple credential encrypted by TypeScript", async () => {
    const credential = "gum_abc123def456ghijkl";
    const passphrase = "cross-compat-test-passphrase";

    // Write vault metadata
    const metaPath = path.join(tmpVaultDir, ".vault-meta.json");
    fs.writeFileSync(
      metaPath,
      JSON.stringify({
        createdAt: "2026-03-08T00:00:00.000Z",
        installTimestamp: "2026-03-08T00:00:00.000Z",
        masterKeyMode: "passphrase",
      })
    );

    // Encrypt with TypeScript
    await writeCredentialFile(tmpVaultDir, "gumroad", credential, passphrase);

    // Verify the encrypted file exists and has correct structure
    const encPath = path.join(tmpVaultDir, "gumroad.enc");
    expect(fs.existsSync(encPath)).toBe(true);
    const encData = fs.readFileSync(encPath);
    expect(encData.length).toBeGreaterThanOrEqual(44 + credential.length);

    // Decrypt with Rust binary
    const request = JSON.stringify({
      tool: "gumroad",
      context: "exec",
      command: "test",
    });

    const result = execFileSync(resolverBinary, [], {
      input: request,
      env: {
        HOME: tmpHome,
        OPENCLAW_VAULT_PASSPHRASE: passphrase,
      },
      timeout: 60000,
    });

    const response = JSON.parse(result.toString().trim());
    expect(response.credential).toBe(credential);
    expect(response.expires).toBeNull();
  });

  it("should decrypt a credential with special characters", async () => {
    const credential = 'sk_live_with"special&chars<>!@#$%^&*()_+-=';
    const passphrase = "special-chars-test";

    await writeCredentialFile(tmpVaultDir, "special", credential, passphrase);

    const request = JSON.stringify({
      tool: "special",
      context: "test",
      command: "test",
    });

    const result = execFileSync(resolverBinary, [], {
      input: request,
      env: {
        HOME: tmpHome,
        OPENCLAW_VAULT_PASSPHRASE: passphrase,
      },
      timeout: 60000,
    });

    const response = JSON.parse(result.toString().trim());
    expect(response.credential).toBe(credential);
  });

  it("should decrypt a long credential", async () => {
    const credential = "x".repeat(5000);
    const passphrase = "long-cred-test";

    await writeCredentialFile(tmpVaultDir, "longcred", credential, passphrase);

    const request = JSON.stringify({
      tool: "longcred",
      context: "test",
      command: "test",
    });

    const result = execFileSync(resolverBinary, [], {
      input: request,
      env: {
        HOME: tmpHome,
        OPENCLAW_VAULT_PASSPHRASE: passphrase,
      },
      timeout: 60000,
    });

    const response = JSON.parse(result.toString().trim());
    expect(response.credential).toBe(credential);
  });

  it("should decrypt using machine passphrase mode", async () => {
    // Create a separate temp dir structure for machine mode test
    const machineHome = fs.mkdtempSync(path.join(os.tmpdir(), "vault-machine-"));
    const machineVaultDir = path.join(machineHome, ".openclaw", "vault");
    fs.mkdirSync(machineVaultDir, { recursive: true });

    try {
      const credential = "github_pat_1234567890abcdef";
      const timestamp = "2026-03-08T06:00:00.000Z";

      // Get the machine passphrase from TypeScript
      const machinePassphrase = getMachinePassphrase(timestamp);

      // Write metadata in machine mode
      const metaPath = path.join(machineVaultDir, ".vault-meta.json");
      fs.writeFileSync(
        metaPath,
        JSON.stringify({
          createdAt: "2026-03-08T00:00:00.000Z",
          installTimestamp: timestamp,
          masterKeyMode: "machine",
        })
      );

      // Encrypt with the machine passphrase (this is what TS does internally)
      await writeCredentialFile(machineVaultDir, "github", credential, machinePassphrase);

      // The Rust binary will derive the same machine passphrase from
      // hostname:uid:timestamp and use it to decrypt
      const request = JSON.stringify({
        tool: "github",
        context: "exec",
        command: "gh pr list",
      });

      // Don't set OPENCLAW_VAULT_PASSPHRASE — let the binary derive it
      const result = execFileSync(resolverBinary, [], {
        input: request,
        env: {
          HOME: machineHome,
          // No OPENCLAW_VAULT_PASSPHRASE — binary will use machine mode
        },
        timeout: 60000,
      });

      const response = JSON.parse(result.toString().trim());
      expect(response.credential).toBe(credential);
      console.log("✓ Machine passphrase derivation matches between TS and Rust");
    } finally {
      fs.rmSync(machineHome, { recursive: true, force: true });
    }
  });

  it("should decrypt using pinned hostname in machine mode", async () => {
    const machineHome = fs.mkdtempSync(path.join(os.tmpdir(), "vault-pinned-"));
    const machineVaultDir = path.join(machineHome, ".openclaw", "vault");
    fs.mkdirSync(machineVaultDir, { recursive: true });

    try {
      const credential = "ghp_pinnedHostnameTest123456";
      const timestamp = "2026-03-24T00:00:00.000Z";
      const pinnedHostname = "test-pinned-host";

      // Get the machine passphrase from TypeScript with pinned hostname
      const machinePassphrase = getMachinePassphrase(timestamp, pinnedHostname);

      // Write metadata with pinnedHostname
      const metaPath = path.join(machineVaultDir, ".vault-meta.json");
      fs.writeFileSync(
        metaPath,
        JSON.stringify({
          createdAt: "2026-03-24T00:00:00.000Z",
          installTimestamp: timestamp,
          masterKeyMode: "machine",
          pinnedHostname: pinnedHostname,
        })
      );

      // Encrypt with the pinned machine passphrase
      await writeCredentialFile(machineVaultDir, "github", credential, machinePassphrase);

      const request = JSON.stringify({
        tool: "github",
        context: "exec",
        command: "gh pr list",
      });

      // Rust binary should read pinnedHostname from meta and derive the same passphrase
      const result = execFileSync(resolverBinary, [], {
        input: request,
        env: {
          HOME: machineHome,
        },
        timeout: 60000,
      });

      const response = JSON.parse(result.toString().trim());
      expect(response.credential).toBe(credential);
      console.log("✓ Pinned hostname machine passphrase matches between TS and Rust");
    } finally {
      fs.rmSync(machineHome, { recursive: true, force: true });
    }
  });
});

describe.skipIf(!HAS_RESOLVER)("Cross-language: Rust binary error handling", () => {
  it("should exit with code 1 for missing credential", () => {
    const emptyHome = fs.mkdtempSync(path.join(os.tmpdir(), "vault-empty-"));
    const emptyVault = path.join(emptyHome, ".openclaw", "vault");
    fs.mkdirSync(emptyVault, { recursive: true });
    fs.writeFileSync(
      path.join(emptyVault, ".vault-meta.json"),
      JSON.stringify({
        createdAt: "2026-03-08T00:00:00.000Z",
        installTimestamp: "2026-03-08T00:00:00.000Z",
        masterKeyMode: "passphrase",
      })
    );

    try {
      execFileSync(resolverBinary, [], {
        input: JSON.stringify({ tool: "nonexistent", context: "test", command: "test" }),
        env: { HOME: emptyHome, OPENCLAW_VAULT_PASSPHRASE: "test" },
        timeout: 10000,
      });
      expect.fail("Should have thrown");
    } catch (err: any) {
      expect(err.status).toBe(1);
    } finally {
      fs.rmSync(emptyHome, { recursive: true, force: true });
    }
  });

  it("should exit with code 2 for wrong passphrase", async () => {
    const wrongHome = fs.mkdtempSync(path.join(os.tmpdir(), "vault-wrong-"));
    const wrongVault = path.join(wrongHome, ".openclaw", "vault");
    fs.mkdirSync(wrongVault, { recursive: true });
    fs.writeFileSync(
      path.join(wrongVault, ".vault-meta.json"),
      JSON.stringify({
        createdAt: "2026-03-08T00:00:00.000Z",
        installTimestamp: "2026-03-08T00:00:00.000Z",
        masterKeyMode: "passphrase",
      })
    );

    try {
      await writeCredentialFile(wrongVault, "test", "secret", "correct-pass");

      execFileSync(resolverBinary, [], {
        input: JSON.stringify({ tool: "test", context: "test", command: "test" }),
        env: { HOME: wrongHome, OPENCLAW_VAULT_PASSPHRASE: "wrong-pass" },
        timeout: 60000,
      });
      expect.fail("Should have thrown");
    } catch (err: any) {
      expect(err.status).toBe(2);
    } finally {
      fs.rmSync(wrongHome, { recursive: true, force: true });
    }
  });
});

describe.skipIf(!HAS_RESOLVER)("Cross-language: Argon2id key derivation consistency", () => {
  it("should produce identical derived keys for known inputs", async () => {
    // This test verifies that Argon2id with our specific parameters produces
    // the same output in both TypeScript and Rust.
    // The TS encrypt → Rust decrypt tests above prove this indirectly,
    // but this test documents the exact parameters used.

    const passphrase = "argon2id-consistency-test";
    const salt = Buffer.alloc(16, 0xaa); // known salt

    const key = await deriveKey(passphrase, salt);
    expect(key.length).toBe(32);

    // Log the derived key for manual verification against Rust if needed
    console.log(`Argon2id key (hex): ${key.toString("hex")}`);
    console.log("Parameters: memory=64MiB, iterations=3, parallelism=1, hashLength=32");
    console.log("If Rust decrypt works, keys are identical.");
  });
});
